# STAGED Core

**English** · [Português (Brasil)](README.pt-BR.md)

This directory holds the framework's **generic core**. It provides all the infrastructure needed to create, run and evaluate decoys, without knowing anything about specific protocols.

**This code must not be modified to add support for new protocols or CVEs.** Each CVE is a driver in `drivers/` (see [drivers/README.md](../drivers/README.md)). When several CVEs of one protocol share a reconnaissance trunk and a port, that trunk is a family in `families/` (see [families/README.md](../families/README.md)). Either way, the core stays as it is.

This file documents the core's API. For running the launcher, the comparison lab and the results, see the [root README](../README.md).

---

## Components

`framework/__init__.py` exports the four names a driver needs: `from framework import StagedDriver, DriverMetadata, StageDefinition, SCTracker`. The bundled families reach `FamilyDriver` and `PortListener` through `from framework import family`.

### `base.py` — Driver contract

Defines the classes every driver uses:

- **`StagedDriver`**: the abstract base class. Every driver inherits from it and implements three methods: `get_metadata()`, `start(port, tracker)` and `stop()`.
  - The launcher calls `start()` in a thread of its own, with the port to serve and the driver's `SCTracker`. It is expected to serve until the driver stops, so it normally blocks.
  - The launcher never calls `stop()`: Ctrl+C or SIGTERM ends the process, and sessions still open are not written. `get_port_override()` is not used either; the launcher applies `--port` itself.
- **`DriverMetadata`**: a dataclass that describes what the driver simulates (table below).
- **`StageDefinition`**: a dataclass that defines one stage of the reconnaissance exchange: `number` (from 1), `name`, `description` and `protocol_layer`.

| `DriverMetadata` field | Meaning |
|---|---|
| `name` | The driver's name, e.g. `EternalBlue`. The `--driver` key is derived from it (see `launcher.py` below) |
| `cve`, `cve_alias` | e.g. `CVE-2017-0144` and `MS17-010` |
| `protocol` | e.g. `SMB` |
| `default_port` | The port the driver serves, unless `--port` is given together with `--driver` |
| `scanner_module`, `scanner_tool` | The scanner the driver is built to fool, e.g. `auxiliary/scanner/smb/smb_ms17_010` and `Metasploit Framework`. They are copied into every session record and do not identify the tool that actually connected |
| `description` | A short description |
| `stages` | The `StageDefinition` list, in order. Its length is N (`total_stages`) |
| `family` | Optional (`None` by default): the family the driver belongs to, e.g. `SMB1-Recon`. `--list` shows it, and a connection the family cannot resolve to a driver is filed under it |

### `tracker.py` — Stage Coverage

Tracks a scanner's progress through the protocol's stages and computes the SC metric, SC = completed stages / N.

- **`SCTracker`**: built by the launcher from the driver's `DriverMetadata` (`SCTracker.from_metadata()`) and passed to `start()`. For each connection, the driver takes a tracker of its own with `tracker.fork()` and opens the session with `new_session()`. It then calls `complete_stage(n, ...)` as the scanner progresses and, at the end, `finalize_session()`, which saves a JSON record with all the session's data.

The tracker is generic: it doesn't know whether it is tracking SMB, RDP or any other protocol. It receives the driver's total number of stages and counts how many were completed.

| Method | What it does |
|---|---|
| `SCTracker.from_metadata(meta)` | Builds a tracker from a `DriverMetadata`. The constructor itself takes the fields one by one: `SCTracker(driver_name, cve, cve_alias, protocol, total_stages, scanner_tool="", scanner_module="")` |
| `fork()` | A new tracker with the same metadata and no session: one per connection |
| `new_session(source_ip="", source_port=0)` | Opens a session: a new session ID, the start time and the client's address. Clears the completed stages |
| `complete_stage(stage_number, stage_name="", source_ip="", source_port=0, data=None)` | Credits the stage, with the data captured at it. A stage that was already credited is ignored. With no open session, it opens one with that source IP and source port 0. The event's IP and port default to the session's |
| `note_activity_beyond_n(description, data=None)` | Records something the scanner did after stage N, in `activity_beyond_n`. It does not count toward SC, and it is ignored when no session is open |
| `get_sc()` | The current SC, from 0.0 to 1.0 (0.0 when N = 0) |
| `get_sc_display()` | The current SC as text, e.g. `3/5` |
| `finalize_session(deception_success=False)` | Closes the session, writes its record and returns the file's path, or `None` when no session is open |
| `print_status()` | Prints a box to stdout with ✅ or ⬜ for each stage |

The tracker counts distinct stage numbers and does not check them against `stages`, so report only numbers from 1 to N.

#### Session records

- **Where.** In `$STAGED_LOG_DIR`, which defaults to `/var/log/staged`. The variable is read once, when `framework.tracker` is imported, so set it before the launcher starts. The directory is created whenever a tracker is built: when the launcher starts a driver, at every `fork()` and at every `unresolved_tracker()`. Without root and without `STAGED_LOG_DIR`, this fails with a `PermissionError` in the driver's thread (see [Troubleshooting](../README.md#troubleshooting)).
- **Name.** `sc_<driver_name>_<YYYYmmdd_HHMMSS_microseconds>_<6 hex>.json`, from the session's start time in UTC: for example `sc_BlueKeep_20261106_141639_130315_4a71f2.json`, or `sc_RDP-Recon_20261106_141639_026898_809f91.json` for a connection filed under its family. The microseconds and the random suffix keep two sessions from getting the same name.
- **When.** `finalize_session()` writes a record for any open session, even one with no completed stage. The families call it when the connection closes, and only if at least one stage was completed, so a bare TCP connection leaves no record.

| Field | Content |
|---|---|
| `session_id` | `<driver_name>_<timestamp>_<6 hex>`: the file name without `sc_` and `.json` |
| `driver_name`, `cve`, `cve_alias`, `protocol` | From the metadata. A connection filed under its family has the family's name, `unresolved` and `<family> (unresolved)` |
| `scanner_tool`, `scanner_module` | From the metadata: the scanner the driver is built for, not the tool that connected. Empty for a connection filed under its family |
| `total_stages`, `completed_stages`, `sc_score` | N, the number of stages credited, and SC as a fraction (`0.6` for 3/5) |
| `start_time`, `end_time` | ISO 8601, UTC |
| `source_ip`, `source_port` | The client's address, as passed to `new_session()` |
| `events` | One per credited stage: `stage_number`, `stage_name`, `timestamp`, `source_ip`, `source_port`, `data_captured` |
| `deception_success` | Whatever the driver passed to `finalize_session()` |
| `activity_beyond_n` | One entry per `note_activity_beyond_n()` call: `timestamp`, `description`, `data` |

#### What counts toward SC

The tracker records what the driver reports. Two conventions, which every bundled driver follows, decide what that is:

- **Stage N is the verdict-bearing exchange**: the request and response the scanner derives its verdict from. Whatever the scanner does afterwards goes to `note_activity_beyond_n()` and never counts toward SC.
- **`deception_success` is true only at SC = N**, that is, with the success threshold α = 1. The tracker does not compute the flag: the driver passes it, as `finalize_session(deception_success=(t.get_sc() == 1.0))`, and the families pass the same condition. At 4/5 the scanner has not reached the exchange it decides on.

The reasoning behind these rules, and how these records (SC_int) are checked against the packet capture (SC_obs), are in the root README's [Stage Coverage](../README.md#stage-coverage) section.

#### One tracker per connection

A tracker holds one session at a time, and the launcher gives each driver a single tracker. If two connections shared it, the second connection's `new_session()` would discard the first one's stages, and both connections would then write the second one's session, to the same file. So call `tracker.fork()` for every connection and `new_session(source_ip, source_port)` on the fork. The families do this when they resolve a connection to a variant, and `PortListener.unresolved_tracker()` builds a new tracker for every connection it files under the family.

### `family.py` — Several drivers on one port

Generic support for families: several drivers of one protocol (the *variants*, one CVE each) share one TCP port, and which variant handles a connection is decided while the connection runs. The module knows no protocol: it manages sockets, threads and the variants registered on each port. Parsing the shared trunk and spotting the divergence signal is the job of the family in `families/`; [families/README.md](../families/README.md) explains the dispatch.

- **`FamilyDriver(StagedDriver)`**: the base of the family bases (`smb.SMBFamilyDriver`, `rdp.RDPFamilyDriver`).
  - `start(port, tracker)` keeps the tracker, which the family forks for each connection, and registers the variant with the port's listener. The listeners are kept in a registry keyed by port and shared by every family. The first variant to start on a port creates the listener (`_listener_cls(port)`) and runs it; the others only register and wait until it stops. Each variant is therefore started like any other driver, in its own launcher thread.
  - `stop()` stops the port's listener, for every variant on it.
  - `is_default_variant()` returns `False` unless the driver overrides it. Exactly one variant per port should return `True`: it takes the connections that no other variant claims.
  - `matches_variant()` and `handle_variant_stages()` raise `NotImplementedError`. Each family redeclares them with its protocol's parameters, and each driver implements them. They are ordinary methods, not abstract ones: a driver that leaves them out is still discovered and started, and the error only shows when a connection reaches them.
  - `get_metadata()` stays abstract, so `FamilyDriver` and the family bases cannot be instantiated (see the import rule under `launcher.py`).
- **`PortListener`**: the single TCP socket of a port, shared by the variants registered on it. A family subclasses it and implements only `_create_handler(sock, addr)`, which returns the protocol's connection handler.
  - `run()` binds `0.0.0.0:<port>`, that is, every interface (`SO_REUSEADDR`, backlog 10), and logs `🍯 Família STAGED escutando na porta <port>`. It then waits `REGISTRATION_GRACE_SECONDS` (0.3 s), so that variants whose threads start a moment later can register, logs `🍯 Variantes ativas na porta <port>: [...]` and starts accepting. A connection that arrives in the meantime waits in the backlog. Each accepted connection is handled by its handler's `handle()`, in a daemon thread of its own.
  - `effective_default_variant()` returns the variant marked as default or, if there is none, the first one registered. With a single variant on the port, that variant takes every connection: with `--driver bluekeep`, an MS12-020 check is filed as BlueKeep.
  - `unresolved_tracker()` builds a new tracker for a connection that ended before any variant could be told apart. Only the family's trunk was exercised, so the record goes to the family, not to the default variant: `driver_name` is the variants' `family` (or `port-<port>` if none has one), `cve` is `unresolved`, `cve_alias` is `<family> (unresolved)`, and N is the largest N among the variants.
  - `stop()` closes the socket and releases the variants waiting on it.

The registry is keyed by port alone, so drivers of different families must not share a port: the first one to start decides which protocol's listener serves it.

### `launcher.py` — Discovery and execution

Discovers all the drivers in `drivers/` automatically, instantiates them and runs them in separate threads. The command line is described in the root README's [Running STAGED](../README.md#running-staged) section; these are the rules behind it.

Discovery (`discover_drivers()`):

1. It scans `drivers/*.py`, not subdirectories, and skips names that start with `_`. So `drivers/__init__.py` and the helpers in `drivers/_common/` are not drivers.
2. It imports each file as the module `drivers.<stem>` (the file name without `.py`). An import error is only a warning (`Erro ao importar drivers.<stem>: …`): that driver is skipped and the others load.
3. It instantiates every `StagedDriver` subclass visible in the module's namespace, imported names included, and calls its `get_metadata()`. Errors here are not caught: they abort the launcher, `--list` included. An abstract class imported by name (`from families.smb import SMBFamilyDriver`, or `FamilyDriver`) is such a subclass, and it ends discovery with `TypeError: Can't instantiate abstract class …`. Hence the rule in [families/README.md](../families/README.md): import a family as a module (`from families import smb`). `DriverMetadata`, `StageDefinition` and `PortListener` are not `StagedDriver` subclasses and can be imported by name.
4. It registers the class under its key: the metadata `name` in lower case, with spaces replaced by `_`. MS12-020's name is `MS12020`, so its key is `ms12020`, not its file name `ms12_020`. Keys must be unique: of two drivers with the same key, only one is kept. `--verbose` prints `Driver descoberto: <key> (<CVE>)` for each driver.

Execution:

- It creates an `SCTracker` for each driver from its `DriverMetadata`, and calls `start(port, tracker)` in a daemon thread per driver.
- It runs all the drivers it found at once, or only the one named by `--driver`, which is lower-cased before the lookup but keeps its spaces. The port is `--port` when given together with `--driver`, and `default_port` otherwise. `--port` on its own is ignored.
- A driver whose `start()` raises, for instance because its port is taken, loses only its own thread: the traceback goes to the console and the launcher keeps running.
- `--report` runs before discovery and imports no driver. It only reads `$STAGED_LOG_DIR/sc_*.json`, so it also works on the records of a stored lab run: point `STAGED_LOG_DIR` at one of its `*.sc_int/` directories.

---

## Why not modify the core?

The separation between the core and the protocol code (families and drivers) is the dissertation's central architectural contribution. The framework is analogous to the engine of an IDS such as Snort or Suricata: it provides the generic infrastructure, and users write "signatures" (drivers) for the protocols they want to simulate. Families are the protocol decoders that related signatures share.

If logic specific to a protocol lived inside the framework, the architecture would lose its generality and the academic argument would weaken. All logic that depends on a protocol (parsing packets, building responses, handshakes) belongs in `families/` when it is the trunk that several CVEs share, or in the corresponding driver in `drivers/` when it is one CVE's divergence, and never in `framework/`. `family.py` is part of the core because it parses no protocol data: it only manages sockets, threads and the variants registered on each port.

---

## Driver API

A complete standalone driver: the skeleton from the root README's [Writing a new driver](../README.md#writing-a-new-driver) section, filled in for a line-based toy protocol. It runs as it is.

```python
# drivers/my_protocol.py
import socket
import threading

from framework import StagedDriver, DriverMetadata, StageDefinition, SCTracker

# A line-based toy protocol: per stage, the request the scanner sends and the reply it waits for.
EXCHANGES = [(b"HELLO", b"HELLO PROTO/1.0\n"),
             (b"NEGOTIATE", b"OK\n"),
             (b"CHECK", b"VULNERABLE\n")]


class MyProtocolDriver(StagedDriver):

    def __init__(self):
        self._stopping = threading.Event()

    def get_metadata(self) -> DriverMetadata:
        return DriverMetadata(
            name="MyProtocol",                 # --driver key: myprotocol
            cve="CVE-XXXX-XXXX",
            cve_alias="PopularName",
            protocol="PROTO",
            default_port=9999,
            scanner_module="auxiliary/scanner/proto/cve_xxxx",
            scanner_tool="Metasploit Framework",
            description="Simulates a vulnerable PROTO server",
            stages=[
                StageDefinition(1, "Handshake", "The client opens a session", "PROTO"),
                StageDefinition(2, "Negotiate", "Parameter negotiation", "PROTO"),
                StageDefinition(3, "Vuln Check", "The exchange the scanner takes its verdict from", "PROTO"),
            ],
        )

    def start(self, port: int, tracker: SCTracker) -> None:
        # Runs in this driver's launcher thread and serves until stop().
        with socket.create_server(("0.0.0.0", port)) as server:
            server.settimeout(1.0)                     # so the loop notices stop()
            while not self._stopping.is_set():
                try:
                    conn, (ip, src_port) = server.accept()
                except TimeoutError:
                    continue
                t = tracker.fork()                     # one tracker per connection
                threading.Thread(target=self._serve, args=(conn, ip, src_port, t),
                                 daemon=True).start()

    def _serve(self, conn: socket.socket, ip: str, src_port: int, t: SCTracker) -> None:
        t.new_session(source_ip=ip, source_port=src_port)
        conn.settimeout(30)
        with conn, conn.makefile("rb") as lines:
            try:
                for stage, (request, reply) in zip(self.get_metadata().stages, EXCHANGES):
                    if lines.readline().strip() != request:
                        break                          # not what this stage expects: hang up
                    conn.sendall(reply)
                    t.complete_stage(stage.number, stage.name, source_ip=ip,
                                     data={"request": request.decode()})
                if t.get_sc() == 1.0:                  # stage N done: the rest is beyond N
                    for line in lines:
                        extra = line.strip().decode(errors="replace")
                        t.note_activity_beyond_n("request after the verdict", {"request": extra})
            except OSError:                            # timeout or reset
                pass
        if t.get_sc() > 0:                             # as in the families: no record for 0 stages
            t.finalize_session(deception_success=(t.get_sc() == 1.0))

    def stop(self) -> None:
        self._stopping.set()
```

- `start()` blocks while it serves. It checks the stop flag between `accept()` calls because, on Linux, closing a listening socket from another thread does not interrupt `accept()`. `PortListener.run()` uses the same one-second timeout.
- Every connection gets its own tracker (`tracker.fork()`) and a session with its source IP and port.
- A stage is credited when its exchange completes: stage 3 once the decoy has answered `CHECK`. What the client sends after stage N is recorded with `note_activity_beyond_n()` and does not count.
- `deception_success` is true only at SC = N. A connection that completed no stage writes no record, as in the families.
- A driver that joins a family subclasses the family's base instead (`smb.SMBFamilyDriver`, `rdp.RDPFamilyDriver`). It still implements `get_metadata()`, but instead of `start()` and `stop()`, which the family provides, it implements `matches_variant()` and `handle_variant_stages()`, plus `is_default_variant()` if it is the family's default: see [drivers/README.md](../drivers/README.md).

To try it, save it as `drivers/my_protocol.py` and, from the repository root, run:

```bash
STAGED_LOG_DIR=$PWD/logs/sc python3 -m framework.launcher --driver myprotocol
```

In a second terminal, from the same directory:

```bash
python3 - <<'EOF'
import socket
with socket.create_connection(("127.0.0.1", 9999)) as s, s.makefile("rb") as replies:
    for request in (b"HELLO", b"NEGOTIATE", b"CHECK"):
        s.sendall(request + b"\n")
        print(replies.readline())
EOF
STAGED_LOG_DIR=$PWD/logs/sc python3 -m framework.launcher --report
```

The client prints the three replies, `--report` lists the session as `SC=3/3  ✅`, and the launcher's console shows:

```
19:29:01 [staged.MyProtocol] INFO: Nova sessão: MyProtocol_20261115_222901_616603_375e47 de 127.0.0.1:37516
19:29:01 [staged.MyProtocol] INFO: [MyProtocol] Stage 1/3 (Handshake) completada — SC = 1/3
19:29:01 [staged.MyProtocol] INFO: [MyProtocol] Stage 2/3 (Negotiate) completada — SC = 2/3
19:29:01 [staged.MyProtocol] INFO: [MyProtocol] Stage 3/3 (Vuln Check) completada — SC = 3/3
19:29:01 [staged.MyProtocol] INFO: Sessão finalizada: SC = 3/3 (SUCESSO) → /…/logs/sc/sc_MyProtocol_20261115_222901_616603_375e47.json
```

Delete the file when you are done: a launcher run without `--driver` starts every driver in `drivers/`, this one included.
