# STAGED — STage-Aware Generic Extensible Decoys

**English** · [Português (Brasil)](README.pt-BR.md)

STAGED is a framework for building decoys that carry reconnaissance scanners through every stage of a real vulnerability check. A decoy answers each step of the scanner's protocol exchange the way a vulnerable host would, so the scanner keeps going, reaches its verdict, and leaves a record of everything it did on the way. The framework measures this with **Stage Coverage (SC)**: how much of the scanner's check the decoy sustained.

It was developed for a master's dissertation at PPGInf/UFPR. The repository holds:

- **the framework** (`framework/`, `families/`, `drivers/`): Python standard library only, with three bundled decoys (EternalBlue, BlueKeep, MS12-020);
- **a Honeyd baseline** (`honeyd/`): Honeyd V1.6d in a container, with its own stock SMB script;
- **the comparison lab** (`honeyd/lab/`, `honeyd/sc_toolkit/`): a rootless podman testbed that runs real scanners against STAGED, Honeyd and an inert socket, scores every run from its packet capture, and builds the tables. The stored runs are in `honeyd/lab/results/`.

## Contents

1. [Quick start](#quick-start)
2. [Repository layout](#repository-layout)
3. [Architecture](#architecture)
4. [Stage Coverage](#stage-coverage)
5. [Bundled drivers](#bundled-drivers)
6. [Running STAGED](#running-staged)
7. [Testing STAGED with real scanners](#testing-staged-with-real-scanners)
8. [Running Honeyd](#running-honeyd)
9. [Running STAGED vs Honeyd](#running-staged-vs-honeyd)
10. [Results](#results)
11. [Writing a new driver](#writing-a-new-driver)
12. [Scope and safety](#scope-and-safety)

## Quick start

You need Linux and Python 3.10 or newer. There is nothing to install: `requirements.txt` is intentionally empty.

```bash
git clone https://github.com/danmvas/staged-decoys.git
cd staged-decoys
python3 -m framework.launcher --list

# the EternalBlue decoy on an unprivileged port (no root needed)
STAGED_LOG_DIR=$PWD/logs/sc python3 -m framework.launcher --driver eternalblue --port 14455
```

In a second terminal, from the same directory, walk it through its five stages and read the session summary:

```bash
python3 honeyd/sc_toolkit/probe_smb.py --host 127.0.0.1 --port 14455
STAGED_LOG_DIR=$PWD/logs/sc python3 -m framework.launcher --report
```

`probe_smb.py` is a hand-written stand-in for the MS17-010 check. To use the real scanners, see [Testing STAGED with real scanners](#testing-staged-with-real-scanners). Stop the decoy with Ctrl+C.

## Repository layout

```
framework/              generic core, no protocol logic
  base.py               StagedDriver, DriverMetadata, StageDefinition: the driver contract
  family.py             FamilyDriver + PortListener: several drivers on one shared port
  tracker.py            SCTracker: stage tracking, SC, one JSON record per session
  launcher.py           driver discovery and the command-line launcher
families/               optional shared protocol trunks
  smb.py                SMB1-Recon: Negotiate → Session Setup → Tree Connect IPC$
  rdp.py                RDP-Recon: X.224 Connection Request → Security Negotiation → MCS Connect Initial
drivers/                one thin module per CVE
  eternalblue.py        CVE-2017-0144 (MS17-010)
  bluekeep.py           CVE-2019-0708 (BlueKeep)
  ms12_020.py           CVE-2012-0002 (MS12-020)
  _common/              logging helper shared by the drivers (not a driver)
main.py                 the launcher, runnable from any directory
honeyd/                 the Honeyd baseline and the comparison lab
  Containerfile, entrypoint.sh, windows.conf.in    the Honeyd image and its configuration
  smoke_test.sh         proves the Honeyd image answers (about 5 s)
  HONEYD_SETUP.md       how the Honeyd build was worked out (§0 is the verified path)
  RUNBOOK.md            the comparison procedure
  lab/                  the podman lab: lab.sh, run_all.sh, report.py, FINDINGS.md, results/
  sc_toolkit/           the observer and run tools: sc_observer.py, run_matrix.sh, aggregate_sc.py,
                        probe_smb.py, honeyd_inetd.py, experimental_protocol.md
framework_architecture.pdf, .png    the architecture figure
```

`framework/`, `families/` and `drivers/` each have their own README.

## Architecture

![STAGED architecture: core, protocol families and drivers](framework_architecture.png)

The figure is also available as a [PDF](framework_architecture.pdf).

STAGED has two mandatory layers and one optional layer:

- **The core** (`framework/`) knows nothing about protocols. It discovers drivers, tracks stages, computes SC, writes the session records, and lets several drivers share one port (`family.py`).
- **Drivers** (`drivers/`) are the unit of extension: one CVE each. A driver declares its stages and answers the scanner.
- **Families** (`families/`) are optional. A family holds the reconnaissance trunk that several CVEs of one protocol share, and lets their drivers share a port: it decides, per connection, which driver takes over. A driver can also subclass `StagedDriver` directly and own its port (the standalone path in the figure).

New families and drivers are added without changing the core. The analogy is an IDS such as Snort or Suricata, where a generic engine runs signatures written by its users: here the core is the deception engine, families are protocol decoders shared by related signatures, and drivers are the signatures.

### Family dispatch

All drivers of a family registered on the same port share one listener. The family plays the trunk stages once per connection, buffers them, and resolves the connection to one driver (a *variant*) when the divergence signal appears:

- **SMB1-Recon (445).** The first command after Tree Connect decides. EternalBlue is the only member for now, and the default variant.
- **RDP-Recon (3389).** BlueKeep and MS12-020 share the port. MS12-020 claims the connection at its second Attach User Request; otherwise BlueKeep, the default variant, takes it at the first Channel Join. The family then carries the RDP connection sequence (security exchange, licensing, capabilities, finalization, first screen update) through to the scanner's probe.

A connection that ends before it can be resolved has exercised only the trunk, so it is recorded under the family (`SMB1-Recon` or `RDP-Recon`, with `cve` = `unresolved`), not under a driver. Nmap's `rdp-enum-encryption` and the fingerprint connection of Metasploit's BlueKeep scanner produce such records.

Dispatch needs both RDP drivers in the same launcher process. With `--driver bluekeep`, an MS12-020 check is filed as a BlueKeep session at 4/5, although the scanner still reports VULNERABLE. See [families/README.md](families/README.md) for the mechanism.

## Stage Coverage

```
SC = completed stages / N
```

Each driver declares its N stages in `DriverMetadata.stages` and reports progress with `tracker.complete_stage(n, ...)`. Every bundled driver has N = 5. Three rules apply to every driver:

- **Stage N is the verdict-bearing exchange**: the request and response the scanner derives its verdict from. Whatever the scanner does afterwards is recorded in `activity_beyond_n` and does not count. Metasploit's MS17-010 scanner, for example, keeps sending transactions after the PeekNamedPipe that gives it its verdict, while Nmap stops there; both score 5/5.
- **`deception_success` is true only at SC = N.** At 4/5 the scanner has not reached the exchange it decides on.
- **SC = N does not mean the scanner said VULNERABLE.** It means the scanner was carried through the exchange it decides on, so the verdict is reported in its own column. In one earlier run, MS12-020 reached 5/5 on the wire while the scanner said SAFE in 29 of 30 runs.

SC is measured from two sides:

- **SC_int** is STAGED's own record: one `sc_*.json` per session.
- **SC_obs** comes from the external observer, `honeyd/sc_toolkit/sc_observer.py`, which scores a packet capture against the same stage lists without consulting the decoy. A stage counts only when both the client's request and the server's response are on the wire, so a decoy that takes a probe and stays silent scores 0. SC_obs is what puts a third-party decoy such as Honeyd on the same scale.

In the cited lab run, SC_int and SC_obs agree on every session.

## Bundled drivers

| Driver | CVE | Protocol, port | Family (variant) | `--driver` key | Scanner it is built to fool |
|---|---|---|---|---|---|
| EternalBlue | CVE-2017-0144 (MS17-010) | SMB1, 445 | SMB1-Recon (default) | `eternalblue` | `auxiliary/scanner/smb/smb_ms17_010` |
| BlueKeep | CVE-2019-0708 | RDP, 3389 | RDP-Recon (default) | `bluekeep` | `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` |
| MS12-020 | CVE-2012-0002 | RDP, 3389 | RDP-Recon | `ms12020` | `auxiliary/scanner/rdp/ms12_020_check` |

The lab also runs Nmap's `smb-vuln-ms17-010`, the `check` of Metasploit's MS17-010 exploit module, rdpscan and Nmap's `rdp-enum-encryption` against them (see [Results](#results)).

### EternalBlue (SMB)

| # | Stage | What happens |
|---|---|---|
| 1 | SMB Negotiate | The client offers its dialects; the decoy picks NT LM 0.12 (SMB1) |
| 2 | Session Setup | The decoy accepts the session as a Windows 7 SP1 host, and records the client's account, domain, native OS and LAN Manager strings |
| 3 | Tree Connect IPC$ | Records the share path |
| 4 | PeekNamedPipe | The scanner's first Trans PeekNamedPipe |
| 5 | Vuln Check Response | The decoy answers that PeekNamedPipe with STATUS_INSUFF_SERVER_RESOURCES, which scanners read as VULNERABLE. This is the verdict-bearing exchange |

Stages 4 and 5 are credited together, so SC goes from 3/5 straight to 5/5. The behavioural signal that sets automated reconnaissance apart from ordinary traffic is the step from 3 to 4: IPC$ followed by PeekNamedPipe, without touching any real resource. IPC$ on its own is normal on Windows networks.

### BlueKeep (RDP)

| # | Stage | What happens |
|---|---|---|
| 1 | X.224 Connection Request | Records the cookie, the requested security protocols and a guess at the tool |
| 2 | Security Negotiation | The Connection Confirm selects Standard RDP Security: no TLS, no NLA. It is credited together with stage 1 and has no exchange of its own |
| 3 | MCS Connect Initial | Records the client's RDP version, resolution, keyboard layout, build, hostname and static channels |
| 4 | Channel Join | The scanner joins the virtual channels |
| 5 | MS_T120 Probe | Data on the MS_T120 channel after the full connection sequence. The decoy answers with an MCS Disconnect Provider Ultimatum, as a vulnerable host does. This is the verdict-bearing exchange |

Because stage 2 rides on stage 1, any client that sends a valid X.224 Connection Request scores at least 2/5 on RDP.

### MS12-020 (RDP)

| # | Stage | What happens |
|---|---|---|
| 1–3 | RDP-Recon trunk | As for BlueKeep |
| 4 | Second Attach User Request | The scanner asks for a second MCS user ID; the connection resolves to MS12-020 here |
| 5 | Channel Join Check | The first Channel Join after the second Attach User, accepted with result 0. This is the verdict-bearing exchange for `ms12_020_check` |

Whether that Channel Join is a cross-user bind is recorded (`cross_user`) but not required: Metasploit takes the initiator from bytes of its first read, so it is never one of the attached users.

> **Disclosure.** `ms12_020_check` reads at fixed offsets from whatever its first `recv` returns. The RDP family holds the MCS Connect Response for up to 100 ms (`CONNECT_RESPONSE_HOLD` in `families/rdp.py`) and sends it in the same segment as the next reply, so the module's offsets land where it expects. This is tuned to Metasploit's parser and has not been checked against a real Windows host. It is a deception choice, not protocol fidelity.

## Running STAGED

### Requirements

- Linux and Python 3.10 or newer (developed and tested with 3.14), standard library only.
- Root only for port 445. Port 3389 is above Linux's default `net.ipv4.ip_unprivileged_port_start` (1024), so a normal user can bind it.
- [podman](https://podman.io), rootless, for the container option, the real scanners and the lab.

### The launcher

Run it from the repository root. `python3 main.py …` takes the same options and works from any directory.

| Command | Effect |
|---|---|
| `python3 -m framework.launcher` | Start every driver, each on its default port |
| `python3 -m framework.launcher --driver <key>` | Start one driver: `eternalblue`, `bluekeep` or `ms12020` |
| `python3 -m framework.launcher --driver <key> --port <n>` | Start it on another port. `--port` is ignored without `--driver` |
| `python3 -m framework.launcher --list` | List the drivers. `--verbose --list` also prints their keys |
| `python3 -m framework.launcher --report` | Summarise the session records in `$STAGED_LOG_DIR` |
| `python3 -m framework.launcher --verbose` | Debug output for driver discovery |

The launcher's messages are in Portuguese. `--list` prints:

```
======================================================================
  STAGED — Drivers Disponíveis
======================================================================
  Nome                 CVE                Protocolo  Porta    Stages   Família
  ────────────────────────────────────────────────────────────────────────────────
  BlueKeep             CVE-2019-0708      RDP        3389     5        RDP-Recon
  EternalBlue          CVE-2017-0144      SMB        445      5        SMB1-Recon
  MS12020              CVE-2012-0002      RDP        3389     5        RDP-Recon
======================================================================
```

`STAGED_LOG_DIR` sets where the session records go. It defaults to `/var/log/staged`, which a normal user cannot create, so **set it on every run without root**, and use the same value for `--report`.

### Option 1: one driver, without root

```bash
STAGED_LOG_DIR=$PWD/logs/sc python3 -m framework.launcher --driver eternalblue --port 14455
STAGED_LOG_DIR=$PWD/logs/sc python3 -m framework.launcher --driver bluekeep     # 3389 needs no root
```

`logs/` is in `.gitignore`. Remember that MS12-020 is only told apart from BlueKeep when both run in one process (options 2 and 3).

### Option 2: every driver on the real ports, as root

```bash
sudo python3 -m framework.launcher
```

The session records go to `/var/log/staged/`. If a port is taken, `sudo ss -ltnp 'sport = :445 or sport = :3389'` shows by what: usually Samba (`smb`/`nmb` on Fedora, `smbd`/`nmbd` on Debian and Ubuntu) or an RDP server such as xrdp, GNOME Remote Desktop or KDE's KRdp.

A root run leaves root-owned files in `./logs/`. A later run without root from the same directory then drops those drivers with a warning (`Erro ao importar drivers.… Permission denied`), so use another directory or `sudo chown -R "$USER" logs`.

Without root, the full launcher still serves RDP on 3389, but the EternalBlue thread dies on 445 with a traceback while the process keeps running.

### Option 3: every driver, without root, in a container

The container binds 445 and 3389 in its own network namespace, and podman publishes them on loopback ports of the host. Run this from the repository root:

```bash
mkdir -p "$HOME/staged-run/logs" "$HOME/staged-run/sc"
podman run -d --rm --name staged --security-opt label=disable \
  -v "$PWD":/app:ro -v "$HOME/staged-run/logs":/app/logs -v "$HOME/staged-run/sc":/logs \
  -w /app -e STAGED_LOG_DIR=/logs -e PYTHONUNBUFFERED=1 \
  -p 127.0.0.1:14455:445 -p 127.0.0.1:13389:3389 \
  docker.io/library/python:3.14-slim python3 -m framework.launcher
podman logs -f staged     # ready at "Variantes ativas na porta 3389: ['BlueKeep', 'MS12020']"
```

- The writable `/app/logs` mount is required: the repository is mounted read-only, and each driver opens its log files when it is imported.
- `--security-opt label=disable` lets the container read the repository on SELinux hosts such as Fedora, without relabelling it.
- Publishing on `127.0.0.1` keeps the decoy off your network. Remove the address to expose it.
- Through rootless port forwarding, sessions are recorded with your host's main IP address as their source, not 127.0.0.1.

Stop it with `podman stop staged`, and summarise its sessions with `STAGED_LOG_DIR=$HOME/staged-run/sc python3 -m framework.launcher --report`.

### What a run produces

- **Console:** stage-by-stage progress, variant resolution, and a summary box per session. Most lines are printed twice, in two formats.
- **Session records (SC_int):** `$STAGED_LOG_DIR/sc_<name>_<UTC timestamp>_<random>.json`, where `<name>` is the driver, or the family for an unresolved session. There is one file per connection that completed at least one stage, so a plain port scan writes nothing and one scan can write several files. Each holds the driver and CVE, the total and completed stages, `sc_score`, `deception_success`, the start and end times, the source IP and port, every stage event with the data captured at it, and `activity_beyond_n`. `scanner_tool` and `scanner_module` name the scanner the driver was built for, not the tool that connected.
- **Driver logs,** relative to the working directory: `logs/eternalblue/{staged.log,events.jsonl}`, `logs/bluekeep/{bluekeep_staged.log,bluekeep_events.jsonl}` and `logs/ms12_020/{staged.log,events.jsonl}`. The drivers create them when they are imported, even for `--list`. They hold the drivers' own lines and structured events; the stage progress is on the console and in the session records.
- **`--report`** reads `$STAGED_LOG_DIR/sc_*.json` and prints, per driver or family, every session (time, SC, ✅ or ❌ for `deception_success`, source IP) and the average and highest SC.

Ctrl+C or SIGTERM stops the launcher. Sessions still open at that moment are not written.

### Troubleshooting

| Symptom | Cause |
|---|---|
| A thread traceback ending in `PermissionError: … '/var/log/staged'`, and nothing listens | Running without root and without `STAGED_LOG_DIR` |
| `PermissionError` or `Address already in use` when binding, and the launcher keeps running | Port 445 without root, or a port already in use. A driver that fails doesn't stop the others; check with `ss -ltn` |
| `Driver 'ms12_020' não encontrado` | The key is `ms12020` |
| `--port` has no effect | It only applies together with `--driver` |
| `No module named 'framework'` | `-m framework.launcher` only works from the repository root; elsewhere use `python3 /path/to/main.py` |
| A driver is missing from `--list`, with `Erro ao importar … Permission denied` | Root-owned files in `./logs/` from an earlier `sudo` run |

## Testing STAGED with real scanners

The scanners live in one image, `localhost/sc-scanner`: Metasploit 6.5.9-dev, Nmap 7.99, rdpscan (commit 09db271) and tcpdump. `./honeyd/lab/lab.sh up` builds it when it's missing. To build it by hand (about 2.5 GB, needs internet access):

```bash
podman build --cap-add NET_RAW -t localhost/sc-scanner -f honeyd/lab/scanner.Containerfile honeyd/lab
```

With the container from option 3 running (SMB on 14455, RDP on 13389):

```bash
SCAN="podman run --rm --network host --cap-add NET_RAW localhost/sc-scanner"

$SCAN msfconsole -q -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 127.0.0.1; set RPORT 14455; run; exit'
$SCAN msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 127.0.0.1; set RPORT 14455; set PAYLOAD generic/shell_reverse_tcp; set LHOST 127.0.0.1; check; exit'
$SCAN nmap --unprivileged -Pn -p14455 --script smb-vuln-ms17-010 --script-args smbport=14455 127.0.0.1

$SCAN msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS 127.0.0.1; set RPORT 13389; run; exit'
$SCAN rdpscan -p 13389 127.0.0.1
$SCAN nmap --unprivileged -Pn -p13389 --script +rdp-enum-encryption 127.0.0.1

$SCAN msfconsole -q -x 'use auxiliary/scanner/rdp/ms12_020_check; set RHOSTS 127.0.0.1; set RPORT 13389; run; exit'
```

| Tool | Verdict line | Session records |
|---|---|---|
| msf `smb_ms17_010` | `Host is likely VULNERABLE to MS17-010!` | EternalBlue 5/5, with activity beyond N |
| msf `ms17_010_eternalblue` `check` | `The target is vulnerable.` | EternalBlue 5/5, with activity beyond N |
| nmap `smb-vuln-ms17-010` | `State: VULNERABLE` | EternalBlue 5/5 |
| msf `cve_2019_0708_bluekeep` | `The target is vulnerable. The target attempted cleanup of the incorrectly-bound MS_T120 channel.` | BlueKeep 5/5, plus RDP-Recon 2/5 for its fingerprint connection |
| rdpscan | `VULNERABLE - got appid` | BlueKeep 5/5 |
| nmap `rdp-enum-encryption` | a table of security layers, no vulnerability verdict | 9 × RDP-Recon, at most 3/5 |
| msf `ms12_020_check` | `The target is vulnerable. Response confirmed vulnerability presence` | MS12020 5/5 |

- `--cap-add NET_RAW` is required under rootless podman: `msfconsole` (Ruby) and `nmap` carry file capabilities and otherwise fail with `Operation not permitted`. With `--network host`, Nmap also needs `--unprivileged`.
- On non-default ports Nmap silently skips both scripts unless told otherwise: `smb-vuln-ms17-010` needs `--script-args smbport=<port>`, and `rdp-enum-encryption` needs the `+` in front of its name. Against the real ports 445 and 3389 (option 2), leave out `RPORT`, `smbport` and the `+`.
- `rdp-enum-encryption` is a reconnaissance probe, not a BlueKeep check. It negotiates and enumerates security layers but never attaches a user or joins a channel, so it stops at 3/5 by design.
- Use the EternalBlue exploit module with `check` only. Never `run` or `exploit` it.
- Without the scanner image, `python3 honeyd/sc_toolkit/probe_smb.py --host 127.0.0.1 --port 14455 [--stop-at N]` walks the SMB stages by hand.

## Running Honeyd

Honeyd is the related-work baseline (target T2 in the lab). The image builds Honeyd V1.6d from DataSoft/Honeyd at commit a0f3d64 and configures one virtual host that claims to be Windows 7:

- Port 445 runs Honeyd's only stock SMB script, `smb-autofail`, ported to Python 3. It answers Negotiate and Session Setup, and denies the Tree Connect with STATUS_ACCESS_DENIED.
- Honeyd ships no RDP script, so 3389 is reset, like every other port.

Everything below runs rootless, from the repository root.

**1. Build the image** once (needs internet access). `smoke_test.sh` and `lab.sh` also build it when it's missing.

```bash
podman build -t localhost/honeyd:a0f3d64 -f honeyd/Containerfile honeyd/
```

**2. Run the smoke test** (about 5 s). It creates the isolated podman network `honeylab` (10.0.0.0/24, no route out), runs Honeyd at 10.0.0.2 emulating 10.0.0.50, and probes it from 10.0.0.9 with a real tcpdump capture.

```bash
./honeyd/smoke_test.sh                  # output in honeyd/smoke_out/ (git-ignored)
OUT=/some/dir ./honeyd/smoke_test.sh    # or somewhere else
```

A good run shows `ttl=128` (the Windows personality), `445 port … succeeded!`, `3389 … Connection refused` and `SC_obs = 2/5` (SMB Negotiate, Session Setup). An extra `SC_obs = 0/5` session is the port check. The script asserts nothing, so look for those lines rather than at its exit status. Don't run it while the lab is up: both use `honeylab` and the same addresses.

**3. Check the configuration** without any network:

```bash
podman run --rm --network none -e HONEYD_IFACE=lo localhost/honeyd:a0f3d64 --verify-config
```

**4. Run it yourself** on the same network, with the lab down:

```bash
podman network exists honeylab || podman network create --internal --disable-dns --subnet 10.0.0.0/24 honeylab
podman run -d --name honeyd --network honeylab --ip 10.0.0.2 --cap-add NET_RAW --cap-add NET_ADMIN \
  -e HONEYD_IFACE=eth0 -e HONEYD_IP=10.0.0.50 -e HONEYD_MAC=00:1b:21:3a:4f:50 \
  localhost/honeyd:a0f3d64
podman logs -f honeyd     # ready at "Demoting process privileges to uid 65534"

# a client on the same network
podman run --rm -it --network honeylab --ip 10.0.0.9 --cap-add NET_RAW --cap-add NET_ADMIN \
  --entrypoint bash localhost/honeyd:a0f3d64
#   inside: ethtool -K eth0 tx off; ping -c1 10.0.0.50; nc -vz 10.0.0.50 445

podman cp honeyd:/var/log/honeyd/. ./honeyd-logs/    # Honeyd's own logs
podman rm -f honeyd
```

| Variable | Default | Meaning |
|---|---|---|
| `HONEYD_IFACE` | `eth0` | The interface Honeyd listens on; it must exist where Honeyd runs |
| `HONEYD_IP` | `10.0.0.50` | The emulated host's address |
| `HONEYD_MAC` | `00:1b:21:3a:4f:50` | The emulated host's MAC |

Arguments after the image name go to `honeyd` itself. The configuration template is `honeyd/windows.conf.in`.

- **Checksum offload.** On a veth, bridge or tap network, the sender leaves TCP checksums to a network card that doesn't exist, and Honeyd drops every SYN as corrupt: ping still works, but every TCP port times out and SC_obs is 0/5. Turn offload off on the client (`ethtool -K eth0 tx off`), as the smoke test and the lab do. A physical wire doesn't need this.
- The container names `t2-honeyd` (the lab) and `honeyd-t2` (the smoke test) are already in use.

**5. On a real network card,** Honeyd needs root, because it sends raw frames: see §0 of [honeyd/HONEYD_SETUP.md](honeyd/HONEYD_SETUP.md). Rootful podman has its own image store, so build the image again with `sudo` or copy it with `podman save localhost/honeyd:a0f3d64 | sudo podman load`.

§§1–9 of `HONEYD_SETUP.md` and the "Build, install and route" part of `RUNBOOK.md` §1 predate the container and are superseded.

## Running STAGED vs Honeyd

The comparison lab runs real scanners against each target, R times per tool, on one machine, rootless:

| Target | What it is | Address |
|---|---|---|
| T1 | STAGED: this repository, mounted read-only, every driver | 10.0.0.40 |
| T2 | Honeyd, as above | 10.0.0.50 (container at 10.0.0.2) |
| T3 | A real unpatched Windows host: the top of the scale | not available in this lab |
| T4 | A real patched Windows host: the negative reference | not available in this lab |
| T5 | An inert socket that accepts on 445 and 3389 and never answers: the floor | 10.0.0.70 |

The scanner container is at 10.0.0.9. The podman network `honeylab` is internal, without DNS, and `run_all.sh` refuses to start if the scanner can reach the internet.

| Attack | Port | Tools |
|---|---|---|
| `eternalblue` | 445 | msf `smb_ms17_010`; msf `ms17_010_eternalblue` `check`; nmap `smb-vuln-ms17-010` |
| `bluekeep` | 3389 | msf `cve_2019_0708_bluekeep`; rdpscan; nmap `rdp-enum-encryption` |
| `ms12_020` | 3389 | msf `ms12_020_check` |

Before every run the decoy is restarted with its logs cleared, and the scanner's traffic is captured. The lab keeps, per run, the pcap, the observer's score (SC_obs), the tool's output, the decoy's log and its container cost, and for T1 the session records (SC_int). The cells run in random order.

### Requirements

- Linux with rootless podman and cgroup v2 (the cost columns read the containers' `memory.peak` and `cpu.stat`), and `python3` on the host.
- Internet access the first time, to build `localhost/honeyd:a0f3d64` and `localhost/sc-scanner` (about 2.5 GB). `lab.sh up` builds whichever is missing.
- No root.

### Quick run (R = 1, about 5 minutes)

```bash
OUT=$PWD/honeyd/lab/results/try R=1 ./honeyd/lab/run_all.sh
python3 honeyd/lab/report.py honeyd/lab/results/try > honeyd/lab/results/try/REPORT.md
./honeyd/lab/lab.sh down
```

The table for each attack is printed as it goes. Expect STAGED at 5/5 with every tool except nmap `rdp-enum-encryption` (3/5), Honeyd at 2/5, 2/5 and 1/5 on SMB and 0/5 on RDP, and the inert socket at 0/5 everywhere. `REPORT.md` adds the tools' verdicts, SC_int against SC_obs, and the cost per run.

### Full run (R = 30, about 90 minutes)

```bash
OUT=$PWD/honeyd/lab/results/<new-run> ./honeyd/lab/run_all.sh
```

Always set `OUT`. It defaults to `honeyd/lab/results/main`, the stored original run, whose files would be overwritten.

| Variable | Default | Meaning |
|---|---|---|
| `R` | `30` | Repetitions per target and tool |
| `OUT` | `honeyd/lab/results/main` | Where the run's files go: an absolute path inside `$LAB_RESULTS`. The scanner container only mounts that directory, so a run with `OUT` outside it produces no results |
| `ATTACKS` | `eternalblue bluekeep ms12_020` | Which attacks to run |
| `LAB_RESULTS` | `honeyd/lab/results` | The lab's working directory: container state and `versions.txt` |
| `T1_SRC` | the repository | The source tree T1 runs |

`run_all.sh` runs `lab.sh up` (images, network, containers), `lab.sh versions` (records every tool's version in `versions.txt`) and `lab.sh safety`, then, for each attack, `run_matrix.sh` and an `aggregate_sc.py` table. Each run leaves `<attack>_<target>_<tool>_r<i>.{pcap,json,log,decoy.log,cost.json}` in `$OUT`, plus `.sc_int/` and `.t1_logs/` for STAGED; each attack leaves `matrix_<attack>.out` and `table_<attack>.txt`.

### Reports

```bash
python3 honeyd/lab/report.py honeyd/lab/results/<run> > honeyd/lab/results/<run>/REPORT.md
python3 honeyd/lab/report.py --rescore honeyd/lab/results/<run>    # re-score the stored pcaps under the current stage rules
```

For each attack, `report.py` gives SC_obs per cell (each run scored by its deepest TCP session), the tool's own verdict, the stages reached, SC_int against SC_obs matched by client source port, and the median container cost. It regenerates the stored reports exactly.

### Other lab tools

| Command | Purpose |
|---|---|
| `./honeyd/lab/lab.sh up`, `down`, `status` | Start, remove or list the lab containers (results are kept) |
| `./honeyd/lab/lab.sh versions`, `safety` | Record tool versions; prove there is no route off the host |
| `./honeyd/lab/lab.sh restart <target>` | Restart a decoy (`STAGED`, `Honeyd` or `Inert`) with its logs cleared |
| `./honeyd/lab/lab.sh exec <cmd…>` | Run a command in the scanner container |
| `./honeyd/lab/checks.sh` | Ping, port and SMB probe of every decoy, scored from a real capture (lab up) |
| `./honeyd/lab/idle_cost.sh` | Each decoy's start-up cost with no scan (R = 10) |
| `./honeyd/lab/diag_bluekeep_verbose.sh` | Verbose BlueKeep verdicts: Metasploit's scanner otherwise prints only VULNERABLE ones |
| `./honeyd/lab/whatif/run_whatif.sh` | Historical: the first RDP fixes as a patch on the original code. The patch applies to `d29f66e`, not to the current code, which already contains the fixes |

These scripts write into `honeyd/lab/results/` by default, where the stored runs live under version control.

To run one cell by hand, with the lab up:

```bash
./honeyd/lab/lab.sh up
cd honeyd/sc_toolkit
EXEC="../lab/lab.sh exec" RESTART="../lab/lab.sh restart" COLLECT="../lab/lab.sh collect" \
  ONLY="STAGED" IFACE=eth0 TCPDUMP_OPTS="-Z root" R=1 OUT=../lab/results/single ./run_matrix.sh ms12_020
python3 sc_observer.py --pcap ../lab/results/single/ms12_020_STAGED_msf_ms12_020_r1.pcap --attack ms12_020
```

The procedure, the reasoning behind the stage rules and every finding are in [honeyd/RUNBOOK.md](honeyd/RUNBOOK.md) (§8 covers this lab), [honeyd/lab/FINDINGS.md](honeyd/lab/FINDINGS.md) and [honeyd/sc_toolkit/experimental_protocol.md](honeyd/sc_toolkit/experimental_protocol.md).

## Results

The numbers to cite come from `honeyd/lab/results/decided/`: R = 30, 630 runs, framework commit `54ab944`. Every cell was deterministic, with the same value in all 30 runs. Each cell shows SC_obs per run (its deepest session), then the tool's verdict or what stopped it.

| Attack | Tool | T1 STAGED | T2 Honeyd | T5 inert |
|---|---|---|---|---|
| EternalBlue | msf `smb_ms17_010` | 5/5, VULNERABLE ×30 | 2/5, tree connect denied | 0/5 |
| | msf `ms17_010_eternalblue` `check` | 5/5, VULNERABLE ×30 | 2/5, unknown | 0/5 |
| | nmap `smb-vuln-ms17-010` | 5/5, VULNERABLE ×30 | 1/5, no result | 0/5 |
| BlueKeep | msf `cve_2019_0708_bluekeep` | 5/5, VULNERABLE ×30 | 0/5, port reset | 0/5 |
| | rdpscan | 5/5, VULNERABLE ×30 | 0/5, port reset | 0/5 |
| | nmap `rdp-enum-encryption` | 3/5, enumerated (no verdict) | 0/5, port reset | 0/5 |
| MS12-020 | msf `ms12_020_check` | 5/5, VULNERABLE ×30 | 0/5, port reset | 0/5 |

- **SC_int = SC_obs** on every compared session, and no session record was lost.
- **Cost** per run (median of the container's cgroup counters, start-up included): STAGED about 17.8 MiB and 225–249 ms of CPU, Honeyd 12–14.5 MiB and 51–61 ms, the inert socket 5.7 MiB and about 23 ms. With no scan at all (`idle_cost.sh`) the figures are 17.8 MiB and 235 ms, 12.0 MiB and 47 ms, and 5.6 MiB and 25 ms: a scan adds nothing measurable to STAGED.
- **Honeyd** stops where its stock script does, at the denied tree connect. Against Nmap it gets one stage fewer: Nmap asks for extended security in its Negotiate, the script answers without it, and Nmap then sends no Session Setup.

Limitations:

- **T3 and T4 were not run.** There was no hypervisor or Windows image, so the top of the scale is not anchored, and every VULNERABLE above is a scanner's verdict on a decoy.
- **The stage rules were settled after the data was seen.** They are applied uniformly to every attack, target and run, older runs included, and the baselines don't move under them.
- **The MS12-020 verdict depends on the reply batching** disclosed in [MS12-020](#ms12-020-rdp).

The earlier runs are kept as the record: `results/main` (the original code, `d29f66e`) and `results/fixed` (after the RDP fixes, `fd136d2`), each with a `REPORT-rescored.md` under the current rules. The code changes since `54ab944` only touch labels and the `deception_success` flag, and change no number above.

> **Old commit IDs.** `FINDINGS.md`, `RUNBOOK.md` and the stored `versions.txt` files cite commit IDs from before the repository's history was rewritten. The file trees did not change: `0564e0d` is now `d29f66e`, `b02681d` is `fd136d2`, and `6e183c4` is `54ab944`. The stored records also use older names: `XXX` as STAGED's target name and "Exploit PDU" for BlueKeep's stage 5.

## Writing a new driver

1. Find a real reconnaissance scanner for the CVE: a Metasploit `auxiliary/scanner/` module or an equivalent. It must not be an exploit module, even in `check` mode, nor a script categorised as intrusive or dos.
2. Read the scanner's source or capture its traffic, and split the exchange into stages. Each message after which the scanner waits for a specific answer is a stage, and the list ends at the exchange the scanner takes its verdict from.
3. Write `drivers/<name>.py`. Subclass `StagedDriver` directly to own a port, or a family base (`smb.SMBFamilyDriver`, `rdp.RDPFamilyDriver`) to share a protocol trunk and port with other drivers.
4. Run `python3 -m framework.launcher --list`: drivers are discovered automatically, and the `--driver` key is the metadata name in lower case.

A standalone driver has this shape:

```python
# drivers/my_protocol.py
from framework import StagedDriver, DriverMetadata, StageDefinition, SCTracker


class MyProtocolDriver(StagedDriver):

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
        # Bind the port and serve connections. For each connection:
        #   t = tracker.fork()
        #   t.new_session(source_ip=ip, source_port=src_port)
        #   t.complete_stage(n, "Stage name", source_ip=ip, data={...})   as the scanner advances
        #   t.note_activity_beyond_n("what it did", {...})                  for anything after stage N
        #   t.finalize_session(deception_success=(t.get_sc() == 1.0))
        ...

    def stop(self) -> None:
        ...
```

- Use one tracker per connection (`tracker.fork()`): connections that share a tracker overwrite each other's session.
- Set `deception_success` only at SC = N, and send anything after stage N to `note_activity_beyond_n()`.
- In a driver, import a family as a module (`from families import smb`), never its classes. Discovery instantiates every `StagedDriver` subclass it finds in a driver's namespace, and an abstract base imported by name aborts it.

[drivers/README.md](drivers/README.md) covers new drivers and new variants of an existing family, [families/README.md](families/README.md) covers dispatch and new families, and [framework/README.md](framework/README.md) covers the core API.

## Scope and safety

- **Reconnaissance only.** Every driver corresponds to a real, safe, non-invasive scanner, never to an exploit. A second SMBv1 CVE, MS08-067, was evaluated and dropped for this reason: Metasploit has no MS08-067 scanner (only the exploit `ms08_067_netapi`), and Nmap's `smb-vuln-ms08-067` is categorised `intrusive`, `exploit` and `dos`; its own documentation warns that a vulnerable system is more likely to crash than to survive the check. SMB1-Recon keeps a single member until an SMBv1 CVE with a dedicated safe scanner turns up.
- **Only on networks you control.** The decoys listen on every interface. The lab's network has no route off the host, and the exploit module is only ever used with `check`.
