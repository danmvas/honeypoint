# How to run the comparison

Everything below assumes the protocol in `experimental_protocol.md`. The one
instrument you cannot improvise is the observer; it is written and validated
(`sc_observer.py`, see §6 for what was checked).

---

## 0. Before anything: isolate and pin

The testbed is a host-only network with **no route to the campus network or the
Internet**. One Linux host runs the decoys and the capture; one VM is the real
Windows target; the scanner can run on the Linux host.

Record these once and put them in the paper:

```bash
msfconsole --version ; nmap --version | head -1 ; rdpscan --help 2>&1 | head -1
git -C /path/to/honeypoint rev-parse --short HEAD
honeyd --version 2>&1 | head -1
```

---

## 1. Bring up the five targets

Give each target its own IP so a single capture can be filtered per target.

### T1 — your honeypoint

```bash
cd /path/to/honeypoint
sudo systemctl stop smbd nmbd xrdp          # free 445 and 3389
sudo HONEYPOINT_LOG_DIR=/var/log/honeypoint python3 -m framework.launcher
```

Both RDP variants bind 3389 together, so the dispatch is exercised by the same
runs. Keep `/var/log/honeypoint/sc_*.json` — those are your `SC_int` values.

### T2 — Honeyd

Two facts decide how this target is configured, both checked against the
Honeyd source tree (DataSoft/Honeyd, 434 files, 139 service scripts):

- **The only SMB script Honeyd ships is `scripts/misc/smb-autofail.py`.** It
  answers four SMB commands — Negotiate (0x72), Session Setup (0x73), Tree
  Connect (0x75) and Tree Disconnect (0x71) — and sends an error for anything
  else. Its Tree Connect answers NT status `0xC0000022`
  (STATUS_ACCESS_DENIED).
- **Honeyd ships no RDP script at all.** Every other script in the tree is a
  banner-level emulator for a text protocol (telnet, ftp, pop3, imap, smtp,
  http, snmp, ldap, finger, mssql, mysql, dns).

So the fair baseline is: give Honeyd its own stock SMB script, and for RDP
report that no stock script exists.

#### Build, install and route

> **Superseded (2026-11-05).** The commands below were never run and do not
> work as written (link errors with modern GCC, a libtool mismatch, a parallel
> make race, and ARP handled by Honeyd itself). Use `HONEYD_SETUP.md` §0 (the
> verified container build) and §8 of this runbook. They are kept here for the
> reasoning.

**Setup is a document of its own: see `HONEYD_SETUP.md`.** It is not one command,
and two of its steps are in neither the README nor my first draft of this
runbook. The short version:

```bash
sudo apt install -y automake autoconf libtool libevent-dev libpcap-dev \
                    libdumbnet-dev zlib1g-dev libpcre3-dev libreadline-dev \
                    flex bison wget sharutils
git clone https://github.com/DataSoft/Honeyd.git && cd Honeyd
./autogen.sh && ./configure --prefix=/usr/local && make -j"$(nproc)"
sudo make install
```

Four things that will stop you, all covered in `HONEYD_SETUP.md`:

1. **`libdumbnet-dev`, not `libdnet-dev`** — Debian renamed it and `configure.in`
   branches on it explicitly.
2. **`./autogen.sh` must run before `./configure`** — `config.sub` and
   `config.guess` are not in the repository, and configure dies on
   `cannot run /bin/sh ./config.sub` without them.
3. **The personality string must match a `Fingerprint` line in `nmap-os-db`
   exactly**, or Honeyd will not start. Use `"Microsoft Windows 7"` so the
   baseline presents the same OS as the real unpatched target.
4. **Something must answer ARP for the virtual address.** Honeyd answers for
   addresses no interface owns, so either run `farpd`, or — simpler in an
   isolated lab — pin a static ARP entry and a host route on the scanner. Do
   *not* `ip addr add` the address on the Honeyd host; the kernel would then
   answer before Honeyd sees anything.

Prove it is answering before you run any matrix:

```bash
ping -c1 10.0.0.50 && nc -vz 10.0.0.50 445
python3 probe_smb.py --host 10.0.0.50 --port 445 --pcap honeyd.pcap
python3 sc_observer.py --pcap honeyd.pcap --attack eternalblue --target Honeyd
```

#### Develop and measure the script without a working Honeyd

Honeyd's extension point is a program whose stdin and stdout are the TCP
connection. `honeyd_inetd.py` reproduces that contract, so the script can be
exercised before the build is working:

```bash
sudo python3 honeyd_inetd.py --port 445 -- \
     python3 honeyd/smb-autofail-py3.py x honeyd/smb.conf
python3 probe_smb.py --host 127.0.0.1 --port 445 --pcap honeyd.pcap
python3 sc_observer.py --pcap honeyd.pcap --attack eternalblue --target Honeyd
```

**This reproduces the application-layer contract only** — the exact bytes the
script sees and emits, which is what SC measures. It does **not** reproduce
Honeyd's simplified TCP state machine, its personality engine or its virtual
routing. A figure obtained this way is an estimate of the script's stage depth
and must be labelled as such; confirm it against a real Honeyd before the number
goes in the paper as "Honeyd".

#### What this already produced here

Running the stock script behind the wrapper, with the same probe and the same
observer used against the honeypoint:

| Target | `SC_obs` | Stages reached |
|---|---|---|
| Honeyd, stock `smb-autofail` | **2/5** | SMB Negotiate, Session Setup |
| Honeypoint EternalBlue driver | **5/5** | all five (`SC_int` agreed) |

Honeyd stops at stage 3 because its stock script denies the IPC$ tree connect,
so the scanner never issues the named-pipe probe that carries the verdict. Note
what that means for the paper: Honeyd sustains the *generic* part of the SMB
handshake and fails at the *vulnerability-specific* part — which is exactly the
division between the family trunk and the driver divergence in Section 4.

Treat 2/5 as preliminary. It was obtained with a hand-written probe, through the
wrapper rather than Honeyd itself, and against a port of the script.

> **If Honeyd will not build**, do not silently substitute something else.
> Either report the build failure as the reason, or report the wrapper figure
> explicitly labelled as the stock script's stage depth under Honeyd's documented
> contract — never as Honeyd itself.

### T3 — real unpatched host

A Windows 7 SP1 VM with MS17-010 and CVE-2019-0708 **not** installed, snapshot
taken, network adapter host-only. `bind 10.0.0.60`.

### T4 — real patched host

Same image, fully updated. `10.0.0.61`.

### T5 — inert socket

```bash
sudo python3 - <<'EOF'
import socket, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(32)
    while True:
        c, _ = s.accept(); threading.Timer(30, c.close).start()   # accept, never answer
for p in (445, 3389):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
EOF
```

---

## 2. Run the matrix

`run_matrix.sh` loops over targets x tools x repetitions, captures each run to
its own pcap, and scores it. Edit the IPs at the top, then:

```bash
sudo ./run_matrix.sh eternalblue        # or: bluekeep | ms12_020
```

One pcap and one JSON per run, under `results/`. Restarting the decoy between
runs matters: your tracker keeps one session per driver, so overlapping runs can
interleave (see §5).

---

## 3. Score a capture by hand

```bash
python3 sc_observer.py --pcap results/run.pcap --attack eternalblue \
        --target "Honeyd" --tool "msf smb_ms17_010" --json results/run.json
```

```
10.0.0.9:51234 -> 10.0.0.50:445  SC_obs = 2/5 (40%)  stages=[1, 2]
    1. SMB Negotiate
    2. Session Setup
```

A stage counts only when **both** the client request and the server response are
present. A decoy that takes the probe and stays silent scores 0, which is the
behaviour that distinguishes a decoy from an open port.

---

## 4. Build the tables

```bash
python3 aggregate_sc.py --glob 'results/*.json' --attack eternalblue --latex
```

It prints the per-cell values, flags any cell that was **not** deterministic
across its R runs, and emits LaTeX rows to paste into `5-Evaluation.tex`. Report
zero variance explicitly where you find it — it is a stronger statement than a
mean, and it is what you should expect from deterministic scanners.

---

## 5. The third result: SC_int against SC_obs

For each honeypoint session, match the driver's own record to the observer's by
source port and compare:

```bash
python3 - <<'EOF'
import json, glob
obs = {(r["client"].split(":")[1]): r for f in glob.glob("results/*.json")
       for r in json.load(open(f)) if r["target"].startswith("XXX")}
for f in sorted(glob.glob("/var/log/honeypoint/sc_*.json")):
    j = json.load(open(f))
    port = str(j["events"][0]["source_port"]) if j["events"] else None
    o = obs.get(port)
    if o:
        print(f, "SC_int", j["completed_stages"], "SC_obs", o["completed_stages"],
              "AGREE" if j["completed_stages"] == o["completed_stages"] else "DIFFER")
EOF
```

**Expect a mismatch on RDP.** Your tracker credits stage 2 without any exchange
(`families/rdp.py`, "Security Negotiation (sintética — sem troca de dados)"),
while the observer credits it only if the Connection Confirm actually carried an
RDP negotiation response. For your own decoy both hold, so they agree; for a
decoy that answers the Connection Request without a negotiation response they
will not. That difference is a finding, not a bug — report it.

`StageEvent.source_port` is currently never populated (always 0), so the match
above needs that fixed first, or match on timestamps instead.

---

## 6. What was already validated, and what was not

Checked on this machine, against your real drivers:

| Check | Result |
|---|---|
| `SC_obs` vs `SC_int`, EternalBlue, full 5-stage exchange | both 5/5 |
| EternalBlue degradation ladder (truncating the client) | 5, 4, 3, 2, 1 |
| Decoy receives probes but never answers | 0/5 |
| BlueKeep capture, BlueKeep scorer | 5/5 |
| MS12-020 capture, MS12-020 scorer | 5/5 |
| Cross-scoring (each scorer on the other's capture) | 4/5 and 3/5, as expected |
| Family dispatch on a shared port | BlueKeep and MS12-020 sessions each resolved to the right variant |
| Honeyd stock SMB script, via the stdio wrapper | 2/5 (Negotiate, Session Setup) |
| Tree connect answered ACCESS_DENIED is not credited | stage 3 withheld |

**Not** validated, and you must confirm before trusting a number:

- No real scanner has driven the observer. The probes above were written by hand
  against your drivers' parsers. Run `msf smb_ms17_010` against T1 once and check
  the observer reports what the driver reports.
- No real `tcpdump` capture has been parsed; this sandbox has no `CAP_NET_RAW`,
  so the pcaps were synthesised. The reader handles classic pcap (both
  endiannesses, microsecond and nanosecond) and Ethernet/`\lo`/SLL link types,
  but **capture with `tcpdump -w`**: pcapng is rejected with a message telling
  you to convert with `editcap -F pcap`.
- Honeyd itself has not run: the figure above came from its stock script behind
  `honeyd_inetd.py`, not from a Honeyd deployment, and the script was ported from
  Python 2.
- Nothing has run against a real Windows host.
- TCP reassembly tolerates loss by zero-filling gaps; a capture with heavy drop
  will under-report. Capture with `-s0` on the decoy host itself.

---

## 7. Safety checklist

- [ ] Testbed has no route off-host.
- [ ] Exploitation modules are pointed only at T1, T2 and T5 — **never** at T3.
- [ ] T3 and T4 snapshots taken before the first run.
- [ ] Captures contain only lab traffic before you publish them.

---

## 8. Running all of it on one machine (podman lab, verified 2026-11-05)

Sections 0–7 were run end to end on one Fedora workstation, rootless, with no
sudo. Everything is in `honeyd/lab/`, and the results and defects found are in
`honeyd/lab/FINDINGS.md`.

```bash
podman build -t localhost/honeyd:a0f3d64 -f honeyd/Containerfile honeyd/   # once
./honeyd/lab/run_all.sh          # s0 versions, s7 isolation, s2 matrix, s4 tables (R=30, ~90 min)
./honeyd/lab/checks.sh           # HONEYD_SETUP s7 checks against every decoy
python3 honeyd/lab/report.py honeyd/lab/results/main > REPORT.md   # tables, verdicts, s5, cost
```

How the lab maps onto this runbook:

- **Network.** The podman network `honeylab` is created with `--internal` and
  `--disable-dns`: no NAT, no default route, checked by `lab.sh safety`
  (s0/s7). The addresses are those of s1. The scanner (Metasploit, Nmap,
  rdpscan, tcpdump) is a container at 10.0.0.9.
- **Targets.** T1 runs this repository read-only in `python:3.14-slim`; its
  `logs/` and `HONEYPOINT_LOG_DIR` are bind-mounted out. T2 is the Honeyd image
  (stock `smb-autofail` on 445; 3389 resets, since there is no stock RDP script).
  T5 is the s1 snippet verbatim. **T3/T4 were not run**: there is no
  hypervisor or Windows image on that machine.
- **`run_matrix.sh` hooks.** `EXEC` runs capture + tool in the scanner,
  `RESTART` restarts the decoy and clears its logs before every run (protocol
  s3), `COLLECT` keeps each run's decoy log, `sc_*.json` and cgroup cost next to
  its pcap, and `ONLY` restricts the targets. With all hooks unset the script
  behaves as before.
- **s4.** Use `aggregate_sc.py --per-run`. Pooling every TCP session counts
  nmap's payload-less SYN port probe as a 0/5 session and makes deterministic
  cells look non-deterministic.
- **s5.** `report.py` matches SC_int to SC_obs by client source port, recovered
  from T1's console log ("Nova conexão … ip:port" … "Encerrada"), because
  `source_port` is still always 0. This also covers `sc_*.json` files lost to
  same-second session IDs.
- **Two things needed only on a virtual network.** (1) Turn off TX checksum
  offload on the scanner (`ethtool -K eth0 tx off`); otherwise Honeyd sees
  every SYN with a bad checksum and drops it. (2) Pin each container's MAC, so
  that a decoy restart does not leave the scanner with a stale ARP entry.

s6, updated: a real scanner has now driven the observer (Metasploit, Nmap,
rdpscan), real tcpdump captures were parsed (630 runs), and Honeyd itself ran.
Still not done: anything against a real Windows host.

Re-run after the framework fixes (framework commit `b02681d`, 2026-11-06):
`honeyd/lab/results/fixed/`. Both BlueKeep scanners now report T1 VULNERABLE
in 30/30 runs, and every cell is deterministic. What is still open (the
stage-2 rule on legacy requests, the MS12-020 verdict race, T3/T4) is in the
"Update" section of `honeyd/lab/FINDINGS.md`.
