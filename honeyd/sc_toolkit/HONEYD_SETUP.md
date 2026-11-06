# Setting up Honeyd (target T2)

## 0. Verified path (2026-11-05): container build + smoke test

Sections 1–9 below were written before Honeyd had been built. It has now been
built and run, and several predictions there were **wrong**. Use this path; the
rest of the document is kept for its reasoning.

```bash
# build: rootless, Debian bookworm, GCC 12, Honeyd pinned at a0f3d64 (V1.6d)
podman build -t localhost/honeyd:a0f3d64 -f honeyd/Containerfile honeyd/

# prove it answers: isolated podman bridge 10.0.0.0/24, no root, no real NIC
./honeyd/smoke_test.sh          # outputs -> honeyd/smoke_out/
```

Smoke test result, against **real Honeyd** and a **real tcpdump capture**:
ping answered with TTL 128 (the Windows personality is applied), 445 open, 3389
refused, `SC_obs = 2/5` (Negotiate, Session Setup). That matches the
`honeyd_inetd.py` estimate.

To run it on the lab NIC (needs root, because Honeyd sends raw frames):

```bash
sudo podman run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
     -e HONEYD_IFACE=<lab-nic> -e HONEYD_IP=10.0.0.50 \
     -e HONEYD_MAC=00:1b:21:3a:4f:50 localhost/honeyd:a0f3d64
```

Rootful podman has its own image store, so build the image once with
`sudo podman build ...` too, or copy it across with
`podman save localhost/honeyd:a0f3d64 | sudo podman load`.

The full RUNBOOK comparison built on this image (all targets, all scanners, R=30) is in
`honeyd/lab/` (see RUNBOOK §8 and `honeyd/lab/FINDINGS.md`).

What the real build and run showed, and where it contradicts §§1–8:

| Finding | Effect | Fix (in `Containerfile` / `windows.conf.in`) |
|---|---|---|
| Globals defined in headers; GCC ≥10 defaults to `-fno-common` | link fails: `multiple definition of 'libevent_base'` | `CC="gcc -fcommon"`. **Not** `CFLAGS`: `Makefile.am` hard-codes `CFLAGS`, so the §3 flags are silently ignored |
| Repo commits `ltmain.sh` as a symlink to a 2013 libtool path | `./autogen.sh` → `libtool: Version mismatch error` | `rm -f ltmain.sh && autoreconf -fi` instead of `./autogen.sh` |
| `fdpass.o` is built twice under parallel make | link fails at random (`cannot find fdpass.o`), 1 in 3 builds | `make -j1` (4/4 clean builds pass) |
| `make install` runs `python scripts/lib/init.py` (Python 2) | install fails: `python: command not found` | shim `python` → `/bin/true` during install. That step only seeds a names DB for other stock scripts |
| §6 is wrong: Honeyd answers ARP itself once the host has a MAC | farpd and static ARP are both unnecessary | `set <ip> ethernet "<mac>"` |
| `bind` clones the template and **randomises the low 3 MAC bytes** | a template-level MAC changes on every start | set the MAC on the bound IP, **after** `bind` |
| Honeyd demotes to `nobody` **before** opening its logs | `fopen(...honeyd.log): Permission denied` (non-fatal, but no logs) | `chown 65534 /var/log/honeyd` in `entrypoint.sh` |
| Over veth/bridge/tap, TCP checksums are left for a NIC to fill in | Honeyd drops every SYN (bad checksum); ping still works | on the **sender**: `ethtool -K <if> tx off`. Not needed over a physical wire |

The last row matters for the runbook: if the scanner and Honeyd share one Linux
host and traffic goes over a bridge/veth/tap, turn off TX checksum offload on the
scanner's interface. Otherwise Honeyd scores 0/5 for a reason unrelated to its
SMB behaviour.

---

Honeyd is a 2004 codebase. Nothing about installing it is one command, and two
steps are not in its README at all. Everything marked **[verified]** below was
checked against the source tree (DataSoft/Honeyd, shallow clone, this week);
everything marked **[expected]** is a prediction you should confirm on your box.

---

## 1. Packages

The authoritative list is the project's own `debian/control`, `Build-Depends`
**[verified]**:

```bash
sudo apt install -y automake autoconf libtool \
                    libevent-dev libpcap-dev libdumbnet-dev \
                    zlib1g-dev libpcre3-dev libreadline-dev \
                    flex bison wget sharutils
```

Two traps here:

- **It is `libdumbnet-dev`, not `libdnet-dev`.** Debian renamed libdnet because
  of a name clash, and `configure.in` carries an explicit branch for it
  ("whether libdnet is a libdumbnet"). Installing `libdnet-dev` gives you a
  different library and the build will not find what it wants. **[verified]**
- `autoconf` and `libtool` are **not** in `Build-Depends` but `autogen.sh` calls
  `aclocal`, `autoheader`, `libtoolize`, `autoconf` and `automake`, so you need
  them anyway. **[verified]**

---

## 2. Source, and the step people skip

```bash
git clone https://github.com/DataSoft/Honeyd.git
cd Honeyd
./autogen.sh          # <-- REQUIRED FIRST, see below
./configure --prefix=/usr/local
```

`config.sub` and `config.guess` are **not in the repository** **[verified]**.
If you run `./configure` first you get, immediately:

```
configure: error: cannot run /bin/sh ./config.sub
```

That is not a missing dependency — it means `automake --add-missing --copy`
(which `autogen.sh` runs) has not supplied those two files yet. Run
`./autogen.sh`, then configure.

---

## 3. Build against a modern compiler

```bash
make -j"$(nproc)"
```

**[expected]** GCC 14 and newer promote `implicit-function-declaration` and
`int-conversion` from warnings to errors, and this is pre-C99 code. If the build
stops on either, relax it rather than editing the sources:

```bash
make clean
./configure --prefix=/usr/local \
  CFLAGS="-g -O2 -std=gnu89 -Wno-error=implicit-function-declaration -Wno-error=int-conversion"
make -j"$(nproc)"
sudo make install
```

Record the commit you built (`git rev-parse --short HEAD`) for the paper.

---

## 4. The fingerprint database

Honeyd's personalities come from an nmap-format fingerprint file passed with
`-p`. The tree ships `nmap-os-db`: 3.1 MB, **3572 fingerprints**
**[verified]**. `nmap.prints`, which older documentation refers to, is *not*
present.

The personality string in your config must match a `Fingerprint` line
**exactly**, or Honeyd refuses to start. Both of these exist **[verified]**:

```
Microsoft Windows XP Professional SP1
Microsoft Windows 7
```

Use **`Microsoft Windows 7`**, so Honeyd presents the same operating system as
your real unpatched target (T3). Matching them removes a confound a reviewer
would otherwise raise.

Check any string before you trust it:

```bash
grep -c '^Fingerprint Microsoft Windows 7$' nmap-os-db
```

---

## 5. Configuration

`/usr/local/share/honeyd/windows.conf`:

```
create windows
set windows personality "Microsoft Windows 7"
set windows default tcp action reset

add windows tcp port 445  "/usr/bin/python3 /opt/scripts/smb-autofail-py3.py x /opt/scripts/smb.conf"
add windows tcp port 3389 "/bin/sh /opt/scripts/nostock-rdp.sh"

bind 10.0.0.50 windows
```

- `default tcp action reset` makes every unlisted port refuse rather than hang,
  which is what a real host does and keeps your scan times sane.
- The SMB script takes its personality strings from a file given as its
  **second** argument, hence the `x` placeholder in first position
  **[verified]** — it reads `sys.argv[2]`.
- There is no stock RDP script, so port 3389 gets whatever you write. Say so in
  the paper rather than leaving the row unexplained.

`/opt/scripts/smb.conf`:

```
NATIVE_OS Windows 5.1
LAN_MANAGER Windows 2000 LAN Manager
PRIMARY_DOMAIN WORKGROUP
TIME_ZONE 0
```

---

## 6. Getting packets to the virtual address — the step that actually blocks you

**This is the part my earlier runbook omitted, and it is where Honeyd setups
stall.** Honeyd answers for addresses that no interface owns, so something must
reply to ARP for `10.0.0.50` or no packet ever arrives. Honeyd's own
documentation says you "might need other tools like arpd or proxy arp"
**[verified]**, and the Debian package `Recommends: farpd` **[verified]**.

Pick one of the two.

### Option A — farpd (the documented way)

```bash
sudo apt install -y farpd
sudo farpd -d -i eth1 10.0.0.50
```

Leave it running in its own terminal. Note the FAQ's warning: answering ARP for
a whole unused range "often causes DHCP to stop working" **[verified]** — scope
it to the single address you bound, not a range.

### Option B — static ARP on the scanner (simpler for an isolated lab)

Because your testbed is host-only and you control the scanner, you can skip ARP
emulation entirely by telling the scanner where to send the packets. On the
**scanner** host:

```bash
sudo ip neigh replace 10.0.0.50 lladdr <MAC-of-honeyd-host-iface> dev eth1
sudo ip route add 10.0.0.50/32 dev eth1
```

Get the MAC with `ip link show eth1` on the Honeyd host. This is deterministic
and has no DHCP side effects, which is why I would use it for the experiment.

**Do not** `ip addr add 10.0.0.50/24` on the Honeyd host. The kernel would then
own the address and answer before Honeyd ever sees the connection — you would be
measuring Linux, not Honeyd.

---

## 7. Start it, and prove it is answering

Run in the foreground for the first attempt:

```bash
sudo honeyd -d -i eth1 -p /usr/local/share/honeyd/nmap-os-db \
            -f /usr/local/share/honeyd/windows.conf \
            -l /var/log/honeyd.log 10.0.0.50
```

`-d` keeps it in the foreground with debug output, so configuration errors are
visible instead of silently fatal.

Three checks, in order. Do not proceed past a failing one:

```bash
ping -c1 10.0.0.50                      # 1. ARP/routing works
nc -vz 10.0.0.50 445                    # 2. Honeyd accepts on the port
python3 probe_smb.py --host 10.0.0.50 --port 445 --pcap honeyd.pcap   # 3. the script speaks SMB
python3 sc_observer.py --pcap honeyd.pcap --attack eternalblue --target Honeyd
```

Check 1 failing means section 6, not section 5. Check 2 failing with check 1
passing means the config file or the personality string. Check 3 returning 0/5
with check 2 passing means the service script is not executing — look for a
Python 2 traceback, or a wrong path, in Honeyd's debug output.

---

## 8. Troubleshooting

| Symptom | Cause |
|---|---|
| `cannot run /bin/sh ./config.sub` | `./autogen.sh` not run first (§2) **[verified]** |
| configure cannot find libdnet | you installed `libdnet-dev`; it wants `libdumbnet-dev` (§1) **[verified]** |
| `libevent is too old` | `configure.in` requires `event_priority_init`; install `libevent-dev` **[verified]** |
| build dies on implicit declarations | modern GCC; use the `CFLAGS` in §3 **[expected]** |
| Honeyd exits at startup complaining about the personality | the string does not match a `Fingerprint` line in `nmap-os-db` exactly (§4) **[verified]** |
| No packets reach Honeyd; ping fails | ARP, not Honeyd — §6 |
| Port open but `SC_obs = 0/5` | the service script is not running; check the path and that it is Python 3 |
| Tree connect refused, `SC_obs` caps at 2/5 | **expected** — the stock script answers IPC$ with ACCESS_DENIED. That is the measurement, not a fault |

---

## 9. What I could not verify, and what to do if it will not build

This sandbox has no autotools, no `libpcap`/`libdnet`/`libevent` headers and no
root, so **the compile itself was never run**. Sections 1, 2, 4, 5 and 6 come
from the source tree and its packaging; section 3 is a prediction.

If the build defeats you, you still have two honest options, and neither is
inventing a number:

1. **Report the build failure.** "Honeyd could not be built against a current
   toolchain" is a legitimate, interesting observation about a system that
   Section 3 presents as the extensible baseline.
2. **Report the script's stage depth through the stdio wrapper**, as
   `honeyd_inetd.py` does, labelled as exactly that — the stage depth of
   Honeyd's stock SMB script under Honeyd's documented script contract, measured
   without Honeyd's TCP stack. That figure was **2/5** here.

What you must not do is call either of those "Honeyd" without the qualifier.
