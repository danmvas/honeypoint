# Honeypoint vs Honeyd: results of the RUNBOOK run (2026-11-05/06)

Everything in `RUNBOOK.md` and `HONEYD_SETUP.md` that can run on one machine,
run end to end in the podman lab in this directory. Raw data, per-run pcaps and
logs: `results/main/` (630 runs). Generated tables: `results/main/REPORT.md`.

**Setup.** Honeypoint at commit `0564e0d` (T1, unmodified), Honeyd V1.6d at
`a0f3d64` (T2, stock `smb-autofail` on 445, no RDP script, so 3389 resets), and the
inert socket (T5). Scanners: Metasploit 6.5.9-dev, Nmap 7.99, rdpscan `09db271`.
The network is internal (no route off-host, checked). R = 30, cell order randomised,
each decoy restarted and its logs cleared before every run, and one pcap per run
captured on the scanner. Versions: `results/main/versions.txt`.

**Not run: T3 and T4 (real Windows).** There is no hypervisor and no Windows 7
image on this machine, so the top of the scale is not anchored yet. Every
"VULNERABLE" below is the scanner's verdict on a decoy. Nothing was checked
against a real host.

## Update (2026-11-06): after the fixes, framework commit `b02681d`

Defects F1–F8 below are fixed in `b02681d`; the RDP connection is now carried
through to the scanner's MS_T120 probe. The lab, scanners, observer and R = 30
are unchanged. Data: `results/fixed/` (630 runs, every run scored, provenance in
`results/fixed/versions.txt`). **Every SC_obs cell was deterministic.**

| T1 (your framework) | before (`0564e0d`) | after (`b02681d`) |
|---|---|---|
| EternalBlue: msf scanner / msf check / nmap | 5/5, 5/5, 4/5; all VULNERABLE | **unchanged** |
| msf BlueKeep scanner | 5/5 (29), 3/5 (1); **not vulnerable** | 5/5 ×30; **VULNERABLE ×30** |
| rdpscan | 3/5 (24), 5/5 (6); UNKNOWN | 5/5 ×30; **VULNERABLE ×30** |
| nmap `rdp-enum-encryption` | 3/5 | 2/5 (see I1) |
| msf `ms12_020_check` | 2/5; "Could not connect to RDP" | 3/5 (stages 1, 3, 4); SAFE ×29, VULNERABLE ×1 |
| SC_int records lost to same-second IDs | 224 of 360 | **0** |

Honeyd and the inert socket gave exactly the same values as before in every cell,
which is a useful check that the testbed didn't drift between runs.

**SC_int vs SC_obs, per session by source port:** SMB 90/90; msf BlueKeep 60/60
(30 BlueKeep sessions plus its 30 fingerprint connections, now filed under
`RDP-Recon`); rdpscan 30/30; nmap 150/270; msf MS12-020 0/30. **All 150
disagreements are one thing: stage 2 on a legacy request** (no `RDP_NEG_REQ`).
The tracker credits its synthetic "Security Negotiation"; the observer requires
an `RDP_NEG_RSP`, which a correct server no longer sends there. This is exactly
the mismatch RUNBOOK §5 predicted. It was hidden before only because of F1
(`RDP_NEG_RSP` was always sent). It drops to zero once I1 is decided.

**What is still open**

1. **I1 (your decision): stage 2 on legacy requests.** Either the observer
   credits stage 2 when the request had no `RDP_NEG_REQ` and the server answered
   with a Connection Confirm, or the tracker stops crediting it there. In the
   second case MS12-020 tops out at 4/5 for every target, Windows included.
   Either way SC_int = SC_obs everywhere again.
2. **The MS12-020 verdict is a race inside Metasploit.** The module sends
   Connect Initial and Attach User back to back, then reads once per request,
   and takes the user id from whatever the first read returns. Its own Nagle
   buffering holds back the Attach User Request until the Connect Response
   arrives, so that read usually holds the Connect Response alone. Every later
   read is then one reply behind, and the module checks an Attach User Confirm
   instead of the Channel Join Confirm: SAFE. In run r18 the first read caught
   both replies, the reads lined up, and the verdict was VULNERABLE.
   The framework could make this deterministic by sending the Connect Response
   together with the first Attach User Confirm (holding it a few milliseconds).
   Whether Windows does that needs the T3 capture, so it hasn't been done.
3. **Decision 1 / I2.** The observer still credits BlueKeep stage 5 on any
   client Send Data. It no longer changes a number, since T1 now reaches the
   probe and 5/5 coincides with VULNERABLE, but it would for a decoy that stops
   after the Security Exchange.
4. **T3/T4.** Still missing.

**Claims supported now:** five scanner implementations judge T1 VULNERABLE with
zero variance across 30 runs: Metasploit's MS17-010 scanner and check, Nmap
`smb-vuln-ms17-010`, Metasploit's BlueKeep scanner, and rdpscan. Honeyd gets
none. MS12-020 isn't there yet (item 2). On BlueKeep the two independent
implementations now agree (5/5, VULNERABLE). The cost is unchanged: T1 about
17.8 MiB and 214–241 ms CPU per run.

The sections below describe the original run at `0564e0d` and are kept as the record.

## Table 2 — SMB / EternalBlue (N = 5)

SC_obs per run, as the deepest TCP session of the run. All cells were
deterministic: the same value in all 30 runs.

| target | msf `smb_ms17_010` | msf `ms17_010_eternalblue` check | nmap `smb-vuln-ms17-010` |
|---|---|---|---|
| T1 honeypoint | **5/5**, VULNERABLE | **5/5**, "The target is vulnerable" | **4/5**, VULNERABLE |
| T2 Honeyd | 2/5, error: STATUS_ACCESS_DENIED at IPC$ | 2/5, Unknown | 1/5, no result |
| T5 inert | 0/5 | 0/5 | 0/5 |

Honeyd stops where the runbook predicted (tree connect denied). Under nmap it
gets one stage fewer: nmap's Negotiate asks for extended security
(flags2 0x6845), Honeyd's script answers without it (flags2 0x41c8), and nmap
then sends no Session Setup. T1's 4/5 under nmap is Decision 1 again: nmap stops
at the verdict (stage 4), while Metasploit sends the post-verdict transaction.

## Table 3 — RDP / BlueKeep and MS12-020 (N = 5)

| target | msf BlueKeep scanner | rdpscan | nmap `rdp-enum-encryption` | msf `ms12_020_check` |
|---|---|---|---|---|
| T1 honeypoint | 5/5 (29 runs), 3/5 (1 run); **not vulnerable** (Unknown) | 3/5 (24 runs), 5/5 (6 runs); UNKNOWN | 3/5 | **2/5**; "Could not connect to RDP" |
| T2 Honeyd | 0/5, refused | 0/5, refused | 0/5, port closed | 0/5 |
| T5 inert | 0/5 | 0/5 | 0/5 | 0/5 |

**No RDP tool judged T1 vulnerable.** The verbose diagnostic
(`results/diag/`) shows Metasploit getting as far as the client info PDU, then
"Error communicating RDP protocol", verdict Unknown. Both of T1's
non-deterministic cells come from one framing bug (F3 below).

## SC_int vs SC_obs (RUNBOOK §5)

Matched per session by client source port. The port comes from T1's console log,
because `StageEvent.source_port` is never filled (`report.py`).

| tool | sessions | agree |
|---|---|---|
| all three SMB tools | 90 | **90** |
| msf BlueKeep / rdpscan / msf MS12-020 | 60 / 30 / 30 | **all** |
| nmap `rdp-enum-encryption` | 270 | 240: T1 over-reports by one stage in 30 (F5) |

The runbook's predicted RDP mismatch (stage 2 is synthetic in the tracker) does
not show up at commit `0564e0d`. T1 always sends `RDP_NEG_RSP`, so both sides
credit stage 2. It appears as soon as F1 is fixed (see the what-if).

**Cost**, as the median per run of the container cgroup from start to the end of
the run (startup included): T1 ≈ 17 MiB and 210–220 ms CPU; Honeyd 12–15 MiB and
50–63 ms; inert 5.7 MiB and 24 ms.

## Defects found in the honeypoint (T1) — all fixed in `b02681d`

Line numbers refer to `0564e0d`. The fix commit also corrects the Connect
Initial parser, which located CS_CORE inside the GCC header (hence the garbage
client hostnames in every log). That bug blocked the channel lookup F4 needs.

| # | Where | What the real scanners exposed |
|---|---|---|
| F1 | [`x224_cc`, families/rdp.py:57](../../families/rdp.py#L57) | The Connection Confirm doesn't match Windows: DST-REF/SRC-REF are swapped, LI is 11 instead of 14, and `RDP_NEG_RSP` is sent even when the request had no `RDP_NEG_REQ`. `ms12_020_check` requires the legacy `03 00 00 0b 06 d0 00 00 12 34 00`, so the whole MS12-020 row fails at its first exchange. |
| F2 | [families/rdp.py:92-95](../../families/rdp.py#L92) | `RSA_PUBLIC_KEY.keylen` = 64 omits the 8 bytes of padding that MS-RDPBCGR 2.2.1.4.3.1.1.1 requires (72). rdpscan reads a 448-bit key and aborts. |
| F3 | [`_recv`, families/rdp.py:487](../../families/rdp.py#L487) | The handler treats one `recv()` as one PDU. When Erect Domain and Attach User Request arrive in the same read, the Attach User Request is silently dropped and the client waits until its timeout. This is the source of all RDP non-determinism (rdpscan 24/30, msf 1/30). The SMB handler ([families/smb.py:513](../../families/smb.py#L513)) has the same assumption; it wasn't triggered, because SMB1 scanners wait for each reply. |
| F4 | [families/rdp.py:463](../../families/rdp.py#L463), [drivers/bluekeep.py:80](../../drivers/bluekeep.py#L80) | "Exploit PDU" (stage 5) is credited on the first MCS Send Data, which is the ordinary Security Exchange PDU, and the connection is then closed. Metasploit's check never reaches its MS_T120 probe (it wants an MCS Disconnect Provider Ultimatum in reply). Fixing this means carrying the RDP connection sequence through to that probe: a feature, not a bug fix. |
| F5 | [families/rdp.py:420](../../families/rdp.py#L420) | Any bytes after the Connection Confirm are taken as an MCS Connect Initial. Nmap's TLS ClientHello gets stage 3 credited and an MCS Connect Response sent back. This is the only SC_int ≠ SC_obs case. |
| F6 | [framework/tracker.py:111](../../framework/tracker.py#L111) | `session_id` has one-second resolution, so sessions finishing in the same second overwrite each other's `sc_*.json`. **224 of 360** BlueKeep-family records were lost (msf 29/60, nmap 195/270). |
| F7 | [`_finalize`, families/rdp.py:500](../../families/rdp.py#L500) | Connections never resolved to a variant are recorded under the default variant. All 30 MS12-020 scans are filed as BlueKeep sessions. |
| F8 | tracker callers | `source_port` is never passed (as the runbook noted). The source-port match above recovers it from the log. |

## Issues in the instrument and protocol

- **I1 — MS12-020 stage 2 can't be earned honestly.** The observer credits
  stage 2 only if the Connection Confirm carries `RDP_NEG_RSP`. `ms12_020_check`
  (and some nmap probes) send legacy requests with no negotiation, so a correct
  server, a real Windows 7 included, gets no stage 2, and the ceiling is 4/5.
  T1 earns stage 2 today only because of F1. The rule needs a decision, for
  example "credit stage 2 on any CC when the CR carried no RDP_NEG_REQ", or
  mark it not applicable.
- **I2 — BlueKeep stage 5 is satisfied before the verdict.** "Client MCS Send
  Data on the bound channel" matches the Security Exchange PDU, so SC = 5/5
  coexists with a not-vulnerable verdict. This is Decision 1 (protocol §6)
  showing up in data; option (a) would move stage N to the MS_T120 probe and its
  answer.
- **I3** — Metasploit's BlueKeep scanner prints a verdict only when the target is
  vulnerable. Safe and Unknown are verbose-only, so the matrix command can't tell
  them apart.
- **I4** — `aggregate_sc.py` pooled every TCP session, so nmap's payload-less SYN
  probe made deterministic cells look non-deterministic. Added `--per-run`
  (deepest session per run); the default is unchanged.
- **I5** — `run_matrix.sh` had never run: `${1:?…{a|b}}` appended `}` to every
  attack name. Fixed.
- Lab note: over veth, TCP checksums are left for a NIC that doesn't exist, and
  Honeyd (pcap) drops every SYN. TX offload is disabled on the scanner, for every
  target alike.

## What-if: T1 with F1–F3 fixed (`whatif/rdp-fixes.patch`, R = 5)

This is a temporary copy of `0564e0d` with the patch applied; the repository was
not modified. Data: `results/whatif/`.

| tool on T1 | at `0564e0d` (R=30) | patched (R=5) |
|---|---|---|
| msf `ms12_020_check` | 2/5, "Could not connect to RDP" | 3/5 (stages 1, 3, 4), **SAFE** |
| rdpscan | 3/5 or 5/5, UNKNOWN | 5/5 ×5, UNKNOWN (reset after the Security Exchange, F4) |
| msf BlueKeep | 5/5 or 3/5, not vulnerable | 5/5 ×5, not vulnerable (F4) |
| nmap `rdp-enum-encryption` | 3/5 | 2/5: legacy requests now get the legacy CC, so the observer can't credit stage 2 (I1) |

The fixes remove the non-determinism and get both scanners past their first
failure, which confirms the diagnosis. They don't produce an RDP verdict.

MS12-020 now runs its full check, and the result is "The target is not
exploitable. Not vulnerable". T1's Channel Join Confirm is correct (`3e 00`,
result 0), but the module's reads fall one reply behind. It sends Connect
Initial and the first Attach User Request together, then reads once, and takes
the user id from bytes 9–10 of what arrives. That was T1's Connect Response, so
it used initiator 0x8201. Its Channel Join (initiator 33281, channel 2002) is
therefore not a cross-user bind. The reply it checks is the second Attach User
Confirm, not the Join Confirm. The module's outcome depends on how the server
batches its replies into TCP reads. A T3 capture is needed to see how Windows
does it, and whether the observer's MS12-020 stage 5 (a bind by an *attached*
user) is reachable with this module at all.

## Claims the tables support today (protocol §4)

1. SMB: T1 reaches the verdict-bearing stage and Honeyd doesn't, with all three
   tools and zero variance. RDP: T1 goes further than Honeyd (which has no RDP
   at all), but **no RDP tool's verdict was obtained**, so the abstract's RDP claim
   isn't supported by this run.
2. SC_int = SC_obs held for every SMB session and for three of the four RDP tools.
   The exceptions are F5 (30 sessions over-reported) and F6 (records lost).
3. T5 anchors the floor (0 everywhere). **T3 is still missing for the ceiling.**
4. Tool independence: Metasploit and nmap differ only by the post-verdict stage
   on SMB. On RDP they differ because of F3, which the patch removes.

## Reproduce

```bash
podman build -t localhost/honeyd:a0f3d64 -f honeyd/Containerfile honeyd/   # once
./honeyd/lab/run_all.sh                       # RUNBOOK s0, s7, s2, s4; ~90 min at R=30
OUT=$PWD/honeyd/lab/results/fixed ./honeyd/lab/run_all.sh   # what produced results/fixed
python3 honeyd/lab/report.py honeyd/lab/results/main > REPORT.md
./honeyd/lab/diag_bluekeep_verbose.sh         # verbose verdicts
./honeyd/lab/whatif/run_whatif.sh             # patched copy, R=5
```
