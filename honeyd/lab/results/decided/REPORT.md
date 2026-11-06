```
# recorded 2026-11-06T13:25:41Z by honeyd/lab/lab.sh versions
host: Linux 7.2.15-200.fc44.x86_64, Fedora Linux 44 (KDE Plasma Desktop Edition), podman 5.8.9
honeypoint: 6e183c4
msfconsole: Framework Version: 6.5.9-dev
nmap: Nmap version 7.99 ( https://nmap.org )
rdpscan: commit 09db2719a76d0fbc535f99fb51304ef060c0e484
honeyd: Honeyd V1.6d Copyright (c) 2002-2007 Niels Provos, commit a0f3d64834781cf2c02f6d7302638f54c68dfdb0
T1/T5 python: Python 3.14.10
images:
  docker.io/library/python@sha256:ac25e5afbfdb4a94ff99cc24b0345719210133144481480bcba6085efa36a341 d8f0d5177291
  localhost/honeyd:a0f3d64 1ec9994a1a26
  localhost/sc-scanner 5c0b8e38d667
```


## eternalblue

SC_obs per run (deepest TCP session of the run); verdict = the tool's own output

| target | msf_exploit | msf_smb_ms17_010 | nmap_smb_vuln |
|---|---|---|---|
| T1 honeypoint | 5/5 (R=30)<br>*VULNERABLE ×30* | 5/5 (R=30)<br>*VULNERABLE ×30* | 5/5 (R=30)<br>*VULNERABLE ×30* |
| T2 Honeyd | 2/5 (R=30)<br>*UNKNOWN ×30* | 2/5 (R=30)<br>*error: ACCESS_DENIED (tree connect) ×30* | 1/5 (R=30)<br>*no script result ×30* |
| T5 inert | 0/5 (R=30)<br>*UNKNOWN ×30* | 0/5 (R=30)<br>*error: no IPC$ tree ×30* | 0/5 (R=30)<br>*no script result ×30* |

Stages reached (observer), per cell:

- T1 honeypoint × msf_exploit: SMB Negotiate → Session Setup → Tree Connect IPC$ → PeekNamedPipe → Vuln Check Response ×30 (+ activity beyond N in 30 runs)
- T1 honeypoint × msf_smb_ms17_010: SMB Negotiate → Session Setup → Tree Connect IPC$ → PeekNamedPipe → Vuln Check Response ×30 (+ activity beyond N in 30 runs)
- T1 honeypoint × nmap_smb_vuln: SMB Negotiate → Session Setup → Tree Connect IPC$ → PeekNamedPipe → Vuln Check Response ×30
- T2 Honeyd × msf_exploit: SMB Negotiate → Session Setup ×30
- T2 Honeyd × msf_smb_ms17_010: SMB Negotiate → Session Setup ×30
- T2 Honeyd × nmap_smb_vuln: SMB Negotiate ×30
- T5 inert × msf_exploit: (none) ×30
- T5 inert × msf_smb_ms17_010: (none) ×30
- T5 inert × nmap_smb_vuln: (none) ×30

**SC_int vs SC_obs (T1, per session)**

matched by client source port; sessions with no stage on either side are skipped

| tool | sessions compared | agree | differ | SC_obs > 0 but no SC_int | SC_int recorded under |
|---|---|---|---|---|---|
| msf_exploit | 30 | 30 | 0 | 0 | EternalBlue ×30 |
| msf_smb_ms17_010 | 30 | 30 | 0 | 0 | EternalBlue ×30 |
| nmap_smb_vuln | 30 | 30 | 0 | 0 | EternalBlue ×30 |

SC_int records overwritten (two sessions, same one-second session id): 0

**Decoy cost per run** (container cgroup; median over runs)

| target | memory.peak | CPU time |
|---|---|---|
| T1 honeypoint | 17.8 MiB | 231 ms |
| T2 Honeyd | 14.5 MiB | 61 ms |
| T5 inert | 5.7 MiB | 23 ms |

## bluekeep

SC_obs per run (deepest TCP session of the run); verdict = the tool's own output

| target | msf_bluekeep | nmap_rdp_enum | rdpscan |
|---|---|---|---|
| T1 honeypoint | 5/5 (R=30)<br>*VULNERABLE ×30* | 3/5 (R=30)<br>*enumerated ×30* | 5/5 (R=30)<br>*VULNERABLE - got appid ×30* |
| T2 Honeyd | 0/5 (R=30)<br>*not reported vulnerable ×30* | 0/5 (R=30)<br>*port closed ×30* | 0/5 (R=30)<br>*UNKNOWN - no connection - refused (RST) ×30* |
| T5 inert | 0/5 (R=30)<br>*not reported vulnerable ×30* | 0/5 (R=30)<br>*unhandled packet ×30* | 0/5 (R=30)<br>*UNKNOWN - RDP protocol error - receive timeout ×30* |

Stages reached (observer), per cell:

- T1 honeypoint × msf_bluekeep: X.224 Connection Request → Security Negotiation → MCS Connect Initial → Channel Join → Exploit PDU ×30
- T1 honeypoint × nmap_rdp_enum: X.224 Connection Request → Security Negotiation → MCS Connect Initial ×30
- T1 honeypoint × rdpscan: X.224 Connection Request → Security Negotiation → MCS Connect Initial → Channel Join → Exploit PDU ×30
- T2 Honeyd × msf_bluekeep: (none) ×30
- T2 Honeyd × nmap_rdp_enum: (none) ×30
- T2 Honeyd × rdpscan: (none) ×30
- T5 inert × msf_bluekeep: (none) ×30
- T5 inert × nmap_rdp_enum: (none) ×30
- T5 inert × rdpscan: (none) ×30

**SC_int vs SC_obs (T1, per session)**

matched by client source port; sessions with no stage on either side are skipped

| tool | sessions compared | agree | differ | SC_obs > 0 but no SC_int | SC_int recorded under |
|---|---|---|---|---|---|
| msf_bluekeep | 60 | 60 | 0 | 0 | RDP-Recon ×30, BlueKeep ×30 |
| nmap_rdp_enum | 270 | 270 | 0 | 0 | RDP-Recon ×270 |
| rdpscan | 30 | 30 | 0 | 0 | BlueKeep ×30 |

SC_int records overwritten (two sessions, same one-second session id): 0

**Decoy cost per run** (container cgroup; median over runs)

| target | memory.peak | CPU time |
|---|---|---|
| T1 honeypoint | 17.9 MiB | 249 ms |
| T2 Honeyd | 12.0 MiB | 51 ms |
| T5 inert | 5.7 MiB | 24 ms |

## ms12_020

SC_obs per run (deepest TCP session of the run); verdict = the tool's own output

| target | msf_ms12_020 |
|---|---|
| T1 honeypoint | 5/5 (R=30)<br>*VULNERABLE ×30* |
| T2 Honeyd | 0/5 (R=30)<br>*Unable to determine MS12-020 vulnerability status ×30* |
| T5 inert | 0/5 (R=30)<br>*Could not connect to RDP ×30* |

Stages reached (observer), per cell:

- T1 honeypoint × msf_ms12_020: X.224 Connection Request → Security Negotiation → MCS Connect Initial → Second Attach User → Channel Join Check ×30
- T2 Honeyd × msf_ms12_020: (none) ×30
- T5 inert × msf_ms12_020: (none) ×30

**SC_int vs SC_obs (T1, per session)**

matched by client source port; sessions with no stage on either side are skipped

| tool | sessions compared | agree | differ | SC_obs > 0 but no SC_int | SC_int recorded under |
|---|---|---|---|---|---|
| msf_ms12_020 | 30 | 30 | 0 | 0 | MS12020 ×30 |

SC_int records overwritten (two sessions, same one-second session id): 0

**Decoy cost per run** (container cgroup; median over runs)

| target | memory.peak | CPU time |
|---|---|---|
| T1 honeypoint | 17.8 MiB | 225 ms |
| T2 Honeyd | 12.0 MiB | 52 ms |
| T5 inert | 5.6 MiB | 23 ms |
