
## bluekeep

SC_obs per run (deepest TCP session of the run); verdict = the tool's own output

| target | msf_bluekeep | nmap_rdp_enum | rdpscan |
|---|---|---|---|
| T1 STAGED | 5/5 (R=5)<br>*not reported vulnerable ×5* | 2/5 (R=5)<br>*enumerated ×5* | 5/5 (R=5)<br>*UNKNOWN - RDP protocol error - connection reset by peer ×5* |
| T2 Honeyd | - | - | - |
| T5 inert | - | - | - |

Stages reached (observer), per cell:

- T1 STAGED × msf_bluekeep: X.224 Connection Request → Security Negotiation → MCS Connect Initial → Channel Join → Exploit PDU ×5
- T1 STAGED × nmap_rdp_enum: X.224 Connection Request → Security Negotiation ×4; X.224 Connection Request → MCS Connect Initial ×1
- T1 STAGED × rdpscan: X.224 Connection Request → Security Negotiation → MCS Connect Initial → Channel Join → Exploit PDU ×5

**SC_int vs SC_obs (T1, per session)**

matched by client source port; sessions with no stage on either side are skipped

| tool | sessions compared | agree | differ | SC_obs > 0 but no SC_int | SC_int recorded under |
|---|---|---|---|---|---|
| msf_bluekeep | 10 | 10 | 0 | 0 | BlueKeep ×10 |
| nmap_rdp_enum | 45 | 20 | 25 | 0 | BlueKeep ×45 |
| rdpscan | 5 | 5 | 0 | 0 | BlueKeep ×5 |

Disagreements (SC_int stages vs SC_obs stages, same source port):
- nmap_rdp_enum: SC_int [1, 2, 3] vs SC_obs [1, 2] ×5
- nmap_rdp_enum: SC_int [1, 2, 3] vs SC_obs [1, 3] ×20

SC_int records overwritten (two sessions, same one-second session id): 36

**Decoy cost per run** (container cgroup; median over runs)

| target | memory.peak | CPU time |
|---|---|---|
| T1 STAGED | 16.4 MiB | 228 ms |

## ms12_020

SC_obs per run (deepest TCP session of the run); verdict = the tool's own output

| target | msf_ms12_020 |
|---|---|
| T1 STAGED | 3/5 (R=5)<br>*SAFE ×5* |
| T2 Honeyd | - |
| T5 inert | - |

Stages reached (observer), per cell:

- T1 STAGED × msf_ms12_020: X.224 Connection Request → MCS Connect Initial → Second Attach User ×5

**SC_int vs SC_obs (T1, per session)**

matched by client source port; sessions with no stage on either side are skipped

| tool | sessions compared | agree | differ | SC_obs > 0 but no SC_int | SC_int recorded under |
|---|---|---|---|---|---|
| msf_ms12_020 | 5 | 0 | 5 | 0 | BlueKeep ×5 |

Disagreements (SC_int stages vs SC_obs stages, same source port):
- msf_ms12_020: SC_int [1, 2, 3, 4] vs SC_obs [1, 3, 4] ×5

SC_int records overwritten (two sessions, same one-second session id): 0

**Decoy cost per run** (container cgroup; median over runs)

| target | memory.peak | CPU time |
|---|---|---|
| T1 STAGED | 16.3 MiB | 217 ms |
