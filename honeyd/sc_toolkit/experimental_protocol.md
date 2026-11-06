# Experimental protocol — AINA 2027, Section 5
## STAGED, comparative evaluation with Stage Coverage

Prepared in response to Vinícius's request: an experimental protocol that uses
Stage Coverage (SC) **and** includes a comparative test against at least one
honeypoint/honeypot from the literature, in at most 3 pages.

---

## 0. The one idea that makes comparison possible

A third-party honeypot has no drivers and declares no stages, so its SC cannot
be read from its own logs. The protocol therefore **moves the measurement off
the decoy**: SC is computed by an external observer from a packet capture of the
session, using the stage list of the reconnaissance attack under test.

This is sound because of how the paper already defines the terms. Section 2
defines a stage as an exchange that is *individually observable*, and Section 4
states that `N` belongs to the reconnaissance attack, not to the core. The
driver declares `N` because it models that attack — but the attack, and hence
the stage list, exists independently of any decoy. The same stage list can
therefore be scored against STAGED, against a third-party honeypot, and
against a real host.

Two consequences, both useful:

1. **Comparability.** Any target that speaks the protocol can be placed on the
   same scale. This is exactly the property Section 3 found missing from prior
   systems, and now it is demonstrated rather than asserted.
2. **Instrument validation.** For STAGED, SC can be obtained twice:
   internally (`SCTracker`) and externally (observer). Agreement is a cheap,
   rigorous check that the framework does not over-report its own performance —
   and it pre-empts the "they only tested themselves" objection.

Notation: `SC_int` = internal tracker, `SC_obs` = external observer.

---

## 1. Targets

Per protocol, five targets. T3 and T4 are what keep this from being
decoy-versus-decoy: they anchor the scale to real hosts.

| ID | Target | Role | Expected position |
|----|--------|------|-------------------|
| T1 | STAGED driver | system under test | — (to measure) |
| T2 | **Honeyd** — the Related Work baseline | comparison, network-layer granularity | — (to measure) |
| T3 | Real **unpatched** host | ceiling / ground truth | the verdict-bearing stage is reached by construction |
| T4 | Real **patched** host | negative reference | scanner reports not vulnerable |
| T5 | Bare TCP listener (accepts, sends nothing) | floor / control | no protocol stage completes |

**Baseline selection: Honeyd, and only Honeyd.** The baseline must be a system
*from Section 3*. Otherwise the paper analyses four systems, claims a gap, and
then benchmarks against others — which a reviewer will notice immediately. Of
the four, Honeyd is the only one that is both obtainable and exercisable by the
same reconnaissance attacks, and it is also the most valuable to measure,
because Section 3's criticism of it is already a stage-depth criticism: a
Honeyd template "can convince a scanner that a host runs a particular operating
system with a particular port open, but it carries no model of the internal
state machine of an application protocol". That is an assertion in the current
draft. SC turns it into a measurement.

Honeyd's own paper supports both the mechanism and the limit: its documented
extension point binds a script or an internal service to a port
(`add <template> tcp port 445 "scripts/..."`), and it implements only a
simplified TCP state machine. Configure it with a Windows personality, the
target port open, and the most capable service obtainable bound to it.

**The other three are excluded, for reasons that follow from Section 3's own
granularity axis — not for convenience:**

| System | Why excluded |
|---|---|
| MTDCD | No public implementation. Operates at the network layer (addresses, ARP/ICMP/DHCP/traceroute), so it declares no application-protocol stage; against an SMB or RDP scanner it would score at the transport floor, which the inert socket already establishes. |
| PHCG | No public implementation; the repositories it references are other systems. It targets the Schneider UMAS PLC protocol family, so it cannot be exercised by an SMB or RDP reconnaissance attack at all — a different protocol means a different stage list. |
| H4 | No public implementation; its honeypoint catalogue requires the full orchestration stack as a mandatory dependency, as Section 3 already notes. |

State this exclusion explicitly in Section 5. It is not an apology: it follows
from the granularity analysis the paper already makes, and it is checkable.

**What the single baseline costs, and what carries the weight instead.** Honeyd
dates from 2004 and was never designed for CVE-specific procedures, so showing
that a stage-aware driver reaches further than Honeyd is, on its own, a weak
result. Two things compensate, and both must be in the paper:

1. **The real hosts do the work.** T3 (unpatched) and T4 (patched) are what make
   the comparison meaningful. A driver that matches a genuinely vulnerable host
   stage for stage, where Honeyd does not, is a claim about reality rather than
   about one old decoy.
2. **State the limitation honestly.** Honeyd is not *incapable* of reaching any
   given stage — a Honeyd subsystem can run an arbitrary program. What the
   measurement characterizes is the *support its extension point provides*: a
   contributor wanting a full reconnaissance procedure under Honeyd would have
   to write the stage structure, the tracking, and the records that our
   architecture factors out. Framed this way the result strengthens the
   architectural argument instead of overclaiming a capability gap.

**Fair-baseline requirement.** Honeyd must be given the best service script
obtainable for each port, so the comparison is not a straw man. A reviewer will
ask; configure it in good faith and state the configuration.

---|---|
| MTDCD | No public implementation. Operates at the network layer (addresses, ARP/ICMP/DHCP/traceroute), so it declares no application-protocol stage; against an SMB or RDP scanner it would score at the transport floor, which the inert socket already establishes. |
| PHCG | No public implementation; the repositories it references are other systems. It targets the Schneider UMAS PLC protocol family, so it cannot be exercised by an SMB or RDP reconnaissance attack at all — a different protocol means a different stage list. |
| H4 | No public implementation; its honeypoint catalogue requires the full orchestration stack as a mandatory dependency, as Section 3 already notes. |

State this exclusion explicitly in Section 5. It is not an apology: it follows
from the granularity analysis the paper already makes, and it is checkable.


---

## 2. Reconnaissance tools (the second axis)

| Protocol | Tool | Class |
|---|---|---|
| SMB | `auxiliary/scanner/smb/smb_ms17_010` (Metasploit) | scanner |
| SMB | `smb-vuln-ms17-010` (Nmap NSE) | scanner, independent implementation |
| SMB | `exploit/windows/smb/ms17_010_eternalblue` | exploiter |
| RDP | `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` | scanner |
| RDP | `auxiliary/scanner/rdp/ms12_020_check` | scanner (second variant) |
| RDP | `rdpscan` | scanner, independent implementation |
| RDP | `rdp-enum-encryption` (Nmap NSE) | shallow probe |

Two independent implementations per protocol matter: they show SC is a property
of the procedure, not of one vendor's client.

> **Safety constraint.** Exploit modules are run **only** against the decoys (T1,
> T2) and the inert socket (T5),
> none of which can be compromised. They are **never** run against T3, the real
> unpatched host. The exploiter row of T3 is therefore left empty by design, and
> the paper must say so rather than leave a blank the reader has to interpret.
> The whole testbed is an isolated host-only network with no route to campus or
> to the Internet.

---

## 3. Measurement procedure

1. **Stage trace, not just a score.** For every run, the observer records the
   full ordered trace of recognised stages, with timestamps, not only `|C|`.
   This is the robustness move: if the stage list is later revised (see §6,
   decision 1), SC under the new definition is recomputed from the stored
   traces without re-running anything.
2. **Capture.** `tcpdump` on the link, one pcap per run, filtered to the target
   port. The observer is passive and identical for all five targets — it is not
   told which target it is scoring.
3. **Repetitions.** R = 30 runs per (target, tool) cell, decoy restarted and
   logs cleared between runs, cell order randomised. SC is expected to be
   deterministic per cell; if it is, report the value and state that variance
   was zero across 30 runs, which is a stronger claim than a mean. If it is not,
   report median and range and investigate.
4. **Pinned versions.** Record exact versions of Metasploit, Nmap, rdpscan,
   Honeyd, and the STAGED commit. Publish the pcaps and the scorer.
5. **Cost.** Peak RSS and CPU time per decoy under a fixed scan load, one line
   in the text, supporting the lightweight claim of Section 4.5.

### Stage recognition rules for the observer

All stages below are on the wire and recognisable with `tshark`/`scapy`.

**EternalBlue, SMB (N = 5)**

| # | Wire signature |
|---|---|
| 1 | client `SMB_COM_NEGOTIATE` (0x72) and server response |
| 2 | client `SMB_COM_SESSION_SETUP_ANDX` (0x73), server status 0 |
| 3 | client `SMB_COM_TREE_CONNECT_ANDX` (0x75), share path ending `\IPC$` |
| 4 | client `SMB_COM_TRANSACTION` (0x25), subcommand `PeekNamedPipe` |
| 5 | a further transaction (0x25/0x32/0xA0) after the verdict — see decision 1 |

**BlueKeep, RDP (N = 5)**

| # | Wire signature |
|---|---|
| 1 | TPKT + X.224 Connection Request (0xE0) |
| 2 | server Connection Confirm carrying `RDP_NEG_RSP` (type 0x02) |
| 3 | client MCS Connect-Initial / GCC Conference Create Request |
| 4 | client MCS Channel Join Request, server Channel Join Confirm (0x3E) |
| 5 | client MCS Send Data on the bound channel |

**MS12-020, RDP (N = 5)** — stages 1–3 as above; stage 4 is a *second* MCS
Attach User Request; stage 5 is a Channel Join binding the first user to a
channel of the second, confirmed by the server.

---

## 4. Results to report (fits the 3-page budget)

| Slot | Content | Budget |
|---|---|---|
| 5.1 | Testbed, targets, baseline configuration | 0.5 p |
| 5.2 | Protocol, observer, metrics, `SC_int` vs `SC_obs` validation | 0.6 p |
| 5.3 | **Table 2** SMB: SC per target × tool + verdict; **Table 3** RDP: same | 1.3 p |
| 5.4 | Discussion and threats to validity | 0.6 p |

A stage-profile figure (target × stage reached) is the natural fourth element
but does not fit alongside two tables. Add it only if Vinícius's final trim
frees space.

**Claims the tables are designed to support**, in the order a reader needs them:

1. Our driver reaches the verdict-bearing stage and Honeyd does not reach as far
   (or it does — either outcome is publishable and must be reported honestly).
2. `SC_int = SC_obs` on T1, so the framework's self-reporting is sound.
3. T3 anchors the top of the scale and T5 the bottom, so SC is not an arbitrary
   ratio.
4. Two independent scanner implementations agree, so SC is tool-independent.

---

## 5. Threats to validity (say these before a reviewer does)

1. **The stage list is chosen by the driver author.** A driver could inflate SC
   by declaring few stages. Mitigation: stages are derived from the scanner's
   own source code, and the derivation is stated.
2. **RDP has a structural floor.** Stage 2 is credited once the server answers
   the Connection Request, so any client completing stage 1 also completes
   stage 2. For RDP the discriminating range is therefore 3 of 5 stages, not 5.
   Disclose it.
3. **Single isolated testbed**, no Internet exposure, no live adversaries.
4. **Baseline configuration** is ours, not the baseline authors'.
5. **MS12-020 signal offset** is not yet confirmed against a live handshake
   (noted in the driver source). Until it is, that row is preliminary.

---

## 6. Two decisions to settle *before* running anything

**Decision 1 — what stage N means. This is the important one.**

The three drivers are currently inconsistent about their last stage:

- EternalBlue stage 5 is labelled "Vuln Check Response", but the code credits it
  only on a *second* transaction and logs it as `EXPLOIT_ATTEMPT`. A scanner
  therefore stops at 4/5.
- BlueKeep stage 5 is an MCS Send Data, which the Metasploit scanner does send.
  A scanner therefore reaches 5/5.

So "scanner reaches N−1, exploiter reaches N" holds for SMB but not for RDP, and
the abstract's claim that both drivers reach SC = 5/5 is in tension with the
repository's own 4/5 for the EternalBlue scanners. Two coherent ways out:

- **(a) Recommended. Stages 1..N are the reconnaissance procedure, ending at the
  verdict-bearing exchange.** A scanner that obtains its verdict reaches
  SC = 1.0. Exploitation is reported as a separate binary ("activity beyond
  stage N"), not as part of SC. SC then measures exactly what its name says, the
  abstract becomes true for both drivers, and α acquires a much better
  justification than the current one: α = 1.0 means the decoy delivered the
  verdict the scanner came for. Cost: EternalBlue's stage 5 is renamed and
  BlueKeep's stage 5 is reclassified, and Section 4.5's α paragraph is rewritten.
- **(b)** Keep a uniform post-verdict stage in every driver. Cost: BlueKeep's
  stage list must be re-derived so that its scanner stops at N−1 too.

Because the observer stores full stage traces, the experiments can be run before
this is settled and scored either way afterwards. But the decision must be made
before the section is written.

**Decision 2 — framework name.** Settled (2026-11-06): **STAGED** (STage-Aware
Generic Extensible Decoys). Runs recorded before this carry the placeholder
`XXX` as the T1 target key; the lab's report and aggregation map it to STAGED.

---

## 7. References to add to `references.bib`

- Zirngibl et al., *Looking for Honey Once Again: Detecting RDP and SMB
  Honeypots on the Internet*, WTMC 2022 — cited for the fingerprinting threat in
  the threats-to-validity subsection. Honeyd itself is already in the bibliography
  as `Provos2004`, so the baseline needs no new entry.

Morić et al. (*Advancing Cybersecurity with Honeypots and Deception
Strategies*), already in the corpus, supports the baseline set and, more
usefully, shows that the state of the art compares honeypots on **qualitative**
descriptors ("Weak", "Acceptable", "Excellent"). That is the gap SC fills, and
it is worth one sentence in Section 5.2.
