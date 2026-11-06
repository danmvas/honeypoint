#!/usr/bin/env python3
"""
report.py - turn a lab results directory into the comparison report.

    python3 honeyd/lab/report.py [--rescore] honeyd/lab/results/main > REPORT.md

Per attack: SC_obs per (target, tool) cell, each run scored by its deepest TCP
session (aggregate_sc.py --per-run), the scanner's own verdict, RUNBOOK s5
(SC_int vs SC_obs for our honeypoint), session-file collisions, and decoy cost.
Reads only files written by run_matrix.sh and lab.sh; stdlib only.
"""
import collections, datetime, glob, json, os, re, statistics, sys

TARGETS = ["XXX", "Honeyd", "Inert"]
LABEL = {"XXX": "T1 honeypoint", "Honeyd": "T2 Honeyd", "Inert": "T5 inert"}
RUN_RE = re.compile(r"^(eternalblue|bluekeep|ms12_020)_(XXX|Honeyd|Inert|Unpatched|Patched)_(.+)_r(\d+)$")

# First match wins. Labels are short; the evidence line is kept in the report.
VERDICTS = {
    "msf_smb_ms17_010": [
        (r"Host is likely VULNERABLE to MS17-010", "VULNERABLE"),
        (r"Host does NOT appear vulnerable", "SAFE"),
        (r"STATUS_ACCESS_DENIED", "error: ACCESS_DENIED (tree connect)"),
        (r"SMB Login Error occurred while connecting to the IPC\$ tree", "error: no IPC$ tree"),
        (r"\[-\].*", "error"),
    ],
    "msf_exploit": [
        (r"The target is vulnerable", "VULNERABLE"),
        (r"The target is not exploitable", "SAFE"),
        (r"Cannot reliably check exploitability", "UNKNOWN"),
    ],
    "nmap_smb_vuln": [
        (r"State: VULNERABLE", "VULNERABLE"),
        (r"State: NOT VULNERABLE", "SAFE"),
        (r"445/tcp\s+open", "no script result"),
        (r"445/tcp\s+closed", "port closed"),
    ],
    "msf_bluekeep": [
        (r"\[\+\].*", "VULNERABLE"),
        (r"Scanned 1 of 1 hosts", "not reported vulnerable"),   # Safe/Unknown are verbose-only
    ],
    "rdpscan": [
        (r" - (VULNERABLE|SAFE|UNKNOWN) - (.*)$", None),        # label = the tool's own words
    ],
    "nmap_rdp_enum": [
        (r"Security layer", "enumerated"),
        (r"Received unhandled packet", "unhandled packet"),
        (r"3389/tcp\s+closed", "port closed"),
        (r"3389/tcp\s+open", "no script result"),
    ],
    "msf_ms12_020": [
        (r"Response confirmed vulnerability presence", "VULNERABLE"),
        (r"Not vulnerable", "SAFE"),
        (r"Cannot reliably check exploitability\. (.*)$", None),
    ],
}


def verdict(tool, log_path):
    try:
        text = open(log_path, errors="replace").read().splitlines()
    except OSError:
        return "no log"
    for pat, label in VERDICTS.get(tool, []):
        for line in text:
            m = re.search(pat, line)
            if m:
                if label is None:
                    return " - ".join(g.strip() for g in m.groups())
                return label
    return "no verdict line"


def iso(ts):
    return datetime.datetime.fromisoformat(ts).timestamp()


RESCORE = False   # --rescore: score each stored pcap with the current sc_observer


def _observer():
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sc_toolkit"))
    import sc_observer
    return sc_observer


def load_runs(root):
    runs = []
    for path in sorted(glob.glob(os.path.join(root, "*.json"))):
        tag = os.path.basename(path)[:-5]
        m = RUN_RE.match(tag)
        if not m:
            continue
        attack, target, tool, rep = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if RESCORE:
            obs = _observer().analyse(os.path.join(root, tag + ".pcap"), attack,
                                      None, target, tool)
        else:
            obs = json.load(open(path))
        best = max(obs, key=lambda r: r["completed_stages"]) if obs else None
        ints = []
        for f in sorted(glob.glob(os.path.join(root, tag + ".sc_int", "sc_*.json"))):
            ints.append(json.load(open(f)))
        cost = None
        try:
            cost = json.load(open(os.path.join(root, tag + ".cost.json")))
        except (OSError, ValueError):
            pass
        finals = []
        try:
            for line in open(os.path.join(root, tag + ".decoy.log"), errors="replace"):
                m2 = re.search(r"Sessão finalizada: SC = (\d+)/(\d+).*→ (\S+)", line)
                if m2 and "[INFO]" not in line[:30]:      # the logger prints each line twice
                    finals.append((int(m2.group(1)), m2.group(3)))
        except OSError:
            pass
        runs.append(dict(tag=tag, attack=attack, target=target, tool=tool, rep=rep,
                         obs=obs, best=best, ints=ints, cost=cost, finals=finals,
                         verdict=verdict(tool, os.path.join(root, tag + ".log"))))
    return runs


def cell_text(vals, n):
    if not vals:
        return "-"
    uniq = sorted(set(vals))
    if len(uniq) == 1:
        return f"{uniq[0]}/{n} (R={len(vals)})"
    return f"{int(statistics.median(vals))}/{n} [{min(vals)}-{max(vals)}] (R={len(vals)})"


CONSOLE = re.compile(r"^\d\d:\d\d:\d\d \[")      # root handler; the driver handler repeats lines


def int_sessions_by_port(decoy_log):
    """SC_int per client source port, from the honeypoint's own console log.

    The tracker never records the source port (StageEvent.source_port is
    always 0), but every connection handler ends with "Encerrada [ip:port]",
    logged in its `finally` right after the tracker's "Stage n/N" and
    "Sessão finalizada" lines for that connection. Pending tracker lines are
    therefore attributed to the next "Encerrada". (Attributing them to the
    last "Nova conexão" is wrong when the next connection is accepted before
    the previous handler finalises.) This is the source-port match RUNBOOK s5
    asks for, and it also covers sessions whose JSON file was overwritten.
    """
    conns, pending, final = {}, set(), None
    try:
        lines = open(decoy_log, errors="replace").read().splitlines()
    except OSError:
        return conns
    driver = None
    for line in lines:
        if not CONSOLE.match(line):
            continue
        m = re.search(r"\[([\w-]+)\] Stage (\d+)/\d+ \(", line)
        if m:
            driver = m.group(1); pending.add(int(m.group(2)))
            continue
        m = re.search(r"Sessão finalizada: SC = (\d+)/\d+.*→ (\S+)", line)
        if m:
            final = (int(m.group(1)), m.group(2))
            continue
        m = re.search(r"\[[\d.]+:(\d+)\] Encerrada", line)
        if m:
            conns[int(m.group(1))] = {"stages": pending, "driver": driver, "final": final}
            pending, final, driver = set(), None, None
    return conns


def main():
    global RESCORE
    args = [a for a in sys.argv[1:] if a != "--rescore"]
    RESCORE = len(args) != len(sys.argv) - 1
    root = args[0] if args else "results/main"
    runs = load_runs(root)
    if not runs:
        raise SystemExit(f"no runs under {root}")
    out = []
    p = out.append
    try:
        p("```\n" + open(os.path.join(root, "versions.txt")).read().strip() + "\n```\n")
    except OSError:
        pass

    for attack in ["eternalblue", "bluekeep", "ms12_020"]:
        ar = [r for r in runs if r["attack"] == attack]
        if not ar:
            continue
        tools = sorted({r["tool"] for r in ar})
        n = next(r["best"]["total_stages"] for r in ar if r["best"])
        p(f"\n## {attack}\n")
        p("SC_obs per run (deepest TCP session of the run); verdict = the tool's own output\n")
        p("| target | " + " | ".join(tools) + " |")
        p("|---|" + "---|" * len(tools))
        for t in TARGETS:
            cells = []
            for w in tools:
                rr = [r for r in ar if r["target"] == t and r["tool"] == w]
                vals = [r["best"]["completed_stages"] if r["best"] else 0 for r in rr]
                verd = collections.Counter(r["verdict"] for r in rr)
                vtxt = "; ".join(f"{k} ×{c}" for k, c in verd.most_common())
                cells.append(f"{cell_text(vals, n)}<br>*{vtxt}*" if rr else "-")
            p(f"| {LABEL[t]} | " + " | ".join(cells) + " |")
        nosess = [r["tag"] for r in ar if not r["obs"]]
        if nosess:
            p(f"\nruns with no TCP session on the port (scored 0 above): {len(nosess)}")

        # stage depth reached, per target (which stages, not just how many)
        p("\nStages reached (observer), per cell:\n")
        for t in TARGETS:
            for w in tools:
                rr = [r for r in ar if r["target"] == t and r["tool"] == w and r["best"]]
                if not rr:
                    continue
                names = collections.Counter(
                    " → ".join(e["name"] for e in r["best"]["events"]) or "(none)" for r in rr)
                beyond = sum(1 for r in rr if r["best"].get("activity_beyond_n"))
                p(f"- {LABEL[t]} × {w}: " + "; ".join(f"{k} ×{c}" for k, c in names.most_common())
                  + (f" (+ activity beyond N in {beyond} runs)" if beyond else ""))

        # RUNBOOK s5: SC_int vs SC_obs on T1
        xr = [r for r in ar if r["target"] == "XXX"]
        p("\n**SC_int vs SC_obs (T1, per session)**\n")
        p("matched by client source port; sessions with no stage on either side are skipped\n")
        p("| tool | sessions compared | agree | differ | SC_obs > 0 but no SC_int | SC_int recorded under |")
        p("|---|---|---|---|---|---|")
        diffs = collections.Counter()
        for w in tools:
            agree = differ = missing = compared = 0
            drivers = collections.Counter()
            for r in [x for x in xr if x["tool"] == w]:
                ints = int_sessions_by_port(os.path.join(root, r["tag"] + ".decoy.log"))
                for o in r["obs"]:
                    port = int(o["client"].rsplit(":", 1)[1])
                    i = ints.get(port)
                    si = sorted(i["stages"]) if i else []
                    so = o["stages_completed"]
                    if i and i["driver"]:
                        drivers[i["driver"]] += 1
                    if not si and not so:
                        continue                      # e.g. a SYN probe: nothing on either side
                    compared += 1
                    if not i or not si:
                        missing += 1
                        diffs[(w, "none", str(so))] += 1
                    elif si == so:
                        agree += 1
                    else:
                        differ += 1
                        diffs[(w, str(si), str(so))] += 1
            dtxt = ", ".join(f"{k} ×{c}" for k, c in drivers.most_common()) or "-"
            p(f"| {w} | {compared} | {agree} | {differ} | {missing} | {dtxt} |")
        if diffs:
            p("\nDisagreements (SC_int stages vs SC_obs stages, same source port):")
            for (w, si, so), c in sorted(diffs.items()):
                p(f"- {w}: SC_int {si} vs SC_obs {so} ×{c}")

        # session-file collisions: two sessions finalised to the same sc_*.json
        coll = 0
        for r in xr:
            paths = collections.Counter(path for _sc, path in r["finals"])
            coll += sum(c - 1 for c in paths.values() if c > 1)
        p(f"\nSC_int records overwritten (two sessions, same one-second session id): {coll}")

        # cost (protocol s3.5)
        p("\n**Decoy cost per run** (container cgroup; median over runs)\n")
        p("| target | memory.peak | CPU time |")
        p("|---|---|---|")
        for t in TARGETS:
            cs = [r["cost"] for r in ar if r["target"] == t and r["cost"]
                  and r["cost"].get("memory_peak_bytes")]
            if cs:
                mem = statistics.median(c["memory_peak_bytes"] for c in cs) / 2**20
                cpu = statistics.median(c["cpu_usage_usec"] for c in cs) / 1000
                p(f"| {LABEL[t]} | {mem:.1f} MiB | {cpu:.0f} ms |")
    print("\n".join(out))


if __name__ == "__main__":
    main()
