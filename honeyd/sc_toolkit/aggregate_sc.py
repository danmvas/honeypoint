#!/usr/bin/env python3
"""
aggregate_sc.py - turn per-run observer JSONs into the Section 5 tables.

    python3 aggregate_sc.py --glob 'results/*.json' --attack eternalblue --latex

Reports, for each (target, tool) cell, the SC values seen across the R runs.
Zero variance across runs is a stronger claim than a mean, so it is stated
explicitly rather than averaged away.
"""
import argparse, glob, json, statistics
from collections import defaultdict


def load(patterns):
    rows, empty = [], []
    for pat in patterns:
        for path in sorted(glob.glob(pat)):
            with open(path) as fh:
                payload = json.load(fh)
            payload = payload if isinstance(payload, list) else [payload]
            if not payload:
                empty.append(path)
            for r in payload:
                r["_file"] = path
                rows.append(r)
    return rows, empty


def deepest_per_run(rows):
    """One row per result file (= one run): its deepest session.

    A tool may open more than one TCP connection per run. nmap, for one, sends
    a SYN port probe before its NSE script connects; that probe carries no
    payload and always scores 0, so pooling it with the script's session makes
    a deterministic cell look non-deterministic.
    """
    best = {}
    for r in rows:
        k = r["_file"]
        if k not in best or r["completed_stages"] > best[k]["completed_stages"]:
            best[k] = r
    return list(best.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", action="append", required=True)
    ap.add_argument("--attack", default=None)
    ap.add_argument("--latex", action="store_true")
    ap.add_argument("--per-run", action="store_true",
                    help="score each run by its deepest TCP session instead of "
                         "pooling every session (see deepest_per_run)")
    a = ap.parse_args()

    rows, empty = load(a.glob)
    rows = [r for r in rows if not a.attack or r.get("attack") == a.attack]
    if not rows:
        raise SystemExit("no matching result files")
    if a.per_run:
        rows = deepest_per_run(rows)
        print(f"per-run: each run scored by its deepest session ({len(rows)} runs)")
    if empty:
        print(f"{len(empty)} run(s) with no TCP session on the port, not in the table:")
        for p in empty:
            print(f"  {p}")

    cells = defaultdict(list)
    for r in rows:
        # "XXX" was the framework's placeholder name in runs recorded before it was named
        t = r.get("target") or "?"
        t = "STAGED" if t == "XXX" else t
        cells[(t, r.get("tool") or "?")].append(r)

    targets = sorted({t for t, _ in cells})
    tools = sorted({w for _, w in cells})

    print(f"attack: {a.attack or 'all'}   sessions: {len(rows)}\n")
    hdr = f"{'target':34s}" + "".join(f"{w[:20]:>22s}" for w in tools)
    print(hdr); print("-" * len(hdr))
    summary = {}
    for t in targets:
        line = f"{t[:34]:34s}"
        for w in tools:
            rs = cells.get((t, w), [])
            if not rs:
                line += f"{'-':>22s}"; continue
            n = rs[0]["total_stages"]
            vals = [x["completed_stages"] for x in rs]
            uniq = sorted(set(vals))
            if len(uniq) == 1:
                txt = f"{uniq[0]}/{n} (R={len(vals)})"
            else:
                txt = f"{int(statistics.median(vals))}/{n} [{min(vals)}-{max(vals)}]"
            summary[(t, w)] = (vals, n, len(uniq) == 1)
            line += f"{txt:>22s}"
        print(line)

    nondet = [k for k, v in summary.items() if not v[2]]
    print()
    if nondet:
        print("NON-DETERMINISTIC cells (investigate before reporting):")
        for t, w in nondet:
            print(f"  {t} x {w}: {sorted(set(summary[(t, w)][0]))}")
    else:
        print("every cell was deterministic across its runs")

    if a.latex:
        print("\n% --- table rows; paste into 5-Evaluation.tex ---")
        for t in targets:
            cs = []
            for w in tools:
                v = summary.get((t, w))
                if not v:
                    cs.append("--")
                else:
                    vals, n, det = v
                    cs.append(f"{vals[0]}/{n}" if det
                              else f"{int(statistics.median(vals))}/{n}")
            print(f"{t} & " + " & ".join(cs) + r" \\")


if __name__ == "__main__":
    main()
