#!/usr/bin/env bash
# Start-up cost of each decoy with no scan: restart it exactly as run_matrix.sh
# does before a run, wait IDLE_WAIT seconds, and read the same cgroup counters
# lab.sh collect reads. Subtracting this from the per-run cost separates what a
# decoy costs to start from what one scan adds.
#
#   ./honeyd/lab/idle_cost.sh            # R=10 per decoy, results/idle/
#   R=30 IDLE_WAIT=5 ./honeyd/lab/idle_cost.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
R="${R:-10}"; IDLE_WAIT="${IDLE_WAIT:-5}"
OUT="${OUT:-$HERE/results/idle}"; mkdir -p "$OUT"

for i in $(seq 1 "$R"); do
  for t in XXX Honeyd Inert; do
    "$HERE/lab.sh" restart "$t" >/dev/null
    python3 -c "import time; time.sleep($IDLE_WAIT)"
    case $t in XXX) c=t1-honeypoint;; Honeyd) c=t2-honeyd;; Inert) c=t5-inert;; esac
    podman exec "$c" sh -c 'printf "{\"memory_peak_bytes\": %s, \"cpu_usage_usec\": %s, \"memory_current_bytes\": %s}\n" \
        "$(cat /sys/fs/cgroup/memory.peak)" \
        "$(awk "/^usage_usec/{print \$2}" /sys/fs/cgroup/cpu.stat)" \
        "$(cat /sys/fs/cgroup/memory.current)"' > "$OUT/${t}_idle_r$i.cost.json"
    # The process's own resident set, for comparison with the cgroup charge
    # (the cgroup is not charged for shared pages already in the page cache).
    pid1=$(podman exec "$c" sh -c 'grep -E "^(VmHWM|RssAnon|RssFile):" /proc/1/status | tr -s " \t" " " | tr "\n" ";"' 2>/dev/null || true)
    echo "$pid1" > "$OUT/${t}_idle_r$i.proc.txt"
  done
done

python3 - "$OUT" <<'EOF'
import json, glob, statistics as st, sys, os
out = sys.argv[1]
print("target   memory.peak (MiB)  CPU (ms)   [median over runs; min-max]")
for t in ("XXX", "Honeyd", "Inert"):
    rs = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(out, f"{t}_idle_r*.cost.json")))]
    m = [r["memory_peak_bytes"] / 2**20 for r in rs]; c = [r["cpu_usage_usec"] / 1000 for r in rs]
    print(f"{t:8} {st.median(m):6.1f} [{min(m):.1f}-{max(m):.1f}]   {st.median(c):5.0f} [{min(c):.0f}-{max(c):.0f}]   R={len(rs)}")
EOF
