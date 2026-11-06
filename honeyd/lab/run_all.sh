#!/usr/bin/env bash
# run_all.sh - RUNBOOK s0 (pin), s7 (isolation), s2 (matrix) and s4 (tables),
# end to end in the podman lab, for every attack.
#
#   ./honeyd/lab/run_all.sh                 # R=30, results in honeyd/lab/results/main
#   R=1 OUT=/abs/path ./honeyd/lab/run_all.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TK="$(cd "$HERE/../sc_toolkit" && pwd)"
export OUT="${OUT:-$HERE/results/main}" R="${R:-30}"
ATTACKS="${ATTACKS:-eternalblue bluekeep ms12_020}"

"$HERE/lab.sh" up
"$HERE/lab.sh" versions
"$HERE/lab.sh" safety || { echo "testbed is not isolated; refusing to run" >&2; exit 1; }
mkdir -p "$OUT"; cp "$HERE/results/versions.txt" "$OUT/"

cd "$TK"
export EXEC="$HERE/lab.sh exec" RESTART="$HERE/lab.sh restart" \
       COLLECT="$HERE/lab.sh collect" ONLY="STAGED Honeyd Inert" \
       IFACE=eth0 TCPDUMP_OPTS="-Z root"
for a in $ATTACKS; do
  echo "########## $a  R=$R  $(date -u +%FT%TZ)"
  ./run_matrix.sh "$a" > "$OUT/matrix_$a.out" 2>&1
  python3 aggregate_sc.py --glob "$OUT/${a}_*.json" --attack "$a" --per-run --latex \
      | tee "$OUT/table_$a.txt"
done
echo "########## finished $(date -u +%FT%TZ)"
