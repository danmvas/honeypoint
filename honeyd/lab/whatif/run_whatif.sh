#!/usr/bin/env bash
# run_whatif.sh - the RDP matrices again, T1 only, against the honeypoint at
# HEAD with rdp-fixes.patch applied in a temporary copy. The repository is not
# modified. Results: honeyd/lab/results/whatif (score with ../report.py).
#
#   ./honeyd/lab/whatif/run_whatif.sh          (R=5 by default)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$LAB/../.." && pwd)"
TK="$(cd "$LAB/../sc_toolkit" && pwd)"
export OUT="${OUT:-$LAB/results/whatif}" R="${R:-5}"

SRC="$(mktemp -d)"
git -C "$REPO" archive HEAD framework families drivers main.py | tar -x -C "$SRC"
patch -s -d "$SRC" -p1 < "$HERE/rdp-fixes.patch"
mkdir -p "$OUT"; cp "$HERE/rdp-fixes.patch" "$OUT/"
echo "T1 = $(git -C "$REPO" rev-parse --short HEAD) + rdp-fixes.patch, from $SRC"

T1_SRC="$SRC" "$LAB/lab.sh" up
cd "$TK"
export EXEC="$LAB/lab.sh exec" RESTART="$LAB/lab.sh restart" \
       COLLECT="$LAB/lab.sh collect" ONLY="XXX" IFACE=eth0 TCPDUMP_OPTS="-Z root"
for a in ms12_020 bluekeep; do
  ./run_matrix.sh "$a" > "$OUT/matrix_$a.out" 2>&1
done
"$LAB/lab.sh" up          # back to the unpatched repository
python3 "$LAB/report.py" "$OUT"
