#!/usr/bin/env bash
# diag_bluekeep_verbose.sh - one run of the Metasploit BlueKeep scanner per
# target with VERBOSE on. The matrix command prints a verdict only when the
# target is VULNERABLE (Safe/Unknown are vprint-only), so this records WHY the
# others were not. Same restart/capture/collect procedure as run_matrix.sh.
#
#   ./honeyd/lab/diag_bluekeep_verbose.sh        (lab must be up and idle)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TK="$(cd "$HERE/../sc_toolkit" && pwd)"
OUT="${OUT:-$HERE/results/diag}"
mkdir -p "$OUT"
LAB="$HERE/lab.sh"
declare -A IP=([XXX]=10.0.0.40 [Honeyd]=10.0.0.50 [Inert]=10.0.0.70)

cd "$TK"
for t in XXX Honeyd Inert; do
  ip=${IP[$t]}; tag="bluekeep_${t}_msf_bluekeep_verbose_r1"
  "$LAB" restart "$t"
  "$LAB" exec bash -c '
    tcpdump -Z root -i eth0 -s0 -w "$1/$2.pcap" "tcp port 3389 and host $3" 2>/dev/null & td=$!
    sleep 1
    msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS $3; set VERBOSE true; run; exit" > "$1/$2.log" 2>&1
    sleep 1; kill $td; wait $td 2>/dev/null; true' _ "$OUT" "$tag" "$ip"
  "$LAB" collect "$t" "$tag" "$OUT"
  python3 sc_observer.py --pcap "$OUT/$tag.pcap" --attack bluekeep --target "$t" \
      --tool msf_bluekeep_verbose --json "$OUT/$tag.json" --quiet || true
  echo "=== $t ($ip)"
  grep -E '^\[[-+*!]\]' "$OUT/$tag.log" | grep -v -E 'RHOSTS|VERBOSE|Setting default action|Scanned 1 of 1|module execution completed' | sed 's/^/  /'
done
