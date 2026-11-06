#!/usr/bin/env bash
# checks.sh - HONEYD_SETUP.md s7 "start it, and prove it is answering", run
# against every decoy in the lab, each from a fresh restart, with a real
# tcpdump capture next to the probe's own pcap.
#
#   ./honeyd/lab/checks.sh            (lab must be up: lab.sh up)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TK="$(cd "$HERE/../sc_toolkit" && pwd)"
OUT="${LAB_RESULTS:-$HERE/results}/checks"
mkdir -p "$OUT"
LAB="$HERE/lab.sh"

declare -A IP=([Honeyd]=10.0.0.50 [STAGED]=10.0.0.40 [Inert]=10.0.0.70)

for t in Honeyd STAGED Inert; do
  ip=${IP[$t]}; tag="check_$t"
  echo "=================== $t ($ip)"
  "$LAB" restart "$t"
  (cd "$TK" && "$LAB" exec bash -c '
    ip=$1; out=$2; tag=$3
    tcpdump -Z root -i eth0 -s0 -w "$out/$tag.real.pcap" "tcp port 445 and host $ip" 2>/dev/null & td=$!
    sleep 1
    echo "--- 1. ping";        ping -c1 -W2 "$ip" | sed -n 2p
    echo "--- 2. nc 445";      nc -vz -w3 "$ip" 445 2>&1
    echo "--- 3. probe_smb";   timeout 60 python3 probe_smb.py --host "$ip" --port 445 --pcap "$out/$tag.probe.pcap" 2>&1 | tail -3
    sleep 1; kill $td; wait $td 2>/dev/null; true' _ "$ip" "$OUT" "$tag")
  "$LAB" collect "$t" "$tag" "$OUT"
  echo "--- 4. sc_observer, real capture"
  python3 "$TK/sc_observer.py" --pcap "$OUT/$tag.real.pcap" --attack eternalblue --target "$t" \
      --json "$OUT/$tag.real.json"
  if [[ "$t" == STAGED ]]; then
    echo "--- SC_int (framework's own sc_*.json)"
    for f in "$OUT/$tag.sc_int"/sc_*.json; do
      [[ -e "$f" ]] || { echo "  none written"; break; }
      python3 -c 'import json,sys; j=json.load(open(sys.argv[1])); print("  %s  SC_int = %d/%d  stages=%s" % (sys.argv[1].rsplit("/",1)[1], j["completed_stages"], j["total_stages"], [e["stage_number"] for e in j["events"]]))' "$f"
    done
  fi
done
