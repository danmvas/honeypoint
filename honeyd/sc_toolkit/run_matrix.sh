#!/usr/bin/env bash
# run_matrix.sh - targets x tools x repetitions, one pcap and one JSON per run.
set -uo pipefail

# (no braces in the message: "{a|b}}" closed the expansion early and left a
#  stray "}" on every attack name, so no attack was ever accepted)
ATTACK="${1:?usage: run_matrix.sh eternalblue|bluekeep|ms12_020}"
R="${R:-30}"
OUT="${OUT:-results}"
IFACE="${IFACE:-lo}"

# ---- edit these -----------------------------------------------------------
declare -A TARGET=(
  [STAGED]=10.0.0.40            # T1 STAGED
  [Honeyd]=10.0.0.50         # T2 Related Work baseline
  [Unpatched]=10.0.0.60      # T3 ceiling
  [Patched]=10.0.0.61        # T4 negative reference
  [Inert]=10.0.0.70          # T5 floor
)
# ---------------------------------------------------------------------------

# ---- lab hooks: all optional; unset = the original single-host behaviour --
# EXEC          prefix that runs capture + tool where the scanner lives
#               (e.g. "../lab/lab.sh exec"). Unset: on this host.
# RESTART       "$RESTART <target>" before every run: restart the decoy and
#               clear its logs (protocol s3: "decoy restarted and logs cleared
#               between runs"). Unset: nothing is restarted.
# COLLECT       "$COLLECT <target> <tag> <outdir>" after every run, to keep the
#               decoy's own records (SC_int JSON, log) with that run.
# ONLY          space-separated subset of the targets above. Unset: all five.
# TCPDUMP_OPTS  extra tcpdump options (e.g. "-Z root"). Unset: none.
EXEC="${EXEC:-}"; RESTART="${RESTART:-}"; COLLECT="${COLLECT:-}"
ONLY="${ONLY:-}"; TCPDUMP_OPTS="${TCPDUMP_OPTS:-}"
# ---------------------------------------------------------------------------

case "$ATTACK" in
  eternalblue) PORT=445
     declare -a TOOLS=(
       "msf_smb_ms17_010|msfconsole -q -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS %IP%; run; exit'"
       "nmap_smb_vuln|nmap -Pn -p445 --script smb-vuln-ms17-010 %IP%"
       "msf_exploit|msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS %IP%; set PAYLOAD generic/shell_reverse_tcp; set LHOST 127.0.0.1; check; exit'"
     ) ;;
  bluekeep) PORT=3389
     declare -a TOOLS=(
       "msf_bluekeep|msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS %IP%; run; exit'"
       "rdpscan|rdpscan %IP%"
       "nmap_rdp_enum|nmap -Pn -p3389 --script rdp-enum-encryption %IP%"
     ) ;;
  ms12_020) PORT=3389
     declare -a TOOLS=(
       "msf_ms12_020|msfconsole -q -x 'use auxiliary/scanner/rdp/ms12_020_check; set RHOSTS %IP%; run; exit'"
     ) ;;
  *) echo "unknown attack: $ATTACK" >&2; exit 2 ;;
esac

mkdir -p "$OUT"
$EXEC sh -c 'command -v tcpdump' >/dev/null || { echo "tcpdump missing" >&2; exit 1; }

# Randomise cell order so a drift in the testbed does not align with one target.
CELLS=()
for t in "${!TARGET[@]}"; do
  [[ -n "$ONLY" && " $ONLY " != *" $t "* ]] && continue
  for spec in "${TOOLS[@]}"; do CELLS+=("$t|$spec"); done
done
mapfile -t CELLS < <(printf '%s\n' "${CELLS[@]}" | shuf)

for rep in $(seq 1 "$R"); do
  for cell in "${CELLS[@]}"; do
    target="${cell%%|*}"; rest="${cell#*|}"
    tool="${rest%%|*}";   cmd="${rest#*|}"
    ip="${TARGET[$target]}"

    # Exploitation modules are never pointed at the real unpatched host.
    if [[ "$tool" == *exploit* && "$target" == "Unpatched" ]]; then continue; fi

    tag="${ATTACK}_${target}_${tool}_r${rep}"
    pcap="$OUT/$tag.pcap"

    [[ -n "$RESTART" ]] && $RESTART "$target"

    # capture + tool, unchanged, but run wherever EXEC points (here if unset)
    $EXEC bash -c '
      tcpdump -i "$1" -s0 $6 -w "$2" "$3" 2>/dev/null &
      tcpdump_pid=$!
      sleep 1
      eval "$4" >"$5" 2>&1
      sleep 1
      kill "$tcpdump_pid" 2>/dev/null; wait "$tcpdump_pid" 2>/dev/null
      true' _ "$IFACE" "$pcap" "tcp port $PORT and host $ip" \
              "${cmd//%IP%/$ip}" "$OUT/$tag.log" "$TCPDUMP_OPTS"

    [[ -n "$COLLECT" ]] && $COLLECT "$target" "$tag" "$OUT"

    python3 sc_observer.py --pcap "$pcap" --attack "$ATTACK" --port "$PORT" \
        --target "$target" --tool "$tool" --json "$OUT/$tag.json" --quiet \
      || echo "  no session scored: $tag"
    echo "done $tag"
  done
done

echo
python3 aggregate_sc.py --glob "$OUT/*.json" --attack "$ATTACK" --latex
