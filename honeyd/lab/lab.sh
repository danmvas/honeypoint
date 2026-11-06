#!/usr/bin/env bash
# lab.sh - the RUNBOOK testbed on one machine, rootless, with podman.
#
#   lab.sh up                       build/start network, decoys and scanner
#   lab.sh down                     remove containers (results are kept)
#   lab.sh status
#   lab.sh versions                 RUNBOOK section 0: pin and record versions
#   lab.sh safety                   RUNBOOK section 7: prove there is no route off-host
#   lab.sh restart <target>         stop, clear logs, start, wait until it listens
#   lab.sh collect <target> <tag> <outdir>
#                                   keep the decoy's own records with the run:
#                                   its log, SC_int JSONs (XXX), cgroup cost
#   lab.sh exec <cmd...>            run in the scanner (same paths as the host)
#
# run_matrix.sh drives it through its EXEC / RESTART / COLLECT hooks, e.g.:
#   cd honeyd/sc_toolkit
#   EXEC="../lab/lab.sh exec" RESTART="../lab/lab.sh restart" \
#   COLLECT="../lab/lab.sh collect" ONLY="XXX Honeyd Inert" IFACE=eth0 \
#   TCPDUMP_OPTS="-Z root" OUT=../lab/results ./run_matrix.sh eternalblue
#
# Addresses are the runbook's. T3/T4 (real Windows VMs) do not exist here.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
T1_SRC="${T1_SRC:-$REPO}"      # what T1 runs; whatif/run_whatif.sh points it at a patched copy
TOOLKIT="$REPO/honeyd/sc_toolkit"
RESULTS="${LAB_RESULTS:-$HERE/results}"
STATE="$RESULTS/.state"
T1LOGS="$RESULTS/.t1_live"          # HONEYPOINT_LOG_DIR: sc_*.json (SC_int)
T1APPLOGS="$RESULTS/.t1_applogs"    # mounted over the repo's logs/ (driver text + events.jsonl)

NET=honeylab
PY=docker.io/library/python@sha256:ac25e5afbfdb4a94ff99cc24b0345719210133144481480bcba6085efa36a341  # 3.14.10-slim
HONEYD_IMG=localhost/honeyd:a0f3d64
SCANNER_IMG=localhost/sc-scanner
NOLABEL=(--security-opt label=disable)   # bind-mount the repo without relabelling it

cname() {
  case "$1" in
    XXX)    echo t1-honeypoint ;;
    Honeyd) echo t2-honeyd ;;
    Inert)  echo t5-inert ;;
    Unpatched|Patched) echo "lab.sh: $1 (real Windows VM) does not exist in this lab" >&2; return 1 ;;
    *) echo "lab.sh: unknown target $1" >&2; return 1 ;;
  esac
}

listening() {   # container port...  -> 0 when every port is in LISTEN
  local c=$1; shift
  local tbl; tbl=$(podman exec "$c" cat /proc/net/tcp /proc/net/tcp6 2>/dev/null) || return 1
  for p in "$@"; do
    awk -v h="$(printf ':%04X' "$p")" '$2 ~ h"$" && $4 == "0A" {f=1} END {exit !f}' <<<"$tbl" || return 1
  done
}

wait_ready() {
  local c=$1 since=$2 i
  for i in $(seq 1 150); do
    case "$c" in
      t2-honeyd) podman logs --since "$since" "$c" 2>&1 | grep -q 'Demoting process privileges' && return 0 ;;
      *)         listening "$c" 445 3389 && return 0 ;;
    esac
    sleep 0.1
  done
  echo "lab.sh: $c not ready after 15s" >&2; podman logs --tail 20 "$c" >&2; return 1
}

start_decoy() {
  local c=$1 since
  since=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
  mkdir -p "$STATE"; echo "$since" > "$STATE/$c.since"
  podman start "$c" >/dev/null
  wait_ready "$c" "$since"
}

cmd_up() {
  mkdir -p "$RESULTS" "$STATE" "$T1LOGS" "$T1APPLOGS"
  podman image exists "$HONEYD_IMG" || podman build -t "$HONEYD_IMG" -f "$REPO/honeyd/Containerfile" "$REPO/honeyd"
  podman image exists "$SCANNER_IMG" || podman build --cap-add NET_RAW -t "$SCANNER_IMG" -f "$HERE/scanner.Containerfile" "$HERE"

  podman rm -f t1-honeypoint t2-honeyd t5-inert scanner >/dev/null 2>&1 || true

  # --internal: no NAT, no default route -> no path off this host (RUNBOOK s0, s7)
  # --disable-dns: otherwise nmap's reverse lookup returns container names for
  #   T1/T5 but not for Honeyd's virtual IP, a lab artifact that differs by target
  podman network rm -f "$NET" >/dev/null 2>&1 || true
  podman network create --internal --disable-dns --subnet 10.0.0.0/24 "$NET" >/dev/null

  # T1 - the honeypoint framework, all drivers (445 + both RDP variants on 3389)
  podman create --name t1-honeypoint --network "$NET" --ip 10.0.0.40 --mac-address 02:00:0a:00:00:28 \
    "${NOLABEL[@]}" -v "$T1_SRC:/app:ro" -v "$T1APPLOGS:/app/logs" -v "$T1LOGS:/logs" -w /app \
    -e HONEYPOINT_LOG_DIR=/logs -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUNBUFFERED=1 \
    "$PY" python3 -m framework.launcher >/dev/null

  # T2 - Honeyd, virtual host 10.0.0.50 (the container itself is 10.0.0.2)
  podman create --name t2-honeyd --network "$NET" --ip 10.0.0.2 --mac-address 02:00:0a:00:00:02 \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    -e HONEYD_IFACE=eth0 -e HONEYD_IP=10.0.0.50 -e HONEYD_MAC=00:1b:21:3a:4f:50 \
    "$HONEYD_IMG" >/dev/null

  # T5 - inert socket
  podman create --name t5-inert --network "$NET" --ip 10.0.0.70 --mac-address 02:00:0a:00:00:46 \
    "${NOLABEL[@]}" -v "$HERE/inert.py:/inert.py:ro" "$PY" python3 /inert.py >/dev/null

  for c in t1-honeypoint t2-honeyd t5-inert; do start_decoy "$c"; done

  # Scanner. Toolkit and results mounted at the SAME absolute paths as on the
  # host, so run_matrix.sh's relative paths mean the same thing on both sides.
  podman run -d --name scanner --network "$NET" --ip 10.0.0.9 --mac-address 02:00:0a:00:00:09 \
    --cap-add NET_RAW --cap-add NET_ADMIN "${NOLABEL[@]}" \
    -v "$TOOLKIT:$TOOLKIT" -v "$RESULTS:$RESULTS" \
    "$SCANNER_IMG" >/dev/null
  # veth leaves TCP checksums for a NIC that does not exist; Honeyd (pcap,
  # userspace) would drop every SYN as corrupt. Applied for every target alike.
  podman exec scanner ethtool -K eth0 tx off >/dev/null
  [[ "$T1_SRC" == "$REPO" ]] || echo "NOTE: T1 runs $T1_SRC, not the repository"
  cmd_status
}

cmd_down() { podman rm -f t1-honeypoint t2-honeyd t5-inert scanner >/dev/null 2>&1 || true; echo "containers removed; results kept in $RESULTS"; }

cmd_status() {
  podman ps -a --filter name='t1-honeypoint|t2-honeyd|t5-inert|scanner' \
    --format '{{.Names}}\t{{.Status}}\t{{.Networks}}'
}

cmd_restart() {
  local c; c=$(cname "$1")
  podman stop -t 3 "$c" >/dev/null 2>&1 || true
  if [[ "$c" == t1-honeypoint ]]; then
    # anything left here was not collected with a run: keep it, but apart
    local d; d="$RESULTS/.orphans/$(date +%s%N)"
    for src in "$T1LOGS" "$T1APPLOGS"; do
      if compgen -G "$src/*" >/dev/null; then mkdir -p "$d"; mv "$src"/* "$d/"; fi
    done
  fi
  start_decoy "$c"
}

cmd_collect() {
  local target=$1 tag=$2 out=$3 c; c=$(cname "$target")
  # cost (protocol s3.5): this container's cgroup since its last start
  podman exec "$c" sh -c 'printf "{\"memory_peak_bytes\": %s, \"cpu_usage_usec\": %s}\n" \
      "$(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo null)" \
      "$(awk "/^usage_usec/{print \$2}" /sys/fs/cgroup/cpu.stat 2>/dev/null || echo null)"' \
      > "$out/$tag.cost.json" 2>/dev/null || true
  podman stop -t 3 "$c" >/dev/null 2>&1 || true          # nothing late can leak into the next run
  podman logs --since "$(cat "$STATE/$c.since")" "$c" > "$out/$tag.decoy.log" 2>&1 || true
  if [[ "$c" == t1-honeypoint ]]; then
    mkdir -p "$out/$tag.sc_int" "$out/$tag.t1_logs"
    if compgen -G "$T1LOGS/sc_*.json" >/dev/null; then mv "$T1LOGS"/sc_*.json "$out/$tag.sc_int/"; fi
    if compgen -G "$T1APPLOGS/*" >/dev/null; then mv "$T1APPLOGS"/* "$out/$tag.t1_logs/"; fi
  fi
}

cmd_exec() { podman exec -w "$PWD" scanner "$@"; }

# What T2 claims to be, read from the Honeyd image: the personality string,
# the nmap-os-db entry it resolves to (Honeyd keeps the LAST fingerprint with a
# given name, personality.c "Overwriting old fingerprint"), the database's $Id,
# and the OS strings the SMB script announces.
honeyd_persona() {
  podman run --rm -i --entrypoint sh "$HONEYD_IMG" -s <<'EOF'
conf=/opt/honeyd/windows.conf.in; db=/usr/local/share/honeyd/nmap-os-db; smb=/opt/scripts/smb.conf
p=$(sed -n 's/^set [^ ]* personality "\(.*\)"$/\1/p' "$conf" | head -1)
n=$(grep -c "^Fingerprint $p\$" "$db")
ln=$(grep -n "^Fingerprint $p\$" "$db" | tail -1 | cut -d: -f1)
c=$(awk -v ln="$ln" 'NR<ln && /^#/ {c=$0} NR==ln {print c; exit}' "$db")
echo "honeyd personality: \"$p\" ($n fingerprints share the name; Honeyd keeps the last, line $ln)"
echo "  entry in effect: ${c#\# }"
echo "  nmap-os-db: $(grep -m1 '^# \$Id' "$db" | sed -e 's/^# //' -e 's/ *$//')"
echo "honeyd smb-autofail: NATIVE_OS \"$(sed -n 's/^NATIVE_OS //p' "$smb")\", LAN_MANAGER \"$(sed -n 's/^LAN_MANAGER //p' "$smb")\""
EOF
}

cmd_versions() {
  local f="$RESULTS/versions.txt"
  {
    echo "# recorded $(date -u +%FT%TZ) by honeyd/lab/lab.sh versions"
    echo "host: $(uname -sr), $(. /etc/os-release; echo "$PRETTY_NAME"), podman $(podman version --format '{{.Client.Version}}')"
    echo "honeypoint: $(git -C "$REPO" rev-parse --short HEAD)$(git -C "$REPO" diff --quiet -- framework families drivers || echo ' (+ uncommitted changes in framework/families/drivers)')"
    echo "msfconsole: $(podman exec scanner msfconsole --version 2>&1 | tail -1)"
    echo "nmap: $(podman exec scanner nmap --version | head -1)"
    echo "rdpscan: commit $(podman exec scanner git -C /src/rdpscan rev-parse HEAD)"
    echo "honeyd: $(podman exec t2-honeyd honeyd --version 2>&1 | head -1), commit $(podman exec t2-honeyd cat /usr/local/share/honeyd/BUILT_FROM_COMMIT)"
    echo "T1/T5 python: $(podman exec t1-honeypoint python3 -V)"
    honeyd_persona
    echo "images:"
    for i in "$PY" "$HONEYD_IMG" "$SCANNER_IMG"; do
      echo "  $i $(podman image inspect "$i" --format '{{.Id}}' | cut -c1-12)"
    done
  } | tee "$f"
}

cmd_safety() {
  echo "network $NET internal=$(podman network inspect "$NET" --format '{{.Internal}}')"
  echo "scanner routes:"; podman exec scanner ip route | sed 's/^/  /'
  if podman exec scanner nc -z -w 3 1.1.1.1 443 2>/dev/null; then
    echo "FAIL: scanner reached 1.1.1.1:443"; return 1
  else
    echo "ok: scanner cannot reach 1.1.1.1:443 (no route off-host)"
  fi
}

case "${1:-}" in
  up) cmd_up ;; down) cmd_down ;; status) cmd_status ;;
  versions) cmd_versions ;; safety) cmd_safety ;;
  restart) cmd_restart "$2" ;;
  collect) cmd_collect "$2" "$3" "$4" ;;
  exec) shift; cmd_exec "$@" ;;
  *) sed -n '2,22p' "$0"; exit 2 ;;
esac; exit $?   # same line: bash never reads past here, so editing this file mid-run is safe
