#!/usr/bin/env bash
# smoke_test.sh - prove the Honeyd image answers, rootless, no real NIC touched.
#
# Creates an isolated podman bridge (10.0.0.0/24, the runbook's addresses),
# runs Honeyd on 10.0.0.2 emulating 10.0.0.50, and runs the runbook's three
# checks from a client at 10.0.0.9, capturing with a real tcpdump.
#
#   ./honeyd/smoke_test.sh            # builds the image if missing
#   OUT=/some/dir ./honeyd/smoke_test.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
IMG=localhost/honeyd:a0f3d64
NET=honeylab
OUT="${OUT:-$HERE/smoke_out}"
mkdir -p "$OUT/logs" "$OUT/pcap"

podman image exists "$IMG" || podman build -t "$IMG" -f "$HERE/Containerfile" "$HERE"
podman network exists "$NET" || podman network create --internal --disable-dns --subnet 10.0.0.0/24 "$NET" >/dev/null

cleanup() { podman rm -f honeyd-t2 >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

podman run -d --name honeyd-t2 --network "$NET" --ip 10.0.0.2 \
    --cap-add NET_RAW --cap-add NET_ADMIN "$IMG" >/dev/null
sleep 2
echo "=== honeyd startup"; podman logs honeyd-t2 2>&1 | sed 's/^/  /'

podman run --rm --network "$NET" --ip 10.0.0.9 \
    --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint bash \
    -v "$HERE/sc_toolkit:/t:ro,Z" -v "$OUT/pcap:/out:Z" "$IMG" -c '
set -u
# veth leaves TCP checksums for the NIC to fill in; there is no NIC, so Honeyd
# would see every SYN with a bad checksum and drop it. Real wire: not needed.
ethtool -K eth0 tx off >/dev/null
tcpdump -Z root -i eth0 -s0 -U -w /out/honeyd_real.pcap host 10.0.0.50 2>/dev/null &
TD=$!; sleep 1
echo "=== 1. ARP + ICMP";   ping -c1 -W2 10.0.0.50 | sed -n 2p; ip neigh show 10.0.0.50
echo "=== 2. TCP 445";      nc -vz -w3 10.0.0.50 445 2>&1
echo "=== 2b. TCP 3389";    nc -vz -w3 10.0.0.50 3389 2>&1 || true
echo "=== 3. SMB probe";    python3 /t/probe_smb.py --host 10.0.0.50 --port 445 --pcap /out/honeyd_probe.pcap 2>&1 | tail -8
sleep 1; kill $TD; wait $TD 2>/dev/null
echo "=== 4. observer, probe-written pcap"
python3 /t/sc_observer.py --pcap /out/honeyd_probe.pcap --attack eternalblue --target Honeyd 2>&1
echo "=== 5. observer, real tcpdump capture"
python3 /t/sc_observer.py --pcap /out/honeyd_real.pcap --attack eternalblue --target Honeyd \
        --json /out/honeyd_real.json 2>&1
'
echo "=== honeyd log"; podman logs honeyd-t2 2>&1 | tail -n +6 | sed 's/^/  /' | tail -25
# podman cp, not a bind mount: Honeyd writes its logs as nobody, which would
# leave sub-UID-owned files on the host that you cannot delete without
# "podman unshare".
podman cp honeyd-t2:/var/log/honeyd/. "$OUT/logs/"
echo "artifacts in $OUT"
