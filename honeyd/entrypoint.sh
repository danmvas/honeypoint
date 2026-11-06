#!/bin/sh
# Render the config for this run and start Honeyd in the foreground.
# Extra arguments are passed straight to honeyd.
set -eu

: "${HONEYD_IFACE:=eth0}"
: "${HONEYD_IP:=10.0.0.50}"
: "${HONEYD_MAC:=00:1b:21:3a:4f:50}"   # fixed Intel OUI; set to taste
CONF=/etc/honeyd/windows.conf
DATA=/usr/local/share/honeyd

mkdir -p /etc/honeyd /var/log/honeyd
sed -e "s/@HONEYD_IP@/${HONEYD_IP}/g" -e "s/@HONEYD_MAC@/${HONEYD_MAC}/g" \
    /opt/honeyd/windows.conf.in > "$CONF"

# Honeyd demotes itself to nobody (65534) *before* opening its logs.
chown 65534:65534 /var/log/honeyd

echo "honeyd commit: $(cat "$DATA/BUILT_FROM_COMMIT")"
echo "interface=${HONEYD_IFACE} virtual_ip=${HONEYD_IP} mac=${HONEYD_MAC} config=${CONF}"

exec honeyd -d -i "$HONEYD_IFACE" \
    -p "$DATA/nmap-os-db" -x "$DATA/xprobe2.conf" -a "$DATA/nmap.assoc" \
    -f "$CONF" \
    -l /var/log/honeyd/honeyd.log -s /var/log/honeyd/service.log \
    "$@" "$HONEYD_IP"
