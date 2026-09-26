#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${1:-wlan0}"

if command -v nmcli &>/dev/null; then
    if ! nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list ifname "$INTERFACE" 2>/dev/null | while IFS=: read -r ssid signal enc; do
        [ -z "$ssid" ] && continue
        printf "%-30s  %-5s  %s\n" "$ssid" "$signal" "$enc"
    done | sort -k2 -rn; then
        echo "error: interface $INTERFACE could not be scanned" >&2
        exit 1
    fi
    exit 0
fi

if ! command -v iwlist &>/dev/null; then
    echo "error: neither nmcli nor iwlist found (install wireless-tools or NetworkManager)" >&2
    exit 1
fi

if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "error: interface $INTERFACE not found" >&2
    exit 1
fi

echo "[*] Scanning on $INTERFACE ..." >&2
iwlist "$INTERFACE" scan 2>/dev/null | awk '
/ESSID/ {
    gsub(/.*ESSID:"|"/, "")
    ssid = $0
}
/Encryption/ {
    gsub(/.*Encryption:/, "")
    enc = $0
}
/Quality/ {
    gsub(/  Quality/, "")
    gsub(/  Signal level/, "")
    qual = $1
    if (ssid != "" && ssid !~ /^$/) {
        printf "%-30s  %-15s  %s\n", ssid, qual, enc
    }
    ssid = ""
}
' | sort -t/ -k2 -rn 2>/dev/null || echo "[-] No networks found or scan failed."
