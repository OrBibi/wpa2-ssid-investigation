#!/usr/bin/env bash
# Reset Track 3 lab state before a fresh run.
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Stopping hostapd, dnsmasq..."
killall hostapd dnsmasq 2>/dev/null || true

echo "[*] Removing captures and parser outputs..."
rm -f captures/track3_*.pcapng
rm -f outputs/frames.csv outputs/claim_summary.json

echo "[*] Removing runtime configs and logs..."
rm -f hostapd_ap2.conf hostapd_ap2.log dnsmasq_ap2.conf dnsmasq_ap2.log lab_config.json
rm -f /tmp/track3_*.pcapng

echo "[+] Lab cleanup done. Run: sudo .venv/bin/python lab_cli.py"
