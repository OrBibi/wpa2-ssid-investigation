#!/usr/bin/env python3
"""Track 3 lab wizard. Run: sudo .venv/bin/python lab_cli.py"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from lab.ap2_hostapd import HOSTAPD_LOG, ensure_ap2_running, start_ap2, stop_ap2
from lab.capture import (
    CAPTURE_SECONDS,
    build_filtered_captures,
    print_summary,
    require_root,
    restore_managed_mode,
    run_parser,
    scan_wpa2_networks,
    set_monitor_mode,
    test_monitor,
    timed_capture,
)
from lab.config import (
    LabConfig,
    default_config_path,
    load_config,
    prompt_int,
    prompt_mac,
    prompt_password,
    prompt_text,
    save_config,
)
from lab.devices import choose_wireless_device, list_adapters_brief, discover_wireless_devices


REPO_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = default_config_path(REPO_ROOT)
TOTAL_STEPS = 10


def step(n: int, title: str) -> None:
    print(f"\n[{n}/{TOTAL_STEPS}] {title}")


def abort(msg: str) -> None:
    print(f"[-] {msg}")
    stop_ap2()
    sys.exit(1)


def _tshark_macs(pcap: Path, display_filter: str) -> List[str]:
    try:
        out = subprocess.check_output(
            ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields", "-e", "wlan.sa", "-e", "wlan.da"],
            text=True,
            timeout=60,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    macs: set[str] = set()
    for line in out.splitlines():
        for part in line.split("\t"):
            mac = part.strip().lower()
            if mac and len(mac) == 17 and mac.count(":") == 5:
                macs.add(mac)
    return sorted(macs)


def discover_client_mac_from_pcap(pcap: Path, ssid: str, ap1_bssid: str = "") -> str:
    """Prefer auth/assoc/eapol to AP1 over probe requests (fewer false positives)."""
    candidates: List[str] = []

    if ap1_bssid:
        for filt in (
            f"wlan.fc.type_subtype==0x0b && wlan.da=={ap1_bssid}",
            f"wlan.fc.type_subtype==0x0 && wlan.da=={ap1_bssid}",
            f"eapol && wlan.addr=={ap1_bssid}",
        ):
            for mac in _tshark_macs(pcap, filt):
                if mac != ap1_bssid.lower():
                    candidates.append(mac)

    for mac in _tshark_macs(pcap, f'wlan.fc.type_subtype==0x0004 && wlan.ssid=="{ssid}"'):
        candidates.append(mac)

    # Most frequent client address wins (real phone sends many frames).
    counts: Dict[str, int] = {}
    for mac in candidates:
        counts[mac] = counts.get(mac, 0) + 1
    if not counts:
        return ""

    ranked = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    if len(ranked) == 1 or ranked[0][1] >= ranked[1][1] * 2:
        print(f"[+] client MAC auto-detected: {ranked[0][0]}")
        return ranked[0][0]

    print("[!] Multiple client MACs — pick your phone:")
    for i, (mac, n) in enumerate(ranked[:5]):
        print(f"  [{i}] {mac}  ({n} frames)")
    try:
        return ranked[int(input("Client MAC #: ").strip())][0]
    except (ValueError, IndexError):
        return ""


def discover_client_mac_from_hostapd_log() -> str:
    try:
        text = HOSTAPD_LOG.read_text(encoding="utf-8")
    except OSError:
        return ""
    for line in reversed(text.splitlines()):
        if "AP-STA-CONNECTED" in line:
            mac = line.strip().split()[-1].lower()
            if len(mac) == 17:
                return mac
    return ""


def print_capture_help(step: int, cfg: LabConfig, *, ap2_on: bool) -> None:
    print("  ┌─ PHONE ACTIONS ─────────────────────────────────────")
    print(f"  │ 1. Press ENTER → auto-records {CAPTURE_SECONDS}s")
    print(f"  │ 2. Immediately: Wi-Fi OFF → ON → {cfg.target_ssid}")
    if step == 7:
        print("  │    (AP2 OFF — phone should connect to real router ✓)")
    elif ap2_on:
        print("  │    (AP1+AP2 ON — AP2 has DHCP, ✓ may appear)")
    print("  │ 3. Wait — recording stops automatically")
    print("  │    Goal: capture Auth + Assoc + EAPOL during reconnect")
    print("  └────────────────────────────────────────────────────")


def configure_target_network(cfg: LabConfig) -> LabConfig:
    step(4, "Target network (WPA2-PSK)")
    full = input("Scan ch 1-13? [Y/n]: ").strip().lower()
    if full in ("", "y", "yes"):
        networks = scan_wpa2_networks(cfg.monitor_iface, seconds_per_channel=3)
    else:
        ch = int(input("Channel [6]: ").strip() or "6")
        networks = scan_wpa2_networks(cfg.monitor_iface, channels=[ch], seconds_per_channel=12)

    selected = None
    if networks:
        print(f"  {'#':<4} {'SSID':<24} {'BSSID':<18} {'CH'}")
        for i, net in enumerate(networks):
            print(f"  [{i:<2}] {net['ssid']:<24} {net['bssid']:<18} {net['channel']}")
        try:
            selected = networks[int(input("Network #: ").strip())]
        except (ValueError, IndexError):
            pass

    if selected is None:
        print("[!] Manual entry:")
        cfg.target_ssid = prompt_text("SSID", cfg.target_ssid)
        cfg.ap1_bssid = prompt_mac("AP1 BSSID", cfg.ap1_bssid)
        cfg.channel = prompt_int("Channel", cfg.channel, 1, 13)
    else:
        cfg.target_ssid = selected["ssid"]
        cfg.ap1_bssid = selected["bssid"]
        if str(selected.get("channel", "")).isdigit():
            cfg.channel = int(selected["channel"])

    print(f"[+] {cfg.target_ssid} | AP1 {cfg.ap1_bssid} | ch{cfg.channel}")
    cfg.wpa_passphrase = prompt_password("WPA2 password")
    return cfg.normalized()


def run_wizard() -> None:
    cfg = load_config(CONFIG_PATH).normalized()

    step(1, "Hardware")
    list_adapters_brief()
    if len(discover_wireless_devices()) < 2:
        abort("Need 2 USB Wi-Fi adapters.")

    step(2, "Monitor (Tenda/Ralink)")
    dev = choose_wireless_device("Monitor:", exclude=[cfg.ap2_iface] if cfg.ap2_iface else None)
    if not dev:
        abort("No monitor selected.")
    cfg.monitor_iface = dev.iface
    print(f"[+] {dev.iface}")

    step(3, "AP2 (EDUP/MediaTek)")
    dev = choose_wireless_device("AP2:", exclude=[cfg.monitor_iface])
    if not dev:
        abort("No AP2 selected.")
    cfg.ap2_iface = dev.iface
    cfg.ap2_bssid = dev.mac.lower() if dev.mac else ""
    print(f"[+] {cfg.ap2_iface} bssid={cfg.ap2_bssid}")

    cfg = configure_target_network(cfg)

    step(5, "Client MAC")
    print("  Phone MAC (Settings → Wi-Fi → network details). ENTER = auto-detect later.")
    raw = input("MAC [skip]: ").strip().lower()
    if raw and len(raw) == 17 and raw.count(":") == 5:
        cfg.client_mac = raw

    step(6, "Monitor test")
    set_monitor_mode(cfg.monitor_iface, cfg.channel)
    if not test_monitor(cfg.monitor_iface):
        abort("Monitor test failed.")

    step(7, "Baseline capture")
    stop_ap2()
    print_capture_help(7, cfg, ap2_on=False)
    set_monitor_mode(cfg.monitor_iface, cfg.channel)
    if not timed_capture(cfg.monitor_iface, cfg.capture_path("baseline_raw")):
        abort("Baseline capture failed.")
    if not cfg.client_mac:
        cfg.client_mac = discover_client_mac_from_pcap(
            cfg.capture_path("baseline_raw"), cfg.target_ssid, cfg.ap1_bssid,
        )
        if not cfg.client_mac:
            cfg.client_mac = prompt_mac("Client MAC (from phone settings)")

    step(8, "Modified capture")
    if not start_ap2(cfg):
        abort("AP2 start failed. See hostapd_ap2.log / dnsmasq_ap2.log")
    set_monitor_mode(cfg.monitor_iface, cfg.channel, kill_interfering=False)
    if not ensure_ap2_running(cfg):
        abort("AP2 died after monitor setup. See hostapd_ap2.log")
    print_capture_help(8, cfg, ap2_on=True)
    if not timed_capture(cfg.monitor_iface, cfg.capture_path("modified_raw")):
        stop_ap2()
        abort("Modified capture failed.")
    phone_mac = discover_client_mac_from_hostapd_log()
    if phone_mac and phone_mac != cfg.client_mac:
        print(f"[!] hostapd saw phone {phone_mac} — using it instead of {cfg.client_mac or '(none)'}")
        cfg.client_mac = phone_mac
    stop_ap2()

    step(9, "Filter")
    if not build_filtered_captures(cfg):
        abort("Filter failed.")

    step(10, "Parser")
    if not run_parser(cfg, REPO_ROOT):
        abort("Parser failed.")
    print_summary(cfg)

    save_config(CONFIG_PATH, cfg, include_password=False)
    restore_managed_mode(cfg.monitor_iface)
    print("\n[+] Done. See captures/ and outputs/")


def main() -> None:
    require_root()
    os.chdir(REPO_ROOT)
    Path("captures").mkdir(exist_ok=True)
    Path("outputs").mkdir(exist_ok=True)
    try:
        run_wizard()
    except KeyboardInterrupt:
        stop_ap2()
        sys.exit(1)


if __name__ == "__main__":
    main()
