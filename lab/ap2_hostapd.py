"""AP2 rogue-condition access point via hostapd (Tenda USB adapter)."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from lab.ap2_dhcp import start_dnsmasq, stop_dnsmasq
from lab.config import LabConfig


HOSTAPD_CONF = Path("hostapd_ap2.conf")
HOSTAPD_LOG = Path("hostapd_ap2.log")
_ap2_process: Optional[subprocess.Popen] = None


def write_hostapd_conf(cfg: LabConfig) -> None:
    if not cfg.ap2_iface:
        raise ValueError("ap2_iface is not set")
    if not cfg.target_ssid:
        raise ValueError("target_ssid is not set")
    if not cfg.wpa_passphrase:
        raise ValueError("wpa_passphrase is not set")

    HOSTAPD_CONF.write_text(
        (
            f"interface={cfg.ap2_iface}\n"
            "driver=nl80211\n"
            f"ssid={cfg.target_ssid}\n"
            "hw_mode=g\n"
            f"channel={cfg.channel}\n"
            "country_code=IL\n"
            "ieee80211n=0\n"
            "wmm_enabled=1\n"
            "macaddr_acl=0\n"
            "auth_algs=3\n"
            "wpa=2\n"
            f"wpa_passphrase={cfg.wpa_passphrase}\n"
            "wpa_key_mgmt=WPA-PSK\n"
            "rsn_pairwise=CCMP\n"
            "ignore_broadcast_ssid=0\n"
            "ap_isolate=0\n"
        ),
        encoding="utf-8",
    )


def _wait_for_ap_enabled(timeout: int = 15) -> bool:
    for _ in range(timeout):
        try:
            if "AP-ENABLED" in HOSTAPD_LOG.read_text(encoding="utf-8"):
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


def prepare_ap2_interface(iface: str, channel: int) -> None:
    os.system(f"nmcli device set {iface} managed no 2>/dev/null")
    os.system(f"ip link set {iface} down 2>/dev/null")
    os.system(f"ip addr flush dev {iface} 2>/dev/null")
    os.system(f"iw dev {iface} set type managed 2>/dev/null")
    os.system(f"iw dev {iface} set channel {channel} 2>/dev/null")
    os.system(f"ip link set {iface} up 2>/dev/null")
    time.sleep(1)


def start_ap2(cfg: LabConfig) -> bool:
    global _ap2_process

    if is_ap2_running():
        return True
    if not cfg.ap2_iface or not cfg.target_ssid or not cfg.wpa_passphrase:
        print("[-] AP2: missing iface/ssid/password")
        return False

    os.system("killall hostapd dnsmasq 2>/dev/null")
    time.sleep(1)
    prepare_ap2_interface(cfg.ap2_iface, cfg.channel)
    write_hostapd_conf(cfg)

    with HOSTAPD_LOG.open("w", encoding="utf-8") as logf:
        _ap2_process = subprocess.Popen(
            ["hostapd", str(HOSTAPD_CONF)], stdout=logf, stderr=subprocess.STDOUT,
        )

    if not _wait_for_ap_enabled() or (_ap2_process.poll() is not None):
        print("[-] AP2 failed. See hostapd_ap2.log")
        stop_ap2()
        return False

    if not start_dnsmasq(cfg.ap2_iface):
        print("[-] AP2 DHCP failed. See dnsmasq_ap2.log")
        stop_ap2()
        return False

    print(f"[+] AP2 ON {cfg.target_ssid} ch{cfg.channel}")
    return True


def stop_ap2() -> None:
    global _ap2_process
    stop_dnsmasq()
    if _ap2_process and _ap2_process.poll() is None:
        _ap2_process.terminate()
        try:
            _ap2_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _ap2_process.kill()
    _ap2_process = None
    os.system("killall hostapd dnsmasq 2>/dev/null")


def is_ap2_running() -> bool:
    if _ap2_process and _ap2_process.poll() is None:
        return True
    return False


def ensure_ap2_running(cfg: LabConfig) -> bool:
    """Restart AP2 if hostapd was killed (e.g. by airmon-ng check kill)."""
    if is_ap2_running():
        return True
    print("[!] AP2 not running — restarting hostapd...")
    return start_ap2(cfg)
