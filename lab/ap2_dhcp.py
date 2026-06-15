"""Minimal DHCP on AP2 so phones complete connection (like evil_twin lab)."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Optional

AP2_GATEWAY = "10.0.0.1"
AP2_NETMASK = "24"
DNSMASQ_CONF = Path("dnsmasq_ap2.conf")
DNSMASQ_LOG = Path("dnsmasq_ap2.log")

_dnsmasq_process: Optional[subprocess.Popen] = None


def write_dnsmasq_conf(iface: str) -> None:
    DNSMASQ_CONF.write_text(
        (
            f"interface={iface}\n"
            "bind-interfaces\n"
            f"listen-address={AP2_GATEWAY}\n"
            "dhcp-authoritative\n"
            "dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,30m\n"
            f"dhcp-option=3,{AP2_GATEWAY}\n"
            f"dhcp-option=6,{AP2_GATEWAY}\n"
            "log-dhcp\n"
        ),
        encoding="utf-8",
    )


def setup_ap2_gateway(iface: str) -> bool:
    os.system(f"ip addr flush dev {iface} 2>/dev/null")
    rc = os.system(f"ip addr add {AP2_GATEWAY}/{AP2_NETMASK} dev {iface} 2>/dev/null")
    os.system(f"ip link set {iface} up 2>/dev/null")
    return rc == 0


def allow_dhcp_firewall(iface: str) -> None:
    """airmon-ng check kill can set INPUT DROP — allow DHCP on AP2 iface."""
    rules = [
        f"iptables -I INPUT 1 -i {iface} -p udp --dport 67 -j ACCEPT",
        f"iptables -I INPUT 1 -i {iface} -p udp --sport 68 --dport 67 -j ACCEPT",
    ]
    for cmd in rules:
        os.system(f"{cmd} 2>/dev/null")


def start_dnsmasq(iface: str) -> bool:
    global _dnsmasq_process
    os.system("killall dnsmasq 2>/dev/null")
    time.sleep(0.5)
    write_dnsmasq_conf(iface)
    if not setup_ap2_gateway(iface):
        print(f"[-] Could not assign {AP2_GATEWAY} on {iface}")
        return False
    allow_dhcp_firewall(iface)
    with DNSMASQ_LOG.open("w", encoding="utf-8") as logf:
        _dnsmasq_process = subprocess.Popen(
            ["dnsmasq", "-C", str(DNSMASQ_CONF), "-d"],
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
    time.sleep(1)
    if _dnsmasq_process.poll() is not None:
        print("[-] dnsmasq failed. See dnsmasq_ap2.log")
        return False
    print(f"[+] DHCP ON {iface} ({AP2_GATEWAY}, pool 10.0.0.10-100)")
    return True


def stop_dnsmasq() -> None:
    global _dnsmasq_process
    if _dnsmasq_process and _dnsmasq_process.poll() is None:
        _dnsmasq_process.terminate()
        try:
            _dnsmasq_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _dnsmasq_process.kill()
    _dnsmasq_process = None
    os.system("killall dnsmasq 2>/dev/null")
