"""Wireless interface and USB adapter discovery."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


# Common USB Wi-Fi vendor IDs (not tied to a specific serial number).
KNOWN_WIFI_VENDORS = {
    "0e8d": "MediaTek",
    "148f": "Ralink",
    "0bda": "Realtek",
    "2357": "TP-Link",
    "7392": "Edimax",
    "2001": "D-Link",
    "0cf3": "Qualcomm/Atheros",
}


@dataclass
class WirelessDevice:
    iface: str
    mac: str = ""
    usb_vendor_id: str = ""
    usb_product_id: str = ""
    usb_serial: str = ""
    usb_manufacturer: str = ""
    usb_product_name: str = ""
    iw_type: str = ""
    link_state: str = ""
    role_hint: str = ""
    has_netdev: bool = True

    @property
    def usb_id(self) -> str:
        if self.usb_vendor_id and self.usb_product_id:
            return f"{self.usb_vendor_id}:{self.usb_product_id}"
        return ""

    def short_label(self) -> str:
        parts = [self.iface]
        if self.mac:
            parts.append(self.mac)
        if self.usb_id:
            parts.append(self.usb_id)
        return " ".join(parts)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _iface_mac(iface: str) -> str:
    raw = _read_text(Path(f"/sys/class/net/{iface}/address"))
    return raw.lower()


def _iface_link_state(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["ip", "-br", "link", "show", iface],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        parts = out.split()
        return parts[2] if len(parts) >= 3 else ""
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _iface_iw_type(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "info"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        for line in out.splitlines():
            if "type" in line:
                return line.split("type", 1)[1].strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def _usb_fields_from_iface(iface: str) -> Dict[str, str]:
    fields = {
        "usb_vendor_id": "",
        "usb_product_id": "",
        "usb_serial": "",
        "usb_manufacturer": "",
        "usb_product_name": "",
    }
    try:
        dev = Path(os.path.realpath(f"/sys/class/net/{iface}/device"))
    except OSError:
        return fields

    fields["usb_vendor_id"] = _read_text(dev / "idVendor")
    fields["usb_product_id"] = _read_text(dev / "idProduct")
    fields["usb_serial"] = _read_text(dev / "serial")
    fields["usb_manufacturer"] = _read_text(dev / "manufacturer")
    fields["usb_product_name"] = _read_text(dev / "product")

    if not fields["usb_serial"]:
        try:
            out = subprocess.check_output(
                ["udevadm", "info", "-q", "property", "-p", str(dev)],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            for line in out.splitlines():
                if line.startswith("ID_SERIAL_SHORT="):
                    fields["usb_serial"] = line.split("=", 1)[1].strip()
                elif line.startswith("ID_VENDOR=") and not fields["usb_manufacturer"]:
                    fields["usb_manufacturer"] = line.split("=", 1)[1].strip()
                elif line.startswith("ID_MODEL=") and not fields["usb_product_name"]:
                    fields["usb_product_name"] = line.split("=", 1)[1].strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return fields


def role_hint_for_device(vendor_id: str, product_id: str) -> str:
    vendor = KNOWN_WIFI_VENDORS.get(vendor_id.lower(), "")
    if vendor_id.lower() == "0e8d":
        return "MediaTek/EDUP — recommended AP2 (hostapd rogue AP)"
    if vendor_id.lower() == "148f":
        return "Ralink/Tenda — recommended MONITOR (sniff/capture)"
    if vendor:
        return f"{vendor} USB Wi-Fi adapter"
    return "USB Wi-Fi adapter"


def list_wlan_interface_names() -> List[str]:
    names: List[str] = []
    try:
        out = subprocess.check_output(
            ["iw", "dev"], stderr=subprocess.DEVNULL, text=True, timeout=5
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                names.append(line.split()[1])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    if not names:
        try:
            out = subprocess.check_output(
                ["ip", "-br", "link"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            for line in out.splitlines():
                iface = line.split()[0]
                if iface.startswith(("wl", "wlan", "wlp", "wlx")):
                    names.append(iface)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

    seen = set()
    unique: List[str] = []
    for iface in names:
        if iface not in seen:
            seen.add(iface)
            unique.append(iface)
    return unique


def discover_wireless_devices() -> List[WirelessDevice]:
    devices: List[WirelessDevice] = []
    for iface in list_wlan_interface_names():
        usb = _usb_fields_from_iface(iface)
        devices.append(
            WirelessDevice(
                iface=iface,
                mac=_iface_mac(iface),
                iw_type=_iface_iw_type(iface),
                link_state=_iface_link_state(iface),
                role_hint=role_hint_for_device(usb["usb_vendor_id"], usb["usb_product_id"]),
                has_netdev=True,
                **usb,
            )
        )
    return devices


def _parse_lsusb_entries() -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    try:
        out = subprocess.check_output(["lsusb"], stderr=subprocess.DEVNULL, text=True, timeout=5)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return entries

    pattern = re.compile(
        r"^Bus (\d+) Device (\d+): ID ([0-9a-f]{4}):([0-9a-f]{4}) (.+)$",
        re.IGNORECASE,
    )
    for line in out.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        bus, dev, vid, pid, desc = match.groups()
        if vid.lower() not in KNOWN_WIFI_VENDORS:
            continue
        entries.append(
            {
                "bus": bus,
                "device": dev,
                "usb_vendor_id": vid.lower(),
                "usb_product_id": pid.lower(),
                "description": desc.strip(),
            }
        )
    return entries


def discover_usb_wifi_without_interface() -> List[WirelessDevice]:
    """USB Wi-Fi visible in lsusb but without a kernel netdev yet."""
    iface_usb_ids = {
        (d.usb_vendor_id, d.usb_product_id)
        for d in discover_wireless_devices()
        if d.usb_vendor_id and d.usb_product_id
    }
    extras: List[WirelessDevice] = []
    for entry in _parse_lsusb_entries():
        key = (entry["usb_vendor_id"], entry["usb_product_id"])
        if key in iface_usb_ids:
            continue
        extras.append(
            WirelessDevice(
                iface=f"usb:{entry['bus']}:{entry['device']}",
                usb_vendor_id=entry["usb_vendor_id"],
                usb_product_id=entry["usb_product_id"],
                usb_product_name=entry["description"],
                role_hint=role_hint_for_device(entry["usb_vendor_id"], entry["usb_product_id"]),
                has_netdev=False,
            )
        )
    return extras


def list_all_wifi_hardware() -> List[WirelessDevice]:
    return discover_wireless_devices() + discover_usb_wifi_without_interface()


def list_adapters_brief() -> None:
    devices = discover_wireless_devices()
    if not devices:
        print("[-] No wlan interfaces")
        return
    for dev in devices:
        print(f"  {dev.short_label()}")


def choose_wireless_device(
    prompt: str,
    *,
    require_netdev: bool = True,
    exclude: Optional[List[str]] = None,
) -> Optional[WirelessDevice]:
    exclude = {e.lower() for e in (exclude or [])}
    devices = discover_wireless_devices() if require_netdev else list_all_wifi_hardware()
    devices = [d for d in devices if d.iface.lower() not in exclude]

    if not devices:
        print("[-] No interfaces")
        return None

    for idx, dev in enumerate(devices):
        print(f"  [{idx}] {dev.short_label()}")

    try:
        choice = int(input(f"{prompt} ").strip())
        if choice < 0 or choice >= len(devices):
            raise IndexError
        return devices[choice]
    except (ValueError, IndexError):
        print("[-] Invalid")
        return None
