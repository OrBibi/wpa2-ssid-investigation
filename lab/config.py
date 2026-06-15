"""Lab configuration persistence."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional


MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)

CAPTURE_FILES = {
    "baseline_raw": "track3_same_ssid_baseline_ap1_only.pcapng",
    "modified_raw": "track3_same_ssid_modified_ap1_ap2.pcapng",
    "baseline_filtered": "track3_filtered_baseline_authorized_only.pcapng",
    "modified_filtered": "track3_filtered_modified_authorized_only.pcapng",
}


@dataclass
class LabConfig:
    target_ssid: str = ""
    ap1_bssid: str = ""
    ap2_bssid: str = ""
    client_mac: str = ""
    monitor_iface: str = ""
    ap2_iface: str = ""
    wpa_passphrase: str = ""
    channel: int = 6
    capture_dir: str = "captures"
    output_dir: str = "outputs"

    def capture_path(self, key: str) -> Path:
        return Path(self.capture_dir) / CAPTURE_FILES[key]

    def normalized(self) -> "LabConfig":
        cfg = LabConfig(**asdict(self))
        cfg.ap1_bssid = cfg.ap1_bssid.lower()
        cfg.ap2_bssid = cfg.ap2_bssid.lower()
        cfg.client_mac = cfg.client_mac.lower()
        return cfg

    def validate_for_capture(self) -> list[str]:
        errors: list[str] = []
        if not self.monitor_iface:
            errors.append("monitor_iface is not set")
        if self.channel < 1 or self.channel > 196:
            errors.append("channel must be between 1 and 196")
        if not self.target_ssid:
            errors.append("target_ssid is not set")
        return errors

    def validate_for_filter(self) -> list[str]:
        errors = self.validate_for_capture()
        for field_name in ("ap1_bssid", "client_mac"):
            value = getattr(self, field_name)
            if not value or not MAC_RE.match(value):
                errors.append(f"{field_name} must be a valid MAC address")
        return errors

    def validate_for_modified_filter(self) -> list[str]:
        errors = self.validate_for_filter()
        if not self.ap2_bssid or not MAC_RE.match(self.ap2_bssid):
            errors.append("ap2_bssid must be a valid MAC address")
        return errors

    def validate_for_parser(self) -> list[str]:
        errors = self.validate_for_modified_filter()
        for key in ("baseline_filtered", "modified_filtered"):
            path = self.capture_path(key)
            if not path.exists():
                errors.append(f"missing filtered capture: {path}")
        return errors

    def to_dict(self, *, include_password: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if not include_password:
            data["wpa_passphrase"] = ""
        return data

    def masked_passphrase(self) -> str:
        if not self.wpa_passphrase:
            return "(not set)"
        return "*" * min(len(self.wpa_passphrase), 12)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LabConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


def default_config_path(repo_root: Path) -> Path:
    return repo_root / "lab_config.json"


def load_config(path: Path) -> LabConfig:
    if not path.exists():
        return LabConfig()
    data = json.loads(path.read_text(encoding="utf-8"))
    return LabConfig.from_dict(data)


def save_config(path: Path, config: LabConfig, *, include_password: bool = True) -> None:
    path.write_text(
        json.dumps(config.normalized().to_dict(include_password=include_password), indent=2),
        encoding="utf-8",
    )


def prompt_password(label: str = "WPA2 passphrase") -> str:
    import getpass

    while True:
        value = getpass.getpass(f"{label}: ").strip()
        if len(value) >= 8:
            return value
        print("  Passphrase >= 8 chars")


def prompt_mac(label: str, current: str = "") -> str:
    while True:
        raw = input(f"{label}{' [' + current + ']' if current else ''}: ").strip().lower()
        if not raw and current:
            return current.lower()
        if MAC_RE.match(raw):
            return raw
        print("  bad MAC")


def prompt_text(label: str, current: str = "", required: bool = True) -> str:
    while True:
        raw = input(f"{label}{' [' + current + ']' if current else ''}: ").strip()
        if raw:
            return raw
        if current:
            return current
        if not required:
            return ""
        print("  Value is required.")


def prompt_int(label: str, current: int, min_value: int, max_value: int) -> int:
    while True:
        raw = input(f"{label} [{current}]: ").strip()
        if not raw:
            return current
        try:
            value = int(raw)
            if min_value <= value <= max_value:
                return value
        except ValueError:
            pass
        print(f"  Enter an integer between {min_value} and {max_value}.")
