"""Capture, filtering, monitor setup, and parser execution."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from lab.config import LabConfig


def prepare_rf_environment(iface: str, *, kill_interfering: bool = True) -> None:
    """Prepare monitor iface. Skip airmon-ng check kill when AP2 hostapd must stay up."""
    os.system("rfkill unblock all 2>/dev/null")
    os.system(f"nmcli device set {iface} managed no 2>/dev/null")
    if kill_interfering:
        os.system("airmon-ng check kill >/dev/null 2>&1")
        time.sleep(1)


def require_root() -> None:
    if os.geteuid() != 0:
        print("[-] Run: sudo .venv/bin/python lab_cli.py")
        sys.exit(1)


def run_command(cmd: List[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check)


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def set_monitor_mode(iface: str, channel: int, *, kill_interfering: bool = True) -> None:
    prepare_rf_environment(iface, kill_interfering=kill_interfering)
    run_command(["ip", "link", "set", iface, "down"], check=False)
    run_command(["iw", "dev", iface, "set", "type", "monitor"], check=False)
    run_command(["ip", "link", "set", iface, "up"], check=False)
    run_command(["iw", "dev", iface, "set", "channel", str(channel)], check=False)
    time.sleep(1)


def restore_managed_mode(iface: str) -> None:
    if not iface:
        return
    run_command(["ip", "link", "set", iface, "down"], check=False)
    run_command(["iw", "dev", iface, "set", "type", "managed"], check=False)
    run_command(["ip", "link", "set", iface, "up"], check=False)


def test_monitor(iface: str) -> bool:
    try:
        proc = subprocess.run(
            ["tcpdump", "-i", iface, "-c", "10", "type", "mgt"],
            timeout=20, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        return False


CAPTURE_SECONDS = 25


def timed_capture(iface: str, output_path: Path, seconds: int = CAPTURE_SECONDS) -> bool:
    """Record for a fixed duration — one ENTER to start, auto-stops (no second ENTER)."""
    ensure_directory(output_path.parent)
    if output_path.exists():
        if input(f"Overwrite {output_path.name}? [y/N]: ").strip().lower() != "y":
            return False

    print(f"  >> Press ENTER → records {seconds}s automatically")
    sys.stdout.flush()
    input()

    print(f"  >> RECORDING {seconds}s — toggle phone Wi-Fi NOW")
    sys.stdout.flush()

    proc = subprocess.Popen(
        ["timeout", str(seconds), "tcpdump", "-i", iface, "-w", str(output_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    start = time.time()
    while proc.poll() is None:
        left = max(0, seconds - int(time.time() - start))
        print(f"\r  >> {left}s left...   ", end="", flush=True)
        time.sleep(1)
    print()

    ok = output_path.exists() and output_path.stat().st_size > 24
    size = output_path.stat().st_size if output_path.exists() else 0
    print(f"[{'+'if ok else'-'}] {output_path.name} ({size} B)")
    sys.stdout.flush()
    return ok


def interactive_capture(iface: str, output_path: Path, instructions: str = "") -> bool:
    """Deprecated — use timed_capture. Kept for manual/script use."""
    ensure_directory(output_path.parent)
    if output_path.exists():
        if input(f"Overwrite {output_path.name}? [y/N]: ").strip().lower() != "y":
            return False

    if instructions:
        print(instructions)
    print("[2/2] ENTER = start tcpdump | ENTER again = stop (keep ~20s between)")
    sys.stdout.flush()
    input()
    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", str(output_path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print("[*] capturing... toggle phone Wi-Fi now if reconnecting")
    sys.stdout.flush()
    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        if proc.poll() is None:
            print("[*] stopping capture...")
            sys.stdout.flush()
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()

    ok = output_path.exists() and output_path.stat().st_size > 24
    size = output_path.stat().st_size if output_path.exists() else 0
    print(f"[{'+'if ok else'-'}] {output_path.name} ({size} B)")
    sys.stdout.flush()
    return ok


def baseline_capture_instructions(cfg: LabConfig) -> str:
    return (
        "BASELINE capture\n"
        f"- Target SSID: {cfg.target_ssid}\n"
        f"- AP1 (real router) BSSID: {cfg.ap1_bssid or '(set from scan)'}\n"
        "- AP2 (Tenda USB rogue AP) must be STOPPED.\n"
        "- Trigger the same client reconnect action you will use in the modified run."
    )


def modified_capture_instructions(cfg: LabConfig) -> str:
    return (
        "MODIFIED capture\n"
        f"- Target SSID: {cfg.target_ssid}\n"
        f"- AP1 (real router) BSSID: {cfg.ap1_bssid}\n"
        f"- AP2 (Tenda USB) BSSID: {cfg.ap2_bssid}\n"
        "- AP1 and AP2 must both advertise the same SSID with WPA2-PSK.\n"
        "- Use the same client reconnect action as in baseline."
    )


def _tshark_filter_addresses(cfg: LabConfig, *, include_ap2: bool) -> str:
    addresses = [cfg.client_mac, cfg.ap1_bssid]
    if include_ap2:
        addresses.append(cfg.ap2_bssid)
    addr_expr = " || ".join(f"wlan.addr=={mac}" for mac in addresses)
    return f"(wlan.fc.type==0 || eapol) && ({addr_expr})"


def filter_capture(input_path: Path, output_path: Path, display_filter: str, *, force: bool = False) -> bool:
    ensure_directory(output_path.parent)
    if not input_path.exists():
        print(f"[-] Missing input capture: {input_path}")
        return False

    if output_path.exists() and not force:
        if input(f"Overwrite {output_path.name}? [y/N]: ").strip().lower() != "y":
            return False

    try:
        subprocess.run(
            ["tshark", "-r", str(input_path), "-Y", display_filter, "-w", str(output_path)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        print(f"[-] filter failed: {input_path.name}")
        return False
    except FileNotFoundError:
        print("[-] tshark not found")
        return False

    ok = output_path.exists() and output_path.stat().st_size > 24
    if ok:
        print(f"[+] {output_path.name}")
    return ok


def build_filtered_captures(cfg: LabConfig) -> bool:
    errors = cfg.validate_for_modified_filter()
    if errors:
        for err in errors:
            print(f"[-] {err}")
        return False

    baseline_filter = _tshark_filter_addresses(cfg, include_ap2=False)
    modified_filter = _tshark_filter_addresses(cfg, include_ap2=True)

    ok_baseline = filter_capture(
        cfg.capture_path("baseline_raw"),
        cfg.capture_path("baseline_filtered"),
        baseline_filter,
        force=True,
    )
    ok_modified = filter_capture(
        cfg.capture_path("modified_raw"),
        cfg.capture_path("modified_filtered"),
        modified_filter,
        force=True,
    )
    return ok_baseline and ok_modified


def is_wpa2_psk_network(net: Dict[str, str]) -> bool:
    """AKM suite type 2 = WPA2-PSK; fallback to RSN/privacy for picky drivers."""
    akm = net.get("akm", "").strip()
    if akm and any(part.strip() == "2" for part in akm.split(",")):
        return True
    if net.get("rsn_present") == "1" and net.get("privacy") == "1":
        return True
    return False


def normalize_ssid(raw: str) -> str:
    """Decode tshark hex SSIDs (e.g. 4d696368616c5f322e34 -> Michal_2.4)."""
    text = (raw or "").strip()
    if not text or text.upper() in ("<MISSING>", "<HIDDEN>"):
        return "(hidden)"

    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) >= 2 and len(text) % 2 == 0:
        try:
            return bytes.fromhex(text).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass
    return text


def _parse_beacon_pcap(pcap_path: Path, default_channel: int) -> List[Dict[str, str]]:
    if not pcap_path.exists() or pcap_path.stat().st_size <= 24:
        return []

    try:
        out = subprocess.check_output(
            [
                "tshark",
                "-r",
                str(pcap_path),
                "-Y",
                "wlan.fc.type_subtype == 0x0008",
                "-T",
                "fields",
                "-E",
                "separator=|",
                "-e",
                "wlan.bssid",
                "-e",
                "wlan.ssid",
                "-e",
                "wlan_radio.channel",
                "-e",
                "wlan.rsn.akms.type",
                "-e",
                "wlan.rsn.version",
                "-e",
                "wlan.fc.protected",
            ],
            text=True,
            timeout=60,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    networks: Dict[str, Dict[str, str]] = {}
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) < 2:
            continue
        bssid, ssid = parts[0].strip().lower(), normalize_ssid(parts[1].strip())
        if not bssid:
            continue
        channel_seen = parts[2].strip() if len(parts) > 2 and parts[2].strip() else str(default_channel)
        akm = parts[3].strip() if len(parts) > 3 else ""
        rsn_version = parts[4].strip() if len(parts) > 4 else ""
        privacy = parts[5].strip() if len(parts) > 5 else ""
        networks[bssid] = {
            "bssid": bssid,
            "ssid": ssid,
            "channel": channel_seen,
            "akm": akm,
            "rsn_present": "1" if rsn_version else ("1" if akm else "0"),
            "privacy": privacy,
        }
    return list(networks.values())


def _channel_hopper(iface: str, channels: List[int], dwell_sec: float, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        for channel in channels:
            if stop_event.is_set():
                break
            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            time.sleep(dwell_sec)


def scan_beacons(iface: str, channel: int, seconds: int = 12) -> List[Dict[str, str]]:
    """Passive beacon scan on one channel."""
    set_monitor_mode(iface, channel)
    tmp_path = Path(f"/tmp/track3_beacon_scan_ch{channel}.pcapng")
    if tmp_path.exists():
        tmp_path.unlink()

    print(f"[*] Scanning beacons for {seconds}s on channel {channel}...")
    proc = subprocess.run(
        [
            "timeout",
            str(seconds),
            "tcpdump",
            "-i",
            iface,
            "-w",
            str(tmp_path),
            "type",
            "mgt",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 124):
        err = (proc.stderr or proc.stdout or "").strip()
        if err:
            print(f"    tcpdump note: {err}")

    networks = _parse_beacon_pcap(tmp_path, channel)
    return networks


def scan_wpa2_networks(
    iface: str,
    *,
    channels: Optional[List[int]] = None,
    seconds_per_channel: int = 4,
) -> List[Dict[str, str]]:
    """Multi-channel scan with channel hopping — more reliable than fixed-channel capture."""
    channels = channels or list(range(1, 14))
    dwell = max(2.0, float(seconds_per_channel))
    total_seconds = int(len(channels) * dwell) + 3
    tmp_path = Path("/tmp/track3_hop_scan.pcapng")
    if tmp_path.exists():
        tmp_path.unlink()

    print(f"[*] scan ch {channels[0]}-{channels[-1]}")
    set_monitor_mode(iface, channels[0])
    stop_event = threading.Event()
    hopper = threading.Thread(
        target=_channel_hopper,
        args=(iface, channels, dwell, stop_event),
        daemon=True,
    )
    hopper.start()
    proc = subprocess.run(
        [
            "timeout",
            str(total_seconds),
            "tcpdump",
            "-i",
            iface,
            "-w",
            str(tmp_path),
            "type",
            "mgt",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    stop_event.set()
    hopper.join(timeout=5)

    if proc.returncode not in (0, 124):
        err = (proc.stderr or proc.stdout or "").strip()
        if err:
            print(f"[-] tcpdump: {err}")

    all_nets = _parse_beacon_pcap(tmp_path, channels[0])
    discovered: Dict[str, Dict[str, str]] = {}
    for net in all_nets:
        if is_wpa2_psk_network(net):
            discovered[f"{net['bssid']}|{net['ssid']}"] = net

    results = list(discovered.values())
    results.sort(key=lambda n: (n["ssid"].lower(), n["bssid"]))
    print(f"[+] {len(results)} WPA2-PSK network(s)")
    if not results and all_nets:
        for net in all_nets:
            print(f"    {net['ssid']:<22} {net['bssid']} ch{net['channel']}")
    return results


def run_parser(cfg: LabConfig, repo_root: Path) -> bool:
    errors = cfg.validate_for_parser()
    if errors:
        for err in errors:
            print(f"[-] {err}")
        return False

    parser_script = repo_root / "parser" / "ssid_track3_parser.py"
    if not parser_script.exists():
        print(f"[-] Parser not found: {parser_script}")
        return False

    venv_python = repo_root / ".venv" / "bin" / "python"
    python_bin = str(venv_python) if venv_python.exists() else sys.executable

    ensure_directory(Path(cfg.output_dir))
    cmd = [
        python_bin,
        str(parser_script),
        "--pcap",
        str(cfg.capture_path("baseline_filtered")),
        "--pcap",
        str(cfg.capture_path("modified_filtered")),
        "--output-dir",
        cfg.output_dir,
        "--target-ssid",
        cfg.target_ssid,
        "--ap1-bssid",
        cfg.ap1_bssid,
        "--ap2-bssid",
        cfg.ap2_bssid,
    ]
    print("[*] parser...")
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("[-] parser failed")
        return False
    return True


def print_summary(cfg: LabConfig) -> None:
    summary_path = Path(cfg.output_dir) / "claim_summary.json"
    if not summary_path.exists():
        print(f"[-] missing {summary_path}")
        return
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    print(
        f"ssid_pre_assoc={summary.get('ssid_visible_pre_assoc')} "
        f"multi_bssid={summary.get('same_ssid_advertised_by_multiple_bssids')} "
        f"selected={summary.get('selected_bssid_from_auth_assoc')} "
        f"eapol={summary.get('eapol_seen')}"
    )
