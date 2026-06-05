#!/usr/bin/env python3
"""
Track 3 parser for SSID/BSSID evidence.

Outputs:
- outputs/frames.csv
- outputs/claim_summary.json

Usage example:
python parser/ssid_track3_parser.py \
  --pcap captures/track3_filtered_baseline_authorized_only.pcapng \
  --pcap captures/track3_filtered_modified_authorized_only.pcapng \
  --output-dir outputs \
  --target-ssid "MyLabSSID" \
  --ap1-bssid aa:bb:cc:dd:ee:01 \
  --ap2-bssid aa:bb:cc:dd:ee:02
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List

import pyshark


def safe_get(obj, attr: str, default: str = "") -> str:
    try:
        value = getattr(obj, attr, default)
        return str(value) if value is not None else default
    except Exception:
        return default


def ws_type_subtype(pkt) -> str:
    try:
        if hasattr(pkt, "wlan") and hasattr(pkt.wlan, "fc_type_subtype"):
            raw = str(pkt.wlan.fc_type_subtype)
            value = int(raw, 16) if raw.startswith("0x") else int(raw)
            return f"0x{value:04x}"
    except Exception:
        pass
    return ""


def extract_record(pkt, source_file: str, ap1_bssid: str, ap2_bssid: str) -> Dict[str, str]:
    frame_no = safe_get(pkt.frame_info, "number")
    timestamp_epoch = safe_get(pkt.frame_info, "time_epoch")
    frame_protocols = safe_get(pkt.frame_info, "protocols")

    tx = ""
    rx = ""
    bssid = ""
    type_subtype_hex = ""
    ssid = ""
    auth_alg = ""
    assoc_status_code = ""
    rsn_present = "0"
    akm_suites = ""
    pairwise_cipher = ""
    pmf_capable = ""
    pmf_required = ""
    eapol_msg_num = ""
    eapol_replay_counter = ""
    has_eapol = "0"

    if hasattr(pkt, "wlan"):
        wlan = pkt.wlan
        tx = safe_get(wlan, "ta")
        rx = safe_get(wlan, "ra")
        bssid = safe_get(wlan, "bssid").lower()
        type_subtype_hex = ws_type_subtype(pkt)
        ssid = safe_get(wlan, "ssid")
        auth_alg = safe_get(wlan, "fixed_auth_alg")
        assoc_status_code = safe_get(wlan, "fixed_status_code")

        # RSN fields may be exposed in wlan or wlan_rsn, depending on dissector details.
        rsn_present = "1" if (
            hasattr(wlan, "rsn_akms_type") or
            hasattr(wlan, "rsn_pcs_type") or
            hasattr(wlan, "rsn_capabilities_mfpc") or
            hasattr(wlan, "rsn_capabilities_mfpr")
        ) else "0"

        akm_suites = safe_get(wlan, "rsn_akms_type")
        pairwise_cipher = safe_get(wlan, "rsn_pcs_type")
        pmf_capable = safe_get(wlan, "rsn_capabilities_mfpc")
        pmf_required = safe_get(wlan, "rsn_capabilities_mfpr")

    if hasattr(pkt, "wlan_rsn"):
        wlan_rsn = pkt.wlan_rsn
        if not akm_suites:
            akm_suites = safe_get(wlan_rsn, "akms_type")
        if not pairwise_cipher:
            pairwise_cipher = safe_get(wlan_rsn, "pcs_type")
        if not pmf_capable:
            pmf_capable = safe_get(wlan_rsn, "capabilities_mfpc")
        if not pmf_required:
            pmf_required = safe_get(wlan_rsn, "capabilities_mfpr")
        if akm_suites or pairwise_cipher or pmf_capable or pmf_required:
            rsn_present = "1"

    # Some captures expose EAPOL details in pkt.eapol, others in pkt.wlan_rsna_eapol.
    has_eapol = "1" if hasattr(pkt, "eapol") or hasattr(pkt, "wlan_rsna_eapol") else "0"
    if has_eapol == "1":
        if hasattr(pkt, "wlan_rsna_eapol"):
            eapol_layer = pkt.wlan_rsna_eapol
            eapol_msg_num = safe_get(eapol_layer, "keydes_msgnr")
            eapol_replay_counter = safe_get(eapol_layer, "keydes_replay_counter")
        if (not eapol_msg_num or not eapol_replay_counter) and hasattr(pkt, "eapol"):
            eapol_layer = pkt.eapol
            if not eapol_msg_num:
                eapol_msg_num = safe_get(eapol_layer, "keydes_msgnr")
            if not eapol_replay_counter:
                eapol_replay_counter = safe_get(eapol_layer, "keydes_replay_counter")

    phase = "other"
    if type_subtype_hex in {"0x0008", "0x0004", "0x0005"}:
        phase = "discovery"
    elif type_subtype_hex in {"0x000b", "0x0000", "0x0001"}:
        phase = "auth_assoc"
    elif has_eapol == "1":
        phase = "key_exchange"

    ap_identity = "unknown"
    if bssid and bssid == ap1_bssid:
        ap_identity = "ap1"
    elif bssid and bssid == ap2_bssid:
        ap_identity = "ap2"

    return {
        "source_file": source_file,
        "frame_no": frame_no,
        "timestamp_epoch": timestamp_epoch,
        "tx": tx.lower(),
        "rx": rx.lower(),
        "bssid": bssid,
        "frame_protocols": frame_protocols,
        "type_subtype_hex": type_subtype_hex,
        "phase": phase,
        "ap_identity": ap_identity,
        "ssid": ssid,
        "rsn_present": rsn_present,
        "akm_suites": akm_suites,
        "pairwise_cipher": pairwise_cipher,
        "pmf_capable": pmf_capable,
        "pmf_required": pmf_required,
        "auth_alg": auth_alg,
        "assoc_status_code": assoc_status_code,
        "has_eapol": has_eapol,
        "eapol_msg_num": eapol_msg_num,
        "eapol_replay_counter": eapol_replay_counter,
    }


def parse_pcap(path: Path, ap1_bssid: str, ap2_bssid: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    capture = pyshark.FileCapture(
        str(path),
        display_filter="wlan.fc.type == 0 || eapol",
        keep_packets=False,
    )
    try:
        for pkt in capture:
            records.append(extract_record(pkt, path.name, ap1_bssid, ap2_bssid))
    finally:
        capture.close()
    return records


def build_summary(records: List[Dict[str, str]], target_ssid: str, ap1_bssid: str, ap2_bssid: str) -> Dict:
    summary = {
        "total_records": len(records),
        "target_ssid": target_ssid,
        "ap1_bssid": ap1_bssid,
        "ap2_bssid": ap2_bssid,
        "counts_by_phase": {},
        "ssid_visible_pre_assoc": False,
        "same_ssid_advertised_by_multiple_bssids": False,
        "selected_bssid_from_auth_assoc": [],
        "eapol_seen": False,
        "notes": [
            "This summary reports observed frame-level evidence only.",
            "It does not claim universal behavior beyond captured lab conditions.",
        ],
    }

    phase_counts: Dict[str, int] = {}
    ssid_bssid_set = set()
    selected_bssid = set()

    for r in records:
        phase_counts[r["phase"]] = phase_counts.get(r["phase"], 0) + 1

        if r["phase"] in {"discovery", "auth_assoc"} and r["ssid"] == target_ssid:
            summary["ssid_visible_pre_assoc"] = True

        if r["ssid"] == target_ssid and r["bssid"]:
            ssid_bssid_set.add(r["bssid"])

        if r["phase"] == "auth_assoc" and r["type_subtype_hex"] in {"0x000b", "0x0000"} and r["bssid"]:
            selected_bssid.add(r["bssid"])

        if r["has_eapol"] == "1":
            summary["eapol_seen"] = True

    summary["counts_by_phase"] = phase_counts
    summary["same_ssid_advertised_by_multiple_bssids"] = len(ssid_bssid_set) >= 2
    summary["selected_bssid_from_auth_assoc"] = sorted(selected_bssid)
    return summary


def write_csv(path: Path, records: List[Dict[str, str]]) -> None:
    headers = [
        "source_file",
        "frame_no",
        "timestamp_epoch",
        "tx",
        "rx",
        "bssid",
        "frame_protocols",
        "type_subtype_hex",
        "phase",
        "ap_identity",
        "ssid",
        "rsn_present",
        "akm_suites",
        "pairwise_cipher",
        "pmf_capable",
        "pmf_required",
        "auth_alg",
        "assoc_status_code",
        "has_eapol",
        "eapol_msg_num",
        "eapol_replay_counter",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(records)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Track 3 parser for SSID/BSSID evidence")
    parser.add_argument("--pcap", action="append", required=True, help="PCAP/PCAPNG input path (repeatable)")
    parser.add_argument("--output-dir", default="outputs", help="Output directory path")
    parser.add_argument("--target-ssid", required=True, help="Target SSID used in experiment")
    parser.add_argument("--ap1-bssid", required=True, help="Baseline AP BSSID")
    parser.add_argument("--ap2-bssid", required=True, help="Modified-condition AP BSSID")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ap1_bssid = args.ap1_bssid.lower()
    ap2_bssid = args.ap2_bssid.lower()

    all_records: List[Dict[str, str]] = []
    for pcap_str in args.pcap:
        pcap = Path(pcap_str)
        if not pcap.exists():
            raise FileNotFoundError(f"Missing pcap: {pcap}")
        all_records.extend(parse_pcap(pcap, ap1_bssid, ap2_bssid))

    out_dir = Path(args.output_dir)
    frames_csv = out_dir / "frames.csv"
    summary_json = out_dir / "claim_summary.json"

    write_csv(frames_csv, all_records)
    summary = build_summary(all_records, args.target_ssid, ap1_bssid, ap2_bssid)
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Wrote {frames_csv}")
    print(f"Wrote {summary_json}")
    print(f"Parsed records: {len(all_records)}")


if __name__ == "__main__":
    main()
