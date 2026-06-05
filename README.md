# WPA2 SSID Investigation - Assignment 2 Track 3

This project contains a simple, evidence-based parser workflow for:
- Same SSID advertised by multiple BSSIDs
- Client-selected BSSID behavior
- Pre-association management-frame visibility

## Project Folder Structure
- `parser/ssid_track3_parser.py` - parser script
- `captures/` - put your PCAP/PCAPNG files here
- `outputs/` - parser output files are written here
- `docs/` - capture checklist and filter guidance
- `report/` - report and evidence templates

## Where to Put PCAP Files
Place your capture files inside `captures/`, for example:
- `captures/track3_filtered_baseline_authorized_only.pcapng`
- `captures/track3_filtered_modified_authorized_only.pcapng`

Note: capture files are added later, after you run the authorized hardware lab.

## Install Requirements
```bash
python -m pip install -r requirements.txt
```

## Run Parser
```bash
python parser/ssid_track3_parser.py \
  --pcap captures/track3_filtered_baseline_authorized_only.pcapng \
  --pcap captures/track3_filtered_modified_authorized_only.pcapng \
  --output-dir outputs \
  --target-ssid "MyLabSSID" \
  --ap1-bssid aa:bb:cc:dd:ee:01 \
  --ap2-bssid aa:bb:cc:dd:ee:02
```

You can pass one or more `--pcap` arguments.

## Outputs Created
- `outputs/frames.csv`
- `outputs/claim_summary.json`

## What Each Output Means
- `frames.csv`  
  Per-frame extracted data used in the assignment evidence table:
  frame number, timestamp, transmitter, receiver, BSSID, subtype, SSID, RSN fields, PMF fields (if present), auth/assoc details, and EAPOL fields (if present).

- `claim_summary.json`  
  Short summary for Track 3 claim support:
  counts by phase, whether target SSID appears pre-association, whether the same SSID appears with multiple BSSIDs, selected BSSID evidence from auth/assoc frames, and whether EAPOL was observed.

## Notes for Oral Defense
- The script is intentionally simple: one pass over packets, one CSV output, one JSON summary.
- Conclusions should stay evidence-based and limited to your own captures.
