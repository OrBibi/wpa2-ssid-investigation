# Assignment 2 — Track 3: SSID/BSSID Identity and Evil Twin Trust Assumptions

Wireless and Mobile Network Security (2-7038910-1)  
Ariel University, Department of Computer Science

## Group Members

| Name | ID |
|------|-----|
| Aliza Lazar | 336392899 |
| Or Bibi | 207707613 |
| Meir Shuker | 318901527 |

**Track:** 3 — SSID/BSSID Identity and Evil Twin Trust Assumptions  
**Submission date:** June 15, 2026

The final **PDF report** (`report.pdf`) is submitted separately by email.  
This repository is the **reproducibility package** (code, captures, parser output, figures, LaTeX source).

Repository: [https://github.com/OrBibi/wpa2-ssid-investigation](https://github.com/OrBibi/wpa2-ssid-investigation)

GitHub ZIP download: `https://github.com/OrBibi/wpa2-ssid-investigation/archive/refs/heads/main.zip`

---

## Investigative Claim

We demonstrate that:

1. The SSID is visible in multiple unprotected management frame types before association.
2. The BSSID is not cryptographically bound to the SSID in WPA2-PSK.
3. A client will initiate association with a rogue AP presenting a known SSID without detecting the BSSID identity mismatch at the protocol level.

All conclusions are evidence-based observations from our controlled lab captures.

---

## Hardware

| Device | Role | Details |
|--------|------|---------|
| Home router | AP1 (legitimate) | SSID `Michal_2.4`, BSSID `d6:35:1d:9f:89:fc`, channel 12, WPA2-PSK |
| Tenda USB (Ralink `148f:3070`) | AP2 (rogue-condition) | Interface `wlxc83a35c2e0b7`, BSSID `c8:3a:35:c2:e0:b7`, hostapd + dnsmasq |
| EDUP USB (MediaTek `0e8d:7961`) | Monitor | Interface `wlxe84e06aed7c8`, MAC `e8:4e:06:ae:d7:c8` |
| Smartphone | Client | MAC `32:0a:af:e3:81:b2`, saved WPA2 profile for `Michal_2.4` |
| Host | Lab VM | Ubuntu 24.04 (DragonOS Noble) in VirtualBox |

---

## Software Versions

| Component | Version |
|-----------|---------|
| OS | Ubuntu 24.04 / DragonOS Noble |
| Wireshark / TShark | 4.2.2 |
| Python | 3.12.3 |
| PyShark | 0.6 |
| tcpdump | system package |
| hostapd | system package |
| dnsmasq | system package |
| iw | system package |

---

## Repository Structure

```
.
├── README.md                    # This file
├── report.tex                   # LaTeX source (compile to report.pdf)
├── figures/                     # Wireshark screenshots used in the report
├── captures/                    # PCAP/PCAPNG files (raw + filtered)
├── outputs/                     # Parser output (frames.csv, claim_summary.json)
├── parser/ssid_track3_parser.py # Evidence parser
├── lab_cli.py                   # Guided lab wizard (10 steps)
├── lab/                         # Capture, AP2, device helpers
├── docs/capture_checklist.md    # Capture workflow reference
├── report/                      # Report templates
├── dnsmasq_ap2.conf             # AP2 DHCP configuration (reference)
├── run_lab.sh                   # Run wizard with venv
└── cleanup_lab.sh               # Clean runtime artifacts
```

---

## Capture Files

| File | Description |
|------|-------------|
| `captures/track3_same_ssid_baseline_ap1_only.pcapng` | Raw baseline — AP1 only, AP2 off |
| `captures/track3_same_ssid_modified_ap1_ap2.pcapng` | Raw modified — AP1 + AP2 active |
| `captures/track3_filtered_baseline_authorized_only.pcapng` | Filtered baseline (authorized MACs only) |
| `captures/track3_filtered_modified_authorized_only.pcapng` | Filtered modified (authorized MACs only) |

**Authorized MAC addresses:**

- Client: `32:0a:af:e3:81:b2`
- AP1: `d6:35:1d:9f:89:fc`
- AP2: `c8:3a:35:c2:e0:b7`
- Monitor: `e8:4e:06:ae:d7:c8`

---

## Install Dependencies

```bash
cd repo
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo apt install tcpdump tshark hostapd dnsmasq iw
```

Or use the helper script:

```bash
chmod +x run_lab.sh cleanup_lab.sh
./run_lab.sh
```

---

## Run the Full Lab (Reproduce Captures)

```bash
sudo .venv/bin/python lab_cli.py
```

Wizard steps:

| Step | Action |
|------|--------|
| 1–6 | Device discovery, network selection, monitor setup |
| 7 | **Baseline** — AP2 off, phone reconnects, 25s capture |
| 8 | **Modified** — AP2 on, phone reconnects, 25s capture |
| 9 | Filter PCAPs with tshark |
| 10 | Run parser, write outputs |

Hardware roles:

| USB adapter | Role |
|-------------|------|
| EDUP | Monitor (passive capture) |
| Tenda | AP2 (rogue AP via hostapd) |
| Real router | AP1 (legitimate network) |

---

## Run Parser Only (Reproduce Analysis)

```bash
.venv/bin/python parser/ssid_track3_parser.py \
  --pcap captures/track3_filtered_baseline_authorized_only.pcapng \
  --pcap captures/track3_filtered_modified_authorized_only.pcapng \
  --output-dir outputs \
  --target-ssid "Michal_2.4" \
  --ap1-bssid d6:35:1d:9f:89:fc \
  --ap2-bssid c8:3a:35:c2:e0:b7
```

**Outputs:**

- `outputs/frames.csv` — per-frame extracted fields (frame number, timestamp, tx/rx, BSSID, subtype, SSID, RSN, EAPOL, etc.)
- `outputs/claim_summary.json` — summary flags for Track 3 claims

---

## Compile Report PDF

From the repository root (requires `pdflatex`):

```bash
pdflatex report.tex
pdflatex report.tex
```

Produces `report.pdf` (submit separately by email).

---

## Key Evidence (Frame Numbers — Filtered Captures)

### Baseline (`track3_filtered_baseline_authorized_only.pcapng`)

| Frame | Type | Evidence |
|-------|------|----------|
| 1 | Beacon | AP1 advertises `Michal_2.4` |
| 16 | Probe Request | Client searches for `Michal_2.4` |
| 17 | EAPOL msg 2 | Key exchange with AP1 (`d6:35:1d:9f:89:fc`) |

### Modified (`track3_filtered_modified_authorized_only.pcapng`)

| Frame | Type | Evidence |
|-------|------|----------|
| 4, 89 | Beacon | Same SSID from AP1 and AP2 |
| 68 | Authentication | Client → AP2 (`c8:3a:35:c2:e0:b7`) |
| 71 | Assoc Request | Association to AP2 |
| 75–78 | EAPOL | Full 4-way handshake with AP2 |
| 193–202 | Auth/Assoc/EAPOL | Second reconnect cycle to AP2 |

Wireshark screenshots for these frames are in `figures/`.

---

## Ethics and Scope

- All experiments used **authorized lab equipment only** (listed MAC addresses).
- No credential cracking, no deauthentication of third-party networks, no analysis of unrelated devices.
- Third-party frames in raw captures were excluded via display filters.
- WPA2 passphrase is **omitted** from this repository and the report.
- AP2 is a **controlled rogue-condition AP** operated by the lab team, not an attack on external infrastructure.

---

## Known Limitations

- Results are specific to our phone, router, USB adapters, and WPA2-PSK setup.
- Baseline capture may show abbreviated Auth/Assoc (PMKSA fast reconnect); EAPOL to AP1 confirms reconnect.
- Parser JSON flags `ssid_visible_pre_assoc` and `same_ssid_advertised_by_multiple_bssids` are false negatives for Beacon SSID fields; manual TShark verification was used (documented in report).
- No deauthentication was used; AP2 selection may be influenced by beacon rate and signal strength.
- Conclusions do not claim universal behavior for all clients or WPA3/PMF configurations.

---

## Submission Checklist

Email submission (subject: **CWN 2026**):

1. **`report.pdf`** — final report (compiled from `report.tex`)
2. **GitHub repository link** — this repo (examiner downloads ZIP from GitHub)

This repository contains everything else required by the assignment:

- [x] PCAP/PCAPNG files (baseline + modified, raw + filtered)
- [x] Parser script (`parser/ssid_track3_parser.py`)
- [x] Parser outputs (`outputs/frames.csv`, `outputs/claim_summary.json`)
- [x] Wireshark screenshots (`figures/`)
- [x] LaTeX source (`report.tex`)
- [x] README with setup, hardware, versions, ethics
- [x] Lab configuration reference (`dnsmasq_ap2.conf`, `lab_config.example.json`)

---

## References

- IEEE Std 802.11-2020
- Wireshark WLAN filters: https://www.wireshark.org/docs/dfref/w/wlan.html
- Gollier & Vanhoef, *SSID Confusion*, WiSec 2024: https://papers.mathyvanhoef.com/wisec2024.pdf
