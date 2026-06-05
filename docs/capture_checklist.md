# Track 3 Capture Checklist (Same SSID, Different BSSID)

## Goal
Capture two controlled conditions that differ by one variable only:
- Same SSID
- Different available BSSID set

## Required File Names
- Raw baseline: `captures/track3_same_ssid_baseline_ap1_only.pcapng`
- Raw modified: `captures/track3_same_ssid_modified_ap1_ap2.pcapng`
- Filtered baseline: `captures/track3_filtered_baseline_authorized_only.pcapng`
- Filtered modified: `captures/track3_filtered_modified_authorized_only.pcapng`
- Optional merged filtered: `captures/track3_filtered_comparison_authorized_only.pcapng`

## Authorized Device Inventory (fill before capture)
- `CLIENT_MAC=<client_mac>`
- `AP1_BSSID=<ap1_bssid>`
- `AP2_BSSID=<ap2_bssid>`
- `MONITOR_IF=<monitor_interface>`
- `TARGET_SSID=<target_ssid>`

## Monitor-Mode Setup (Linux)
```bash
sudo ip link set <interface> down
sudo iw dev <interface> set type monitor
sudo ip link set <interface> up
sudo iw dev <interface> set channel <channel>
sudo tcpdump -i <interface> -c 10 type mgt
```

## Baseline Condition (AP1 only)
1. Keep AP1 enabled, AP2 disabled/out of range.
2. Start capture:
```bash
sudo tcpdump -i <monitor_interface> -w captures/track3_same_ssid_baseline_ap1_only.pcapng
```
3. Trigger client connect/reconnect to target SSID.
4. Stop capture after discovery + authentication + association + (if present) EAPOL.

## Modified Condition (AP1 and AP2)
1. Enable AP1 and AP2 with same SSID and same WPA2-PSK.
2. Start capture:
```bash
sudo tcpdump -i <monitor_interface> -w captures/track3_same_ssid_modified_ap1_ap2.pcapng
```
3. Trigger the same client reconnect action used in baseline.
4. Stop capture after full sequence.

## Required Wireshark Filters (hex subtype)
- Beacon: `wlan.fc.type_subtype == 0x0008`
- Probe Request: `wlan.fc.type_subtype == 0x0004`
- Probe Response: `wlan.fc.type_subtype == 0x0005`
- Authentication: `wlan.fc.type_subtype == 0x000b`
- Association Request: `wlan.fc.type_subtype == 0x0000`
- Association Response: `wlan.fc.type_subtype == 0x0001`
- EAPOL: `eapol`

## Analysis Filters (authorized lab devices only)
- Full timeline:
```text
(wlan.fc.type == 0 || eapol) && (wlan.addr == <client_mac> || wlan.addr == <ap1_bssid> || wlan.addr == <ap2_bssid>)
```
- SSID-focused:
```text
wlan.ssid == "<target_ssid>" && wlan.fc.type == 0
```
- BSSID comparison:
```text
wlan.bssid == <ap1_bssid> || wlan.bssid == <ap2_bssid>
```

## Build Filtered Evidence PCAPs
```bash
tshark -r captures/track3_same_ssid_baseline_ap1_only.pcapng \
  -Y "(wlan.fc.type==0 || eapol) && (wlan.addr==<client_mac> || wlan.addr==<ap1_bssid>)" \
  -w captures/track3_filtered_baseline_authorized_only.pcapng

tshark -r captures/track3_same_ssid_modified_ap1_ap2.pcapng \
  -Y "(wlan.fc.type==0 || eapol) && (wlan.addr==<client_mac> || wlan.addr==<ap1_bssid> || wlan.addr==<ap2_bssid>)" \
  -w captures/track3_filtered_modified_authorized_only.pcapng
```

## Evidence Quality Checks
- Both captures include at least:
  - Beacon or probe evidence for target SSID
  - Authentication and association exchange
  - EAPOL messages if handshake is present
- Modified capture shows same SSID advertised by both AP BSSIDs.
- Report uses only authorized devices and states exclusion of unrelated traffic.
