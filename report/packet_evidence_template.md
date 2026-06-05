# Packet Evidence (Annotated Table Template)

Use this table format in the report and fill values from `outputs/frames.csv` and Wireshark.

## Baseline Capture
Capture file: `captures/track3_same_ssid_baseline_ap1_only.pcapng`

| Frame No | Time (epoch) | Type/Subtype (hex) | Tx | Rx | BSSID | Important Fields | Evidence-Based Interpretation |
|---|---:|---|---|---|---|---|---|
|  |  | 0x0008 (Beacon) |  |  |  | SSID, RSN IE | AP1 advertises target SSID in clear-text management traffic. |
|  |  | 0x000b (Authentication) |  |  |  | auth_alg | Client starts open authentication with selected BSSID. |
|  |  | 0x0000 (Assoc Request) |  |  |  | SSID, RSN AKM/cipher | Client requests association for target SSID using WPA2 parameters. |
|  |  | 0x0001 (Assoc Response) |  |  |  | status_code | AP responds to association request. |
|  |  | eapol |  |  |  | msg_num, replay_counter | Key-establishment evidence appears after auth/assoc stage. |

## Modified Capture
Capture file: `captures/track3_same_ssid_modified_ap1_ap2.pcapng`

| Frame No | Time (epoch) | Type/Subtype (hex) | Tx | Rx | BSSID | Important Fields | Evidence-Based Interpretation |
|---|---:|---|---|---|---|---|---|
|  |  | 0x0008 (Beacon) |  |  | AP1 | SSID | AP1 advertises target SSID. |
|  |  | 0x0008 (Beacon) |  |  | AP2 | SSID | AP2 also advertises same target SSID. |
|  |  | 0x000b (Authentication) |  |  |  | auth_alg | Authentication frame indicates client-selected BSSID. |
|  |  | 0x0000 (Assoc Request) |  |  |  | SSID, RSN AKM/cipher | Association request confirms selected BSSID under same SSID context. |
|  |  | eapol |  |  |  | msg_num, replay_counter | Handshake-related evidence starts after association. |

## Recommended Extraction Query (TShark)
```bash
tshark -r captures/<capture_name>.pcapng \
  -Y "(wlan.fc.type==0 || eapol) && (wlan.addr==<client_mac> || wlan.addr==<ap1_bssid> || wlan.addr==<ap2_bssid>)" \
  -T fields -E header=y -E separator=, \
  -e frame.number -e frame.time_epoch -e wlan.ta -e wlan.ra -e wlan.bssid \
  -e wlan.fc.type_subtype -e wlan.ssid -e wlan.rsn.akms.type -e wlan.rsn.pcs.type \
  -e wlan.fixed.auth.alg -e wlan.fixed.status_code \
  -e wlan_rsna_eapol.keydes.msgnr -e wlan_rsna_eapol.keydes.replay_counter
```
