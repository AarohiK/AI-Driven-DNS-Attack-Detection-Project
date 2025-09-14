# AI-Driven-DNS-Attack-Detection-Project

This project demonstrates detection of DNS tunneling (dnscat2) and C2 channels from a 24-hour PCAP capture.

## Features
- Extracts DNS/TCP features from PCAP.
- Computes anomaly scores using sequence heuristics and simple ML.
- Generates SOC-style CSV and HTML reports with flagged suspicious sessions.

## Usage
1. Download the dnscat2 PCAP safely inside a VM: 
   [ActiveCountermeasures dnscat2 PCAP](https://www.dropbox.com/s/4r9mcn792dbzonf/dnscat2_dns_tunneling_24hr.pcap?dl=0)
2. Run the script:
   ```bash
   python3 detect_dnscat.py /path/to/dnscat2_dns_tunneling_24hr.pcap
## Process & Logic used:

| Feature | Description | Rationale |
|---------|------------|-----------|
| **DNS Query Length (`dns_len`)** | Number of characters in the DNS query | DNS tunnels often encode data in queries, making them unusually long. |
| **DNS Query Entropy (`dns_entropy`)** | Shannon entropy of query string | Randomized or encoded queries have high entropy compared to normal domain names. |
| **TCP Payload Presence (`tcp_payload_present`)** | Binary flag: 1 if payload exists, 0 otherwise | Malicious DNS tunnels may carry additional data in TCP/UDP payloads. |

## Anomaly Score Calculation
Each packet’s anomaly score is computed as:
score = 0.4 * dns_len + 0.4 * dns_entropy + 0.2 * tcp_payload_present

- Higher score → more likely to be part of a DNS tunnel.
- Weights emphasize DNS length and entropy while still considering payload presence.

  | Adjustment | Purpose |
|------------|---------|
| **Threshold tuning** | Lower → more sensitivity, may increase false positives. Higher → fewer false positives, may miss subtle tunnels. |
| **Weight adjustment** | Adjust relative importance of features (e.g., increase entropy weight if encoding dominates). |
| **Additional features** | Inter-packet timing, query type patterns, repeated domain frequency can improve detection. |
