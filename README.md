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
