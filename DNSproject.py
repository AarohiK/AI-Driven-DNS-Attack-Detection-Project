pcap_file = "dnscat2_dns_tunneling_24hr.pcap"


"""
AI Detection of DNS Tunneling (dnscat2) from a PCAP

Usage:
    python3 detect_dnscat.py /path/to/dnscat2_dns_tunneling_24hr.pcap
Outputs:
    - alerts.csv : CSV with flagged suspicious packets
    - report.html : SOC-style HTML report with anomaly scores
"""

import pyshark, sys, json
import pandas as pd
import math, os
from datetime import datetime



def shannon_entropy(s): # Compute the shannon entropy of a string. 
                        # Used to detect unusual/high-randomness DNS queries which is common for tunneling
    """Compute Shannon entropy of a string"""
    if not s: 
        return 0
    probs = [float(s.count(c))/len(s) for c in set(s)]
    return -sum(p*math.log2(p) for p in probs)

cap = pyshark.FileCapture(pcap_file, keep_packets=False, only_summaries=False)


def extract_features(pcap_file): # reads PCAP using pyshark and extracts features for each packet.
                                 # returns a pandas dataframe with columns:
                                 # frame, timestamp, src/dst IP, sec/dst port, DNS query, length, entropy, payload
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    data = [] ## list to hold packet dictionaries

    max_packets = 5000
    for i, pkt in enumerate(cap):
        if i >= max_packets:
            break
        try:
            # DNS query name if DNS layer exists
            dns_q = getattr(pkt.dns, 'qry_name', '') if 'DNS' in pkt else ''
            # TCP payload if TCP layer exists
            tcp_payload = getattr(pkt.tcp, 'payload', '') if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload') else ''
            # storing features in dictionary
            row = {
                'frame': pkt.number,
                'time': pkt.sniff_timestamp,
                'src_ip': getattr(pkt.ip, 'src', ''),
                'dst_ip': getattr(pkt.ip, 'dst', ''),
                'src_port': getattr(pkt[pkt.transport_layer.lower()], 'srcport', '') if hasattr(pkt, 'transport_layer') else '',
                'dst_port': getattr(pkt[pkt.transport_layer.lower()], 'dstport', '') if hasattr(pkt, 'transport_layer') else '',
                'dns_query': dns_q,
                'dns_len': len(dns_q),
                'dns_entropy': shannon_entropy(dns_q),
                'tcp_payload_len': len(tcp_payload),
                'tcp_payload_present': int(bool(tcp_payload))
            }
            data.append(row)
        except Exception as e:
            # skip malformed packets
            continue
            # convert list of dicts to pandas data frame to easily analyze
    return pd.DataFrame(data)

def compute_anomaly_score(df):
    # adds anomaly score for each packet: 
    # - combines dns length, entropy, tcp payload presence
    # - flags packets as suspicious if score > threshold (5 in this case)
    # 5 is arbitrary but reasonable but keeps balance of flagging read suspicion vs noise
    # can adjust to 4 or 6 depending on diff PCAPS.
    df['score'] = df['dns_len'] * 0.4 + df['dns_entropy'] * 0.4 + df['tcp_payload_present'] * 0.2
    df['flag'] = df['score'] > 5  # threshold, adjust for sensitivity
    return df

def save_reports(df, out_prefix='alerts'):
    # CSV report
    csv_file = f"{out_prefix}.csv"
    df.to_csv(csv_file, index=False)

    # HTML report
    html_file = f"{out_prefix}.html"
    with open(html_file,'w') as f:
        f.write("<html><body>")
        f.write(f"<h2>DNS Tunneling / C2 Anomaly Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>")
        f.write(df.to_html(index=False))
        f.write("</body></html>")

    print(f"Reports saved: {csv_file}, {html_file}")




if __name__ == "__main__":
    # Path to your PCAP file (update this to your local path)
    pcap_file = r"C:\Users\aaroh\OneDrive\Desktop\PCAPs\dnscat2_dns_tunneling_24hr.pcap"
    
    # Check if file exists
    if not os.path.exists(pcap_file):
        print("PCAP not found!")
        sys.exit(1)

    # Step 1: Extract features
    print("Extracting features...")
    df = extract_features(pcap_file)
    print(f"Extracted {len(df)} packets")

    # Step 2: Compute anomaly scores
    df = compute_anomaly_score(df)
    flagged = df[df['flag']].shape[0]
    print(f"Flagged {flagged} suspicious packets")

    # Step 3: Save CSV and HTML reports
    save_reports(df)
