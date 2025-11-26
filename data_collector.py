from scapy.all import sniff, IP, TCP, UDP
import csv
from datetime import datetime

OUTPUT_FILE = "network_data.csv"

# Create CSV file with headers
with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "src_ip", "dst_ip", "proto", "sport", "dport", "length", "label"])
    # label = 0 means normal traffic

def process_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)
        sport = dport = 0

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        row = [datetime.now().isoformat(), src, dst, proto, sport, dport, length, 0]

        with open(OUTPUT_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)

        print("Saved packet:", row)

print("Collecting packets... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)
