from scapy.all import sniff, IP, TCP, UDP

def process_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)

        sport = dport = None
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        print(f"[PACKET] {src} -> {dst} | proto={proto} | sport={sport} | dport={dport} | len={length}")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)
