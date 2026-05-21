from scapy.all import sniff, IP, TCP, UDP, ICMP

packet_count = {}

def log_packet(text):
    with open("logs.txt", "a") as f:
        f.write(text + "\n")

def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        # Count packets
        packet_count[src] = packet_count.get(src, 0) + 1

        # Alert detection
        if packet_count[src] > 20:
            alert_msg = f"[ALERT] Too many packets from {src}"
            print(alert_msg)
            log_packet(alert_msg)

        # Protocol detection
        if packet.haslayer(TCP):
            msg = f"[TCP] {src} -> {dst}"
        elif packet.haslayer(UDP):
            msg = f"[UDP] {src} -> {dst}"
        elif packet.haslayer(ICMP):
            msg = f"[ICMP] {src} -> {dst}"
        else:
            msg = f"[OTHER] {src} -> {dst}"

        print(msg)
        log_packet(msg)

print("Monitoring network...")
sniff(prn=process_packet, store=False)