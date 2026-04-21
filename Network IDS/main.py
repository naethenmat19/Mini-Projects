from scapy.all import sniff
from detector import analyze_packet, ip_packet_count
from scapy.layers.inet import IP, TCP, UDP
from config import PACKET_THRESHOLD, PORT_SCAN_THRESHOLD

packet_count = 0


# Format packet into clean readable form
def format_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            port = packet[UDP].dport
        else:
            proto = "OTHER"
            port = "-"

        return f"[PACKET] {proto} | {src} → {dst} | Port: {port}"

    return None


# Callback for each packet
def packet_callback(packet):
    global packet_count
    packet_count += 1

    # Show only every 10th packet (reduces noise)
    if packet_count % 10 == 0:
        formatted = format_packet(packet)
        if formatted:
            print(formatted)

    # Analyze packet for IDS logic
    analyze_packet(packet)


def start_ids():
    print("🔍 Starting Network Intrusion Detection System...\n")

    # Show configuration (NEW)
    print("Configuration:")
    print(f"Packet Threshold: {PACKET_THRESHOLD}")
    print(f"Port Scan Threshold: {PORT_SCAN_THRESHOLD}")
    print("\nPress Ctrl+C to stop.\n")

    try:
        sniff(prn=packet_callback, store=False)

    except KeyboardInterrupt:
        print("\n\n--- SUMMARY ---")
        print(f"Total unique IPs detected: {len(ip_packet_count)}")

        if ip_packet_count:
            top_ip = max(ip_packet_count, key=ip_packet_count.get)
            print(f"Top Attacker: {top_ip} ({ip_packet_count[top_ip]} packets)")

        print("Monitoring stopped.")


if __name__ == "__main__":
    start_ids()