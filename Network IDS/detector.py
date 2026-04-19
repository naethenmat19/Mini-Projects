from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from logger import log_alert
from config import PACKET_THRESHOLD, PORT_SCAN_THRESHOLD, MY_IP, WHITELIST

ip_packet_count = defaultdict(int)
ip_port_access = defaultdict(set)

alerted_ips = set()
alerted_portscan_ips = set()

last_top_ip = None


def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def analyze_packet(packet):
    global last_top_ip

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip == MY_IP or src_ip in WHITELIST:
        return

    protocol = get_protocol(packet)

    ip_packet_count[src_ip] += 1

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        ip_port_access[src_ip].add(packet.dport)

    if ip_packet_count[src_ip] > PACKET_THRESHOLD and src_ip not in alerted_ips:
        log_alert(f"[WARNING] High traffic from {src_ip} | Packets: {ip_packet_count[src_ip]} | Protocol: {protocol}")
        alerted_ips.add(src_ip)

    if len(ip_port_access[src_ip]) > PORT_SCAN_THRESHOLD and src_ip not in alerted_portscan_ips:
        log_alert(f"[ALERT] Port scan from {src_ip} | Ports: {len(ip_port_access[src_ip])} | Protocol: {protocol}")
        alerted_portscan_ips.add(src_ip)

    if ip_packet_count:
        top_ip = max(ip_packet_count, key=ip_packet_count.get)

        if top_ip != last_top_ip and ip_packet_count[top_ip] % 20 == 0:
            log_alert(f"[INFO] Top Attacker: {top_ip} ({ip_packet_count[top_ip]} packets)")