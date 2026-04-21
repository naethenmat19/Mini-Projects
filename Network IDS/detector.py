# -*- coding: utf-8 -*-
"""
detector.py - Core IDS detection engine
========================================
Analyses individual packets and fires alerts when traffic from a single
source IP exceeds configured thresholds.
"""

from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from logger import log_alert
from config import PACKET_THRESHOLD, PORT_SCAN_THRESHOLD, MY_IP, WHITELIST

# ── Per-IP tracking state ────────────────────────────────────────────────────
ip_packet_count     = defaultdict(int)
ip_port_access      = defaultdict(set)
alerted_ips         = set()
alerted_portscan_ips = set()
last_top_ip         = None


def reset_state():
    """Clear all tracking state. Used between simulation scenarios."""
    global last_top_ip
    ip_packet_count.clear()
    ip_port_access.clear()
    alerted_ips.clear()
    alerted_portscan_ips.clear()
    last_top_ip = None


def get_protocol(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def analyze_packet(packet):
    """
    Analyse a single packet for anomalous behaviour.

    Checks performed:
      - High traffic: total packets from src_ip > PACKET_THRESHOLD
      - Port scan:    unique dst ports from src_ip > PORT_SCAN_THRESHOLD
      - Top attacker: informational log every 20 packets from the top source
    """
    global last_top_ip

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # Skip own traffic and whitelisted IPs
    if src_ip == MY_IP or src_ip in WHITELIST:
        return

    protocol = get_protocol(packet)

    # Count packets per source IP
    ip_packet_count[src_ip] += 1

    # Track unique destination ports
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        ip_port_access[src_ip].add(packet.dport)

    # High-traffic alert (fires once per IP)
    if ip_packet_count[src_ip] > PACKET_THRESHOLD and src_ip not in alerted_ips:
        log_alert(
            f"[WARNING] High traffic from {src_ip} | "
            f"Packets: {ip_packet_count[src_ip]} | Protocol: {protocol}"
        )
        alerted_ips.add(src_ip)

    # Port-scan alert (fires once per IP)
    if len(ip_port_access[src_ip]) > PORT_SCAN_THRESHOLD and src_ip not in alerted_portscan_ips:
        log_alert(
            f"[ALERT] Port scan from {src_ip} | "
            f"Ports: {len(ip_port_access[src_ip])} | Protocol: {protocol}"
        )
        alerted_portscan_ips.add(src_ip)

    # Top-attacker informational log
    if ip_packet_count:
        top_ip = max(ip_packet_count, key=ip_packet_count.get)
        if top_ip != last_top_ip and ip_packet_count[top_ip] % 20 == 0:
            log_alert(
                f"[INFO] Top Attacker: {top_ip} "
                f"({ip_packet_count[top_ip]} packets)"
            )