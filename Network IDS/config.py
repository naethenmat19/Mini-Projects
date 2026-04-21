# -*- coding: utf-8 -*-
"""
config.py - Network IDS Configuration
======================================
Central configuration for detection thresholds, identity, and logging.
"""

import os
import socket

# ── Detection thresholds ─────────────────────────────────────────────────────
PACKET_THRESHOLD    = 20      # packets from a single IP before WARNING
PORT_SCAN_THRESHOLD = 10      # unique ports from a single IP before ALERT

# ── Log file ─────────────────────────────────────────────────────────────────
LOG_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# ── Your system IP (auto-detected, override if needed) ───────────────────────
def _detect_ip():
    """Best-effort LAN IP detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

MY_IP = _detect_ip()

# ── Trusted IPs (ignored by the detector) ────────────────────────────────────
WHITELIST = ["8.8.8.8", "1.1.1.1"]