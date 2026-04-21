# Network Intrusion Detection System (IDS)

A real-time Network Intrusion Detection System built with Python that monitors network traffic, detects suspicious activities such as DDoS floods, port scans, and brute-force attempts, and displays colour-coded alerts in a modern GUI dashboard.

---

## Features

- **Real-time packet capture** using Scapy with live traffic analysis
- **DDoS / high-traffic detection** -- alerts when a single IP exceeds the packet threshold
- **Port scan detection** -- alerts when a single IP probes more ports than the configured threshold
- **Top attacker tracking** -- periodic informational logs identifying the most active source
- **Modern dark-themed GUI** (Tkinter) with colour-coded log output
  - **Live statistics dashboard** -- packets captured, alerts, warnings, and uptime
  - **Severity filter bar** -- toggle ALERT / WARNING / INFO / PACKET lines on or off
  - **Status bar** -- shows running state, start time, and live packet count
  - **Log export** -- save the current log to a `.log` or `.txt` file
- **Built-in attack simulation** -- 5 real-world scenarios run inside the GUI (no admin or live network required)
- **Thread-safe architecture** -- queue-based logging, reliable stop via `threading.Event`
- **Standalone test suite** -- 7 automated scenarios validate the detection engine without network access
- **Auto-detected local IP** -- `config.py` detects your LAN IP at startup

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| Packet capture | Scapy |
| GUI | Tkinter (built-in) |
| Packet driver | Npcap (Windows) or libpcap (Linux/macOS) |

---

## Project Structure

```
network-ids/
├── config.py        Configuration: thresholds, auto-detected IP, whitelist
├── detector.py      Core detection engine (high traffic, port scan, top attacker)
├── logger.py        Logging to console, GUI callback, and log file
├── gui.py           Tkinter GUI dashboard with live stats and simulation
├── main.py          CLI entry point (headless mode)
├── test.py          Automated test suite (7 scenarios, no network required)
├── requirements.txt Python dependencies
├── logs/
│   └── alerts.log   Timestamped alert log (created at runtime)
└── README.md
```

---

## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/your-username/network-ids.git
cd network-ids
```

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Install Npcap** (Windows only -- required for live packet capture):

   Download from [npcap.com](https://npcap.com/) and install with the **"WinPcap API-compatible mode"** option enabled.

---

## Usage

### GUI Dashboard

```bash
python gui.py
```

| Button | Action |
|--------|--------|
| **START** | Begin live packet sniffing (requires admin/root for raw sockets) |
| **STOP** | Stop the sniffer thread cleanly |
| **CLEAR** | Clear the log panel |
| **EXPORT** | Save the visible log to a file |
| **SIMULATE** | Run 5 built-in attack scenarios without any network access |

> **Tip:** You can click **SIMULATE** immediately after launching -- no admin rights or live network needed. Alerts will appear in real-time with colour-coded severity.

### CLI Mode (headless)

```bash
python main.py
```

Runs the IDS in a terminal with console output. Press `Ctrl+C` to stop and see a summary.

### Live Scan with nmap

To generate real traffic for the IDS to detect, run nmap in a separate terminal:

```bash
# Fast service scan on common ports
nmap -sV -sC -p 22,80,135,443,445,3306,3389,8080 --open -T4 <TARGET_IP>

# Full port scan (slower, generates more traffic)
nmap -p- <TARGET_IP>
```

> **Note:** When scanning `127.0.0.1`, Npcap must be configured to capture loopback traffic. The IDS captures more reliably when scanning the machine's LAN IP instead of localhost.

### Automated Test Suite

```bash
python test.py
```

Runs 7 scenarios using synthetic Scapy packets fed directly to the detector -- no network access, no admin rights:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | Normal background traffic | 0 alerts (no false positives) |
| 2 | DDoS flood (3x threshold) | WARNING: high traffic |
| 3 | Vertical port scan (nmap-style) | ALERT: port scan |
| 4 | Horizontal host sweep (30 IPs) | 0 alerts (no false positives) |
| 5 | ICMP ping flood | WARNING: high traffic |
| 6 | Multi-attacker raid (3 IPs) | Multiple ALERT + WARNING |
| 7 | SSH brute-force (single port) | WARNING only, no scan ALERT |

---

## Configuration

Edit `config.py` to tune detection thresholds:

```python
PACKET_THRESHOLD    = 20    # packets from one IP before WARNING
PORT_SCAN_THRESHOLD = 10    # unique ports from one IP before ALERT

WHITELIST = ["8.8.8.8", "1.1.1.1"]  # trusted IPs (ignored)
```

`MY_IP` is auto-detected at startup. Override it manually if needed.

---

## How It Works

```
Packet Source (live sniff or simulation)
        │
        ▼
  detector.analyze_packet()
        │
        ├── Count packets per source IP
        ├── Track unique destination ports per IP
        │
        ├── Packets > PACKET_THRESHOLD?  ──▶  [WARNING] High traffic
        ├── Ports > PORT_SCAN_THRESHOLD? ──▶  [ALERT] Port scan
        └── Top attacker every 20 pkts?  ──▶  [INFO] Top attacker
                │
                ▼
        logger.log_alert()
        ├── Console (stdout)
        ├── GUI callback (thread-safe queue)
        └── File (logs/alerts.log)
```

---

## Author

Naethen Mathew Anil

---

## Acknowledgements

This project was developed as part of a mini project for learning network security concepts.
