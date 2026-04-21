# -*- coding: utf-8 -*-
"""
test.py - Network IDS Simulation Test Suite
=============================================
Runs a series of realistic attack-scenario simulations by crafting synthetic
Scapy packets and feeding them directly to detector.analyze_packet().

No live network interface or admin/root privileges are required.

Scenarios covered
-----------------
1. Normal Background Traffic      -- mixed benign traffic from whitelisted & unknown IPs
2. High-Traffic Flood (DDoS)      -- single IP hammering the threshold
3. Vertical Port Scan             -- one IP probing many ports (nmap-style)
4. Horizontal Sweep               -- many IPs each touching the same port
5. ICMP Ping Sweep                -- ICMP flood from one source
6. Mixed Multi-Attacker           -- several IPs triggering different alert types
7. Brute-Force SSH (repeated TCP) -- single IP repeatedly hitting port 22

Usage
-----
    python test.py
"""

import sys
import io
import time
import datetime
from collections import defaultdict

# Force UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── Scapy imports ─────────────────────────────────────────────────────────────
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
import colorama
colorama.init()

# -- Project imports -----------------------------------------------------------
# Reset detector state between scenarios by re-importing carefully
import detector
import config
from logger import set_gui_logger, log_alert


# ==============================================================================
#  ANSI colours for a readable console output
# ==============================================================================
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    GREY   = "\033[90m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"


# ==============================================================================
#  Test-session state
# ==============================================================================
session_alerts:   list[str] = []   # every message captured during the run
scenario_results: list[dict] = []  # pass/fail per scenario


def capture_log(message: str) -> None:
    """Intercept logger output so we can assert on it."""
    session_alerts.append(message)

    # Still echo to console with colour
    if "[ALERT]" in message:
        print(f"  {C.RED}{C.BOLD}{message}{C.RESET}")
    elif "[WARNING]" in message:
        print(f"  {C.YELLOW}{message}{C.RESET}")
    elif "[INFO]" in message:
        print(f"  {C.CYAN}{message}{C.RESET}")
    else:
        print(f"  {C.GREY}{message}{C.RESET}")


def reset_detector() -> None:
    """Clear all detector state so scenarios are independent."""
    detector.reset_state()
    session_alerts.clear()


# ==============================================================================
#  Packet factories
# ==============================================================================

def make_tcp(src: str, dst: str, dport: int) -> Packet:
    return IP(src=src, dst=dst) / TCP(dport=dport, sport=50000)


def make_udp(src: str, dst: str, dport: int) -> Packet:
    return IP(src=src, dst=dst) / UDP(dport=dport, sport=50000)


def make_icmp(src: str, dst: str) -> Packet:
    return IP(src=src, dst=dst) / ICMP()


# ==============================================================================
#  Scenario helpers
# ==============================================================================

def run_scenario(name: str, description: str, fn) -> None:
    """Wrap a scenario function, capture results, and print a header."""
    reset_detector()
    before = len(session_alerts)

    SEP1 = "=" * 70
    SEP2 = "-" * 70
    print()
    print(f"{C.BOLD}{C.WHITE}{SEP1}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}  SCENARIO: {name}{C.RESET}")
    print(f"{C.GREY}  {description}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{SEP2}{C.RESET}")

    t0 = time.perf_counter()
    passed, details = fn()
    elapsed = time.perf_counter() - t0

    alerts_fired = len(session_alerts) - before

    status_sym = f"{C.GREEN}PASS{C.RESET}" if passed else f"{C.RED}FAIL{C.RESET}"
    print(f"\n  Result : {status_sym}")
    print(f"  Alerts : {alerts_fired}")
    print(f"  Time   : {elapsed*1000:.1f} ms")
    if details:
        print(f"  Detail : {C.GREY}{details}{C.RESET}")

    scenario_results.append({
        "name":    name,
        "passed":  passed,
        "alerts":  alerts_fired,
        "elapsed": elapsed,
        "details": details,
    })


# ==============================================================================
#  Individual scenario definitions
# ==============================================================================

def scenario_normal_traffic() -> tuple[bool, str]:
    """
    Benign traffic: whitelisted IPs + local machine.
    Expectation: ZERO alerts generated.
    """
    # Whitelisted IPs from config
    for _ in range(50):
        detector.analyze_packet(make_tcp("8.8.8.8",  config.MY_IP, 443))
        detector.analyze_packet(make_tcp("1.1.1.1",  config.MY_IP, 53))
        detector.analyze_packet(make_tcp(config.MY_IP, "8.8.8.8",  443))

    fired = [m for m in session_alerts if "[ALERT]" in m or "[WARNING]" in m]
    passed = len(fired) == 0
    return passed, f"Expected 0 alerts, got {len(fired)}"


def scenario_ddos_flood() -> tuple[bool, str]:
    """
    Single external IP sends far more packets than PACKET_THRESHOLD.
    Expectation: at least one [WARNING] High-traffic alert.
    """
    attacker = "203.0.113.99"   # TEST-NET-3 (RFC 5737) -- documentation range
    count    = config.PACKET_THRESHOLD * 3   # well over threshold

    for i in range(count):
        detector.analyze_packet(make_tcp(attacker, config.MY_IP, 80))

    warnings = [m for m in session_alerts if "[WARNING]" in m and attacker in m]
    passed   = len(warnings) >= 1
    return passed, f"Sent {count} packets; expected >=1 WARNING, got {len(warnings)}"


def scenario_port_scan_vertical() -> tuple[bool, str]:
    """
    One IP probes PORT_SCAN_THRESHOLD+5 unique ports (classic nmap-style).
    Expectation: [ALERT] Port scan detected.
    """
    scanner = "198.51.100.42"   # TEST-NET-2 (RFC 5737)
    ports   = list(range(20, 20 + config.PORT_SCAN_THRESHOLD + 5))

    for port in ports:
        detector.analyze_packet(make_tcp(scanner, config.MY_IP, port))

    alerts = [m for m in session_alerts if "[ALERT]" in m and scanner in m]
    passed = len(alerts) >= 1
    return passed, (
        f"Scanned {len(ports)} ports; expected >=1 ALERT, got {len(alerts)}"
    )


def scenario_horizontal_sweep() -> tuple[bool, str]:
    """
    Many different IPs each hit port 22 (SSH) once.
    Individual IPs stay under thresholds -- this tests that the IDS does NOT
    fire false positives for distributed low-volume activity.
    Expectation: ZERO alerts (each IP is well under threshold).
    """
    port      = 22
    ip_count  = 30   # 30 different IPs, 1 packet each

    for i in range(ip_count):
        src = f"10.20.{i // 256}.{i % 256}"
        detector.analyze_packet(make_tcp(src, config.MY_IP, port))

    fired = [m for m in session_alerts if "[ALERT]" in m or "[WARNING]" in m]
    passed = len(fired) == 0
    return passed, f"30 unique IPs x 1 packet each; expected 0 alerts, got {len(fired)}"


def scenario_icmp_flood() -> tuple[bool, str]:
    """
    Single IP sends many ICMP echo requests (ping flood / smurf-style).
    Expectation: [WARNING] High traffic alert for that IP.
    """
    attacker = "192.0.2.200"   # TEST-NET-1 (RFC 5737)
    count    = config.PACKET_THRESHOLD * 2

    for _ in range(count):
        detector.analyze_packet(make_icmp(attacker, config.MY_IP))

    warnings = [m for m in session_alerts if "[WARNING]" in m and attacker in m]
    passed   = len(warnings) >= 1
    return passed, f"Sent {count} ICMP packets; expected >=1 WARNING, got {len(warnings)}"


def scenario_multi_attacker() -> tuple[bool, str]:
    """
    Three simultaneous attackers:
      - A: DDoS flood  -> should trigger [WARNING]
      - B: Port scan   -> should trigger [ALERT]
      - C: Mixed       -> both
    Expectation: at least 3 distinct alert messages.
    """
    ip_a = "203.0.113.10"
    ip_b = "203.0.113.20"
    ip_c = "203.0.113.30"

    # A -- flood
    for _ in range(config.PACKET_THRESHOLD * 2):
        detector.analyze_packet(make_tcp(ip_a, config.MY_IP, 80))

    # B -- port scan
    for p in range(1, config.PORT_SCAN_THRESHOLD + 6):
        detector.analyze_packet(make_tcp(ip_b, config.MY_IP, p))

    # C -- both (flood + many ports)
    for _ in range(config.PACKET_THRESHOLD * 2):
        detector.analyze_packet(make_tcp(ip_c, config.MY_IP, 80))
    for p in range(100, 100 + config.PORT_SCAN_THRESHOLD + 6):
        detector.analyze_packet(make_tcp(ip_c, config.MY_IP, p))

    total = len([m for m in session_alerts if "[ALERT]" in m or "[WARNING]" in m])
    passed = total >= 3
    return passed, f"3 simultaneous attackers; expected >=3 alerts, got {total}"


def scenario_ssh_brute_force() -> tuple[bool, str]:
    """
    One IP repeatedly hits port 22 (SSH brute-force simulation).
    This should cross the PACKET_THRESHOLD and trigger a [WARNING].
    Port scan alert should NOT fire (only one port probed).
    """
    attacker = "185.220.101.55"   # Tor-exit-like address (documentation example)
    port     = 22
    count    = config.PACKET_THRESHOLD * 4

    for _ in range(count):
        detector.analyze_packet(make_tcp(attacker, config.MY_IP, port))

    warnings     = [m for m in session_alerts if "[WARNING]" in m and attacker in m]
    port_alerts  = [m for m in session_alerts if "Port scan" in m and attacker in m]

    high_traffic_ok  = len(warnings) >= 1
    no_false_scan    = len(port_alerts) == 0   # only 1 port, should NOT alert scan
    passed           = high_traffic_ok and no_false_scan
    return passed, (
        f"SSH brute-force: {count} packets on port 22; "
        f"warnings={len(warnings)}, false-scan-alerts={len(port_alerts)}"
    )


# ==============================================================================
#  Summary printer
# ==============================================================================

def print_summary() -> None:
    passed = sum(1 for r in scenario_results if r["passed"])
    total  = len(scenario_results)

    SEP1 = "=" * 70
    SEP2 = "-" * 70
    print()
    print(f"{C.BOLD}{C.WHITE}{SEP1}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  TEST SUMMARY - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{SEP2}{C.RESET}")

    for r in scenario_results:
        sym    = f"{C.GREEN}PASS{C.RESET}" if r["passed"] else f"{C.RED}FAIL{C.RESET}"
        timing = f"{r['elapsed']*1000:6.1f} ms"
        alerts = f"{r['alerts']:3d} alerts"
        print(f"  {sym}  {r['name']:<40} {alerts}   {timing}")

    print(f"{C.BOLD}{C.WHITE}{SEP2}{C.RESET}")

    colour = C.GREEN if passed == total else C.RED
    print(f"  {colour}{C.BOLD}{passed}/{total} scenarios passed{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{SEP1}{C.RESET}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    # Redirect logger output to our capture function
    set_gui_logger(capture_log)

    print(f"\n  Network IDS - Simulation Test Suite")
    print(f"  Config: PACKET_THRESHOLD={config.PACKET_THRESHOLD}  "
          f"PORT_SCAN_THRESHOLD={config.PORT_SCAN_THRESHOLD}")
    print(f"  MY_IP={config.MY_IP}  WHITELIST={config.WHITELIST}")

    run_scenario(
        "Normal Background Traffic",
        "Whitelisted IPs & local machine -- should produce ZERO alerts.",
        scenario_normal_traffic,
    )

    run_scenario(
        "DDoS Flood (High Traffic)",
        f"Single attacker exceeds PACKET_THRESHOLD ({config.PACKET_THRESHOLD}) "
        "by 3x -- expect [WARNING].",
        scenario_ddos_flood,
    )

    run_scenario(
        "Vertical Port Scan (nmap-style)",
        f"One IP probes {config.PORT_SCAN_THRESHOLD + 5} unique ports -- expect [ALERT].",
        scenario_port_scan_vertical,
    )

    run_scenario(
        "Horizontal Host Sweep",
        "30 IPs x 1 packet each on SSH port -- no single IP crosses threshold.",
        scenario_horizontal_sweep,
    )

    run_scenario(
        "ICMP Ping Flood",
        f"ICMP flood (2x PACKET_THRESHOLD={config.PACKET_THRESHOLD * 2} packets) "
        "-- expect [WARNING].",
        scenario_icmp_flood,
    )

    run_scenario(
        "Multi-Attacker (Simultaneous)",
        "Three attackers: DDoS, port-scan, and both combined -- expect >=3 alerts.",
        scenario_multi_attacker,
    )

    run_scenario(
        "SSH Brute-Force (single port)",
        f"4x PACKET_THRESHOLD packets all on port 22 -- "
        "expect [WARNING] but NOT a port-scan [ALERT].",
        scenario_ssh_brute_force,
    )

    print_summary()

    # Exit with non-zero code if any scenario failed (useful in CI pipelines)
    failed = sum(1 for r in scenario_results if not r["passed"])
    sys.exit(failed)


if __name__ == "__main__":
    main()
