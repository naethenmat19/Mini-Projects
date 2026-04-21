import queue
import threading
import datetime
import time
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from detector import analyze_packet, reset_state
from logger import set_gui_logger
from config import PACKET_THRESHOLD, PORT_SCAN_THRESHOLD, MY_IP

# -- Colour palette -----------------------------------------------------------
BG_DEEP    = "#0d1117"
BG_PANEL   = "#161b22"
BG_CARD    = "#1c2128"
FG_PRIMARY = "#c9d1d9"
FG_MUTED   = "#8b949e"
CLR_ALERT  = "#ff4d4f"
CLR_WARN   = "#f1e05a"
CLR_INFO   = "#58a6ff"
CLR_PKT    = "#3fb950"
CLR_GREEN  = "#238636"
CLR_RED    = "#da3633"
CLR_AMBER  = "#9e6a03"
CLR_BLUE   = "#1f6feb"
CLR_PURPLE = "#8957e5"
CLR_DISABLED = "#30363d"
FONT       = "Segoe UI"


class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network IDS Dashboard")
        self.root.geometry("1020x700")
        self.root.minsize(820, 580)
        self.root.configure(bg=BG_DEEP)

        self._running    = False
        self._stop_event = threading.Event()
        self._log_queue  = queue.Queue()
        self._start_time = None
        self._uptime_job = None
        self._sim_thread = None

        self.packet_count  = 0
        self.alert_count   = 0
        self.warning_count = 0

        self._filter_vars = {
            "alert":   tk.BooleanVar(value=True),
            "warning": tk.BooleanVar(value=True),
            "info":    tk.BooleanVar(value=True),
            "packet":  tk.BooleanVar(value=True),
        }

        self._build_ui()
        set_gui_logger(self.log)
        self._poll_log_queue()

    # ── UI CONSTRUCTION ──────────────────────────────────────────────────

    def _build_ui(self):
        # Title
        hdr = tk.Frame(self.root, bg=BG_DEEP)
        hdr.pack(fill="x", padx=20, pady=(12, 4))
        tk.Label(hdr, text="[+] Network Intrusion Detection System",
                 bg=BG_DEEP, fg=FG_PRIMARY, font=(FONT, 15, "bold"),
                 anchor="w").pack(side="left")
        tk.Label(hdr, text="Real-time threat detection",
                 bg=BG_DEEP, fg=FG_MUTED, font=(FONT, 9),
                 anchor="e").pack(side="right")

        # Stats bar
        stats = tk.Frame(self.root, bg=BG_PANEL, pady=8)
        stats.pack(fill="x", padx=15, pady=(0, 4))
        cards = [
            ("Packets", "pkt_var",  CLR_INFO),
            ("Alerts",  "alt_var",  CLR_ALERT),
            ("Warnings","wrn_var",  CLR_WARN),
            ("Uptime",  "upt_var",  CLR_PKT),
        ]
        for label, attr, clr in cards:
            c = tk.Frame(stats, bg=BG_CARD, padx=16, pady=6)
            c.pack(side="left", expand=True, fill="both", padx=6)
            var = tk.StringVar(value="0" if "upt" not in attr else "00:00:00")
            setattr(self, attr, var)
            tk.Label(c, text=label, bg=BG_CARD, fg=FG_MUTED,
                     font=(FONT, 9)).pack()
            tk.Label(c, textvariable=var, bg=BG_CARD, fg=clr,
                     font=(FONT, 13, "bold")).pack()

        # Buttons
        brow = tk.Frame(self.root, bg=BG_DEEP)
        brow.pack(padx=15, pady=4, fill="x")

        self.btn_start = self._btn(brow, "START",    CLR_GREEN,  self.start_ids)
        self.btn_stop  = self._btn(brow, "STOP",     CLR_RED,    self.stop_ids, state="disabled")
        self._btn(brow, "CLEAR",    CLR_AMBER,  self.clear_logs)
        self._btn(brow, "EXPORT",   CLR_BLUE,   self.export_log)
        self.btn_sim = self._btn(brow, "SIMULATE", CLR_PURPLE, self.run_simulation)

        # Filter bar
        fbar = tk.Frame(self.root, bg=BG_DEEP)
        fbar.pack(padx=15, pady=(0, 4), fill="x")
        tk.Label(fbar, text="Show:", bg=BG_DEEP, fg=FG_MUTED,
                 font=(FONT, 9)).pack(side="left", padx=(0, 6))
        for label, key, clr in [("ALERT","alert",CLR_ALERT),
                                 ("WARNING","warning",CLR_WARN),
                                 ("INFO","info",CLR_INFO),
                                 ("PACKET","packet",CLR_PKT)]:
            tk.Checkbutton(fbar, text=label, variable=self._filter_vars[key],
                           command=lambda k=key: self._apply_filter(k),
                           bg=BG_DEEP, fg=clr, activebackground=BG_DEEP,
                           activeforeground=clr, selectcolor=BG_PANEL,
                           font=(FONT, 9, "bold"), bd=0).pack(side="left", padx=4)

        # Log panel
        lf = tk.Frame(self.root, bg=BG_PANEL, bd=1, relief="solid")
        lf.pack(fill="both", expand=True, padx=15, pady=(0, 4))
        tk.Label(lf, text="Live Traffic Log", bg=BG_PANEL, fg=FG_PRIMARY,
                 font=(FONT, 10, "bold"), anchor="w").pack(anchor="w", padx=10, pady=(6,2))
        self.log_area = scrolledtext.ScrolledText(
            lf, bg=BG_DEEP, fg=FG_PRIMARY, insertbackground="white",
            font=("Consolas", 10), bd=0, highlightthickness=0)
        self.log_area.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.log_area.tag_config("alert",   foreground=CLR_ALERT)
        self.log_area.tag_config("warning", foreground=CLR_WARN)
        self.log_area.tag_config("info",    foreground=CLR_INFO)
        self.log_area.tag_config("packet",  foreground=CLR_PKT)

        # Status bar
        sb = tk.Frame(self.root, bg=BG_PANEL, pady=3)
        sb.pack(fill="x", side="bottom")
        self._dot = tk.Label(sb, text="*", bg=BG_PANEL, fg=CLR_RED, font=(FONT, 12, "bold"))
        self._dot.pack(side="left", padx=(10, 2))
        self._stxt = tk.Label(sb, text="IDLE", bg=BG_PANEL, fg=FG_MUTED, font=(FONT, 9))
        self._stxt.pack(side="left")
        self._spkt = tk.Label(sb, text="Packets: 0", bg=BG_PANEL, fg=FG_MUTED, font=(FONT, 9))
        self._spkt.pack(side="right", padx=10)

    def _btn(self, parent, text, bg, cmd, state="normal"):
        b = tk.Button(parent, text=text, command=cmd, bg=bg, fg="white",
                      activebackground=bg, activeforeground="white",
                      relief="flat", bd=0, font=(FONT, 10, "bold"),
                      padx=14, pady=5, cursor="hand2", state=state)
        b.pack(side="left", padx=(0, 6))
        if state == "disabled":
            b.config(bg=CLR_DISABLED)
        return b

    # ── THREAD-SAFE LOGGING ──────────────────────────────────────────────

    def log(self, message):
        self._log_queue.put(message)

    def _poll_log_queue(self):
        try:
            for _ in range(200):  # drain up to 200 per tick
                msg = self._log_queue.get_nowait()
                self._write(msg)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_log_queue)

    def _write(self, message):
        tag = None
        if "[ALERT]" in message:
            tag = "alert"
            self.alert_count += 1
            self.alt_var.set(str(self.alert_count))
        elif "[WARNING]" in message:
            tag = "warning"
            self.warning_count += 1
            self.wrn_var.set(str(self.warning_count))
        elif "[INFO]" in message:
            tag = "info"
        elif "[PACKET]" in message:
            tag = "packet"

        start = self.log_area.index("end-1c")
        self.log_area.insert(tk.END, message + "\n")
        end = self.log_area.index("end-1c")
        if tag:
            self.log_area.tag_add(tag, start, end)
            if not self._filter_vars.get(tag, tk.BooleanVar(value=True)).get():
                self.log_area.tag_config(tag, elide=True)
        self.log_area.yview(tk.END)

    def _apply_filter(self, key):
        self.log_area.tag_config(key, elide=not self._filter_vars[key].get())

    # ── PACKET HANDLING ──────────────────────────────────────────────────

    def _fmt(self, pkt):
        if pkt.haslayer(IP):
            s, d = pkt[IP].src, pkt[IP].dst
            if pkt.haslayer(TCP):
                return f"[PACKET] TCP | {s} -> {d} | Port: {pkt[TCP].dport}"
            elif pkt.haslayer(UDP):
                return f"[PACKET] UDP | {s} -> {d} | Port: {pkt[UDP].dport}"
            return f"[PACKET] OTHER | {s} -> {d}"
        return None

    def _pkt_cb(self, pkt):
        if not self._running:
            return
        self.packet_count += 1
        self.pkt_var.set(f"{self.packet_count:,}")
        self._spkt.config(text=f"Packets: {self.packet_count:,}")
        if self.packet_count % 10 == 0:
            f = self._fmt(pkt)
            if f:
                self.log(f)
        analyze_packet(pkt)

    def _sniff(self):
        try:
            sniff(prn=self._pkt_cb, store=False,
                  stop_filter=lambda _: self._stop_event.is_set())
        except Exception as e:
            self.log(f"[WARNING] Sniffer error: {e}")

    # ── CONTROLS ─────────────────────────────────────────────────────────

    def start_ids(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._start_time = datetime.datetime.now()
        self.packet_count = self.alert_count = self.warning_count = 0
        self.pkt_var.set("0"); self.alt_var.set("0"); self.wrn_var.set("0")
        self.upt_var.set("00:00:00")
        self.btn_start.config(state="disabled", bg=CLR_DISABLED)
        self.btn_stop.config(state="normal", bg=CLR_RED)
        self._dot.config(fg=CLR_GREEN)
        self._stxt.config(text=f"MONITORING | Started: {self._start_time:%H:%M:%S}", fg=CLR_GREEN)
        self.log(f"[INFO] IDS Started at {self._start_time:%Y-%m-%d %H:%M:%S}")
        threading.Thread(target=self._sniff, daemon=True).start()
        self._tick()

    def stop_ids(self):
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._uptime_job:
            self.root.after_cancel(self._uptime_job)
            self._uptime_job = None
        self.btn_start.config(state="normal", bg=CLR_GREEN)
        self.btn_stop.config(state="disabled", bg=CLR_DISABLED)
        self._dot.config(fg=CLR_RED)
        self._stxt.config(text="STOPPED", fg=FG_MUTED)
        self.log("[INFO] IDS Stopped.\n")

    def clear_logs(self):
        self.log_area.delete(1.0, tk.END)

    def export_log(self):
        content = self.log_area.get(1.0, tk.END)
        if not content.strip():
            messagebox.showinfo("Export", "Log is empty.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Log", defaultextension=".log",
            filetypes=[("Log files","*.log"),("Text files","*.txt"),("All","*.*")],
            initialfile=f"ids_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Export", f"Saved to:\n{path}")

    def _tick(self):
        if not self._running or not self._start_time:
            return
        s = int((datetime.datetime.now() - self._start_time).total_seconds())
        h, r = divmod(s, 3600)
        m, s = divmod(r, 60)
        self.upt_var.set(f"{h:02d}:{m:02d}:{s:02d}")
        self._uptime_job = self.root.after(1000, self._tick)

    # ── BUILT-IN ATTACK SIMULATION ───────────────────────────────────────

    def run_simulation(self):
        if self._sim_thread and self._sim_thread.is_alive():
            self.log("[WARNING] Simulation already running...")
            return
        self.btn_sim.config(state="disabled", bg=CLR_DISABLED)
        self._sim_thread = threading.Thread(target=self._simulate, daemon=True)
        self._sim_thread.start()

    def _simulate(self):
        """Run 5 real-world attack scenarios IN-PROCESS so alerts appear in the GUI."""
        self.log("")
        self.log("=" * 80)
        self.log("[INFO] === ATTACK SIMULATION STARTING ===")
        self.log("=" * 80)
        self.log("")

        scenarios = [
            ("DDoS Flood",           self._sim_ddos),
            ("Port Scan (nmap)",     self._sim_portscan),
            ("ICMP Ping Flood",      self._sim_icmp),
            ("SSH Brute-Force",      self._sim_ssh_brute),
            ("Multi-Attacker Raid",  self._sim_multi),
        ]

        for i, (name, fn) in enumerate(scenarios, 1):
            reset_state()
            self.log("")
            self.log("-" * 60)
            self.log(f"[INFO] Scenario {i}/{len(scenarios)}: {name}")
            self.log("-" * 60)
            time.sleep(0.8)
            fn()
            time.sleep(1.0)

        self.log("")
        self.log("=" * 80)
        self.log("[INFO] === SIMULATION COMPLETE ===")
        self.log("=" * 80)

        # Re-enable button on the main thread
        self.root.after(0, lambda: self.btn_sim.config(state="normal", bg=CLR_PURPLE))

    def _make_tcp(self, src, dst, dport):
        return IP(src=src, dst=dst) / TCP(dport=dport, sport=50000)

    def _make_icmp(self, src, dst):
        return IP(src=src, dst=dst) / ICMP()

    def _sim_ddos(self):
        attacker = "203.0.113.99"
        self.log(f"[INFO] Simulating DDoS flood from {attacker} (60 packets)...")
        for i in range(PACKET_THRESHOLD * 3):
            analyze_packet(self._make_tcp(attacker, MY_IP, 80))
            if i % 15 == 0:
                time.sleep(0.05)

    def _sim_portscan(self):
        scanner = "198.51.100.42"
        ports = list(range(20, 20 + PORT_SCAN_THRESHOLD + 5))
        self.log(f"[INFO] Simulating port scan from {scanner} ({len(ports)} ports)...")
        for p in ports:
            analyze_packet(self._make_tcp(scanner, MY_IP, p))
            time.sleep(0.03)

    def _sim_icmp(self):
        attacker = "192.0.2.200"
        count = PACKET_THRESHOLD * 2
        self.log(f"[INFO] Simulating ICMP flood from {attacker} ({count} pings)...")
        for i in range(count):
            analyze_packet(self._make_icmp(attacker, MY_IP))
            if i % 10 == 0:
                time.sleep(0.04)

    def _sim_ssh_brute(self):
        attacker = "185.220.101.55"
        count = PACKET_THRESHOLD * 4
        self.log(f"[INFO] Simulating SSH brute-force from {attacker} ({count} attempts on port 22)...")
        for i in range(count):
            analyze_packet(self._make_tcp(attacker, MY_IP, 22))
            if i % 20 == 0:
                time.sleep(0.04)

    def _sim_multi(self):
        ips = ["203.0.113.10", "203.0.113.20", "203.0.113.30"]
        self.log(f"[INFO] Simulating 3 simultaneous attackers: {', '.join(ips)}...")
        # Attacker A: flood
        for _ in range(PACKET_THRESHOLD * 2):
            analyze_packet(self._make_tcp(ips[0], MY_IP, 80))
        time.sleep(0.2)
        # Attacker B: port scan
        for p in range(1, PORT_SCAN_THRESHOLD + 6):
            analyze_packet(self._make_tcp(ips[1], MY_IP, p))
        time.sleep(0.2)
        # Attacker C: flood + scan
        for _ in range(PACKET_THRESHOLD * 2):
            analyze_packet(self._make_tcp(ips[2], MY_IP, 80))
        for p in range(100, 100 + PORT_SCAN_THRESHOLD + 6):
            analyze_packet(self._make_tcp(ips[2], MY_IP, p))


if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()