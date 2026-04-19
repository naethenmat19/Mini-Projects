import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from detector import analyze_packet
from logger import set_gui_logger

running = False


class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network IDS Dashboard")
        self.root.geometry("900x550")
        self.root.configure(bg="#0d1117")

        self.packet_count = 0

        # ===== TITLE =====
        tk.Label(
            root,
            text="Network Intrusion Detection System",
            bg="#0d1117",
            fg="#c9d1d9",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=10)

        # ===== BUTTONS =====
        btn_frame = tk.Frame(root, bg="#0d1117")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="▶ Start", command=self.start_ids,
                  bg="#6e7681", fg="white", bd=0,
                  font=("Times New Roman", 10, "bold"), padx=15, pady=5).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="⏹ Stop", command=self.stop_ids,
                  bg="#6e7681", fg="white", bd=0,
                  font=("Times New Roman", 10, "bold"), padx=15, pady=5).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="🗑 Clear", command=self.clear_logs,
                  bg="#6e7681", fg="white", bd=0,
                  font=("Times New Roman", 10, "bold"), padx=15, pady=5).pack(side=tk.LEFT, padx=10)

        # ===== LOG PANEL =====
        frame = tk.Frame(root, bg="#161b22", bd=1, relief="solid")
        frame.pack(fill="both", expand=True, padx=15, pady=10)

        tk.Label(frame, text="Live Traffic Logs",
                 bg="#161b22", fg="#c9d1d9",
                 font=("Times New Roman", 11, "bold")).pack(anchor="w", padx=10, pady=5)

        self.log_area = scrolledtext.ScrolledText(
            frame,
            bg="#0d1117",
            fg="#c9d1d9",
            insertbackground="white",
            font=("Consolas", 10),
            bd=0,
            highlightthickness=0
        )
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)

        # Color tags
        self.log_area.tag_config("alert", foreground="#ff4d4f")
        self.log_area.tag_config("warning", foreground="#f1e05a")
        self.log_area.tag_config("info", foreground="#58a6ff")

        set_gui_logger(self.log)

    # ===== FORMAT PACKET =====
    def format_packet(self, packet):
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

    # ===== LOG =====
    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")

        if "[ALERT]" in message:
            self.log_area.tag_add("alert", "end-1l", "end")
        elif "[WARNING]" in message:
            self.log_area.tag_add("warning", "end-1l", "end")
        elif "[INFO]" in message:
            self.log_area.tag_add("info", "end-1l", "end")

        self.log_area.yview(tk.END)

    # ===== PACKET HANDLER =====
    def packet_callback(self, packet):
        global running
        if not running:
            return

        self.packet_count += 1

        if self.packet_count % 10 == 0:
            formatted = self.format_packet(packet)
            if formatted:
                self.log(formatted)

        analyze_packet(packet)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=False)

    # ===== CONTROLS =====
    def start_ids(self):
        global running
        running = True
        self.log("[INFO] IDS Started...\n")

        Thread(target=self.sniff_packets, daemon=True).start()

    def stop_ids(self):
        global running
        running = False
        self.log("\n[INFO] IDS Stopped.\n")

    def clear_logs(self):
        self.log_area.delete(1.0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()