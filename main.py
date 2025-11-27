# main.py - CyberShield UNSTOPPABLE v3.2 — FULL LIVE-DASHBOARD
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import os
import webbrowser
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from datetime import datetime
import sys
import random
import queue

# Ensure matplotlib is installed
try:
    import matplotlib
except ImportError:
    print("Installing matplotlib...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "matplotlib"])
    import matplotlib

# Automatic updater
try:
    from updater import update
    update()
except:
    pass

# Core modules
from core.scanner import VulnerabilityScanner
from core.reporter import generate as generate_report


# ==================== CVSS VULNERABILITY CLASS ====================
class Vulnerability:
    def __init__(self, vuln_type, severity, description, url, param=None, line=None, payload=None):
        self.type = vuln_type
        self.severity = severity.upper()
        self.description = description
        self.url = url
        self.param = param
        self.line = line
        self.payload = payload
        self.timestamp = datetime.now().strftime("%H:%M:%S")

        # CVSS v3.1 base scores
        scores = {"XSS": 8.8, "SQLi": 9.8, "RCE": 9.8, "LFI": 7.5,
                  "Missing": 7.4, "Clickjacking": 6.5, "Open": 6.1}
        self.score = scores.get(vuln_type.split()[0], 5.0)
        self.vector = (
            f"CVSS:3.1/AV:N/AC:L/PR:N/UI:{'R' if 'XSS' in vuln_type else 'N'}"
            f"/S:U/C:H/I:H/A:N"
        )

    def location_str(self):
        loc = self.url
        if self.param:
            loc += f"?{self.param}=..."
        if self.line:
            loc += f" @ line ~{self.line}"
        return loc


# ==================== MAIN TKINTER APPLICATION ====================
class CyberShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberShield UNSTOPPABLE v3.2 - CVSS + Clickable Vulns")
        self.geometry("1700x1000")
        self.minsize(1300, 800)
        self.configure(bg="#0d1117")

        self.scan_active = False
        self.vulnerabilities = []
        self.current_report_path = None

        # Queue for live updates from scanner thread
        self.ui_queue = queue.Queue()

        # Global style
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background="#0d1117", foreground="#c9d1d9")
        style.configure("TNotebook.Tab", background="#161b22", foreground="#8b949e", padding=[20, 12])
        style.map("TNotebook.Tab",
                  background=[("selected", "#21262d")],
                  foreground=[("selected", "#58a6ff")])

        # Main Notebook Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=16)

        self.home_frame = self.create_home()
        self.scan_frame = self.create_scan_frame()
        self.dashboard_frame = self.create_dashboard_frame()
        self.report_frame = self.create_report_frame()

        self.notebook.add(self.home_frame, text=" Home")
        self.notebook.add(self.scan_frame, text=" Scanner")
        self.notebook.add(self.dashboard_frame, text=" Live Dashboard")
        self.notebook.add(self.report_frame, text=" Report")

        # Scanner core
        self.scanner = VulnerabilityScanner()

        # Start dashboard auto-refresh
        self.after(100, self.update_dashboard)
        self.after(200, self.process_ui_queue)

    # ==================== HOME PAGE ====================
    def create_home(self):
        f = ttk.Frame(self.notebook, padding=80)
        tk.Label(f, text="CYBERSHIELD", font=("Segoe UI", 60, "bold"),
                 fg="#58a6ff", bg="#0d1117").pack(pady=(80, 20))
        tk.Label(f, text="UNSTOPPABLE v3.2", font=("Segoe UI", 20),
                 fg="#8b949e", bg="#0d1117").pack()
        tk.Label(f, text="Real-Time • CVSS Scoring • Clickable Vulnerabilities",
                 font=("Segoe UI", 16), fg="#79c0ff", bg="#0d1117").pack(pady=20)
        tk.Button(
            f, text="LAUNCH SCANNER", font=("Segoe UI", 20, "bold"),
            bg="#238636", fg="white", width=30, height=2,
            command=lambda: self.notebook.select(self.scan_frame)
        ).pack(pady=60)
        return f

    # ==================== SCANNER PAGE ====================
    def create_scan_frame(self):
        f = ttk.Frame(self.notebook, padding=40)
        tk.Label(f, text="Target Scanner", font=("Segoe UI", 34, "bold"),
                 fg="#58a6ff", bg="#0d1117").pack(pady=(20, 40))

        inp = tk.Frame(f, bg="#0d1117")
        inp.pack(pady=20, fill="x", padx=120)
        tk.Label(inp, text="Target URL:", font=("Segoe UI", 14),
                 fg="#c9d1d9", bg="#0d1117").pack(anchor="w")

        self.target_entry = tk.Entry(inp, font=("Consolas", 16),
                                     bg="#161b22", fg="#79c0ff",
                                     insertbackground="white")
        self.target_entry.pack(fill="x", pady=10, ipady=12)
        self.target_entry.insert(0, "https://testphp.vulnweb.com")

        self.status_var = tk.StringVar(value="Status: Ready")
        tk.Label(f, textvariable=self.status_var,
                 font=("Segoe UI", 13), fg="#58a6ff", bg="#0d1117").pack(pady=20)

        self.progress = ttk.Progressbar(f, length=900, mode="determinate")
        self.progress.pack(pady=25)

        btns = tk.Frame(f, bg="#0d1117")
        btns.pack(pady=30)

        self.start_btn = tk.Button(
            btns, text="START SCAN", font=("Segoe UI", 16, "bold"),
            bg="#238636", fg="white", width=20, command=self.start_scan
        )
        self.start_btn.pack(side="left", padx=30)

        self.stop_btn = tk.Button(
            btns, text="STOP", bg="#da3633",
            fg="white", width=16, state="disabled",
            command=self.stop_scan
        )
        self.stop_btn.pack(side="left", padx=30)

        return f

    # ==================== DASHBOARD PAGE ====================
    def create_dashboard_frame(self):
        f = ttk.Frame(self.notebook, padding=20)

        top = tk.Frame(f, bg="#0d1117")
        top.pack(fill="x", pady=10)
        self.risk_label = tk.Label(
            top, text="RISK: 0%", font=("Segoe UI", 38, "bold"),
            fg="#238636", bg="#0d1117"
        )
        self.risk_label.pack(side="left", padx=40)

        # CVSS Radar Chart
        self.cvss_fig, self.cvss_ax = plt.subplots(
            figsize=(5, 5), subplot_kw=dict(projection='polar'),
            facecolor="#0d1117"
        )
        self.cvss_ax.set_facecolor("#161b22")
        self.cvss_canvas = FigureCanvasTkAgg(self.cvss_fig, top)
        self.cvss_canvas.get_tk_widget().pack(side="right", padx=40)

        # Vulnerability Table
        tree_f = tk.Frame(f)
        tree_f.pack(fill="both", expand=True, pady=20)
        cols = ("Severity", "CVSS", "Type", "Location", "ID")
        self.vuln_tree = ttk.Treeview(tree_f, columns=cols, show="headings", height=16)
        for c in cols:
            self.vuln_tree.heading(c, text=c)
            self.vuln_tree.column(c, width=500 if c == "Location" else 150, anchor="center")
        self.vuln_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(tree_f, command=self.vuln_tree.yview)
        sb.pack(side="right", fill="y")
        self.vuln_tree.configure(yscrollcommand=sb.set)
        self.vuln_tree.bind("<Double-1>", self.show_vuln_details)

        # Bar + Pie charts
        self.fig, (self.ax1, self.ax2) = plt.subplots(
            1, 2, figsize=(14, 5.5), facecolor="#0d1117"
        )
        self.ax1.set_facecolor("#161b22")
        self.ax2.set_facecolor("#161b22")
        self.canvas = FigureCanvasTkAgg(self.fig, f)
        self.canvas.get_tk_widget().pack(pady=20)
        toolbar = NavigationToolbar2Tk(self.canvas, f)
        toolbar.update()
        return f

    # ==================== VULNERABILITY DETAILS ====================
    def show_vuln_details(self, event):
        sel = self.vuln_tree.selection()
        if not sel:
            return
        idx = int(self.vuln_tree.item(sel[0])["values"][-1])
        v = self.vulnerabilities[idx]
        details = f"""
[{v.severity}] {v.type}
CVSS Score: {v.score} | {v.vector}

Location:
  {v.location_str()}

Payload: {v.payload or "N/A"}
Description: {v.description}
Discovered: {v.timestamp}
""".strip()
        messagebox.showinfo("Vulnerability Details", details, parent=self)

    # ==================== REPORT PAGE ====================
    def create_report_frame(self):
        f = ttk.Frame(self.notebook, padding=30)
        header = tk.Frame(f, bg="#0d1117")
        header.pack(fill="x")
        tk.Label(header, text="Final Report", font=("Segoe UI", 32, "bold"),
                 fg="#58a6ff", bg="#0d1117").pack(side="left")
        self.open_btn = tk.Button(
            header, text="Open Report", bg="#30363d", fg="#58a6ff",
            command=self.open_report, state="disabled"
        )
        self.open_btn.pack(side="right")

        txt_f = tk.Frame(f)
        txt_f.pack(fill="both", expand=True)
        self.report_text = tk.Text(
            txt_f, font=("Consolas", 11), bg="#161b22",
            fg="#79c0ff", wrap="word"
        )
        self.report_text.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(txt_f, command=self.report_text.yview)
        sb.pack(side="right", fill="y")
        self.report_text.config(yscrollcommand=sb.set, state="disabled")
        return f

    # ==================== DASHBOARD AUTO-UPDATE ====================
    def update_dashboard(self):
        # Live risk calculation
        total_score = sum(v.score for v in self.vulnerabilities)
        risk = min(100, int(total_score * 2))
        color = "#238636" if risk < 40 else "#f0883e" if risk < 80 else "#f85149"
        self.risk_label.config(text=f"RISK: {risk}%", fg=color)

        # Radar Chart - average CVSS
        labels = ['AV', 'AC', 'PR', 'UI', 'Scope', 'Impact']
        if self.vulnerabilities:
            avg_score = sum(v.score for v in self.vulnerabilities)/len(self.vulnerabilities)
            values = [avg_score]*6
        else:
            values = [0]*6
        values += values[:1]
        angles = [n / len(labels) * 2 * 3.14159 for n in range(len(labels))]
        angles += angles[:1]

        self.cvss_ax.clear()
        self.cvss_ax.plot(angles, values, 'o-', linewidth=2, color='#58a6ff')
        self.cvss_ax.fill(angles, values, color='#58a6ff', alpha=0.2)
        self.cvss_canvas.draw()

        # Bar + Pie charts
        self.ax1.clear()
        self.ax2.clear()
        sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        counts = [len([v for v in self.vulnerabilities if v.severity == s]) for s in sevs]
        colors = ["#f85149", "#f0883e", "#d29922", "#238636"]
        self.ax1.bar(sevs, counts, color=colors)
        self.ax1.set_title("Vulnerabilities by Severity", color="#58a6ff")
        if sum(counts) > 0:
            self.ax2.pie(counts, labels=sevs, colors=colors,
                         autopct=lambda p: f'{p:.1f}%' if p > 0 else '',
                         textprops={'color': "white", 'weight': 'bold'})
        else:
            self.ax2.text(0.5, 0.5, "No findings yet", transform=self.ax2.transAxes,
                          ha='center', va='center', color="#666", fontsize=14)
        self.canvas.draw()
        self.after(2000, self.update_dashboard)

    # ==================== START SCAN ====================
    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target.startswith("http"):
            messagebox.showwarning("Invalid", "Enter a valid URL")
            return
        self.vulnerabilities.clear()
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.scan_active = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress["value"] = 0
        self.status_var.set("Status: Running...")
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()

    # ==================== SCAN THREAD ====================
    def run_scan(self, target):
        def callback(status, progress=None, finding=None):
            self.ui_queue.put((status, progress, finding))

        try:
            self.scanner.scan(target, callback=callback)
            self.current_report_path = generate_report({"findings": self.vulnerabilities})
            self.ui_queue.put(("Scan completed! Check Live Dashboard", None, None))
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.scan_active = False
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    # ==================== UI QUEUE PROCESSING ====================
    def process_ui_queue(self):
        while not self.ui_queue.empty():
            status, progress, finding = self.ui_queue.get()
            self.status_var.set(f"Status: {status}")
            if progress is not None:
                self.progress["value"] = progress
            if isinstance(finding, Vulnerability):
                self.vulnerabilities.append(finding)
                loc = finding.location_str()
                short_loc = loc[:67] + "..." if len(loc) > 70 else loc
                self.vuln_tree.insert("", "end",
                                      values=(finding.severity, f"{finding.score:.1f}",
                                              finding.type, short_loc, len(self.vulnerabilities)-1),
                                      tags=(finding.severity,))
                # Color tags
                self.vuln_tree.tag_configure("CRITICAL", background="#330000", foreground="#ff5555")
                self.vuln_tree.tag_configure("HIGH", background="#332900", foreground="#ffaa00")
                self.vuln_tree.tag_configure("MEDIUM", background="#333300", foreground="#ffff55")
                self.vuln_tree.tag_configure("LOW", background="#003300", foreground="#88ff88")
        self.after(200, self.process_ui_queue)

    # ==================== STOP SCAN ====================
    def stop_scan(self):
        self.scan_active = False
        self.status_var.set("Status: Scan stopped.")
        self.progress["value"] = 0
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    # ==================== OPEN REPORT ====================
    def open_report(self):
        if self.current_report_path:
            webbrowser.open(self.current_report_path)


# ==================== RUN APPLICATION ====================
if __name__ == "__main__":
    app = CyberShieldApp()
    app.mainloop()
