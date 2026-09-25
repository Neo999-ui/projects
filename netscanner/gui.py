"""
NetPulse Pro - Graphical User Interface (Tkinter)
Provides a modern dark-themed GUI for scanning network devices, inspecting details, and exporting reports.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import webbrowser
import os
import json
import time
from typing import List, Dict, Optional

from scanner_engine import NetworkUtils, HostDiscoveryScanner, PortScanner, SecurityAuditor, COMMON_PORTS
from history_manager import HistoryManager
from report_generator import ReportGenerator


class NetPulseGUI:
    """Tkinter-based GUI for NetPulse Pro Network Scanner."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NetPulse Pro - Personal Network Scanner & Auditor")
        self.root.geometry("1150x730")
        self.root.minsize(950, 600)

        # Scanning State
        self.is_scanning = False
        self.stop_requested = False
        self.scanned_hosts: List[Dict] = []
        self.filtered_hosts: List[Dict] = []

        # Auto-detect Network Info
        self.local_ip = NetworkUtils.get_local_ip()
        self.gateway_ip = NetworkUtils.get_default_gateway()
        self.default_subnet = NetworkUtils.get_default_subnet()

        # Apply Dark Theme Styles
        self._setup_theme()

        # Build UI Components
        self._build_header()
        self._build_control_panel()
        self._build_stats_panel()
        self._build_search_filter_bar()
        self._build_table_view()
        self._build_status_and_export_bar()

        # Check History for Intrusion Alerts
        self.root.after(500, self._check_initial_intrusion_alert)

    def _setup_theme(self):
        """Sets up dark mode color scheme for Tkinter and TTK widgets."""
        self.colors = {
            "bg": "#0f172a",
            "card_bg": "#1e293b",
            "input_bg": "#0f172a",
            "border": "#334155",
            "text": "#f8fafc",
            "text_muted": "#94a3b8",
            "accent": "#0ea5e9",
            "accent_hover": "#0284c7",
            "green": "#10b981",
            "amber": "#f59e0b",
            "red": "#ef4444",
            "blue": "#3b82f6"
        }

        self.root.configure(bg=self.colors["bg"])

        style = ttk.Style()
        style.theme_use("clam")

        # Global Frame & Label Styles
        style.configure(".", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("TFrame", background=self.colors["bg"])
        style.configure("Card.TFrame", background=self.colors["card_bg"], relief="flat")
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=self.colors["card_bg"], foreground=self.colors["text"])
        style.configure("Muted.TLabel", background=self.colors["bg"], foreground=self.colors["text_muted"], font=("Segoe UI", 9))
        style.configure("CardMuted.TLabel", background=self.colors["card_bg"], foreground=self.colors["text_muted"], font=("Segoe UI", 9))

        # Button Styles
        style.configure("Accent.TButton", background=self.colors["accent"], foreground="#ffffff", font=("Segoe UI", 10, "bold"), borderwidth=0, padding=8)
        style.map("Accent.TButton", background=[("active", self.colors["accent_hover"]), ("disabled", "#475569")])

        style.configure("Stop.TButton", background=self.colors["red"], foreground="#ffffff", font=("Segoe UI", 10, "bold"), borderwidth=0, padding=8)
        style.map("Stop.TButton", background=[("active", "#dc2626"), ("disabled", "#475569")])

        style.configure("Secondary.TButton", background=self.colors["card_bg"], foreground=self.colors["text"], font=("Segoe UI", 9), borderwidth=1, relief="solid", padding=6)
        style.map("Secondary.TButton", background=[("active", self.colors["border"])])

        # Progressbar Style
        style.configure("TProgressbar", troughcolor=self.colors["card_bg"], background=self.colors["accent"], borderwidth=0)

        # Treeview Styles
        style.configure("Treeview",
                        background=self.colors["card_bg"],
                        foreground=self.colors["text"],
                        fieldbackground=self.colors["card_bg"],
                        rowheight=28,
                        font=("Segoe UI", 9),
                        bordercolor=self.colors["border"])

        style.configure("Treeview.Heading",
                        background="#0f172a",
                        foreground=self.colors["text_muted"],
                        font=("Segoe UI", 9, "bold"),
                        padding=6,
                        borderwidth=0)
        style.map("Treeview.Heading", background=[("active", "#1e293b")])

    def _build_header(self):
        """Header banner displaying app logo and active network info."""
        header_frame = ttk.Frame(self.root, padding=(16, 12, 16, 8))
        header_frame.pack(fill="x")

        title_label = tk.Label(header_frame, text="⚡ NetPulse Pro", font=("Segoe UI", 18, "bold"), bg=self.colors["bg"], fg=self.colors["accent"])
        title_label.pack(side="left")

        subnet_info = f"Local IP: {self.local_ip}  |  Gateway: {self.gateway_ip}  |  Subnet: {self.default_subnet}"
        info_label = ttk.Label(header_frame, text=subnet_info, style="Muted.TLabel")
        info_label.pack(side="right", pady=(4, 0))

    def _build_control_panel(self):
        """Top scanning controls: Target subnet, Scan mode selector, Start/Stop buttons."""
        ctrl_card = ttk.Frame(self.root, style="Card.TFrame", padding=14)
        ctrl_card.pack(fill="x", padx=16, pady=4)

        # Target IP Range Entry
        ttk.Label(ctrl_card, text="Target IP Range:", style="Card.TLabel", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 6))

        self.target_entry = tk.Entry(ctrl_card, bg=self.colors["input_bg"], fg=self.colors["text"], insertbackground=self.colors["text"],
                                     font=("Consolas", 10), relief="flat", highlightbackground=self.colors["border"], highlightthickness=1)
        self.target_entry.insert(0, self.default_subnet)
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=(0, 14), ipady=4)

        # Scan Mode Selector
        ttk.Label(ctrl_card, text="Scan Intensity:", style="Card.TLabel", font=("Segoe UI", 9, "bold")).grid(row=0, column=2, sticky="w", padx=(0, 6))

        self.mode_var = tk.StringVar(value="Standard Audit (Top Ports)")
        self.mode_combo = ttk.Combobox(ctrl_card, textvariable=self.mode_var, state="readonly", width=28)
        self.mode_combo["values"] = [
            "Quick Discovery (Ping Sweep + ARP)",
            "Standard Audit (Top Ports)",
            "Deep Security Audit (Top 100 + Banners)"
        ]
        self.mode_combo.grid(row=0, column=3, sticky="w", padx=(0, 16))

        # Start / Stop Buttons
        self.btn_start = ttk.Button(ctrl_card, text="▶ Start Scan", style="Accent.TButton", command=self.start_scan)
        self.btn_start.grid(row=0, column=4, padx=(0, 8))

        self.btn_stop = ttk.Button(ctrl_card, text="⏹ Stop", style="Stop.TButton", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=0, column=5)

        ctrl_card.columnconfigure(1, weight=1)

        # Progress Bar
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100.0)
        self.progress_bar.pack(fill="x", padx=16, pady=(6, 4))

    def _build_stats_panel(self):
        """Dashboard stat summary cards."""
        stats_frame = ttk.Frame(self.root, padding=(16, 4, 16, 4))
        stats_frame.pack(fill="x")

        # Grid of 4 Card Panels
        self.card_active_val = self._create_stat_card(stats_frame, "ACTIVE HOSTS", "0", self.colors["accent"], 0)
        self.card_ports_val = self._create_stat_card(stats_frame, "OPEN PORTS", "0", self.colors["green"], 1)
        self.card_risks_val = self._create_stat_card(stats_frame, "HIGH RISKS", "0", self.colors["red"], 2)
        self.card_vendors_val = self._create_stat_card(stats_frame, "VENDORS", "0", self.colors["text"], 3)

        for i in range(4):
            stats_frame.columnconfigure(i, weight=1)

    def _create_stat_card(self, parent, title: str, default_val: str, color: str, col_idx: int) -> tk.Label:
        card = ttk.Frame(parent, style="Card.TFrame", padding=10)
        card.grid(row=0, column=col_idx, sticky="nsew", padx=4, pady=2)

        lbl_title = ttk.Label(card, text=title, style="CardMuted.TLabel")
        lbl_title.pack(anchor="w")

        lbl_val = tk.Label(card, text=default_val, font=("Segoe UI", 20, "bold"), bg=self.colors["card_bg"], fg=color)
        lbl_val.pack(anchor="w", pady=(2, 0))

        return lbl_val

    def _build_search_filter_bar(self):
        """Search entry and filter combobox above table."""
        filter_frame = ttk.Frame(self.root, padding=(16, 6, 16, 4))
        filter_frame.pack(fill="x")

        ttk.Label(filter_frame, text="🔍 Search:", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._apply_table_filters())
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var, bg=self.colors["card_bg"], fg=self.colors["text"],
                                insertbackground=self.colors["text"], relief="flat", highlightbackground=self.colors["border"],
                                highlightthickness=1, font=("Segoe UI", 9))
        search_entry.pack(side="left", fill="x", expand=True, padx=(0, 16), ipady=3)

        ttk.Label(filter_frame, text="Risk Filter:", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))

        self.filter_risk_var = tk.StringVar(value="All Risk Levels")
        risk_combo = ttk.Combobox(filter_frame, textvariable=self.filter_risk_var, state="readonly", width=16)
        risk_combo["values"] = ["All Risk Levels", "High", "Medium", "Safe / Low"]
        risk_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_table_filters())
        risk_combo.pack(side="left")

    def _build_table_view(self):
        """Main device results Treeview table."""
        table_frame = ttk.Frame(self.root, padding=(16, 2, 16, 4))
        table_frame.pack(fill="both", expand=True)

        columns = ("num", "ip", "hostname", "mac", "vendor", "device_type", "latency", "risk", "ports")

        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("num", text="#")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("hostname", text="Hostname / Name")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("vendor", text="Hardware Vendor")
        self.tree.heading("device_type", text="Device Type")
        self.tree.heading("latency", text="Ping Latency")
        self.tree.heading("risk", text="Security Risk")
        self.tree.heading("ports", text="Open Ports")

        self.tree.column("num", width=40, anchor="center")
        self.tree.column("ip", width=120, anchor="w")
        self.tree.column("hostname", width=160, anchor="w")
        self.tree.column("mac", width=140, anchor="center")
        self.tree.column("vendor", width=180, anchor="w")
        self.tree.column("device_type", width=140, anchor="w")
        self.tree.column("latency", width=90, anchor="center")
        self.tree.column("risk", width=110, anchor="center")
        self.tree.column("ports", width=160, anchor="w")

        # Scrollbars
        v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Configure Row Tags for Risk Highlighting
        self.tree.tag_configure("High", foreground=self.colors["red"])
        self.tree.tag_configure("Medium", foreground=self.colors["amber"])
        self.tree.tag_configure("Low", foreground=self.colors["green"])
        self.tree.tag_configure("Safe", foreground=self.colors["text"])

        # Bind Double-Click to Open Host Inspector Modal
        self.tree.bind("<Double-1>", self._on_host_double_click)

    def _build_status_and_export_bar(self):
        """Bottom status bar and export buttons."""
        bottom_frame = ttk.Frame(self.root, padding=(16, 6, 16, 12))
        bottom_frame.pack(fill="x")

        self.lbl_status = ttk.Label(bottom_frame, text="Ready to scan.", style="Muted.TLabel")
        self.lbl_status.pack(side="left")

        # Export Buttons
        btn_json = ttk.Button(bottom_frame, text="JSON", style="Secondary.TButton", command=self.export_json)
        btn_json.pack(side="right", padx=(4, 0))

        btn_csv = ttk.Button(bottom_frame, text="CSV", style="Secondary.TButton", command=self.export_csv)
        btn_csv.pack(side="right", padx=(4, 0))

        btn_html = ttk.Button(bottom_frame, text="📄 Export HTML Report", style="Secondary.TButton", command=self.export_html)
        btn_html.pack(side="right", padx=(4, 0))

    # =========================================================================
    # SCANNING LOGIC
    # =========================================================================
    def start_scan(self):
        """Launches network scan in a background worker thread."""
        if self.is_scanning:
            return

        target_range = self.target_entry.get().strip()
        if not target_range:
            messagebox.showerror("Error", "Please enter a valid IP range or CIDR subnet.")
            return

        self.is_scanning = True
        self.stop_requested = False
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.progress_var.set(0.0)

        # Clear existing table
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.scanned_hosts.clear()

        # Update Stat Cards
        self.card_active_val.configure(text="0")
        self.card_ports_val.configure(text="0")
        self.card_risks_val.configure(text="0")
        self.card_vendors_val.configure(text="0")

        self.lbl_status.configure(text=f"Scanning target network {target_range}...")

        # Start thread
        thread = threading.Thread(target=self._run_scan_thread, args=(target_range,), daemon=True)
        thread.start()

    def stop_scan(self):
        """Flags stop request to worker thread."""
        if self.is_scanning:
            self.stop_requested = True
            self.lbl_status.configure(text="Stopping scan... Please wait.")

    def _run_scan_thread(self, target_range: str):
        """Worker thread function for executing scan steps."""
        ip_list = NetworkUtils.expand_ip_range(target_range)
        total_ips = len(ip_list)

        def progress_cb(completed: int, total: int, current_ip: str):
            if self.stop_requested:
                return
            pct = (completed / total) * 50.0  # Phase 1: Host Discovery is 50%
            self.root.after(0, self._update_progress, pct, f"Discovering hosts... ({completed}/{total}) Checking {current_ip}")

        # Phase 1: Host Discovery
        discovered_hosts = HostDiscoveryScanner.scan_network(ip_list, progress_callback=progress_cb)

        if self.stop_requested:
            self.root.after(0, self._scan_finished, "Scan cancelled by user.")
            return

        # Phase 2: Port Scanning & Security Audit
        scan_mode = self.mode_var.get()
        hosts_count = len(discovered_hosts)

        for idx, host in enumerate(discovered_hosts, 1):
            if self.stop_requested:
                break

            pct = 50.0 + ((idx / max(hosts_count, 1)) * 50.0)
            self.root.after(0, self._update_progress, pct, f"Auditing host ports & banners ({idx}/{hosts_count}) {host['ip']}...")

            if "Standard" in scan_mode:
                # Scan top 20 ports
                host["open_ports"] = PortScanner.scan_host_ports(host["ip"], port_list=list(COMMON_PORTS.keys())[:20])
            elif "Deep" in scan_mode:
                # Scan all common ports
                host["open_ports"] = PortScanner.scan_host_ports(host["ip"], port_list=list(COMMON_PORTS.keys()))

            # Audit Security Risk
            risk_score, risk_details = SecurityAuditor.audit_host(host)
            host["risk_score"] = risk_score
            host["risk_details"] = risk_details

        self.scanned_hosts = discovered_hosts

        # Save scan to history
        HistoryManager.save_scan(self.scanned_hosts, target_range)

        # Update UI with final results
        self.root.after(0, self._scan_finished, f"Scan complete! Discovered {len(self.scanned_hosts)} active hosts.")

    def _update_progress(self, percentage: float, status_text: str):
        """Main thread callback to update progress bar and status text."""
        self.progress_var.set(percentage)
        self.lbl_status.configure(text=status_text)

    def _scan_finished(self, status_msg: str):
        """Resets controls and updates table with scan results."""
        self.is_scanning = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.progress_var.set(100.0 if "complete" in status_msg.lower() else 0.0)
        self.lbl_status.configure(text=status_msg)

        # Update Table and Stats
        self._apply_table_filters()
        self._update_stats_dashboard()

        # Check Diff for Intrusion Alerts
        history = HistoryManager.load_history()
        if len(history) >= 2:
            current_scan = history[0]["hosts"]
            prev_scan = history[1]["hosts"]
            diff = HistoryManager.diff_scans(current_scan, prev_scan)

            if diff["new_devices"]:
                new_ips = ", ".join([h["ip"] for h in diff["new_devices"]])
                messagebox.showwarning(
                    "⚠️ New Device Alert!",
                    f"NetPulse Pro detected {len(diff['new_devices'])} NEW device(s) on your network since the last scan:\n\nIPs: {new_ips}"
                )

    def _update_stats_dashboard(self):
        """Recalculates stat card totals."""
        total_active = len(self.scanned_hosts)
        total_ports = sum(len(h.get("open_ports", [])) for h in self.scanned_hosts)
        high_risks = sum(1 for h in self.scanned_hosts if h.get("risk_score") == "High")
        unique_vendors = len(set(h.get("vendor", "Unknown") for h in self.scanned_hosts))

        self.card_active_val.configure(text=str(total_active))
        self.card_ports_val.configure(text=str(total_ports))
        self.card_risks_val.configure(text=str(high_risks))
        self.card_vendors_val.configure(text=str(unique_vendors))

    def _apply_table_filters(self):
        """Filters treeview rows based on search text and risk dropdown."""
        query = self.search_var.get().lower().strip()
        risk_filter = self.filter_risk_var.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.filtered_hosts = []
        for idx, host in enumerate(self.scanned_hosts, 1):
            ip = host.get("ip", "").lower()
            name = host.get("hostname", "").lower()
            mac = host.get("mac", "").lower()
            vendor = host.get("vendor", "").lower()
            risk = host.get("risk_score", "Safe")

            # Check search match
            matches_search = not query or (query in ip or query in name or query in mac or query in vendor)

            # Check risk match
            matches_risk = True
            if risk_filter == "High":
                matches_risk = (risk == "High")
            elif risk_filter == "Medium":
                matches_risk = (risk == "Medium")
            elif risk_filter == "Safe / Low":
                matches_risk = (risk in ["Safe", "Low"])

            if matches_search and matches_risk:
                self.filtered_hosts.append(host)
                ports_list = host.get("open_ports", [])
                ports_str = f"{len(ports_list)} Open" if ports_list else "None"

                self.tree.insert("", "end", values=(
                    idx,
                    host["ip"],
                    host["hostname"] or "N/A",
                    host["mac"],
                    host["vendor"],
                    host["device_type"],
                    f"{host.get('latency_ms', 1.0)} ms",
                    risk,
                    ports_str
                ), tags=(risk,))

    # =========================================================================
    # DETAILED HOST INSPECTOR MODAL
    # =========================================================================
    def _on_host_double_click(self, event):
        """Opens a detailed modal inspector for the selected device."""
        selected_item = self.tree.selection()
        if not selected_item:
            return

        item_values = self.tree.item(selected_item[0], "values")
        if not item_values or len(item_values) < 2:
            return

        ip = item_values[1]
        host = next((h for h in self.scanned_hosts if h["ip"] == ip), None)
        if not host:
            return

        # Create Modal Window
        modal = tk.Toplevel(self.root)
        modal.title(f"Device Inspector - {host['ip']}")
        modal.geometry("620x520")
        modal.configure(bg=self.colors["card_bg"])
        modal.transient(self.root)
        modal.grab_set()

        # Header Info
        header_frame = tk.Frame(modal, bg=self.colors["card_bg"], padx=20, pady=16)
        header_frame.pack(fill="x")

        tk.Label(header_frame, text=f"💻 {host['hostname'] or host['ip']}", font=("Segoe UI", 14, "bold"), bg=self.colors["card_bg"], fg=self.colors["accent"]).pack(anchor="w")
        tk.Label(header_frame, text=f"IP: {host['ip']}   |   MAC: {host['mac']}   |   Vendor: {host['vendor']}", font=("Segoe UI", 9), bg=self.colors["card_bg"], fg=self.colors["text_muted"]).pack(anchor="w", pady=(2, 0))

        # Divider
        tk.Frame(modal, bg=self.colors["border"], height=1).pack(fill="x", padx=20)

        # Tab notebook / Sections
        body_frame = tk.Frame(modal, bg=self.colors["card_bg"], padx=20, pady=12)
        body_frame.pack(fill="both", expand=True)

        # Security Risk Summary
        risk = host.get("risk_score", "Safe")
        risk_color = self.colors["red"] if risk == "High" else (self.colors["amber"] if risk == "Medium" else self.colors["green"])

        tk.Label(body_frame, text=f"Security Status: {risk}", font=("Segoe UI", 11, "bold"), bg=self.colors["card_bg"], fg=risk_color).pack(anchor="w")

        details_text = "\n".join(host.get("risk_details", ["No security vulnerabilities detected."]))
        tk.Label(body_frame, text=details_text, font=("Segoe UI", 9), bg=self.colors["card_bg"], fg=self.colors["text"], justify="left").pack(anchor="w", pady=(4, 12))

        # Open Ports List
        tk.Label(body_frame, text="Open Network Ports & Banners:", font=("Segoe UI", 10, "bold"), bg=self.colors["card_bg"], fg=self.colors["text"]).pack(anchor="w")

        ports_listbox = tk.Text(body_frame, height=9, bg=self.colors["bg"], fg=self.colors["text"], relief="flat", font=("Consolas", 9), padx=8, pady=8)
        ports_listbox.pack(fill="both", expand=True, pady=6)

        ports = host.get("open_ports", [])
        if ports:
            for p in ports:
                banner_info = f" -> {p['banner']}" if p.get("banner") else ""
                ports_listbox.insert("end", f"Port {p['port']:<5} | Service: {p['service']}{banner_info}\n")
        else:
            ports_listbox.insert("end", "No open TCP ports discovered during this scan.\n")

        ports_listbox.configure(state="disabled")

        # Action Buttons (Quick Browser Launcher & Copy IP)
        actions_frame = tk.Frame(modal, bg=self.colors["card_bg"], padx=20, pady=14)
        actions_frame.pack(fill="x")

        def open_browser():
            webbrowser.open(f"http://{host['ip']}")

        def copy_ip():
            self.root.clipboard_clear()
            self.root.clipboard_append(host['ip'])
            messagebox.showinfo("Copied", f"Copied IP address {host['ip']} to clipboard.", parent=modal)

        btn_open = ttk.Button(actions_frame, text="🌐 Open HTTP in Browser", style="Secondary.TButton", command=open_browser)
        btn_open.pack(side="left", padx=(0, 8))

        btn_copy = ttk.Button(actions_frame, text="📋 Copy IP", style="Secondary.TButton", command=copy_ip)
        btn_copy.pack(side="left")

        btn_close = ttk.Button(actions_frame, text="Close", style="Secondary.TButton", command=modal.destroy)
        btn_close.pack(side="right")

    # =========================================================================
    # EXPORT HANDLERS
    # =========================================================================
    def export_html(self):
        """Export scan report to interactive HTML file."""
        if not self.scanned_hosts:
            messagebox.showinfo("Export", "No scan data to export. Please run a scan first.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")], title="Save HTML Report")
        if filepath:
            path = ReportGenerator.generate_html_report(self.scanned_hosts, self.target_entry.get(), filepath)
            if messagebox.askyesno("Report Generated", f"HTML Report generated successfully at:\n{path}\n\nWould you like to open it in your web browser?"):
                webbrowser.open(f"file:///{path}")

    def export_csv(self):
        """Export scan data to CSV file."""
        if not self.scanned_hosts:
            messagebox.showinfo("Export", "No scan data to export. Please run a scan first.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save CSV Export")
        if filepath:
            path = ReportGenerator.generate_csv_report(self.scanned_hosts, filepath)
            messagebox.showinfo("Export Successful", f"Scan results exported to CSV:\n{path}")

    def export_json(self):
        """Export scan data to JSON file."""
        if not self.scanned_hosts:
            messagebox.showinfo("Export", "No scan data to export. Please run a scan first.")
            return

        filepath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], title="Save JSON Export")
        if filepath:
            path = ReportGenerator.generate_json_report(self.scanned_hosts, self.target_entry.get(), filepath)
            messagebox.showinfo("Export Successful", f"Scan results exported to JSON:\n{path}")

    def _check_initial_intrusion_alert(self):
        """Checks saved history on app launch to alert if new devices joined."""
        history = HistoryManager.load_history()
        if len(history) >= 2:
            diff = HistoryManager.diff_scans(history[0]["hosts"], history[1]["hosts"])
            if diff["new_devices"]:
                self.lbl_status.configure(text=f"⚠️ Warning: {len(diff['new_devices'])} new device(s) detected since previous scan!")


def launch_gui():
    """Main entry point to run Tkinter GUI loop."""
    root = tk.Tk()
    app = NetPulseGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
