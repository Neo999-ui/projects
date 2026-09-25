"""
NetPulse Pro - Command Line Interface (CLI)
Provides command-line options for automated or headless network scanning.
"""

import argparse
import sys
import os
import time
from typing import List, Dict

from scanner_engine import NetworkUtils, HostDiscoveryScanner, PortScanner, SecurityAuditor, COMMON_PORTS
from history_manager import HistoryManager
from report_generator import ReportGenerator

# Ensure stdout handles UTF-8 on Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def print_banner():
    """Prints banner for NetPulse Pro CLI."""
    banner = """
====================================================================
   NetPulse Pro - Personal Network Scanner & Security Auditor
====================================================================
"""
    print(banner)


def run_cli_scan(target: str, scan_ports: bool = True, deep_scan: bool = False,
                 export_html_path: str = None, export_csv_path: str = None, export_json_path: str = None):
    """Executes network scan in CLI mode and outputs formatted console report."""
    print_banner()

    if not target:
        target = NetworkUtils.get_default_subnet()

    local_ip = NetworkUtils.get_local_ip()
    gateway = NetworkUtils.get_default_gateway()

    print(f"[*] Local Adapter IP : {local_ip}")
    print(f"[*] Default Gateway  : {gateway}")
    print(f"[*] Target Subnet    : {target}")
    print(f"[*] Scan Intensity   : {'Deep (Top 100 + Banners)' if deep_scan else ('Standard (Top 20 Ports)' if scan_ports else 'Quick Discovery')}")
    print("-" * 68)

    ip_list = NetworkUtils.expand_ip_range(target)
    print(f"[*] Expanding target IP list... Total IPs to check: {len(ip_list)}")
    print("[*] Initiating multi-threaded host discovery ping sweep...\n")

    start_time = time.time()

    def progress_callback(completed, total, current_ip):
        pct = int((completed / total) * 100)
        sys.stdout.write(f"\rScanning IPs: [{completed}/{total}] ({pct}%) Checking {current_ip:<15}")
        sys.stdout.flush()

    hosts = HostDiscoveryScanner.scan_network(ip_list, progress_callback=progress_callback)
    sys.stdout.write("\r" + " " * 60 + "\r")  # Clear line

    print(f"[+] Host discovery finished! Found {len(hosts)} active hosts.\n")

    if scan_ports and hosts:
        print("[*] Performing port scanning and security risk audit on discovered hosts...")
        port_list = list(COMMON_PORTS.keys()) if deep_scan else list(COMMON_PORTS.keys())[:20]

        for idx, host in enumerate(hosts, 1):
            print(f"    [{idx}/{len(hosts)}] Auditing {host['ip']} ({host['hostname'] or 'N/A'})...")
            host["open_ports"] = PortScanner.scan_host_ports(host["ip"], port_list=port_list)
            risk_score, risk_details = SecurityAuditor.audit_host(host)
            host["risk_score"] = risk_score
            host["risk_details"] = risk_details

    # Save to scan history
    HistoryManager.save_scan(hosts, target)

    elapsed = round(time.time() - start_time, 2)

    # Output Console Results Table
    print("\n" + "=" * 100)
    print(f"{'#':<3} {'IP Address':<16} {'Hostname':<20} {'MAC Address':<18} {'Vendor':<20} {'Risk':<8} {'Open Ports'}")
    print("=" * 100)

    for idx, h in enumerate(hosts, 1):
        ip = h.get("ip", "")
        hostname = (h.get("hostname") or "N/A")[:18]
        mac = h.get("mac", "")
        vendor = h.get("vendor", "")[:18]
        risk = h.get("risk_score", "Safe")
        ports = ", ".join([str(p["port"]) for p in h.get("open_ports", [])]) or "None"

        print(f"{idx:<3} {ip:<16} {hostname:<20} {mac:<18} {vendor:<20} {risk:<8} {ports}")

    print("=" * 100)
    print(f"[+] Total Active Hosts: {len(hosts)} | Completed in {elapsed}s")

    # Check for new devices / intrusion diff
    history = HistoryManager.load_history()
    if len(history) >= 2:
        diff = HistoryManager.diff_scans(history[0]["hosts"], history[1]["hosts"])
        if diff["new_devices"]:
            print("\n" + "!" * 68)
            print(f"[!] INTRUSION ALERT: {len(diff['new_devices'])} NEW device(s) joined your network!")
            for dev in diff["new_devices"]:
                print(f"   -> New IP: {dev['ip']} | MAC: {dev['mac']} | Vendor: {dev['vendor']}")
            print("!" * 68)

    # Exports
    if export_html_path:
        path = ReportGenerator.generate_html_report(hosts, target, export_html_path)
        print(f"[+] HTML Report generated: {path}")

    if export_csv_path:
        path = ReportGenerator.generate_csv_report(hosts, export_csv_path)
        print(f"[+] CSV Report generated: {path}")

    if export_json_path:
        path = ReportGenerator.generate_json_report(hosts, target, export_json_path)
        print(f"[+] JSON Report generated: {path}")


def main_cli():
    """Main CLI entry point argument handler."""
    parser = argparse.ArgumentParser(description="NetPulse Pro - Personal Network Scanner & Security Auditor")
    parser.add_argument("-t", "--target", type=str, help="Target IP range or CIDR subnet (e.g. 192.168.1.0/24 or 192.168.1.1-50)")
    parser.add_argument("--quick", action="store_true", help="Quick host discovery scan without port scanning")
    parser.add_argument("--deep", action="store_true", help="Deep scan with full port scan and banner grabbing")
    parser.add_argument("--export-html", type=str, nargs="?", const="netpulse_report.html", help="Export scan results to interactive HTML report")
    parser.add_argument("--export-csv", type=str, nargs="?", const="netpulse_report.csv", help="Export scan results to CSV file")
    parser.add_argument("--export-json", type=str, nargs="?", const="netpulse_report.json", help="Export scan results to JSON file")

    args = parser.parse_args()

    scan_ports = not args.quick
    deep_scan = args.deep

    run_cli_scan(
        target=args.target,
        scan_ports=scan_ports,
        deep_scan=deep_scan,
        export_html_path=args.export_html,
        export_csv_path=args.export_csv,
        export_json_path=args.export_json
    )


if __name__ == "__main__":
    main_cli()
