"""
NetPulse Pro - Report Generator
Generates standalone interactive HTML dashboard reports, CSV files, and JSON exports.
"""

import csv
import json
import time
import os
from typing import List, Dict


class ReportGenerator:
    """Generates styled HTML, CSV, and JSON scan reports."""

    @staticmethod
    def generate_html_report(hosts: List[Dict], scan_range: str, output_path: str = "netpulse_scan_report.html") -> str:
        """Generates an interactive, standalone HTML scan report."""
        timestamp = time.strftime("%B %d, %Y - %H:%M:%S")
        total_hosts = len(hosts)

        # Calculate statistics
        total_ports = sum(len(h.get("open_ports", [])) for h in hosts)
        high_risk = sum(1 for h in hosts if h.get("risk_score") == "High")
        medium_risk = sum(1 for h in hosts if h.get("risk_score") == "Medium")
        safe_hosts = sum(1 for h in hosts if h.get("risk_score") in ["Safe", "Low"])
        unique_vendors = len(set(h.get("vendor", "Unknown") for h in hosts))

        # Build Host Rows HTML
        host_rows_html = ""
        for index, host in enumerate(hosts, 1):
            risk = host.get("risk_score", "Safe")
            risk_badge_class = f"badge-{risk.lower()}"

            ports = host.get("open_ports", [])
            if ports:
                ports_str = ", ".join([f"{p['port']}/{p['service'].split()[0]}" for p in ports])
            else:
                ports_str = "<span class='text-muted'>None detected</span>"

            details = host.get("risk_details", [])
            details_html = "<br>".join(details) if details else "Device appears secure."

            host_rows_html += f"""
            <tr class="host-row" data-risk="{risk.lower()}" data-search="{host['ip']} {host['hostname']} {host['mac']} {host['vendor']}">
                <td><strong>#{index}</strong></td>
                <td><span class="ip-address">{host['ip']}</span></td>
                <td><strong>{host['hostname'] or 'N/A'}</strong></td>
                <td><code>{host['mac']}</code></td>
                <td>{host['vendor']}</td>
                <td><span class="badge {risk_badge_class}">{risk}</span></td>
                <td>{ports_str}</td>
                <td><span class="latency">{host.get('latency_ms', 1.0)} ms</span></td>
            </tr>
            <tr class="details-row">
                <td colspan="8">
                    <div class="device-details">
                        <strong>Security & Audit Notes for {host['ip']}:</strong>
                        <p>{details_html}</p>
                    </div>
                </td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetPulse Pro - Network Audit Report</title>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --risk-high: #ef4444;
            --risk-med: #f59e0b;
            --risk-low: #10b981;
            --risk-safe: #3b82f6;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}

        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}

        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}

        .logo {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .logo-icon {{
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            width: 44px;
            height: 44px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 22px;
            color: #fff;
        }}

        .title {{
            font-size: 24px;
            font-weight: 700;
            margin: 0;
        }}

        .subtitle {{
            color: var(--text-muted);
            font-size: 14px;
            margin-top: 4px;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}

        .stat-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }}

        .stat-label {{
            color: var(--text-muted);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .stat-value {{
            font-size: 32px;
            font-weight: 700;
            margin-top: 8px;
            color: var(--accent-cyan);
        }}

        .stat-value.high {{ color: var(--risk-high); }}
        .stat-value.med {{ color: var(--risk-med); }}
        .stat-value.safe {{ color: var(--risk-low); }}

        /* Filter Controls */
        .controls {{
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}

        .search-box {{
            flex: 1;
            min-width: 280px;
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background-color: var(--card-bg);
            color: var(--text-main);
            font-size: 14px;
        }}

        .filter-btn {{
            padding: 10px 18px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background-color: var(--card-bg);
            color: var(--text-main);
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }}

        .filter-btn.active, .filter-btn:hover {{
            background-color: var(--accent-blue);
            border-color: var(--accent-blue);
        }}

        /* Table */
        .table-container {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 14px;
        }}

        th {{
            background-color: #0f172a;
            padding: 14px 16px;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
        }}

        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
        }}

        tr.host-row:hover {{
            background-color: #273549;
            cursor: pointer;
        }}

        .ip-address {{
            font-family: monospace;
            color: var(--accent-cyan);
            font-weight: bold;
        }}

        code {{
            font-family: monospace;
            background-color: #0f172a;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
        }}

        .badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }}

        .badge-high {{ background-color: rgba(239, 68, 68, 0.2); color: var(--risk-high); border: 1px solid var(--risk-high); }}
        .badge-medium {{ background-color: rgba(245, 158, 11, 0.2); color: var(--risk-med); border: 1px solid var(--risk-med); }}
        .badge-low {{ background-color: rgba(16, 185, 129, 0.2); color: var(--risk-low); border: 1px solid var(--risk-low); }}
        .badge-safe {{ background-color: rgba(59, 130, 246, 0.2); color: var(--risk-safe); border: 1px solid var(--risk-safe); }}

        .latency {{
            font-size: 12px;
            color: var(--text-muted);
        }}

        .details-row {{
            display: none;
            background-color: #172033;
        }}

        .details-row.active {{
            display: table-row;
        }}

        .device-details {{
            padding: 12px 20px;
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.6;
        }}

        .footer {{
            margin-top: 36px;
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">
                <div class="logo-icon">NP</div>
                <div>
                    <h1 class="title">NetPulse Pro - Network Scan Report</h1>
                    <div class="subtitle">Scan Target: <strong>{scan_range}</strong> | Generated on: <strong>{timestamp}</strong></div>
                </div>
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Active Devices</div>
                <div class="stat-value">{total_hosts}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Open Network Ports</div>
                <div class="stat-value">{total_ports}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High Risk Alerts</div>
                <div class="stat-value high">{high_risk}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium Risk Alerts</div>
                <div class="stat-value med">{medium_risk}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Hardware Vendors</div>
                <div class="stat-value">{unique_vendors}</div>
            </div>
        </div>

        <!-- Controls -->
        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search by IP, Hostname, MAC address, or Vendor..." onkeyup="filterTable()">
            <button class="filter-btn active" onclick="setRiskFilter('all', this)">All ({total_hosts})</button>
            <button class="filter-btn" onclick="setRiskFilter('high', this)">High Risk ({high_risk})</button>
            <button class="filter-btn" onclick="setRiskFilter('medium', this)">Medium Risk ({medium_risk})</button>
            <button class="filter-btn" onclick="setRiskFilter('safe', this)">Safe / Low ({safe_hosts})</button>
        </div>

        <!-- Table -->
        <div class="table-container">
            <table id="deviceTable">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>MAC Address</th>
                        <th>Vendor</th>
                        <th>Security Risk</th>
                        <th>Open Ports</th>
                        <th>Latency</th>
                    </tr>
                </thead>
                <tbody>
                    {host_rows_html}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by <strong>NetPulse Pro</strong> Network Scanner & Auditor &bull; Confidential
        </div>
    </div>

    <script>
        let currentRisk = 'all';

        function setRiskFilter(risk, btn) {{
            currentRisk = risk;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterTable();
        }}

        function filterTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('#deviceTable tbody tr.host-row');

            rows.forEach(row => {{
                const searchData = row.getAttribute('data-search').toLowerCase();
                const riskData = row.getAttribute('data-risk');
                const nextRow = row.nextElementSibling;

                const matchesSearch = searchData.includes(query);
                let matchesRisk = true;

                if (currentRisk === 'high') matchesRisk = (riskData === 'high');
                else if (currentRisk === 'medium') matchesRisk = (riskData === 'medium');
                else if (currentRisk === 'safe') matchesRisk = (riskData === 'safe' || riskData === 'low');

                if (matchesSearch && matchesRisk) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                    if (nextRow && nextRow.classList.contains('details-row')) {{
                        nextRow.classList.remove('active');
                    }}
                }}
            }});
        }}

        // Toggle details row on click
        document.querySelectorAll('#deviceTable tbody tr.host-row').forEach(row => {{
            row.addEventListener('click', () => {{
                const detailsRow = row.nextElementSibling;
                if (detailsRow && detailsRow.classList.contains('details-row')) {{
                    detailsRow.classList.toggle('active');
                }}
            }});
        }});
    </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return os.path.abspath(output_path)

    @staticmethod
    def generate_csv_report(hosts: List[Dict], output_path: str = "netpulse_scan_report.csv") -> str:
        """Generates a CSV export of host details."""
        fieldnames = ["IP Address", "Hostname", "MAC Address", "Vendor", "Device Type", "Risk Level", "Latency (ms)", "Open Ports Count", "Open Ports List"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(fieldnames)

            for h in hosts:
                ports = ", ".join([f"{p['port']}:{p['service']}" for p in h.get("open_ports", [])])
                writer.writerow([
                    h.get("ip"),
                    h.get("hostname"),
                    h.get("mac"),
                    h.get("vendor"),
                    h.get("device_type"),
                    h.get("risk_score"),
                    h.get("latency_ms"),
                    len(h.get("open_ports", [])),
                    ports
                ])

        return os.path.abspath(output_path)

    @staticmethod
    def generate_json_report(hosts: List[Dict], scan_range: str, output_path: str = "netpulse_scan_report.json") -> str:
        """Generates a JSON export of the scan results."""
        data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_range": scan_range,
            "total_hosts": len(hosts),
            "hosts": hosts
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return os.path.abspath(output_path)
