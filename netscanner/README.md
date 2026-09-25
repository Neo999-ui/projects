# ⚡ NetPulse Pro - Personal Network Scanner & Security Auditor

**NetPulse Pro** is a modern, multi-threaded Personal Network Scanner and Security Auditor written in Python. It automatically discovers active network devices on your Wi-Fi or LAN, resolves hostnames and hardware MAC vendors, performs port scanning & banner grabbing, audits security risks, alerts you to unrecognized new devices (intruder detection), and generates standalone interactive HTML, CSV, and JSON reports.

---

## 🚀 Key Features

- **🌐 Network Auto-Detection & Range Calculation**:
  - Automatically identifies your primary network adapter IP, subnet mask, default gateway, and CIDR subnet (e.g. `192.168.1.0/24`).
  - Supports scanning custom subnets, IP ranges (`192.168.1.1-50`), or single targets (`192.168.1.10`).

- **🔍 Multi-Threaded Host Discovery**:
  - **Ping Sweep & TCP Probes**: Probes hosts concurrently using system ICMP ping and non-admin TCP connect probes.
  - **Windows ARP Table Parser**: Extracts hardware MAC addresses from the ARP cache (`arp -a`).
  - **NetBIOS Name Query**: Sends UDP port 137 probes to discover Windows computer names, SMB shares, and workgroups.
  - **Reverse DNS Lookup**: Resolves hostnames via `socket.gethostbyaddr`.

- **🏭 Embedded MAC Vendor Database (OUI)**:
  - Built-in offline database mapping thousands of MAC prefixes to hardware vendors (Apple, Samsung, Intel, TP-Link, Cisco, Netgear, Raspberry Pi, Amazon, Asus, Espressif, Dell, HP, etc.).

- **🛡️ Port Scanner & Security Risk Auditor**:
  - Scans common services (HTTP, HTTPS, SSH, FTP, Telnet, SMB, RDP, VNC, MySQL, PostgreSQL, MongoDB, Redis, etc.) with banner grabbing.
  - Automatically flags security risks (e.g., exposed unencrypted Telnet/FTP, VNC/RDP exposure, database ports).

- **🚨 Intruder Detection & Scan History**:
  - Saves scan sessions to `scan_history.json`.
  - Automatically compares current scan against past scans to alert you if a **new or unrecognized device** joins your network.

- **📊 Modern Graphical UI (Tkinter)**:
  - Dark-themed dashboard with stat summary cards (Active Hosts, Open Ports, High Risks, Vendors Count).
  - Search bar & risk filtering.
  - Double-click host inspector modal to inspect open ports, banners, security recommendations, and quick launcher (`http://` in browser, Copy IP/MAC).

- **📄 Interactive HTML, CSV & JSON Reports**:
  - Export beautiful, standalone HTML dashboard reports with styled tables, risk badges, and interactive search/filter.

---

## 📦 Requirements

- **Python 3.8+** (Tested on Python 3.14 on Windows, macOS, and Linux).
- Uses **standard library** only (`tkinter`, `socket`, `threading`, `subprocess`, `json`, `csv`, `concurrent.futures`, `ipaddress`, `webbrowser`). Zero mandatory external pip dependencies required!

---

## 🛠️ Usage

### 🖥️ Graphical User Interface (GUI Mode)

Launch the application simply by running:

```bash
python main.py
```
*(or double-click `main.py`)*

#### GUI Capabilities:
1. Click **▶ Start Scan** to begin scanning your auto-detected network subnet.
2. Select scan intensity:
   - **Quick Discovery**: Fast Ping + ARP + NetBIOS sweep.
   - **Standard Audit**: Host discovery + Top 20 Ports scan.
   - **Deep Security Audit**: Host discovery + Top 100 Ports scan + Service Banners.
3. Filter results live using the search box or risk dropdown.
4. **Double-click any host row** to view the **Device Inspector Modal**.
5. Click **📄 Export HTML Report**, **CSV**, or **JSON** buttons to export reports.

---

### 💻 Command Line Interface (CLI Mode)

Run headless or automated scans directly from your terminal:

```bash
# Scan local default subnet
python main.py --target 192.168.1.0/24

# Quick scan without port scanning
python main.py --target 192.168.1.1-50 --quick

# Deep scan with full port scan and export interactive HTML report
python main.py --target 192.168.1.0/24 --deep --export-html my_network_report.html

# Export CSV and JSON reports
python main.py --target 192.168.1.0/24 --export-csv report.csv --export-json report.json
```

#### CLI Flags Reference:

| Flag | Description |
| :--- | :--- |
| `-t`, `--target` | Target CIDR range (`192.168.1.0/24`), range (`192.168.1.1-50`), or single IP (`192.168.1.10`) |
| `--quick` | Host discovery only (skips port scan) |
| `--deep` | Deep audit scanning top 100 ports & grabbing service banners |
| `--export-html [path]` | Export interactive HTML dashboard report |
| `--export-csv [path]` | Export CSV data table |
| `--export-json [path]` | Export JSON data report |

---

## 🧪 Running Automated Tests

Run the included verification test suite:

```bash
python test_scanner.py
```

---

## 📁 Project Architecture

```
The Bug Factory/
├── main.py              # Main application launcher (GUI or CLI router)
├── gui.py               # Tkinter GUI implementation (Dark Mode Dashboard)
├── cli.py               # Command Line Interface runner & console output
├── scanner_engine.py    # Core discovery, port scanner, OUI database & risk auditor
├── history_manager.py   # Scan history persistence & intruder detection diffing
├── report_generator.py  # HTML, CSV, and JSON report generation engines
├── test_scanner.py      # Automated unit test suite
└── README.md            # User documentation
```

---

## ⚖️ Disclaimer

NetPulse Pro is intended for legal personal network monitoring, security auditing, and educational use on networks you own or have explicit authorization to scan.
