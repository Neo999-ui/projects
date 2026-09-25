"""
NetPulse Pro - Core Scanning Engine
Handles network auto-detection, host discovery, port scanning, MAC vendor lookup, and security risk auditing.
"""

import socket
import subprocess
import threading
import concurrent.futures
import re
import os
import platform
import time
from typing import List, Dict, Tuple, Optional, Callable

# ============================================================================
# MAC VENDOR DATABASE (OUI Lookups)
# ============================================================================
OUI_DATABASE = {
    # Apple
    "00:03:93": "Apple, Inc.", "00:05:02": "Apple, Inc.", "00:0A:27": "Apple, Inc.",
    "00:0D:93": "Apple, Inc.", "00:10:FA": "Apple, Inc.", "00:11:24": "Apple, Inc.",
    "00:14:51": "Apple, Inc.", "00:16:CB": "Apple, Inc.", "00:17:F2": "Apple, Inc.",
    "00:1C:B3": "Apple, Inc.", "00:1D:4F": "Apple, Inc.", "00:1E:52": "Apple, Inc.",
    "00:1F:5B": "Apple, Inc.", "00:1F:F3": "Apple, Inc.", "00:21:E9": "Apple, Inc.",
    "00:22:41": "Apple, Inc.", "00:23:12": "Apple, Inc.", "00:23:32": "Apple, Inc.",
    "00:23:6C": "Apple, Inc.", "00:24:36": "Apple, Inc.", "00:25:00": "Apple, Inc.",
    "00:25:4B": "Apple, Inc.", "00:26:08": "Apple, Inc.", "00:26:4A": "Apple, Inc.",
    "00:26:B0": "Apple, Inc.", "00:26:BB": "Apple, Inc.", "28:CF:DA": "Apple, Inc.",
    "3C:D0:F8": "Apple, Inc.", "40:3C:FC": "Apple, Inc.", "40:6C:8F": "Apple, Inc.",
    "48:43:7C": "Apple, Inc.", "54:26:96": "Apple, Inc.", "60:F8:1D": "Apple, Inc.",
    "70:56:81": "Apple, Inc.", "70:A2:B3": "Apple, Inc.", "74:8D:08": "Apple, Inc.",
    "78:CA:39": "Apple, Inc.", "80:E6:50": "Apple, Inc.", "84:FC:AC": "Apple, Inc.",
    "88:66:5D": "Apple, Inc.", "94:10:3E": "Apple, Inc.", "A4:5E:60": "Apple, Inc.",
    "AC:BC:B3": "Apple, Inc.", "B8:E8:56": "Apple, Inc.", "BC:52:B7": "Apple, Inc.",
    "C0:CC:25": "Apple, Inc.", "DC:A9:04": "Apple, Inc.", "E4:CE:8F": "Apple, Inc.",
    "F0:99:BF": "Apple, Inc.", "F4:0F:24": "Apple, Inc.", "F4:5C:89": "Apple, Inc.",

    # Samsung
    "00:00:F0": "Samsung Electronics", "00:02:78": "Samsung Electronics", "00:07:AB": "Samsung Electronics",
    "00:09:B8": "Samsung Electronics", "00:0D:AE": "Samsung Electronics", "00:12:47": "Samsung Electronics",
    "00:13:77": "Samsung Electronics", "00:15:99": "Samsung Electronics", "00:16:32": "Samsung Electronics",
    "00:17:C9": "Samsung Electronics", "00:18:AF": "Samsung Electronics", "00:1B:98": "Samsung Electronics",
    "00:1C:43": "Samsung Electronics", "00:1D:25": "Samsung Electronics", "00:1E:E1": "Samsung Electronics",
    "00:1F:CC": "Samsung Electronics", "00:21:19": "Samsung Electronics", "00:21:4C": "Samsung Electronics",
    "00:23:D7": "Samsung Electronics", "00:24:54": "Samsung Electronics", "00:25:67": "Samsung Electronics",
    "00:26:7D": "Samsung Electronics", "50:01:D9": "Samsung Electronics", "50:B7:C3": "Samsung Electronics",
    "84:25:DB": "Samsung Electronics", "88:32:9B": "Samsung Electronics", "A8:06:00": "Samsung Electronics",
    "C0:BD:D1": "Samsung Electronics", "CC:F4:11": "Samsung Electronics", "E4:B0:21": "Samsung Electronics",

    # Intel
    "00:02:B3": "Intel Corporation", "00:03:47": "Intel Corporation", "00:04:23": "Intel Corporation",
    "00:0E:0C": "Intel Corporation", "00:11:11": "Intel Corporation", "00:13:02": "Intel Corporation",
    "00:13:20": "Intel Corporation", "00:13:CE": "Intel Corporation", "00:15:00": "Intel Corporation",
    "00:16:EA": "Intel Corporation", "00:18:DE": "Intel Corporation", "00:19:D2": "Intel Corporation",
    "00:1B:21": "Intel Corporation", "00:1C:C0": "Intel Corporation", "00:1D:E0": "Intel Corporation",
    "00:1E:64": "Intel Corporation", "00:1F:3C": "Intel Corporation", "00:21:6A": "Intel Corporation",
    "00:22:FB": "Intel Corporation", "00:23:14": "Intel Corporation", "00:24:D7": "Intel Corporation",
    "00:26:C7": "Intel Corporation", "3C:97:0E": "Intel Corporation", "48:51:B7": "Intel Corporation",
    "60:57:18": "Intel Corporation", "7C:5C:F8": "Intel Corporation", "80:86:F2": "Intel Corporation",
    "A0:36:9F": "Intel Corporation", "C8:5B:76": "Intel Corporation", "DC:53:7C": "Intel Corporation",

    # Cisco & Linksys
    "00:00:0C": "Cisco Systems", "00:01:42": "Cisco Systems", "00:01:43": "Cisco Systems",
    "00:01:63": "Cisco Systems", "00:01:96": "Cisco Systems", "00:01:97": "Cisco Systems",
    "00:02:16": "Cisco Systems", "00:02:17": "Cisco Systems", "00:02:4A": "Cisco Systems",
    "00:02:7D": "Cisco Systems", "00:02:7E": "Cisco Systems", "00:02:FC": "Cisco Systems",
    "00:03:31": "Cisco Systems", "00:03:6B": "Cisco Systems", "00:03:E3": "Cisco Systems",
    "00:0F:66": "Cisco-Linksys", "00:12:17": "Cisco-Linksys", "00:13:10": "Cisco-Linksys",
    "00:14:BF": "Cisco-Linksys", "00:16:B6": "Cisco-Linksys", "00:18:39": "Cisco-Linksys",
    "00:1A:70": "Cisco-Linksys", "00:1C:10": "Cisco-Linksys", "00:1D:7E": "Cisco-Linksys",

    # TP-Link
    "00:19:E0": "TP-Link Technologies", "00:1D:0F": "TP-Link Technologies", "00:21:27": "TP-Link Technologies",
    "00:23:CD": "TP-Link Technologies", "00:25:86": "TP-Link Technologies", "00:27:19": "TP-Link Technologies",
    "14:CC:20": "TP-Link Technologies", "18:A6:F7": "TP-Link Technologies", "30:B5:C2": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies", "60:32:B1": "TP-Link Technologies", "64:66:B3": "TP-Link Technologies",
    "70:4F:57": "TP-Link Technologies", "74:DA:38": "TP-Link Technologies", "78:44:76": "TP-Link Technologies",
    "84:16:F9": "TP-Link Technologies", "84:C9:B2": "TP-Link Technologies", "8C:21:0A": "TP-Link Technologies",
    "98:DA:C4": "TP-Link Technologies", "A0:F3:C1": "TP-Link Technologies", "B0:48:7A": "TP-Link Technologies",
    "C0:25:E9": "TP-Link Technologies", "C4:6E:1F": "TP-Link Technologies", "D8:07:B6": "TP-Link Technologies",
    "E8:94:F6": "TP-Link Technologies", "EC:08:6B": "TP-Link Technologies", "F8:1A:67": "TP-Link Technologies",

    # Netgear
    "00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear", "00:18:4D": "Netgear",
    "00:1B:2F": "Netgear", "00:1E:2A": "Netgear", "00:1F:33": "Netgear", "00:22:3F": "Netgear",
    "00:24:B2": "Netgear", "00:26:F2": "Netgear", "20:4E:7F": "Netgear", "28:C6:8E": "Netgear",
    "4C:60:DE": "Netgear", "84:1B:5E": "Netgear", "9C:3D:CF": "Netgear", "A0:04:60": "Netgear",
    "B0:7F:B9": "Netgear", "C0:3F:0E": "Netgear", "CC:40:D0": "Netgear", "E0:46:9A": "Netgear",

    # Raspberry Pi Foundation
    "28:CD:C1": "Raspberry Pi Trading", "B8:27:EB": "Raspberry Pi Foundation",
    "D8:3A:DD": "Raspberry Pi Trading", "E4:5F:01": "Raspberry Pi Trading",
    "DC:A6:32": "Raspberry Pi Trading",

    # Amazon / Eero
    "00:FC:8B": "Amazon Technologies", "0C:47:C9": "Amazon Technologies", "18:74:2E": "Amazon Technologies",
    "34:D2:70": "Amazon Technologies", "38:F7:3D": "Amazon Technologies", "40:B4:CD": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies", "50:F5:DA": "Amazon Technologies", "68:37:E9": "Amazon Technologies",
    "74:C2:46": "Amazon Technologies", "AC:63:BE": "Amazon Technologies", "FC:A1:83": "Amazon Technologies",

    # ASUS
    "00:0E:A6": "ASUSTek Computer", "00:11:D8": "ASUSTek Computer", "00:13:D4": "ASUSTek Computer",
    "00:15:F2": "ASUSTek Computer", "00:17:31": "ASUSTek Computer", "00:18:F3": "ASUSTek Computer",
    "00:1B:FC": "ASUSTek Computer", "00:1D:60": "ASUSTek Computer", "00:1E:8C": "ASUSTek Computer",
    "08:60:6E": "ASUSTek Computer", "10:BF:48": "ASUSTek Computer", "1C:87:2C": "ASUSTek Computer",
    "2C:4D:54": "ASUSTek Computer", "30:85:A9": "ASUSTek Computer", "50:46:5D": "ASUSTek Computer",
    "70:8BCD": "ASUSTek Computer", "90:E6:BA": "ASUSTek Computer", "AC:9E:17": "ASUSTek Computer",

    # Espressif (ESP8266 / ESP32 IoT devices)
    "18:FE:34": "Espressif Inc.", "24:0A:C4": "Espressif Inc.", "24:62:AB": "Espressif Inc.",
    "24:B2:DE": "Espressif Inc.", "30:AE:A4": "Espressif Inc.", "34:85:18": "Espressif Inc.",
    "40:22:D8": "Espressif Inc.", "48:3F:DA": "Espressif Inc.", "54:5A:A6": "Espressif Inc.",
    "60:01:94": "Espressif Inc.", "68:C6:3A": "Espressif Inc.", "84:F3:EB": "Espressif Inc.",
    "8C:AA:B5": "Espressif Inc.", "A4:CF:12": "Espressif Inc.", "BC:DD:C2": "Espressif Inc.",
    "CC:50:E3": "Espressif Inc.", "DC:4F:22": "Espressif Inc.", "EC:FA:BC": "Espressif Inc.",

    # Microsoft
    "00:03:FF": "Microsoft Corporation", "00:0D:3A": "Microsoft Corporation", "00:12:5A": "Microsoft Corporation",
    "00:15:5D": "Microsoft Corporation (Hyper-V)", "00:17:FA": "Microsoft Corporation",
    "00:1D:D8": "Microsoft Corporation", "00:22:48": "Microsoft Corporation", "00:25:AE": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation", "60:45:BD": "Microsoft Corporation", "7C:ED:8D": "Microsoft Corporation",
    "DC:B4:C4": "Microsoft Corporation", "E0:D5:5E": "Microsoft Corporation",

    # Sony, Dell, HP, LG, Xiaomi, Realtek, Huawei, Google
    "00:01:4A": "Sony Corporation", "00:04:13": "Sony Corporation", "00:13:A9": "Sony Corporation",
    "00:14:A4": "Sony Corporation", "00:1A:80": "Sony Corporation", "00:1D:BA": "Sony Corporation",
    "00:06:5B": "Dell Inc.", "00:08:74": "Dell Inc.", "00:0B:DB": "Dell Inc.", "00:11:43": "Dell Inc.",
    "00:12:79": "Dell Inc.", "00:13:72": "Dell Inc.", "00:14:22": "Dell Inc.", "00:15:C5": "Dell Inc.",
    "00:01:E6": "Hewlett-Packard", "00:02:A5": "Hewlett-Packard", "00:04:EA": "Hewlett-Packard",
    "00:08:02": "Hewlett-Packard", "00:0E:7F": "Hewlett-Packard", "00:0F:20": "Hewlett-Packard",
    "00:05:78": "LG Electronics", "00:0B:E1": "LG Electronics", "00:12:56": "LG Electronics",
    "00:1C:62": "LG Electronics", "00:1E:B2": "LG Electronics", "00:1F:E3": "LG Electronics",
    "00:1A:11": "Google LLC", "3C:5A:B4": "Google LLC", "54:60:09": "Google LLC", "70:3E:AC": "Google LLC",
    "94:EB:CD": "Google LLC", "A4:77:33": "Google LLC", "F8:8F:CA": "Google LLC",
    "00:07:61": "Logitech", "00:1F:20": "Logitech", "00:04:4B": "NVIDIA Corporation",
    "00:04:0E": "AVM GmbH (Fritz!Box)", "00:1C:4A": "AVM GmbH (Fritz!Box)",
    "00:05:5D": "D-Link Corporation", "00:0D:88": "D-Link Corporation", "00:0F:3D": "D-Link Corporation",
}


class MacVendorLookup:
    """Provides MAC address vendor lookup from embedded OUI database."""

    @staticmethod
    def format_mac(mac: str) -> str:
        """Standardizes MAC address format to XX:YY:ZZ:AA:BB:CC."""
        if not mac:
            return ""
        clean = re.sub(r'[^a-fA-F0-9]', '', mac).upper()
        if len(clean) == 12:
            return ":".join(clean[i:i+2] for i in range(0, 12, 2))
        return mac.upper()

    @classmethod
    def lookup(cls, mac: str) -> str:
        """Looks up the vendor name for a given MAC address."""
        formatted = cls.format_mac(mac)
        if not formatted or len(formatted) < 8:
            return "Unknown Vendor"
        prefix = formatted[:8]  # First 3 bytes: XX:YY:ZZ
        return OUI_DATABASE.get(prefix, "Unknown / Generic Vendor")


# ============================================================================
# NETWORK UTILITIES
# ============================================================================
class NetworkUtils:
    """Provides network adapter and IP calculation helper utilities."""

    @staticmethod
    def get_local_ip() -> str:
        """Gets the primary local IP address of this computer."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(0.5)
                # Connect to non-routable IP to force socket binding to primary adapter
                s.connect(("10.255.255.255", 1))
                return s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    @staticmethod
    def get_default_gateway() -> str:
        """Attempts to discover default gateway IP."""
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output("ipconfig", text=True, errors="replace")
                match = re.search(r"Default Gateway[.\s]*:[ \t]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", output)
                if match:
                    return match.group(1)
            else:
                output = subprocess.check_output("netstat -rn", shell=True, text=True, errors="replace")
                match = re.search(r"(0\.0\.0\.0|default)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", output)
                if match:
                    return match.group(2)
        except Exception:
            pass
        
        # Fallback heuristic: replace last octet of local IP with .1
        local_ip = NetworkUtils.get_local_ip()
        parts = local_ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        return "192.168.1.1"

    @staticmethod
    def get_default_subnet() -> str:
        """Calculates default CIDR subnet (e.g. 192.168.1.0/24) based on local IP."""
        local_ip = NetworkUtils.get_local_ip()
        parts = local_ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "192.168.1.0/24"

    @staticmethod
    def expand_ip_range(target: str) -> List[str]:
        """
        Expands CIDR notation (192.168.1.0/24), single IP (192.168.1.10),
        or range string (192.168.1.1-192.168.1.5 or 192.168.1.1-50) into a list of IP strings.
        """
        target = target.strip()
        if not target:
            target = NetworkUtils.get_default_subnet()

        # Single IP
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return [target]

        # Full IP Range: 192.168.1.1-192.168.1.50
        full_range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})$", target)
        if full_range_match:
            base = full_range_match.group(1)
            start_num = int(full_range_match.group(2))
            end_num = int(full_range_match.group(3))
            if start_num <= end_num:
                return [f"{base}{i}" for i in range(start_num, end_num + 1)]

        # Short Range: 192.168.1.1-50
        short_range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
        if short_range_match:
            base = short_range_match.group(1)
            start_num = int(short_range_match.group(2))
            end_num = int(short_range_match.group(3))
            if start_num <= end_num:
                return [f"{base}{i}" for i in range(start_num, end_num + 1)]

        # CIDR notation: 192.168.1.0/24
        if "/" in target:
            try:
                base_ip, prefix = target.split("/")
                prefix_num = int(prefix)
                ip_parts = [int(p) for p in base_ip.split(".")]
                if len(ip_parts) == 4 and prefix_num == 24:
                    prefix_str = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                    return [f"{prefix_str}.{i}" for i in range(1, 255)]
                elif len(ip_parts) == 4 and prefix_num == 16:
                    prefix_str = f"{ip_parts[0]}.{ip_parts[1]}"
                    return [f"{prefix_str}.0.{i}" for i in range(1, 255)]
            except Exception:
                pass

        # Fallback to default subnet range /24
        local_ip = NetworkUtils.get_local_ip()
        parts = local_ip.split(".")
        return [f"{parts[0]}.{parts[1]}.{parts[2]}.{i}" for i in range(1, 255)]


# ============================================================================
# HOST DISCOVERY ENGINE
# ============================================================================
class HostDiscoveryScanner:
    """Multi-threaded host discovery combining Ping, ARP, NetBIOS, and reverse DNS."""

    @staticmethod
    def get_arp_cache() -> Dict[str, str]:
        """Executes system `arp -a` command and parses IP -> MAC mappings."""
        arp_map = {}
        try:
            cmd = "arp -a"
            output = subprocess.check_output(cmd, shell=True, text=True, errors="replace")
            matches = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2})", output, re.IGNORECASE)
            for ip, mac in matches:
                clean_mac = MacVendorLookup.format_mac(mac)
                arp_map[ip] = clean_mac
        except Exception:
            pass
        return arp_map

    @staticmethod
    def ping_host(ip: str, timeout: float = 0.8) -> Tuple[bool, float]:
        """Pings host via system ping process. Returns (is_alive, response_time_ms)."""
        system = platform.system().lower()
        if system == "windows":
            timeout_ms = int(timeout * 1000)
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

        start_time = time.time()
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", timeout=timeout + 0.5)
            rtt = (time.time() - start_time) * 1000
            if res.returncode == 0:
                match = re.search(r"time[=<]\s*(\d+(\.\d+)?)ms", res.stdout, re.IGNORECASE)
                if match:
                    rtt = float(match.group(1))
                return True, round(rtt, 1)
        except Exception:
            pass
        return False, 0.0

    @staticmethod
    def tcp_probe(ip: str, ports: List[int] = [80, 443, 445, 135, 22, 8080], timeout: float = 0.6) -> bool:
        """Attempts TCP connect on common ports to detect hosts blocking ICMP pings."""
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return True
            except Exception:
                pass
            finally:
                sock.close()
        return False

    @staticmethod
    def query_netbios(ip: str, timeout: float = 0.6) -> Optional[str]:
        """Sends NetBIOS Name Service Status Request (UDP 137) to get Windows Computer Name."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            payload = (
                b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41"
                b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
            )
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, 137))
            data, _ = sock.recvfrom(1024)

            if len(data) > 57:
                num_names = data[56]
                if num_names > 0:
                    name_bytes = data[57:57 + 15]
                    name = name_bytes.decode('ascii', errors='ignore').strip()
                    if name:
                        return name
        except Exception:
            pass
        finally:
            sock.close()
        return None

    @staticmethod
    def reverse_dns(ip: str) -> str:
        """Performs reverse DNS lookup to obtain hostname."""
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return ""

    @classmethod
    def probe_single_host(cls, ip: str, arp_map: Dict[str, str], local_ip: str, gateway_ip: str) -> Optional[Dict]:
        """Probes a single IP for activity and gathers metadata."""
        is_local = (ip == local_ip)
        is_alive = is_local

        rtt = 0.0
        if is_local:
            rtt = 0.1
        else:
            is_alive, rtt = cls.ping_host(ip)
            if not is_alive:
                is_alive = cls.tcp_probe(ip)

        if not is_alive and ip not in arp_map:
            return None

        # Gather Hostname & NetBIOS Name
        hostname = ""
        netbios_name = cls.query_netbios(ip)
        if netbios_name:
            hostname = netbios_name
        else:
            rdns = cls.reverse_dns(ip)
            if rdns:
                hostname = rdns

        # Resolve MAC Address & Vendor
        mac = arp_map.get(ip, "Unknown")
        if is_local:
            mac = "Local Interface"
            vendor = "Local Device"
            if not hostname:
                hostname = socket.gethostname()
        elif ip == gateway_ip:
            vendor = MacVendorLookup.lookup(mac)
            if "Gateway" not in vendor:
                vendor += " (Gateway)"
            if not hostname:
                hostname = "Router / Gateway"
        else:
            vendor = MacVendorLookup.lookup(mac)
            if not hostname:
                hostname = "Host-" + ip.split(".")[-1]

        # Classify Device Type
        device_type = "Workstation / PC"
        if ip == gateway_ip or "Router" in vendor or "Gateway" in vendor or "TP-Link" in vendor or "Netgear" in vendor:
            device_type = "Router / Network Gateway"
        elif "Apple" in vendor or "Samsung" in vendor or "Google" in vendor or "LG" in vendor:
            device_type = "Mobile / Smart Device"
        elif "Raspberry" in vendor or "Espressif" in vendor:
            device_type = "IoT / Embedded Controller"
        elif "Printer" in hostname.lower() or "Hewlett-Packard" in vendor:
            device_type = "Network Printer"

        return {
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "device_type": device_type,
            "latency_ms": rtt if rtt > 0 else 1.0,
            "status": "Online",
            "open_ports": [],
            "risk_score": "Safe",
            "risk_details": []
        }

    @classmethod
    def scan_network(cls, ip_list: List[str], progress_callback: Optional[Callable[[int, int, str], None]] = None, max_threads: int = 40) -> List[Dict]:
        """Scans a list of IPs concurrently."""
        local_ip = NetworkUtils.get_local_ip()
        gateway_ip = NetworkUtils.get_default_gateway()
        arp_map = cls.get_arp_cache()

        discovered_hosts = []
        total = len(ip_list)
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {
                executor.submit(cls.probe_single_host, ip, arp_map, local_ip, gateway_ip): ip
                for ip in ip_list
            }

            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, ip)
                try:
                    res = future.result()
                    if res:
                        discovered_hosts.append(res)
                except Exception:
                    pass

        discovered_hosts.sort(key=lambda x: [int(part) for part in x["ip"].split(".")])
        return discovered_hosts


# ============================================================================
# PORT SCANNER & SERVICE DETECTION ENGINE
# ============================================================================
COMMON_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote CLI)",
    25: "SMTP (Mail Server)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Server)",
    110: "POP3 (Email)",
    135: "MSRPC (Microsoft RPC)",
    139: "NetBIOS Session",
    143: "IMAP (Email)",
    443: "HTTPS (Secure Web Server)",
    445: "SMB (Windows File Sharing)",
    548: "AFP (Apple Filing Protocol)",
    1433: "MSSQL (Microsoft SQL Server)",
    1883: "MQTT (IoT Messaging)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis In-Memory Data Store",
    8080: "HTTP-Alt (Web Proxy / Dev Server)",
    8443: "HTTPS-Alt (Secure Web Proxy)",
    9100: "RAW Printer Port",
    27017: "MongoDB Database"
}


class PortScanner:
    """Multi-threaded port scanner and banner grabber."""

    @staticmethod
    def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
        """Attempts banner grabbing on an open port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in [80, 8080, 8000]:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")

            banner = sock.recv(256).decode('ascii', errors='ignore').strip()
            if banner:
                line = banner.splitlines()[0]
                return line[:60]
        except Exception:
            pass
        finally:
            sock.close()
        return ""

    @classmethod
    def scan_port(cls, ip: str, port: int, timeout: float = 0.8) -> Optional[Dict]:
        """Scans a single port on a target IP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, f"Custom Port {port}")
                banner = cls.grab_banner(ip, port)
                return {
                    "port": port,
                    "service": service,
                    "banner": banner
                }
        except Exception:
            pass
        finally:
            sock.close()
        return None

    @classmethod
    def scan_host_ports(cls, ip: str, port_list: Optional[List[int]] = None, max_threads: int = 20) -> List[Dict]:
        """Scans a list of ports for a single host."""
        if port_list is None:
            port_list = list(COMMON_PORTS.keys())

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(cls.scan_port, ip, port) for port in port_list]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)

        open_ports.sort(key=lambda x: x["port"])
        return open_ports


# ============================================================================
# SECURITY RISK AUDITOR
# ============================================================================
class SecurityAuditor:
    """Evaluates security vulnerabilities and assigns risk levels to hosts."""

    @staticmethod
    def audit_host(host: Dict) -> Tuple[str, List[str]]:
        """Analyzes host open ports & configuration. Returns (risk_score, risk_details_list)."""
        open_ports = [p["port"] for p in host.get("open_ports", [])]
        details = []
        high_risk_count = 0
        med_risk_count = 0

        if 23 in open_ports:
            high_risk_count += 1
            details.append("CRITICAL: Telnet (Port 23) open - plain text credentials transmitted.")
        if 21 in open_ports:
            med_risk_count += 1
            details.append("WARNING: FTP (Port 21) open - unencrypted file transfer protocol.")

        if 5900 in open_ports:
            med_risk_count += 1
            details.append("WARNING: VNC Remote Desktop (Port 5900) open - verify authentication.")
        if 3389 in open_ports:
            med_risk_count += 1
            details.append("NOTICE: RDP Remote Desktop (Port 3389) exposed to local subnet.")

        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 1433: "MSSQL"}
        for db_port, db_name in db_ports.items():
            if db_port in open_ports:
                med_risk_count += 1
                details.append(f"NOTICE: Database service {db_name} (Port {db_port}) exposed.")

        if 445 in open_ports or 139 in open_ports:
            details.append("INFO: Windows SMB File Sharing (Port 445/139) enabled.")

        if 80 in open_ports and 443 not in open_ports:
            details.append("INFO: HTTP Web Server (Port 80) without HTTPS.")

        if high_risk_count > 0 or med_risk_count >= 2:
            risk_level = "High"
        elif med_risk_count == 1:
            risk_level = "Medium"
        elif len(open_ports) > 0:
            risk_level = "Low"
        else:
            risk_level = "Safe"
            details.append("No high-risk exposed services detected.")

        return risk_level, details
