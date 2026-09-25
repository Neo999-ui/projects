"""
NetPulse Pro - Verification & Unit Test Suite
Tests network utilities, scanner engine, MAC lookup, security auditor, history diffing, and report exports.
"""

import os
import sys
import unittest

from scanner_engine import NetworkUtils, MacVendorLookup, HostDiscoveryScanner, PortScanner, SecurityAuditor
from history_manager import HistoryManager
from report_generator import ReportGenerator


class TestNetPulseScanner(unittest.TestCase):
    """Test suite for NetPulse Pro functionality."""

    def test_network_utils(self):
        """Tests local IP, gateway, subnet detection, and range expansion."""
        local_ip = NetworkUtils.get_local_ip()
        self.assertIsNotNone(local_ip)
        self.assertIn(".", local_ip)

        gateway = NetworkUtils.get_default_gateway()
        self.assertIsNotNone(gateway)
        self.assertIn(".", gateway)

        subnet = NetworkUtils.get_default_subnet()
        self.assertIn("/24", subnet)

        # Expand range test
        ip_range = NetworkUtils.expand_ip_range("192.168.1.1-192.168.1.5")
        self.assertEqual(len(ip_range), 5)
        self.assertEqual(ip_range[0], "192.168.1.1")
        self.assertEqual(ip_range[-1], "192.168.1.5")

    def test_mac_vendor_lookup(self):
        """Tests MAC vendor resolution from OUI database."""
        apple_vendor = MacVendorLookup.lookup("00:03:93:11:22:33")
        self.assertIn("Apple", apple_vendor)

        rpi_vendor = MacVendorLookup.lookup("B8:27:EB:AA:BB:CC")
        self.assertIn("Raspberry Pi", rpi_vendor)

        tp_vendor = MacVendorLookup.lookup("14-CC-20-DE-AD-BE")
        self.assertIn("TP-Link", tp_vendor)

        unknown = MacVendorLookup.lookup("00:99:99:99:99:99")
        self.assertIn("Unknown", unknown)

    def test_host_discovery(self):
        """Tests single host probe against localhost (127.0.0.1)."""
        res = HostDiscoveryScanner.probe_single_host("127.0.0.1", {}, "127.0.0.1", "127.0.0.1")
        self.assertIsNotNone(res)
        self.assertEqual(res["ip"], "127.0.0.1")
        self.assertEqual(res["status"], "Online")

    def test_port_scanner_and_security_auditor(self):
        """Tests port scanning and security risk auditor."""
        sample_host = {
            "ip": "192.168.1.50",
            "hostname": "test-device",
            "mac": "00:11:22:33:44:55",
            "vendor": "Test Vendor",
            "open_ports": [
                {"port": 23, "service": "Telnet", "banner": ""},
                {"port": 80, "service": "HTTP", "banner": "Server: Apache"}
            ]
        }

        risk_level, details = SecurityAuditor.audit_host(sample_host)
        self.assertEqual(risk_level, "High")
        self.assertTrue(any("Telnet" in d for d in details))

    def test_history_manager_and_diff(self):
        """Tests history saving and intruder detection diff."""
        test_history_file = "test_scan_history.json"
        if os.path.exists(test_history_file):
            os.remove(test_history_file)

        scan_1 = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:01", "hostname": "Router", "vendor": "Cisco"}
        ]

        scan_2 = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:01", "hostname": "Router", "vendor": "Cisco"},
            {"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "Unknown-Device", "vendor": "Apple"}
        ]

        HistoryManager.save_scan(scan_1, "192.168.1.0/24", test_history_file)
        HistoryManager.save_scan(scan_2, "192.168.1.0/24", test_history_file)

        history = HistoryManager.load_history(test_history_file)
        self.assertEqual(len(history), 2)

        diff = HistoryManager.diff_scans(scan_2, scan_1)
        self.assertEqual(len(diff["new_devices"]), 1)
        self.assertEqual(diff["new_devices"][0]["ip"], "192.168.1.50")

        # Cleanup
        if os.path.exists(test_history_file):
            os.remove(test_history_file)

    def test_report_generators(self):
        """Tests HTML, CSV, and JSON report generation."""
        sample_hosts = [
            {
                "ip": "192.168.1.1",
                "hostname": "router.local",
                "mac": "00:11:22:33:44:55",
                "vendor": "TP-Link",
                "device_type": "Router / Gateway",
                "latency_ms": 1.2,
                "status": "Online",
                "risk_score": "Safe",
                "risk_details": ["Device is secure."],
                "open_ports": [{"port": 80, "service": "HTTP", "banner": ""}]
            }
        ]

        html_file = "test_report.html"
        csv_file = "test_report.csv"
        json_file = "test_report.json"

        html_path = ReportGenerator.generate_html_report(sample_hosts, "192.168.1.0/24", html_file)
        csv_path = ReportGenerator.generate_csv_report(sample_hosts, csv_file)
        json_path = ReportGenerator.generate_json_report(sample_hosts, "192.168.1.0/24", json_file)

        self.assertTrue(os.path.exists(html_path))
        self.assertTrue(os.path.exists(csv_path))
        self.assertTrue(os.path.exists(json_path))

        # Cleanup
        for path in [html_path, csv_path, json_path]:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main()
