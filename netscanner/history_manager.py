"""
NetPulse Pro - History & Intrusion Alert Manager
Handles saving scan sessions to JSON and diffing scans to detect new/unrecognized network devices.
"""

import json
import os
import time
from typing import List, Dict, Tuple, Optional

HISTORY_FILE = "scan_history.json"


class HistoryManager:
    """Manages persistence and diffing of historical scan sessions."""

    @staticmethod
    def save_scan(hosts: List[Dict], scan_range: str, filepath: str = HISTORY_FILE) -> bool:
        """Saves current scan session to JSON history file."""
        try:
            history = HistoryManager.load_history(filepath)

            session = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_range": scan_range,
                "total_hosts": len(hosts),
                "hosts": hosts
            }

            history.insert(0, session)
            # Keep up to 20 historical sessions
            history = history[:20]

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving scan history: {e}")
            return False

    @staticmethod
    def load_history(filepath: str = HISTORY_FILE) -> List[Dict]:
        """Loads historical scan sessions from JSON file."""
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading scan history: {e}")
            return []

    @staticmethod
    def get_latest_previous_scan(filepath: str = HISTORY_FILE) -> Optional[Dict]:
        """Gets the most recent previous scan session."""
        history = HistoryManager.load_history(filepath)
        if len(history) >= 1:
            return history[0]
        return None

    @staticmethod
    def diff_scans(current_hosts: List[Dict], previous_hosts: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Compares current scan against a previous scan.
        Identifies:
        - new_devices: Devices present now but not in previous scan.
        - disconnected_devices: Devices in previous scan but missing now.
        - changed_devices: Devices with matching MAC but changed IP address.
        """
        # Map MACs to host objects for previous scan
        prev_mac_map = {h["mac"]: h for h in previous_hosts if h.get("mac") and h.get("mac") != "Unknown"}
        prev_ip_map = {h["ip"]: h for h in previous_hosts}

        curr_mac_map = {h["mac"]: h for h in current_hosts if h.get("mac") and h.get("mac") != "Unknown"}
        curr_ip_map = {h["ip"]: h for h in current_hosts}

        new_devices = []
        disconnected_devices = []
        changed_devices = []

        # Find New & Changed Devices
        for curr_host in current_hosts:
            mac = curr_host.get("mac")
            ip = curr_host.get("ip")

            if mac and mac != "Unknown" and mac in prev_mac_map:
                prev_host = prev_mac_map[mac]
                if prev_host["ip"] != ip:
                    changed_devices.append({
                        "device": curr_host,
                        "old_ip": prev_host["ip"],
                        "new_ip": ip
                    })
            elif ip not in prev_ip_map:
                new_devices.append(curr_host)

        # Find Disconnected Devices
        for prev_host in previous_hosts:
            mac = prev_host.get("mac")
            ip = prev_host.get("ip")

            if mac and mac != "Unknown":
                if mac not in curr_mac_map:
                    disconnected_devices.append(prev_host)
            else:
                if ip not in curr_ip_map:
                    disconnected_devices.append(prev_host)

        return {
            "new_devices": new_devices,
            "disconnected_devices": disconnected_devices,
            "changed_devices": changed_devices
        }
