import os
import re
import json
import time
import platform
import subprocess
import logging
from typing import List, Dict, Any, Optional, Set
from ctem_agent.client import CtemClient

logger = logging.getLogger("ctem_agent.monitors.peripherals")


class PeripheralMonitor:
    def __init__(self, client: CtemClient, asset_id: Optional[str] = None):
        self.client = client
        self.asset_id = asset_id
        self.known_serials: Set[str] = set()
        self.first_run = True

    def set_asset_id(self, asset_id: str):
        self.asset_id = asset_id

    def scan_usb_devices(self) -> List[Dict[str, str]]:
        """Scans attached USB devices and retrieves their serial numbers."""
        devices = []
        os_name = platform.system()

        if os_name == "Linux":
            devices = self._scan_linux()
        elif os_name == "Darwin":
            devices = self._scan_macos()
        elif os_name == "Windows":
            devices = self._scan_windows()

        return devices

    def _scan_linux(self) -> List[Dict[str, str]]:
        devices = []
        base_dir = "/sys/bus/usb/devices"
        if not os.path.exists(base_dir):
            return devices

        try:
            for item in os.listdir(base_dir):
                dev_dir = os.path.join(base_dir, item)
                serial_file = os.path.join(dev_dir, "serial")
                product_file = os.path.join(dev_dir, "product")
                vendor_file = os.path.join(dev_dir, "idVendor")

                if os.path.exists(serial_file):
                    try:
                        with open(serial_file, "r") as sf:
                            serial = sf.read().strip()
                        product = "USB Device"
                        if os.path.exists(product_file):
                            with open(product_file, "r") as pf:
                                product = pf.read().strip()
                        vendor = ""
                        if os.path.exists(vendor_file):
                            with open(vendor_file, "r") as vf:
                                vendor = vf.read().strip()

                        if serial:
                            devices.append({"serial": serial, "product": product, "vendor": vendor})
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Linux USB scan error: {e}")

        return devices

    def _scan_macos(self) -> List[Dict[str, str]]:
        devices = []
        try:
            out = subprocess.check_output(["system_profiler", "SPUSBDataType", "-json"], text=True)
            data = json.loads(out)
            usb_items = data.get("SPUSBDataType", [])

            def extract_serials(items):
                for item in items:
                    serial = item.get("serial_num")
                    name = item.get("_name", "USB Device")
                    if serial:
                        devices.append({"serial": serial.strip(), "product": name, "vendor": item.get("vendor_id", "")})
                    if "_items" in item:
                        extract_serials(item["_items"])

            extract_serials(usb_items)
        except Exception as e:
            logger.debug(f"macOS USB scan error: {e}")
        return devices

    def _scan_windows(self) -> List[Dict[str, str]]:
        devices = []
        try:
            cmd = "Get-CimInstance Win32_USBControllerDevice | ForEach-Object { [wmi]($_.Dependent) } | Select-Object DeviceID, Name | ConvertTo-Json"
            out = subprocess.check_output(["powershell", "-Command", cmd], text=True)
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for dev in parsed:
                dev_id = dev.get("DeviceID", "")
                if "USB\\VID_" in dev_id:
                    parts = dev_id.split("\\")
                    serial = parts[-1] if len(parts) > 2 else dev_id
                    devices.append({"serial": serial, "product": dev.get("Name", "USB Device")})
        except Exception as e:
            logger.debug(f"Windows USB scan error: {e}")
        return devices

    def check_devices(self) -> List[Dict[str, str]]:
        """
        Detects newly attached hardware and verifies authorization with CTEM.
        """
        current_devices = self.scan_usb_devices()
        current_serials = {d["serial"]: d for d in current_devices if d.get("serial")}

        if self.first_run:
            self.known_serials = set(current_serials.keys())
            self.first_run = False
            logger.info(f"Initialized USB peripheral baseline: {len(self.known_serials)} devices")
            return current_devices

        # Check for newly inserted devices
        for serial, dev in current_serials.items():
            if serial not in self.known_serials:
                product_name = dev.get("product", "External USB Device")
                logger.info(f"New peripheral plugged in: {product_name} (Serial: {serial})")

                # Verify against CTEM allowlist
                is_authorized = self.client.check_peripheral(serial_number=serial)
                if is_authorized:
                    logger.info(f"[PERIPHERAL AUTHORIZED] Device approved by CTEM: {serial}")
                else:
                    summary = f"Unauthorized peripheral device detected: {product_name} (Serial: {serial})"
                    logger.warning(f"[UNAUTHORIZED HARDWARE] {summary}")
                    self.client.send_log_event(
                        event_type="peripheral_unauthorized",
                        severity="high",
                        summary=summary,
                        asset_id=self.asset_id,
                        source="ctem_agent_peripherals",
                    )

        self.known_serials = set(current_serials.keys())
        return current_devices
