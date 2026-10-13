#!/usr/bin/env python3
"""
CTEM Peripheral Enforcement Agent (Linux)
=========================================
Monitors USB device plug-in events, queries the CTEM Peripheral Allowlist API,
and physically blocks unauthorized devices by disabling their kernel authorization.

Usage:
  sudo python3 peripheral_blocker.py http://<CTEM_SERVER_IP>:8000

Can also be invoked via udev rule:
  ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/bin/python3 /path/to/peripheral_blocker.py http://<CTEM_SERVER_IP>:8000 --device %p"
"""

import os
import sys
import json
import time
import urllib.request
import subprocess

def check_ctem_authorization(api_base, serial_number):
    endpoint = f"{api_base.rstrip('/')}/peripherals/check"
    payload = {"serial_number": serial_number}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode())
            return result.get("result") == "authorized"
    except Exception as err:
        print(f"[!] Warning: Could not reach CTEM ({err}). Defaulting to DENY (Zero Trust).")
        return False


def block_usb_device(devpath):
    """Disables the USB device via Linux kernel sysfs authorization control."""
    authorized_path = os.path.join("/sys", devpath.lstrip("/"), "authorized")
    if os.path.exists(authorized_path):
        try:
            with open(authorized_path, "w") as f:
                f.write("0\n")
            print(f"[BLOCKED] Hardware device at {devpath} has been disabled.")
            return True
        except PermissionError:
            print(f"[!] Root privileges required to block device at {authorized_path}")
    return False


def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 peripheral_blocker.py http://<CTEM_SERVER_IP>:8000 [--device /sys/path]")
        sys.exit(1)

    api_base = sys.argv[1]

    # Mode 1: Triggered by udev for a single device
    if "--device" in sys.argv:
        idx = sys.argv.index("--device")
        devpath = sys.argv[idx + 1]
        serial_path = os.path.join("/sys", devpath.lstrip("/"), "serial")
        serial = "UNKNOWN"
        if os.path.exists(serial_path):
            with open(serial_path) as f:
                serial = f.read().strip()

        print(f"[*] Checking device: Serial={serial}, Path={devpath}")
        if not check_ctem_authorization(api_base, serial):
            block_usb_device(devpath)
        else:
            print(f"[AUTHORIZED] Device {serial} is approved in CTEM allowlist.")
        return

    # Mode 2: Standalone daemon monitoring udev events
    print(f"[*] CTEM Peripheral Blocker running against: {api_base}")
    print("[*] Monitoring for USB connection events (Ctrl+C to quit)...")
    
    try:
        proc = subprocess.Popen(
            ["udevadm", "monitor", "--udev", "--subsystem-match=usb"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in proc.stdout:
            if "add" in line and "usb" in line:
                parts = line.strip().split()
                if len(parts) >= 4:
                    devpath = parts[3]
                    serial_file = os.path.join("/sys", devpath.lstrip("/"), "serial")
                    time.sleep(0.5) # Allow sysfs to populate
                    if os.path.exists(serial_file):
                        with open(serial_file) as sf:
                            serial = sf.read().strip()
                        print(f"[*] USB Inserted: Serial={serial}")
                        if not check_ctem_authorization(api_base, serial):
                            block_usb_device(devpath)
                        else:
                            print(f"[AUTHORIZED] Device {serial} approved.")
    except FileNotFoundError:
        print("[!] Note: 'udevadm' not available on this platform. Use udev rule on Linux endpoints.")
    except KeyboardInterrupt:
        print("\n[*] Stopped.")

if __name__ == "__main__":
    main()
