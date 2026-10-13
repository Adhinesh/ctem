#!/usr/bin/env python3
"""
CTEM Platform - UEBA Auth Log Forwarder for Victim Machines
===========================================================
Deploy this lightweight agent script to your victim/monitored machine.
It tails /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS/Rocky)
and streams authentication events into your CTEM backend in real time.

Usage:
  sudo python3 ueba_forwarder.py http://<YOUR_CTEM_SERVER_IP>:8000
"""

import os
import re
import sys
import time
import json
import urllib.request

# Default log locations
LOG_PATHS = [
    "/var/log/auth.log",       # Debian, Ubuntu, Kali
    "/var/log/secure",         # RHEL, CentOS, Rocky, Fedora
    "/var/log/messages"
]

# Patterns for SSH & local authentication events
FAILED_PATTERNS = [
    re.compile(r"Failed (?:password|publickey) for invalid user (\S+) from (\S+)"),
    re.compile(r"Failed (?:password|publickey) for (\S+) from (\S+)"),
    re.compile(r"authentication failure;.*user=(\S+).*rhost=(\S+)"),
]

SUCCESS_PATTERNS = [
    re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)"),
    re.compile(r"session opened for user (\S+)"),
]


def find_log_file():
    for p in LOG_PATHS:
        if os.path.exists(p) and os.access(p, os.R_OK):
            return p
    return None


def send_to_ctem(api_base, username, event_type, source_ip=None):
    endpoint = f"{api_base.rstrip('/')}/ueba/events"
    payload = {
        "username": username,
        "event_type": event_type,
        "source_ip": source_ip or "127.0.0.1",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                print(f"[+] Forwarded to CTEM: {event_type} | User: {username} | IP: {source_ip}")
            else:
                print(f"[-] CTEM returned status {response.status}")
    except Exception as err:
        print(f"[!] Failed to send event to CTEM: {err}")


def tail_log(filepath):
    """Tails a file similarly to tail -F."""
    with open(filepath, "r") as f:
        # Seek to the end of the file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    if len(sys.argv) > 1:
        api_base = sys.argv[1]
    else:
        api_base = "http://localhost:8000"

    log_path = find_log_file()
    if not log_path:
        print(f"[!] Error: Could not find readable auth log file in {LOG_PATHS}")
        print("    Try running with sudo: sudo python3 ueba_forwarder.py " + api_base)
        sys.exit(1)

    print(f"[*] CTEM UEBA Forwarder started.")
    print(f"[*] Monitoring log file: {log_path}")
    print(f"[*] Target CTEM Backend: {api_base}/ueba/events")
    print("[*] Waiting for authentication events (Ctrl+C to stop)...\n")

    for line in tail_log(log_path):
        matched = False

        # Check Failed Logins
        for pattern in FAILED_PATTERNS:
            m = pattern.search(line)
            if m:
                groups = m.groups()
                user = groups[0]
                ip = groups[1] if len(groups) > 1 else None
                send_to_ctem(api_base, username=user, event_type="failed_login", source_ip=ip)
                matched = True
                break

        if matched:
            continue

        # Check Successful Logins
        for pattern in SUCCESS_PATTERNS:
            m = pattern.search(line)
            if m:
                groups = m.groups()
                user = groups[0]
                ip = groups[1] if len(groups) > 1 else None
                send_to_ctem(api_base, username=user, event_type="login", source_ip=ip)
                break


if __name__ == "__main__":
    main()
