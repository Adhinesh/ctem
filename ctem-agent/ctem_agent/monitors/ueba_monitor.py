import re
import logging
from typing import Optional, Dict, Any
from ctem_agent.client import CtemClient

logger = logging.getLogger("ctem_agent.monitors.ueba")

FAILED_PATTERNS = [
    re.compile(r"Failed (?:password|publickey) for invalid user (\S+) from (\S+)"),
    re.compile(r"Failed (?:password|publickey) for (\S+) from (\S+)"),
    re.compile(r"authentication failure;.*user=(\S+).*rhost=(\S+)"),
    re.compile(r"authentication failure;.*rhost=(\S+).*user=(\S+)"),
    re.compile(r"pam_unix\(.*:auth\): authentication failure;.*user=(\S+)"),
    re.compile(r"Invalid user (\S+) from (\S+)"),
]

SUCCESS_PATTERNS = [
    re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)"),
    re.compile(r"session opened for user (\S+) by \(uid=\d+\)"),
    re.compile(r"sshd\[\d+\]: Accepted \S+ for (\S+) from (\S+)"),
]

SUDO_PATTERNS = [
    re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)"),
    re.compile(r"su\[\d+\]: Successful su for (\S+) by (\S+)"),
]


class UebaMonitor:
    def __init__(self, client: CtemClient):
        self.client = client

    def process_auth_line(self, line: str) -> bool:
        """
        Inspects an authentication log line and forwards any
        extracted login/failed login/privilege change event to CTEM UEBA engine.
        """
        line_clean = line.strip()
        if not line_clean:
            return False

        # 1. Check for Failed Logins
        for pattern in FAILED_PATTERNS:
            m = pattern.search(line_clean)
            if m:
                groups = m.groups()
                if len(groups) >= 2:
                    # Handle if first group is IP (e.g. rhost before user)
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", groups[0]):
                        source_ip = groups[0]
                        user = groups[1]
                    else:
                        user = groups[0]
                        source_ip = groups[1]
                else:
                    user = groups[0]
                    source_ip = "127.0.0.1"

                # Strip port if present in IP (e.g. 192.168.1.50:54321)
                if ":" in source_ip and not source_ip.startswith("::"):
                    source_ip = source_ip.split(":")[0]

                logger.info(f"[UEBA] Detected failed login: user={user}, ip={source_ip}")
                self.client.send_ueba_event(
                    username=user,
                    event_type="failed_login",
                    source_ip=source_ip,
                )
                return True

        # 2. Check for Successful Logins
        for pattern in SUCCESS_PATTERNS:
            m = pattern.search(line_clean)
            if m:
                groups = m.groups()
                user = groups[0]
                source_ip = groups[1] if len(groups) > 1 else "127.0.0.1"
                if ":" in source_ip and not source_ip.startswith("::"):
                    source_ip = source_ip.split(":")[0]

                logger.info(f"[UEBA] Detected successful login: user={user}, ip={source_ip}")
                self.client.send_ueba_event(
                    username=user,
                    event_type="login",
                    source_ip=source_ip,
                )
                return True

        # 3. Check for Privilege Escalation (sudo / su)
        for pattern in SUDO_PATTERNS:
            m = pattern.search(line_clean)
            if m:
                groups = m.groups()
                user = groups[0]
                cmd = groups[1] if len(groups) > 1 else "root command"
                logger.info(f"[UEBA] Detected privilege change: user={user}, command={cmd}")
                self.client.send_ueba_event(
                    username=user,
                    event_type="privilege_change",
                    source_ip="127.0.0.1",
                )
                return True

        return False
