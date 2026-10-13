import os
import re
import socket
import platform
import subprocess
import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from ctem_agent.client import CtemClient

logger = logging.getLogger("ctem_agent.monitors.ports")

# Known suspicious ports often associated with trojans, backdoors, or CTF bind shells
SUSPICIOUS_PORTS = {
    1337: "leet backdoor / bind shell",
    31337: "Back Orifice / elite backdoor",
    4444: "Metasploit default payload handler",
    5555: "Android ADB / Trojan listener",
    6200: "vsftpd backdoor trigger",
    6667: "IRC / Botnet C2 channel",
    8888: "Suspicious HTTP proxy / payload delivery",
    9999: "Urgent bind shell / abyss backdoor",
    44444: "Metasploit alternate payload port",
}

COMMON_SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3000: "react-next-frontend",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "fastapi-backend",
    8080: "http-proxy",
    8443: "https-alt",
    9090: "prometheus",
    27017: "mongodb",
}


class PortMonitor:
    def __init__(self, client: CtemClient, asset_id: Optional[str] = None):
        self.client = client
        self.asset_id = asset_id
        self.previous_ports: Dict[str, Dict[str, Any]] = {}
        self.first_run = True

    def set_asset_id(self, asset_id: str):
        self.asset_id = asset_id

    @staticmethod
    def get_service_name(port: int, proto: str = "tcp") -> str:
        if port in COMMON_SERVICE_NAMES:
            return COMMON_SERVICE_NAMES[port]
        try:
            return socket.getservbyport(port, proto)
        except Exception:
            return "unknown"

    def scan_listening_ports(self) -> List[Dict[str, Any]]:
        """
        Discovers all listening TCP ports on the local system.
        Uses psutil if available, otherwise OS-specific command line tools.
        """
        ports: Dict[str, Dict[str, Any]] = {}

        # 1. Try psutil if available
        try:
            import psutil
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == psutil.CONN_LISTEN:
                    p = conn.laddr.port
                    service = self.get_service_name(p, "tcp")
                    key = f"{p}/tcp"
                    ports[key] = {
                        "port": str(p),
                        "protocol": "tcp",
                        "service": service,
                        "ip": conn.laddr.ip,
                    }
            if ports:
                return list(ports.values())
        except Exception:
            pass

        # 2. Fallbacks based on OS
        os_name = platform.system()
        if os_name == "Linux":
            ports = self._scan_linux()
        elif os_name == "Darwin":
            ports = self._scan_macos()
        elif os_name == "Windows":
            ports = self._scan_windows()

        return list(ports.values())

    def _scan_macos(self) -> Dict[str, Dict[str, Any]]:
        ports: Dict[str, Dict[str, Any]] = {}
        try:
            out = subprocess.check_output(["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"], text=True)
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    addr_info = parts[8]
                    if ":" in addr_info:
                        port_str = addr_info.rsplit(":", 1)[1]
                        if port_str.isdigit():
                            port = int(port_str)
                            key = f"{port}/tcp"
                            ports[key] = {
                                "port": str(port),
                                "protocol": "tcp",
                                "service": self.get_service_name(port, "tcp"),
                            }
        except Exception as e:
            logger.debug(f"macOS lsof port scan error: {e}")
        return ports

    def _scan_linux(self) -> Dict[str, Dict[str, Any]]:
        ports: Dict[str, Dict[str, Any]] = {}
        # Try `ss -tln`
        try:
            out = subprocess.check_output(["ss", "-tln"], text=True)
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[3]
                    port_str = local_addr.rsplit(":", 1)[-1]
                    if port_str.isdigit():
                        port = int(port_str)
                        key = f"{port}/tcp"
                        ports[key] = {
                            "port": str(port),
                            "protocol": "tcp",
                            "service": self.get_service_name(port, "tcp"),
                        }
            if ports:
                return ports
        except Exception:
            pass

        # Parse /proc/net/tcp
        try:
            with open("/proc/net/tcp", "r") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) >= 4 and fields[3] == "0A":  # 0A = TCP_LISTEN
                        local_addr = fields[1]
                        port_hex = local_addr.split(":")[1]
                        port = int(port_hex, 16)
                        key = f"{port}/tcp"
                        ports[key] = {
                            "port": str(port),
                            "protocol": "tcp",
                            "service": self.get_service_name(port, "tcp"),
                        }
        except Exception as e:
            logger.debug(f"Linux /proc/net/tcp error: {e}")

        return ports

    def _scan_windows(self) -> Dict[str, Dict[str, Any]]:
        ports: Dict[str, Dict[str, Any]] = {}
        try:
            out = subprocess.check_output(["netstat", "-ano", "-p", "tcp"], text=True)
            for line in out.splitlines():
                if "LISTENING" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        local_addr = parts[1]
                        port_str = local_addr.rsplit(":", 1)[-1]
                        if port_str.isdigit():
                            port = int(port_str)
                            key = f"{port}/tcp"
                            ports[key] = {
                                "port": str(port),
                                "protocol": "tcp",
                                "service": self.get_service_name(port, "tcp"),
                            }
        except Exception as e:
            logger.debug(f"Windows netstat error: {e}")
        return ports

    def check_drift(self) -> List[Dict[str, Any]]:
        """
        Scans listening ports, detects any changes since last check,
        and sends security events / alerts to the CTEM platform.
        """
        current_ports_list = self.scan_listening_ports()
        current_map = {f"{p['port']}/{p['protocol']}": p for p in current_ports_list}

        if self.first_run:
            self.previous_ports = current_map
            self.first_run = False
            logger.info(f"Initial open port baseline recorded: {len(current_ports_list)} listening ports: {list(current_map.keys())}")
            return current_ports_list

        # Detect newly opened ports
        for key, p in current_map.items():
            if key not in self.previous_ports:
                port_num = int(p["port"])
                is_suspicious = port_num in SUSPICIOUS_PORTS
                severity = "high" if is_suspicious else "medium"
                extra = f" (SUSPICIOUS: {SUSPICIOUS_PORTS[port_num]})" if is_suspicious else ""

                summary = f"New listening port opened on asset: {key} ({p['service']}){extra}"
                logger.warning(f"[ATTACK SURFACE DRIFT] {summary}")

                self.client.send_log_event(
                    event_type="port_opened",
                    severity=severity,
                    summary=summary,
                    asset_id=self.asset_id,
                    source="ctem_agent_ports",
                )

        # Detect closed ports
        for key, p in self.previous_ports.items():
            if key not in current_map:
                summary = f"Listening port closed on asset: {key} ({p['service']})"
                logger.info(f"[ATTACK SURFACE DRIFT] {summary}")

                self.client.send_log_event(
                    event_type="port_closed",
                    severity="low",
                    summary=summary,
                    asset_id=self.asset_id,
                    source="ctem_agent_ports",
                )

        self.previous_ports = current_map
        return current_ports_list
