import os
import platform
import subprocess
import logging
from typing import List, Dict, Any, Optional, Set
from ctem_agent.client import CtemClient

logger = logging.getLogger("ctem_agent.monitors.process")

# Threat binaries commonly used for intrusion, pivoting, or mining
THREAT_BINARIES = {
    "nc": ("netcat reverse shell utility", "high"),
    "netcat": ("netcat reverse shell utility", "high"),
    "ncat": ("ncat network pipe utility", "high"),
    "socat": ("socat bidirectional relay", "high"),
    "hydra": ("hydra network login brute-forcing tool", "high"),
    "medusa": ("medusa brute-forcing tool", "high"),
    "mimikatz": ("mimikatz credential extraction tool", "critical"),
    "chisel": ("chisel TCP/UDP tunnel utility", "high"),
    "xmrig": ("xmrig cryptocurrency miner", "high"),
    "minerd": ("minerd cryptocurrency miner", "high"),
    "msfconsole": ("Metasploit Framework interactive console", "high"),
    "meterpreter": ("Metasploit Meterpreter agent", "critical"),
    "responder": ("Responder LLMNR/NBT-NS poisoner", "high"),
    "tcpdump": ("tcpdump packet capture sniffer", "medium"),
}

WEB_USERS = {"www-data", "nobody", "apache", "nginx", "httpd", "www"}
SHELL_BINARIES = {"bash", "sh", "zsh", "dash", "ksh", "python", "perl", "php"}


class ProcessMonitor:
    def __init__(self, client: CtemClient, asset_id: Optional[str] = None):
        self.client = client
        self.asset_id = asset_id
        self.alerted_pids: Set[int] = set()

    def set_asset_id(self, asset_id: str):
        self.asset_id = asset_id

    def check_processes(self) -> List[Dict[str, Any]]:
        """
        Inspects process table for suspicious hacker tools,
        webshell behaviors, or extreme resource anomalies.
        """
        anomalies = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'cpu_percent']):
                try:
                    info = proc.info
                    name = (info.get('name') or '').lower()
                    username = (info.get('username') or '').lower()
                    pid = info.get('pid')
                    cmdline = " ".join(info.get('cmdline') or [])

                    if pid in self.alerted_pids:
                        continue

                    # 1. Check for offensive tools
                    if name in THREAT_BINARIES:
                        desc, severity = THREAT_BINARIES[name]
                        summary = f"Suspicious offensive process detected: '{name}' (PID {pid}, User: {username}) - {desc}"
                        self._trigger_anomaly(pid, "threat_process_detected", severity, summary)
                        anomalies.append({"pid": pid, "name": name, "reason": desc})

                    # 2. Check for webshell behavior (interactive shell run by web server user)
                    if username in WEB_USERS and name in SHELL_BINARIES:
                        summary = f"Possible Web Shell: User '{username}' spawned shell '{name}' (PID {pid}, Cmd: {cmdline[:80]})"
                        self._trigger_anomaly(pid, "webshell_spawned", "critical", summary)
                        anomalies.append({"pid": pid, "name": name, "reason": "webshell"})

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            # Fallback for systems without psutil
            anomalies = self._fallback_check()

        return anomalies

    def _trigger_anomaly(self, pid: int, event_type: str, severity: str, summary: str):
        self.alerted_pids.add(pid)
        logger.warning(f"[{severity.upper()}] {summary}")
        self.client.send_log_event(
            event_type=event_type,
            severity=severity,
            summary=summary,
            asset_id=self.asset_id,
            source="ctem_agent_process",
        )

    def _fallback_check(self) -> List[Dict[str, Any]]:
        anomalies = []
        if platform.system() == "Windows":
            return anomalies

        try:
            out = subprocess.check_output(["ps", "-eo", "pid,user,comm"], text=True)
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    pid_str, user, comm = parts[0], parts[1].lower(), parts[2].lower()
                    if not pid_str.isdigit():
                        continue
                    pid = int(pid_str)
                    comm_base = os.path.basename(comm)

                    if pid in self.alerted_pids:
                        continue

                    if comm_base in THREAT_BINARIES:
                        desc, severity = THREAT_BINARIES[comm_base]
                        summary = f"Suspicious offensive process detected: '{comm_base}' (PID {pid}, User: {user}) - {desc}"
                        self._trigger_anomaly(pid, "threat_process_detected", severity, summary)
                        anomalies.append({"pid": pid, "name": comm_base, "reason": desc})
        except Exception as e:
            logger.debug(f"ps fallback error: {e}")
        return anomalies
