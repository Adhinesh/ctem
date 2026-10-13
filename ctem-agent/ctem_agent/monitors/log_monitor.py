import os
import re
import time
import json
import platform
import subprocess
import threading
import logging
from typing import List, Optional
from ctem_agent.client import CtemClient
from ctem_agent.monitors.ueba_monitor import UebaMonitor

logger = logging.getLogger("ctem_agent.monitors.logs")

DEFAULT_LOG_CANDIDATES = [
    "/var/log/auth.log",       # Debian, Ubuntu, Kali
    "/var/log/secure",         # RHEL, CentOS, Rocky, Fedora
    "/var/log/syslog",         # Debian/Ubuntu general syslog
    "/var/log/messages",       # RHEL/CentOS system messages
    "/var/log/system.log",     # macOS system log
]

# System error patterns for security logging
CRITICAL_LOG_PATTERNS = [
    (re.compile(r"Out of memory: Kill process (\d+) \(([^)]+)\)"), "oom_killer", "high", "OOM Killer invoked for process"),
    (re.compile(r"kernel:.*segfault at [0-9a-f]+.*in ([^\s]+)"), "segfault", "medium", "Application segmentation fault detected"),
    (re.compile(r"I/O error, dev (\S+)"), "disk_io_error", "high", "Hardware filesystem I/O error"),
    (re.compile(r"\[UFW BLOCK\] IN=(\S+) OUT=.*SRC=(\S+) DST=(\S+)"), "firewall_drop", "low", "UFW Firewall blocked incoming connection"),
    (re.compile(r"kernel:.*possible SYN flooding on port (\d+)"), "syn_flood_detected", "high", "Kernel reported potential SYN flood DoS attack"),
]


class LogMonitor:
    def __init__(
        self,
        client: CtemClient,
        ueba_monitor: UebaMonitor,
        asset_id: Optional[str] = None,
        custom_log_paths: Optional[List[str]] = None,
    ):
        self.client = client
        self.ueba = ueba_monitor
        self.asset_id = asset_id
        self.custom_log_paths = custom_log_paths or []
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []

    def set_asset_id(self, asset_id: str):
        self.asset_id = asset_id

    def find_active_logs(self) -> List[str]:
        """Finds all readable log files on the host system."""
        found = []
        candidates = list(self.custom_log_paths) + DEFAULT_LOG_CANDIDATES
        for path in candidates:
            if os.path.exists(path) and os.access(path, os.R_OK):
                if path not in found:
                    found.append(path)
        return found

    def start(self):
        """Starts tailing discovered logs in background worker threads."""
        if platform.system() == "Windows":
            logger.info("Detected Windows OS. Launching Windows Security Event Log monitor...")
            t_win = threading.Thread(target=self._tail_windows_events, daemon=True, name="LogTailer-WinSecurity")
            t_win.start()
            self._threads.append(t_win)

        logs = self.find_active_logs()
        if logs:
            logger.info(f"Starting log monitors for {len(logs)} log target(s): {logs}")
            for path in logs:
                t = threading.Thread(target=self._tail_worker, args=(path,), daemon=True, name=f"LogTailer-{os.path.basename(path)}")
                t.start()
                self._threads.append(t)
        elif platform.system() != "Windows":
            logger.info("No system log files found or accessible without elevated privileges.")

    def stop(self):
        """Signals all tailing workers to shut down."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=1.0)

    def _tail_windows_events(self):
        """Streams Windows Security Event log entries in real-time via PowerShell."""
        ps_cmd = (
            "$last = [DateTime]::UtcNow.AddSeconds(-10); "
            "while ($true) { "
            "  $now = [DateTime]::UtcNow; "
            "  $evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4624,4672,4720; StartTime=$last} -ErrorAction SilentlyContinue; "
            "  $last = $now; "
            "  if ($evts) { "
            "    foreach ($e in $evts) { "
            "      $id = $e.Id; "
            "      $u = ''; $ip = '127.0.0.1'; "
            "      if ($id -eq 4625) { $u = [string]$e.Properties[5].Value; $ip = [string]$e.Properties[19].Value } "
            "      elseif ($id -eq 4624) { $u = [string]$e.Properties[5].Value; $ip = [string]$e.Properties[18].Value } "
            "      elseif ($id -eq 4672) { $u = [string]$e.Properties[1].Value } "
            "      elseif ($id -eq 4720) { $u = [string]$e.Properties[0].Value } "
            "      [PSCustomObject]@{ Id=$id; User=$u; Ip=$ip; Time=$e.TimeCreated.ToString('o') } | ConvertTo-Json -Compress "
            "    } "
            "  }; "
            "  Start-Sleep -Seconds 2 "
            "}"
        )
        try:
            proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            while not self._stop_event.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.5)
                    continue
                try:
                    data = json.loads(line.strip())
                    evt_id = data.get("Id")
                    user = data.get("User")
                    ip = data.get("Ip") or "127.0.0.1"
                    if ip in ("-", "", "::1"):
                        ip = "127.0.0.1"

                    if not user or user.endswith("$") or user.upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                        continue

                    if evt_id == 4625:  # Failed logon
                        logger.warning(f"[WINDOWS SECURITY] Event 4625 Failed Logon: User '{user}' from IP {ip}")
                        self.client.send_ueba_event(username=user, event_type="failed_login", source_ip=ip)
                    elif evt_id == 4624:  # Successful logon
                        logger.info(f"[WINDOWS SECURITY] Event 4624 Successful Logon: User '{user}' from IP {ip}")
                        self.client.send_ueba_event(username=user, event_type="login", source_ip=ip)
                    elif evt_id == 4672:  # Admin privileges assigned
                        logger.info(f"[WINDOWS SECURITY] Event 4672 Admin Privileges Assigned: User '{user}'")
                        self.client.send_ueba_event(username=user, event_type="privilege_change", source_ip=ip)
                    elif evt_id == 4720:  # User account created
                        summary = f"New user account created on Windows host: '{user}' (Event ID 4720)"
                        logger.warning(f"[WINDOWS SECURITY] {summary}")
                        self.client.send_log_event(
                            event_type="account_created",
                            severity="high",
                            summary=summary,
                            asset_id=self.asset_id,
                            source="windows_security_eventlog",
                        )
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Windows event log listener error: {e}")

    def _tail_worker(self, filepath: str):
        """Tails a file continuously with log rotation handling."""
        logger.debug(f"Tail worker active for {filepath}")
        try:
            with open(filepath, "r", errors="ignore") as f:
                # Seek to current end of file on startup
                f.seek(0, os.SEEK_END)
                last_inode = os.fstat(f.fileno()).st_ino

                while not self._stop_event.is_set():
                    line = f.readline()
                    if line:
                        self._process_line(line, filepath)
                    else:
                        time.sleep(0.5)
                        # Check for log rotation (file truncated or inode changed)
                        try:
                            curr_stat = os.stat(filepath)
                            if curr_stat.st_ino != last_inode or curr_stat.st_size < f.tell():
                                logger.info(f"Detected log rotation on {filepath}, reopening.")
                                f.close()
                                f = open(filepath, "r", errors="ignore")
                                last_inode = os.fstat(f.fileno()).st_ino
                        except Exception:
                            pass
        except PermissionError:
            logger.warning(f"Permission denied reading {filepath}. Run agent with sudo to stream authentication events.")
        except Exception as e:
            logger.error(f"Error in tail worker for {filepath}: {e}")

    def _process_line(self, line: str, source_path: str):
        # 1. First feed to UEBA engine
        handled = self.ueba.process_auth_line(line)
        if handled:
            return

        # 2. Check for system security and operational anomalies
        for pattern, event_type, severity, title in CRITICAL_LOG_PATTERNS:
            m = pattern.search(line)
            if m:
                matched_details = ", ".join(m.groups())
                summary = f"{title}: {matched_details} (File: {os.path.basename(source_path)})"
                logger.warning(f"[{severity.upper()}] {summary}")
                self.client.send_log_event(
                    event_type=event_type,
                    severity=severity,
                    summary=summary,
                    asset_id=self.asset_id,
                    source=f"syslog_{os.path.basename(source_path)}",
                )
                break
