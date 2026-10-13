import os
import sys
import time
import socket
import platform
import shutil
import subprocess
import uuid
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ctem_agent.collector")

# Optional psutil integration for higher precision
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class SystemCollector:
    @staticmethod
    def get_primary_ip() -> str:
        """Determines the primary outbound IPv4 address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            # Connecting to a public IP doesn't actually send packets over UDP
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    @staticmethod
    def get_mac_address() -> str:
        try:
            raw_mac = uuid.getnode()
            mac = ":".join(("%012X" % raw_mac)[i:i+2] for i in range(0, 12, 2))
            return mac.lower()
        except Exception:
            return "00:00:00:00:00:00"

    @classmethod
    def get_host_info(cls) -> Dict[str, Any]:
        """Collects static hardware and operating system metadata."""
        os_name = platform.system()
        os_release = platform.release()
        os_version = platform.version()
        arch = platform.machine()
        cpu_count = os.cpu_count() or 1
        primary_ip = cls.get_primary_ip()
        mac_addr = cls.get_mac_address()
        hostname = socket.gethostname()

        total_memory_mb = cls._get_total_memory_mb()

        return {
            "hostname": hostname,
            "ip_address": primary_ip,
            "mac_address": mac_addr,
            "os_name": os_name,
            "os_version": f"{os_release} ({os_version})",
            "arch": arch,
            "cpu_count": cpu_count,
            "memory_mb": total_memory_mb,
            "python_version": sys.version.split()[0],
            "has_psutil": HAS_PSUTIL,
        }

    @classmethod
    def get_system_metrics(cls) -> Dict[str, Any]:
        """Collects dynamic health, CPU, memory, and disk utilization metrics."""
        metrics: Dict[str, Any] = {
            "timestamp": time.time(),
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "disk_percent": 0.0,
            "uptime_seconds": cls._get_uptime(),
            "load_avg": cls._get_load_avg(),
            "process_count": cls._get_process_count(),
        }

        # 1. Disk usage (standard library shutil works everywhere)
        try:
            root_path = "C:\\" if platform.system() == "Windows" else "/"
            total, used, free = shutil.disk_usage(root_path)
            metrics["disk_percent"] = round((used / total) * 100, 1)
            metrics["disk_total_gb"] = round(total / (1024 ** 3), 2)
            metrics["disk_used_gb"] = round(used / (1024 ** 3), 2)
        except Exception as e:
            logger.debug(f"Disk metric collection error: {e}")

        # 2. CPU and Memory via psutil if available
        if HAS_PSUTIL:
            try:
                metrics["cpu_percent"] = round(psutil.cpu_percent(interval=0.1), 1)
                mem = psutil.virtual_memory()
                metrics["memory_percent"] = round(mem.percent, 1)
                metrics["memory_used_mb"] = round(mem.used / (1024 ** 2), 1)
                metrics["memory_total_mb"] = round(mem.total / (1024 ** 2), 1)
                return metrics
            except Exception as e:
                logger.debug(f"psutil metric error: {e}")

        # 3. Fallback OS-specific CPU/Memory collection
        metrics["cpu_percent"] = cls._fallback_cpu_percent(metrics["load_avg"])
        mem_info = cls._fallback_memory_info()
        metrics["memory_percent"] = mem_info.get("percent", 0.0)
        if "used_mb" in mem_info:
            metrics["memory_used_mb"] = mem_info["used_mb"]
        if "total_mb" in mem_info:
            metrics["memory_total_mb"] = mem_info["total_mb"]

        return metrics

    @staticmethod
    def _get_total_memory_mb() -> int:
        if HAS_PSUTIL:
            try:
                return int(psutil.virtual_memory().total / (1024 ** 2))
            except Exception:
                pass

        os_name = platform.system()
        if os_name == "Linux" and os.path.exists("/proc/meminfo"):
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            kb = int(line.split()[1])
                            return int(kb / 1024)
            except Exception:
                pass
        elif os_name == "Darwin":
            try:
                out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip()
                return int(int(out) / (1024 ** 2))
            except Exception:
                pass
        return 0

    @staticmethod
    def _get_load_avg() -> List[float]:
        if hasattr(os, "getloadavg"):
            try:
                return [round(x, 2) for x in os.getloadavg()]
            except Exception:
                pass
        return [0.0, 0.0, 0.0]

    @classmethod
    def _fallback_cpu_percent(cls, load_avg: List[float]) -> float:
        cpu_count = os.cpu_count() or 1
        if load_avg and load_avg[0] > 0:
            # Estimate CPU usage from 1-minute load average normalized by core count
            pct = min(100.0, round((load_avg[0] / cpu_count) * 100, 1))
            return pct
        return 0.0

    @staticmethod
    def _fallback_memory_info() -> Dict[str, Any]:
        os_name = platform.system()
        if os_name == "Linux" and os.path.exists("/proc/meminfo"):
            try:
                total_kb, avail_kb = 0, 0
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            total_kb = int(line.split()[1])
                        elif line.startswith("MemAvailable:"):
                            avail_kb = int(line.split()[1])
                if total_kb > 0:
                    used_kb = total_kb - avail_kb
                    return {
                        "percent": round((used_kb / total_kb) * 100, 1),
                        "used_mb": round(used_kb / 1024, 1),
                        "total_mb": round(total_kb / 1024, 1),
                    }
            except Exception:
                pass
        elif os_name == "Darwin":
            try:
                # Use vm_stat on macOS
                out = subprocess.check_output(["vm_stat"], text=True)
                lines = out.splitlines()
                pages: Dict[str, int] = {}
                for line in lines[1:]:
                    parts = line.split(":")
                    if len(parts) == 2:
                        k = parts[0].strip()
                        v = int(parts[1].strip().rstrip("."))
                        pages[k] = v
                page_size = 4096
                free = pages.get("Pages free", 0) * page_size
                active = pages.get("Pages active", 0) * page_size
                inactive = pages.get("Pages inactive", 0) * page_size
                wired = pages.get("Pages wired down", 0) * page_size
                compressed = pages.get("Pages occupied by compressor", 0) * page_size
                used = active + wired + compressed
                total = used + free + inactive
                if total > 0:
                    return {
                        "percent": round((used / total) * 100, 1),
                        "used_mb": round(used / (1024 ** 2), 1),
                        "total_mb": round(total / (1024 ** 2), 1),
                    }
            except Exception:
                pass
        return {"percent": 0.0}

    @staticmethod
    def _get_uptime() -> int:
        if HAS_PSUTIL:
            try:
                return int(time.time() - psutil.boot_time())
            except Exception:
                pass

        os_name = platform.system()
        if os_name == "Linux" and os.path.exists("/proc/uptime"):
            try:
                with open("/proc/uptime", "r") as f:
                    return int(float(f.readline().split()[0]))
            except Exception:
                pass
        elif os_name == "Darwin":
            try:
                out = subprocess.check_output(["sysctl", "-n", "kern.boottime"], text=True)
                # Form: { sec = 1727610000, usec = ... }
                if "sec =" in out:
                    sec_str = out.split("sec =")[1].split(",")[0].strip()
                    return int(time.time() - int(sec_str))
            except Exception:
                pass
        return 0

    @staticmethod
    def _get_process_count() -> int:
        if HAS_PSUTIL:
            try:
                return len(psutil.pids())
            except Exception:
                pass

        if platform.system() != "Windows":
            try:
                out = subprocess.check_output(["ps", "-A"], text=True)
                return max(0, len(out.splitlines()) - 1)
            except Exception:
                pass
        return 0
