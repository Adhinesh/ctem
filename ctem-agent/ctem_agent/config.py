import os
import json
import socket
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger("ctem_agent.config")

DEFAULT_STATE_FILE = ".agent_state.json"
DEFAULT_BUFFER_DB = ".agent_buffer.db"
DEFAULT_CONFIG_FILE = "config.json"


class AgentConfig:
    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8000",
        asset_id: Optional[str] = None,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
        asset_type: str = "endpoint",
        zone: str = "internal",
        criticality: str = "medium",
        heartbeat_interval: int = 30,
        port_scan_interval: int = 60,
        process_scan_interval: int = 30,
        enable_logs: bool = True,
        enable_ueba: bool = True,
        enable_ports: bool = True,
        enable_processes: bool = True,
        enable_peripherals: bool = True,
        custom_log_paths: Optional[List[str]] = None,
        buffer_db_path: str = DEFAULT_BUFFER_DB,
        state_file_path: str = DEFAULT_STATE_FILE,
        agent_dir: Optional[str] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.asset_id = asset_id
        self.hostname = hostname or socket.gethostname()
        self.ip_address = ip_address
        self.asset_type = asset_type
        self.zone = zone
        self.criticality = criticality
        self.heartbeat_interval = heartbeat_interval
        self.port_scan_interval = port_scan_interval
        self.process_scan_interval = process_scan_interval
        self.enable_logs = enable_logs
        self.enable_ueba = enable_ueba
        self.enable_ports = enable_ports
        self.enable_processes = enable_processes
        self.enable_peripherals = enable_peripherals
        self.custom_log_paths = custom_log_paths or []
        self.agent_dir = agent_dir or str(Path(__file__).resolve().parent.parent)

        # File paths relative to agent_dir if not absolute
        self.buffer_db_path = os.path.join(self.agent_dir, buffer_db_path) if not os.path.isabs(buffer_db_path) else buffer_db_path
        self.state_file_path = os.path.join(self.agent_dir, state_file_path) if not os.path.isabs(state_file_path) else state_file_path

    @classmethod
    def load(cls, config_path: Optional[str] = None, agent_dir: Optional[str] = None) -> "AgentConfig":
        """
        Loads configuration with precedence:
        1. Environment variables
        2. Config file (config.json)
        3. Persisted agent state (.agent_state.json)
        4. Sensible defaults
        """
        base_dir = agent_dir or str(Path(__file__).resolve().parent.parent)
        file_cfg: Dict[str, Any] = {}

        # 1. Check specified or default config file
        target_cfg = config_path or os.path.join(base_dir, DEFAULT_CONFIG_FILE)
        if os.path.exists(target_cfg):
            try:
                with open(target_cfg, "r") as f:
                    file_cfg = json.load(f)
                logger.info(f"Loaded config from {target_cfg}")
            except Exception as e:
                logger.warning(f"Failed to read {target_cfg}: {e}")

        # 2. Check persisted state file for asset_id
        state_file = os.path.join(base_dir, DEFAULT_STATE_FILE)
        persisted_asset_id = None
        if os.path.exists(state_file):
            try:
                with open(state_file, "r") as f:
                    state_data = json.load(f)
                    persisted_asset_id = state_data.get("asset_id")
            except Exception as e:
                logger.debug(f"Could not load state file: {e}")

        # 3. Environment variables take precedence over config file
        server_url = os.environ.get("CTEM_SERVER_URL") or file_cfg.get("server_url") or "http://127.0.0.1:8000"
        asset_id = os.environ.get("CTEM_ASSET_ID") or file_cfg.get("asset_id") or persisted_asset_id
        hostname = os.environ.get("CTEM_HOSTNAME") or file_cfg.get("hostname") or socket.gethostname()
        ip_address = os.environ.get("CTEM_IP_ADDRESS") or file_cfg.get("ip_address")
        asset_type = os.environ.get("CTEM_ASSET_TYPE") or file_cfg.get("asset_type") or "endpoint"
        zone = os.environ.get("CTEM_ZONE") or file_cfg.get("zone") or "internal"
        criticality = os.environ.get("CTEM_CRITICALITY") or file_cfg.get("criticality") or "medium"

        heartbeat_interval = int(os.environ.get("CTEM_HEARTBEAT_INTERVAL") or file_cfg.get("heartbeat_interval") or 30)
        port_scan_interval = int(os.environ.get("CTEM_PORT_SCAN_INTERVAL") or file_cfg.get("port_scan_interval") or 60)
        process_scan_interval = int(os.environ.get("CTEM_PROCESS_SCAN_INTERVAL") or file_cfg.get("process_scan_interval") or 30)

        enable_logs = str(os.environ.get("CTEM_ENABLE_LOGS", file_cfg.get("enable_logs", True))).lower() in ("true", "1", "yes")
        enable_ueba = str(os.environ.get("CTEM_ENABLE_UEBA", file_cfg.get("enable_ueba", True))).lower() in ("true", "1", "yes")
        enable_ports = str(os.environ.get("CTEM_ENABLE_PORTS", file_cfg.get("enable_ports", True))).lower() in ("true", "1", "yes")
        enable_processes = str(os.environ.get("CTEM_ENABLE_PROCESSES", file_cfg.get("enable_processes", True))).lower() in ("true", "1", "yes")
        enable_peripherals = str(os.environ.get("CTEM_ENABLE_PERIPHERALS", file_cfg.get("enable_peripherals", True))).lower() in ("true", "1", "yes")

        custom_log_paths = file_cfg.get("custom_log_paths", [])

        return cls(
            server_url=server_url,
            asset_id=asset_id,
            hostname=hostname,
            ip_address=ip_address,
            asset_type=asset_type,
            zone=zone,
            criticality=criticality,
            heartbeat_interval=heartbeat_interval,
            port_scan_interval=port_scan_interval,
            process_scan_interval=process_scan_interval,
            enable_logs=enable_logs,
            enable_ueba=enable_ueba,
            enable_ports=enable_ports,
            enable_processes=enable_processes,
            enable_peripherals=enable_peripherals,
            custom_log_paths=custom_log_paths,
            agent_dir=base_dir,
        )

    def save_state(self, asset_id: str, extra: Optional[Dict[str, Any]] = None):
        """Persists the assigned asset_id to disk so agent restarts maintain continuity."""
        self.asset_id = asset_id
        payload = {
            "asset_id": asset_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "server_url": self.server_url,
        }
        if extra:
            payload.update(extra)

        try:
            with open(self.state_file_path, "w") as f:
                json.dump(payload, f, indent=2)
            logger.info(f"Persisted agent state to {self.state_file_path}")
        except Exception as e:
            logger.warning(f"Could not persist agent state: {e}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_url": self.server_url,
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "asset_type": self.asset_type,
            "zone": self.zone,
            "criticality": self.criticality,
            "heartbeat_interval": self.heartbeat_interval,
            "port_scan_interval": self.port_scan_interval,
            "process_scan_interval": self.process_scan_interval,
            "enable_logs": self.enable_logs,
            "enable_ueba": self.enable_ueba,
            "enable_ports": self.enable_ports,
            "enable_processes": self.enable_processes,
            "enable_peripherals": self.enable_peripherals,
            "custom_log_paths": self.custom_log_paths,
            "buffer_db_path": self.buffer_db_path,
            "state_file_path": self.state_file_path,
        }
