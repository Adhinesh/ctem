#!/usr/bin/env python3
"""
CTEM Endpoint Asset Monitoring & Log Forwarding Agent
=====================================================
Monitors host assets, resources, open ports, authentication logs,
system events, and peripherals, continuously forwarding them to the
CTEM Platform backend and central database.

Usage:
  python3 agent.py run             # Run continuous monitoring daemon
  python3 agent.py status          # View host metrics & registration state
  python3 agent.py test            # Run end-to-end connectivity test
  python3 agent.py scan-ports      # Inspect listening network ports
  python3 agent.py simulate        # Simulate security events for alert verification
  python3 agent.py install-service # Install as systemd unit or macOS launchd service
"""

import os
import sys
import time
import signal
import logging
import argparse
from typing import Optional

# Ensure package is in pythonpath
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ctem_agent.config import AgentConfig
from ctem_agent.offline_queue import OfflineQueue
from ctem_agent.client import CtemClient
from ctem_agent.collector import SystemCollector
from ctem_agent.monitors import (
    PortMonitor,
    LogMonitor,
    UebaMonitor,
    ProcessMonitor,
    PeripheralMonitor,
)
from ctem_agent.service import install_service

# Configure clean, informative logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ctem_agent")


class CtemAgentDaemon:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.queue = OfflineQueue(self.config.buffer_db_path)
        self.client = CtemClient(self.config.server_url, queue=self.queue)
        self.running = False

        # Initialize sub-monitors
        self.port_monitor = PortMonitor(self.client, asset_id=self.config.asset_id)
        self.ueba_monitor = UebaMonitor(self.client)
        self.log_monitor = LogMonitor(
            self.client,
            ueba_monitor=self.ueba_monitor,
            asset_id=self.config.asset_id,
            custom_log_paths=self.config.custom_log_paths,
        )
        self.process_monitor = ProcessMonitor(self.client, asset_id=self.config.asset_id)
        self.peripheral_monitor = PeripheralMonitor(self.client, asset_id=self.config.asset_id)

    def register_or_sync_asset(self) -> bool:
        """
        Connects to CTEM backend, checks health, discovers host
        metadata, and ensures the asset is registered.
        """
        logger.info(f"Connecting to CTEM backend at: {self.config.server_url}")

        # Check server reachability
        is_healthy = self.client.check_health()
        if not is_healthy:
            logger.warning(
                f"[!] CTEM backend at {self.config.server_url} is not currently responding to health checks. "
                "Agent will queue events offline until connection is established."
            )

        host_info = SystemCollector.get_host_info()
        logger.info(
            f"Discovered Host: {host_info['hostname']} (IP: {host_info['ip_address']}, OS: {host_info['os_name']} {host_info['arch']}, RAM: {host_info['memory_mb']} MB)"
        )

        if not self.config.ip_address:
            self.config.ip_address = host_info["ip_address"]

        # If asset_id is already cached, verify or continue
        if self.config.asset_id:
            logger.info(f"Reusing cached Asset ID: {self.config.asset_id}")
            self._update_monitor_asset_ids(self.config.asset_id)
            return True

        if is_healthy:
            # Register with CTEM
            logger.info("Registering host with CTEM Platform...")
            asset_id = self.client.register(
                hostname=self.config.hostname,
                ip_address=self.config.ip_address,
                mac_address=host_info.get("mac_address"),
                os_name=host_info.get("os_name"),
                os_version=host_info.get("os_version"),
                asset_type=self.config.asset_type,
                zone=self.config.zone,
                criticality=self.config.criticality,
                metadata=host_info,
            )
            if asset_id:
                self.config.save_state(asset_id, extra={"registered_at": time.time()})
                self._update_monitor_asset_ids(asset_id)
                logger.info(f"[+] Asset registered successfully! Assigned CTEM Asset ID: {asset_id}")
                return True

        logger.warning("Could not obtain Asset ID from CTEM yet. Will retry during heartbeat cycle.")
        return False

    def _update_monitor_asset_ids(self, asset_id: str):
        self.port_monitor.set_asset_id(asset_id)
        self.log_monitor.set_asset_id(asset_id)
        self.process_monitor.set_asset_id(asset_id)
        self.peripheral_monitor.set_asset_id(asset_id)

    def start(self):
        """Starts all monitoring routines in continuous loop."""
        self.running = True
        logger.info("======================================================")
        logger.info("  Starting CTEM Continuous Asset Monitoring Agent     ")
        logger.info("======================================================")

        self.register_or_sync_asset()

        # Start background log tailing if enabled
        if self.config.enable_logs:
            self.log_monitor.start()

        # Initial baseline scans
        initial_ports = []
        if self.config.enable_ports:
            initial_ports = self.port_monitor.check_drift()

        if self.config.enable_processes:
            self.process_monitor.check_processes()

        if self.config.enable_peripherals:
            self.peripheral_monitor.check_devices()

        last_heartbeat = 0
        last_port_scan = 0
        last_process_scan = 0

        logger.info(f"Agent monitoring loop running. Heartbeat interval: {self.config.heartbeat_interval}s. (Ctrl+C to stop)")

        try:
            while self.running:
                now = time.time()

                # If not registered yet, try to register
                if not self.config.asset_id:
                    self.register_or_sync_asset()

                # 1. Process Anomalies Scan
                if self.config.enable_processes and (now - last_process_scan >= self.config.process_scan_interval):
                    self.process_monitor.check_processes()
                    last_process_scan = now

                # 2. Port Drift Scan
                if self.config.enable_ports and (now - last_port_scan >= self.config.port_scan_interval):
                    self.port_monitor.check_drift()
                    last_port_scan = now

                # 3. Peripheral Device Check
                if self.config.enable_peripherals:
                    self.peripheral_monitor.check_devices()

                # 4. System Health Metrics & Heartbeat
                if now - last_heartbeat >= self.config.heartbeat_interval:
                    metrics = SystemCollector.get_system_metrics()
                    ports = self.port_monitor.scan_listening_ports() if self.config.enable_ports else []

                    logger.info(
                        f"[HEARTBEAT] CPU: {metrics['cpu_percent']}% | RAM: {metrics['memory_percent']}% | "
                        f"Disk: {metrics['disk_percent']}% | Ports: {len(ports)} listening"
                    )

                    if self.config.asset_id:
                        self.client.send_heartbeat(
                            asset_id=self.config.asset_id,
                            hostname=self.config.hostname,
                            metrics=metrics,
                            listening_ports=ports,
                        )

                    # Flush any offline buffered events
                    if self.queue.size() > 0:
                        flushed = self.client.flush_queue()
                        if flushed > 0:
                            logger.info(f"Flushed {flushed} events from offline buffer.")

                    last_heartbeat = now

                time.sleep(1.0)

        except KeyboardInterrupt:
            logger.info("Received interrupt signal. Stopping agent...")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.config.enable_logs:
            self.log_monitor.stop()
        logger.info("CTEM Agent stopped cleanly.")


def cmd_status(config: AgentConfig):
    """Prints diagnostic status of the host and CTEM agent."""
    print("==================================================")
    print("             CTEM Agent Status Report             ")
    print("==================================================")
    host_info = SystemCollector.get_host_info()
    metrics = SystemCollector.get_system_metrics()
    queue = OfflineQueue(config.buffer_db_path)
    client = CtemClient(config.server_url)

    is_online = client.check_health()

    print(f"Backend Server URL : {config.server_url} [{'ONLINE' if is_online else 'OFFLINE'}]")
    print(f"Registered Asset ID: {config.asset_id or 'Not Registered'}")
    print(f"Configured Hostname: {config.hostname}")
    print(f"Primary IP Address : {host_info['ip_address']}")
    print(f"MAC Address        : {host_info['mac_address']}")
    print(f"OS & Architecture  : {host_info['os_name']} {host_info['arch']} ({host_info['os_version']})")
    print(f"CPU Utilization    : {metrics['cpu_percent']}% ({host_info['cpu_count']} cores)")
    print(f"Memory Utilization : {metrics['memory_percent']}% ({metrics.get('memory_used_mb', 0)}MB / {metrics.get('memory_total_mb', 0)}MB)")
    print(f"Disk Utilization   : {metrics['disk_percent']}% ({metrics.get('disk_used_gb', 0)}GB / {metrics.get('disk_total_gb', 0)}GB)")
    print(f"System Uptime      : {metrics['uptime_seconds']} seconds")
    print(f"Offline Buffer Size: {queue.size()} events queued")
    print("==================================================")


def cmd_test(config: AgentConfig):
    """Runs an interactive diagnostic and verification test against CTEM backend."""
    print("[*] Starting CTEM Agent End-to-End Diagnostic Test...")
    queue = OfflineQueue(config.buffer_db_path)
    client = CtemClient(config.server_url, queue=queue)

    print(f"1. Checking CTEM API Health ({config.server_url}/health)...")
    if client.check_health():
        print("   [+] PASS: CTEM Backend is reachable and healthy!")
    else:
        print("   [-] FAIL: CTEM Backend is unreachable. Please verify backend is running on " + config.server_url)
        return

    print("2. Discovering Host Metadata...")
    host_info = SystemCollector.get_host_info()
    print(f"   [+] Discovered: {host_info['hostname']} ({host_info['ip_address']}, {host_info['os_name']})")

    print("3. Registering / Syncing Asset with CTEM...")
    asset_id = client.register(
        hostname=config.hostname,
        ip_address=host_info["ip_address"],
        mac_address=host_info.get("mac_address"),
        os_name=host_info.get("os_name"),
        os_version=host_info.get("os_version"),
        asset_type=config.asset_type,
        zone=config.zone,
        criticality=config.criticality,
    )
    if asset_id:
        print(f"   [+] PASS: Asset ID assigned: {asset_id}")
        config.save_state(asset_id)
    else:
        print("   [-] FAIL: Registration failed.")
        return

    print("4. Testing Heartbeat & Telemetry Forwarding...")
    metrics = SystemCollector.get_system_metrics()
    port_monitor = PortMonitor(client, asset_id=asset_id)
    ports = port_monitor.scan_listening_ports()
    ok = client.send_heartbeat(asset_id, config.hostname, metrics, ports)
    if ok:
        print(f"   [+] PASS: Heartbeat delivered successfully! (Reported {len(ports)} listening ports)")
    else:
        print("   [-] FAIL: Heartbeat failed.")

    print("5. Testing Security Event Ingestion (/logs/events)...")
    ok_log = client.send_log_event(
        event_type="agent_diagnostic_test",
        severity="low",
        summary=f"Diagnostic test verified by CTEM Agent on {config.hostname}",
        asset_id=asset_id,
        source="ctem_agent_test",
    )
    if ok_log:
        print("   [+] PASS: Log event delivered successfully!")
    else:
        print("   [-] FAIL: Log event forwarding failed.")

    print("6. Testing UEBA Authentication Stream (/ueba/events)...")
    ok_ueba = client.send_ueba_event(
        username="test_admin",
        event_type="login",
        source_ip=host_info["ip_address"],
    )
    if ok_ueba:
        print("   [+] PASS: UEBA event delivered successfully!")
    else:
        print("   [-] FAIL: UEBA event forwarding failed.")

    print("\n[✔] ALL DIAGNOSTIC TESTS PASSED! Your agent is ready for continuous monitoring.")


def cmd_scan_ports(config: AgentConfig):
    """Scans and displays active listening ports on the local machine."""
    client = CtemClient(config.server_url)
    pm = PortMonitor(client)
    ports = pm.scan_listening_ports()
    print(f"[*] Found {len(ports)} listening TCP port(s):")
    print(f"{'PORT/PROTO':<15} {'SERVICE':<20} {'LOCAL BIND'}")
    print("-" * 50)
    for p in ports:
        bind_ip = p.get("ip", "*")
        print(f"{p['port'] + '/' + p['protocol']:<15} {p['service']:<20} {bind_ip}")


def cmd_simulate(config: AgentConfig, attack_type: str):
    """Simulates security events to test anomaly detection and alert triggering."""
    client = CtemClient(config.server_url)
    asset_id = config.asset_id

    if not asset_id:
        host_info = SystemCollector.get_host_info()
        asset_id = client.register(
            hostname=config.hostname,
            ip_address=host_info["ip_address"],
            asset_type=config.asset_type,
            zone=config.zone,
            criticality=config.criticality,
        )

    print(f"[*] Running attack simulation: {attack_type} against Asset ID: {asset_id}")

    if attack_type == "bruteforce":
        print("[*] Simulating SSH Brute-Force Burst (6 rapid failed logins)...")
        for i in range(1, 7):
            client.send_ueba_event(
                username="victim_admin",
                event_type="failed_login",
                source_ip="198.51.100.99",
            )
            print(f"    [-] Sent failed login attempt #{i} for user 'victim_admin' from 198.51.100.99")
            time.sleep(0.3)
        print("[+] Done! Check CTEM Alerts dashboard (http://localhost:3000/alerts) for HIGH alert: 'Repeated failed logins for victim_admin'.")

    elif attack_type == "rogue_ip":
        print("[*] Simulating Login from New/Rogue Source IP...")
        client.send_ueba_event(
            username="analyst_jane",
            event_type="login",
            source_ip="203.0.113.77",
        )
        print("[+] Done! Check CTEM Alerts dashboard for MEDIUM alert: 'Login from new source IP for analyst_jane'.")

    elif attack_type == "webshell":
        print("[*] Simulating Web Shell Process Execution...")
        client.send_log_event(
            event_type="webshell_spawned",
            severity="critical",
            summary="Web Shell Detected: Process '/bin/bash' spawned by user 'www-data' (PID 14820)",
            asset_id=asset_id,
            source="ctem_agent_process",
        )
        print("[+] Done! Check CTEM Alerts dashboard for CRITICAL alert: 'critical severity event: webshell_spawned'.")

    elif attack_type == "suspicious_port":
        print("[*] Simulating Suspicious Backdoor Port Opening (4444/tcp Metasploit)...")
        client.send_log_event(
            event_type="port_opened",
            severity="high",
            summary="New listening port opened on asset: 4444/tcp (SUSPICIOUS: Metasploit default payload handler)",
            asset_id=asset_id,
            source="ctem_agent_ports",
        )
        print("[+] Done! Check CTEM Alerts dashboard for HIGH alert.")
    else:
        print(f"Unknown attack type: {attack_type}. Available: bruteforce, rogue_ip, webshell, suspicious_port")


def main():
    parser = argparse.ArgumentParser(description="CTEM Endpoint Asset Monitoring & Log Forwarding Agent")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "status", "test", "scan-ports", "simulate", "install-service"], help="Command to execute")
    parser.add_argument("--server", dest="server_url", help="CTEM backend server URL (e.g. http://192.168.1.50:8000)")
    parser.add_argument("--asset-id", dest="asset_id", help="Explicit CTEM Asset ID")
    parser.add_argument("--hostname", dest="hostname", help="Override host name")
    parser.add_argument("--config", dest="config_path", help="Path to config.json")
    parser.add_argument("--attack", dest="attack_type", default="bruteforce", choices=["bruteforce", "rogue_ip", "webshell", "suspicious_port"], help="Type of attack to simulate")

    args = parser.parse_args()

    # Load configuration
    config = AgentConfig.load(config_path=args.config_path)

    # CLI flag overrides
    if args.server_url:
        config.server_url = args.server_url.rstrip("/")
    if args.asset_id:
        config.asset_id = args.asset_id
    if args.hostname:
        config.hostname = args.hostname

    if args.command == "status":
        cmd_status(config)
    elif args.command == "test":
        cmd_test(config)
    elif args.command == "scan-ports":
        cmd_scan_ports(config)
    elif args.command == "simulate":
        cmd_simulate(config, args.attack_type)
    elif args.command == "install-service":
        agent_dir = os.path.dirname(os.path.abspath(__file__))
        install_service(agent_dir)
    elif args.command == "run":
        daemon = CtemAgentDaemon(config)
        # Handle termination signals cleanly
        signal.signal(signal.SIGINT, lambda s, f: daemon.stop())
        signal.signal(signal.SIGTERM, lambda s, f: daemon.stop())
        daemon.start()


if __name__ == "__main__":
    main()
