import os
import sys
import unittest
import tempfile
import shutil

# Include agent in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ctem_agent.config import AgentConfig
from ctem_agent.collector import SystemCollector
from ctem_agent.offline_queue import OfflineQueue
from ctem_agent.monitors.port_monitor import PortMonitor
from ctem_agent.monitors.ueba_monitor import UebaMonitor
from ctem_agent.client import CtemClient


class MockCtemClient:
    def __init__(self):
        self.sent_ueba = []
        self.sent_logs = []

    def send_ueba_event(self, username, event_type, source_ip=None, occurred_at=None):
        self.sent_ueba.append({"username": username, "event_type": event_type, "source_ip": source_ip})
        return True

    def send_log_event(self, event_type, severity="low", summary=None, asset_id=None, source="mock"):
        self.sent_logs.append({"event_type": event_type, "severity": severity, "summary": summary})
        return True


class TestCtemAgent(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_config_defaults(self):
        cfg = AgentConfig(agent_dir=self.test_dir)
        self.assertTrue(cfg.server_url.startswith("http"))
        self.assertIsNotNone(cfg.hostname)
        self.assertEqual(cfg.asset_type, "endpoint")
        self.assertTrue(cfg.enable_logs)
        self.assertTrue(cfg.enable_ports)

    def test_collector_host_info(self):
        host_info = SystemCollector.get_host_info()
        self.assertIn("hostname", host_info)
        self.assertIn("ip_address", host_info)
        self.assertIn("os_name", host_info)
        self.assertIn("cpu_count", host_info)
        self.assertGreaterEqual(host_info["cpu_count"], 1)

    def test_collector_metrics(self):
        metrics = SystemCollector.get_system_metrics()
        self.assertIn("cpu_percent", metrics)
        self.assertIn("memory_percent", metrics)
        self.assertIn("disk_percent", metrics)
        self.assertIn("uptime_seconds", metrics)
        self.assertGreaterEqual(metrics["disk_percent"], 0.0)

    def test_offline_queue(self):
        db_path = os.path.join(self.test_dir, "test_queue.db")
        q = OfflineQueue(db_path)
        self.assertEqual(q.size(), 0)

        # Enqueue item
        ok = q.enqueue("log", "/logs/events", {"event_type": "unit_test", "severity": "low"})
        self.assertTrue(ok)
        self.assertEqual(q.size(), 1)

        # Peek
        batch = q.peek_batch(10)
        self.assertEqual(len(batch), 1)
        item_id, event_type, endpoint, payload = batch[0]
        self.assertEqual(event_type, "log")
        self.assertEqual(payload["event_type"], "unit_test")

        # Remove
        q.remove_ids([item_id])
        self.assertEqual(q.size(), 0)

    def test_ueba_parser_failed_login(self):
        mock_client = MockCtemClient()
        ueba = UebaMonitor(mock_client)

        line = "Sep 29 12:00:01 host sshd[1234]: Failed password for invalid user hacker from 198.51.100.5 port 44321 ssh2"
        handled = ueba.process_auth_line(line)
        self.assertTrue(handled)
        self.assertEqual(len(mock_client.sent_ueba), 1)
        self.assertEqual(mock_client.sent_ueba[0]["username"], "hacker")
        self.assertEqual(mock_client.sent_ueba[0]["event_type"], "failed_login")
        self.assertEqual(mock_client.sent_ueba[0]["source_ip"], "198.51.100.5")

    def test_ueba_parser_successful_login(self):
        mock_client = MockCtemClient()
        ueba = UebaMonitor(mock_client)

        line = "Accepted password for admin from 10.0.1.20 port 51222 ssh2"
        handled = ueba.process_auth_line(line)
        self.assertTrue(handled)
        self.assertEqual(len(mock_client.sent_ueba), 1)
        self.assertEqual(mock_client.sent_ueba[0]["username"], "admin")
        self.assertEqual(mock_client.sent_ueba[0]["event_type"], "login")
        self.assertEqual(mock_client.sent_ueba[0]["source_ip"], "10.0.1.20")

    def test_port_monitor_service_resolution(self):
        self.assertEqual(PortMonitor.get_service_name(22, "tcp"), "ssh")
        self.assertEqual(PortMonitor.get_service_name(80, "tcp"), "http")
        self.assertEqual(PortMonitor.get_service_name(443, "tcp"), "https")
        self.assertEqual(PortMonitor.get_service_name(8000, "tcp"), "fastapi-backend")


if __name__ == "__main__":
    unittest.main()
