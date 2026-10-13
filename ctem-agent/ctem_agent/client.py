import json
import time
import urllib.request
import urllib.error
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from ctem_agent.offline_queue import OfflineQueue

logger = logging.getLogger("ctem_agent.client")


class CtemClient:
    def __init__(self, base_url: str, queue: Optional[OfflineQueue] = None, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.queue = queue
        self.timeout = timeout
        self.is_connected = False

    def _request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Tuple[bool, Any]:
        """Performs an HTTP request using Python's standard urllib."""
        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/json", "User-Agent": "CTEM-Endpoint-Agent/1.0"}
        body = json.dumps(data).encode("utf-8") if data is not None else None

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                self.is_connected = True
                resp_bytes = response.read()
                try:
                    resp_json = json.loads(resp_bytes.decode("utf-8"))
                    return True, resp_json
                except Exception:
                    return True, resp_bytes.decode("utf-8")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            logger.warning(f"HTTP {e.code} error from {endpoint}: {err_body}")
            return False, f"HTTP {e.code}: {err_body}"
        except Exception as e:
            if "localhost" in self.base_url:
                # Retry with 127.0.0.1 if IPv6 localhost fails
                alt_base = self.base_url.replace("localhost", "127.0.0.1")
                alt_url = f"{alt_base}{endpoint}"
                try:
                    alt_req = urllib.request.Request(alt_url, data=body, headers=headers, method=method)
                    with urllib.request.urlopen(alt_req, timeout=self.timeout) as response:
                        self.base_url = alt_base
                        self.is_connected = True
                        resp_bytes = response.read()
                        try:
                            return True, json.loads(resp_bytes.decode("utf-8"))
                        except Exception:
                            return True, resp_bytes.decode("utf-8")
                except Exception:
                    pass
            self.is_connected = False
            logger.debug(f"Connection failure to {url}: {e}")
            return False, str(e)

    def check_health(self) -> bool:
        ok, res = self._request("GET", "/health")
        return ok and isinstance(res, dict) and res.get("status") == "ok"

    def register(
        self,
        hostname: str,
        ip_address: Optional[str] = None,
        mac_address: Optional[str] = None,
        os_name: Optional[str] = None,
        os_version: Optional[str] = None,
        asset_type: str = "endpoint",
        zone: str = "internal",
        criticality: str = "medium",
        agent_version: str = "1.0.0",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Registers the endpoint with CTEM.
        Tries /agent/register first; falls back to /assets/declared.
        Returns the asset_id UUID.
        """
        payload = {
            "hostname": hostname,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "os_name": os_name,
            "os_version": os_version,
            "asset_type": asset_type,
            "zone": zone,
            "criticality": criticality,
            "agent_version": agent_version,
            "metadata": metadata,
        }

        # 1. Primary endpoint: /agent/register
        ok, res = self._request("POST", "/agent/register", payload)
        if ok and isinstance(res, dict) and res.get("asset_id"):
            asset_id = res["asset_id"]
            logger.info(f"Successfully registered with CTEM via /agent/register. Asset ID: {asset_id}")
            return asset_id

        # 2. Fallback endpoint: /assets/declared
        logger.info("Attempting fallback registration via /assets/declared...")
        declared_payload = {
            "declared_by": f"ctem-agent v{agent_version}",
            "assets": [
                {
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "asset_type": asset_type,
                    "zone": zone,
                    "criticality": criticality,
                }
            ],
        }
        ok_dec, res_dec = self._request("POST", "/assets/declared", declared_payload)
        if ok_dec and isinstance(res_dec, dict) and res_dec.get("assets"):
            created_list = res_dec["assets"]
            if created_list and isinstance(created_list[0], dict) and "id" in created_list[0]:
                asset_id = created_list[0]["id"]
                logger.info(f"Fallback registration successful. Asset ID: {asset_id}")
                return asset_id

        logger.error(f"Failed to register asset with CTEM backend: {res}")
        return None

    def send_heartbeat(
        self,
        asset_id: str,
        hostname: Optional[str] = None,
        metrics: Optional[Dict[str, Any]] = None,
        listening_ports: Optional[List[Dict[str, Any]]] = None,
        agent_version: str = "1.0.0",
    ) -> bool:
        """Sends periodic host metrics and open ports to CTEM."""
        payload = {
            "asset_id": asset_id,
            "hostname": hostname,
            "metrics": metrics or {},
            "listening_ports": listening_ports,
            "agent_version": agent_version,
        }

        # Try /agent/heartbeat
        ok, res = self._request("POST", "/agent/heartbeat", payload)
        if ok:
            return True

        # Fallback to /logs/events
        summary_str = f"Agent Heartbeat [{hostname}]: CPU={metrics.get('cpu_percent')}% RAM={metrics.get('memory_percent')}% Disk={metrics.get('disk_percent')}%"
        fallback_log = {
            "source": "ctem_agent",
            "asset_id": asset_id,
            "event_type": "heartbeat",
            "severity": "low",
            "summary": summary_str,
            "occurred_at": datetime.utcnow().isoformat(),
        }
        ok_fb, _ = self._request("POST", "/logs/events", fallback_log)
        if ok_fb:
            return True

        # Buffer to queue if offline
        if self.queue:
            self.queue.enqueue("heartbeat", "/agent/heartbeat", payload)
        return False

    def send_log_event(
        self,
        event_type: str,
        severity: str = "low",
        summary: Optional[str] = None,
        asset_id: Optional[str] = None,
        source: str = "ctem_agent",
        occurred_at: Optional[str] = None,
    ) -> bool:
        """Forwards a security or system log event to /logs/events."""
        payload = {
            "source": source,
            "asset_id": asset_id,
            "event_type": event_type,
            "severity": severity,
            "summary": summary,
            "occurred_at": occurred_at or datetime.utcnow().isoformat(),
        }

        ok, res = self._request("POST", "/logs/events", payload)
        if ok:
            logger.debug(f"Forwarded log event [{severity.upper()}]: {summary}")
            return True

        logger.warning(f"Could not reach CTEM backend. Buffering log event to offline queue.")
        if self.queue:
            self.queue.enqueue("log", "/logs/events", payload)
        return False

    def send_ueba_event(
        self,
        username: str,
        event_type: str,
        source_ip: Optional[str] = None,
        occurred_at: Optional[str] = None,
    ) -> bool:
        """Forwards an authentication / user behavior event to /ueba/events."""
        payload = {
            "username": username,
            "event_type": event_type,
            "source_ip": source_ip or "127.0.0.1",
            "occurred_at": occurred_at or datetime.utcnow().isoformat(),
        }

        ok, res = self._request("POST", "/ueba/events", payload)
        if ok:
            logger.info(f"Forwarded UEBA event: {event_type} | User: {username} | IP: {source_ip}")
            return True

        logger.warning("Could not reach CTEM backend. Buffering UEBA event to offline queue.")
        if self.queue:
            self.queue.enqueue("ueba", "/ueba/events", payload)
        return False

    def check_peripheral(self, serial_number: Optional[str] = None, device_identifier: Optional[str] = None) -> bool:
        """Queries CTEM to check if a hardware peripheral is authorized."""
        payload = {}
        if serial_number:
            payload["serial_number"] = serial_number
        if device_identifier:
            payload["device_identifier"] = device_identifier

        ok, res = self._request("POST", "/peripherals/check", payload)
        if ok and isinstance(res, dict):
            return res.get("result") == "authorized"
        # Zero trust: default to false if unreachable or unauthorized
        return False

    def flush_queue(self, max_items: int = 100) -> int:
        """Flushes buffered events from the offline queue to the server."""
        if not self.queue or self.queue.size() == 0:
            return 0

        batch = self.queue.peek_batch(limit=max_items)
        if not batch:
            return 0

        delivered_ids = []
        failed_ids = []

        for item_id, event_type, endpoint, payload in batch:
            ok, _ = self._request("POST", endpoint, payload)
            if ok:
                delivered_ids.append(item_id)
            else:
                failed_ids.append(item_id)
                # If we encounter network failure, abort the batch to avoid spamming
                break

        if delivered_ids:
            self.queue.remove_ids(delivered_ids)
            logger.info(f"Successfully drained {len(delivered_ids)} buffered events from offline queue.")

        if failed_ids:
            self.queue.increment_retries(failed_ids)

        return len(delivered_ids)
