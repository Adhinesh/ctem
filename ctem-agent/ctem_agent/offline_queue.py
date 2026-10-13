import os
import json
import time
import sqlite3
import threading
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger("ctem_agent.queue")


class OfflineQueue:
    """
    Persistent SQLite-backed queue for buffering logs and events
    during network dropouts or backend maintenance.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS queue_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        retry_count INTEGER DEFAULT 0,
                        created_at REAL NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_created ON queue_events(created_at)")
                conn.commit()

    def enqueue(self, event_type: str, endpoint: str, payload: Dict[str, Any]) -> bool:
        """Buffers an event to local disk."""
        payload_str = json.dumps(payload)
        now = time.time()
        try:
            with self._lock:
                with self._get_connection() as conn:
                    conn.execute(
                        "INSERT INTO queue_events (event_type, endpoint, payload, created_at) VALUES (?, ?, ?, ?)",
                        (event_type, endpoint, payload_str, now),
                    )
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to buffer event to queue: {e}")
            return False

    def peek_batch(self, limit: int = 50) -> List[Tuple[int, str, str, Dict[str, Any]]]:
        """Returns the oldest unacknowledged batch of events."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT id, event_type, endpoint, payload FROM queue_events ORDER BY id ASC LIMIT ?",
                    (limit,)
                )
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    try:
                        results.append((row["id"], row["event_type"], row["endpoint"], json.loads(row["payload"])))
                    except Exception:
                        pass
                return results

    def remove_ids(self, ids: List[int]):
        """Removes delivered events from the queue."""
        if not ids:
            return
        with self._lock:
            with self._get_connection() as conn:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM queue_events WHERE id IN ({placeholders})", ids)
                conn.commit()

    def increment_retries(self, ids: List[int]):
        """Increments retry counters on failed delivery."""
        if not ids:
            return
        with self._lock:
            with self._get_connection() as conn:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"UPDATE queue_events SET retry_count = retry_count + 1 WHERE id IN ({placeholders})", ids)
                conn.commit()

    def size(self) -> int:
        """Returns the count of waiting items in the buffer."""
        try:
            with self._lock:
                with self._get_connection() as conn:
                    cursor = conn.execute("SELECT COUNT(*) FROM queue_events")
                    return cursor.fetchone()[0]
        except Exception:
            return 0
