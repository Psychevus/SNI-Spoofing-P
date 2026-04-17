from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RuntimeEvent:
    timestamp: float
    name: str
    details: dict[str, Any]


class RuntimeMetrics:
    def __init__(self, max_events: int = 200) -> None:
        self.started_at = time.time()
        self._lock = threading.RLock()
        self._counters: dict[str, int] = {
            "clients_total": 0,
            "clients_rejected_capacity": 0,
            "connect_requests": 0,
            "connect_rejected": 0,
            "tunnels_established": 0,
            "raw_tunnels_established": 0,
            "fake_ack_total": 0,
            "upstream_failures": 0,
            "relay_finished": 0,
            "bytes_client_to_upstream": 0,
            "bytes_upstream_to_client": 0,
        }
        self._gauges: dict[str, int] = {
            "active_connections": 0,
        }
        self._events: deque[RuntimeEvent] = deque(maxlen=max_events)

    def increment(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + value

    def gauge(self, name: str, value: int) -> None:
        with self._lock:
            self._gauges[name] = value

    def add_bytes(self, name: str, value: int) -> None:
        if value > 0:
            self.increment(name, value)

    def event(self, name: str, **details: Any) -> None:
        clean_details = {key: value for key, value in details.items() if value is not None}
        with self._lock:
            self._events.append(RuntimeEvent(time.time(), name, clean_details))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self.started_at, 3),
                "started_at": self.started_at,
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "events": [
                    {
                        "timestamp": event.timestamp,
                        "name": event.name,
                        "details": event.details,
                    }
                    for event in list(self._events)
                ],
            }
