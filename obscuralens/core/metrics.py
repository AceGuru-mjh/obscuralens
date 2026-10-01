"""
Lightweight, thread-safe network metrics for the current process.

Used by `obscuralens stats --network` and logged in debug mode so users can see
how much traffic a lookup actually generated.
"""

import threading
from typing import Any, Dict


class NetworkMetrics:
    """Counters for HTTP activity."""

    def __init__(self):
        self._lock = threading.Lock()
        self.requests = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.failures = 0
        self.timeouts = 0
        self.bytes_received = 0
        self.sources_used = 0
        self.sources_failed = 0

    def reset(self) -> None:
        with self._lock:
            self.requests = 0
            self.cache_hits = 0
            self.cache_misses = 0
            self.failures = 0
            self.timeouts = 0
            self.bytes_received = 0
            self.sources_used = 0
            self.sources_failed = 0

    def record_request(self, url: str) -> None:
        with self._lock:
            self.requests += 1

    def record_cache(self, hit: bool) -> None:
        with self._lock:
            if hit:
                self.cache_hits += 1
            else:
                self.cache_misses += 1

    def record_failure(self, error: str = '') -> None:
        with self._lock:
            self.failures += 1
            if 'timeout' in (error or '').lower():
                self.timeouts += 1

    def record_bytes(self, count: int) -> None:
        if count > 0:
            with self._lock:
                self.bytes_received += count

    def record_sources(self, ok: int, failed: int) -> None:
        with self._lock:
            self.sources_used += ok
            self.sources_failed += failed

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            total_lookups = self.cache_hits + self.cache_misses
            hit_rate = (self.cache_hits / total_lookups * 100) if total_lookups else 0.0
            return {
                'requests': self.requests,
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'cache_hit_rate': round(hit_rate, 1),
                'failures': self.failures,
                'timeouts': self.timeouts,
                'bytes_received': self.bytes_received,
                'sources_used': self.sources_used,
                'sources_failed': self.sources_failed,
            }


metrics = NetworkMetrics()
