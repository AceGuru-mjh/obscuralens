"""
Per-host token-bucket rate limiting.

Public OSINT endpoints are shared infrastructure: hammering them gets the
tool blocked and is impolite. Every HTTP request passes through a per-host
bucket configured by ``app.requests_per_second``. A rate of 0 disables
throttling.
"""

import threading
import time
from typing import Any, Dict
from urllib.parse import urlparse


class RateLimiter:
    """Thread-safe token bucket, one bucket per host."""

    def __init__(self, rate: float = 8.0, burst: int = 4):
        self._rate = rate
        self._burst = max(1, burst)
        self._lock = threading.Lock()
        self._buckets: Dict[str, Dict[str, float]] = {}
        self.waits = 0

    def configure(self, rate: float, burst: int = 4) -> None:
        with self._lock:
            self._rate = rate
            self._burst = max(1, burst)
            self._buckets.clear()

    @staticmethod
    def host_of(url_or_host: str) -> str:
        if '://' in url_or_host:
            return (urlparse(url_or_host).hostname or '').lower()
        return url_or_host.lower()

    def _tokens(self, host: str, now: float) -> float:
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = {'tokens': float(self._burst), 'updated': now}
            self._buckets[host] = bucket
        elapsed = now - bucket['updated']
        bucket['tokens'] = min(float(self._burst),
                               bucket['tokens'] + elapsed * self._rate)
        bucket['updated'] = now
        return bucket['tokens']

    def acquire(self, url_or_host: str) -> float:
        """
        Block until a token is available for the host.

        Returns the number of seconds spent waiting (0 when not throttled).
        """
        rate = self._rate
        if rate <= 0:
            return 0.0

        host = self.host_of(url_or_host)
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                tokens = self._tokens(host, now)
                if tokens >= 1.0:
                    self._buckets[host]['tokens'] = tokens - 1.0
                    return waited
                needed = (1.0 - tokens) / rate
            time.sleep(needed)
            waited += needed
            self.waits += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'rate_per_second': self._rate,
                'burst': self._burst,
                'hosts': len(self._buckets),
                'waits': self.waits,
            }


# Shared limiter, configured from app.request_per_second on each call.
limiter = RateLimiter()


def acquire(url: str) -> float:
    """Convenience wrapper that applies the live configured rate."""
    from ..config import config
    rate = float(config.app_config.requests_per_second or 0)
    if rate != limiter._rate:  # keep runtime changes in effect
        limiter.configure(rate)
    return limiter.acquire(url)
