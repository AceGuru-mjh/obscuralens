"""
Per-host token-bucket rate limiting.

Public OSINT endpoints are shared infrastructure: hammering them gets the
tool blocked and is impolite. Every HTTP request passes through a per-host
bucket configured by ``app.requests_per_second``. A rate of 0 disables
throttling.

v6.1 adds ``HOST_RATE_OVERRIDES``: hosts whose published limits sit below
the user-configured default get their own slower buckets, so a 12-worker
parallel sweep cannot trip a 429 by bursting a fragile community API.
"""

import threading
import time
from typing import Any, Dict
from urllib.parse import urlparse

#: Hosts with documented or empirically verified limits below the default
#: per-host rate. Rates are requests per second. Applied on top of (never
#: instead of) the global ``app.requests_per_second``: the slower of the
#: two wins for these hosts.
HOST_RATE_OVERRIDES: Dict[str, float] = {
    # Ethplorer's keyless ``freekey`` tier throttles after a couple of
    # rapid requests (verified live: second immediate request -> 429).
    'api.ethplorer.io': 0.4,
    # Community ADS-B aggregator; aggressive nginx-level 429s (verified).
    'api.adsb.lol': 0.8,
    # Documented "1 per 1 minute" on the public API (verified live).
    'api.ransomware.live': 0.02,
    # Community Cosmos LCD proxy; be a polite tenant.
    'rest.cosmos.directory': 0.5,
    # NEAR Foundation public RPC.
    'rpc.mainnet.near.org': 0.5,
    # TRON's official public node.
    'api.trongrid.io': 2.0,
    # Ava Labs public C-chain RPC.
    'api.avax.network': 2.0,
    # Community XRP cluster.
    'xrplcluster.com': 1.0,
}


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

    def rate_for(self, host: str) -> float:
        """
        Effective rate for a host: the slower of the configured default
        and any per-host override (v6.1). A configured rate of 0 disables
        throttling entirely, overrides included.
        """
        if self._rate <= 0:
            return 0.0
        override = HOST_RATE_OVERRIDES.get(host)
        if override is not None and override < self._rate:
            return override
        return self._rate

    def _tokens(self, host: str, now: float) -> float:
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = {'tokens': float(self._burst), 'updated': now}
            self._buckets[host] = bucket
        elapsed = now - bucket['updated']
        bucket['tokens'] = min(float(self._burst),
                               bucket['tokens'] + elapsed * self.rate_for(host))
        bucket['updated'] = now
        return bucket['tokens']

    def acquire(self, url_or_host: str) -> float:
        """
        Block until a token is available for the host.

        Returns the number of seconds spent waiting (0 when not throttled).
        """
        if self._rate <= 0:
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
                needed = (1.0 - tokens) / self.rate_for(host)
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
                'overridden_hosts': sorted(
                    h for h in self._buckets if h in HOST_RATE_OVERRIDES),
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
