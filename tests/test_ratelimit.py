"""Rate limiter tests."""

import time

from obscuralens.core.ratelimit import RateLimiter


def test_host_of():
    assert RateLimiter.host_of('https://API.Example.COM/path') == 'api.example.com'
    assert RateLimiter.host_of('example.com:443') == 'example.com:443'


def test_zero_rate_is_a_noop():
    limiter = RateLimiter(rate=0)
    started = time.monotonic()
    for _ in range(5):
        limiter.acquire('https://example.com')
    assert time.monotonic() - started < 0.2


def test_burst_then_throttle():
    limiter = RateLimiter(rate=5.0, burst=1)
    started = time.monotonic()
    limiter.acquire('https://example.com')
    limiter.acquire('https://example.com')
    elapsed = time.monotonic() - started
    # Second call must wait ~1/5s for a token.
    assert elapsed >= 0.1
    assert limiter.snapshot()['waits'] >= 1


def test_hosts_are_independent():
    limiter = RateLimiter(rate=1.0, burst=1)
    started = time.monotonic()
    limiter.acquire('https://a.test')
    limiter.acquire('https://b.test')
    assert time.monotonic() - started < 0.5
