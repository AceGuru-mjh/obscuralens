"""
Core-platform benchmarks: validators, kind detection, the SQLite cache,
rate limiting, metrics, formatting, coordinate maths, dorks and the data
catalog.

Every benchmark is a pure, offline, deterministic measurement of code the
platform executes on every lookup: no network, no configuration writes, no
dependence on wall-clock time.  Inputs are fixed literals (or
``random.Random(42)`` series where volume matters).  The two stateful
groups isolate themselves under the caller's workdir:

* ``cache`` builds a private :class:`~obscuralens.core.cache.HttpCache`
  pointed at ``<workdir>/cache/http_cache.db`` and temporarily forces
  ``config.app_config.cache_enabled`` on (restored in teardown) so the
  bench measures real get/set work regardless of the ambient setting;
* nothing else in this module touches disk at all.

Register everything with :func:`build_benches` (consumed by
:mod:`benchmarks.run`).
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

from obscuralens.core.cache import HttpCache
from obscuralens.core.metrics import NetworkMetrics
from obscuralens.core.ratelimit import RateLimiter
from obscuralens.investigate import detect_kind
from obscuralens.utils import data_catalog
from obscuralens.utils.coordinate_math import (
    geohash_to_latlon,
    haversine_km,
    latlon_to_dms,
    latlon_to_geohash,
    latlon_to_mgrs,
    latlon_to_utm,
    utm_to_latlon,
)
from obscuralens.utils.dorks import KINDS_WITH_DORKS, dorks_for
from obscuralens.utils.formatting import fmt_value, label, rows_from_fields
from obscuralens.utils.validators import (
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_username,
)

from .harness import BenchSpec, state_dir

# --- fixed inputs (deterministic, no reseeding needed) -----------------------

#: One valid + one invalid sample per validator, exercised in every call.
IP_SAMPLES = ('8.8.8.8', '2001:4860:4860::8888', '999.999.1.1', 'not-an-ip')
EMAIL_SAMPLES = ('user@example.com', 'alice.smith+tag@company.co.uk',
                 'broken-at-example.com', '@no-local-part.net')
DOMAIN_SAMPLES = ('example.com', 'www.security-platform.org', 'no-tld-',
                  '-leading-dash.example')
USERNAME_SAMPLES = ('some_user', 'osint_analyst42', 'a', 'way_too_long_username_x')
PHONE_SAMPLES = ('+14155552671', '081234567890', '12345', 'call-me-maybe')

#: One sample per supported kind (all 20 classify through detect_kind).
DETECT_SAMPLES: Tuple[Tuple[str, str], ...] = (
    ('ip', '8.8.8.8'),
    ('phone', '+14155552671'),
    ('username', 'some_user'),
    ('email', 'user@example.com'),
    ('domain', 'example.com'),
    ('url', 'https://example.com/page'),
    ('crypto', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'),
    ('hash', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    ('cve', 'CVE-2021-44228'),
    ('asn', 'AS15169'),
    ('mac', 'b8:27:eb:dc:aa:bb'),
    ('iban', 'DE89370400440532013000'),
    ('imei', '490154203237518'),
    ('coords', '48.8584, 2.2945'),
    ('vin', '1HGCM82633A004352'),
    ('flight', 'BA1234'),
    ('mmsi', '366999888'),
    ('app', 'pypi:requests'),
    ('bssid', 'b827ebdcaabb'),
    ('plate', 'DE:B-AB 1234'),
)

#: Fixed coordinates exercising both hemispheres and several UTM zones.
COORDS: Tuple[Tuple[float, float], ...] = (
    (48.8584, 2.2945),      # Paris, zone 31U
    (51.5074, -0.1278),     # London, zone 30U
    (35.6762, 139.6503),    # Tokyo, zone 54S
    (-33.8688, 151.2093),   # Sydney, zone 56H
    (-23.5505, -46.6333),   # Sao Paulo, zone 23K
    (40.7128, -74.0060),    # New York, zone 18T
    (55.7558, 37.6173),     # Moscow, zone 37U
    (-1.2921, 36.8219),     # Nairobi, zone 37M
    (64.1466, -21.9426),    # Reykjavik, zone 27W
    (0.0, 0.0),
)

#: Dork targets, one per kind that ships dorks.
DORK_SAMPLES: Dict[str, str] = {
    'ip': '8.8.8.8',
    'domain': 'example.com',
    'email': 'user@example.com',
    'username': 'some_user',
    'phone': '+14155552671',
    'url': 'https://example.com/page',
    'crypto': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
    'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'cve': 'CVE-2021-44228',
    'asn': 'AS15169',
    'mac': 'b8:27:eb:dc:aa:bb',
    'coords': '48.8584, 2.2945',
    'iban': 'DE89370400440532013000',
}

#: Data-catalog lookups mixing hits, misses and case variants.
CATALOG_SAMPLES = (
    ('country', 'US'), ('country', 'usa'), ('country', 'XX'),
    ('port', 22), ('port', '443'), ('port', 99999),
    ('cwe', 'CWE-79'), ('cwe', 'cwe-89'), ('cwe', 'CWE-99999'),
    ('http_status', 404), ('http_status', '500'), ('http_status', 999),
)

#: Synthetic tracker-style field map for the formatting benches.
FIELD_MAP: Dict[str, Any] = {
    'ip': '8.8.8.8', 'country': 'United States', 'country_code': 'US',
    'region': 'California', 'city': 'Mountain View', 'postal': '94043',
    'latitude': 37.4056, 'longitude': -122.0775, 'asn': 'AS15169',
    'org': 'Google LLC', 'reverse_dns': 'dns.google', 'timezone': 'America/Los_Angeles',
    'is_proxy': False, 'is_tor': True, 'ports': [53, 443, 8443],
    'vulns': [], 'hostnames': ['dns.google'], 'tags': ['dns', 'google'],
    'reputation': 'harmless', 'malicious': 0, 'suspicious': 0,
    'last_update': '2024-01-01', 'coordinates_by_source': [],
    'source': 'ipwhois.app', 'field_sources': {'country': ['ipwhois.app']},
}


# --- helper ------------------------------------------------------------------

def _loop(samples: Tuple[Any, ...], fn: Callable[[Any], Any]) -> Callable[[], Any]:
    """Wrap a per-sample callable into a zero-argument batch runner."""
    def run() -> None:
        for _ in range(10):
            for sample in samples:
                fn(sample)
    return run


# --- group builders ----------------------------------------------------------

def build_benches(workdir: Optional[str] = None) -> List[BenchSpec]:
    """
    Build every core benchmark.

    Args:
        workdir: optional caller-owned directory for on-disk state (the
            cache group); when None the group self-manages a tempdir that
            its teardown removes.

    Returns:
        :class:`~benchmarks.harness.BenchSpec` list, registration order.
    """
    specs: List[BenchSpec] = []
    specs.extend(_validator_benches())
    specs.extend(_detect_benches())
    specs.extend(_cache_benches(workdir))
    specs.extend(_ratelimit_benches())
    specs.extend(_metrics_benches())
    specs.extend(_formatting_benches())
    specs.extend(_coordinate_benches())
    specs.extend(_dorks_benches())
    specs.extend(_catalog_benches())
    return specs


def _validator_benches() -> List[BenchSpec]:
    """validate_* over valid + invalid samples (10 x sample-list per call)."""
    groups = (
        ('validators_ip', validate_ip, IP_SAMPLES),
        ('validators_email', validate_email, EMAIL_SAMPLES),
        ('validators_domain', validate_domain, DOMAIN_SAMPLES),
        ('validators_username', validate_username, USERNAME_SAMPLES),
        ('validators_phone', validate_phone, PHONE_SAMPLES),
    )
    return [BenchSpec(name, _loop(samples, fn), repeat=5, number=50, tags=('core',))
            for name, fn, samples in groups]


def _detect_benches() -> List[BenchSpec]:
    """detect_kind over one sample per supported kind (20 kinds)."""

    def detect_all() -> None:
        for _ in range(10):
            for _, sample in DETECT_SAMPLES:
                detect_kind(sample)

    return [BenchSpec('detect_kind_all20', detect_all, repeat=5, number=20,
                      tags=('core',))]


def _cache_benches(workdir: Optional[str]) -> List[BenchSpec]:
    """
    HttpCache get/set against a private temp SQLite database.

    The bench owns an isolated :class:`HttpCache` (never the shared
    singleton) and forces ``config.app_config.cache_enabled`` on for its
    duration so both the ambient "enabled" default and the test-suite
    "disabled" environment measure real cache work.  The previous setting
    is restored in teardown, along with the tempdir when self-managed.
    """
    from obscuralens.config import config

    state: Dict[str, Any] = {}

    def setup() -> None:
        path, cleanup = state_dir(workdir, 'cache')
        state['cleanup'] = cleanup
        state['old_enabled'] = config.app_config.cache_enabled
        config.app_config.cache_enabled = True
        cache = HttpCache(path=str(path / 'http_cache.db'), default_ttl=3600)
        state['cache'] = cache
        for i in range(100):
            cache.set('bench', f'https://example.com/api/{i}',
                      {'data': {'index': i, 'payload': 'x' * 96}})

    def teardown() -> None:
        config.app_config.cache_enabled = state.pop('old_enabled', True)
        state.pop('cache', None)
        cleanup = state.pop('cleanup', None)
        if cleanup is not None:
            cleanup()

    def get_hits() -> None:
        cache = state['cache']
        for i in range(100):
            cache.get('bench', f'https://example.com/api/{i % 100}')

    def get_misses() -> None:
        cache = state['cache']
        for i in range(100):
            cache.get('bench', f'https://missing.example.com/{i}')

    def set_replaces() -> None:
        cache = state['cache']
        for i in range(100):
            cache.set('bench', f'https://example.com/api/{i % 50}',
                      {'data': {'index': i, 'payload': 'y' * 96}})

    return [
        BenchSpec('cache_get_hit', get_hits, repeat=5, number=20,
                  tags=('core', 'cache'), setup=setup, teardown=teardown),
        BenchSpec('cache_get_miss', get_misses, repeat=5, number=20,
                  tags=('core', 'cache'), setup=setup, teardown=teardown),
        BenchSpec('cache_set_replace', set_replaces, repeat=5, number=20,
                  tags=('core', 'cache'), setup=setup, teardown=teardown),
    ]


def _ratelimit_benches() -> List[BenchSpec]:
    """
    Token-bucket acquire/refill over rotating hosts.

    A private limiter with a very high rate refills instantly, so every
    acquire exercises lock, bucket lookup, elapsed-time refill and token
    deduction without ever sleeping - the measurement is pure overhead.
    """
    limiter = RateLimiter(rate=1_000_000.0, burst=4)
    urls = tuple(f'https://host-{i % 64}.example.com/api/v1/resource'
                 for i in range(64))
    hosts = tuple(f'host-{i % 64}.example.com' for i in range(64))

    def acquire_urls() -> None:
        for _ in range(4):
            for url in urls:
                limiter.acquire(url)

    def acquire_hosts() -> None:
        for _ in range(4):
            for host in hosts:
                limiter.acquire(host)

    return [
        BenchSpec('ratelimit_acquire_url', acquire_urls, repeat=5, number=10,
                  tags=('core',)),
        BenchSpec('ratelimit_acquire_host', acquire_hosts, repeat=5, number=10,
                  tags=('core',)),
    ]


def _metrics_benches() -> List[BenchSpec]:
    """NetworkMetrics counter churn on a private instance (1000 ops/call)."""

    def record_ops() -> None:
        fresh = NetworkMetrics()
        for i in range(1000):
            fresh.record_request(f'https://example.com/{i}')
            fresh.record_cache(i % 2 == 0)
            if i % 50 == 0:
                fresh.record_failure('timeout after 30s')
            fresh.record_bytes(1024)
        fresh.record_sources(ok=3, failed=1)
        fresh.snapshot()

    return [BenchSpec('metrics_record_ops', record_ops, repeat=5, number=20,
                      tags=('core',))]


def _formatting_benches() -> List[BenchSpec]:
    """label / fmt_value / rows_from_fields over a synthetic field map."""

    def rows() -> None:
        for _ in range(20):
            rows_from_fields(FIELD_MAP)

    def labels() -> None:
        for _ in range(20):
            for key in FIELD_MAP:
                label(key)
                fmt_value(key, FIELD_MAP[key])

    return [
        BenchSpec('formatting_rows_from_fields', rows, repeat=5, number=20,
                  tags=('core',)),
        BenchSpec('formatting_label_fmt_value', labels, repeat=5, number=20,
                  tags=('core',)),
    ]


def _coordinate_benches() -> List[BenchSpec]:
    """Pure coordinate conversions over the fixed COORDS list (10 points)."""

    def haversine() -> None:
        for _ in range(10):
            for lat, lon in COORDS:
                haversine_km(lat, lon, -lat, -lon)

    def to_utm() -> None:
        for _ in range(10):
            for lat, lon in COORDS:
                latlon_to_utm(lat, lon)

    def from_utm() -> None:
        for _ in range(10):
            for lat, lon in COORDS:
                zone, band, easting, northing = latlon_to_utm(lat, lon)
                utm_to_latlon(zone, easting, northing, band)

    def to_geohash() -> None:
        for _ in range(10):
            for lat, lon in COORDS:
                latlon_to_geohash(lat, lon)

    def from_geohash() -> None:
        for _ in range(10):
            for lat, lon in COORDS:
                geohash_to_latlon(latlon_to_geohash(lat, lon))

    def to_mgrs() -> None:
        for _ in range(10):
            for lat, lon in COORDS:
                latlon_to_mgrs(lat, lon)

    def to_dms() -> None:
        for _ in range(10):
            for lat, lon in COORDS:
                latlon_to_dms(lat, axis='lat')
                latlon_to_dms(lon, axis='lon')

    return [
        BenchSpec('coord_haversine_km', haversine, repeat=5, number=20,
                  tags=('core', 'geo')),
        BenchSpec('coord_latlon_to_utm', to_utm, repeat=5, number=20,
                  tags=('core', 'geo')),
        BenchSpec('coord_utm_to_latlon', from_utm, repeat=5, number=20,
                  tags=('core', 'geo')),
        BenchSpec('coord_latlon_to_geohash', to_geohash, repeat=5, number=20,
                  tags=('core', 'geo')),
        BenchSpec('coord_geohash_to_latlon', from_geohash, repeat=5, number=20,
                  tags=('core', 'geo')),
        BenchSpec('coord_latlon_to_mgrs', to_mgrs, repeat=5, number=20,
                  tags=('core', 'geo')),
        BenchSpec('coord_latlon_to_dms', to_dms, repeat=5, number=20,
                  tags=('core', 'geo')),
    ]


def _dorks_benches() -> List[BenchSpec]:
    """dorks_for over one target per dork-shipping kind (13 kinds)."""

    def all_kinds() -> None:
        for _ in range(10):
            for kind in KINDS_WITH_DORKS:
                dorks_for(kind, DORK_SAMPLES[kind])

    return [BenchSpec('dorks_all_kinds', all_kinds, repeat=5, number=20,
                      tags=('core',))]


def _catalog_benches() -> List[BenchSpec]:
    """Bundled data-catalog lookups plus a full country-name scan."""

    def lookups() -> None:
        for _ in range(20):
            for pack, key in CATALOG_SAMPLES:
                if pack == 'country':
                    data_catalog.country(key)
                elif pack == 'port':
                    data_catalog.port_service(key)
                elif pack == 'cwe':
                    data_catalog.cwe(key)
                else:
                    data_catalog.http_status(key)

    def search() -> None:
        for _ in range(20):
            data_catalog.search_countries('united')
            data_catalog.search_countries('stan')

    return [
        BenchSpec('catalog_lookups', lookups, repeat=5, number=20,
                  tags=('core', 'catalog')),
        BenchSpec('catalog_search_countries', search, repeat=5, number=10,
                  tags=('core', 'catalog')),
    ]


__all__ = ['build_benches']
