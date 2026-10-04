"""
Optional FastAPI web UI and JSON REST API for ObscuraLens v5.0.

This module is an *extra*: the core package and CLI never import it, and
FastAPI/uvicorn are imported lazily inside :func:`create_app` / :func:`serve`
so that ``import obscuralens`` keeps working when the optional dependencies
are absent. Install them with::

    pip install "obscuralens[web]"

What the server exposes
-----------------------
* the single-page application served from ``web/static`` at ``/`` (dark and
  light themes, ten views, command palette — no external assets, works
  offline),
* every tracker (20 kinds), the investigation engine, risk scoring,
  timelines, correlation, cases, the watchlist, exports and statistics as
  JSON under ``/api`` (see ``docs/api.md``),
* the v5.0 analyst toolbox (encoders, JWT, hash identification, coordinate
  conversion, entity extraction, typosquat generation), local file analysis
  (EXIF + steganography — bytes are analysed in-process and never leave the
  machine), batch lookups, self-contained HTML reports, pattern-of-life
  analysis, webhook alerts and runtime settings/API-key management.

All endpoints return JSON unless documented otherwise; errors are plain
``{'detail': ...}`` responses with matching HTTP status codes.
"""

import asyncio
import contextlib
import json
import threading
from dataclasses import fields as dataclass_fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .. import __version__
from .. import investigate as investigate_module
from ..core.cache import cache
from ..core.metrics import metrics
from ..database import db, set_save_hook
from ..trackers import (
    AppTracker,
    ASNTracker,
    BSSIDTracker,
    CoordsTracker,
    CryptoTracker,
    CVETracker,
    DomainTracker,
    EmailTracker,
    FlightTracker,
    HashTracker,
    IBANTracker,
    IMEITracker,
    IPTracker,
    MACTracker,
    MMSITracker,
    PhoneTracker,
    PlateTracker,
    URLTracker,
    UsernameTracker,
    VINTracker,
)
from ..utils.validators import (
    validate_app,
    validate_asn,
    validate_bssid,
    validate_coords,
    validate_crypto_address,
    validate_cve,
    validate_domain,
    validate_email,
    validate_flight,
    validate_hash,
    validate_iban,
    validate_imei,
    validate_ip,
    validate_mac,
    validate_mmsi,
    validate_phone,
    validate_plate,
    validate_url,
    validate_username,
    validate_vin,
)
from ..watchlist import set_check_hook, watchlist

KINDS = ('ip', 'phone', 'username', 'email', 'domain', 'url', 'crypto',
         'hash', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords',
         # v6.0 kinds
         'vin', 'flight', 'mmsi', 'app', 'bssid', 'plate')

_VALIDATORS: Dict[str, Callable[[str], Any]] = {
    'ip': validate_ip,
    'phone': validate_phone,
    'username': validate_username,
    'email': validate_email,
    'domain': validate_domain,
    'url': validate_url,
    'crypto': validate_crypto_address,
    'hash': validate_hash,
    'cve': validate_cve,
    'asn': validate_asn,
    'mac': validate_mac,
    'iban': validate_iban,
    'imei': validate_imei,
    'coords': validate_coords,
    'vin': validate_vin,
    'flight': validate_flight,
    'mmsi': validate_mmsi,
    'app': validate_app,
    'bssid': validate_bssid,
    'plate': validate_plate,
}

_TRACKERS: Dict[str, Any] = {
    'ip': IPTracker,
    'phone': PhoneTracker,
    'username': UsernameTracker,
    'email': EmailTracker,
    'domain': DomainTracker,
    'url': URLTracker,
    'crypto': CryptoTracker,
    'hash': HashTracker,
    'cve': CVETracker,
    'asn': ASNTracker,
    'mac': MACTracker,
    'iban': IBANTracker,
    'imei': IMEITracker,
    'coords': CoordsTracker,
    'vin': VINTracker,
    'flight': FlightTracker,
    'mmsi': MMSITracker,
    'app': AppTracker,
    'bssid': BSSIDTracker,
    'plate': PlateTracker,
}

# Field each tracker uses to echo back the queried target.
_TARGET_KEY = {
    'ip': 'ip',
    'phone': 'phone_number',
    'username': 'username',
    'email': 'email',
    'domain': 'domain',
    'url': 'url',
    'crypto': 'address',
    'hash': 'hash',
    'cve': 'cve',
    'asn': 'asn',
    'mac': 'mac',
    'iban': 'iban',
    'imei': 'imei',
    'coords': 'coords',
    'vin': 'vin',
    'flight': 'flight',
    'mmsi': 'mmsi',
    'app': 'app',
    'bssid': 'bssid',
    'plate': 'plate',
}

# Registry metadata for GET /api/kinds (label, example, one-line blurb).
_KIND_INFO: Dict[str, Dict[str, str]] = {
    'ip': {'label': 'IP address', 'example': '8.8.8.8',
           'blurb': 'Geo, ASN, reverse DNS, ports, threat intel'},
    'domain': {'label': 'Domain', 'example': 'example.com',
               'blurb': 'Registration, DNS posture, CT logs, archives'},
    'email': {'label': 'Email', 'example': 'user@example.com',
              'blurb': 'Breach exposure, reputation, linked profiles'},
    'username': {'label': 'Username', 'example': 'johndoe',
                 'blurb': '45 platforms, honest 3-state verdicts'},
    'phone': {'label': 'Phone', 'example': '+14155552671',
              'blurb': 'E.164 formatting, carrier hints, geo enrichment'},
    'url': {'label': 'URL', 'example': 'https://example.com/page',
            'blurb': 'Redirects, urlscan, archives, safety verdicts'},
    'crypto': {'label': 'Crypto address', 'example': '1BoatSLRHtKN42kdutzZbHwYQeMwfQ7HNo',
               'blurb': 'Balances and activity on BTC/ETH/LTC/DOGE'},
    'hash': {'label': 'File hash', 'example': 'e3b0c44298fc1c149afbf4c8996fb924',
             'blurb': 'Malware family, file names, detections'},
    'cve': {'label': 'CVE', 'example': 'CVE-2021-44228',
            'blurb': 'CVSS, affected products, EPSS probability'},
    'asn': {'label': 'AS number', 'example': 'AS15169',
            'blurb': 'Holder, prefixes, peers'},
    'mac': {'label': 'MAC address', 'example': 'b8:27:eb:aa:bb:cc',
            'blurb': 'Vendor from the offline IEEE OUI pack + two APIs'},
    'iban': {'label': 'IBAN', 'example': 'DE89370400440532013000',
             'blurb': 'Checksum, issuing bank, country structure'},
    'imei': {'label': 'IMEI', 'example': '356938035643809',
             'blurb': 'TAC decomposition, manufacturer, Luhn validity'},
    'coords': {'label': 'Coordinates', 'example': '48.8584, 2.2945',
               'blurb': 'Every format, reverse geocode, elevation, solar'},
    # v6.0 kinds
    'vin': {'label': 'VIN', 'example': '1M8GDM9AXKP042788',
            'blurb': 'ISO 3779 decode, WMI registry, NHTSA vPIC vehicle data'},
    'flight': {'label': 'Flight number', 'example': 'BA2490',
               'blurb': 'Airline pack, IATA/ICAO codes, live status via API key'},
    'mmsi': {'label': 'MMSI', 'example': '366910000',
             'blurb': 'ITU station class, MID flag state, AIS identity anatomy'},
    'app': {'label': 'Software package', 'example': 'pypi:requests',
            'blurb': 'Registry records + OSV CVEs for pypi/npm/crate/docker/github'},
    'bssid': {'label': 'WiFi BSSID', 'example': '00:1A:2B:3C:4D:5E',
              'blurb': 'OUI vendor, EUI-48 anatomy, crowd-sourced geolocation'},
    'plate': {'label': 'License plate', 'example': 'DE:B-AB 1234',
              'blurb': 'Country format matching, German city codes, style heuristics'},
}

# Friendly descriptions of the keyed services (GET /api/keys).
_SERVICE_INFO: Dict[str, str] = {
    'shodan': 'Shodan InternetDB is keyless; a key unlocks full host intel',
    'haveibeenpwned': 'Breach exposure for email lookups',
    'hunter': 'Email finder/verifier enrichment',
    'virustotal': 'URL, hash and IP verdicts',
    'ipinfo': 'Detailed IP geo and ASN',
    'numverify': 'Phone validation extras',
    'abuseipdb': 'IP abuse confidence scores',
    'google_maps': 'Geocoding fallback for phone/coords enrichment',
    'etherscan': 'Ethereum address and transaction detail',
    'greynoise': 'Internet scanner classification for IPs',
    'otx': 'Higher AlienVault OTX rate limits (works keyless)',
    'google_safe_browsing': 'URL safety verdicts',
    'github': 'Higher GitHub search rate limits (works keyless)',
    'nvd': 'Higher NVD 2.0 CVE rate limits (works keyless)',
    'malwarebazaar': 'abuse.ch Auth-Key for hash lookups',
    'securitytrails': 'Historical DNS and subdomain intel',
    'llm': 'OpenAI-compatible endpoint for experimental summaries',
}

# Settings the web UI may never read or change (secrets live in /api/keys).
_SETTINGS_BLOCKLIST = frozenset({
    'sqlite_path', 'cache_path', 'report_dir', 'chart_dir', 'proxy',
})

#: Static SPA directory shipped inside the package.
STATIC_DIR = Path(__file__).resolve().parent / 'static'

#: Hard cap for uploaded files in the EXIF/stego endpoints (bytes).
MAX_UPLOAD_BYTES = 16 * 1024 * 1024

#: Hard cap for /api/tools/batch targets.
MAX_BATCH_TARGETS = 25

#: Heartbeat interval for the SSE stream (seconds).
STREAM_HEARTBEAT_S = 15.0

#: Topics a client declared via POST /api/stream/subscribe (empty = all).
_STREAM_TOPICS: frozenset = frozenset()


class _EventBus:
    """
    In-process publish/subscribe bus feeding ``GET /api/stream``.

    Lookups run in the FastAPI threadpool (sync endpoints) and
    ``db.save_query`` fires its hook from whichever thread called it, so
    ``publish`` must be callable from *any* thread. Each subscriber records
    the event loop its ``asyncio.Queue`` belongs to; cross-thread deliveries
    hop through ``loop.call_soon_threadsafe`` so the loop (not the publisher)
    touches the queue. Queues are capped — a slow client drops its oldest
    buffered events instead of growing without bound.
    """

    def __init__(self, max_queue: int = 100):
        self._max_queue = max_queue
        self._lock = threading.Lock()
        self._subscribers: List[Dict[str, Any]] = []

    def subscribe(self) -> 'asyncio.Queue':
        """
        Register a queue bound to the caller's running event loop.

        Called from inside the async stream endpoint, so the loop is live;
        a headless caller (unit tests) gets ``loop=None`` and synchronous
        best-effort delivery.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue)
        try:
            loop: Optional[asyncio.AbstractEventLoop] = \
                asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        with self._lock:
            self._subscribers.append({'queue': queue, 'loop': loop})
        return queue

    def unsubscribe(self, queue: 'asyncio.Queue') -> bool:
        """Drop one subscriber; returns True when it was actually found."""
        with self._lock:
            before = len(self._subscribers)
            self._subscribers = [sub for sub in self._subscribers
                                 if sub['queue'] is not queue]
            return len(self._subscribers) < before

    def subscriber_count(self) -> int:
        """Number of live stream subscribers (for status frames/tests)."""
        with self._lock:
            return len(self._subscribers)

    @staticmethod
    def _offer(queue: 'asyncio.Queue', payload: Any) -> None:
        """Non-blocking enqueue; a full queue drops its oldest event."""
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            with contextlib.suppress(asyncio.QueueEmpty):
                queue.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(payload)

    def publish(self, topic: str, data: Any) -> int:
        """
        Fan one event out to every subscriber; returns delivery attempts.

        Never raises: a closed/stopped loop simply means that client is gone.
        """
        payload = (str(topic), data)
        with self._lock:
            subscribers = list(self._subscribers)
        delivered = 0
        for sub in subscribers:
            loop = sub['loop']
            try:
                if loop is None:
                    # headless subscriber — deliver synchronously
                    self._offer(sub['queue'], payload)
                elif not loop.is_closed():
                    loop.call_soon_threadsafe(self._offer, sub['queue'],
                                              payload)
                else:
                    continue
                delivered += 1
            except RuntimeError:
                continue  # loop died between snapshot and hop
        return delivered


#: Module-level bus shared by every app instance and the save/check hooks.
event_bus = _EventBus()


def _wire_event_bus() -> None:
    """
    Publish lookups and watchlist checks onto :data:`event_bus`.

    Registered at import time (idempotent, defensive — the hooks themselves
    are wrapped in try/except inside the observers' callers, and
    ``_EventBus.publish`` never raises).
    """
    def _on_save(query_type: str, query_value: str, success: bool) -> None:
        event_bus.publish('lookup', {
            'kind': query_type,
            'value': query_value,
            'success': bool(success),
            'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        })

    def _on_check(kind: str, target: str, success: bool,
                  changes: int) -> None:
        event_bus.publish('watch', {
            'kind': kind,
            'target': target,
            'success': bool(success),
            'changes': int(changes),
            'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        })

    set_save_hook(_on_save)
    set_check_hook(_on_check)


_wire_event_bus()


def _sse_frame(event: str, data: Any) -> str:
    """Format one server-sent-event frame (event line + JSON data)."""
    payload = json.dumps(data, ensure_ascii=False, default=str)
    return f'event: {event}\ndata: {payload}\n\n'


def _stream_topic_filter(topics: Optional[str]) -> frozenset:
    """
    Resolve the topic filter for one stream connection.

    An explicit ``?topics=a,b`` wins; otherwise the set declared via
    ``POST /api/stream/subscribe`` applies; an empty set means "everything".
    """
    if topics is None or not str(topics).strip():
        return _STREAM_TOPICS
    parts = {part.strip().lower()
             for part in str(topics).split(',') if part.strip()}
    return frozenset(parts) or frozenset({'*'})


def _parse_result_info(result_data: str) -> Dict[str, Any]:
    """Best-effort ``info`` dict from one stored JSON result (never raises)."""
    if not result_data:
        return {}
    try:
        data = json.loads(result_data)
    except (TypeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    info = data.get('info')
    return info if isinstance(info, dict) else {}


def _result_sources(result_data: str) -> Dict[str, int]:
    """``sources_ok`` / ``sources_failed`` counts of a stored result."""
    if not result_data:
        return {'sources_ok': 0, 'sources_failed': 0}
    try:
        data = json.loads(result_data)
    except (TypeError, ValueError):
        return {'sources_ok': 0, 'sources_failed': 0}
    if not isinstance(data, dict):
        return {'sources_ok': 0, 'sources_failed': 0}
    ok = data.get('sources_ok')
    failed = data.get('sources_failed')
    return {
        'sources_ok': len(ok) if isinstance(ok, (list, tuple)) else 0,
        'sources_failed': len(failed) if isinstance(failed, dict) else 0,
    }


def _geo_point_of(kind: str, info: Dict[str, Any]) -> Optional[Dict[str, float]]:
    """
    Extract ``{'lat', 'lon'}`` from a stored ``info`` block, if present.

    Coords and IP results carry ``latitude``/``longitude``; BSSID results
    carry ``lat``/``lon``. Values are range-checked so a string or a null
    never reaches the map.
    """
    candidates = (
        (info.get('latitude'), info.get('longitude')),
        (info.get('lat'), info.get('lon')),
    ) if kind in ('coords', 'ip', 'bssid') else ()
    for raw_lat, raw_lon in candidates:
        try:
            lat = float(raw_lat)
            lon = float(raw_lon)
        except (TypeError, ValueError):
            continue
        if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
            return {'lat': lat, 'lon': lon}
    return None


def _compare_value(value: Any) -> str:
    """Stringify one tracker field for comparison (80-char cap)."""
    if value is None:
        text = 'null'
    elif isinstance(value, bool):
        text = 'true' if value else 'false'
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, default=str,
                          sort_keys=True)
    return text if len(text) <= 80 else text[:77] + '...'


def _flat_fields(result: Dict[str, Any]) -> Dict[str, str]:
    """Comparable ``field -> stringified value`` view of one tracker result."""
    info = result.get('info') if isinstance(result, dict) else None
    if not isinstance(info, dict):
        return {}
    return {str(key): _compare_value(value)
            for key, value in info.items() if key is not None}


def _failure_payload(kind: str, target: str, message: str) -> Dict[str, Any]:
    """Uniform tracker-failure dict (never leaks a traceback)."""
    return {
        _TARGET_KEY.get(kind, 'target'): target,
        'info': {},
        'sources_ok': [],
        'sources_failed': {kind: message},
        'field_count': 0,
        'success': False,
        'errors': [message],
        'error': message,
    }


def _source_catalogs() -> Dict[str, Dict[str, str]]:
    """Source catalogs for every kind that publishes one."""
    from ..trackers.app_sources import SOURCE_CATALOG as APP_CATALOG
    from ..trackers.asn_sources import SOURCE_CATALOG as ASN_CATALOG
    from ..trackers.bssid_sources import SOURCE_CATALOG as BSSID_CATALOG
    from ..trackers.crypto_sources import SOURCE_CATALOG as CRYPTO_CATALOG
    from ..trackers.cve_sources import SOURCE_CATALOG as CVE_CATALOG
    from ..trackers.domain_sources import SOURCE_CATALOG as DOMAIN_CATALOG
    from ..trackers.email_sources import SOURCE_CATALOG as EMAIL_CATALOG
    from ..trackers.flight_sources import SOURCE_CATALOG as FLIGHT_CATALOG
    from ..trackers.hash_sources import SOURCE_CATALOG as HASH_CATALOG
    from ..trackers.iban_sources import SOURCE_CATALOG as IBAN_CATALOG
    from ..trackers.imei_sources import SOURCE_CATALOG as IMEI_CATALOG
    from ..trackers.ip_sources import SOURCE_CATALOG as IP_CATALOG
    from ..trackers.mac_sources import SOURCE_CATALOG as MAC_CATALOG
    from ..trackers.mmsi_sources import SOURCE_CATALOG as MMSI_CATALOG
    from ..trackers.plate_sources import SOURCE_CATALOG as PLATE_CATALOG
    from ..trackers.url_sources import SOURCE_CATALOG as URL_CATALOG
    from ..trackers.vin_sources import SOURCE_CATALOG as VIN_CATALOG

    catalogs: Dict[str, Dict[str, str]] = {
        'ip': IP_CATALOG,
        'email': EMAIL_CATALOG,
        'domain': DOMAIN_CATALOG,
        'url': URL_CATALOG,
        'crypto': CRYPTO_CATALOG,
        'hash': HASH_CATALOG,
        'cve': CVE_CATALOG,
        'asn': ASN_CATALOG,
        'mac': MAC_CATALOG,
        'iban': IBAN_CATALOG,
        'imei': IMEI_CATALOG,
        # v6.0 kinds
        'vin': VIN_CATALOG,
        'flight': FLIGHT_CATALOG,
        'mmsi': MMSI_CATALOG,
        'app': APP_CATALOG,
        'bssid': BSSID_CATALOG,
        'plate': PLATE_CATALOG,
    }
    # username/phone keep their platform catalogs on the trackers.
    try:
        catalogs['username'] = dict(UsernameTracker().source_catalog())
    except Exception:  # pragma: no cover - defensive
        catalogs['username'] = {}
    try:
        catalogs['phone'] = dict(PhoneTracker().source_catalog())
    except Exception:  # pragma: no cover - defensive
        catalogs['phone'] = {}
    try:
        catalogs['coords'] = dict(CoordsTracker().source_catalog())
    except Exception:  # pragma: no cover - defensive
        catalogs['coords'] = {}
    return catalogs


def create_app():
    """
    Build the ObscuraLens FastAPI application.

    FastAPI is imported here rather than at module import time so the rest of
    the package does not depend on the optional ``web`` extra.

    Raises:
        ImportError: if FastAPI is not installed, with an install hint.
    """
    try:
        from fastapi import FastAPI, HTTPException, UploadFile
        from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ImportError(
            'The ObscuraLens web UI requires FastAPI. '
            'Install it with: pip install "obscuralens[web]"'
        ) from exc

    app = FastAPI(
        title='ObscuraLens',
        version=__version__,
        description='Multi-source OSINT web UI and JSON REST API '
                    '(20 target kinds, analyst toolbox, dork builder, '
                    'evidence confidence, local file analysis).',
    )

    # ------------------------------------------------------------------
    # Static SPA
    # ------------------------------------------------------------------
    if STATIC_DIR.is_dir():
        app.mount('/static', StaticFiles(directory=str(STATIC_DIR)),
                  name='static')

        @app.get('/', include_in_schema=False)
        def index() -> Any:
            """Single-page application shell."""
            return FileResponse(STATIC_DIR / 'index.html')
    else:  # pragma: no cover - wheel without static data
        @app.get('/', response_class=HTMLResponse, include_in_schema=False)
        def index_fallback() -> str:
            return ('<doctype html><title>ObscuraLens</title>'
                    '<p>Static assets missing from this install. '
                    'Use the JSON API below; interactive docs at /docs.</p>')

    # ------------------------------------------------------------------
    # Core endpoints (v3.1 / v4.0 — unchanged semantics)
    # ------------------------------------------------------------------

    @app.get('/api/health')
    def api_health() -> Dict[str, Any]:
        """Liveness probe with the package version."""
        return {'status': 'ok', 'version': __version__}

    @app.get('/api/lookup/{kind}/{target}')
    def api_lookup(kind: str, target: str) -> Dict[str, Any]:
        """Run the tracker for one kind and return its raw result dict."""
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        ok, error = _VALIDATORS[kind](target)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        try:
            result = _TRACKERS[kind]().track(target)
        except Exception as exc:  # never leak a tracker traceback
            message = f"{type(exc).__name__}: {exc}"
            return _failure_payload(kind, target, message)
        # v6.1: evidence confidence from the provenance map.
        try:
            from ..correlation import attach_confidence
            attach_confidence(result)
        except Exception:
            pass
        return result

    @app.get('/api/investigate')
    def api_investigate(target: str, pivot: bool = True) -> Dict[str, Any]:
        """Auto-detect a target and (optionally) follow related pivots."""
        if investigate_module.detect_kind(target) is None:
            raise HTTPException(status_code=400, detail='unknown target type')
        try:
            return investigate_module.investigate(target, pivot=pivot)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @app.get('/api/sources')
    def api_sources() -> Dict[str, Any]:
        """Source catalogues for every kind."""
        return _source_catalogs()

    @app.get('/api/stats')
    def api_stats() -> Dict[str, Any]:
        """Database, cache, network and source-health statistics."""
        from ..health import health
        return {
            'database': db.get_statistics(),
            'cache': cache.stats(),
            'network': metrics.snapshot(),
            'source_health': health.get_health(),
        }

    @app.get('/api/risk/{kind}/{target}')
    def api_risk(kind: str, target: str) -> Dict[str, Any]:
        """Run a lookup and attach explainable heuristic risk scoring."""
        from ..correlation import attach_risk
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        ok, error = _VALIDATORS[kind](target)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        try:
            result = _TRACKERS[kind]().track(target)
            attach_risk(kind, result)
            return result
        except Exception as exc:
            return _failure_payload(kind, target,
                                    f"{type(exc).__name__}: {exc}")

    @app.get('/api/timeline')
    def api_timeline(target: Optional[str] = None,
                     limit: int = 100) -> Dict[str, Any]:
        """Chronological event timeline across stored lookup history."""
        from ..correlation import build_timeline, history_records
        records = history_records(limit=max(limit * 3, 200))
        if target:
            needle = target.lower()
            records = [r for r in records
                       if needle in str(r.get('value', '')).lower()]
        return build_timeline(records, cap=limit)

    @app.get('/api/correlate')
    def api_correlate(limit: Optional[int] = None) -> Dict[str, Any]:
        """Correlation graph, clusters and bridge entities from history."""
        from ..config import config
        from ..correlation import build_graph, history_records
        records = history_records(
            limit=limit or config.app_config.correlation_max_history)
        if not records:
            return {'entities': [], 'links': [], 'clusters': [], 'stats': {}}
        return build_graph(records)

    @app.get('/api/correlate/pair')
    def api_correlate_pair(a: str, b: str) -> Dict[str, Any]:
        """Shared-infrastructure comparison between two targets."""
        from ..correlation import correlate
        return correlate(a, b)

    @app.get('/api/intel/{target}')
    def api_intel(target: str) -> Dict[str, Any]:
        """Threat-intel verdict for an IP: Tor exit, blocklist feeds."""
        from ..intel import feeds as intel_feeds
        from ..intel import tor as intel_tor
        ok, error = validate_ip(target)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        return {
            'ip': target,
            'feeds': intel_feeds.check_ip(target),
            'tor_exit': intel_tor.is_tor_exit(target),
            'relay': intel_tor.relay_details(target),
        }

    # ------------------------------------------------------------------
    # Cases (v4 + v5 additions)
    # ------------------------------------------------------------------

    @app.get('/api/cases')
    def api_cases_list() -> Any:
        """Every investigation case with item/note/tag counts."""
        from ..cases import cases
        return cases.list_cases(include_archived=True)

    @app.get('/api/cases/{case_id}')
    def api_cases_get(case_id: int) -> Dict[str, Any]:
        """One case with items, notes and tags."""
        from ..cases import cases
        case = cases.get_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail='not found')
        return case

    @app.post('/api/cases', status_code=201)
    def api_cases_create(body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a case ({name, description})."""
        from ..cases import cases
        payload = body or {}
        name = str(payload.get('name', '') or '')
        if not name.strip():
            raise HTTPException(status_code=400, detail='name is required')
        return cases.create_case(
            name.strip(), description=str(payload.get('description', '') or ''))

    @app.patch('/api/cases/{case_id}')
    def api_cases_update(case_id: int,
                         body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update case status ({status: open|closed|archived}).

        New in v5.0 — used by the web UI to archive and reopen cases.
        """
        from ..cases import cases
        payload = body or {}
        status = str(payload.get('status', '') or '')
        if status == 'archived':
            case = cases.archive_case(case_id)
        elif status == 'closed':
            case = cases.close_case(case_id)
        elif status == 'open':
            case = cases.reopen_case(case_id)
        else:
            raise HTTPException(
                status_code=400,
                detail="status must be one of open, closed, archived")
        if not case:
            raise HTTPException(status_code=404, detail='not found')
        return case

    @app.post('/api/cases/{case_id}/items', status_code=201)
    def api_cases_add_item(case_id: int,
                           body: Dict[str, Any]) -> Dict[str, Any]:
        """Add an item ({kind, target, note?}) to a case."""
        from ..cases import cases
        payload = body or {}
        kind = str(payload.get('kind', 'auto') or 'auto')
        target = str(payload.get('target', '') or '')
        note = str(payload.get('note', '') or '') or None
        if not target.strip():
            raise HTTPException(status_code=400, detail='target is required')
        try:
            return cases.add_item(case_id, kind, target.strip(), note=note)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @app.post('/api/cases/{case_id}/notes', status_code=201)
    def api_cases_add_note(case_id: int,
                           body: Dict[str, Any]) -> Dict[str, Any]:
        """Append a note ({note}) to a case."""
        from ..cases import cases
        text = str((body or {}).get('note', '') or '')
        if not text.strip():
            raise HTTPException(status_code=400, detail='note is required')
        try:
            return cases.add_note(case_id, text.strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @app.post('/api/cases/{case_id}/tags', status_code=201)
    def api_cases_add_tag(case_id: int,
                          body: Dict[str, Any]) -> Dict[str, Any]:
        """Add a tag ({tag}) to a case."""
        from ..cases import cases
        tag = str((body or {}).get('tag', '') or '')
        if not tag.strip():
            raise HTTPException(status_code=400, detail='tag is required')
        try:
            return cases.add_tag(case_id, tag.strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    # ------------------------------------------------------------------
    # Watchlist (v4, unchanged) + diff (v5)
    # ------------------------------------------------------------------

    @app.get('/api/watch')
    def api_watch_list() -> Any:
        """Every watched target as a plain dict."""
        from dataclasses import asdict
        return [asdict(entry) for entry in watchlist.list()]

    @app.post('/api/watch', status_code=201)
    def api_watch_add(body: Dict[str, Any]) -> Dict[str, Any]:
        """Add a target to the watchlist; 409-style errors become 400."""
        target = str((body or {}).get('target', '') or '')
        label = str((body or {}).get('label', '') or '')
        try:
            watch_id = watchlist.add(target, label=label)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        return {'id': watch_id}

    @app.delete('/api/watch/{identifier}')
    def api_watch_remove(identifier: str) -> Dict[str, Any]:
        """Remove a watch by numeric id or target string."""
        ident: Any = int(identifier) if identifier.isdigit() else identifier
        removed = watchlist.remove(ident)
        if not removed:
            raise HTTPException(status_code=404, detail='not found')
        return {'removed': removed}

    @app.post('/api/watch/check')
    def api_watch_check(identifier: Optional[str] = None) -> Any:
        """Check one watch (id or target) or every watch; returns diffs."""
        from dataclasses import asdict
        ident: Any = None
        if identifier:
            ident = int(identifier) if identifier.isdigit() else identifier
        return [asdict(diff) for diff in watchlist.check(ident)]

    @app.get('/api/diff/{kind}/{target}')
    def api_diff(kind: str, target: str) -> Dict[str, Any]:
        """
        Snapshot diff for one watched target (latest two snapshots).

        New in v5.0. Returns ``added`` / ``removed`` / ``changed`` field
        sets. A watched target with fewer than two snapshots answers with
        ``changed: false`` and a note.
        """
        from ..watchlist import diff_snapshots
        if kind not in KINDS and kind != 'auto':
            raise HTTPException(status_code=400, detail='unknown kind')
        entry = watchlist.get(target) or watchlist.get(target.lower())
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail='target is not on the watchlist')
        snaps = watchlist.history(target, limit=2)
        if len(snaps) < 2:
            return {'target': target, 'kind': entry.kind,
                    'changed_any': False,
                    'added': {}, 'removed': {}, 'changed': {},
                    'note': 'only one snapshot stored — run a watch check '
                            'first (POST /api/watch/check)'}
        try:
            old = json.loads(snaps[1]['data'])
            new = json.loads(snaps[0]['data'])
        except (ValueError, KeyError, TypeError):
            raise HTTPException(status_code=500,
                                detail='corrupt snapshot data') from None
        added, removed, changed = diff_snapshots(old, new)
        return {'target': target, 'kind': entry.kind,
                'changed_any': bool(added or removed or changed),
                'added': added, 'removed': removed, 'changed': changed,
                'previous': snaps[1]['created_at'],
                'current': snaps[0]['created_at']}

    # ------------------------------------------------------------------
    # Graph export (v4, unchanged)
    # ------------------------------------------------------------------

    @app.get('/api/export/{fmt}/{target}')
    def api_export(fmt: str, target: str, pivot: bool = True) -> Dict[str, Any]:
        """Export an investigation entity graph as text (graphml/gexf/dot/...)."""
        from ..export import EXPORT_FORMATS, render
        if fmt not in EXPORT_FORMATS:
            raise HTTPException(status_code=400, detail='unknown format')
        if investigate_module.detect_kind(target) is None:
            raise HTTPException(status_code=400, detail='unknown target type')
        payload = investigate_module.investigate(target, pivot=pivot)
        text = render(payload.get('entities', []), payload.get('links', []), fmt)
        return {'target': target, 'format': fmt, 'graph': text,
                'entities': len(payload.get('entities', [])),
                'links': len(payload.get('links', []))}

    # ------------------------------------------------------------------
    # v5.0 — kinds registry, history, settings, keys
    # ------------------------------------------------------------------

    @app.get('/api/kinds')
    def api_kinds() -> List[Dict[str, Any]]:
        """Registry of every target kind with labels and source lists."""
        catalogs = _source_catalogs()
        out: List[Dict[str, Any]] = []
        for kind in KINDS:
            info = _KIND_INFO.get(kind, {})
            catalog = catalogs.get(kind, {})
            out.append({
                'kind': kind,
                'label': info.get('label', kind),
                'example': info.get('example', ''),
                'blurb': info.get('blurb', ''),
                'sources': sorted(catalog.keys()),
                'source_count': len(catalog),
            })
        return out

    @app.get('/api/history')
    def api_history(kind: Optional[str] = None, q: Optional[str] = None,
                    limit: int = 100) -> Dict[str, Any]:
        """
        Search stored lookup history (new in v5.0).

        ``kind`` filters by target kind; ``q`` is a case-insensitive
        substring match on the stored value; ``limit`` caps rows (≤ 500).
        Each item carries the parsed field count and success flag.
        """
        from ..database import DatabaseManager
        limit = max(1, min(limit, 500))
        if q:
            records = db.search_history(q, limit=limit)
            if kind:
                records = [r for r in records if r.query_type == kind]
        else:
            records = db.get_history(query_type=kind, limit=limit)
        items = []
        for record in records:
            items.append({
                'id': record.id,
                'kind': record.query_type,
                'value': record.query_value,
                'timestamp': record.created_at,
                'success': bool(record.success),
                'field_count': DatabaseManager.count_fields(record.result_data),
                'error': record.error_message or '',
            })
        return {'items': items, 'count': len(items), 'limit': limit,
                'kind': kind or '', 'q': q or ''}

    @app.get('/api/settings')
    def api_settings_get() -> Dict[str, Any]:
        """
        Runtime application settings as dotted-path keys (new in v5.0).

        Secret and filesystem paths are not exposed; API keys live under
        ``/api/keys``. Values are the *live* runtime configuration (env
        overrides included), not the YAML file contents.
        """
        from ..config import AppConfig, config
        settings: Dict[str, Any] = {}
        for field in dataclass_fields(AppConfig):
            if field.name in _SETTINGS_BLOCKLIST:
                continue
            settings[f'app.{field.name}'] = getattr(config.app_config,
                                                    field.name, '')
        return {'settings': settings, 'version': __version__,
                'note': 'runtime view — POST /api/settings to change '
                        'in-memory values (not persisted across restarts)'}

    @app.post('/api/settings')
    def api_settings_set(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update one runtime setting (``{path: 'app.cache_ttl', value: 300}``).

        Only ``app.*`` keys not on the blocklist are accepted; values are
        coerced to the current field type. Changes are in-memory only.
        """
        from ..config import AppConfig, config
        payload = body or {}
        path = str(payload.get('path', '') or '')
        raw_value = payload.get('value')
        if not path.startswith('app.'):
            raise HTTPException(status_code=400,
                                detail="path must start with 'app.'")
        name = path[4:]
        valid = {f.name: f for f in dataclass_fields(AppConfig)}
        if name not in valid or name in _SETTINGS_BLOCKLIST:
            raise HTTPException(status_code=400,
                                detail=f"unknown or protected setting: {path}")
        current = getattr(config.app_config, name)
        try:
            coerced = _coerce_setting(current, raw_value)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"value for {path} must be {type(current).__name__}"
            ) from exc
        setattr(config.app_config, name, coerced)
        return {'ok': True, 'path': path, 'value': coerced}

    @app.get('/api/keys')
    def api_keys_list() -> List[Dict[str, Any]]:
        """Which keyed services are configured (values never returned)."""
        from ..config import SERVICES, config
        return [{'service': service,
                 'configured': bool(config.is_configured(service)),
                 'description': _SERVICE_INFO.get(service, '')}
                for service in SERVICES]

    @app.post('/api/keys/{service}')
    def api_keys_set(service: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Store an API key for a service ({key: '...'})."""
        from ..config import SERVICES, config
        if service not in SERVICES:
            raise HTTPException(status_code=400,
                                detail=f'unknown service: {service}')
        key = str((body or {}).get('key', '') or '').strip()
        if not key:
            raise HTTPException(status_code=400, detail='key is required')
        try:
            config.set_api_key(service, key)
            config.save_secrets()
        except Exception as exc:  # unwritable secrets.yaml etc.
            raise HTTPException(
                status_code=500,
                detail=f'could not persist key: {exc}') from None
        return {'ok': True, 'service': service, 'configured': True}

    @app.delete('/api/keys/{service}')
    def api_keys_clear(service: str) -> Dict[str, Any]:
        """Remove a stored API key."""
        from ..config import SERVICES, config
        if service not in SERVICES:
            raise HTTPException(status_code=400,
                                detail=f'unknown service: {service}')
        try:
            config.set_api_key(service, '')
            config.save_secrets()
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f'could not persist change: {exc}') from None
        return {'ok': True, 'service': service, 'configured': False}

    # ------------------------------------------------------------------
    # v5.0 — analyst toolbox
    # ------------------------------------------------------------------

    @app.get('/api/tools/encodings')
    def api_tools_encodings(text: str) -> Dict[str, Any]:
        """
        Encode one input into every scheme (hex, base32/64/85, url, html,
        rot13, binary, morse, reversed…) plus a full digest panel (MD5 →
        SHA-3/BLAKE2, CRC32). All local computation.
        """
        from ..experimental import encoders
        try:
            encoded = encoders.encode_all(text)
        except Exception as exc:
            raise HTTPException(status_code=400,
                                detail=f'encoding failed: {exc}') from None
        try:
            hashes = encoders.hash_all(text)
        except Exception:
            hashes = {}
        return {'text': text, 'encodings': encoded, 'hashes': hashes,
                'schemes': list(encoders.SCHEMES.keys())}

    @app.post('/api/tools/decode')
    def api_tools_decode(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decode a value with one scheme, or rank every scheme's attempt.

        Body: ``{scheme: 'base64', value: '...'} `` — use ``scheme: 'auto'``
        for the ranked magic-decoder list.
        """
        from ..experimental import encoders
        payload = body or {}
        scheme = str(payload.get('scheme', 'auto') or 'auto').lower()
        value = str(payload.get('value', '') or '')
        if not value:
            raise HTTPException(status_code=400, detail='value is required')
        if scheme == 'auto':
            return {'scheme': 'auto', 'candidates': encoders.decode_auto(value)}
        if scheme not in encoders.SCHEMES:
            raise HTTPException(
                status_code=400,
                detail=f'unknown scheme: {scheme} '
                       f'(use one of {sorted(encoders.SCHEMES)} or auto)')
        try:
            result = encoders.SCHEMES[scheme]['decode'](value)
        except Exception as exc:
            raise HTTPException(status_code=400,
                                detail=f'decode failed: {exc}') from None
        return {'scheme': scheme, 'result': result}

    @app.get('/api/tools/jwt')
    def api_tools_jwt(token: str) -> Dict[str, Any]:
        """Decode and inspect a JWT (no signature verification — local)."""
        from ..experimental.jwt_tools import inspect_jwt
        try:
            return inspect_jwt(token)
        except Exception as exc:
            raise HTTPException(status_code=400,
                                detail=f'invalid JWT: {exc}') from None

    @app.get('/api/tools/hash-id')
    def api_tools_hash_id(value: str) -> Dict[str, Any]:
        """Identify candidate hash formats for a digest-shaped string."""
        from ..experimental.hash_identify import identify_hash
        return {'value': value, 'candidates': identify_hash(value)}

    @app.post('/api/tools/coords')
    def api_tools_coords(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse coordinates (DD/DMS/DDM/UTM/MGRS) and convert to every format.

        Body: ``{value: '48.8584, 2.2945'}``.
        """
        from ..utils.coordinate_math import (
            latlon_to_ddm,
            latlon_to_dms,
            latlon_to_geohash,
            latlon_to_maidenhead,
            latlon_to_mgrs,
            latlon_to_utm,
        )
        from ..utils.validators import parse_coords
        value = str((body or {}).get('value', '') or '')
        parsed = parse_coords(value)
        if parsed is None:
            raise HTTPException(
                status_code=400,
                detail='unrecognised coordinate format '
                       '(DD, DMS, UTM or MGRS)')
        lat, lon = parsed
        return {
            'input': value,
            'latitude': lat,
            'longitude': lon,
            'decimal': f'{lat:.6f}, {lon:.6f}',
            'dms': f"{latlon_to_dms(lat, 'lat')} {latlon_to_dms(lon, 'lon')}",
            'ddm': latlon_to_ddm(lat, lon),
            'utm': latlon_to_utm(lat, lon),
            'mgrs': latlon_to_mgrs(lat, lon),
            'geohash': latlon_to_geohash(lat, lon),
            'maidenhead': latlon_to_maidenhead(lat, lon),
        }

    @app.post('/api/tools/extract')
    def api_tools_extract(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract entities from free text: emails, IPs, domains, URLs, phones,
        hashes, CVEs, crypto addresses, MACs, IBANs, IMEIs, coordinates,
        handles and tracking IDs. All local regex + validator work.
        """
        from ..experimental.entity_extract import (
            extract_entities,
            summarize_entities,
        )
        text = str((body or {}).get('text', '') or '')
        if not text.strip():
            raise HTTPException(status_code=400, detail='text is required')
        found = extract_entities(text)
        return {'entities': found, 'summary': summarize_entities(found)}

    @app.post('/api/tools/squat')
    def api_tools_squat(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate and score typosquatting variants for a domain
        (omission, insertion, transposition, homoglyphs, bitsquatting,
        combo-squatting, TLD swaps…). Local generation only.
        """
        from ..experimental.squatting import (
            generate_variants,
            score_variants,
        )
        domain = str((body or {}).get('domain', '') or '').strip().lower()
        ok, error = validate_domain(domain)
        if not ok:
            raise HTTPException(status_code=400,
                                detail=error or 'invalid domain')
        variants = score_variants(generate_variants(domain), domain)
        return {'domain': domain, 'count': len(variants),
                'variants': variants}

    @app.get('/api/tools/dorks')
    def api_tools_dorks(target: str, kind: Optional[str] = None) -> Dict[str, Any]:
        """
        Ready-to-open search-engine dorks for a target (v6.1): the kind is
        auto-detected unless overridden, and the links are generated locally
        - the analyst stays in control of every active query.
        """
        from ..utils.dorks import KINDS_WITH_DORKS, dorks_for_target
        value = (target or '').strip()
        if not value:
            raise HTTPException(status_code=400, detail='target is required')
        links = dorks_for_target(value, kind)
        detected = investigate_module.detect_kind(value)
        return {
            'target': value,
            'detected_kind': detected,
            'count': len(links),
            'dorks': links,
            'dork_kinds': list(KINDS_WITH_DORKS),
        }

    @app.post('/api/tools/file/exif')
    async def api_tools_file_exif(file: UploadFile) -> Dict[str, Any]:
        """
        EXIF / metadata analysis of an uploaded image (JPEG, PNG, GIF, BMP,
        WebP). Parsing happens in-process — the file is never stored or
        transmitted anywhere else.
        """
        return await _analyse_upload(file, 'exif')

    @app.post('/api/tools/file/stego')
    async def api_tools_file_stego(file: UploadFile) -> Dict[str, Any]:
        """
        Steganography / entropy analysis of an uploaded file (LSB planes,
        chi-square markers, embedded-file carving, trailing data). Runs
        locally; nothing is persisted.
        """
        return await _analyse_upload(file, 'stego')

    async def _analyse_upload(file: UploadFile, mode: str) -> Dict[str, Any]:
        """Shared upload guard + local analysis dispatch for both modes."""
        if mode == 'exif':
            from ..experimental.exif_reader import analyze as analyse
        else:
            from ..experimental.steganography import analyze as analyse
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if not data:
            raise HTTPException(status_code=400, detail='empty file')
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f'file too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)')
        try:
            result = analyse(data)
        except Exception as exc:  # analysis must never 500 on user bytes
            raise HTTPException(status_code=422,
                                detail=f'analysis failed: {exc}') from None
        result['filename'] = file.filename or ''
        result['mode'] = mode
        return result

    @app.post('/api/tools/batch')
    def api_tools_batch(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Batch lookup up to 25 targets of one kind.

        Body: ``{kind: 'ip', targets: ['8.8.8.8', ...], risk: false}``.
        """
        from ..advanced.batch import run_batch
        payload = body or {}
        kind = str(payload.get('kind', '') or '')
        if kind not in KINDS:
            raise HTTPException(status_code=400,
                                detail=f'unknown kind: {kind}')
        targets = payload.get('targets') or []
        if not isinstance(targets, list) or not targets:
            raise HTTPException(status_code=400, detail='targets[] is required')
        targets = [str(t) for t in targets[:MAX_BATCH_TARGETS]]
        use_risk = bool(payload.get('risk', False))
        return run_batch(kind, targets, risk=use_risk)

    # ------------------------------------------------------------------
    # v5.0 — reports, patterns, alerts
    # ------------------------------------------------------------------

    @app.get('/api/report/{kind}/{target}')
    def api_report(kind: str, target: str,
                   download: bool = False) -> Any:
        """
        Build a self-contained HTML investigation report for one target.

        Default response is JSON ``{html, size}``; pass ``?download=1`` to
        receive the HTML document directly with an attachment header.
        """
        from ..advanced.report_builder import build_report
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        ok, error = _VALIDATORS[kind](target)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        try:
            html = build_report(kind, target)
        except Exception as exc:
            raise HTTPException(status_code=500,
                                detail=f'report failed: {exc}') from None
        if download:
            safe = ''.join(c if c.isalnum() else '_' for c in target)[:60]
            return HTMLResponse(
                content=html,
                headers={'Content-Disposition':
                         f'attachment; filename="report_{kind}_{safe}.html"'},
            )
        return {'kind': kind, 'target': target, 'size': len(html),
                'html': html}

    @app.get('/api/patterns')
    def api_patterns(kind: str, target: str) -> Dict[str, Any]:
        """
        Pattern-of-life analysis for one target across stored history:
        hour/weekday histograms, 7×24 activity matrix, cadence, bursts.
        """
        from ..advanced.patterns import pattern_report
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        return pattern_report(kind, target)

    @app.get('/api/alerts')
    def api_alerts_get() -> Dict[str, Any]:
        """Webhook alert configuration plus the recent event log."""
        from ..advanced.alerts import get_config, recent
        config = get_config()
        return {**config, 'recent': recent(20),
                'event_types': _alert_event_types()}

    @app.post('/api/alerts')
    def api_alerts_configure(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Configure webhook alerts (``{webhook_url, events: [...]}``).

        An empty URL disables notifications; the event log keeps recording
        locally either way.
        """
        from ..advanced.alerts import configure, get_config
        payload = body or {}
        url = str(payload.get('webhook_url', '') or '').strip()
        events = payload.get('events')
        if events is not None and not isinstance(events, list):
            raise HTTPException(status_code=400,
                                detail='events must be a list')
        allowed = _alert_event_types()
        if events:
            bad = [e for e in events if e not in allowed]
            if bad:
                raise HTTPException(
                    status_code=400,
                    detail=f'unknown events: {bad} (allowed: {allowed})')
        configure(url, events=events)
        return {**get_config(), 'event_types': allowed}

    @app.post('/api/alerts/test')
    def api_alerts_test() -> Dict[str, Any]:
        """Send a test notification through the configured webhook."""
        from ..advanced.alerts import test
        return test()

    def _alert_event_types() -> List[str]:
        from ..advanced.alerts import EVENT_TYPES
        return list(EVENT_TYPES)

    # ------------------------------------------------------------------
    # v6.0 Part 2: analytics endpoints (offline, pure computation)
    # ------------------------------------------------------------------

    def _numbers_of(body: Dict[str, Any]) -> List[float]:
        """
        Clean a request body's ``values`` list into finite floats.

        Non-numeric items are dropped (the analytics package would drop them
        anyway); an empty *result* - missing field, non-list, or nothing
        usable left after cleaning - raises HTTP 400 so a malformed client
        request cannot silently masquerade as "no data".
        """
        payload = body or {}
        raw = payload.get('values')
        if not isinstance(raw, list) or not raw:
            raise HTTPException(status_code=400,
                                detail='values must be a non-empty list of '
                                       'numbers')
        cleaned = [float(item) for item in raw
                   if isinstance(item, (int, float))
                   and not isinstance(item, bool)]
        if not cleaned:
            raise HTTPException(status_code=400,
                                detail='values contains no usable numbers')
        return cleaned

    @app.post('/api/analytics/stats')
    def api_analytics_stats(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Descriptive statistics plus a histogram for a numeric list.

        Body: ``{"values": [1, 2, 3, 4, 100], "bins": 10}`` — non-numeric
        items are dropped, then ``summarize`` (count/mean/median/stdev/
        quartiles/skew/kurtosis) and ``histogram`` run over the survivors.
        ``400`` when ``values`` is missing, not a list, or has no usable
        numbers left after cleaning.
        """
        from ..analytics.stats import histogram, summarize
        values = _numbers_of(body)
        try:
            bins = int((body or {}).get('bins', 10) or 10)
        except (TypeError, ValueError):
            bins = 10
        bins = max(1, min(bins, 100))
        return {'count': len(values), 'summary': summarize(values),
                'histogram': histogram(values, bins=bins)}

    @app.post('/api/analytics/anomalies')
    def api_analytics_anomalies(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Outlier detection over a numeric list.

        Body: ``{"values": [1, 2, 3, 4, 100], "method": "ensemble",
        "threshold": 3.0}`` — method is one of zscore/iqr/mad/grubbs/
        ensemble/threshold (default ensemble; unknown names return an empty
        hit list). ``threshold`` only applies to the zscore detector.
        Returns ``dataclass-asdict`` records: value, score, method, detail.
        """
        from dataclasses import asdict

        from ..analytics.anomaly import detect_anomalies
        values = _numbers_of(body)
        method = str((body or {}).get('method', 'ensemble') or 'ensemble')
        kwargs: Dict[str, Any] = {}
        threshold = (body or {}).get('threshold')
        if isinstance(threshold, (int, float)) \
                and not isinstance(threshold, bool) and method == 'zscore':
            kwargs['threshold'] = float(threshold)
        hits = detect_anomalies(values, method=method, **kwargs)
        return {'count': len(values), 'method': method,
                'anomaly_count': len(hits),
                'anomalies': [asdict(hit) for hit in hits]}

    @app.post('/api/analytics/timeseries')
    def api_analytics_timeseries(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trend / changepoint summary for a value sequence.

        Body: ``{"values": [5, 6, 5, 6, 20, 21]}`` — values are indexed as
        consecutive days, then ``series_summary`` reports count, span,
        least-squares trend with direction verdict, mean/variance and CUSUM
        changepoint count.
        """
        from ..analytics.timeseries import series_summary, to_points
        values = _numbers_of(body)
        points = to_points([(index * 86400, value)
                             for index, value in enumerate(values)])
        return {'count': len(values), 'summary': series_summary(points)}

    @app.post('/api/analytics/clusters')
    def api_analytics_clusters(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Kilometre-space clustering of ``[lat, lon]`` coordinate pairs.

        Body: ``{"points": [[52.0, 13.0], [52.1, 13.1]], "eps_km": 25,
        "min_points": 3}`` — great-circle DBSCAN via ``cluster_points``.
        ``400`` when ``points`` is missing, not a list, or contains no
        usable two-number rows.
        """
        from ..analytics.geoanalytics import cluster_points
        raw = (body or {}).get('points')
        if not isinstance(raw, list) or not raw:
            raise HTTPException(status_code=400,
                                detail='points must be a non-empty list of '
                                       '[lat, lon] pairs')
        points: List[List[float]] = []
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                lat, lon = item
                if isinstance(lat, (int, float)) \
                        and not isinstance(lat, bool) \
                        and isinstance(lon, (int, float)) \
                        and not isinstance(lon, bool):
                    points.append([float(lat), float(lon)])
        if not points:
            raise HTTPException(status_code=400,
                                detail='points contains no usable '
                                       '[lat, lon] pairs')
        eps = (body or {}).get('eps_km', 25.0)
        eps = float(eps) if isinstance(eps, (int, float)) \
            and not isinstance(eps, bool) and eps > 0 else 25.0
        min_points = (body or {}).get('min_points', 3)
        min_points = int(min_points) if isinstance(min_points, int) \
            and not isinstance(min_points, bool) and min_points > 0 else 3
        clusters = cluster_points(points, eps_km=eps, min_points=min_points)
        return {'point_count': len(points), 'eps_km': eps,
                'min_points': min_points, 'cluster_count': len(clusters),
                'clusters': clusters}

    @app.post('/api/analytics/keywords')
    def api_analytics_keywords(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stopword-filtered keyword mining for a text.

        Body: ``{"text": "the quick brown fox ...", "top": 10}`` — returns
        ``term``/``count``/``weight`` records sorted by weight.
        """
        from ..analytics.textmetrics import extract_keywords
        text = str((body or {}).get('text', '') or '')
        if not text.strip():
            raise HTTPException(status_code=400, detail='text is required')
        top = (body or {}).get('top', 10)
        top = int(top) if isinstance(top, int) and not isinstance(top, bool) \
            and top > 0 else 10
        keywords = extract_keywords(text, top=top)
        return {'keyword_count': len(keywords), 'keywords': keywords}

    @app.post('/api/analytics/language')
    def api_analytics_language(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Script and language fingerprint for a text.

        Body: ``{"text": "Le renard brun ..."}`` — dominant script, per-
        script character counts, a language guess with confidence and a
        human-readable hint.
        """
        from ..analytics.textmetrics import detect_language_script
        text = str((body or {}).get('text', '') or '')
        if not text.strip():
            raise HTTPException(status_code=400, detail='text is required')
        return detect_language_script(text)

    @app.post('/api/analytics/similarity')
    def api_analytics_similarity(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Four-metric similarity between two texts.

        Body: ``{"a": "paypal", "b": "paypa1"}`` — Jaro-Winkler, Levenshtein
        ratio, bigram similarity, sparse cosine, their mean and lengths.
        """
        from ..analytics.textmetrics import text_similarity_report
        a = str((body or {}).get('a', '') or '')
        b = str((body or {}).get('b', '') or '')
        if not a.strip() or not b.strip():
            raise HTTPException(status_code=400,
                                detail='a and b are both required')
        return text_similarity_report(a, b)

    @app.post('/api/analytics/graph')
    def api_analytics_graph(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Graph metrics over an ``entities``/``links`` payload.

        Body: ``{"entities": [{"id": "a"}, ...], "links": [{"source": "a",
        "target": "b"}, ...]}`` — the investigate/correlation payload shape
        (``from``/``to`` link keys are accepted too). Returns the one-shot
        ``graph_summary`` dossier: node/edge counts, density, components,
        communities, top entities by degree/PageRank/betweenness, bridges
        and isolated nodes. ``400`` when neither list is present.
        """
        from ..analytics.graphmetrics import graph_summary
        payload = body or {}
        entities = payload.get('entities')
        links = payload.get('links')
        if not isinstance(entities, list) and not isinstance(links, list):
            raise HTTPException(status_code=400,
                                detail='entities and/or links lists are '
                                       'required')
        summary = graph_summary(entities if isinstance(entities, list) else [],
                                links if isinstance(links, list) else [])
        return {'entity_count': len(entities) if isinstance(entities, list)
                else 0,
                'link_count': len(links) if isinstance(links, list) else 0,
                'summary': summary}

    @app.get('/api/analytics/history')
    def api_analytics_history(limit: int = 500) -> Dict[str, Any]:
        """
        Enrichment report over stored query history.

        Query: ``?limit=500`` (newest rows considered) — kind frequency,
        hour/weekday activity profiles, per-kind success rates, field-count
        statistics, source reliability, day-volume anomalies and the most
        re-queried targets. An empty history yields a well-formed empty
        report, not an error.
        """
        from ..analytics.enrich import enrichment_report
        safe_limit = limit if isinstance(limit, int) and limit > 0 else 500
        return enrichment_report(limit=safe_limit)

    # ------------------------------------------------------------------
    # Live stream + aggregation views (v6.0 part 3)
    # ------------------------------------------------------------------

    @app.get('/api/stream')
    async def api_stream(max_events: Optional[int] = None,
                         heartbeat_ms: Optional[int] = None,
                         topics: Optional[str] = None) -> Any:
        """
        Server-sent events feed: live lookups, watch checks and heartbeats.

        An endless ``text/event-stream``: a ``connected`` frame on open, then
        one ``event: <topic>`` frame per published event (``lookup`` from the
        database save hook, ``watch`` from the watchlist check hook) and an
        ``event: heartbeat`` frame whenever the feed has been idle for the
        heartbeat interval (15 s by default). Client disconnects are cleaned
        up quietly (the subscriber's queue is dropped in a ``finally``).

        Query:

        * ``topics`` — comma-separated whitelist (else the set declared via
          ``POST /api/stream/subscribe``; empty = every topic),
        * ``max_events`` — *test hook*: end the stream cleanly after N
          events (also switches the heartbeat to 50 ms so tests finish fast;
          production never sends it),
        * ``heartbeat_ms`` — override the heartbeat interval (10 ms…10 min).
        """
        queue = event_bus.subscribe()
        topic_filter = _stream_topic_filter(topics)
        heartbeat = STREAM_HEARTBEAT_S
        if max_events is not None:
            max_events = max(1, min(1000, int(max_events)))
            heartbeat = 0.05  # test mode — finish quickly
        if heartbeat_ms is not None:
            heartbeat = max(0.01, min(600.0, heartbeat_ms / 1000.0))

        async def event_stream():
            sent = 0
            try:
                yield _sse_frame('connected', {
                    'subscribers': event_bus.subscriber_count(),
                    'topics': sorted(topic_filter) if topic_filter else ['*'],
                })
                while max_events is None or sent < max_events:
                    try:
                        topic, data = await asyncio.wait_for(
                            queue.get(), timeout=heartbeat)
                    except asyncio.TimeoutError:
                        yield _sse_frame('heartbeat', {
                            'ts': datetime.now(timezone.utc).isoformat(
                                timespec='seconds'),
                        })
                        sent += 1
                        continue
                    if topic_filter and topic not in topic_filter:
                        continue
                    yield _sse_frame(topic, data)
                    sent += 1
            finally:
                # runs on clean end, client disconnect and cancellation —
                # never yields, so it is safe inside an async generator
                event_bus.unsubscribe(queue)

        return StreamingResponse(
            event_stream(),
            media_type='text/event-stream',
            headers={'Cache-Control': 'no-cache',
                     'X-Accel-Buffering': 'no'},
        )

    @app.post('/api/stream/subscribe')
    def api_stream_subscribe(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Declare the event topics this deployment's stream should carry.

        Body: ``{"topics": ["lookup", "watch"]}`` (a single comma-separated
        string works too). The set is module-level: every ``GET /api/stream``
        connection without its own ``?topics=`` parameter filters through
        it, and an empty declaration clears the filter (all topics again).
        ``400`` when ``topics`` is missing, not a list of names, or empty.
        """
        global _STREAM_TOPICS
        raw = (body or {}).get('topics')
        if raw is None:
            raise HTTPException(status_code=400,
                                detail='topics is required')
        if isinstance(raw, str):
            raw = raw.split(',')
        if not isinstance(raw, list) or not all(
                isinstance(item, str) and item.strip() for item in raw):
            raise HTTPException(status_code=400,
                                detail='topics must be a list of event names')
        names = sorted({item.strip().lower() for item in raw if item.strip()})
        if not names:
            raise HTTPException(status_code=400,
                                detail='topics must contain at least one name')
        _STREAM_TOPICS = frozenset(names)
        return {'topics': names, 'count': len(names),
                'subscriber_count': event_bus.subscriber_count()}

    @app.get('/api/profile/{kind}/{target}')
    def api_profile(kind: str, target: str,
                    limit: int = 200) -> Dict[str, Any]:
        """
        Aggregated activity profile for one target across stored history.

        Combines ``get_history`` (kind rows) with ``search_history`` (target
        substring matches) and keeps rows whose stored value equals the
        target case-insensitively. The dossier carries first/last seen
        timestamps, success counts, the ten most recent lookups, a field
        frequency census over every stored ``info`` block, and a source-count
        trend (one point per successful lookup) for risk sparklines.
        ``{'found': False}`` for a target with no history; ``400`` for an
        unknown kind.
        """
        from ..database import DatabaseManager
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        safe_limit = max(1, min(500, limit if isinstance(limit, int) else 200))
        needle = str(target or '').strip().lower()

        seen_ids = set()
        rows = []
        for record in db.get_history(query_type=kind, limit=safe_limit):
            seen_ids.add(record.id)
            if record.query_value.strip().lower() == needle:
                rows.append(record)
        for record in db.search_history(str(target or ''), limit=safe_limit):
            if record.id in seen_ids or record.query_type != kind:
                continue
            if record.query_value.strip().lower() == needle:
                rows.append(record)

        if not rows:
            return {'found': False, 'kind': kind, 'target': target,
                    'query_count': 0}

        # newest first (both history calls sort that way); flip for trends
        rows.sort(key=lambda r: (str(r.created_at or ''), r.id or 0))
        success_count = sum(1 for r in rows if r.success)

        field_counts: Dict[str, int] = {}
        trend = []
        for record in rows:
            info = _parse_result_info(record.result_data)
            for key, value in info.items():
                if value is None or value == '' or value == [] or value == {}:
                    continue
                field_counts[str(key)] = field_counts.get(str(key), 0) + 1
            sources = _result_sources(record.result_data)
            if record.success and (sources['sources_ok']
                                   or sources['sources_failed']):
                trend.append({'timestamp': record.created_at, **sources})

        frequency = [{'field': key, 'count': count}
                     for key, count in sorted(
                         field_counts.items(),
                         key=lambda item: (-item[1], item[0]))[:30]]

        recent = [{
            'id': record.id,
            'timestamp': record.created_at,
            'success': bool(record.success),
            'field_count': DatabaseManager.count_fields(record.result_data),
            'error': record.error_message or '',
        } for record in reversed(rows[-10:])]

        return {
            'found': True,
            'kind': kind,
            'target': target,
            'query_count': len(rows),
            'first_seen': rows[0].created_at,
            'last_seen': rows[-1].created_at,
            'success_count': success_count,
            'failure_count': len(rows) - success_count,
            'success_rate': round(success_count / len(rows) * 100, 1),
            'recent': recent,
            'field_frequency': frequency,
            'risk_trend': trend,
        }

    @app.get('/api/compare')
    def api_compare(kind_a: str, target_a: str,
                    kind_b: str, target_b: str) -> Dict[str, Any]:
        """
        Field-level diff between two live lookups (A versus B).

        Runs both trackers now (synchronously in the threadpool — this is a
        plain ``def`` endpoint on purpose so FastAPI keeps the event loop
        free), flattens each ``info`` block to ``field -> string`` and diffs
        the union into ``added`` (B only), ``removed`` (A only) and
        ``differing`` (both, unequal — carries both truncated values).
        Values are capped at 80 characters; volatile fields are kept as-is,
        so comparing a target against itself is the only empty-diff case.
        ``400`` for unknown kinds or invalid targets.
        """
        for kind in (kind_a, kind_b):
            if kind not in KINDS:
                raise HTTPException(status_code=400, detail='unknown kind')
        for kind, target in ((kind_a, target_a), (kind_b, target_b)):
            ok, error = _VALIDATORS[kind](target)
            if not ok:
                raise HTTPException(status_code=400, detail=error)

        def run(kind: str, target: str) -> Dict[str, Any]:
            try:
                return _TRACKERS[kind]().track(target)
            except Exception as exc:  # never leak a tracker traceback
                return _failure_payload(kind, target,
                                        f"{type(exc).__name__}: {exc}")

        result_a = run(kind_a, target_a)
        result_b = run(kind_b, target_b)
        fields_a = _flat_fields(result_a)
        fields_b = _flat_fields(result_b)

        added = [{'field': key, 'value': fields_b[key]}
                 for key in sorted(set(fields_b) - set(fields_a))]
        removed = [{'field': key, 'value': fields_a[key]}
                   for key in sorted(set(fields_a) - set(fields_b))]
        differing = [{'field': key, 'a': fields_a[key], 'b': fields_b[key]}
                     for key in sorted(set(fields_a) & set(fields_b))
                     if fields_a[key] != fields_b[key]]

        def side(kind: str, target: str, result: Dict[str, Any]) -> Dict[str, Any]:
            return {
                'kind': kind,
                'target': target,
                'success': bool(result.get('success')),
                'field_count': int(result.get('field_count') or 0),
                'error': str(result.get('error') or ''),
            }

        return {
            'a': side(kind_a, target_a, result_a),
            'b': side(kind_b, target_b, result_b),
            'added': added,
            'removed': removed,
            'differing': differing,
            'counts': {
                'added': len(added),
                'removed': len(removed),
                'differing': len(differing),
                'common': len(set(fields_a) & set(fields_b)),
            },
        }

    @app.get('/api/map/points')
    def api_map_points(limit: int = 500) -> Dict[str, Any]:
        """
        Geographic points distilled from stored lookup history.

        Query: ``?limit=500`` (newest rows scanned) — coordinates lookups
        (``info.latitude``/``longitude``), IP lookups (same keys) and BSSID
        lookups (``info.lat``/``lon``) are turned into
        ``{lat, lon, label, kind}`` points for the offline map view. Points
        are de-duplicated per kind at ~100 m resolution and returned newest
        first; kinds without coordinates (plate, cve, ...) never contribute.
        An empty history yields an empty list, not an error.
        """
        safe_limit = max(1, min(2000, limit if isinstance(limit, int) else 500))
        points: List[Dict[str, Any]] = []
        seen = set()
        for record in db.get_history(limit=safe_limit):
            info = _parse_result_info(record.result_data)
            if not info:
                continue
            geo = _geo_point_of(record.query_type, info)
            if geo is None:
                continue
            key = (record.query_type, round(geo['lat'], 3), round(geo['lon'], 3))
            if key in seen:
                continue
            seen.add(key)
            points.append({'lat': geo['lat'], 'lon': geo['lon'],
                           'label': record.query_value,
                           'kind': record.query_type})
        return {'points': points, 'count': len(points), 'limit': safe_limit}

    # ------------------------------------------------------------------
    # v6.0 Part 4: notifications, scheduler and STIX/MISP export
    # ------------------------------------------------------------------

    @app.get('/api/notify/channels')
    def api_notify_channels() -> Dict[str, Any]:
        """
        Every configured notification channel plus the protocol
        vocabularies (channel types, severity ladder) a UI needs to render
        pickers.
        """
        from ..automation import notifications
        channels = notifications.list_channels()
        return {'count': len(channels), 'channels': channels,
                'channel_types': list(notifications.CHANNEL_TYPES),
                'severities': list(notifications.SEVERITY_LEVELS)}

    @app.post('/api/notify/channels')
    def api_notify_channels_add(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register one notification channel.

        Body: ``{"name": "team-chat", "type": "telegram", "target":
        "bot_token:chat_id", "events": ["lookup", "watch_diff"],
        "min_severity": "low", "quiet_hours": [22, 7]}`` — ``target`` may
        be empty for the chat/mail types when the matching global config
        key is set. ``400`` when the spec is rejected (unknown type,
        missing target, duplicate name...); the module's reason is the
        ``detail``.
        """
        from ..automation import notifications
        result = notifications.add_channel(body or {})
        if not result.get('ok'):
            raise HTTPException(status_code=400,
                                detail=str(result.get('error')
                                           or 'channel rejected'))
        return {'ok': True, 'channel': result.get('channel')}

    @app.delete('/api/notify/channels/{name}')
    def api_notify_channels_remove(name: str) -> Dict[str, Any]:
        """Delete one channel by name (delivery history stays behind)."""
        from ..automation import notifications
        result = notifications.remove_channel(name)
        if not result.get('ok'):
            raise HTTPException(status_code=404,
                                detail=str(result.get('error')
                                           or 'channel not found'))
        return {'ok': True, 'removed': result.get('removed')}

    @app.post('/api/notify/channels/{name}/test')
    def api_notify_channels_test(name: str) -> Dict[str, Any]:
        """
        Probe one channel with a one-off test message.

        The subscription/severity/quiet-hours/dedup filters are bypassed -
        the question answered is "does the pipe work?". A delivery failure
        is a ``200`` with ``{"ok": false, "error": ...}`` (data, not an
        HTTP error); an unknown channel name is a ``404``.
        """
        from ..automation import notifications
        if notifications.get_channel(name) is None:
            raise HTTPException(status_code=404,
                                detail=f"channel '{name}' not found")
        return notifications.test_channel(name)

    @app.get('/api/notify/recent')
    def api_notify_recent(limit: int = 20) -> Dict[str, Any]:
        """
        Recent notification history, newest first: sends, failures and
        skips alike (the log is the account of everything the module
        wanted to say). ``?limit=20`` caps the window.
        """
        from ..automation import notifications
        safe_limit = max(0, min(200, limit if isinstance(limit, int)
                                and limit > 0 else 20))
        entries = notifications.recent(safe_limit)
        return {'count': len(entries), 'recent': entries}

    @app.post('/api/notify/broadcast')
    def api_notify_broadcast(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fan one event out to every configured channel.

        Body: ``{"title": "watch diff", "body": "…", "severity": "high",
        "event_type": "watch_diff"}`` — per-channel filters (event
        subscriptions, severity floors, quiet hours, dedup) apply inside
        :func:`broadcast`. ``400`` when ``title``/``body`` are missing.
        """
        from ..automation import notifications
        payload = body or {}
        title = str(payload.get('title', '') or '').strip()
        body_text = str(payload.get('body', '') or '')
        if not title:
            raise HTTPException(status_code=400, detail='title is required')
        if not body_text.strip():
            raise HTTPException(status_code=400, detail='body is required')
        severity = str(payload.get('severity', 'info') or 'info')
        event_type = str(payload.get('event_type', 'manual') or 'manual')
        return notifications.broadcast(event_type, title, body_text,
                                       severity=severity)

    @app.get('/api/automation/tasks')
    def api_automation_tasks() -> Dict[str, Any]:
        """Every scheduled task (schedules, bookkeeping fields, health)."""
        from ..automation import scheduler
        tasks = scheduler.list_tasks()
        return {'count': len(tasks), 'tasks': tasks,
                'actions': list(scheduler.TASK_ACTIONS),
                'schedule_types': list(scheduler.SCHEDULE_TYPES)}

    @app.post('/api/automation/tasks')
    def api_automation_tasks_add(body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register one scheduled task.

        Body: ``{"name": "daily-watch", "action": "watch_check",
        "schedule": "daily", "at_time": "09:00", "params": {...}}`` —
        schedule is interval/daily/weekly (default interval with
        ``interval_seconds`` 3600). ``400`` when the spec is rejected;
        the stored task carries a freshly computed ``next_run``.
        """
        from ..automation import scheduler
        result = scheduler.add_task(body or {})
        if not result.get('ok'):
            raise HTTPException(status_code=400,
                                detail=str(result.get('error')
                                           or 'task rejected'))
        return {'ok': True, 'task': result.get('task')}

    @app.delete('/api/automation/tasks/{name}')
    def api_automation_tasks_remove(name: str) -> Dict[str, Any]:
        """Delete one scheduled task by name."""
        from ..automation import scheduler
        result = scheduler.remove_task(name)
        if not result.get('ok'):
            raise HTTPException(status_code=404,
                                detail=str(result.get('error')
                                           or 'task not found'))
        return {'ok': True, 'removed': result.get('removed')}

    @app.post('/api/automation/tasks/{name}/run')
    def api_automation_tasks_run(name: str) -> Dict[str, Any]:
        """
        Execute one task now, regardless of its schedule.

        A failing executor is a ``200`` with ``{"ok": false, "error":
        ...}`` - the run outcome, not an HTTP error. ``404`` when the
        task name is unknown. The persisted bookkeeping (``run_count``,
        ``next_run``...) is left to ``run-due``.
        """
        from ..automation import scheduler
        if scheduler.get_task(name) is None:
            raise HTTPException(status_code=404,
                                detail=f"task '{name}' not found")
        return scheduler.run_task(name)

    @app.post('/api/automation/run-due')
    def api_automation_run_due() -> Dict[str, Any]:
        """
        Run every task whose schedule has arrived, then persist the
        bookkeeping (``last_run``, ``run_count``, ``error_count``,
        ``next_run``). This is exactly what the background tick loop
        does every 30 seconds.
        """
        from ..automation import scheduler
        results = scheduler.run_due()
        return {'ran': len(results), 'results': results}

    @app.get('/api/automation/next')
    def api_automation_next() -> Dict[str, Any]:
        """
        When every task runs next: the stored ``next_run`` plus a fresh
        recomputation from *now* (the two differ while a due task waits
        for the next tick). An empty schedule yields an empty list.
        """
        from ..automation import scheduler
        tasks = []
        for task in scheduler.list_tasks():
            tasks.append({
                'name': task.get('name'),
                'action': task.get('action'),
                'schedule': task.get('schedule'),
                'enabled': task.get('enabled'),
                'stored_next_run': task.get('next_run'),
                'recomputed_next_run': scheduler.compute_next_run(task),
            })
        return {'count': len(tasks), 'tasks': tasks}

    def _history_envelope(kind: str, target: str) -> Dict[str, Any]:
        """
        The newest stored tracker envelope for kind/target (shared by the
        STIX/MISP export endpoints).

        ``404`` when no stored lookup matches - the exports describe what
        was observed, so the analyst runs the lookup first.
        """
        needle = str(target or '').strip().lower()
        for record in db.get_history(query_type=kind, limit=500):
            if str(record.query_value or '').strip().lower() == needle:
                try:
                    envelope = json.loads(record.result_data or '{}')
                except ValueError:
                    continue
                if isinstance(envelope, dict):
                    return envelope
        raise HTTPException(
            status_code=404,
            detail=f"no stored {kind} lookup for {target!r} - "
                   f"run the lookup first")

    @app.get('/api/export/stix/{kind}/{target}')
    def api_export_stix(kind: str, target: str) -> Dict[str, Any]:
        """
        A STIX 2.1 bundle for the newest stored lookup of one target:
        identity + indicator (or vulnerability for CVEs) + observed data +
        provenance note, deterministic UUIDv5 ids throughout so
        re-imports merge. ``400`` unknown kind; ``404`` no stored lookup.
        """
        from ..export.stix import build_bundle
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        return build_bundle(kind, target, _history_envelope(kind, target))

    @app.get('/api/export/misp/{kind}/{target}')
    def api_export_misp(kind: str, target: str) -> Dict[str, Any]:
        """
        A MISP core-format event for the newest stored lookup of one
        target: fixed ObscuraLens ``orgc``, the target attribute, one
        text attribute per ``info`` field and a threat level derived
        from source health. ``400`` unknown kind; ``404`` no stored
        lookup.
        """
        from ..export.misp import build_misp_event
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        return build_misp_event(kind, target, _history_envelope(kind, target))

    return app


def _coerce_setting(current: Any, raw: Any) -> Any:
    """Coerce a JSON value to the type of the current setting value."""
    if isinstance(current, bool):
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            lowered = raw.strip().lower()
            if lowered in ('1', 'true', 'yes', 'on'):
                return True
            if lowered in ('0', 'false', 'no', 'off'):
                return False
        if isinstance(raw, (int, float)):
            return bool(raw)
        raise ValueError(raw)
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    if isinstance(current, (list, tuple)):
        if isinstance(raw, str):
            parts = [p.strip() for p in raw.split(',') if p.strip()]
        elif isinstance(raw, (list, tuple)):
            parts = [str(p) for p in raw]
        else:
            raise ValueError(raw)
        return list(parts) if isinstance(current, list) else tuple(parts)
    return str(raw)


def serve(host: str = '127.0.0.1', port: int = 8000,
          reload: bool = False, open_browser: bool = False) -> None:
    """
    Run the web UI with uvicorn.

    Args:
        host: interface to bind (default loopback only)
        port: TCP port to listen on
        reload: enable uvicorn's auto-reloader for development
        open_browser: open the default browser shortly after startup

    Raises:
        ImportError: if uvicorn is not installed, with an install hint.
    """
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ImportError(
            'The ObscuraLens web server requires uvicorn. '
            'Install it with: pip install "obscuralens[web]"'
        ) from exc

    app = create_app()
    url = f'http://{host}:{port}'
    print(f'ObscuraLens web UI: {url}')
    print('OpenAPI docs:        {}/docs'.format(url))
    if open_browser:
        import threading
        import webbrowser

        def _open() -> None:
            webbrowser.open(url)
        threading.Timer(1.2, _open).start()
    uvicorn.run(app, host=host, port=port, reload=reload)
