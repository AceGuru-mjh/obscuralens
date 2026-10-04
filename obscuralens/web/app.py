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

import json
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .. import __version__
from .. import investigate as investigate_module
from ..core.cache import cache
from ..core.metrics import metrics
from ..database import db
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
from ..watchlist import watchlist

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
        from fastapi.responses import FileResponse, HTMLResponse
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
                    '(17 target kinds, analyst toolbox, local file analysis).',
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
            return _TRACKERS[kind]().track(target)
        except Exception as exc:  # never leak a tracker traceback
            message = f"{type(exc).__name__}: {exc}"
            return _failure_payload(kind, target, message)

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
