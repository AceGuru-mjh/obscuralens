"""
Multi-source file hash intelligence aggregation.

Every provider is queried independently; results are merged field-by-field so a
single flaky source cannot blank out the whole report. Sources marked keyless
work without an API key; keyed sources (VirusTotal) only layer on when a key
is configured. ``app.disabled_sources`` can switch any source off.

Accepted inputs are hex digests of any length the shared validators recognise
(md5/sha1/sha224/sha256/sha384/sha512). Sources that only accept a subset of
algorithms route or decline per digest: CIRCL hashlookup, for example, exposes
md5/sha1/sha256 endpoints and is skipped locally (without spending a request)
for the remaining algorithms.

Field provenance is tracked: ``gather_all`` returns which source(s) supplied
each value, so a report can show exactly where a fact came from. Two identity
fields (``hash`` and ``algorithm``) are derived from the request itself and
injected after the merge, so no payload can spoof or omit them.
"""

import concurrent.futures as futures
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.http_client import http
from ..utils.validators import detect_hash_algorithm

# Digest algorithms the CIRCL hashlookup API can answer for. Everything else
# (sha224/sha384/sha512) is declined locally, before any HTTP traffic is spent.
_HASHLOOKUP_ALGOS = ('md5', 'sha1', 'sha256')


# ---------------------------------------------------------------------------
# Parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _epoch_to_date(value: Any) -> Optional[str]:
    """
    Convert an epoch-seconds timestamp into an ISO date (``YYYY-MM-DD``, UTC).

    Accepts ints, floats and digit-only strings — some APIs serialise epochs as
    strings. Anything unparseable (or out of ``datetime`` range) yields ``None``
    so the field is simply dropped during the merge instead of raising.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str) and value.strip().isdigit():
        seconds = float(value.strip())
    else:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).date().isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _as_int(value: Any, default: int = 0) -> int:
    """Best-effort integer coercion for counter fields from JSON payloads."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _first_key(payload: Dict[str, Any], *keys: str) -> Any:
    """
    Return the first non-empty value among alternative spellings of a key.

    CIRCL hashlookup mixes ``file-name`` / ``FileName`` / ``file_name`` styles
    (and ``SSDEEP`` / ``ssdeep``) depending on endpoint and caller, so each
    logical field is probed against several candidate keys before giving up.
    """
    for key in keys:
        if key in payload and payload[key] not in (None, ''):
            return payload[key]
    return None


def _latest_pulse_date(pulses: List[Dict[str, Any]]) -> Optional[str]:
    """
    Newest pulse timestamp across an OTX pulse list.

    ISO-8601 strings compare lexically, so ``max()`` picks the most recent
    creation date; ``modified`` is used as a fallback for pulses that lack a
    ``created`` field. ``None`` when no pulse carries any timestamp.
    """
    stamps: List[str] = []
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        stamp = pulse.get('created') or pulse.get('modified')
        if isinstance(stamp, str) and stamp:
            stamps.append(stamp)
    return max(stamps) if stamps else None


def _unique_tags(pulses: List[Dict[str, Any]], limit: int = 10) -> List[str]:
    """
    First-seen-ordered unique tag list across pulses, capped at ``limit``.

    Non-string and empty tag entries are ignored rather than raising, and the
    cap is applied while collecting so huge pulse lists do not build an
    unbounded intermediate list.
    """
    tags: List[str] = []
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        for tag in pulse.get('tags') or []:
            if not isinstance(tag, str) or not tag or tag in tags:
                continue
            tags.append(tag)
            if len(tags) >= limit:
                return tags
    return tags


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _malwarebazaar(h: str) -> Dict[str, Any]:
    """
    abuse.ch MalwareBazaar sample database (keyless, optional Auth-Key).

    POSTs ``{'query': 'get_info', 'hash': ...}`` to the abuse.ch API v1 and
    maps the first matching sample record. A ``query_status`` other than
    ``'ok'`` (``no_result``, ``illegal_hash``, rate-limit notices, ...) is a
    "no data" answer, not a failure. The optional Auth-Key is read from the
    local config so the reader stays a FREE source with a keyed fast lane.
    """
    headers: Optional[Dict[str, str]] = None
    auth_key = config.get_api_key('malwarebazaar')
    if auth_key:
        headers = {'Auth-Key': auth_key}

    ok, d, _ = http.post_json(
        'https://mb-api.abuse.ch/api/v1/',
        {'query': 'get_info', 'hash': (h or '').strip().lower()},
        headers=headers)
    if not ok or not isinstance(d, dict):
        return {}
    if d.get('query_status') != 'ok':
        return {}

    entries = d.get('data')
    if not isinstance(entries, list) or not entries:
        return {}
    item = entries[0]
    if not isinstance(item, dict):
        return {}

    out: Dict[str, Any] = {
        'malware_family': item.get('signature'),
        'file_name': item.get('file_name'),
        'file_size': item.get('file_size'),
        'file_type_mime': item.get('file_type_mime'),
        'first_seen': item.get('first_seen'),
        'last_seen': item.get('last_seen'),
        'imphash': item.get('imphash'),
        'mb_sha256': item.get('sha256_hash'),
        'mb_md5': item.get('md5_hash'),
        'mb_sha1': item.get('sha1_hash'),
    }
    tags = item.get('tags')
    if isinstance(tags, list):
        out['malware_tags'] = [t for t in tags if isinstance(t, str) and t]
    return out


def _hashlookup(h: str) -> Dict[str, Any]:
    """
    CIRCL hashlookup known-file corpus (keyless).

    Looks the digest up at ``/api/hash/{algo}/{hash}`` for md5/sha1/sha256
    digests; any other algorithm is declined locally without a request. A 404
    or an empty body means "not in the known-file corpus" and yields {}. A hit
    sets ``known_file`` to True — the file was seen in CIRCL's corpus of
    mostly-benign known files — alongside fuzzy hashes and file metadata.
    """
    algo = detect_hash_algorithm(h or '')
    if algo not in _HASHLOOKUP_ALGOS:
        return {}
    ok, d, _ = http.get_json(
        f"https://hashlookup.circl.eu/api/hash/{algo}/{(h or '').strip().lower()}")
    if not ok or not isinstance(d, dict) or not d:
        return {}
    return {
        'hl_file_name': _first_key(d, 'file-name', 'FileName', 'file_name'),
        'hl_file_size': _first_key(d, 'file-size', 'FileSize', 'file_size'),
        'hl_file_type': _first_key(d, 'file-type', 'FileType', 'file_type'),
        'ssdeep': _first_key(d, 'SSDEEP', 'ssdeep'),
        'tlsh': _first_key(d, 'TLSH', 'tlsh'),
        'known_file': True,
    }


def _otx(h: str) -> Dict[str, Any]:
    """
    AlienVault OTX pulse intelligence for a file hash (keyless, optional key).

    Reads ``/api/v1/indicators/file/{hash}/general`` and reports how many
    community pulses reference the hash, the newest pulse date and the first
    ten unique tags across pulses. A top-level ``whitelist`` flag is mapped to
    ``otx_whitelisted`` whenever OTX includes it (explicit False is a real
    answer and is kept). The optional ``X-OTX-API-KEY`` header is attached
    when a key is configured.
    """
    headers: Optional[Dict[str, str]] = None
    api_key = config.get_api_key('otx')
    if api_key:
        headers = {'X-OTX-API-KEY': api_key}

    ok, d, _ = http.get_json(
        f"https://otx.alienvault.com/api/v1/indicators/file/"
        f"{(h or '').strip().lower()}/general",
        headers=headers)
    if not ok or not isinstance(d, dict) or not d:
        return {}

    pulse_info = d.get('pulse_info')
    if not isinstance(pulse_info, dict):
        pulse_info = {}
    pulses = [p for p in (pulse_info.get('pulses') or []) if isinstance(p, dict)]

    count = pulse_info.get('count')
    if isinstance(count, bool) or not isinstance(count, int):
        count = len(pulses)

    out: Dict[str, Any] = {'otx_pulses': count}
    if 'whitelist' in d:
        out['otx_whitelisted'] = bool(d.get('whitelist'))

    latest = _latest_pulse_date(pulses)
    if latest:
        out['otx_last_pulse'] = latest
    tags = _unique_tags(pulses)
    if tags:
        out['otx_tags'] = tags

    if not pulses and 'whitelist' not in d and not count:
        # No pulses, no whitelist hint and a zero count: nothing to report.
        return {}
    return out


def _virustotal(h: str, api_key: str) -> Dict[str, Any]:
    """
    VirusTotal v3 file report (keyed).

    Reads ``/api/v3/files/{hash}`` with the ``x-apikey`` header and maps
    ``data.attributes``: reputation, file type/size/name/magic, the creation
    date (converted from epoch seconds to an ISO date), detection counters and
    the suggested threat label. ``malicious_score`` is the integer percentage
    of engines that flagged the file as malicious or suspicious.
    """
    ok, d, _ = http.get_json(
        f"https://www.virustotal.com/api/v3/files/{(h or '').strip().lower()}",
        headers={'x-apikey': api_key})
    if not ok or not isinstance(d, dict):
        return {}
    data = d.get('data')
    if not isinstance(data, dict):
        return {}
    attrs = data.get('attributes')
    if not isinstance(attrs, dict):
        attrs = {}

    stats = attrs.get('last_analysis_stats')
    if not isinstance(stats, dict):
        stats = {}
    malicious = _as_int(stats.get('malicious'))
    suspicious = _as_int(stats.get('suspicious'))
    total = sum(_as_int(v) for v in stats.values())
    score = int(((malicious + suspicious) / total) * 100) if total else 0

    threat_classification = attrs.get('popular_threat_classification')
    if not isinstance(threat_classification, dict):
        threat_classification = {}

    return {
        'reputation': attrs.get('reputation'),
        'vt_type': attrs.get('type_description'),
        'vt_size': attrs.get('size'),
        'vt_meaningful_name': attrs.get('meaningful_name'),
        'vt_magic': attrs.get('magic'),
        'vt_created': _epoch_to_date(attrs.get('creation_date')),
        'malicious': malicious,
        'suspicious': suspicious,
        'vt_threat_label': threat_classification.get('suggested_threat_label'),
        'malicious_score': score,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'malwarebazaar': _malwarebazaar,
    'hashlookup': _hashlookup,
    'otx': _otx,
}

KEYED_SOURCES: Dict[str, Any] = {
    'virustotal': _virustotal,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'malwarebazaar': 'abuse.ch MalwareBazaar: malware family, file names, tags '
                     '(keyless, optional Auth-Key)',
    'hashlookup': 'CIRCL hashlookup known-file corpus: ssdeep/TLSH and file '
                  'metadata for md5/sha1/sha256 (keyless)',
    'otx': 'AlienVault OTX: pulse count, latest pulse, tags '
           '(keyless, optional API key)',
    'virustotal': 'VirusTotal file report: detections, reputation, threat '
                  'label (keyed)',
}


def _keep(value: Any) -> bool:
    # Explicit False is a real answer (otx_whitelisted=False, known_file=False).
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(h: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable hash source in parallel and merge the results.

    Args:
        h: target file hash (any hex digest length the validators accept)
        keys: optional {service: api_key} map for keyed sources

    Returns:
        {
          'fields': merged_field_dict (plus injected 'hash'/'algorithm'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }
    """
    keys = keys or {}
    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(h))

    for name, fn in _plugin_sources('hash').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(h))

    key_map = {
        'virustotal': ('virustotal', lambda k: _virustotal(h, k)),
    }
    for service, (source_name, factory) in key_map.items():
        key = keys.get(service)
        if key and config.is_source_enabled(source_name) \
                and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=factory, k=key: f(k))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=min(len(tasks), 12)) as ex:
            future_map = {ex.submit(fn): name for name, fn in tasks.items()}
            for future in futures.as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result() or {}
                    results[name] = data
                    status[name] = {'ok': bool(data), 'error': '' if data else 'no data'}
                except Exception as e:  # a broken source must not kill the scan
                    results[name] = {}
                    status[name] = {'ok': False, 'error': type(e).__name__}

    health.record_batch('hash', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # Identity fields are derived from the request itself and injected after
    # the merge, so no source payload can overwrite or omit them.
    merged['hash'] = (h or '').strip().lower()
    merged['algorithm'] = detect_hash_algorithm(h or '')

    return {'fields': merged, 'sources': status, 'provenance': provenance}
