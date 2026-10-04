"""
Multi-source URL intelligence aggregation.

A URL target answers a different set of questions than an IP or a domain:
where does this link *really* land after every redirect, who archived it, and
does anyone consider it dangerous. Every provider below is queried
independently; results are merged field-by-field so a single flaky source
cannot blank out the whole report.

Keyless sources:

* ``http_probe``            - manual redirect walk, final status, title, server
* ``urlscan``               - public urlscan.io scan history and verdicts
* ``wayback``               - Wayback Machine capture history (CDX API)

Keyed sources (layered on when a key is configured):

* ``google_safe_browsing``  - Google Safe Browsing threat verdicts
* ``virustotal``            - URL scan detections and reputation

Sources listed in ``app.disabled_sources`` are skipped. Field provenance is
tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import base64
import concurrent.futures as futures
import contextlib
import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urljoin, urlparse

from ..config import config
from ..health import health
from ..utils.http_client import http
from ..utils.validators import url_parts

# Statuses that hand the client a new location to fetch.
REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# Cap on the manual redirect walk: browsers stop after ~20, we are stricter
# because every hop costs a full request round-trip.
MAX_REDIRECT_HOPS = 8

_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)

# Scheme a redirect target must carry before we are willing to follow it.
_ABSOLUTE_URL_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')

# Google Safe Browsing: everything a phishing/malware URL can be flagged as.
_GSB_THREAT_TYPES = (
    'MALWARE',
    'SOCIAL_ENGINEERING',
    'UNWANTED_SOFTWARE',
    'POTENTIALLY_HARMFUL_APPLICATION',
)


# ---------------------------------------------------------------------------
# Small helpers shared by the readers
# ---------------------------------------------------------------------------

def _header(headers: Any, name: str) -> Optional[str]:
    """Read a header from a Response-like mapping without ever raising."""
    try:
        value = headers.get(name)
        if value is None:
            value = headers.get(name.lower())
        if value is None:
            value = headers.get(name.upper())
        return str(value) if value is not None else None
    except Exception:
        return None


def _host_is_ip(host: str) -> bool:
    """
    True when the host part is an IPv4/IPv6 literal.

    Numeric hosts (``http://2130706433/``) count as IPs too - they are just
    dotted-quad addresses in decimal form.
    """
    if not host:
        return False
    try:
        if host.isdigit():
            ipaddress.ip_address(str(int(host)))
        else:
            ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _wayback_date(raw: Any) -> Optional[str]:
    """CDX timestamp ``YYYYMMDDhhmmss`` -> ``YYYY-MM-DD`` (None when malformed)."""
    if not isinstance(raw, str) or len(raw) < 8 or not raw[:8].isdigit():
        return None
    return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"


def _vt_url_id(url: str) -> str:
    """
    VirusTotal's identifier for a scanned URL: the URL base64url-encoded
    without padding (``base64.urlsafe_b64encode(url).rstrip('=')``).
    """
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')


# ---------------------------------------------------------------------------
# Keyless source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _http_probe(url: str) -> Dict[str, Any]:
    """
    Fetch a URL while walking its redirect chain manually.

    ``http.get`` is called with ``allow_redirects=False`` so every hop is
    visible: the chain records the status code and resolved target of each
    redirect (relative ``Location`` values are resolved with ``urljoin``).
    When the walk stops on a non-redirect response that response is reused;
    when the hop cap is reached one final permissive fetch lets the HTTP
    client finish the walk for us.
    """
    chain: List[Dict[str, Any]] = []
    current = url

    try:
        response = http.get(current, allow_redirects=False)
    except Exception:
        return {}

    for _ in range(MAX_REDIRECT_HOPS):
        try:
            status = int(response.status_code)
            location = _header(getattr(response, 'headers', None), 'Location')
        except Exception:
            return {}
        if status not in REDIRECT_STATUSES or not location:
            break
        next_url = urljoin(current, str(location))
        if not next_url or not _ABSOLUTE_URL_RE.match(next_url):
            break  # bogus Location; stop instead of chasing it
        chain.append({'url': next_url, 'status': status})
        current = next_url
        try:
            response = http.get(current, allow_redirects=False)
        except Exception:
            return {}

    try:
        status = int(response.status_code)
    except Exception:
        return {}

    # The server would keep redirecting (hop cap hit or missing Location):
    # hand the remainder to the client with redirects allowed.
    if status in REDIRECT_STATUSES:
        try:
            permissive = http.get(current, allow_redirects=True)
        except Exception:
            permissive = None
        if permissive is not None:
            response = permissive

    out: Dict[str, Any] = {
        'redirect_count': len(chain),
        'redirect_chain': chain,
    }

    try:
        final_url = response.url
    except Exception:
        final_url = None
    out['final_url'] = final_url or current

    with contextlib.suppress(Exception):
        out['http_status'] = int(response.status_code)

    try:
        text = response.text or ''
    except Exception:
        text = ''
    match = _TITLE_RE.search(text)
    if match:
        title = re.sub(r'\s+', ' ', match.group(1)).strip()
        if title:
            out['http_title'] = title[:200]

    try:
        headers = response.headers
    except Exception:
        headers = None
    server = _header(headers, 'Server')
    if server:
        out['http_server'] = server[:200]
    content_type = _header(headers, 'Content-Type')
    if content_type:
        out['content_type'] = content_type[:200]

    parts = url_parts(url)
    if parts:
        out['scheme'] = parts.get('scheme')
        out['host'] = parts.get('host')
        out['port'] = parts.get('port')
        out['host_is_ip'] = _host_is_ip(parts.get('host') or '')

    return out


def _urlscan(url: str) -> Dict[str, Any]:
    """
    urlscan.io search API (keyless): public scan history for this exact URL.

    Each result carries the scan time, page metadata and - when the scanning
    account is entitled to verdicts - an overall malicious flag. Times are
    ISO strings so a plain ``max()`` picks the newest scan.
    """
    query = 'page.url:"' + url + '"'
    ok, d, _ = http.get_json(
        f"https://urlscan.io/api/v1/search/?q={quote(query, safe='')}")
    if not ok or not isinstance(d, dict):
        return {}
    results = d.get('results')
    if not isinstance(results, list) or not results:
        return {}

    scanned: List[Any] = []
    countries = set()
    malicious = 0
    for record in results:
        if not isinstance(record, dict):
            continue
        task = record.get('task') or {}
        page = record.get('page') or {}
        verdicts = record.get('verdicts') or {}
        overall = verdicts.get('overall') or {}
        if task.get('time'):
            scanned.append((str(task['time']), page.get('title')))
        if page.get('country'):
            countries.add(str(page['country']))
        if overall.get('malicious') is True:
            malicious += 1

    total = d.get('total')
    out: Dict[str, Any] = {
        'urlscan_total': total if isinstance(total, int) else len(results),
        'urlscan_malicious_verdicts': malicious,
    }
    if scanned:
        newest = max(scanned, key=lambda item: item[0])
        out['urlscan_last_scan'] = newest[0]
        if newest[1]:
            out['urlscan_last_title'] = str(newest[1])[:200]
    if countries:
        out['urlscan_countries'] = sorted(countries)
    return out


def _wayback(url: str) -> Dict[str, Any]:
    """
    Wayback Machine CDX API (keyless): capture history for the exact URL.

    The JSON response is a list of rows; the first row is the header
    (urlkey, timestamp, original, mimetype, statuscode, digest, length).
    Timestamps are fixed-width so lexical min/max equal first/last capture.
    """
    ok, data, _ = http.get_json(
        f"http://web.archive.org/cdx/search/cdx?url={quote(url, safe='')}"
        f"&output=json&limit=50")
    if not ok or not isinstance(data, list) or len(data) < 2:
        return {}

    rows = [row for row in data[1:] if isinstance(row, list) and len(row) >= 3]
    if not rows:
        return {}

    stamps: List[str] = []
    codes = set()
    for row in rows:
        if len(row) > 1 and row[1] is not None:
            stamps.append(str(row[1]))
        if len(row) > 4:
            with contextlib.suppress(TypeError, ValueError):
                codes.add(int(row[4]))

    out: Dict[str, Any] = {'wayback_captures': len(rows)}
    if stamps:
        first = _wayback_date(min(stamps))
        last = _wayback_date(max(stamps))
        if first:
            out['wayback_first_capture'] = first
        if last:
            out['wayback_last_capture'] = last
    if codes:
        out['wayback_status_codes'] = sorted(codes)
    return out


# ---------------------------------------------------------------------------
# Keyed sources (optional)
# ---------------------------------------------------------------------------

def _google_safe_browsing(url: str, api_key: str) -> Dict[str, Any]:
    """
    Google Safe Browsing v4 threatMatches:find (keyed).

    A clean URL answers ``{}`` - which is a real verdict, not a failure, so
    the reader returns ``gsb_malicious: False`` instead of {}.
    """
    payload = {
        'client': {
            'clientId': 'obscuralens',
            'clientVersion': '4.0',
        },
        'threatInfo': {
            'threatTypes': list(_GSB_THREAT_TYPES),
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}],
        },
    }
    try:
        ok, d, _ = http.post_json(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            payload=payload)
    except Exception:
        return {}
    if not ok or not isinstance(d, dict):
        return {}

    matches = d.get('matches')
    if not isinstance(matches, list):
        return {'gsb_threat_types': [], 'gsb_malicious': False}

    threat_types = set()
    for match in matches:
        if isinstance(match, dict) and match.get('threatType'):
            threat_types.add(str(match['threatType']))
    return {
        'gsb_threat_types': sorted(threat_types),
        'gsb_malicious': bool(threat_types),
    }


def _virustotal(url: str, api_key: str) -> Dict[str, Any]:
    """
    VirusTotal v3 URL report (keyed), looked up by the base64url URL id.

    ``malicious_score`` compresses the engine verdicts into 0-100: the share
    of engines calling the URL malicious or suspicious. ``vt_last_analysis``
    is the epoch ``last_analysis_date`` rendered as an ISO date.
    """
    ok, d, _ = http.get_json(
        f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(url)}",
        headers={'x-apikey': api_key})
    if not ok or not isinstance(d, dict):
        return {}

    data = d.get('data')
    attrs = data.get('attributes') if isinstance(data, dict) else None
    attrs = attrs if isinstance(attrs, dict) else {}
    raw_stats = attrs.get('last_analysis_stats')
    stats = raw_stats if isinstance(raw_stats, dict) else {}

    malicious = stats.get('malicious', 0) or 0
    suspicious = stats.get('suspicious', 0) or 0
    total = sum(v for v in stats.values() if isinstance(v, int))
    score = int(((malicious + suspicious) / total) * 100) if total else 0

    out: Dict[str, Any] = {
        'vt_malicious': malicious,
        'vt_suspicious': suspicious,
        'vt_reputation': attrs.get('reputation'),
        'malicious_score': score,
    }

    last_analysis = attrs.get('last_analysis_date')
    if last_analysis is not None:
        with contextlib.suppress(TypeError, ValueError, OSError, OverflowError):
            out['vt_last_analysis'] = datetime.fromtimestamp(
                int(last_analysis), tz=timezone.utc).strftime('%Y-%m-%d')

    title = attrs.get('title')
    if title:
        out['vt_title'] = str(title)[:200]

    categories = attrs.get('categories')
    if isinstance(categories, dict) and categories:
        labels = sorted({str(v) for v in categories.values() if v})
        if labels:
            out['vt_categories'] = labels[:10]
    return out


# ---------------------------------------------------------------------------
# OpenPhish community phishing feed (v5.2)
# ---------------------------------------------------------------------------

_OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt'
# (fetched_at, urls, hosts) - the same cached response body the IP intel
# feeds module consumes, so one download serves both readers.
_openphish_cache: Optional[Tuple[float, Set[str], Set[str]]] = None


def _openphish_feed() -> Tuple[Set[str], Set[str]]:
    """
    Parse the OpenPhish community feed into (urls, hosts), TTL-cached.

    The free feed is small (~100 URLs, refreshed hourly) and its hosts are
    overwhelmingly domains - exactly the IOC type the IP-side feed filters
    out, which is why this URL-side reader keeps them. Cache TTL follows
    ``app.feed_cache_ttl``; a transport failure keeps the last known sets.
    """
    global _openphish_cache
    ttl = int(config.app_config.feed_cache_ttl or 21600)
    now = time.time()
    if _openphish_cache is not None and (now - _openphish_cache[0]) < ttl:
        return _openphish_cache[1], _openphish_cache[2]

    urls: Set[str] = set()
    hosts: Set[str] = set()
    try:
        ok, text, _ = http.get_text(_OPENPHISH_FEED_URL, use_cache=True,
                                    cache_ttl=ttl)
        if ok and text:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(('#', ';')):
                    continue
                urls.add(line)
                try:
                    host = (urlparse(line).hostname or '').lower()
                except ValueError:
                    continue
                if host:
                    hosts.add(host)
    except Exception:  # never raise from a feed read
        pass
    _openphish_cache = (now, urls, hosts)
    return urls, hosts


def _openphish(url: str) -> Dict[str, Any]:
    """
    OpenPhish community feed membership (keyless, v5.2).

    Two verdict levels: an exact URL match is the strongest signal
    (``openphish_match: 'exact url'``), while a host-only match means the
    same host is currently phishing under another path
    (``openphish_match: 'host'``). A feed that answered and does not contain
    the target reports ``openphish_listed: False`` - a genuine clear, not a
    failure. Switched off together with the IP feeds via
    ``app.feeds_enabled``.
    """
    if not config.app_config.feeds_enabled:
        return {}
    target = (url or '').strip()
    if not target:
        return {}
    try:
        host = (urlparse(target).hostname or '').lower()
    except ValueError:
        return {}

    urls, hosts = _openphish_feed()
    if not urls and not hosts:
        return {}  # feed unavailable: no data rather than a false clear

    out: Dict[str, Any] = {}
    if target in urls:
        out['openphish_listed'] = True
        out['openphish_match'] = 'exact url'
    elif host and host in hosts:
        out['openphish_listed'] = True
        out['openphish_match'] = 'host'
    else:
        out['openphish_listed'] = False
    if out.get('openphish_listed'):
        out['openphish_feed'] = 'openphish.com community feed'
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'http_probe': _http_probe,
    'urlscan': _urlscan,
    'wayback': _wayback,
    'openphish': _openphish,
}

KEYED_SOURCES: Dict[str, Any] = {
    'google_safe_browsing': _google_safe_browsing,
    'virustotal': _virustotal,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'http_probe': 'Redirect chain, final status, title and server headers (keyless)',
    'urlscan': 'Public urlscan.io scan history and malicious verdicts (keyless)',
    'wayback': 'Wayback Machine capture history via the CDX API (keyless)',
    'openphish': 'OpenPhish community phishing feed membership: exact-URL '
                 'and host-level matches (keyless; v5.2)',
    'google_safe_browsing': 'Google Safe Browsing threat verdicts (keyed)',
    'virustotal': 'URL scan detections and reputation (keyed)',
}


def _keep(value: Any) -> bool:
    # Explicit False is a real answer (host_is_ip=False, gsb_malicious=False).
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(url: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable source in parallel and merge the results.

    Args:
        url: target URL (validated by the tracker; readers stay defensive)
        keys: optional {service: api_key} map for keyed sources

    Returns:
        {
          'fields': merged_field_dict,
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }
    """
    keys = keys or {}
    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(url))

    for name, fn in _plugin_sources('url').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(url))

    for service, fn in KEYED_SOURCES.items():
        key = keys.get(service)
        if key and config.is_source_enabled(service) \
                and health.source_allowed(service):
            tasks[service] = (lambda f=fn, k=key: f(url, k))

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

    health.record_batch('url', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # Self-describing keys every URL report should carry. The host becomes a
    # 'domain' field only when it really is one, so IP-host URLs do not turn
    # into bogus domain pivots.
    merged['url'] = url
    provenance.setdefault('url', []).append('target')

    host = (url_parts(url) or {}).get('host') or ''
    if host and '.' in host and not _host_is_ip(host):
        merged['domain'] = host
        provenance.setdefault('domain', []).append('target')

    return {'fields': merged, 'sources': status, 'provenance': provenance}
