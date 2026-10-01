"""
Keyless multi-source domain intelligence.

Every provider is queried independently and results are merged field-by-field,
so one blocked or flaky source cannot blank out a whole report. Coverage:

* ``rdap``        - registry registration dates, registrar, nameservers, abuse
* ``dns``         - MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC posture
* ``certspotter`` - Certificate Transparency issuance history and subdomains
* ``http``        - homepage status, title, server/security headers, robots.txt

Sources listed in ``app.disabled_sources`` are skipped. Field provenance is
tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import re
from typing import Any, Dict, List
from urllib.parse import quote

import requests

from ..config import config
from ..utils.http_client import http
from .email_sources import _dns_records, _domain_rdap, _parse_iso

# Response headers whose presence is a useful hardening signal.
SECURITY_HEADERS = (
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
)

# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _rdap(domain: str) -> Dict[str, Any]:
    """Registry registration dates, registrar, nameservers and abuse contact."""
    return _domain_rdap(domain)


def _dns(domain: str) -> Dict[str, Any]:
    """DNS records and mail-security posture (MX, SPF, DMARC, DNSSEC)."""
    return _dns_records(domain)


def _certspotter(domain: str) -> Dict[str, Any]:
    """Certificate Transparency issuance history via Cert Spotter (keyless)."""
    ok, data, _ = http.get_json(
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        f"&include_subdomains=true&expand=dns_names")
    if not ok or not isinstance(data, list):
        return {}

    subdomains = set()
    stamps = []
    revoked = 0

    for record in data:
        if not isinstance(record, dict):
            continue
        if record.get('revoked') is True:
            revoked += 1
        for name in record.get('dns_names') or []:
            name = str(name).strip().lower()
            if name.startswith('*.'):
                name = name[2:]
            name = name.rstrip('.')
            if name and name != domain.lower():
                subdomains.add(name)
        parsed = _parse_iso(record.get('not_before'))
        if parsed:
            stamps.append((parsed, record.get('not_before')))

    out: Dict[str, Any] = {
        'ct_certificates': len(data),
        'ct_revoked': revoked,
    }
    if subdomains:
        out['ct_subdomains'] = sorted(subdomains)[:100]
    if stamps:
        out['ct_last_seen'] = max(stamps, key=lambda item: item[0])[1]
    return out


def _http_probe(domain: str) -> Dict[str, Any]:
    """Homepage status, title, headers and robots.txt presence."""
    response = None
    scheme = 'https'
    for candidate in ('https', 'http'):
        try:
            response = http.get(f"{candidate}://{domain}/", allow_redirects=True)
            scheme = candidate
            break
        except requests.exceptions.RequestException:
            response = None

    if response is None:
        # The page is unreachable over both schemes; robots.txt may still answer.
        status, _text, _error = http.fetch(f"https://{domain}/robots.txt")
        if status == 0:
            return {}
        return {'robots_txt': status == 200}

    out: Dict[str, Any] = {
        'http_status': response.status_code,
        'http_final_url': response.url,
    }

    match = re.search(r'<title[^>]*>(.*?)</title>', response.text or '',
                      re.IGNORECASE | re.DOTALL)
    if match:
        title = re.sub(r'\s+', ' ', match.group(1)).strip()
        if title:
            out['http_title'] = title[:200]

    server = response.headers.get('Server')
    if server:
        out['server'] = server
    powered_by = response.headers.get('X-Powered-By')
    if powered_by:
        out['powered_by'] = powered_by

    present = [name for name in SECURITY_HEADERS if response.headers.get(name)]
    out['security_headers'] = present
    out['missing_security_headers'] = [name for name in SECURITY_HEADERS
                                       if name not in present]

    status, _text, _error = http.fetch(f"{scheme}://{domain}/robots.txt")
    if status != 0:
        out['robots_txt'] = status == 200

    return out


def _urlscan(domain: str) -> Dict[str, Any]:
    """urlscan.io (keyless): public scan history, observed IPs and servers."""
    ok, data, _ = http.get_json(
        f"https://urlscan.io/api/v1/search/?q=domain%3A{quote(domain, safe='')}"
        f"&size=100")
    if not ok or not isinstance(data, dict):
        return {}
    results = data.get('results')
    if not isinstance(results, list) or not results:
        return {}

    ips: List[str] = []
    servers: List[str] = []
    times: List[str] = []
    for record in results:
        if not isinstance(record, dict):
            continue
        page = record.get('page') or {}
        task = record.get('task') or {}
        if page.get('ip'):
            ips.append(str(page['ip']))
        if page.get('server'):
            servers.append(str(page['server']))
        if task.get('time'):
            times.append(str(task['time']))

    out: Dict[str, Any] = {'urlscan_scans': len(results)}
    if times:
        out['urlscan_last'] = max(times)
    if ips:
        out['urlscan_ips'] = sorted(set(ips))[:10]
    if servers:
        out['urlscan_servers'] = sorted(set(servers))[:10]
    return out


def _wayback_timestamp(raw: str) -> str:
    """YYYYMMDDhhmmss -> YYYY-MM-DD hh:mm."""
    try:
        return (f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]} "
                f"{raw[8:10]}:{raw[10:12]}")
    except (TypeError, IndexError):
        return str(raw)


def _wayback(domain: str) -> Dict[str, Any]:
    """Wayback Machine: first and last archived capture (keyless CDX API)."""
    def capture(sort: str) -> Dict[str, str]:
        ok, data, _ = http.get_json(
            f"http://web.archive.org/cdx/search/cdx?url={quote(domain, safe='')}"
            f"&output=json&limit=1&sort={sort}")
        if not ok or not isinstance(data, list) or len(data) < 2:
            return {}
        row = data[1]
        if not isinstance(row, list) or len(row) < 3:
            return {}
        return {
            'timestamp': str(row[1]),
            'url': str(row[2]),
            'status': str(row[4]) if len(row) > 4 else '',
        }

    out: Dict[str, Any] = {}
    first = capture('asc')
    if first:
        out['wayback_first'] = _wayback_timestamp(first['timestamp'])
        out['wayback_first_url'] = first['url']
    last = capture('desc')
    if last:
        out['wayback_last'] = _wayback_timestamp(last['timestamp'])
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'rdap': _rdap,
    'dns': _dns,
    'certspotter': _certspotter,
    'http': _http_probe,
    'urlscan': _urlscan,
    'wayback': _wayback,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'rdap': 'Registration dates, registrar, nameservers, abuse contact (keyless)',
    'dns': 'MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC (keyless)',
    'certspotter': 'Certificate Transparency history and subdomains (keyless)',
    'http': 'Status, title, server/security headers, robots.txt (keyless)',
    'urlscan': 'Public urlscan.io scan history, observed IPs and servers (keyless)',
    'wayback': 'First and last Wayback Machine captures (keyless)',
}


def _keep(value: Any) -> bool:
    # Explicit False is a real answer (no DNSSEC, no robots.txt, ...).
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(domain: str) -> Dict[str, Any]:
    """
    Query every enabled source in parallel and merge the results.

    Args:
        domain: target domain

    Returns:
        {
          'fields': merged_field_dict,
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }
    """
    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name):
            tasks[name] = (lambda f=fn: f(domain))

    for name, fn in _plugin_sources('domain').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name):
            tasks[source_name] = (lambda f=fn: f(domain))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as ex:
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

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    return {'fields': merged, 'sources': status, 'provenance': provenance}
