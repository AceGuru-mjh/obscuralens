"""
Keyless multi-source domain intelligence.

Every provider is queried independently and results are merged field-by-field,
so one blocked or flaky source cannot blank out a whole report. Coverage:

* ``rdap``        - registry registration dates, registrar, nameservers, abuse
* ``dns``         - MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC posture
* ``certspotter`` - Certificate Transparency issuance history and subdomains
* ``http``        - homepage status, title, server/security headers, robots.txt
* ``doh.google``  - A/AAAA/MX/NS via DNS-over-HTTPS, cross-confirming ``dns``
* ``doh.cloudflare`` - the same record set via Cloudflare's 1.1.1.1 resolver
  (v5.2), stacking with both resolvers in provenance - a third independent
  vantage point for DNS answers

Sources listed in ``app.disabled_sources`` are skipped. Field provenance is
tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import quote

import requests

from ..config import config
from ..health import health
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
# v4.0 keyless additions
# ---------------------------------------------------------------------------

def _crtsh(domain: str) -> Dict[str, Any]:
    """
    crt.sh Certificate Transparency search (keyless, can be slow): every
    certificate issued for the domain and its subdomains, with issuer names.
    """
    ok, data, _ = http.get_json(
        f"https://crt.sh/?q=%.{quote(domain, safe='')}&output=json",
        cache_ttl=1800)
    if not ok or not isinstance(data, list) or not data:
        return {}

    root = domain.lower()
    subdomains = set()
    issuers = {}
    serials = set()
    latest = ''
    for record in data:
        if not isinstance(record, dict):
            continue
        if record.get('id') is not None:
            serials.add(record['id'])
        issuer = str(record.get('issuer_name') or '').strip()
        if issuer:
            issuers[issuer] = issuers.get(issuer, 0) + 1
        for field in ('common_name', 'name_value'):
            for name in str(record.get(field) or '').split('\n'):
                name = name.strip().lower().lstrip('*.').rstrip('.')
                if name and name != root and name.endswith(root):
                    subdomains.add(name)
        not_before = str(record.get('not_before') or '')
        if not_before > latest:
            latest = not_before

    out: Dict[str, Any] = {'crtsh_certs': len(serials) or len(data)}
    if subdomains:
        out['crtsh_subdomains'] = sorted(subdomains)[:100]
    top_issuers = sorted(issuers.items(), key=lambda kv: -kv[1])[:3]
    if top_issuers:
        out['crtsh_issuers'] = [name for name, _count in top_issuers]
    if latest:
        out['crtsh_last_issued'] = latest
    return out


def _hackertarget(domain: str) -> Dict[str, Any]:
    """hackertarget.com host search (keyless, daily quota): subdomain/IP pairs."""
    ok, text, _ = http.get_text(
        f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not ok or not text:
        return {}
    low = text.strip().lower()
    if low.startswith('error') or 'invalid' in low or 'quota' in low:
        return {}

    subdomains: List[str] = []
    ips: List[str] = []
    for line in text.strip().splitlines():
        parts = [p.strip() for p in line.split(',')]
        if not parts or not parts[0]:
            continue
        subdomains.append(parts[0])
        if len(parts) > 1 and parts[1]:
            ips.append(parts[1])
    if not subdomains:
        return {}
    out: Dict[str, Any] = {
        'hackertarget_subdomains': subdomains[:50],
        'hackertarget_subdomain_count': len(subdomains),
    }
    if ips:
        out['hackertarget_ips'] = sorted(set(ips))[:20]
    return out


def _security_txt(domain: str) -> Dict[str, Any]:
    """
    RFC 9116 security.txt (keyless): disclosure contacts, expiry and policy
    URLs published under /.well-known/security.txt.
    """
    status, text, _error = http.fetch(f"https://{domain}/.well-known/security.txt")
    if status != 200 or not text:
        return {}

    contacts: List[str] = []
    expires = ''
    languages = ''
    canonical: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        field, _, value = line.partition(':')
        value = value.strip()
        if not value:
            continue
        field = field.lower()
        if field == 'contact' and len(contacts) < 5:
            contacts.append(value)
        elif field == 'expires':
            expires = value
        elif field == 'preferred-languages':
            languages = value
        elif field == 'canonical' and len(canonical) < 3:
            canonical.append(value)

    out: Dict[str, Any] = {'security_txt': True}
    if contacts:
        out['security_contacts'] = contacts
    if expires:
        out['security_expires'] = expires
    if languages:
        out['security_languages'] = languages
    if canonical:
        out['security_canonical'] = canonical
    return out


# ---------------------------------------------------------------------------
# v5.0 keyless additions
# ---------------------------------------------------------------------------

# DoH JSON answer type codes (RFC 8484): A=1, NS=2, MX=15, AAAA=28.
_DOH_TYPE_A = 1
_DOH_TYPE_NS = 2
_DOH_TYPE_MX = 15
_DOH_TYPE_AAAA = 28


def _doh_answers(data: Any, type_code: int) -> List[str]:
    """Collect the ``data`` values of one answer type from a DoH reply."""
    values: List[str] = []
    if not isinstance(data, dict):
        return values
    for answer in data.get('Answer') or []:
        if not isinstance(answer, dict):
            continue
        if answer.get('type') == type_code and answer.get('data'):
            values.append(str(answer['data']))
    return values


def _doh_google(domain: str) -> Dict[str, Any]:
    """
    DNS-over-HTTPS core record set via Google Public DNS (keyless).

    Endpoint: ``https://dns.google/resolve?name={domain}&type=A`` (plus
    AAAA, MX and NS - four sequential queries inside one reader).

    This deliberately re-uses the field names of the built-in ``dns`` source
    (``a_records`` / ``aaaa_records`` / ``mx_records`` / ``ns_records``) so
    the two sources cross-confirm each other: ``gather_all`` provenance then
    lists every provider of a record set instead of silently picking one.
    The extra ``doh_responded`` marker records that the resolver itself
    answered (Status 0) even when a record type is empty - a "no MX"
    answer is a fact, not a failure. A bare ``.`` MX answer (RFC 7505 null
    MX) is dropped just like the ``dns`` reader drops it. If none of the
    four queries reach the resolver, the reader returns ``{}`` so the
    source reports no data.
    """
    out: Dict[str, Any] = {}
    responded = False

    queries = (
        ('A', _DOH_TYPE_A),
        ('AAAA', _DOH_TYPE_AAAA),
        ('MX', _DOH_TYPE_MX),
        ('NS', _DOH_TYPE_NS),
    )
    for rtype, type_code in queries:
        ok, data, _ = http.get_json(
            f"https://dns.google/resolve?name={domain}&type={rtype}")
        if not ok or not isinstance(data, dict) or data.get('Status') != 0:
            continue
        responded = True
        answers = _doh_answers(data, type_code)
        if not answers:
            continue
        if type_code == _DOH_TYPE_A:
            out['a_records'] = [v for v in answers if _is_ipv4_literal(v)]
        elif type_code == _DOH_TYPE_AAAA:
            out['aaaa_records'] = [v for v in answers if _is_ipv6_literal(v)]
        elif type_code == _DOH_TYPE_MX:
            hosts = [h for h in _doh_mx_hosts(answers) if h and h != '.']
            if hosts:
                out['mx_records'] = hosts
        elif type_code == _DOH_TYPE_NS:
            out['ns_records'] = sorted({v.rstrip('.') for v in answers if v})

    if not responded:
        return {}
    out['doh_responded'] = True
    return {k: v for k, v in out.items() if v}


def _is_ipv4_literal(value: str) -> bool:
    """True when the DoH answer value is a literal IPv4 address."""
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def _is_ipv6_literal(value: str) -> bool:
    """True when the DoH answer value is a literal IPv6 address."""
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def _doh_mx_hosts(answers: List[str]) -> List[str]:
    """
    Turn ``"10 alt1.example.com."`` MX answers into hosts, priority-sorted.

    Mirrors the format of the ``dns`` reader's ``mx_records`` field so the
    two sources merge cleanly; ``_doh_google`` then drops the null-MX ``.``
    the same way the ``dns`` reader does.
    """
    records: List[Any] = []
    for raw in answers:
        parts = raw.split()
        if len(parts) == 2:
            try:
                priority = int(parts[0])
            except ValueError:
                priority = 999
            records.append((priority, parts[1].rstrip('.') or '.'))
        elif raw:
            records.append((999, raw.rstrip('.') or '.'))
    records.sort(key=lambda item: item[0])
    return [host for _prio, host in records]


def _doh_cloudflare(domain: str) -> Dict[str, Any]:
    """
    DNS-over-HTTPS core record set via Cloudflare 1.1.1.1 (keyless, v5.2).

    Endpoint: ``https://cloudflare-dns.com/dns-query?name={domain}&type=A``
    (plus AAAA, MX and NS) with the ``Accept: application/dns-json`` header
    the JSON variant of RFC 8484 requires - the plain endpoint without that
    header answers with wireformat bytes instead.

    Like ``doh.google`` this deliberately re-uses the ``dns`` reader's field
    names (``a_records`` / ``aaaa_records`` / ``mx_records`` /
    ``ns_records``) so the classic resolver, Google and Cloudflare stack in
    ``gather_all`` provenance: three independent vantage points answering
    the same question. ``doh_cf_responded`` records that the resolver
    answered (Status 0) even when a record type is empty.
    """
    out: Dict[str, Any] = {}
    responded = False

    queries = (
        ('A', _DOH_TYPE_A),
        ('AAAA', _DOH_TYPE_AAAA),
        ('MX', _DOH_TYPE_MX),
        ('NS', _DOH_TYPE_NS),
    )
    for rtype, type_code in queries:
        ok, data, _ = http.get_json(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}",
            headers={'Accept': 'application/dns-json'})
        if not ok or not isinstance(data, dict) or data.get('Status') != 0:
            continue
        responded = True
        answers = _doh_answers(data, type_code)
        if not answers:
            continue
        if type_code == _DOH_TYPE_A:
            out['a_records'] = [v for v in answers if _is_ipv4_literal(v)]
        elif type_code == _DOH_TYPE_AAAA:
            out['aaaa_records'] = [v for v in answers if _is_ipv6_literal(v)]
        elif type_code == _DOH_TYPE_MX:
            hosts = [h for h in _doh_mx_hosts(answers) if h and h != '.']
            if hosts:
                out['mx_records'] = hosts
        elif type_code == _DOH_TYPE_NS:
            out['ns_records'] = sorted({v.rstrip('.') for v in answers if v})

    if not responded:
        return {}
    out['doh_cf_responded'] = True
    return {k: v for k, v in out.items() if v}


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
    'crt.sh': _crtsh,
    'hackertarget': _hackertarget,
    'security_txt': _security_txt,
    'doh.google': _doh_google,
    'doh.cloudflare': _doh_cloudflare,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'rdap': 'Registration dates, registrar, nameservers, abuse contact (keyless)',
    'dns': 'MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC (keyless)',
    'certspotter': 'Certificate Transparency history and subdomains (keyless)',
    'http': 'Status, title, server/security headers, robots.txt (keyless)',
    'urlscan': 'Public urlscan.io scan history, observed IPs and servers (keyless)',
    'wayback': 'First and last Wayback Machine captures (keyless)',
    'crt.sh': 'Certificate Transparency via crt.sh: certificates, subdomains, issuers (keyless)',
    'hackertarget': 'Subdomain/IP host search (keyless, daily quota)',
    'security_txt': 'RFC 9116 security.txt disclosure contacts and policy (keyless)',
    'doh.google': 'A/AAAA/MX/NS records via Google DNS-over-HTTPS, cross-confirming the dns source (keyless)',
    'doh.cloudflare': 'A/AAAA/MX/NS records via the Cloudflare 1.1.1.1 DoH resolver, a third DNS vantage point (keyless; v5.2)',
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
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(domain))

    for name, fn in _plugin_sources('domain').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
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

    health.record_batch('domain', status)

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
