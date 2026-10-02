"""
Heuristic phishing-likelihood scoring (EXPERIMENTAL).

Scores a URL or bare domain 0-100 with an explainable breakdown: every point
is attached to a reason row (``{'id', 'points', 'detail'}``) whose detail text
contains the actual observed values, so an analyst can audit the verdict.

Verdicts: 0-19 benign, 20-49 suspicious, 50+ likely-phishing.

Signal families: phishing keywords (from the ``phishing_keywords`` data
pack), typosquatting (Levenshtein distance to ``popular_domains`` pack
entries), brand tokens in subdomains, punycode / IP-literal hosts, odd
ports, deep subdomains, hyphen/digit/length anomalies, risky TLDs, doubled
file extensions, embedded 'https' in hosts, userinfo obfuscation, excessive
URL length and (optionally, via the ``fields`` argument) freshly registered
domains.

Data packs are imported defensively - when ``utils.data_packs`` is absent the
pack lists are simply empty and those signals stay silent.
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

try:  # data_packs is being introduced by a parallel v4.0 workstream
    from ..utils import data_packs as _data_packs
except ImportError:  # pragma: no cover - pack module not shipped yet
    _data_packs = None  # type: ignore

__all__ = ['score', 'score_url', 'score_domain', 'phishing_sections']

# Weights (points) per signal.
_W_KEYWORD = 12          # each, capped at 3 keywords
_W_TYPOSQUAT = 25
_W_BRAND_TOKEN = 30
_W_PUNYCODE = 30
_W_IP_HOST = 20
_W_ODD_PORT = 8
_W_SUBDOMAIN_DEPTH = 8
_W_HYPHENS = 8
_W_DIGITS = 6
_W_LONG_HOST = 6
_W_RISKY_TLD = 10
_W_DOUBLE_EXT = 35
_W_HTTPS_IN_HOST = 15
_W_USERINFO = 25
_W_LONG_URL = 5
_W_YOUNG_DOMAIN = 10

_KEYWORD_CAP = 3
_TYPOSQUAT_MAX_DISTANCE = 2
_BRAND_MIN_TOKEN_LEN = 4
_SUBDOMAIN_DEPTH_THRESHOLD = 4
_HYPHEN_THRESHOLD = 3
_DIGIT_THRESHOLD = 3
_HOST_LENGTH_THRESHOLD = 40
_URL_LENGTH_THRESHOLD = 100
_YOUNG_DOMAIN_DAYS = 30
_COMMON_PORTS = (80, 443, 8080, 8443)

RISKY_TLDS = frozenset((
    'zip', 'mov', 'top', 'xyz', 'click', 'gq', 'tk', 'ml', 'cf', 'work',
    'bar', 'rest', 'cyou', 'sbs', 'icu', 'cam',
))

_DOUBLE_EXT_RE = re.compile(
    r'\.(?:pdf|doc|docx|xlsx|jpg|png|txt)\.(?:exe|scr|js|vbs|bat|cmd|ps1|jar|msi)$',
    re.IGNORECASE,
)
_PUNYCODE_RE = re.compile(r'(^|\.)xn--', re.IGNORECASE)

# Module-level caches for the two data packs (populated on first use; empty
# loads are retried on the next call so a pack appearing later is picked up).
_POPULAR_CACHE: Optional[List[str]] = None
_KEYWORD_CACHE: Optional[List[str]] = None


def _reset_cache() -> None:
    """Drop the cached data-pack lists (test hook; also refreshes packs)."""
    global _POPULAR_CACHE, _KEYWORD_CACHE
    _POPULAR_CACHE = None
    _KEYWORD_CACHE = None


def _load_pack(name: str) -> List[str]:
    """Load one data pack through the (possibly absent) data_packs module."""
    if _data_packs is None:
        return []
    try:
        values = _data_packs.load_data_pack(name)
    except Exception:
        return []
    if not isinstance(values, (list, tuple, set)):
        return []
    return sorted({item.strip().lower() for item in values
                   if isinstance(item, str) and item.strip()})


def _popular_domains() -> List[str]:
    global _POPULAR_CACHE
    if _POPULAR_CACHE:
        return _POPULAR_CACHE
    values = _load_pack('popular_domains')
    if values:
        _POPULAR_CACHE = values
    return values


def _phishing_keywords() -> List[str]:
    global _KEYWORD_CACHE
    if _KEYWORD_CACHE:
        return _KEYWORD_CACHE
    values = _load_pack('phishing_keywords')
    if values:
        _KEYWORD_CACHE = values
    return values


def _levenshtein(a: str, b: str, cap: int) -> int:
    """
    Iterative DP edit distance with early exit.

    Returns the real distance when it is <= ``cap``; anything larger (or a
    length difference already beyond the cap) returns ``cap + 1`` so callers
    never pay for unbounded comparisons.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        row_min = i
        for j, char_b in enumerate(b, 1):
            cost = 0 if char_a == char_b else 1
            value = min(previous[j] + 1, current[j - 1] + 1,
                        previous[j - 1] + cost)
            current.append(value)
            if value < row_min:
                row_min = value
        if row_min > cap:
            return cap + 1
        previous = current
    return previous[-1]


def _parse_target(target: Any) -> Dict[str, Any]:
    """Decompose a URL or bare domain into scoring primitives."""
    text = str(target or '').strip()
    is_url = text.lower().startswith(('http://', 'https://'))
    scheme = ''
    port: Optional[int] = None
    userinfo = False
    if is_url:
        parsed = urlsplit(text)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or '').lower()
        path = parsed.path or ''
        query = parsed.query or ''
        userinfo = '@' in (parsed.netloc or '')
        try:
            port = parsed.port
        except ValueError:
            port = None
    else:
        # Bare domain (possibly dirty): take the authority-ish head only.
        head = text.split('/')[0].split('?')[0].split('#')[0]
        host = head.strip('.').lower()
        path = ''
        query = ''
    return {
        'text': text, 'is_url': is_url, 'scheme': scheme, 'host': host,
        'path': path, 'query': query, 'port': port, 'userinfo': userinfo,
    }


def _registered_domain(host: str, is_ip: bool) -> str:
    """Naive registered domain: the last two labels (no public suffix list)."""
    if not host or is_ip or '.' not in host:
        return ''
    labels = host.split('.')
    return '.'.join(labels[-2:]) if len(labels) >= 2 else host


def _is_ip_literal(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        return False
    return True


def _parse_date(value: Any) -> Optional[datetime]:
    """Parse an ISO date or an epoch (s/ms) into an aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        stamp = value
    else:
        text = str(value).strip()
        if not text:
            return None
        stamp = None
        try:
            stamp = datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError:
            stamp = None
        if stamp is None:
            try:
                number = float(text)
            except ValueError:
                return None
            if number <= 0:
                return None
            if number > 1e12:  # milliseconds
                number /= 1000.0
            try:
                stamp = datetime.fromtimestamp(number, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def _domain_age_days(fields: Optional[Dict[str, Any]]) -> Optional[int]:
    """Age in days from the first parsable creation field; None otherwise."""
    if not isinstance(fields, dict):
        return None
    for key in ('created', 'rdap_registered', 'registered', 'created_on'):
        stamp = _parse_date(fields.get(key))
        if stamp is not None:
            age = (datetime.now(timezone.utc) - stamp).total_seconds() / 86400.0
            return int(age)
    return None


def score(target: Any, fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    EXPERIMENTAL: score a URL or bare domain for phishing likelihood.

    Args:
        target: full URL (``http(s)://...``) or bare domain name.
        fields: optional enrichment dict - when it carries a creation date
            (``created`` / ``rdap_registered`` / ``registered`` /
            ``created_on``, ISO or epoch), a domain younger than 30 days
            adds the young-domain signal.

    Returns:
        ``{'target', 'score': 0-100, 'verdict': 'benign'|'suspicious'|
        'likely-phishing', 'reasons': [{'id','points','detail'}],
        'signals': {...raw observed values}}`` - reason details always name
        the actual values observed. Garbage input yields score 0 plus an
        ``'error'`` key. Never raises.
    """
    if not isinstance(target, str) or not target.strip():
        return {'error': 'no target provided', 'target': '', 'score': 0,
                'verdict': 'benign', 'reasons': [], 'signals': {}}

    parsed = _parse_target(target)
    host = parsed['host']
    path = parsed['path']
    query = parsed['query']
    text = parsed['text']
    is_url = parsed['is_url']

    is_ip = _is_ip_literal(host)
    registered = _registered_domain(host, is_ip)
    labels = host.split('.') if host else []
    tld = labels[-1] if len(labels) >= 2 else ''
    subdomain_depth = max(0, len(labels) - 2) if not is_ip else 0
    hyphens = host.count('-')
    digits = sum(1 for ch in host if ch.isdigit())
    keywords = _phishing_keywords()
    popular = _popular_domains()

    reasons: List[Dict[str, Any]] = []

    def add(signal_id: str, points: int, detail: str) -> None:
        reasons.append({'id': signal_id, 'points': points, 'detail': detail})

    # --- phishing keywords in host / path / query (+12 each, cap 3) -------
    matched_keywords: List[str] = []
    for keyword in keywords:
        if len(keyword) < 3:
            continue
        if keyword in host:
            add('keyword', _W_KEYWORD,
                f"phishing keyword '{keyword}' in host '{host}'")
        elif keyword in path:
            add('keyword', _W_KEYWORD,
                f"phishing keyword '{keyword}' in path '{path or '/'}'")
        elif keyword in query:
            add('keyword', _W_KEYWORD,
                f"phishing keyword '{keyword}' in query '{query[:60]}'")
        else:
            continue
        matched_keywords.append(keyword)
        if len(matched_keywords) >= _KEYWORD_CAP:
            break

    # --- typosquatting: small edit distance to a popular domain ----------
    typosquat_of: Optional[str] = None
    typosquat_distance: Optional[int] = None
    if registered and not is_ip:
        for candidate in popular:
            if candidate == registered:
                continue
            distance = _levenshtein(registered, candidate, _TYPOSQUAT_MAX_DISTANCE)
            if distance <= _TYPOSQUAT_MAX_DISTANCE and (
                    typosquat_distance is None or distance < typosquat_distance):
                typosquat_of = candidate
                typosquat_distance = distance
    if typosquat_of:
        add('typosquat', _W_TYPOSQUAT,
            f"'{registered}' is {typosquat_distance} edit(s) from popular "
            f"domain '{typosquat_of}'")

    # --- brand token in host, different registered domain ----------------
    brand_hits: List[str] = []
    for candidate in popular:
        parts = candidate.split('.')
        token = parts[-2] if len(parts) >= 2 else ''
        if len(token) < _BRAND_MIN_TOKEN_LEN:
            continue
        if token in host and registered and candidate != registered \
                and token not in brand_hits:
            brand_hits.append(token)
    for token in brand_hits:
        add('brand_token', _W_BRAND_TOKEN,
            f"brand token '{token}' inside host '{host}' but registered "
            f"domain is '{registered}'")

    # --- host-level oddities -----------------------------------------------
    punycode = bool(_PUNYCODE_RE.search(host))
    if punycode:
        label = next((lab for lab in labels if lab.lower().startswith('xn--')), 'xn--')
        add('punycode', _W_PUNYCODE, f"punycode label '{label}' in host '{host}'")
    if is_ip:
        add('ip_host', _W_IP_HOST, f"host is an IP literal ({host})")
    if parsed['port'] is not None and parsed['port'] not in _COMMON_PORTS:
        add('odd_port', _W_ODD_PORT, f"non-standard port :{parsed['port']}")
    if subdomain_depth >= _SUBDOMAIN_DEPTH_THRESHOLD:
        add('subdomain_depth', _W_SUBDOMAIN_DEPTH,
            f"{subdomain_depth} subdomain labels under '{registered}'")
    if hyphens >= _HYPHEN_THRESHOLD:
        add('hyphens', _W_HYPHENS, f"{hyphens} hyphens in host '{host}'")
    if digits >= _DIGIT_THRESHOLD:
        add('digits', _W_DIGITS, f"{digits} digits in host '{host}'")
    if len(host) >= _HOST_LENGTH_THRESHOLD:
        add('long_host', _W_LONG_HOST,
            f"host is {len(host)} characters long ('{host[:40]}...')")
    if tld in RISKY_TLDS:
        add('risky_tld', _W_RISKY_TLD, f"risky TLD '.{tld}'")

    # --- path-level tricks ---------------------------------------------------
    last_segment = (path or '').rstrip('/').split('/')[-1] if path else ''
    double_extension = last_segment if last_segment and _DOUBLE_EXT_RE.search(
        last_segment) else ''
    if double_extension:
        add('double_extension', _W_DOUBLE_EXT,
            f"double extension '{double_extension}' (document disguised as "
            f"an executable)")
    if 'https' in host:
        add('https_in_host', _W_HTTPS_IN_HOST,
            f"'https' appears inside the host name '{host}'")

    # --- URL-level obfuscation (full-URL targets only) ----------------------
    if is_url:
        if parsed['userinfo']:
            add('userinfo', _W_USERINFO,
                "userinfo obfuscation: credentials before '@' in the URL "
                f"('{text.split('@')[0]}@...')")
        if len(text) >= _URL_LENGTH_THRESHOLD:
            add('long_url', _W_LONG_URL, f"URL is {len(text)} characters long")

    # --- optional enrichment: freshly registered domain ---------------------
    age_days = _domain_age_days(fields)
    if age_days is not None and 0 <= age_days < _YOUNG_DOMAIN_DAYS:
        add('young_domain', _W_YOUNG_DOMAIN,
            f"domain registered {age_days} day(s) ago (<{_YOUNG_DOMAIN_DAYS})")

    total = min(100, sum(int(reason['points']) for reason in reasons))
    if total >= 50:
        verdict = 'likely-phishing'
    elif total >= 20:
        verdict = 'suspicious'
    else:
        verdict = 'benign'

    reasons.sort(key=lambda reason: (-reason['points'], reason['id']))

    signals: Dict[str, Any] = {
        'mode': 'url' if is_url else 'domain',
        'scheme': parsed['scheme'],
        'host': host,
        'registered_domain': registered,
        'tld': tld,
        'path': path,
        'is_ip': is_ip,
        'port': parsed['port'],
        'has_userinfo': parsed['userinfo'],
        'subdomain_depth': subdomain_depth,
        'hyphens': hyphens,
        'digits': digits,
        'host_length': len(host),
        'url_length': len(text),
        'keywords_matched': matched_keywords,
        'typosquat_of': typosquat_of,
        'typosquat_distance': typosquat_distance,
        'brand_tokens': brand_hits,
        'punycode': punycode,
        'double_extension': double_extension,
        'domain_age_days': age_days,
    }
    return {
        'target': text,
        'score': total,
        'verdict': verdict,
        'reasons': reasons,
        'signals': signals,
    }


def score_url(url: Any) -> Dict[str, Any]:
    """EXPERIMENTAL: thin wrapper - :func:`score` for a full URL target."""
    return score(url)


def score_domain(domain: Any) -> Dict[str, Any]:
    """EXPERIMENTAL: thin wrapper - :func:`score` for a bare domain target."""
    return score(domain)


def phishing_sections(result: Any) -> List[Dict[str, Any]]:
    """
    EXPERIMENTAL: report sections for a :func:`score` result.

    A verdict grid followed by a reasons table (signal / points / detail).
    Error results render as a single explanatory text section. Never raises.
    """
    if not isinstance(result, dict) or result.get('error'):
        reason = result.get('error') if isinstance(result, dict) else 'malformed result'
        return [{'title': 'Phishing Score', 'type': 'text',
                 'content': f'Phishing score unavailable: {reason}'}]

    sections: List[Dict[str, Any]] = [{
        'title': 'Phishing Score (experimental)',
        'type': 'grid',
        'data': {
            'Target': result.get('target', ''),
            'Score': f"{result.get('score', 0)}/100",
            'Verdict': result.get('verdict', ''),
            'Signals fired': len(result.get('reasons') or []),
        },
    }]
    rows = [[row.get('id', ''), row.get('points', 0), row.get('detail', '')]
            for row in (result.get('reasons') or [])]
    if rows:
        sections.append({'title': 'Scoring Reasons', 'type': 'table',
                         'columns': ['Signal', 'Points', 'Detail'],
                         'rows': rows})
    return sections
