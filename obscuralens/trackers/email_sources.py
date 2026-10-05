"""
Free email intelligence sources that work without an API key.

Covers MX/A/AAAA/NS/SOA/CAA/TXT records, SPF/DMARC/DKIM/DNSSEC posture,
disposable-mail detection, OpenPGP key presence and domain RDAP registration.
Keyed sources (HIBP, Hunter) are layered on by EmailTracker when configured.
"""

import concurrent.futures as futures
import contextlib
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import config
from ..utils.http_client import http

# Webmail providers - useful for spotting throwaway or generic accounts.
WEBMAIL_DOMAINS = {
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.co.id',
    'ymail.com', 'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'live.com',
    'msn.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com', 'protonmail.com',
    'proton.me', 'pm.me', 'gmx.com', 'gmx.de', 'mail.com', 'yandex.com',
    'yandex.ru', 'zoho.com', 'fastmail.com', 'hushmail.com', 'tutanota.com',
    'tuta.io', 'inbox.lv', 'seznam.cz', 'qq.com', '163.com', '126.com',
    'naver.com', 'daum.net', 'rediffmail.com', 'sina.com', 'foxmail.com',
    'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'bellsouth.net',
    'btinternet.com', 'sky.com', 'orange.fr', 'wanadoo.fr', 'laposte.net',
    'free.fr', 'web.de', 'libero.it', 'virgilio.it', 'terra.com.br',
    'uol.com.br', 'bol.com.br',
}

FREEMAIL_PATTERNS = (
    re.compile(r'\d{5,}'),          # long digit runs
    re.compile(r'^[a-z]{1,4}\d{3,}$', re.I),
)

# Selectors probed for DKIM public keys. Covers the common providers.
DKIM_SELECTORS = ('default', 'google', 'selector1', 'selector2', 'k1',
                  'mail', 'dkim')


def _dns_query(domain: str, rtype: str) -> List[str]:
    """Query DNS-over-HTTPS and return the answer values."""
    ok, data, _ = http.get_json(
        f"https://dns.google/resolve?name={domain}&type={rtype}")
    if not ok or not data or data.get('Status') != 0:
        return []
    values = []
    for answer in data.get('Answer', []) or []:
        value = answer.get('data')
        if value:
            values.append(str(value))
    return values


def _mx_records(domain: str) -> List[str]:
    """MX hosts sorted by priority; '.' stands for a deliberate null MX."""
    ok, data, _ = http.get_json(
        f"https://dns.google/resolve?name={domain}&type=MX")
    if not ok or not data or data.get('Status') != 0:
        return []
    records = []
    for answer in data.get('Answer', []) or []:
        raw = str(answer.get('data', ''))
        # Format: "10 alt1.example.com."
        parts = raw.split()
        if len(parts) == 2:
            try:
                priority = int(parts[0])
            except ValueError:
                priority = 999
            host = parts[1].rstrip('.')
            records.append((priority, host or '.'))
        elif raw:
            records.append((999, raw.rstrip('.') or '.'))
    records.sort(key=lambda x: x[0])
    return [host for _prio, host in records]


def _clean_txt(value: str) -> str:
    """Strip the surrounding quotes DoH puts around TXT chunks."""
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return value.replace('" "', '')


def _dns_records(domain: str) -> Dict[str, Any]:
    """Collect DNS records and mail-security posture for a domain."""
    out: Dict[str, Any] = {}

    # Run the independent DNS lookups concurrently.
    lookups: Dict[str, Any] = {
        'a': lambda: _dns_query(domain, 'A'),
        'aaaa': lambda: _dns_query(domain, 'AAAA'),
        'ns': lambda: _dns_query(domain, 'NS'),
        'soa': lambda: _dns_query(domain, 'SOA'),
        'caa': lambda: _dns_query(domain, 'CAA'),
        'txt': lambda: _dns_query(domain, 'TXT'),
        'dnskey': lambda: _dns_query(domain, 'DNSKEY'),
        'mx': lambda: _mx_records(domain),
    }
    for selector in DKIM_SELECTORS:
        lookups[f'dkim:{selector}'] = (
            lambda s=selector: _dns_query(f"{s}._domainkey.{domain}", 'TXT'))

    results: Dict[str, Any] = {}
    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        future_map = {ex.submit(fn): key for key, fn in lookups.items()}
        for future in futures.as_completed(future_map):
            key = future_map[future]
            try:
                results[key] = future.result() or []
            except Exception:
                results[key] = []

    if results.get('mx'):
        if '.' in results['mx']:
            out['null_mx'] = True
        usable = [host for host in results['mx'] if host and host != '.']
        if usable:
            out['mx_records'] = usable
            out['mx_count'] = len(usable)

    a_records = [v for v in results.get('a', []) if _is_ipv4(v)]
    if a_records:
        out['a_records'] = a_records

    aaaa = [v for v in results.get('aaaa', []) if ':' in v]
    if aaaa:
        out['aaaa_records'] = aaaa

    ns = sorted(v.rstrip('.') for v in results.get('ns', []) if v)
    if ns:
        out['ns_records'] = ns

    soa = results.get('soa', [])
    if soa:
        out['soa_record'] = soa[0]

    caa = [_clean_txt(v) for v in results.get('caa', []) if v]
    if caa:
        out['caa_records'] = caa

    txt = [_clean_txt(v) for v in results.get('txt', []) if v]
    # Keep TXT useful: drop the SPF/DMARC entries that have dedicated fields.
    other_txt = [v for v in txt if not v.lower().startswith(('v=spf1', 'v=dmarc1'))]
    if other_txt:
        out['txt_records'] = sorted(set(other_txt))[:10]

    spf = [v for v in txt if v.lower().startswith('v=spf1')]
    if spf:
        out['spf_record'] = spf[0]
        for token in ('include:', 'redirect=', 'a:', 'mx'):
            if token in spf[0]:
                out['spf_third_party'] = True
                break

    dmarc = [v for v in (_clean_txt(raw)
                          for raw in _dns_query(f"_dmarc.{domain}", 'TXT'))
             if v.lower().startswith('v=dmarc1')]
    if dmarc:
        out['dmarc_record'] = dmarc[0]
        for policy in ('reject', 'quarantine', 'none'):
            if f'p={policy}' in dmarc[0]:
                out['dmarc_policy'] = policy
                break

    out['dnssec'] = bool(results.get('dnskey'))
    found_selectors = [key.split(':', 1)[1] for key in lookups
                       if key.startswith('dkim:')
                       and _dkim_has_key(results.get(key, []))]
    if found_selectors:
        out['dkim_selectors'] = sorted(found_selectors)

    return out


def _dkim_has_key(values: List[str]) -> bool:
    """
    True only for a DKIM record with a non-empty public key.

    Domains often publish a wildcard ``*._domainkey`` with ``p=`` (revoked /
    anti-subdomain-abuse). That is not a usable key and must not be reported
    as one.
    """
    for value in values:
        value = _clean_txt(value)
        if 'v=dkim1' not in value.lower():
            continue
        match = re.search(r'\bp\s*=\s*([^;]+)', value, re.I)
        if match and match.group(1).strip():
            return True
    return False


def _is_ipv4(value: str) -> bool:
    parts = value.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _disposable_check(domain: str, email: str) -> Dict[str, Any]:
    """
    Disposable-mail detection: offline data pack first (3k+ known domains,
    no network), then the keyless debounce.io API as a fallback for domains
    the pack does not know.
    """
    try:  # offline pack - authoritative when it knows the domain
        from ..utils.data_packs import is_disposable_email
        if is_disposable_email(email):
            return {'disposable': True, 'disposable_source': 'local-pack'}
    except Exception:
        pass

    ok, data, _ = http.get_json(
        f"https://disposable.debounce.io/?email={email}")
    if not ok or not data:
        # The pack said 'not disposable' and the API is unreachable: report
        # the offline answer rather than nothing at all.
        return {'disposable': False, 'disposable_source': 'local-pack'}
    value = data.get('disposable')
    if isinstance(value, str):
        value = value.lower() == 'true'
    return {'disposable': bool(value), 'disposable_source': 'debounce.io'}


def _emailrep(email: str) -> Dict[str, Any]:
    """
    EmailRep.io (keyless): reputation score, suspicious flag, linked social
    profiles, breach/leak exposure and first/last activity.
    """
    ok, d, _ = http.get_json(f"https://emailrep.io/{email}", cache_ttl=3600)
    if not ok or not d or d.get('error'):
        return {}
    out: Dict[str, Any] = {
        'emailrep_reputation': d.get('reputation'),
        'emailrep_suspicious': d.get('suspicious'),
        'emailrep_references': d.get('references'),
    }
    profiles = d.get('profiles')
    if isinstance(profiles, list) and profiles:
        out['emailrep_profiles'] = [str(p) for p in profiles[:15]]
        out['emailrep_profile_count'] = len(profiles)
    for field in ('last_seen', 'first_seen'):
        if d.get(field):
            out[f'emailrep_{field}'] = d.get(field)
    # Explicit False is a real answer.
    for field in ('credentials_leaked', 'data_breach', 'active', 'deliverable'):
        if field in d and d.get(field) is not None:
            out[f'emailrep_{field}'] = bool(d.get(field))
    return out


def _github_commits(email: str) -> Dict[str, Any]:
    """
    GitHub commit search by author email (keyless, low rate limit; a token
    configured for the ``github`` service lifts it). A hit proves the address
    contributed code and exposes commit author names and repositories.
    """
    headers = {'Accept': 'application/vnd.github+json'}
    token = config.get_api_key('github')
    if token:
        headers['Authorization'] = f"Bearer {token}"

    ok, d, _ = http.get_json(
        f"https://api.github.com/search/commits?q=author-email:{email}"
        f"&per_page=5&sort=author-date",
        headers=headers, cache_ttl=3600)
    if not ok or not isinstance(d, dict):
        return {}
    total = d.get('total_count')
    if not total:
        return {}

    repos: List[str] = []
    names: List[str] = []
    dates: List[str] = []
    for item in (d.get('items') or []):
        if not isinstance(item, dict):
            continue
        repository = item.get('repository') or {}
        full_name = repository.get('full_name')
        if full_name and full_name not in repos:
            repos.append(str(full_name))
        commit = item.get('commit') or {}
        author = commit.get('author') or {}
        if author.get('name') and author['name'] not in names:
            names.append(str(author['name']))
        if author.get('date'):
            dates.append(str(author['date']))

    out: Dict[str, Any] = {'github_commit_matches': int(total)}
    if repos:
        out['github_commit_repos'] = repos[:5]
    if names:
        out['github_author_names'] = names[:3]
    if dates:
        out['github_last_commit'] = max(dates)
    return out


def _openpgp(email: str) -> Dict[str, Any]:
    """Whether the address has a published OpenPGP key on keys.openpgp.org."""
    status, text, _ = http.fetch(
        f"https://keys.openpgp.org/vks/v1/by-email/{email}")
    # 404 from the keyserver means "no key for this address" - a real answer.
    if status == 404:
        return {'openpgp': False}
    if status != 200:
        return {}
    if 'no key found' in (text or '').lower() or not (text or '').strip():
        return {'openpgp': False}
    fingerprints = re.findall(r'-----END PGP PUBLIC KEY BLOCK-----', text)
    return {'openpgp': True, 'openpgp_key_size': len(fingerprints)}


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _domain_rdap(domain: str) -> Dict[str, Any]:
    """gTLD registration data (creation/expiry dates, registrar)."""
    tld = domain.rsplit('.', 1)[-1].lower()
    if tld in ('com', 'net', 'org'):
        base = "https://rdap.verisign.com"
        path = {"com": "com", "net": "com", "org": "org"}[tld]
        url = f"{base}/{path}/v1/domain/{domain}"
    else:
        url = f"https://rdap.org/domain/{domain}"

    ok, data, _ = http.get_json(url)
    if not ok or not data or data.get('errorCode'):
        return {}

    out: Dict[str, Any] = {}
    out['rdap_handle'] = data.get('handle')
    out['rdap_ldh'] = data.get('ldhName')

    status = data.get('status') or []
    if status:
        out['domain_status'] = status

    for event in data.get('events') or []:
        action = str(event.get('eventAction', '')).lower()
        if action == 'registration':
            out['domain_created'] = event.get('eventDate')
        elif action == 'expiration':
            out['domain_expires'] = event.get('eventDate')
        elif action in ('last changed', 'last update'):
            out['domain_updated'] = event.get('eventDate')

    now = datetime.now(timezone.utc)
    created = _parse_iso(out.get('domain_created'))
    if created:
        out['domain_age_days'] = max(0, (now - created).days)
    expires = _parse_iso(out.get('domain_expires'))
    if expires:
        out['expires_in_days'] = (expires - now).days

    for ent in data.get('entities') or []:
        roles = [str(r).lower() for r in (ent.get('roles') or [])]
        vcard = ent.get('vcardArray')
        fields: Dict[str, str] = {}
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4:
                    fields[item[0]] = item[3]
        if 'registrar' in roles and fields.get('fn'):
            out['registrar'] = fields['fn']
        if 'abuse' in roles and fields.get('email'):
            out['abuse_email'] = fields['email']

    ns = [str(n.get('ldhName', '')).rstrip('.') for n in (data.get('nameservers') or [])]
    if ns:
        out['nameservers'] = sorted(ns)

    return out


def _gravatar(email: str) -> Dict[str, Any]:
    """
    Gravatar check. Gravatar is blocked from some networks, so failures are
    reported as 'unknown' rather than 'no avatar'.
    """
    # Gravatar's URL scheme is defined as md5(lowercase(trim(email))); MD5 is
    # the protocol here, not a security choice, so it is flagged as such
    # (bandit B324) and must not be "upgraded" or the lookup breaks.
    digest = hashlib.md5(email.strip().lower().encode('utf-8'),
                         usedforsecurity=False).hexdigest()
    status, _text, error = http.fetch(
        f"https://www.gravatar.com/avatar/{digest}?d=404&s=80")
    if error or status == 0:
        return {'gravatar': 'unknown', 'gravatar_error': error or 'network'}
    if status == 200:
        return {'gravatar': True}
    if status == 404:
        return {'gravatar': False}
    return {'gravatar': 'unknown'}


def _pattern_analysis(email: str, local_part: str, domain: str) -> Dict[str, Any]:
    """Heuristics on the local part - a weak signal, clearly labelled."""
    out: Dict[str, Any] = {}
    digits = re.sub(r'\D', '', local_part)
    out['local_length'] = len(local_part)
    out['has_digits'] = bool(digits)
    if digits:
        out['digit_count'] = len(digits)
    out['is_webmail'] = domain.lower() in WEBMAIL_DOMAINS
    for pattern in FREEMAIL_PATTERNS:
        if pattern.search(local_part):
            out['looks_generated'] = True
            break
    return out


def _hibp_breaches(email: str, api_key: str) -> Dict[str, Any]:
    ok, data, _ = http.get_json(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers={'hibp-api-key': api_key}, use_cache=False)
    if not ok:
        # 404 means "clean", which get_json reports as an HTTP error.
        return {}
    breaches = data if isinstance(data, list) else []
    return {
        'hibp_breached': True,
        'hibp_breach_count': len(breaches),
        'hibp_breaches': [
            {
                'name': b.get('Name'),
                'domain': b.get('Domain'),
                'date': b.get('BreachDate'),
                'added': b.get('AddedDate'),
                'modified': b.get('ModifiedDate'),
                'pwn_count': b.get('PwnCount'),
                'data_classes': b.get('DataClasses'),
                'description': (b.get('Description') or '')[:300],
                'is_verified': b.get('IsVerified'),
                'is_sensitive': b.get('IsSensitive'),
            }
            for b in breaches
        ],
        'hibp_classes': sorted({
            dc for b in breaches for dc in (b.get('DataClasses') or [])
        }),
    }


def _hibp_pastes(email: str, api_key: str) -> Dict[str, Any]:
    ok, data, _ = http.get_json(
        f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
        headers={'hibp-api-key': api_key}, use_cache=False)
    if not ok or not isinstance(data, list):
        return {}
    return {
        'paste_count': len(data),
        'pastes': [
            {
                'id': p.get('ID'),
                'date': p.get('PasteDate'),
                'url': p.get('URL'),
                'entries': p.get('Entries'),
            }
            for p in data
        ],
    }


def _hunter_verify(email: str, api_key: str) -> Dict[str, Any]:
    ok, data, _ = http.get_json(
        f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}",
        use_cache=False)
    if not ok or not data:
        return {}
    result = data.get('data', {}) or {}
    return {
        'hunter_status': result.get('status'),
        'hunter_result': result.get('result'),
        'hunter_score': result.get('score'),
        'hunter_disposable': result.get('disposable'),
        'hunter_webmail': result.get('webmail'),
        'hunter_mx': result.get('mx_records'),
        'hunter_smtp_server': result.get('smtp_server'),
        'hunter_smtp_check': result.get('smtp_check'),
        'hunter_accept_all': result.get('accept_all'),
        'hunter_blocked': result.get('blocked'),
        'hunter_free': result.get('free'),
    }


# ---------------------------------------------------------------------------
# v6.1 addition: XposedOrNot breach analytics - the keyless counterpart to
# the keyed HIBP breach source. Probed live before shipping (positive
# john@gmail.com answers a full risk profile, a random address answers
# null metrics).
# ---------------------------------------------------------------------------

def _xposedornot(email: str) -> Dict[str, Any]:
    """
    XposedOrNot breach analytics (keyless, v6.1).

    Endpoint: ``https://api.xposedornot.com/v1/breach-analytics?email=…``.
    Aggregates public breach corpora into a risk profile: a 0-100 risk
    score, an industry breakdown, password-strength mix and the list of
    exposing breaches with dates and victim counts. An address with no
    exposure answers null metrics - reported honestly as
    ``xposedornot_breached: False`` rather than a source failure, which
    also cross-confirms the keyed HIBP verdict when both run.

    Fields: ``xposedornot_breached``, ``xposedornot_risk_score``,
    ``xposedornot_risk_label``, ``xposedornot_breaches`` (count),
    ``xposedornot_breach_sites`` (top ten), ``xposedornot_pastes``,
    ``xposedornot_passwords_weak``.
    """
    ok, d, _ = http.get_json(
        f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
        cache_ttl=3600)
    if not isinstance(d, dict):
        return {}

    # The API answers HTTP 200 with null metrics for addresses that have no
    # exposure - a real negative. Only a payload without the metric keys at
    # all (proxies, error pages) counts as no data.
    if 'BreachMetrics' not in d and 'ExposedBreaches' not in d:
        return {}

    breaches = d.get('ExposedBreaches')
    metrics = d.get('BreachMetrics')

    out: Dict[str, Any] = {'xposedornot_breached': bool(breaches)}
    if isinstance(metrics, dict):
        risk = metrics.get('risk')
        if isinstance(risk, list) and risk and isinstance(risk[0], dict):
            if risk[0].get('risk_score') is not None:
                with contextlib.suppress(TypeError, ValueError):
                    out['xposedornot_risk_score'] = int(risk[0].get('risk_score'))
            if risk[0].get('risk_label'):
                out['xposedornot_risk_label'] = risk[0].get('risk_label')
        strength = metrics.get('passwords_strength')
        if isinstance(strength, list) and strength and isinstance(strength[0], dict):
            easy = strength[0].get('EasyToCrack')
            if easy is not None:
                with contextlib.suppress(TypeError, ValueError):
                    out['xposedornot_passwords_weak'] = int(easy)

    if isinstance(breaches, list) and breaches:
        out['xposedornot_breaches'] = len(breaches)
        sites = []
        for breach in breaches[:10]:
            if isinstance(breach, dict) and breach.get('breach'):
                sites.append(str(breach.get('breach')))
        if sites:
            out['xposedornot_breach_sites'] = sites

    pastes = d.get('PastesSummary')
    if isinstance(pastes, dict) and pastes.get('cnt') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['xposedornot_pastes'] = int(pastes.get('cnt'))
    return out


KEYED_SOURCES = {
    'haveibeenpwned': _hibp_breaches,
    'hibp_pastes': _hibp_pastes,
    'hunter': _hunter_verify,
}

FREE_SOURCES = {
    'dns': _dns_records,
    'disposable': _disposable_check,
    'openpgp': _openpgp,
    'domain_rdap': _domain_rdap,
    'gravatar': _gravatar,
    'emailrep': _emailrep,
    'github_commits': _github_commits,
    'xposedornot': _xposedornot,
}

SOURCE_CATALOG = {
    'dns': 'MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC (keyless)',
    'disposable': 'Disposable-mail detection: offline pack + debounce.io (keyless)',
    'openpgp': 'OpenPGP key presence on keys.openpgp.org (keyless)',
    'domain_rdap': 'Domain registration dates, registrar, abuse contact (keyless)',
    'gravatar': 'Gravatar avatar existence (keyless)',
    'emailrep': 'EmailRep.io reputation, linked profiles, leak flags (keyless)',
    'github_commits': 'GitHub commit authorship search (keyless, low rate)',
    'xposedornot': 'Breach risk profile, exposing sites, paste count via '
                   'XposedOrNot breach analytics (keyless; v6.1)',
    'patterns': 'Local-part heuristics (local)',
    'haveibeenpwned': 'Breach exposure (keyed)',
    'hibp_pastes': 'Paste exposure (keyed)',
    'hunter': 'Deliverability verification (keyed)',
}
