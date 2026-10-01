"""
Free email intelligence sources that work without an API key.

Covers MX/A/SPF/DMARC records, disposable-mail detection, OpenPGP key presence
and domain RDAP registration. Keyed sources (HIBP, Hunter) are layered on by
EmailTracker when configured.
"""

import base64
import hashlib
import re
from typing import Any, Dict, List, Optional

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
    'uol.com.br', 'bol.com.br', 'seznam.cz',
}

FREEMAIL_PATTERNS = (
    re.compile(r'\d{5,}'),          # long digit runs
    re.compile(r'^[a-z]{1,4}\d{3,}$', re.I),
)


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
    """MX hosts sorted by priority."""
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
            records.append((priority, parts[1].rstrip('.')))
        elif raw:
            records.append((999, raw.rstrip('.')))
    records.sort(key=lambda x: x[0])
    return [host for _prio, host in records]


def _dns_records(domain: str) -> Dict[str, Any]:
    """Collect MX, A, SPF and DMARC records for a domain."""
    out: Dict[str, Any] = {}

    mx = _mx_records(domain)
    if mx:
        out['mx_records'] = mx
        out['mx_count'] = len(mx)

    a_records = [v for v in _dns_query(domain, 'A') if _is_ipv4(v)]
    if a_records:
        out['a_records'] = a_records

    txt = _dns_query(domain, 'TXT')
    spf = [v for v in txt if v.lower().startswith('v=spf1')]
    if spf:
        out['spf_record'] = spf[0]

    dmarc = [v for v in _dns_query(f"_dmarc.{domain}", 'TXT')
             if v.lower().startswith('v=dmarc1')]
    if dmarc:
        out['dmarc_record'] = dmarc[0]
        if 'p=reject' in dmarc[0]:
            out['dmarc_policy'] = 'reject'
        elif 'p=quarantine' in dmarc[0]:
            out['dmarc_policy'] = 'quarantine'
        elif 'p=none' in dmarc[0]:
            out['dmarc_policy'] = 'none'

    # SPF mechanisms hint at third-party senders.
    if out.get('spf_record'):
        for token in ('include:', 'a:', 'mx', 'redirect='):
            if token in out['spf_record']:
                out['spf_third_party'] = True
                break

    return out


def _is_ipv4(value: str) -> bool:
    parts = value.split('.')
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _disposable_check(domain: str, email: str) -> Dict[str, Any]:
    """disposable.debounce.io - keyless disposable-mail detection."""
    ok, data, _ = http.get_json(
        f"https://disposable.debounce.io/?email={email}")
    if not ok or not data:
        return {}
    value = data.get('disposable')
    if isinstance(value, str):
        value = value.lower() == 'true'
    return {'disposable': bool(value)}


def _openpgp(email: str) -> Dict[str, Any]:
    """Whether the address has a published OpenPGP key on keys.openpgp.org."""
    try:
        response = http.get(f"https://keys.openpgp.org/vks/v1/by-email/{email}")
    except Exception:
        return {}
    # 404 from the keyserver means "no key for this address" - a real answer.
    if response.status_code == 404:
        return {'openpgp': False}
    if response.status_code != 200:
        return {}
    text = response.text or ''
    if 'no key found' in text.lower() or not text.strip():
        return {'openpgp': False}
    fingerprints = re.findall(r'-----END PGP PUBLIC KEY BLOCK-----', text)
    return {'openpgp': True, 'openpgp_key_size': len(fingerprints)}


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
    digest = hashlib.md5(email.strip().lower().encode('utf-8')).hexdigest()
    try:
        response = http.get(
            f"https://www.gravatar.com/avatar/{digest}?d=404&s=80")
    except Exception as e:
        return {'gravatar': 'unknown', 'gravatar_error': type(e).__name__}

    if response.status_code == 200:
        return {'gravatar': True}
    if response.status_code == 404:
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
        headers={'hibp-api-key': api_key})
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
        headers={'hibp-api-key': api_key})
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
        f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}")
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
}
