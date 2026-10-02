"""
Input validation utilities

Every validator returns ``(is_valid, error_message)`` so callers can report a
concrete reason instead of a bare boolean. The v4.0 additions cover the new
target kinds: URLs, cryptocurrency addresses, file hashes, CVE identifiers,
AS numbers and MAC addresses.
"""

import ipaddress
import re
from typing import Optional, Tuple


def validate_ip(ip: str) -> Tuple[bool, str]:
    """
    Validate an IP address

    Args:
        ip: IP address to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip:
        return False, "IP address cannot be empty"

    try:
        ipaddress.ip_address(ip)
        return True, ""
    except ValueError as e:
        return False, f"Invalid IP address: {str(e)}"


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate an email address

    Args:
        email: Email address to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email address cannot be empty"

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(email_regex, email):
        return True, ""

    return False, "Invalid email format"


def validate_phone(phone: str) -> Tuple[bool, str]:
    """
    Validate a phone number

    Args:
        phone: Phone number to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not phone:
        return False, "Phone number cannot be empty"

    # Remove common separators
    cleaned = re.sub(r'[\s\-\(\)\.]', '', phone)

    # Check if it starts with + and has digits
    if cleaned.startswith('+'):
        if not cleaned[1:].isdigit():
            return False, "Phone number can only contain digits after +"
        if len(cleaned) < 8 or len(cleaned) > 15:
            return False, "Phone number must be 8-15 digits"
    else:
        if not cleaned.isdigit():
            return False, "Phone number can only contain digits"
        if len(cleaned) < 8 or len(cleaned) > 15:
            return False, "Phone number must be 8-15 digits"

    return True, ""


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate a username

    Args:
        username: Username to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"

    if len(username) < 3:
        return False, "Username must be at least 3 characters"

    if len(username) > 30:
        return False, "Username must be at most 30 characters"

    # Allow alphanumeric, underscore, and dot
    if not re.match(r'^[a-zA-Z0-9_.]+$', username):
        return False, "Username can only contain letters, numbers, underscore, and dot"

    return True, ""


def validate_domain(domain: str) -> Tuple[bool, str]:
    """
    Validate a domain name

    Args:
        domain: Domain name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not domain:
        return False, "Domain cannot be empty"

    domain_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'

    if re.match(domain_regex, domain):
        return True, ""

    return False, "Invalid domain format"


# ---------------------------------------------------------------------------
# v4.0 target kinds
# ---------------------------------------------------------------------------

# Regex for a host: standard domain or a bracketed IPv6 literal.
_HOST_RE = (
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'|\[[0-9a-fA-F:.]+\])'
)

_URL_RE = re.compile(
    r'^(?P<scheme>https?|ftp)://'
    r'(?P<userinfo>(?:[a-zA-Z0-9._%~+-]+(?::[a-zA-Z0-9._%~+-]*)?@)?)'
    rf'(?P<host>{_HOST_RE})'
    r'(?::(?P<port>\d{1,5}))?'
    r'(?P<path>/[^\s<>"]*)?$',
    re.IGNORECASE,
)

# Punycode labels (xn--...) are valid IDN; allow them plus unicode-free names.
_PUNYCODE_RE = re.compile(r'(^|\.)xn--[a-zA-Z0-9-]+', re.IGNORECASE)


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate an http(s)/ftp URL.

    Accepts user-info, ports, IPv6 literals in brackets and IDN/punycode hosts.
    Rejects bare domains (use the domain tracker) and non-http schemes.
    """
    if not url:
        return False, "URL cannot be empty"

    candidate = url.strip()
    if len(candidate) > 2048:
        return False, "URL is unreasonably long (> 2048 characters)"

    match = _URL_RE.match(candidate)
    if not match:
        if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', candidate):
            return False, "Only http, https and ftp URLs are supported"
        return False, "Invalid URL format (expected scheme://host/path)"

    port = match.group('port')
    if port and not (1 <= int(port) <= 65535):
        return False, f"Invalid port: {port}"

    host = match.group('host')
    if host.startswith('['):
        return True, ""
    if host.isdigit():
        # Bare "http://123456789/" is a numeric host - treat as an IP.
        try:
            ipaddress.ip_address(str(int(host)))
            return True, ""
        except ValueError:
            return False, "Invalid numeric host"
    labels = host.split('.')
    if len(labels) < 2 and host not in ('localhost',):
        return False, "Host must be a domain, an IP or localhost"
    for label in labels:
        if not label or len(label) > 63:
            return False, f"Invalid host label: {label[:40]!r}"
    return True, ""


def url_parts(url: str) -> dict:
    """
    Best-effort decomposition of a validated URL into
    scheme / userinfo / host / port / path.

    Returns an empty dict for invalid URLs. Pure-stdlib parsing without
    urllib.parse quirks around userinfo and IPv6.
    """
    match = _URL_RE.match((url or '').strip())
    if not match:
        return {}
    parts = match.groupdict()
    return {
        'scheme': (parts['scheme'] or '').lower(),
        'userinfo': parts['userinfo'] or '',
        'host': (parts['host'] or '').lower().strip('[]'),
        'port': int(parts['port']) if parts['port'] else None,
        'path': parts['path'] or '/',
    }


# --- cryptocurrency addresses ----------------------------------------------

# Bitcoin: P2PKH (1), P2SH (3), Bech32 (bc1...)
_BTC_BASE58_RE = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$')
_BTC_BECH32_RE = re.compile(r'^bc1[a-z0-9]{11,71}$')
# Ethereum (and EVM chains): 0x + 40 hex chars
_ETH_RE = re.compile(r'^0x[a-fA-F0-9]{40}$')
# Monero: 4/8 + 94 base58 chars
_XMR_RE = re.compile(r'^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$')
# Dogecoin: D + 25-34 base58
_DOGE_RE = re.compile(r'^D[a-mzA-HJ-NP-Z1-9]{25,34}$')
# Litecoin: L/M + 26-33 base58, or ltc1 bech32
_LTC_RE = re.compile(r'^(?:[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{11,71})$')
# Ripple: r + 24-34 base58
_XRP_RE = re.compile(r'^r[1-9A-HJ-NP-Za-km-z]{24,34}$')
# Cardano: addr1... (bech32, 40-120 chars)
_ADA_RE = re.compile(r'^addr1[a-z0-9]{40,120}$')


def detect_crypto_chain(address: str) -> Optional[str]:
    """
    Identify the likely blockchain of an address string.

    Returns one of ``btc / eth / xmr / doge / ltc / xrp / ada`` or ``None``.
    Ethereum-style addresses also cover EVM forks (BSC, Polygon, …) but are
    reported as ``eth`` since the primary lookup path is identical.
    """
    value = (address or '').strip()
    if not value:
        return None
    if _BTC_BASE58_RE.match(value) or _BTC_BECH32_RE.match(value):
        return 'btc'
    if _ETH_RE.match(value):
        return 'eth'
    if _XMR_RE.match(value):
        return 'xmr'
    if _DOGE_RE.match(value):
        return 'doge'
    if _LTC_RE.match(value):
        return 'ltc'
    if _XRP_RE.match(value):
        return 'xrp'
    if _ADA_RE.match(value):
        return 'ada'
    return None


def validate_crypto_address(address: str) -> Tuple[bool, str]:
    """Validate a cryptocurrency address for a supported chain."""
    if not address:
        return False, "Crypto address cannot be empty"
    chain = detect_crypto_chain(address.strip())
    if chain:
        return True, ""
    return False, ("Unrecognised crypto address (supported: btc, eth, xmr, "
                   "doge, ltc, xrp, ada)")


# --- file hashes -------------------------------------------------------------

_HASH_LENGTHS = {
    32: 'md5',
    40: 'sha1',
    56: 'sha224',
    64: 'sha256',
    96: 'sha384',
    128: 'sha512',
}
_HASH_RE = re.compile(r'^[a-fA-F0-9]+$')


def detect_hash_algorithm(value: str) -> Optional[str]:
    """Return the hash algorithm implied by a hex digest's length."""
    candidate = (value or '').strip().lower()
    if not candidate or not _HASH_RE.match(candidate):
        return None
    return _HASH_LENGTHS.get(len(candidate))


def validate_hash(value: str) -> Tuple[bool, str]:
    """Validate a hex file hash (md5/sha1/sha224/sha256/sha384/sha512)."""
    if not value:
        return False, "Hash cannot be empty"
    candidate = value.strip()
    algorithm = detect_hash_algorithm(candidate)
    if algorithm:
        return True, ""
    if _HASH_RE.match(candidate):
        return False, f"Unsupported hash length: {len(candidate)} hex chars"
    return False, "Hash must be a hexadecimal digest"


# --- CVE identifiers ----------------------------------------------------------

_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)


def validate_cve(value: str) -> Tuple[bool, str]:
    """Validate a CVE identifier (CVE-YYYY-NNNN..NNNNNNN)."""
    if not value:
        return False, "CVE identifier cannot be empty"
    candidate = value.strip()
    if _CVE_RE.match(candidate):
        year = int(candidate[4:8])
        if 1999 <= year <= 2100:
            return True, ""
        return False, f"CVE year out of range: {year}"
    return False, "Invalid CVE format (expected CVE-YYYY-NNNN)"


def normalize_cve(value: str) -> str:
    """Uppercase a CVE identifier; empty string when malformed."""
    candidate = (value or '').strip().upper()
    return candidate if _CVE_RE.match(candidate) else ''


# --- AS numbers ---------------------------------------------------------------

_ASN_RE = re.compile(r'^(?:AS)?(\d{1,10})$', re.IGNORECASE)


def validate_asn(value: str) -> Tuple[bool, str]:
    """Validate an autonomous system number, with or without the AS prefix."""
    if not value:
        return False, "AS number cannot be empty"
    match = _ASN_RE.match(value.strip())
    if not match:
        return False, "Invalid AS number (expected AS1234 or 1234)"
    number = int(match.group(1))
    if 0 < number <= 4294967295:
        return True, ""
    return False, f"AS number out of range (1-4294967295): {number}"


def normalize_asn(value: str) -> int:
    """Return the integer AS number; 0 when unparseable."""
    match = _ASN_RE.match((value or '').strip())
    return int(match.group(1)) if match else 0


# --- MAC addresses (bonus kind for vendor lookups) -----------------------------

_MAC_RE = re.compile(
    r'^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
    r'|^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$')


def validate_mac(value: str) -> Tuple[bool, str]:
    """Validate a MAC address (colon, dash or dot notation)."""
    if not value:
        return False, "MAC address cannot be empty"
    if _MAC_RE.match(value.strip()):
        return True, ""
    return False, "Invalid MAC address (aa:bb:cc:dd:ee:ff)"


def normalize_mac(value: str) -> str:
    """Lowercase, colon-separated MAC; empty string when malformed."""
    candidate = (value or '').strip().lower()
    if not _MAC_RE.match(candidate):
        return ''
    candidate = candidate.replace('-', ':').replace('.', ':')
    return ':'.join(part.zfill(2) if len(part) < 2 else part
                    for part in candidate.split(':'))
