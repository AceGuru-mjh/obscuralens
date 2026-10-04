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
# Solana: 32-44 base58 chars, no version prefix (checked last so the
# longer-established base58 families win any length overlap).
_SOL_RE = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')


def detect_crypto_chain(address: str) -> Optional[str]:
    """
    Identify the likely blockchain of an address string.

    Returns one of ``btc / eth / xmr / doge / ltc / xrp / ada / sol`` or
    ``None``. Ethereum-style addresses also cover EVM forks (BSC, Polygon, …)
    but are reported as ``eth`` since the primary lookup path is identical.
    Solana is checked last: its 32-44 char base58 space overlaps the shorter
    Bitcoin families, so the prefixed formats win first.
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
    if _SOL_RE.match(value):
        return 'sol'
    return None


def validate_crypto_address(address: str) -> Tuple[bool, str]:
    """Validate a cryptocurrency address for a supported chain."""
    if not address:
        return False, "Crypto address cannot be empty"
    chain = detect_crypto_chain(address.strip())
    if chain:
        return True, ""
    return False, ("Unrecognised crypto address (supported: btc, eth, xmr, "
                   "doge, ltc, xrp, ada, sol)")


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


# --- IBAN (v5.0) ----------------------------------------------------------------

#: Uppercase, whitespace-free IBAN candidate (country + check digits + BBAN).
_IBAN_RE = re.compile(r'^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$')


def validate_iban(value: str) -> Tuple[bool, str]:
    """
    Validate an IBAN: format, length and the ISO 13616 mod-97 checksum.

    Accepts spaces (printed IBANs such as ``'DE89 3704 0044 0532 0130 00'``),
    lowercase input and a leading ``'iban:'`` marker. The checksum is
    verified with the standard rearrangement algorithm so typos are caught
    before any source is contacted.
    """
    if not value:
        return False, "IBAN cannot be empty"
    candidate = normalize_iban(value)
    if not candidate:
        return False, "Invalid IBAN format (expected e.g. DE89370400440532013000)"
    if not _iban_mod97(candidate):
        return False, "IBAN checksum failed (mod-97)"
    return True, ""


def normalize_iban(value: str) -> str:
    """Uppercase, space-free IBAN; empty string when the shape is wrong."""
    candidate = (value or '').strip().upper()
    if candidate.startswith('IBAN:'):
        candidate = candidate[5:].strip()
    candidate = candidate.replace(' ', '').replace('-', '')
    return candidate if _IBAN_RE.match(candidate) else ''


def _iban_mod97(iban: str) -> bool:
    """ISO 13616 mod-97 checksum: rearrange, map letters, check remainder."""
    if len(iban) < 4:
        return False
    rearranged = iban[4:] + iban[:4]
    total = 0
    for char in rearranged:
        if char.isdigit():
            total = total * 10 + int(char)
        elif 'A' <= char <= 'Z':
            total = total * 100 + (ord(char) - ord('A') + 10)
        else:
            return False
        total %= 97
    return total == 1


# --- IMEI / IMEISV (v5.0) --------------------------------------------------------

#: 15-digit IMEI or 16-digit IMEISV (no separators), or common punctuated forms.
_IMEI_CLEAN_RE = re.compile(r'^\d{15}(\d)?$')


def validate_imei(value: str) -> Tuple[bool, str]:
    """
    Validate an IMEI (15 digits) or IMEISV (16 digits) with the Luhn check.

    Separators (spaces, dashes, dots) are tolerated. A 16-digit value is an
    IMEISV (software version appended) whose Luhn check applies to the first
    15 digits only.
    """
    if not value:
        return False, "IMEI cannot be empty"
    digits = re.sub(r'[\s\-.]', '', value.strip())
    if not digits.isdigit() or not _IMEI_CLEAN_RE.match(digits):
        return False, "Invalid IMEI (expected 15 digits, e.g. 356938035643809)"
    if not _luhn_ok(digits[:15]):
        return False, "IMEI Luhn check failed"
    return True, ""


def normalize_imei(value: str) -> str:
    """Digit-only IMEI/IMEISV; empty string when malformed."""
    digits = re.sub(r'[\s\-.]', '', (value or '').strip())
    return digits if digits.isdigit() and _IMEI_CLEAN_RE.match(digits) else ''


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum over a digit string."""
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# --- geographic coordinates (v5.0) -----------------------------------------------

#: Decimal degrees pair: "48.8584, 2.2945" / "48.8584 2.2945" / "(48.8, 2.29)"
_COORD_DD_RE = re.compile(
    r'^\(?\s*(-?\d{1,3}(?:\.\d+)?)\s*[,;\s]\s*(-?\d{1,3}(?:\.\d+)?)\s*\)?$')
#: Degrees/minutes/seconds with hemisphere letters or signs.
_COORD_DMS_RE = re.compile(
    r'^\(?\s*([NS])?\s*(\d{1,3})[°d:\s]+(\d{1,2}(?:\.\d+)?)?[\'m:\s]*'
    r'(\d{1,2}(?:\.\d+)?)?["s]?\s*([NS])?\s*[,;\s]+'
    r'([EW])?\s*(\d{1,3})[°d:\s]+(\d{1,2}(?:\.\d+)?)?[\'m:\s]*'
    r'(\d{1,2}(?:\.\d+)?)?["s]?\s*([EW])?\s*\)?$', re.IGNORECASE)
#: UTM: zone number, band letter, easting, northing.
_COORD_UTM_RE = re.compile(
    r'^(\d{1,2})\s*([C-HJ-NP-X])\s+(\d{4,7}(?:\.\d+)?)\s*[,;\s]\s*(\d{6,8}(?:\.\d+)?)$',
    re.IGNORECASE)
#: MGRS / USNG: grid zone + 100 km square + numeric pair.
_COORD_MGRS_RE = re.compile(
    r'^(\d{1,2})\s*([C-HJ-NP-X])\s+([A-Z]{2})\s+(\d{1,5})\s+(\d{1,5})$', re.IGNORECASE)


def validate_coords(value: str) -> Tuple[bool, str]:
    """
    Validate geographic coordinates in decimal degrees, DMS or UTM/MGRS.

    Accepts ``'48.8584, 2.2945'``, ``'N 48° 51' 29", E 2° 17' 40"'``,
    ``'31U 448288 5411087'`` (UTM) and ``'31U DQ 48288 11087'`` (MGRS).
    Latitude must be within ±90 and longitude within ±180.
    """
    if not value:
        return False, "Coordinates cannot be empty"
    candidate = (value or '').strip()
    if _COORD_DD_RE.match(candidate):
        lat = float(_COORD_DD_RE.match(candidate).group(1))
        lon = float(_COORD_DD_RE.match(candidate).group(2))
        if abs(lat) > 90 or abs(lon) > 180:
            return False, "Latitude must be within ±90 and longitude within ±180"
        return True, ""
    if _COORD_DMS_RE.match(candidate):
        return True, ""
    if _COORD_UTM_RE.match(candidate):
        return True, ""
    if _COORD_MGRS_RE.match(candidate):
        return True, ""
    return False, "Unrecognised coordinate format (DD, DMS, UTM or MGRS)"


def normalize_coords(value: str) -> str:
    """Canonical decimal-degrees string 'lat, lon'; empty when unparseable."""
    parsed = parse_coords(value)
    if parsed is None:
        return ''
    return f"{parsed[0]:.6f}, {parsed[1]:.6f}"


def parse_coords(value: str) -> Optional[Tuple[float, float]]:
    """
    Parse any accepted coordinate syntax into (latitude, longitude).

    Returns None when the input matches no known format. DMS hemisphere
    letters apply the sign; a leading minus applies it to both components
    of a DD pair only for the field it prefixes.
    """
    candidate = (value or '').strip()
    if not candidate:
        return None
    match = _COORD_DD_RE.match(candidate)
    if match:
        return float(match.group(1)), float(match.group(2))
    match = _COORD_DMS_RE.match(candidate)
    if match:
        lat_h, lat_d, lat_m, lat_s, lat_h2, lon_h, lon_d, lon_m, lon_s, lon_h2 = \
            match.groups()
        lat = _dms_to_decimal(int(lat_d), float(lat_m or 0), float(lat_s or 0))
        lon = _dms_to_decimal(int(lon_d), float(lon_m or 0), float(lon_s or 0))
        north = (lat_h or lat_h2 or 'N').upper() == 'N'
        east = (lon_h or lon_h2 or 'E').upper() == 'E'
        if not north:
            lat = -abs(lat)
        if not east:
            lon = -abs(lon)
        if abs(lat) > 90 or abs(lon) > 180:
            return None
        return lat, lon
    match = _COORD_UTM_RE.match(candidate)
    if match:
        from .coordinate_math import utm_to_latlon
        zone, band, easting, northing = match.groups()
        return utm_to_latlon(int(zone), float(easting), float(northing),
                             northern=band.upper() >= 'N')
    match = _COORD_MGRS_RE.match(candidate)
    if match:
        from .coordinate_math import mgrs_to_latlon
        zone, band, square, easting, northing = match.groups()
        return mgrs_to_latlon(int(zone), band.upper(), square.upper(),
                              int(easting), int(northing))
    return None


def _dms_to_decimal(degrees: int, minutes: float, seconds: float) -> float:
    """Absolute decimal degrees from a DMS triple."""
    return abs(degrees) + minutes / 60.0 + seconds / 3600.0
