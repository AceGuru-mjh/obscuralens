"""
Input validation utilities

Every validator returns ``(is_valid, error_message)`` so callers can report a
concrete reason instead of a bare boolean. The v4.0 additions cover the new
target kinds: URLs, cryptocurrency addresses, file hashes, CVE identifiers,
AS numbers and MAC addresses.
"""

import ipaddress
import re
from typing import Dict, Optional, Tuple


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


# --- Vehicle Identification Number (v6.0) --------------------------------------
#
# ISO 3779 VIN: 17 characters, digits plus uppercase letters with I, O and Q
# excluded (they look like 1, 0 and 0/9), a check digit at position 9 and a
# 30-year model-year code at position 10. The same rules cover ISO 4030
# (VIN placement/verification); position semantics are documented in the
# vin tracker sources, this module only guards the identifier shape.

#: 17-character VIN body: digits + uppercase letters without I/O/Q.
_VIN_RE = re.compile(r'^[0-9A-HJ-NPR-Z]{17}$')

#: Transliteration values for the ISO 3779 check-digit computation (A=1..H=8,
#: skipping I; then J=1..R=9, skipping O and Q; then S=2..Z=9, skipping U).
_VIN_TRANSLITERATION = {
    'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
    'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
    'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
}

#: Check-digit weights for the 17 VIN positions; position 9 (index 8) is the
#: check digit itself and carries weight 0 so the sum runs over the full VIN.
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def _vin_check_digit_value(vin: str) -> str:
    """
    The ISO 3779 check digit a 17-character VIN body should carry.

    Sums transliterated characters times position weights, takes the result
    modulo 11 and maps a remainder of 10 to ``'X'``. Position 9 has weight 0,
    so any character already sitting there is harmlessly ignored.
    """
    total = 0
    for char, weight in zip(vin, _VIN_WEIGHTS):
        value = int(char) if char.isdigit() else _VIN_TRANSLITERATION.get(char, 0)
        total += value * weight
    remainder = total % 11
    return 'X' if remainder == 10 else str(remainder)


def validate_vin(value: str) -> Tuple[bool, str]:
    """
    Validate a Vehicle Identification Number with its ISO 3779 check digit.

    Accepts hyphen/space separated forms (``'1M8-GDM9-A-XKP042788'`` style
    typing aids) and lower case input; the remainder must be exactly 17
    characters of digits and letters without I, O or Q, and position 9 must
    match the computed check digit.
    """
    if not value:
        return False, "VIN cannot be empty"
    candidate = normalize_vin(value)
    if not candidate:
        return False, "Invalid VIN format (expected 17 characters, no I/O/Q)"
    if candidate[8] != _vin_check_digit_value(candidate):
        return False, "VIN check digit failed (position 9)"
    return True, ""


def normalize_vin(value: str) -> str:
    """Uppercase, separator-free VIN; empty string when the shape is wrong."""
    candidate = re.sub(r'[\s\-]', '', (value or '').strip().upper())
    return candidate if _VIN_RE.match(candidate) else ''


# --- flight designators (v6.0) --------------------------------------------------

#: Flight designator: 2-letter IATA or 3-letter ICAO carrier code, 1-4 digit
#: flight number and an optional single suffix letter (BA2490, DLH400A, UA1).
_FLIGHT_RE = re.compile(r'^([A-Z]{3}|[A-Z]{2})(\d{1,4})([A-Z]?)$')


def validate_flight(value: str) -> Tuple[bool, str]:
    """
    Validate a flight designator such as ``'UA1'``, ``'BA2490'`` or ``'DLH400A'``.

    The carrier code must be a 2-letter IATA code or a 3-letter ICAO code;
    this validator checks the identifier grammar only (whether the carrier
    actually exists is the airline pack's job in the tracker).
    """
    if not value:
        return False, "Flight designator cannot be empty"
    if _FLIGHT_RE.match(normalize_flight(value)):
        return True, ""
    return False, ("Invalid flight designator (expected e.g. UA1, BA2490 "
                   "or DLH400A)")


def normalize_flight(value: str) -> str:
    """Uppercase, space-free flight designator; empty when malformed."""
    candidate = re.sub(r'[\s\-]', '', (value or '').strip().upper())
    return candidate if _FLIGHT_RE.match(candidate) else ''


def split_flight(value: str) -> Optional[Tuple[str, str, str]]:
    """
    Split a flight designator into ``(carrier, number, suffix)`` parts.

    ``'DLH400A'`` becomes ``('DLH', '400', 'A')`` and ``'UA1'`` becomes
    ``('UA', '1', '')``. Returns ``None`` when the designator does not parse;
    the carrier keeps its 2- or 3-letter shape so callers can tell an IATA
    code from an ICAO code by length alone.
    """
    match = _FLIGHT_RE.match(normalize_flight(value))
    if not match:
        return None
    carrier, number, suffix = match.groups()
    return carrier, number, suffix


# --- Maritime Mobile Service Identity (v6.0) ------------------------------------

#: MMSI: exactly nine digits after separators and an optional 'MMSI:' marker
#: are stripped (the ITU-R M.1085 identity is always a bare digit string).
_MMSI_RE = re.compile(r'^\d{9}$')


def validate_mmsi(value: str) -> Tuple[bool, str]:
    """
    Validate a Maritime Mobile Service Identity (ITU-R M.1085).

    Accepts integers as well as strings; ``'MMSI: 366-910-000'`` style input
    normalises to the bare nine-digit form ``'366910000'`` before validation.
    """
    if value is None or value == '':
        return False, "MMSI cannot be empty"
    candidate = normalize_mmsi(value)
    if not candidate:
        return False, "Invalid MMSI (expected 9 digits, e.g. 366910000)"
    return True, ""


def normalize_mmsi(value: str) -> str:
    """
    Bare nine-digit MMSI string; empty when the shape is wrong.

    Integers are accepted (``366910000``), surrounding whitespace, hyphens and
    spaces inside groups are dropped, and a case-insensitive ``'MMSI:'``
    prefix marker is removed.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        candidate = str(value)
    elif isinstance(value, str):
        candidate = value.strip()
        if candidate.upper().startswith('MMSI:'):
            candidate = candidate[5:].strip()
        candidate = candidate.replace('-', '').replace(' ', '')
    else:
        return ''
    return candidate if _MMSI_RE.match(candidate) else ''


# --- software package coordinates (v6.0) ---------------------------------------
#
# An app coordinate is "<ecosystem>:<name>" - a package, container image or
# repository written the way dependency manifests spell it. The ecosystem is
# one of pypi / npm / crate / docker / github; the name grammar per ecosystem
# mirrors what the corresponding registry accepts (PyPI names are case and
# dash/underscore tolerant; npm names are lower-case with optional @scope/;
# crate names are short alphanumerics; docker references carry a namespace
# path; github coordinates are owner/repo).

#: Ecosystem prefix -> (label, name-shape regex). The regexes are the full
#: name grammar AFTER the 'ecosystem:' prefix has been split off.
_APP_NAME_RES: Dict[str, Tuple[str, "re.Pattern[str]"]] = {
    'pypi': ('Python Package Index',
             re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')),
    'npm': ('npm registry', re.compile(
        r'^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._-]*$')),
    'crate': ('crates.io', re.compile(r'^[A-Za-z0-9_-]{1,64}$')),
    'docker': ('Docker Hub', re.compile(r'^[a-z0-9][a-z0-9._/-]*$')),
    'github': ('GitHub repository', re.compile(
        r'^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$')),
}

#: Allowed ecosystem prefixes (the tuple order is stable for error messages).
APP_ECOSYSTEMS: Tuple[str, ...] = ('pypi', 'npm', 'crate', 'docker', 'github')


def split_app(value: str) -> Optional[Tuple[str, str]]:
    """
    Split an app coordinate into ``(ecosystem, name)`` parts.

    ``'pypi:requests'`` becomes ``('pypi', 'requests')`` and
    ``'docker:bitnami/kafka'`` becomes ``('docker', 'bitnami/kafka')``.
    Returns ``None`` when the value has no ``<ecosystem>:`` prefix or the
    prefix is not one of the five supported ecosystems. The ecosystem is
    returned lower-cased; the name keeps its typed casing.
    """
    if not isinstance(value, str) or ':' not in value:
        return None
    prefix, _, name = value.strip().partition(':')
    ecosystem = prefix.strip().lower()
    if ecosystem not in APP_ECOSYSTEMS or not name.strip():
        return None
    return ecosystem, name.strip()


def validate_app(value: str) -> Tuple[bool, str]:
    """
    Validate a software package coordinate such as ``'pypi:requests'``.

    The value must carry one of the five ecosystem prefixes (pypi, npm,
    crate, docker, github) followed by a name that fits that ecosystem's
    grammar: PyPI accepts mixed-case letters, digits, dots, underscores and
    dashes; npm names are lower-case with an optional ``@scope/``; crate
    names are 1-64 alphanumerics, dashes or underscores; docker references
    are lower-case namespace paths like ``library/nginx`` or
    ``bitnami/kafka``; github coordinates are ``owner/repo``.
    """
    if not value:
        return False, "App coordinate cannot be empty"
    parts = split_app(value)
    if parts is None:
        return False, ("Invalid app coordinate (expected <ecosystem>:<name>, "
                       "ecosystem in pypi/npm/crate/docker/github)")
    ecosystem, name = parts
    if not _APP_NAME_RES[ecosystem][1].match(name):
        return False, f"Invalid {ecosystem} package name: {name!r}"
    return True, ""


def normalize_app(value: str) -> str:
    """
    Canonical ``<ecosystem>:<name>`` form; empty when the shape is wrong.

    The ecosystem is lower-cased (``'PYPI:Requests'`` -> ``'pypi:Requests'``)
    and surrounding whitespace is dropped; the package name keeps its typed
    casing because PyPI and GitHub names are case-sensitive addresses even
    though their registries resolve them case-insensitively.
    """
    parts = split_app(value or '')
    if parts is None:
        return ''
    ecosystem, name = parts
    if not _APP_NAME_RES[ecosystem][1].match(name):
        return ''
    return f"{ecosystem}:{name}"


# --- WiFi BSSID (v6.0) ---------------------------------------------------------
#
# A BSSID is the EUI-48 burned-in address of a WiFi access point radio: 24
# bits of IEEE-assigned OUI plus 24 bits of device-unique extension. The
# grammar is identical to a MAC address (which is why auto-detection prefers
# 'mac' - a BSSID lookup is an explicit statement that the address belongs
# to an access point), so this validator re-implements the EUI-48 shape
# rules independently rather than importing them: 12 hex digits in colon,
# dash, Cisco-dot or bare notation.

#: BSSID body after separator removal: exactly 12 hexadecimal digits.
_BSSID_RE = re.compile(r'^[0-9A-Fa-f]{12}$')


def validate_bssid(value: str) -> Tuple[bool, str]:
    """
    Validate a WiFi BSSID (EUI-48 access point address).

    Accepts colon (``00:1A:2B:3C:4D:5E``), dash (``00-1A-2B-3C-4D-5E``),
    Cisco dotted (``001a.2b3c.4d5e``) and bare hex (``001a2b3c4d5e``)
    notation; the address must be exactly 48 bits (24-bit OUI + 24-bit
    device number).
    """
    if not value:
        return False, "BSSID cannot be empty"
    if not normalize_bssid(value):
        return False, ("Invalid BSSID (expected 48-bit MAC-style address, "
                       "e.g. 00:1A:2B:3C:4D:5E)")
    return True, ""


def normalize_bssid(value: str) -> str:
    """
    Canonical lower-case colon-separated BSSID; empty when malformed.

    ``'00-1A-2B-3C-4D-5E'`` and ``'001a.2b3c.4d5e'`` both normalise to
    ``'00:1a:2b:3c:4d:5e'``. Only EUI-48 shapes survive - 64-bit EUI-64
    addresses (16 hex digits) are deliberately rejected because a BSSID is
    always a 48-bit radio address.
    """
    if not isinstance(value, str):
        return ''
    candidate = value.strip().lower()
    candidate = candidate.replace(':', '').replace('-', '') \
                         .replace('.', '').replace(' ', '')
    if not _BSSID_RE.match(candidate):
        return ''
    return ':'.join(candidate[i:i + 2] for i in range(0, 12, 2))


# --- license plates (v6.0) -----------------------------------------------------
#
# A plate value is free-form vehicle-registration text, optionally prefixed
# with an issuing jurisdiction such as 'DE:', 'GB:' or 'US-CA:'. Plate
# grammars vary per country (and per state/city inside a country), so this
# validator is deliberately wide - non-empty printable text of reasonable
# length - and the plate_sources pack does the strict per-country pattern
# matching. Wide in, strict out: a typo'd plate still classifies as plate.

#: Optional country prefix: two letters, or two letters + a 2-4 letter
#: state suffix (US-CA, AU-NSW both fit; three-letter state codes exist).
_PLATE_PREFIX_RE = re.compile(r'^([A-Z]{2}(?:-[A-Z]{2,4})?):(.+)$')


def validate_plate(value: str) -> Tuple[bool, str]:
    """
    Validate a license plate value (free-form text, optional country prefix).

    The stripped value must be 3-20 printable characters (a real plate is
    never shorter than three characters nor longer than twenty) containing
    at least one digit - every issued plate carries a number, so a purely
    alphabetic word classifies as a username instead. The optional
    ``<country>:`` or ``<country-state>:`` prefix (``DE:``, ``US-CA:``) is
    included in the length budget. Per-country pattern matching happens
    later, in the plate data pack - this gate only rejects obvious
    non-plates.
    """
    if not value:
        return False, "License plate cannot be empty"
    candidate = (value or '').strip()
    if len(candidate) < 3 or len(candidate) > 20:
        return False, "Invalid license plate (expected 3-20 characters)"
    if not candidate.isprintable():
        return False, "Invalid license plate (expected printable characters)"
    if not any(ch.isdigit() for ch in candidate):
        return False, "Invalid license plate (expected at least one digit)"
    return True, ""


def normalize_plate(value: str) -> str:
    """
    Upper-cased, space-collapsed plate text; empty when the gate fails.

    ``'de:b-ab  1234'`` becomes ``'DE:B-AB 1234'`` (runs of whitespace
    collapse to a single space, everything is upper-cased, surrounding
    whitespace is dropped). The country prefix, when present, is kept and
    upper-cased with the rest. Values failing the plate gate (length,
    printability or the at-least-one-digit rule) normalise to ``''``.
    """
    if not isinstance(value, str):
        return ''
    candidate = ' '.join(value.strip().upper().split())
    if len(candidate) < 3 or len(candidate) > 20:
        return ''
    if not candidate.isprintable():
        return ''
    if not any(ch.isdigit() for ch in candidate):
        return ''
    return candidate


def split_plate(value: str) -> Optional[Tuple[str, str]]:
    """
    Split a plate value into ``(country_prefix, body)`` parts.

    ``'DE:B-AB 1234'`` becomes ``('DE', 'B-AB 1234')`` and ``'US-CA:8ABC123'``
    becomes ``('US-CA', '8ABC123')``; the prefix is upper-cased. Returns
    ``('', <whole value>)`` - an empty prefix - when no country prefix is
    present, and ``None`` when the value fails the plate gate.
    """
    candidate = normalize_plate(value or '')
    if not candidate:
        return None
    match = _PLATE_PREFIX_RE.match(candidate)
    if match:
        return match.group(1), match.group(2).strip()
    return '', candidate
