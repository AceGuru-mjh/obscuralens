"""
Offline reference catalog for ObscuraLens (ISO / IANA / MITRE data packs).

This module turns the plain-text reference packs shipped under
``obscuralens/data`` into typed, queryable Python objects: TCP/UDP port and
service registrations, ISO 3166 countries, ISO 639 languages, ISO 4217
currencies, HTTP status codes, the MITRE CWE catalogue, IANA top-level
domains, file extensions, MIME types and a pool of realistic user-agent
strings.  It exists so the CLI, the web UI and the SDK can answer "what is
port 3389?", "which currency does Vietnam use?" or "is ``.dev`` a real
TLD?" completely offline, without shipping a database.

Design rules (mirroring :mod:`obscuralens.utils.data_packs`):

* **Lazy and cached** -- nothing is read from disk until the first query;
  every pack is then parsed once and the parsed value is stored in the
  module-level ``_CACHE`` dict, so repeated calls return identical objects
  and cost a dictionary lookup.
* **Never raises** -- a missing, empty or half-corrupt pack simply yields
  empty results.  Malformed lines are skipped tolerantly, lookups that miss
  return ``None`` / ``[]`` / ``False`` / ``''`` instead of raising, and
  non-string arguments are rejected politely.  The only guaranteed string
  producer (:func:`random_user_agent`) falls back to a safe constant.
* **Stdlib only** -- just ``pathlib``, ``typing``, ``random`` and ``re``;
  no third-party imports, keeping the module safe to bundle into the
  desktop exe and importable before any configuration exists.
* **Python 3.9 compatible** -- no ``match`` statements, no PEP 604 unions;
  ``typing.Optional`` / ``List`` / ``Dict`` / ``Tuple`` throughout.

Pack line formats -- one entry per line, pipe (``|``) delimited, ``#``
comment lines and blank lines ignored in every pack:

* ``ports_services.txt``    -- ``port/protocol|service|description``,
  e.g. ``22/tcp|ssh|Secure Shell remote login``.
* ``countries_iso3166.txt`` -- ``AA|AAA|numeric|Name|Capital``, e.g.
  ``US|USA|840|United States|Washington, D.C.``.
* ``languages_iso639.txt``  -- ``code|English name``.  The file holds two
  blocks (two-letter ISO 639-1 codes first, then three-letter ISO 639-2/639-3
  codes) separated by comment lines; the parsing itself is uniform.
* ``currencies_iso4217.txt`` -- ``CODE|numeric|minor_units|Name``, e.g.
  ``USD|840|2|US Dollar``.
* ``http_status_codes.txt`` -- ``code|phrase|category``, e.g.
  ``404|Not Found|client_error``.
* ``cwe_catalog.txt``       -- ``CWE-ID|name``, e.g.
  ``CWE-79|Improper Neutralization of Input During Web Page Generation
  ('Cross-site Scripting')``.
* ``iana_tlds.txt``         -- one lowercase TLD per line (e.g. ``dev``).
* ``file_extensions.txt``   -- ``ext|category|description``, e.g.
  ``zip|archive|ZIP archive``.
* ``mime_types.txt``        -- ``mime|extension|description``, e.g.
  ``application/json|json|JSON data``.
* ``user_agents.txt``       -- ``family|platform|user-agent string``.

Usage examples::

    from obscuralens.utils import data_catalog

    data_catalog.country('US')
    # Country(code='US', code3='USA', numeric='840', name='United States', ...)

    data_catalog.port_service(3389)                 # -> PortEntry (rdp)
    data_catalog.port_category(8080)                # -> 'registered'
    data_catalog.currencies_for_country('VN')       # -> ['VND']
    data_catalog.http_status_category(429)          # -> 'client_error'
    data_catalog.cwe('79')                          # -> Cwe('CWE-79', ...)
    data_catalog.is_iana_tld('.dev')                # -> True
    data_catalog.mime_for_extension('json').mime    # -> 'application/json'
    data_catalog.random_user_agent(family='Chrome', seed=42)
    print(data_catalog.catalog_summary())           # stats table

See :func:`catalog_stats` and :func:`catalog_summary` for a quick overview
of what is currently loaded.
"""

import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, Iterator, List, Optional, Tuple, Union

#: Directory holding the shipped ``<name>.txt`` reference packs.  Deliberately
#: duplicates :data:`obscuralens.utils.data_packs.DATA_DIR` so this module
#: stays self-contained (and so tests can point it at a temp directory).
DATA_DIR = Path(__file__).resolve().parent.parent / 'data'

#: Module-level cache: pack name -> parsed pack value (identity-stable, the
#: same pattern as :func:`obscuralens.utils.data_packs.load_data_pack`).
#: Packs whose file is missing are intentionally NOT cached, so a pack that
#: appears on disk later is picked up by the next call without restarts.
_CACHE: Dict[str, Any] = {}

# Pack file names (without the '.txt' suffix).  These are also the _CACHE keys
# and the names reported by catalog_stats() / catalog_summary().
_COUNTRIES_PACK = 'countries_iso3166'
_LANGUAGES_PACK = 'languages_iso639'
_CURRENCIES_PACK = 'currencies_iso4217'
_PORTS_PACK = 'ports_services'
_HTTP_PACK = 'http_status_codes'
_CWES_PACK = 'cwe_catalog'
_TLDS_PACK = 'iana_tlds'
_EXTENSIONS_PACK = 'file_extensions'
_MIMES_PACK = 'mime_types'
_USER_AGENTS_PACK = 'user_agents'

#: User-agent string returned when the pack is missing or empty -- a plain,
#: widely accepted Chrome-on-Windows value so callers always get something
#: usable from :func:`random_user_agent`.
_FALLBACK_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
)

#: Shape every IANA top-level domain must have after normalisation: ASCII
#: letters, digits and hyphens (punycode labels such as ``xn--p1ai`` fit).
_TLD_RE = re.compile(r'^[a-z0-9-]+$')

#: HTTP status class derived from the hundreds digit of the status code
#: (100 -> informational, 200 -> success, ... 500 -> server_error).
_HTTP_CATEGORY_BY_HUNDREDS: Dict[int, str] = {
    1: 'informational',
    2: 'success',
    3: 'redirection',
    4: 'client_error',
    5: 'server_error',
}

#: Primary currency (ISO 4217 alpha code) per ISO 3166-1 alpha-2 country
#: code, covering ~80 frequently queried countries.  Euro-area states all
#: map to ``EUR``; countries not listed here make
#: :func:`currencies_for_country` return ``[]``.
_COUNTRY_CURRENCIES: Dict[str, str] = {
    'US': 'USD',
    'DE': 'EUR',
    'GB': 'GBP',
    'JP': 'JPY',
    'CN': 'CNY',
    'IN': 'INR',
    'BR': 'BRL',
    'RU': 'RUB',
    'KR': 'KRW',
    'AU': 'AUD',
    'CA': 'CAD',
    'CH': 'CHF',
    'SE': 'SEK',
    'NO': 'NOK',
    'DK': 'DKK',
    'PL': 'PLN',
    'CZ': 'CZK',
    'TR': 'TRY',
    'MX': 'MXN',
    'ZA': 'ZAR',
    'SG': 'SGD',
    'HK': 'HKD',
    'NZ': 'NZD',
    'TH': 'THB',
    'ID': 'IDR',
    'MY': 'MYR',
    'PH': 'PHP',
    'VN': 'VND',
    'AE': 'AED',
    'SA': 'SAR',
    'IL': 'ILS',
    'EG': 'EGP',
    'NG': 'NGN',
    'KE': 'KES',
    'MA': 'MAD',
    'UA': 'UAH',
    'RO': 'RON',
    'HU': 'HUF',
    'IS': 'ISK',
    'FI': 'EUR',
    'IE': 'EUR',
    'AT': 'EUR',
    'BE': 'EUR',
    'NL': 'EUR',
    'FR': 'EUR',
    'ES': 'EUR',
    'IT': 'EUR',
    'PT': 'EUR',
    'GR': 'EUR',
    'CL': 'CLP',
    'AR': 'ARS',
    'CO': 'COP',
    'PE': 'PEN',
    'PK': 'PKR',
    'BD': 'BDT',
    'LK': 'LKR',
    'NP': 'NPR',
    'IR': 'IRR',
    'IQ': 'IQD',
    'KW': 'KWD',
    'QA': 'QAR',
    'BH': 'BHD',
    'OM': 'OMR',
    'JO': 'JOD',
    'LB': 'LBP',
    'KZ': 'KZT',
    'UZ': 'UZS',
    'GE': 'GEL',
    'AM': 'AMD',
    'AZ': 'AZN',
    'BY': 'BYN',
    'MD': 'MDL',
    'BG': 'BGN',
    'RS': 'RSD',
    'HR': 'EUR',
    'SI': 'EUR',
    'SK': 'EUR',
    'LT': 'EUR',
    'LV': 'EUR',
    'EE': 'EUR',
    'CY': 'EUR',
    'MT': 'EUR',
    'LU': 'EUR',
    'LI': 'CHF',
    'MC': 'EUR',
    'AD': 'EUR',
    'SM': 'EUR',
    'VA': 'EUR',
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Country:
    """
    One ISO 3166-1 country (or dependent territory) entry.

    Fields:
        code: two-letter alpha-2 code, uppercase (``"US"``).
        code3: three-letter alpha-3 code, uppercase (``"USA"``).
        numeric: three-digit ISO numeric code kept as a string (``"840"``)
            because codes such as ``"004"`` carry a meaningful leading zero.
        name: English country name (``"United States"``).
        capital: capital city name; may be empty for entries without one.

    Example:
        Country('US', 'USA', '840', 'United States', 'Washington, D.C.')
    """

    code: str
    code3: str
    numeric: str
    name: str
    capital: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {
            'code': self.code,
            'code3': self.code3,
            'numeric': self.numeric,
            'name': self.name,
            'capital': self.capital,
        }


@dataclass
class PortEntry:
    """
    One registered service-name / port-number pair.

    Fields:
        port: port number, 0-65535.
        protocol: transport protocol, lowercase (``"tcp"``, ``"udp"``,
            ``"sctp"`` or ``"dccp"``).
        service: IANA service name (``"ssh"``).
        description: short human-readable description; may be empty.

    Example:
        PortEntry(22, 'tcp', 'ssh', 'Secure Shell remote login')
    """

    port: int
    protocol: str
    service: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {
            'port': self.port,
            'protocol': self.protocol,
            'service': self.service,
            'description': self.description,
        }


@dataclass
class Language:
    """
    One ISO 639 language entry (639-1 two-letter or 639-2/639-3 three-letter).

    Fields:
        code: language code, lowercase (``"en"``, ``"deu"``).
        name: English name of the language (``"English"``).

    Example:
        Language('en', 'English')
    """

    code: str
    name: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {'code': self.code, 'name': self.name}


@dataclass
class Currency:
    """
    One ISO 4217 currency entry.

    Fields:
        code: three-letter alpha code, uppercase (``"USD"``).
        numeric: three-digit numeric code kept as a string (``"840"``).
        minor_units: number of minor units per major unit (2 for USD, 0 for
            JPY, 3 for KWD).  Currencies without minor units (``N/A`` in the
            ISO table, e.g. gold) are stored as ``0``.
        name: currency name (``"US Dollar"``).

    Example:
        Currency('EUR', '978', 2, 'Euro')
    """

    code: str
    numeric: str
    minor_units: int
    name: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {
            'code': self.code,
            'numeric': self.numeric,
            'minor_units': self.minor_units,
            'name': self.name,
        }


@dataclass
class HttpStatus:
    """
    One HTTP status code entry.

    Fields:
        code: numeric status code (``404``).
        phrase: reason phrase (``"Not Found"``).
        category: normalised category slug, one of ``informational``,
            ``success``, ``redirection``, ``client_error`` or
            ``server_error``.

    Example:
        HttpStatus(429, 'Too Many Requests', 'client_error')
    """

    code: int
    phrase: str
    category: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {'code': self.code, 'phrase': self.phrase, 'category': self.category}


@dataclass
class Cwe:
    """
    One MITRE Common Weakness Enumeration entry.

    Fields:
        cwe_id: canonical identifier in ``CWE-<number>`` form (``"CWE-79"``);
            lookups accept ``"79"`` and case variations too.
        name: weakness name (``"Improper Neutralization of Input During Web
            Page Generation ('Cross-site Scripting')"``).

    Example:
        Cwe('CWE-79', "Improper Neutralization ... ('Cross-site Scripting')")
    """

    cwe_id: str
    name: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {'cwe_id': self.cwe_id, 'name': self.name}


@dataclass
class FileExtension:
    """
    One file-extension entry.

    Fields:
        ext: normalised extension, lowercase without a leading dot (``"zip"``).
        category: normalised category slug (``"archive"``, ``"executable"``,
            ``"document"``, ``"image"`` ...).
        description: short human-readable description; may be empty.

    Example:
        FileExtension('exe', 'executable', 'Windows executable')
    """

    ext: str
    category: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {'ext': self.ext, 'category': self.category, 'description': self.description}


@dataclass
class MimeType:
    """
    One MIME type entry.

    Fields:
        mime: type/subtype pair, lowercase (``"application/json"``).
        extension: primary file extension, lowercase without a leading dot
            (``"json"``).
        description: short human-readable description; may be empty.

    Example:
        MimeType('application/json', 'json', 'JSON data')
    """

    mime: str
    extension: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {
            'mime': self.mime,
            'extension': self.extension,
            'description': self.description,
        }


@dataclass
class UserAgent:
    """
    One user-agent string entry.

    Fields:
        family: browser/tool family (``"Chrome"``, ``"Firefox"``, ``"curl"``).
        platform: operating-system label (``"Windows 11"``, ``"macOS"``).
        string: the full user-agent string to send over the wire.

    Example:
        UserAgent('curl', 'any', 'curl/8.5.0')
    """

    family: str
    platform: str
    string: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the entry as a plain (JSON-friendly) dict."""
        return {'family': self.family, 'platform': self.platform, 'string': self.string}


@dataclass
class CatalogStats:
    """
    Loading statistics for a single data pack.

    Fields:
        name: pack name without extension (``"iana_tlds"``).
        entries: number of parsed entries (0 for missing/corrupt packs).
        loaded: whether the pack was found on disk and parsed successfully
            (equivalently: its value is resident in the module cache).

    Example:
        CatalogStats('iana_tlds', 1454, True)
    """

    name: str
    entries: int
    loaded: bool

    def to_dict(self) -> Dict[str, Any]:
        """Return the stats record as a plain (JSON-friendly) dict."""
        return {'name': self.name, 'entries': self.entries, 'loaded': self.loaded}


#: Cached record for the countries pack:
#: (entries in file order, alpha-2 index, alpha-3 index).
_CountriesRecord = Tuple[List[Country], Dict[str, Country], Dict[str, Country]]

#: Cached record for the ports pack:
#: (entries in file order, (port, protocol) index, service-name index).
_PortsRecord = Tuple[
    List[PortEntry],
    Dict[Tuple[int, str], PortEntry],
    Dict[str, List[PortEntry]],
]

#: Cached record for the languages pack: (entries in file order, code index).
_LanguagesRecord = Tuple[List[Language], Dict[str, Language]]

#: Cached record for the currencies pack: (entries in file order, code index).
_CurrenciesRecord = Tuple[List[Currency], Dict[str, Currency]]

#: Cached record for the HTTP status pack: (entries, code index).
_HttpStatusRecord = Tuple[List[HttpStatus], Dict[int, HttpStatus]]

#: Cached record for the CWE pack: (entries in file order, id index).
_CwesRecord = Tuple[List[Cwe], Dict[str, Cwe]]

#: Cached record for the TLD pack: (sorted unique TLDs, membership set).
_TldsRecord = Tuple[List[str], FrozenSet[str]]

#: Cached record for the file-extension pack: (entries, ext index).
_ExtensionsRecord = Tuple[List[FileExtension], Dict[str, FileExtension]]

#: Cached record for the MIME pack: (entries, ext index, mime index).
_MimesRecord = Tuple[List[MimeType], Dict[str, MimeType], Dict[str, MimeType]]


# ---------------------------------------------------------------------------
# Core parsing helpers
# ---------------------------------------------------------------------------


def _pack_path(name: str) -> Path:
    """Path of ``<name>.txt`` inside DATA_DIR (``name`` is a module constant)."""
    return DATA_DIR / f'{name}.txt'


def _pack_exists(name: str) -> bool:
    """True when ``<name>.txt`` exists as a file under DATA_DIR. Never raises."""
    try:
        return _pack_path(name).is_file()
    except OSError:  # pathological paths can make even is_file() complain
        return False


def _pack_lines(name: str) -> Iterator[str]:
    """
    Yield the cleaned lines of the ``<name>.txt`` pack under DATA_DIR.

    Lines are stripped of surrounding whitespace; blank lines and comment
    lines starting with ``'#'`` are skipped, exactly like
    :func:`obscuralens.utils.data_packs.load_data_pack`.  A missing or
    unreadable pack yields no lines at all -- this generator never raises.
    """
    try:
        text = _pack_path(name).read_text(encoding='utf-8')
    except (OSError, ValueError):  # missing file, permissions, invalid UTF-8
        return
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            yield stripped


def _parse_pipe_line(line: Any, n_fields: int) -> Optional[List[str]]:
    """
    Split a pipe-delimited pack line into exactly ``n_fields`` parts.

    Every part is stripped of surrounding whitespace.  ``None`` is returned
    when the input is not a string or the field count differs, which lets
    every loader skip malformed lines with a simple ``if fields is None``.
    Empty fields are preserved (loaders validate their own key fields).
    """
    if not isinstance(line, str):
        return None
    parts = line.split('|')
    if len(parts) != n_fields:
        return None
    return [part.strip() for part in parts]


def _normalize_category(value: str) -> str:
    """
    Normalise a category slug: lowercase with underscores.

    ``"Client Error"``, ``"client-error"`` and ``"client_error"`` all become
    ``"client_error"`` so pack files and caller arguments can use any of
    those spellings interchangeably.
    """
    return value.strip().lower().replace(' ', '_').replace('-', '_')


def _normalize_ext(value: Any) -> str:
    """
    Normalise a file-extension argument: strip, drop leading dots, lowercase.

    ``'.ZIP'``, ``' zip '`` and ``'zip'`` all become ``'zip'``.  Non-string
    input normalises to ``''`` (treated as "no extension").
    """
    if not isinstance(value, str):
        return ''
    return value.strip().lower().lstrip('.')


def _coerce_int(value: Any) -> Optional[int]:
    """
    Coerce an argument to ``int``: ints and digit-only strings are accepted.

    Bools are rejected (they are ints in Python but never meaningful codes),
    as are floats, negatives written as text and anything else; the result
    is ``None`` in those cases.  Never raises.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None


def _coerce_port(value: Any) -> Optional[int]:
    """
    Coerce an argument to a valid port number (0-65535) or ``None``.

    Accepts ints and digit-only strings; everything else (including
    out-of-range values such as ``99999``) yields ``None``.  Never raises.
    """
    number = _coerce_int(value)
    if number is None or not 0 <= number <= 65535:
        return None
    return number


def _cwe_digits(value: Any) -> Optional[str]:
    """
    Extract the numeric part of a CWE identifier.

    ``"CWE-79"``, ``"cwe-79"``, ``" 79 "`` and ``"CWE-079"`` all normalise
    to ``"79"`` (leading zeros are dropped); anything without digits yields
    ``None``.  Never raises.
    """
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    if text.startswith('CWE'):
        text = text[3:]
    text = text.lstrip('-').strip()
    if not text.isdigit():
        return None
    return str(int(text))


def _filter_needle(value: Any) -> str:
    """
    Normalise a filter argument to a lowercase needle.

    Returns ``''`` for ``None``, non-strings and blank strings, meaning
    "no filtering" for :func:`_filter_user_agents`.
    """
    if not isinstance(value, str):
        return ''
    return value.strip().lower()


def _load(name: str, builder: Callable[[Iterable[str]], Any], empty: Any) -> Any:
    """
    Memoized loader shared by every pack accessor.

    ``builder`` receives the pack's cleaned lines (see :func:`_pack_lines`)
    and returns the parsed pack value -- a record tuple holding the typed
    entry list plus any lookup indexes.  The value is cached under ``name``
    so every later call returns the identical object, mirroring the
    identity-stable caching of
    :func:`obscuralens.utils.data_packs.load_data_pack`.

    When the pack file is missing, ``empty`` (the pack's empty record) is
    returned WITHOUT caching, so a pack that appears on disk later is
    picked up by the next call without any cache invalidation.  Builders
    are total functions -- they only use non-raising string operations and
    skip malformed lines -- so no pack content can make this loader raise.

    Args:
        name: pack name without the ``.txt`` suffix (a module constant, so
            no path-traversal sanitising is needed here).
        builder: callable turning the cleaned lines into the pack record.
        empty: the pack's empty record, returned for missing packs.
    """
    cached = _CACHE.get(name)
    if cached is not None:
        return cached
    if not _pack_exists(name):
        return empty
    value = builder(_pack_lines(name))
    _CACHE[name] = value
    return value


# ---------------------------------------------------------------------------
# Per-pack builders (each skips malformed lines tolerantly)
# ---------------------------------------------------------------------------


def _build_countries(lines: Iterable[str]) -> _CountriesRecord:
    """
    Build the countries record: ``(entries, by_alpha2, by_alpha3)``.

    Lines are ``AA|AAA|numeric|Name|Capital``.  Entries with a wrong field
    count, bad alpha codes, non-numeric numeric codes or duplicate alpha
    codes are skipped; the first occurrence of a duplicate wins.  Country
    codes are normalised to uppercase.
    """
    entries: List[Country] = []
    by_alpha2: Dict[str, Country] = {}
    by_alpha3: Dict[str, Country] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 5)
        if fields is None:
            continue
        code, code3, numeric, name, capital = fields
        if len(code) != 2 or len(code3) != 3 or not name:
            continue
        if not code.isalpha() or not code3.isalpha():
            continue
        if len(numeric) != 3 or not numeric.isdigit():
            continue
        code = code.upper()
        code3 = code3.upper()
        if code in by_alpha2 or code3 in by_alpha3:
            continue
        country = Country(code=code, code3=code3, numeric=numeric, name=name, capital=capital)
        by_alpha2[code] = country
        by_alpha3[code3] = country
        entries.append(country)
    return entries, by_alpha2, by_alpha3


def _build_ports(lines: Iterable[str]) -> _PortsRecord:
    """
    Build the ports record: ``(entries, by_key, by_service)``.

    Lines are ``port/protocol|service|description``.  Entries with a wrong
    field count, a non-numeric or out-of-range port, a non-alphabetic
    protocol or an empty service name are skipped; duplicate
    ``(port, protocol)`` keys are skipped with the first occurrence winning.
    Protocols and service index keys are lowercased.
    """
    entries: List[PortEntry] = []
    by_key: Dict[Tuple[int, str], PortEntry] = {}
    by_service: Dict[str, List[PortEntry]] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 3)
        if fields is None:
            continue
        port_proto, service, description = fields
        if '/' not in port_proto or not service:
            continue
        port_str, protocol = port_proto.split('/', 1)
        protocol = protocol.strip().lower()
        if not protocol or not protocol.isalpha():
            continue
        port = _coerce_port(port_str.strip())
        if port is None:
            continue
        key = (port, protocol)
        if key in by_key:
            continue
        entry = PortEntry(port=port, protocol=protocol, service=service, description=description)
        by_key[key] = entry
        entries.append(entry)
        by_service.setdefault(service.lower(), []).append(entry)
    return entries, by_key, by_service


def _build_languages(lines: Iterable[str]) -> _LanguagesRecord:
    """
    Build the languages record: ``(entries, by_code)``.

    Lines are ``code|English name``; the pack stores two-letter ISO 639-1
    codes first, then three-letter 639-2/639-3 codes, but the parsing is
    uniform (the separating comment lines are simply skipped).  Entries
    with a wrong field count, a code that is not 2-3 alphabetic characters
    or an empty name are skipped; duplicate codes are skipped too (first
    occurrence wins).  Codes are lowercased.
    """
    entries: List[Language] = []
    by_code: Dict[str, Language] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 2)
        if fields is None:
            continue
        code, name = fields
        if not name or len(code) not in (2, 3) or not code.isalpha():
            continue
        code = code.lower()
        if code in by_code:
            continue
        language = Language(code=code, name=name)
        by_code[code] = language
        entries.append(language)
    return entries, by_code


def _build_currencies(lines: Iterable[str]) -> _CurrenciesRecord:
    """
    Build the currencies record: ``(entries, by_code)``.

    Lines are ``CODE|numeric|minor_units|Name``.  Entries with a wrong field
    count, a non-alphabetic code, a non-3-digit numeric code or an empty
    name are skipped, as are duplicate codes (first occurrence wins).
    Codes are uppercased; minor units that are not plain digits (ISO's
    ``N/A``) are stored as ``0``.
    """
    entries: List[Currency] = []
    by_code: Dict[str, Currency] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 4)
        if fields is None:
            continue
        code, numeric, minor_units, name = fields
        if len(code) != 3 or not code.isalpha() or not name:
            continue
        if len(numeric) != 3 or not numeric.isdigit():
            continue
        code = code.upper()
        if code in by_code:
            continue
        minor = int(minor_units) if minor_units.isdigit() else 0
        currency = Currency(code=code, numeric=numeric, minor_units=minor, name=name)
        by_code[code] = currency
        entries.append(currency)
    return entries, by_code


def _build_http_statuses(lines: Iterable[str]) -> _HttpStatusRecord:
    """
    Build the HTTP status record: ``(entries, by_code)``.

    Lines are ``code|phrase|category``.  Entries with a wrong field count,
    a non-numeric code or an empty phrase/category are skipped; duplicate
    codes are skipped (first occurrence wins).  Categories are normalised
    to lowercase underscore slugs (``"Client Error"`` -> ``"client_error"``).
    """
    entries: List[HttpStatus] = []
    by_code: Dict[int, HttpStatus] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 3)
        if fields is None:
            continue
        code_str, phrase, category = fields
        if not phrase or not category:
            continue
        code = _coerce_int(code_str)
        if code is None or code < 0:
            continue
        status = HttpStatus(code=code, phrase=phrase, category=_normalize_category(category))
        if code in by_code:
            continue
        by_code[code] = status
        entries.append(status)
    return entries, by_code


def _build_cwes(lines: Iterable[str]) -> _CwesRecord:
    """
    Build the CWE record: ``(entries, by_id)``.

    Lines are ``CWE-ID|name``; both ``CWE-79|...`` and a bare ``79|...``
    normalise to the canonical ``CWE-79`` form (leading zeros dropped), so
    duplicate ids after normalisation are skipped (first occurrence wins).
    Entries with a wrong field count, an unusable id or an empty name are
    skipped.
    """
    entries: List[Cwe] = []
    by_id: Dict[str, Cwe] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 2)
        if fields is None:
            continue
        raw_id, name = fields
        digits = _cwe_digits(raw_id)
        if digits is None or not name:
            continue
        cwe_id = f'CWE-{digits}'
        if cwe_id in by_id:
            continue
        entry = Cwe(cwe_id=cwe_id, name=name)
        by_id[cwe_id] = entry
        entries.append(entry)
    return entries, by_id


def _build_tlds(lines: Iterable[str]) -> _TldsRecord:
    """
    Build the TLD record: ``(sorted_unique_tlds, membership_set)``.

    Each line is a single TLD.  Values are lowercased, leading dots are
    dropped, entries that fail the ``^[a-z0-9-]+$`` shape check are skipped
    and duplicates are removed; the resulting list is sorted so
    :func:`iana_tlds` output is stable regardless of file ordering.
    """
    entries: List[str] = []
    seen = set()
    for line in lines:
        tld = line.strip().lower().lstrip('.')
        if not tld or not _TLD_RE.match(tld):
            continue
        if tld in seen:
            continue
        seen.add(tld)
        entries.append(tld)
    entries.sort()
    return entries, frozenset(seen)


def _build_extensions(lines: Iterable[str]) -> _ExtensionsRecord:
    """
    Build the file-extension record: ``(entries, by_ext)``.

    Lines are ``ext|category|description``.  Extensions are normalised
    (lowercase, no leading dot) and categories normalised to underscore
    slugs.  Entries with a wrong field count, an empty extension or an
    empty category are skipped; duplicate extensions are skipped too (first
    occurrence wins).
    """
    entries: List[FileExtension] = []
    by_ext: Dict[str, FileExtension] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 3)
        if fields is None:
            continue
        ext, category, description = fields
        ext = ext.lower().lstrip('.')
        if not ext or not category:
            continue
        if ext in by_ext:
            continue
        entry = FileExtension(ext=ext, category=_normalize_category(category),
                              description=description)
        by_ext[ext] = entry
        entries.append(entry)
    return entries, by_ext


def _build_mimes(lines: Iterable[str]) -> _MimesRecord:
    """
    Build the MIME record: ``(entries, by_ext, by_mime)``.

    Lines are ``mime|extension|description``.  Mime types and extensions
    are lowercased (leading dots dropped from extensions); entries with a
    wrong field count, a mime value without a ``/``, or empty mime/extension
    fields are skipped.  The two indexes keep the FIRST entry seen for any
    duplicate extension or duplicate mime value; the entries list keeps
    every valid line for counting and searching.
    """
    entries: List[MimeType] = []
    by_ext: Dict[str, MimeType] = {}
    by_mime: Dict[str, MimeType] = {}
    for line in lines:
        fields = _parse_pipe_line(line, 3)
        if fields is None:
            continue
        mime, ext, description = fields
        mime = mime.strip().lower()
        ext = ext.strip().lower().lstrip('.')
        if not mime or not ext or '/' not in mime:
            continue
        entry = MimeType(mime=mime, extension=ext, description=description)
        if ext not in by_ext:
            by_ext[ext] = entry
        if mime not in by_mime:
            by_mime[mime] = entry
        entries.append(entry)
    return entries, by_ext, by_mime


def _build_user_agents(lines: Iterable[str]) -> List[UserAgent]:
    """
    Build the user-agent list (kept in file order for stable seeded draws).

    Lines are ``family|platform|user-agent string``.  Entries with a wrong
    field count or any empty field are skipped; no deduplication is applied
    (the same family may legitimately appear for several platforms).
    """
    entries: List[UserAgent] = []
    for line in lines:
        fields = _parse_pipe_line(line, 3)
        if fields is None:
            continue
        family, platform, string = fields
        if not family or not platform or not string:
            continue
        entries.append(UserAgent(family=family, platform=platform, string=string))
    return entries


# ---------------------------------------------------------------------------
# Per-pack loaders (memoized through _load)
# ---------------------------------------------------------------------------


def _load_countries() -> _CountriesRecord:
    """
    Load (and memoize) the ``countries_iso3166`` pack.

    Returns:
        ``(entries, by_alpha2, by_alpha3)`` -- every parsed :class:`Country`
        in file order, plus alpha-2 and alpha-3 lookup indexes that share
        the same entry objects.  A missing pack yields empty structures.
    """
    return _load(_COUNTRIES_PACK, _build_countries, ([], {}, {}))


def _load_ports() -> _PortsRecord:
    """
    Load (and memoize) the ``ports_services`` pack.

    Returns:
        ``(entries, by_key, by_service)`` -- every parsed :class:`PortEntry`
        in file order, a ``(port, protocol)`` index and a lowercase
        service-name -> entries index.  A missing pack yields empty
        structures.
    """
    return _load(_PORTS_PACK, _build_ports, ([], {}, {}))


def _load_languages() -> _LanguagesRecord:
    """
    Load (and memoize) the ``languages_iso639`` pack.

    Returns:
        ``(entries, by_code)`` -- every parsed :class:`Language` in file
        order (two-letter block first) plus a code lookup index.  A missing
        pack yields empty structures.
    """
    return _load(_LANGUAGES_PACK, _build_languages, ([], {}))


def _load_currencies() -> _CurrenciesRecord:
    """
    Load (and memoize) the ``currencies_iso4217`` pack.

    Returns:
        ``(entries, by_code)`` -- every parsed :class:`Currency` in file
        order plus an uppercase code lookup index.  A missing pack yields
        empty structures.
    """
    return _load(_CURRENCIES_PACK, _build_currencies, ([], {}))


def _load_http_statuses() -> _HttpStatusRecord:
    """
    Load (and memoize) the ``http_status_codes`` pack.

    Returns:
        ``(entries, by_code)`` -- every parsed :class:`HttpStatus` in file
        order plus a numeric-code lookup index.  A missing pack yields
        empty structures.
    """
    return _load(_HTTP_PACK, _build_http_statuses, ([], {}))


def _load_cwes() -> _CwesRecord:
    """
    Load (and memoize) the ``cwe_catalog`` pack.

    Returns:
        ``(entries, by_id)`` -- every parsed :class:`Cwe` in file order plus
        a ``CWE-<number>`` lookup index.  A missing pack yields empty
        structures.
    """
    return _load(_CWES_PACK, _build_cwes, ([], {}))


def _load_tlds() -> _TldsRecord:
    """
    Load (and memoize) the ``iana_tlds`` pack.

    Returns:
        ``(tlds, known)`` -- the sorted list of unique TLD strings plus a
        frozenset for membership tests.  A missing pack yields empty
        structures.
    """
    return _load(_TLDS_PACK, _build_tlds, ([], frozenset()))


def _load_extensions() -> _ExtensionsRecord:
    """
    Load (and memoize) the ``file_extensions`` pack.

    Returns:
        ``(entries, by_ext)`` -- every parsed :class:`FileExtension` in file
        order plus a normalised-extension lookup index.  A missing pack
        yields empty structures.
    """
    return _load(_EXTENSIONS_PACK, _build_extensions, ([], {}))


def _load_mimes() -> _MimesRecord:
    """
    Load (and memoize) the ``mime_types`` pack.

    Returns:
        ``(entries, by_ext, by_mime)`` -- every parsed :class:`MimeType` in
        file order plus extension and mime lookup indexes.  A missing pack
        yields empty structures.
    """
    return _load(_MIMES_PACK, _build_mimes, ([], {}, {}))


def _load_user_agents() -> List[UserAgent]:
    """
    Load (and memoize) the ``user_agents`` pack.

    Returns:
        The list of parsed :class:`UserAgent` entries in file order (empty
        for a missing pack).  File order matters because seeded draws index
        into this list.
    """
    return _load(_USER_AGENTS_PACK, _build_user_agents, [])


# ---------------------------------------------------------------------------
# Public API -- countries (ISO 3166-1)
# ---------------------------------------------------------------------------


def country(code: Any) -> Optional[Country]:
    """
    Look up a country by its alpha-2 or alpha-3 code, case-insensitively.

    Args:
        code: two-letter (``"US"``, ``"us"``) or three-letter (``"USA"``,
            ``"usa"``) ISO 3166-1 code.  Non-string input, wrong lengths
            and unknown codes return ``None``; the function never raises.

    Returns:
        The matching :class:`Country` or ``None``.  Both spellings of a
        country resolve to the identical cached object.

    Example:
        country('US').name      # 'United States'
        country('usa').code3    # 'USA'
        country('XXXX')         # None
    """
    if not isinstance(code, str):
        return None
    key = code.strip().upper()
    if not key.isalpha() or len(key) not in (2, 3):
        return None
    entries, by_alpha2, by_alpha3 = _load_countries()
    if len(key) == 2:
        return by_alpha2.get(key)
    return by_alpha3.get(key)


def search_countries(query: Any) -> List[Country]:
    """
    Search countries by a case-insensitive substring of their name.

    Args:
        query: substring to look for inside the (lowercased) country name.
            An empty or whitespace-only string matches every country, so
            ``search_countries('')`` returns the full list (in pack order);
            non-string input returns ``[]``.

    Returns:
        Matching :class:`Country` entries in pack order; never raises.

    Example:
        names = [c.name for c in search_countries('united')]
        # ['United States', 'United Kingdom', 'United Arab Emirates', ...]
    """
    entries, _, _ = _load_countries()
    if not isinstance(query, str):
        return []
    needle = query.strip().lower()
    return [entry for entry in entries if needle in entry.name.lower()]


def countries_count() -> int:
    """
    Number of parsed country entries (0 when the pack is missing).

    Example:
        countries_count() >= 190    # True with the shipped pack
    """
    entries, _, _ = _load_countries()
    return len(entries)


# ---------------------------------------------------------------------------
# Public API -- ports and services
# ---------------------------------------------------------------------------


def port_service(port: Union[int, str], protocol: str = 'tcp') -> Optional[PortEntry]:
    """
    Look up a port registration by port number and transport protocol.

    Args:
        port: port number, 0-65535, as int or digit-string (``22`` or
            ``"22"``).  Out-of-range values and non-numeric input return
            ``None``.
        protocol: transport protocol, case-insensitive (``"tcp"`` by
            default, ``"udp"``, ``"sctp"``, ``"dccp"``).  An empty or
            non-string protocol returns ``None``.

    Returns:
        The matching :class:`PortEntry` or ``None``; never raises.

    Example:
        port_service(22).service            # 'ssh'
        port_service(53, 'udp').service     # 'domain'
        port_service(99999)                 # None
    """
    port_num = _coerce_port(port)
    if port_num is None:
        return None
    if not isinstance(protocol, str) or not protocol.strip():
        return None
    _, by_key, _ = _load_ports()
    return by_key.get((port_num, protocol.strip().lower()))


def ports_for_service(name: Any) -> List[PortEntry]:
    """
    All port registrations using a given service name, case-insensitively.

    Args:
        name: service name (``"http"``, ``"HTTP"``).  Non-string or empty
            input returns ``[]``.

    Returns:
        A fresh list of matching :class:`PortEntry` objects (pack order);
        ``[]`` when the service is unknown.  Never raises.

    Example:
        [p.port for p in ports_for_service('http')]    # [80, ...]
    """
    _, _, by_service = _load_ports()
    if not isinstance(name, str) or not name.strip():
        return []
    return list(by_service.get(name.strip().lower(), []))


def service_names() -> List[str]:
    """
    Sorted list of the distinct service names in the ports pack.

    Returns:
        Unique, sorted, lowercase service names (``['domain', 'http',
        'ssh', ...]``); ``[]`` when the pack is missing.

    Example:
        'https' in service_names()    # True with the shipped pack
    """
    _, _, by_service = _load_ports()
    return sorted(by_service)


def well_known_tcp() -> List[PortEntry]:
    """
    TCP port registrations below 1024 (the "well-known" range).

    Returns:
        A fresh list of :class:`PortEntry` objects with ``protocol ==
        'tcp'`` and ``port < 1024``, in pack order.

    Example:
        22 in [p.port for p in well_known_tcp()]    # True
    """
    entries, _, _ = _load_ports()
    return [entry for entry in entries if entry.protocol == 'tcp' and entry.port < 1024]


def notable_registered() -> List[PortEntry]:
    """
    Port registrations at or above 1024 as shipped in the pack.

    The pack curates the notable entries of the registered range
    (databases, proxies, remote access and similar), so this returns every
    parsed entry with ``port >= 1024`` (any protocol), in pack order.

    Example:
        3306 in [p.port for p in notable_registered()]    # True (MySQL)
    """
    entries, _, _ = _load_ports()
    return [entry for entry in entries if entry.port >= 1024]


def port_category(port: Union[int, str]) -> str:
    """
    Classify a port number into its IANA range.

    Args:
        port: port number as int or digit-string.  Values that cannot be
            interpreted as a port number (including non-string input)
            return ``''``.

    Returns:
        ``"well_known"`` for ports below 1024, ``"registered"`` for
        1024-49151 and ``"dynamic"`` for 49152 and above.

    Example:
        port_category(80)      # 'well_known'
        port_category(8080)    # 'registered'
        port_category(60000)   # 'dynamic'
    """
    port_num = _coerce_port(port)
    if port_num is None:
        return ''
    if port_num < 1024:
        return 'well_known'
    if port_num <= 49151:
        return 'registered'
    return 'dynamic'


# ---------------------------------------------------------------------------
# Public API -- languages (ISO 639)
# ---------------------------------------------------------------------------


def language(code: Any) -> Optional[Language]:
    """
    Look up a language by its ISO 639 code, case-insensitively.

    Args:
        code: two-letter (``"en"``) or three-letter (``"deu"``) language
            code.  Non-string input, wrong lengths and unknown codes return
            ``None``; the function never raises.

    Returns:
        The matching :class:`Language` or ``None``.

    Example:
        language('en').name    # 'English'
        language('DE').name    # 'German'
    """
    if not isinstance(code, str):
        return None
    key = code.strip().lower()
    if not key.isalpha() or len(key) not in (2, 3):
        return None
    _, by_code = _load_languages()
    return by_code.get(key)


def search_languages(query: Any) -> List[Language]:
    """
    Search languages by a case-insensitive substring of name OR code.

    Args:
        query: substring to look for.  An empty or whitespace-only string
            matches every language (the full list, two-letter block first);
            non-string input returns ``[]``.

    Returns:
        Matching :class:`Language` entries in pack order; never raises.

    Example:
        'German' in [lang.name for lang in search_languages('german')]    # True
    """
    entries, _ = _load_languages()
    if not isinstance(query, str):
        return []
    needle = query.strip().lower()
    return [entry for entry in entries
            if needle in entry.name.lower() or needle in entry.code]


def languages_count() -> int:
    """
    Number of parsed language entries (0 when the pack is missing).

    Example:
        languages_count() >= 100    # True with the shipped pack
    """
    entries, _ = _load_languages()
    return len(entries)


# ---------------------------------------------------------------------------
# Public API -- currencies (ISO 4217)
# ---------------------------------------------------------------------------


def currency(code: Any) -> Optional[Currency]:
    """
    Look up a currency by its three-letter code, case-insensitively.

    Args:
        code: ISO 4217 alpha code (``"USD"``, ``"usd"``).  Non-string
            input, wrong lengths and unknown codes return ``None``; the
            function never raises.

    Returns:
        The matching :class:`Currency` or ``None``.

    Example:
        currency('EUR').minor_units    # 2
        currency('usd').code           # 'USD'
    """
    if not isinstance(code, str):
        return None
    key = code.strip().upper()
    if not key.isalpha() or len(key) != 3:
        return None
    _, by_code = _load_currencies()
    return by_code.get(key)


def search_currencies(query: Any) -> List[Currency]:
    """
    Search currencies by a case-insensitive substring of name OR code.

    Args:
        query: substring to look for (``"dollar"``, ``"EUR"``).  An empty
            or whitespace-only string matches every currency; non-string
            input returns ``[]``.

    Returns:
        Matching :class:`Currency` entries in pack order; never raises.

    Example:
        'USD' in [c.code for c in search_currencies('dollar')]    # True
    """
    entries, _ = _load_currencies()
    if not isinstance(query, str):
        return []
    needle = query.strip().lower()
    return [entry for entry in entries
            if needle in entry.name.lower() or needle in entry.code.lower()]


def currencies_for_country(alpha2: Any) -> List[str]:
    """
    Primary currency codes for a country, via the built-in country map.

    Args:
        alpha2: ISO 3166-1 alpha-2 country code, case-insensitive
            (``"US"``, ``"vn"``).  The lookup uses the module-level
            ``_COUNTRY_CURRENCIES`` table of ~80 major countries; countries
            not in the table (and any non-string or malformed input)
            return ``[]``.

    Returns:
        A fresh list with the ISO 4217 alpha code(s); typically exactly one
        entry such as ``['USD']``.

    Example:
        currencies_for_country('US')     # ['USD']
        currencies_for_country('de')     # ['EUR']
        currencies_for_country('XX')     # []
    """
    if not isinstance(alpha2, str):
        return []
    key = alpha2.strip().upper()
    code = _COUNTRY_CURRENCIES.get(key)
    return [code] if code else []


# ---------------------------------------------------------------------------
# Public API -- HTTP status codes
# ---------------------------------------------------------------------------


def http_status(code: Union[int, str]) -> Optional[HttpStatus]:
    """
    Look up an HTTP status code entry by its numeric code.

    Args:
        code: status code as int or digit-string (``404`` or ``"404"``).
            Non-numeric input and unknown codes return ``None``; the
            function never raises.

    Returns:
        The matching :class:`HttpStatus` or ``None``.

    Example:
        http_status(404).phrase     # 'Not Found'
        http_status(999)            # None
    """
    code_num = _coerce_int(code)
    if code_num is None:
        return None
    _, by_code = _load_http_statuses()
    return by_code.get(code_num)


def http_statuses_for_category(category: Any) -> List[HttpStatus]:
    """
    All shipped HTTP status entries for a category, case-insensitively.

    Args:
        category: one of ``informational``, ``success``, ``redirection``,
            ``client_error``, ``server_error`` (any casing; spaces and
            hyphens are treated like underscores, so ``"Client Error"``
            works).  Non-string or unknown categories return ``[]``.

    Returns:
        Matching :class:`HttpStatus` entries in pack order; never raises.

    Example:
        429 in [s.code for s in http_statuses_for_category('client_error')]    # True
    """
    entries, _ = _load_http_statuses()
    if not isinstance(category, str) or not category.strip():
        return []
    key = _normalize_category(category)
    return [entry for entry in entries if entry.category == key]


def http_status_category(code: Union[int, str]) -> Optional[str]:
    """
    Derive the HTTP status class purely from the numeric code.

    Unlike :func:`http_status` this needs no data pack: 1xx codes map to
    ``informational``, 2xx to ``success``, 3xx to ``redirection``, 4xx to
    ``client_error`` and 5xx to ``server_error``.

    Args:
        code: status code as int or digit-string.  Anything outside 100-599
            (and any non-numeric input) returns ``None``.

    Returns:
        The category slug or ``None``.

    Example:
        http_status_category(200)    # 'success'
        http_status_category(429)    # 'client_error'
        http_status_category(999)    # None
    """
    code_num = _coerce_int(code)
    if code_num is None:
        return None
    return _HTTP_CATEGORY_BY_HUNDREDS.get(code_num // 100)


# ---------------------------------------------------------------------------
# Public API -- CWE catalogue
# ---------------------------------------------------------------------------


def cwe(cwe_id: Any) -> Optional[Cwe]:
    """
    Look up a CWE entry by identifier, accepting several spellings.

    Args:
        cwe_id: identifier in any of the forms ``"CWE-79"``, ``"cwe-79"``,
            ``"79"`` or ``"  CWE-79 "`` (leading zeros are ignored).  Empty,
            non-string or non-numeric identifiers return ``None``; the
            function never raises.

    Returns:
        The matching :class:`Cwe` or ``None``.  All spellings resolve to
        the identical cached object, so ``cwe('79') == cwe('CWE-79')``.

    Example:
        cwe('CWE-79').name.startswith('Improper Neutralization')    # True
        cwe('79') == cwe('CWE-79')                                  # True
    """
    digits = _cwe_digits(cwe_id)
    if digits is None:
        return None
    _, by_id = _load_cwes()
    return by_id.get(f'CWE-{digits}')


def search_cwes(query: Any) -> List[Cwe]:
    """
    Search the CWE catalogue by a case-insensitive substring of id OR name.

    Args:
        query: substring to look for (``"injection"``, ``"cwe-79"``).  An
            empty or whitespace-only string matches every entry; non-string
            input returns ``[]``.

    Returns:
        Matching :class:`Cwe` entries in pack order; never raises.

    Example:
        'CWE-89' in [c.cwe_id for c in search_cwes('SQL Injection')]    # True
    """
    entries, _ = _load_cwes()
    if not isinstance(query, str):
        return []
    needle = query.strip().lower()
    return [entry for entry in entries
            if needle in entry.cwe_id.lower() or needle in entry.name.lower()]


def cwes_count() -> int:
    """
    Number of parsed CWE entries (0 when the pack is missing).

    Example:
        cwes_count() >= 100    # True with the shipped pack
    """
    entries, _ = _load_cwes()
    return len(entries)


# ---------------------------------------------------------------------------
# Public API -- IANA top-level domains
# ---------------------------------------------------------------------------


def is_iana_tld(tld: Any) -> bool:
    """
    True when the string is an IANA top-level domain.

    The value is stripped, lowercased and any leading dot is removed, so
    ``'.com'``, ``'COM'`` and ``' com '`` all test the TLD ``com``.  The
    check is an exact membership test against the shipped ``iana_tlds``
    pack -- ``'notarealtld123'`` is False even though it looks well-formed.

    Args:
        tld: candidate TLD.  Non-string input (and anything empty after
            normalisation) returns ``False``; the function never raises.

    Example:
        is_iana_tld('dev')              # True
        is_iana_tld('.com')             # True
        is_iana_tld('notarealtld123')   # False
    """
    if not isinstance(tld, str):
        return False
    key = tld.strip().lower().lstrip('.')
    if not key:
        return False
    _, known = _load_tlds()
    return key in known


def iana_tlds() -> List[str]:
    """
    The sorted list of every IANA top-level domain in the pack.

    Returns:
        The cached, sorted, deduplicated list (identity-stable across
        calls, mirroring :func:`obscuralens.utils.data_packs.load_data_pack`
        -- callers must not mutate it); ``[]`` when the pack is missing.

    Example:
        len(iana_tlds()) == tld_count()    # True
    """
    entries, _ = _load_tlds()
    return entries


def tld_count() -> int:
    """
    Number of TLDs in the pack (0 when the pack is missing).

    Example:
        tld_count() >= 1400    # True with the shipped pack
    """
    entries, _ = _load_tlds()
    return len(entries)


# ---------------------------------------------------------------------------
# Public API -- file extensions
# ---------------------------------------------------------------------------


def file_extension(ext: Any) -> Optional[FileExtension]:
    """
    Look up a file-extension entry by its extension, case-insensitively.

    Args:
        ext: extension with or without a leading dot, any casing (``"exe"``,
            ``".ZIP"``).  Non-string input, empty values and unknown
            extensions return ``None``; the function never raises.

    Returns:
        The matching :class:`FileExtension` or ``None``.

    Example:
        file_extension('exe').category        # 'executable'
        file_extension('.zip').category       # 'archive'
    """
    key = _normalize_ext(ext)
    if not key:
        return None
    _, by_ext = _load_extensions()
    return by_ext.get(key)


def extensions_for_category(category: Any) -> List[FileExtension]:
    """
    All file-extension entries for a category, case-insensitively.

    Args:
        category: category slug (``"archive"``, ``"Archive"``; spaces and
            hyphens are treated like underscores).  Non-string or unknown
            categories return ``[]``.

    Returns:
        Matching :class:`FileExtension` entries in pack order; never raises.

    Example:
        'zip' in [e.ext for e in extensions_for_category('archive')]    # True
    """
    entries, _ = _load_extensions()
    if not isinstance(category, str) or not category.strip():
        return []
    key = _normalize_category(category)
    return [entry for entry in entries if entry.category == key]


def search_extensions(query: Any) -> List[FileExtension]:
    """
    Search file extensions by a substring of ext, category OR description.

    Args:
        query: substring to look for (``"archive"``, ``"word"``).  An empty
            or whitespace-only string matches every entry; non-string input
            returns ``[]``.

    Returns:
        Matching :class:`FileExtension` entries in pack order; never raises.

    Example:
        'zip' in [e.ext for e in search_extensions('archive')]    # True
    """
    entries, _ = _load_extensions()
    if not isinstance(query, str):
        return []
    needle = query.strip().lower()
    return [entry for entry in entries
            if needle in entry.ext or needle in entry.category
            or needle in entry.description.lower()]


def extension_category(ext: Any) -> Optional[str]:
    """
    Category of a file extension, or ``None`` when it is unknown.

    A convenience wrapper around :func:`file_extension` that normalises the
    argument the same way (leading dot stripped, lowercased).

    Args:
        ext: extension such as ``'.zip'``; non-string and unknown values
            return ``None``.

    Example:
        extension_category('.zip')    # 'archive'
        extension_category('exe')     # 'executable'
    """
    entry = file_extension(ext)
    return entry.category if entry is not None else None


# ---------------------------------------------------------------------------
# Public API -- MIME types
# ---------------------------------------------------------------------------


def mime_for_extension(ext: Any) -> Optional[MimeType]:
    """
    Look up the MIME type registered for a file extension.

    Args:
        ext: extension with or without a leading dot, any casing (``"json"``,
            ``".HTML"``).  Non-string input, empty values and unknown
            extensions return ``None``; the function never raises.

    Returns:
        The matching :class:`MimeType` (first entry seen in the pack for
        that extension) or ``None``.

    Example:
        mime_for_extension('json').mime     # 'application/json'
        mime_for_extension('HTML').mime     # 'text/html'
    """
    key = _normalize_ext(ext)
    if not key:
        return None
    _, by_ext, _ = _load_mimes()
    return by_ext.get(key)


def extension_for_mime(mime: Any) -> Optional[MimeType]:
    """
    Look up the file extension registered for a MIME type.

    Args:
        mime: type/subtype pair, any casing (``"application/json"``).
            Non-string input, empty values and unknown types return
            ``None``; the function never raises.

    Returns:
        The matching :class:`MimeType` (first entry seen in the pack for
        that mime value) or ``None``.

    Example:
        extension_for_mime('application/json').extension    # 'json'
    """
    if not isinstance(mime, str):
        return None
    key = mime.strip().lower()
    if not key:
        return None
    _, _, by_mime = _load_mimes()
    return by_mime.get(key)


def search_mimes(query: Any) -> List[MimeType]:
    """
    Search MIME types by a substring of mime, extension OR description.

    Args:
        query: substring to look for (``"json"``, ``"image/"``).  An empty
            or whitespace-only string matches every entry; non-string input
            returns ``[]``.

    Returns:
        Matching :class:`MimeType` entries in pack order; never raises.

    Example:
        'application/json' in [m.mime for m in search_mimes('json')]    # True
    """
    entries, _, _ = _load_mimes()
    if not isinstance(query, str):
        return []
    needle = query.strip().lower()
    return [entry for entry in entries
            if needle in entry.mime or needle in entry.extension
            or needle in entry.description.lower()]


def mimes_count() -> int:
    """
    Number of parsed MIME type entries (0 when the pack is missing).

    Example:
        mimes_count() >= 300    # True with the shipped pack
    """
    entries, _, _ = _load_mimes()
    return len(entries)


# ---------------------------------------------------------------------------
# Public API -- user agents
# ---------------------------------------------------------------------------


def _filter_user_agents(entries: List[UserAgent], family: Any, platform: Any) -> List[UserAgent]:
    """
    Filter user-agent entries by family and/or platform (case-insensitive).

    Both filters are substring matches over the lowercased entry fields;
    ``None``, non-string and blank filter values are ignored.  Returns a
    fresh list, possibly empty.
    """
    family_needle = _filter_needle(family)
    platform_needle = _filter_needle(platform)
    if not family_needle and not platform_needle:
        return list(entries)
    selected: List[UserAgent] = []
    for entry in entries:
        if family_needle and family_needle not in entry.family.lower():
            continue
        if platform_needle and platform_needle not in entry.platform.lower():
            continue
        selected.append(entry)
    return selected


def random_user_agent(family: Optional[str] = None, platform: Optional[str] = None,
                      seed: Optional[int] = None) -> str:
    """
    Draw a random user-agent string from the ``user_agents`` pack.

    Args:
        family: optional family filter (``"Chrome"``, ``"Firefox"`` ...),
            matched case-insensitively as a substring of the entry family.
        platform: optional platform filter (``"Windows 11"``, ``"macOS"``
            ...), matched case-insensitively as a substring of the entry
            platform.
        seed: optional seed for the underlying ``random.Random``; the same
            seed always yields the same string, which keeps tests
            deterministic.  ``None`` draws from OS entropy.  Unhashable seed
            values fall back to entropy instead of raising.

    Returns:
        A user-agent string, never empty and never raising.  When the
        filters match nothing the draw falls back to the unfiltered pool;
        when the pack itself is missing or empty the safe
        ``_FALLBACK_USER_AGENT`` constant is returned.

    Example:
        random_user_agent(seed=42) == random_user_agent(seed=42)          # True
        'Chrome/' in random_user_agent(family='Chrome', seed=7)           # True
        'Windows NT 10.0' in random_user_agent(platform='Windows 11')     # True
    """
    entries = _load_user_agents()
    pool = _filter_user_agents(entries, family, platform)
    if not pool:
        pool = entries
    if not pool:
        return _FALLBACK_USER_AGENT
    try:
        rng = random.Random(seed)
    except TypeError:  # exotic unhashable seeds (lists, dicts, ...)
        rng = random.Random()
    return rng.choice(pool).string


# ---------------------------------------------------------------------------
# Public API -- catalog statistics
# ---------------------------------------------------------------------------

#: (pack name, zero-argument callable returning the pack's entry count), in
#: the display order used by :func:`catalog_stats` / :func:`catalog_summary`.
_PACK_COUNTERS: Tuple[Tuple[str, Callable[[], int]], ...] = (
    (_COUNTRIES_PACK, lambda: len(_load_countries()[0])),
    (_LANGUAGES_PACK, lambda: len(_load_languages()[0])),
    (_CURRENCIES_PACK, lambda: len(_load_currencies()[0])),
    (_PORTS_PACK, lambda: len(_load_ports()[0])),
    (_HTTP_PACK, lambda: len(_load_http_statuses()[0])),
    (_CWES_PACK, lambda: len(_load_cwes()[0])),
    (_TLDS_PACK, lambda: len(_load_tlds()[0])),
    (_EXTENSIONS_PACK, lambda: len(_load_extensions()[0])),
    (_MIMES_PACK, lambda: len(_load_mimes()[0])),
    (_USER_AGENTS_PACK, lambda: len(_load_user_agents())),
)


def catalog_stats() -> List[CatalogStats]:
    """
    Per-pack loading statistics for the whole catalog.

    Calling this function loads (and caches) every pack.  Each result
    records the pack name, its real entry count and whether the pack was
    found on disk and parsed (``loaded``); a missing pack reports
    ``entries=0, loaded=False``.

    Returns:
        One :class:`CatalogStats` per pack -- ten entries in total -- in
        catalog display order.

    Example:
        stats = catalog_stats()
        len(stats)                                     # 10
        {s.name for s in stats} >= {'iana_tlds'}       # True
    """
    stats: List[CatalogStats] = []
    for name, counter in _PACK_COUNTERS:
        entries = counter()
        stats.append(CatalogStats(name=name, entries=entries, loaded=name in _CACHE))
    return stats


def catalog_summary() -> str:
    """
    Render :func:`catalog_stats` as a fixed-width plain-text table.

    The table lists every pack with its entry count and load state plus a
    totals row.  It always contains the ten pack names and their entry
    counts, which makes it a handy one-shot smoke test of the catalog.

    Returns:
        The multi-line summary table (no trailing newline).

    Example:
        print(catalog_summary())
        # ObscuraLens offline data catalog
        #
        # pack                  entries    loaded
        # ------------------------------  -------
        # countries_iso3166           249      yes
        # ...
        # total                       6387   10/10
    """
    stats = catalog_stats()
    header = '{:<20}{:>10}{:>10}'.format('pack', 'entries', 'loaded')
    rule = '-' * len(header)
    lines = ['ObscuraLens offline data catalog', '', header, rule]
    total = 0
    loaded_packs = 0
    for stat in stats:
        total += stat.entries
        if stat.loaded:
            loaded_packs += 1
        lines.append('{:<20}{:>10}{:>10}'.format(
            stat.name, stat.entries, 'yes' if stat.loaded else 'no'))
    lines.append(rule)
    lines.append('{:<20}{:>10}{:>10}'.format(
        'total', total, '{}/{}'.format(loaded_packs, len(stats))))
    return '\n'.join(lines)


#: Public names exported by this module (``from ... import *`` surface).
__all__ = [
    # data model
    'Country',
    'PortEntry',
    'Language',
    'Currency',
    'HttpStatus',
    'Cwe',
    'FileExtension',
    'MimeType',
    'UserAgent',
    'CatalogStats',
    # countries (ISO 3166-1)
    'country',
    'search_countries',
    'countries_count',
    # ports and services
    'port_service',
    'ports_for_service',
    'service_names',
    'well_known_tcp',
    'notable_registered',
    'port_category',
    # languages (ISO 639)
    'language',
    'search_languages',
    'languages_count',
    # currencies (ISO 4217)
    'currency',
    'search_currencies',
    'currencies_for_country',
    # HTTP status codes
    'http_status',
    'http_statuses_for_category',
    'http_status_category',
    # CWE catalogue
    'cwe',
    'search_cwes',
    'cwes_count',
    # IANA top-level domains
    'is_iana_tld',
    'iana_tlds',
    'tld_count',
    # file extensions
    'file_extension',
    'extensions_for_category',
    'search_extensions',
    'extension_category',
    # MIME types
    'mime_for_extension',
    'extension_for_mime',
    'search_mimes',
    'mimes_count',
    # user agents
    'random_user_agent',
    # catalog statistics
    'catalog_stats',
    'catalog_summary',
]
