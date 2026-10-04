"""
IMEI / IMEISV device identification sources.

An IMEI answers "which device is this": the first eight digits are the TAC
(Type Allocation Code) that maps to a manufacturer and model family, the
first two of those digits are the Reporting Body Identifier naming the
certification body, the next six are the per-device serial, the fifteenth
digit is a Luhn check digit and an optional sixteenth digit is the software
version (IMEISV). This module mixes one offline math source and one offline
pack - IMEI intelligence is fully offline today, which is exactly the point:
the decomposition works for any of the ~255,000 known TACs without a network:

* ``imei_math`` - pure-Python 3GPP TS 23.003 decomposition: TAC, reporting
                  body identifier, SNR, check digit, software version digit
                  (IMEISV), Luhn validity and the pretty AA-BBBBBB-CCCCCC-D
                  print format.
* ``tac_pack``  - offline curated TAC pack shipped at
                  ``obscuralens/data/tac.txt`` (139 curated
                  ``TAC8|Manufacturer|Model`` entries: every recent iPhone
                  generation, Galaxy S/Note/Z/A lines, Pixels, Xiaomi/Redmi/
                  POCO, Huawei, OnePlus, HMD Nokia, classic feature phones,
                  IoT modem modules and rugged brands).

Every provider runs independently; results are merged field-by-field so a
single flaky source cannot blank out the whole report. Field provenance is
tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..health import health
from ..utils.data_packs import DATA_DIR
from ..utils.helpers import fanout_workers
from ..utils.validators import normalize_imei

# Reporting Body Identifier (RBI) names, 3GPP TS 23.003 section 3.1. The
# two-digit prefix of every TAC names the certification body that allocated
# it. The well-documented codes:
#   01 = PTCRB (North America)         35 = BABT (United Kingdom)
#   86 = TAF (China)                   91 = TEC (India, domestic makers)
#   44 = BABT-era secondary range (Motorola / Nokia / Siemens era devices)
#   99 = modern mixed allocation (CDMA-era iPhones, current Chinese makers)
# Other two-digit codes (33, 49, 50, 51, 52, 98, ...) are GSMA-assigned
# regional certification identifiers whose public documentation is
# inconsistent, so they are reported as the raw code only.
_REPORTING_BODIES: Dict[str, str] = {
    '01': 'PTCRB (North America)',
    '35': 'BABT (United Kingdom)',
    '44': 'BABT-era secondary range (Motorola/Nokia/Siemens era)',
    '86': 'TAF (China)',
    '91': 'TEC (India, domestic makers)',
    '99': 'modern mixed allocation (CDMA-era iPhones, Chinese makers)',
}

#: Parsed TAC pack cache: 8-digit TAC -> (manufacturer, model hint).
#: ``None`` means "not loaded yet"; a dict (possibly empty) is the cache.
_TAC_CACHE: Optional[Dict[str, Tuple[str, str]]] = None


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _imei_digits(value: Any) -> str:
    """
    Coerce ``'356938035643809'``, ``'35-693803-564380-9'`` or a spaced
    IMEISV into bare digits; ``''`` when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_imei(str(value or ''))


def _luhn_ok(digits: str) -> bool:
    """
    Standard Luhn checksum over a digit string (the IMEI check rule).

    Doubling starts at the second digit from the right; a valid identifier
    totals to a multiple of ten.
    """
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _luhn_check_digit(base: str) -> int:
    """
    The digit that would make ``base`` pass the Luhn check.

    Used to report the expected check digit of a malformed standalone
    lookup (the tracker itself rejects such input before gathering).
    """
    total = 0
    for index, char in enumerate(reversed(base + '0')):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (10 - total % 10) % 10


def _load_tac_pack() -> Dict[str, Tuple[str, str]]:
    """
    Parse the shipped TAC pack into a ``{tac: (manufacturer, model)}`` map.

    The pack is a plain-text file at ``obscuralens/data/tac.txt`` with one
    ``TAC8|Manufacturer|Model-hint`` entry per line, ``#``-comments and
    blank lines ignored. It is parsed directly (not via ``load_data_pack``)
    because manufacturers and model families are case-sensitive - "Apple"
    and "IPHONE 12 PRO MAX" must not be lowercased - and cached at module
    level for the process lifetime. A missing or unreadable pack yields an
    empty dict without raising and without caching, so a later call can
    retry after the file is fixed.
    """
    global _TAC_CACHE
    if _TAC_CACHE is not None:
        return _TAC_CACHE

    entries: Dict[str, Tuple[str, str]] = {}
    path: Path = DATA_DIR / 'tac.txt'
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, ValueError):  # OSError + UnicodeDecodeError
        return entries

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split('|')
        if len(parts) < 3:
            continue
        tac = parts[0].strip()
        manufacturer = parts[1].strip()
        model = parts[2].strip()
        if len(tac) == 8 and tac.isdigit() and manufacturer:
            entries.setdefault(tac, (manufacturer, model))
    _TAC_CACHE = entries
    return entries


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _imei_math(imei_value: Any) -> Dict[str, Any]:
    """
    Pure-Python 3GPP TS 23.003 decomposition - the always-available half.

    Derives everything the digits themselves encode, for any IMEI ever
    minted (no TAC registry needed):

    * ``imei_type``       - ``'IMEI'`` (15 digits) or ``'IMEISV'``
                            (16 digits, software version appended).
    * ``tac``             - Type Allocation Code, the first 8 digits.
    * ``reporting_body_identifier`` - first two TAC digits (the RBI).
    * ``reporting_body``  - certification body name for documented RBIs
                            (01 PTCRB, 35 BABT, 86 TAF, 44, 91, 99).
    * ``serial_number``   - the 6-digit SNR (digits 9-14).
    * ``check_digit``     - digit 15 (int).
    * ``luhn_valid``      - whether digits 1-15 pass the Luhn check; a
                            failed standalone lookup also gets the
                            ``expected_check_digit`` it should have ended
                            with.
    * ``software_version``- IMEISV only: digit 16 (int).
    * ``formatted``       - pretty ``AA-BBBBBB-CCCCCC-D`` print form.
    """
    digits = _imei_digits(imei_value)
    if not digits:
        return {}

    is_sv = len(digits) == 16
    out: Dict[str, Any] = {
        'imei_type': 'IMEISV' if is_sv else 'IMEI',
        'tac': digits[:8],
        'reporting_body_identifier': digits[:2],
        'serial_number': digits[8:14],
        'check_digit': int(digits[14]),
        'luhn_valid': _luhn_ok(digits[:15]),
        'formatted': f"{digits[:2]}-{digits[2:8]}-{digits[8:14]}-{digits[14]}",
    }

    body = _REPORTING_BODIES.get(digits[:2])
    if body:
        out['reporting_body'] = body

    if is_sv:
        out['software_version'] = int(digits[15])
    if not out['luhn_valid']:
        out['expected_check_digit'] = _luhn_check_digit(digits[:14])
    return out


def _tac_pack(imei_value: Any) -> Dict[str, Any]:
    """
    Offline curated TAC pack lookup: manufacturer and model family.

    The pack carries 139 hand-curated TACs (the iconic model families an
    OSINT operator meets most) with manufacturers and model hints in their
    registry casing. A miss means "not in this curated subset", NOT "unknown
    device" - hundreds of thousands of TACs exist and only commercial IMEI
    services resolve them all; ``imei_math`` still decomposes the identifier
    either way.
    """
    digits = _imei_digits(imei_value)
    if not digits:
        return {}

    entry = _load_tac_pack().get(digits[:8])
    if not entry:
        # A miss is an EXPECTED outcome for a curated subset (139 of ~255,000
        # known TACs), not a pack failure: answer with an explicit "no
        # manufacturer" instead of {} so source health records the execution
        # as OK and the circuit breaker never trips on ordinary misses. The
        # merge layer drops None values, so no manufacturer field appears.
        return {'manufacturer': None}
    manufacturer, model = entry
    out: Dict[str, Any] = {'manufacturer': manufacturer}
    if model:
        out['model'] = model
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'imei_math': _imei_math,
    'tac_pack': _tac_pack,
}

# IMEI device intelligence is fully keyless and offline today; the registry
# stays here so future keyed sources (e.g. commercial TAC databases) slot in
# without touching the tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'imei_math': 'Offline 3GPP TS 23.003 decomposition: TAC, reporting body, SNR, Luhn',
    'tac_pack': 'Offline curated TAC pack (obscuralens/data/tac.txt): manufacturer + model',
}


def _keep(value: Any) -> bool:
    # An IMEI whose Luhn check failed (luhn_valid == False) is a real answer,
    # so only None / '' / [] / {} count as "no data". Pack readers also use
    # an explicit None value as the "ran fine, nothing curated" marker,
    # which this same rule filters out of the merged fields.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(imei_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable IMEI source in parallel and merge the results.

    Args:
        imei_value: IMEI (15 digits) or IMEISV (16 digits); spaces, dashes
            and dots are tolerated
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'imei'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as an IMEI / IMEISV.
    """
    keys = keys or {}
    digits = _imei_digits(imei_value)
    if not digits:
        raise ValueError(f"invalid IMEI: {imei_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(digits))

    for name, fn in _plugin_sources('imei').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(digits))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=fanout_workers(len(tasks))) as ex:
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

    health.record_batch('imei', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the standards-derived math beats curated pack data on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the bare digit string in its canonical form.
    merged['imei'] = digits

    return {'fields': merged, 'sources': status, 'provenance': provenance}
