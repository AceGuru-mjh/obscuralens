"""
MMSI (Maritime Mobile Service Identity) intelligence sources.

An MMSI answers "which station is this on the water": the nine-digit
ITU-R M.1085 identity encodes the station class in its leading digits -
individual ship stations carry a three-digit Maritime Identification Digit
(MID, 201-775, assigned per country) plus a six-digit serial, coast
stations are ``00 + MID + 4 digits``, group identities start with a single
zero, handheld VHF transceivers with an 8, and AIS aids to navigation with
99. The MID resolves to the flag country through the shipped pack. This
module is fully offline (like the IMEI kind), mixing one math source and
one pack source:

* ``mmsi_math`` - pure-Python ITU-R M.1085 structure decode: station class
                  from the leading digits, the MID, the serial digits, the
                  ITU series label and a conservative trailing-zero note.
* ``mid_pack``  - offline curated MID pack shipped at
                  ``obscuralens/data/mid_codes.txt`` (97 curated
                  ``MID|country`` assignments covering the major flag
                  states). Resolves the flag country without touching the
                  network.

Every provider runs independently; results are merged field-by-field so a
single flaky source cannot blank out the whole report. Field provenance is
tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.data_packs import DATA_DIR
from ..utils.helpers import fanout_workers
from ..utils.validators import normalize_mmsi

#: Parsed MID pack cache: three-digit MID -> country name.
#: ``None`` means "not loaded yet"; a dict (possibly empty) is the cache.
_MID_CACHE: Optional[Dict[str, str]] = None

#: Station classes keyed by their leading-digit signature. The ITU series
#: notes are quoted conservatively: leading '0' covers both group ship and
#: coast station identity shapes (the '00' prefix marks a coast station
#: proper), and leading '9' is reserved with the '99' block documented for
#: AIS aids to navigation.
_STATION_CLASSES: Dict[str, str] = {
    'ship': ('individual ship station (MID + 6-digit serial)',
             'MID 201-775 individual series'),
    'coast': ('coast station identity (00 + MID + 4 digits)',
              'leading-zero coast series'),
    'group': ('group ship / group coast station identity (0 + MID + 5 digits)',
              'leading-zero group series'),
    'handheld': ('handheld VHF DSC transceiver (8 + MID + 5 digits)',
                 'leading-8 handheld series'),
    'aton': ('AIS aid to navigation (99 + MID + 4 digits)',
             'leading-99 AtoN series'),
    'reserved': ('reserved / future ITU use (leading 9)',
                 'leading-9 reserved series'),
    'unassigned': ('unassigned leading digit (no ITU series starts here)',
                   'unassigned series'),
}


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _mmsi_digits(value: Any) -> str:
    """
    Coerce ``366910000``, ``'366-910-000'`` or ``'MMSI:366910000'`` into
    the bare nine-digit form; ``''`` when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_mmsi(value)


def _load_mid_pack() -> Dict[str, str]:
    """
    Parse the shipped MID pack into a ``{mid: country}`` map.

    The pack is a plain-text file at ``obscuralens/data/mid_codes.txt``
    with one ``MID|country`` entry per line, ``#``-comments and blank
    lines ignored, compiled from the public ITU-R M.1085 Annex I
    assignments (97 curated entries covering the major flag states and the
    countries an OSINT investigation most often meets; several states hold
    multiple MIDs, which is why the US block is 366-369 and Panama holds
    both 35x and 37x ranges). It is parsed directly (not via
    ``load_data_pack``) because country names are case-sensitive - "United
    Kingdom" and "South Korea" must survive - and cached at module level
    for the process lifetime. A missing or unreadable pack yields an empty
    dict without raising and without caching, so a later call can retry
    after the file is fixed.
    """
    global _MID_CACHE
    if _MID_CACHE is not None:
        return _MID_CACHE

    entries: Dict[str, str] = {}
    path: Path = DATA_DIR / 'mid_codes.txt'
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, ValueError):  # OSError + UnicodeDecodeError
        return entries

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        mid, _sep, country = stripped.partition('|')
        mid = mid.strip()
        country = country.strip()
        if len(mid) == 3 and mid.isdigit() and country:
            entries.setdefault(mid, country)
    _MID_CACHE = entries
    return entries


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _mmsi_math(mmsi_value: Any) -> Dict[str, Any]:
    """
    Pure-Python ITU-R M.1085 structure decode - the always-available half.

    Derives everything the digits themselves encode, for any nine-digit
    MMSI (no registry needed):

    * ``mid``             - the three-digit Maritime Identification Digit
                            (where the station class has one).
    * ``station_type``    - human-readable station class from the leading
                            digits (ship / coast / group / handheld / AtoN
                            / reserved / unassigned).
    * ``station_type_code``- short class slug (``'ship'``, ``'coast'``...).
    * ``serial_digits``   - the station serial digits after the MID.
    * ``trailing_zero_notes``- only when the serial ends in zero: a
                            conservative note about the documented
                            data/associated-identity usage of zero-ending
                            serials (unconfirmed convention, flagged as
                            such).
    * ``itu_series``      - the ITU series label the identity belongs to.
    """
    digits = _mmsi_digits(mmsi_value)
    if not digits:
        return {}

    first = digits[0]
    if digits.startswith('00'):
        code = 'coast'
        mid = digits[2:5]
        serial = digits[5:]
    elif first == '0':
        code = 'group'
        mid = digits[1:4]
        serial = digits[4:]
    elif first == '8':
        code = 'handheld'
        mid = digits[1:4]
        serial = digits[4:]
    elif digits.startswith('99'):
        code = 'aton'
        mid = digits[2:5]
        serial = digits[5:]
    elif first == '9':
        code = 'reserved'
        mid = ''
        serial = ''
    else:
        leading = digits[:3]
        if 201 <= int(leading) <= 775:
            code = 'ship'
            mid = leading
            serial = digits[3:]
        else:
            code = 'unassigned'
            mid = ''
            serial = ''

    station_type, itu_series = _STATION_CLASSES[code]
    out: Dict[str, Any] = {
        'station_type': station_type,
        'station_type_code': code,
        'itu_series': itu_series,
    }
    if mid:
        out['mid'] = mid
    if serial:
        out['serial_digits'] = serial
    if code == 'ship' and serial.endswith('0'):
        # Zero-ending ship serials are repeatedly described in ITU-related
        # material as data / associated-station identities, but the rule is
        # not cleanly normative - reported as an unconfirmed convention.
        out['trailing_zero_notes'] = (
            'ship serial ends in zero - commonly associated with data / '
            'selective-call identities in ITU documentation (unconfirmed '
            'convention, not evidence)')
    return out


def _mid_pack(mmsi_value: Any) -> Dict[str, Any]:
    """
    Offline curated ITU MID pack lookup: the flag country of the station.

    The pack carries 97 hand-curated MID assignments (the major flag states
    plus the countries an OSINT investigation most often meets) with
    country names in their ITU casing. A miss means "not in this curated
    subset", NOT "invalid MMSI" - the full ITU table runs to several
    hundred entries and is revised between World Radiocommunication
    Conferences; ``mmsi_math`` still decodes the station class either way.
    """
    digits = _mmsi_digits(mmsi_value)
    if not digits:
        return {}

    # The MID sits at different offsets per station class; mirror the math
    # source's leading-digit logic to find it.
    first = digits[0]
    if digits.startswith('00') or digits.startswith('99'):
        mid = digits[2:5]
    elif first in ('0', '8'):
        mid = digits[1:4]
    else:
        mid = digits[:3]
    if not (len(mid) == 3 and mid.isdigit()):
        return {}

    country = _load_mid_pack().get(mid)
    if not country:
        # A miss is an EXPECTED outcome for a curated subset (97 of several
        # hundred ITU assignments), not a pack failure: answer with an
        # explicit "no country" instead of {} so source health records the
        # execution as OK and the circuit breaker never trips on misses.
        # The merge layer drops None values, so no country field appears.
        return {'country': None}
    return {'country': country}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'mmsi_math': _mmsi_math,
    'mid_pack': _mid_pack,
}

# MMSI station intelligence is fully keyless and offline today; the
# registry stays here so future keyed sources (e.g. AIS position history
# services) slot in without touching the tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'mmsi_math': 'Offline ITU-R M.1085 structure decode: station class, MID, serial',
    'mid_pack': 'Offline curated MID pack (obscuralens/data/mid_codes.txt): flag country',
}


def _keep(value: Any) -> bool:
    # A reserved leading digit (station_type carries a real string either
    # way) is a real answer, so only None / '' / [] / {} count as "no
    # data". The MID pack reader also uses an explicit None value as the
    # "ran fine, nothing curated" marker, which this same rule filters out
    # of the merged fields.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(mmsi_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable MMSI source in parallel and merge the results.

    Args:
        mmsi_value: nine-digit MMSI; integers, hyphen/space separated
            forms and a ``'MMSI:'`` prefix marker are tolerated
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'mmsi'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as an MMSI.
    """
    keys = keys or {}
    digits = _mmsi_digits(mmsi_value)
    if not digits:
        raise ValueError(f"invalid MMSI: {mmsi_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(digits))

    for name, fn in _plugin_sources('mmsi').items():
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

    health.record_batch('mmsi', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the standards-derived math beats the curated pack data on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the bare digit string in its canonical form.
    merged['mmsi'] = digits

    return {'fields': merged, 'sources': status, 'provenance': provenance}
