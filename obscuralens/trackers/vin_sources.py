"""
VIN (Vehicle Identification Number) vehicle intelligence sources.

A VIN answers "which vehicle is this": the 17-character ISO 3779 identifier
encodes the World Manufacturer Identifier (first three characters, allocated
per ISO 3780), a manufacturer-defined Vehicle Descriptor Section (positions
4-8), a check digit at position 9 guarding against typos, a one-character
model-year code at position 10 (a 30-year cycle that repeats, so the year is
always two candidates), the assembly-plant code at position 11 and a
six-digit production serial. This module mixes one offline math source and
one keyless online API:

* ``vin_math``    - pure-Python ISO 3779 decomposition: WMI, VDS and VIS
                    slices, manufacturer and country from the shipped WMI
                    pack, first-character region hint, year code with both
                    model-year candidates, plant code, serial number,
                    the transliterated check-digit verdict (with the
                    expected digit on failure) and a position map
                    describing all 17 characters.
* ``nhtsa_vpic``  - the NHTSA vPIC decoder (keyless,
                    ``vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues``):
                    make, model, model year, body class, engine and drive
                    data, plant city/state/country and the decoder error
                    code, cross-checking the offline verdict (must fail
                    gracefully when unreachable - the offline math carries
                    the day for any VIN).

Every provider is queried independently; results are merged field-by-field
so a single flaky source cannot blank out the whole report. Field provenance
is tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..health import health
from ..utils.data_packs import DATA_DIR
from ..utils.helpers import fanout_workers
from ..utils.http_client import http
from ..utils.validators import normalize_vin

#: VIN-derived strings (manufacturers, plant cities) capped for report sanity.
_MAX_VPIC_CHARS = 80

#: Parsed WMI pack cache: 3-character WMI -> (manufacturer, country).
#: ``None`` means "not loaded yet"; a dict (possibly empty) is the cache.
_WMI_CACHE: Optional[Dict[str, Tuple[str, str]]] = None

#: First VIN character -> the region(s) it was allocated to. Coarser than the
#: WMI pack but always available, even for WMIs the curated pack misses.
#: '7' is historically New Zealand; NHTSA has also allocated 7-prefixed WMIs
#: to United States manufacturers since 2021. 'M' covers several south and
#: southeast Asian allocation blocks; 'N' the Near and Middle East; 'S' is
#: shared between the United Kingdom and Germany; 'T' between Switzerland
#: and the Czech Republic; 'V' between France and Spain; 'Y' between Sweden
#: and Finland.
_FIRST_CHAR_REGIONS: Dict[str, str] = {
    '1': 'United States',
    '4': 'United States',
    '5': 'United States',
    '7': 'New Zealand (also newer United States allocations)',
    '2': 'Canada',
    '3': 'Mexico',
    '6': 'Australia',
    '8': 'South America',
    '9': 'South America',
    'J': 'Japan',
    'K': 'South Korea',
    'L': 'China',
    'M': 'India / Thailand',
    'N': 'Turkey / Iran',
    'R': 'Taiwan / Uruguay',
    'S': 'United Kingdom / Germany',
    'T': 'Switzerland / Czech Republic',
    'V': 'France / Spain',
    'W': 'Germany',
    'X': 'Russia',
    'Y': 'Sweden / Finland',
    'Z': 'Italy',
}

#: Model-year code -> year in the 1980-2009 cycle. The alphabet runs
#: A-Y without I, O, Q, U and Z (21 letters) followed by digits 1-9, a
#: 30-year cycle that repeats from 2010: 'A' = 1980 = 2010, 'Y' = 2000 =
#: 2030, '1' = 2001 = 2031, '9' = 2009 = 2039.
_YEAR_CODES: Dict[str, int] = {}
for _letter in 'ABCDEFGHJKLMNPRSTVWXY':
    _YEAR_CODES[_letter] = 1980 + len(_YEAR_CODES)
for _digit in '123456789':
    _YEAR_CODES[_digit] = 2001 + int(_digit) - 1

#: vPIC field map: API key -> output field. Numeric fields are converted to
#: ints where the API reliably returns digit strings; everything else is a
#: defensively-trimmed string.
_VPIC_TEXT_FIELDS: Tuple[Tuple[str, str], ...] = (
    ('Make', 'vpic_make'),
    ('Model', 'vpic_model'),
    ('VehicleType', 'vpic_vehicle_type'),
    ('BodyClass', 'vpic_body_class'),
    ('DriveType', 'vpic_drive_type'),
    ('FuelTypePrimary', 'vpic_fuel_type'),
    ('TransmissionStyle', 'vpic_transmission_style'),
    ('GVWR', 'vpic_gvwr'),
    ('Series', 'vpic_series'),
    ('Trim', 'vpic_trim'),
    ('Manufacturer', 'vpic_manufacturer'),
    ('OtherMake', 'vpic_other_make'),
    ('PlantCity', 'vpic_plant_city'),
    ('PlantState', 'vpic_plant_state'),
    ('PlantCountry', 'vpic_plant_country'),
    ('ErrorCode', 'vpic_error_code'),
    ('AdditionalErrorText', 'vpic_error_text'),
    ('ElectrificationLevel', 'vpic_electrification'),
)

#: vPIC fields reported as integers (the API ships them as strings).
_VPIC_INT_FIELDS: Tuple[Tuple[str, str], ...] = (
    ('ModelYear', 'vpic_model_year'),
    ('EngineCylinders', 'vpic_engine_cylinders'),
    ('EngineHP', 'vpic_engine_hp'),
    ('Doors', 'vpic_doors'),
)

#: vPIC fields reported as floats (the API ships them as strings).
_VPIC_FLOAT_FIELDS: Tuple[Tuple[str, str], ...] = (
    ('DisplacementL', 'vpic_displacement_l'),
)


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _vin_text(value: Any) -> str:
    """
    Coerce ``'1M8-GDM9-A-XKP042788'``, a lower-case vin or a bare VIN into
    the canonical uppercase 17-character form; ``''`` when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_vin(str(value or ''))


def _expected_check_digit(vin: str) -> str:
    """The ISO 3779 check digit the VIN should carry at position 9."""
    total = 0
    transliteration = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    }
    weights = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)
    for char, weight in zip(vin, weights):
        value = int(char) if char.isdigit() else transliteration.get(char, 0)
        total += value * weight
    remainder = total % 11
    return 'X' if remainder == 10 else str(remainder)


def _load_wmi_pack() -> Dict[str, Tuple[str, str]]:
    """
    Parse the shipped WMI pack into a ``{wmi: (manufacturer, country)}`` map.

    The pack is a plain-text file at ``obscuralens/data/vin_wmi.txt`` with
    one ``WMI|manufacturer|country`` entry per line, ``#``-comments and
    blank lines ignored, compiled from the public ISO 3780 allocations
    (166 curated entries covering the mainstream manufacturers on six
    continents plus historically important marques). It is parsed directly
    (not via ``load_data_pack``) because manufacturer and country names are
    case-sensitive - "Mercedes-Benz" and "South Korea" must survive - and
    cached at module level for the process lifetime. A missing or unreadable
    pack yields an empty dict without raising and without caching, so a
    later call can retry after the file is fixed.
    """
    global _WMI_CACHE
    if _WMI_CACHE is not None:
        return _WMI_CACHE

    entries: Dict[str, Tuple[str, str]] = {}
    path: Path = DATA_DIR / 'vin_wmi.txt'
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
        wmi = parts[0].strip().upper()
        manufacturer = parts[1].strip()
        country = parts[2].strip()
        if len(wmi) == 3 and wmi.isalnum() and manufacturer:
            entries.setdefault(wmi, (manufacturer, country))
    _WMI_CACHE = entries
    return entries


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _vin_math(vin_value: Any) -> Dict[str, Any]:
    """
    Pure-Python ISO 3779 / ISO 4030 decomposition - the offline half.

    Derives everything the identifier itself encodes, for any VIN-shaped
    string (the WMI registry is only consulted for a nicer manufacturer
    label; the structural decode needs no registry at all):

    * ``wmi``                  - World Manufacturer Identifier (chars 1-3).
    * ``manufacturer``         - manufacturer from the shipped WMI pack;
                                 ``None`` (dropped by the merge layer) when
                                 the curated subset misses the WMI.
    * ``country``              - assembly country from the WMI pack.
    * ``region_hint``          - first-character region (always present).
    * ``vds`` / ``vis``        - Vehicle Descriptor / Indicator Sections.
    * ``year_code``            - position 10 character.
    * ``model_year_candidates``- both cycle candidates, e.g. ``[1990, 2020]``.
    * ``model_year``           - the more recent candidate (the 2010-2039
                                 cycle covers most VINs seen in the wild).
    * ``model_year_cycle``     - note explaining the 30-year ambiguity.
    * ``plant_code``           - position 11 assembly-plant character.
    * ``serial_number``        - the six-digit production serial (12-17).
    * ``check_digit``          - the character at position 9.
    * ``check_digit_valid``    - whether it matches the computed digit; a
                                 failed standalone lookup also gets the
                                 ``expected_check_digit`` it should carry.
    * ``position_map``         - dict describing every position range.
    """
    vin = _vin_text(vin_value)
    if not vin:
        return {}

    wmi = vin[:3]
    year_code = vin[9]
    older = _YEAR_CODES.get(year_code)

    out: Dict[str, Any] = {
        'wmi': wmi,
        'vds': vin[3:8],
        'vis': vin[8:],
        'region_hint': _FIRST_CHAR_REGIONS.get(vin[0]),
        'year_code': year_code,
        'plant_code': vin[10],
        'serial_number': vin[11:],
        'check_digit': vin[8],
        'check_digit_valid': vin[8] == _expected_check_digit(vin),
        'position_map': {
            '1-3': 'World Manufacturer Identifier (WMI)',
            '4-8': 'Vehicle Descriptor Section (VDS, manufacturer defined)',
            '9': 'Check digit (ISO 3779 transliteration, mod 11)',
            '10': 'Model year code (30-year cycle)',
            '11': 'Assembly plant code',
            '12-17': 'Production serial number',
        },
    }

    entry = _load_wmi_pack().get(wmi)
    if entry:
        manufacturer, country = entry
        out['manufacturer'] = manufacturer
        if country:
            out['country'] = country
    else:
        # A miss is an EXPECTED outcome for a curated subset (166 of the
        # tens of thousands of allocated WMIs): answer with an explicit
        # "no manufacturer" instead of {} so source health records the
        # execution as OK and the circuit breaker never trips on misses.
        out['manufacturer'] = None

    if older is not None:
        newer = older + 30
        out['model_year_candidates'] = [older, newer]
        out['model_year'] = newer
        out['model_year_cycle'] = (
            f"year code {year_code!r} encodes {older} or {newer} "
            f"(VIN year codes repeat on a 30-year cycle)")
    else:
        out['model_year_cycle'] = (
            f"year code {year_code!r} is not a standard model-year code")

    if not out['check_digit_valid']:
        out['expected_check_digit'] = _expected_check_digit(vin)
    return out


def _nhtsa_vpic(vin_value: Any) -> Dict[str, Any]:
    """
    NHTSA vPIC decoder (keyless): make, model and plant details.

    Endpoint: ``GET https://vpic.nhtsa.dot.gov/api/vehicles/
    DecodeVinValues/{vin}?format=json``. The response wraps one flat record
    in ``{'Results': [{...}]}``; unknown fields come back as empty strings
    which are dropped here. vPIC covers vehicles registered for the North
    American market - European or Asian domestic-market VINs answer with
    the decoder error code only, which is still reported (an honest
    "queried, nothing decoded" rather than a failure).
    """
    vin = _vin_text(vin_value)
    if not vin:
        return {}

    ok, data, _err = http.get_json(
        f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json")
    if not ok or not isinstance(data, dict):
        return {}
    results = data.get('Results')
    if not isinstance(results, list) or not results:
        return {}
    record = results[0]
    if not isinstance(record, dict):
        return {}

    out: Dict[str, Any] = {}
    for api_key, field in _VPIC_TEXT_FIELDS:
        raw = record.get(api_key)
        if not isinstance(raw, str):
            continue
        value = raw.strip()
        if value:
            out[field] = value[:_MAX_VPIC_CHARS]
    for api_key, field in _VPIC_INT_FIELDS:
        raw = str(record.get(api_key) or '').strip()
        if raw.isdigit():
            out[field] = int(raw)
    for api_key, field in _VPIC_FLOAT_FIELDS:
        raw = str(record.get(api_key) or '').strip()
        try:
            out[field] = float(raw)
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'vin_math': _vin_math,
    'nhtsa_vpic': _nhtsa_vpic,
}

# VIN vehicle intelligence is fully keyless today; the registry stays here
# so future keyed sources (e.g. commercial VIN history services) slot in
# without touching the tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'vin_math': 'Offline ISO 3779 decomposition: WMI, year code, check digit, plant',
    'nhtsa_vpic': 'NHTSA vPIC decoder: make, model, body, engine, plant (keyless)',
}


def _keep(value: Any) -> bool:
    # A VIN whose check digit failed (check_digit_valid == False) is a real
    # answer, so only None / '' / [] / {} count as "no data". The WMI pack
    # reader also uses an explicit None value as the "ran fine, nothing
    # curated" marker, which this same rule filters out of the merged fields.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(vin_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable VIN source in parallel and merge the results.

    Args:
        vin_value: 17-character VIN; hyphens, spaces and lower case are
            tolerated
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'vin'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as a VIN.
    """
    keys = keys or {}
    vin = _vin_text(vin_value)
    if not vin:
        raise ValueError(f"invalid VIN: {vin_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(vin))

    for name, fn in _plugin_sources('vin').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(vin))

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

    health.record_batch('vin', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the standards-derived math beats the online decoder on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the canonical uppercase 17-character form every consumer expects.
    merged['vin'] = vin

    return {'fields': merged, 'sources': status, 'provenance': provenance}
