"""
License plate intelligence sources (v6.0, fully offline).

A plate value answers "which jurisdiction issued this plate and what does
its format say": free-form vehicle-registration text, optionally prefixed
with the issuing country (``DE:B-AB 1234``, ``GB:AB12 CDE``,
``US-CA:8ABC123``). Plate grammars vary per country - and per state or city
inside a country - so this module never claims a country outright; it
matches the text against a curated pack of national formats and reports
every jurisdiction whose pattern fits, with a confidence per match. Both
sources are offline:

* ``plate_pack`` - the shipped ``obscuralens/data/plate_formats.txt`` pack
                   (79 curated ``country|region|series|example|notes``
                   entries): parses the country prefix, matches the plate
                   body against every candidate pattern (loose regexes
                   derived from each entry's example: A-Z letters become
                   ``[A-Z]``, digits become ``\\d`` and separators become
                   optional), and reports the matched countries with
                   region, example and confidence - prefixed input scores
                   high, unprefixed heuristics score lower.
* ``plate_math`` - pure-Python character composition analysis: letter and
                   digit counts, separator positions and length; the
                   German city-code special case (a leading ``DE:`` city
                   token resolves against a 40-entry table hardcoded here
                   - B Berlin, M Munich, S Stuttgart, ...); and an
                   EU-style vs North-American-style heuristic (leading
                   regional letter block + separator vs compact
                   alphanumeric).

Every reader is offline, so a report always succeeds for a well-formed
plate and never touches the network. Results are merged field-by-field
with provenance tracked: ``gather_all`` returns which source supplied each
value, so a report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..health import health
from ..utils.data_packs import DATA_DIR
from ..utils.helpers import fanout_workers
from ..utils.validators import normalize_plate, split_plate

#: How many matched-country candidates a single plate reports (some shapes,
#: like three letters + four digits, fit half a dozen US states at once).
_MAX_MATCHES = 8

#: Parsed plate pack cache: list of entries plus a country index.
#: ``None`` means "not loaded yet"; a tuple (possibly empty) is the cache.
_PLATE_CACHE: Optional[Tuple[List[Dict[str, str]], Dict[str, List[Dict[str, str]]]]] = None

#: German distinguishing-sign city codes (the one-letter and two-letter
#: codes an analyst meets on German plates), hardcoded because the city
#: registry is stable knowledge, not curated data that grows. The pack
#: carries a subset of these as per-city format rows; this table resolves
#: any other German city code too.
_GERMAN_CITY_CODES: Dict[str, str] = {
    'B': 'Berlin', 'M': 'Munich (Muenchen)', 'S': 'Stuttgart',
    'HH': 'Hamburg', 'F': 'Frankfurt am Main', 'K': 'Cologne (Koeln)',
    'D': 'Duesseldorf', 'C': 'Chemnitz', 'E': 'Essen', 'H': 'Hannover',
    'L': 'Leipzig', 'N': 'Nuremberg (Nuernberg)', 'A': 'Augsburg',
    'BN': 'Bonn', 'BO': 'Bochum', 'BR': 'Bremen (alternative)',
    'DD': 'Dresden', 'DO': 'Dortmund', 'DU': 'Duisburg',
    'EF': 'Erfurt', 'ER': 'Erlangen', 'G': 'Gera', 'GE': 'Gelsenkirchen',
    'GI': 'Giessen', 'HAL': 'Halle', 'HAM': 'Hamm',
    'HB': 'Bremen', 'HI': 'Hildesheim', 'HL': 'Luebeck',
    'HN': 'Heilbronn', 'HO': 'Hof', 'J': 'Jena', 'KI': 'Kiel',
    'KL': 'Kaiserslautern', 'KS': 'Kassel', 'LU': 'Ludwigshafen',
    'MA': 'Mannheim', 'MD': 'Magdeburg', 'MG': 'Moenchengladbach',
    'MK': 'Maerkischer Kreis', 'MS': 'Muenster', 'NB': 'Neubrandenburg',
    'NE': 'Neuss', 'OB': 'Oberhausen', 'OLD': 'Oldenburg',
    'OS': 'Osnabrueck', 'PB': 'Paderborn', 'PS': 'Pirmasens',
    'R': 'Regensburg', 'RE': 'Recklinghausen', 'RO': 'Rosenheim',
    'SB': 'Saarbruecken', 'SI': 'Siegen', 'SN': 'Schwerin',
    'T': 'Trier', 'UL': 'Ulm', 'W': 'Wuppertal', 'WOB': 'Wolfsburg',
    'WR': 'Wernigerode', 'WUE': 'Wuerzburg', 'ZI': 'Zwickau',
}

#: Confidence scored into each matched-country candidate: a country prefix
#: plus a pattern hit is strong evidence; a pattern hit alone is a weaker
#: heuristic; a known country whose patterns all missed is a fallback.
_CONFIDENCE_PREFIXED = 0.9
_CONFIDENCE_PATTERN = 0.5
_CONFIDENCE_COUNTRY_ONLY = 0.4

#: Country codes whose plates carry a leading regional letter block
#: followed by a separator - the "EU style" heuristic family.
_EU_STYLE_COUNTRIES = frozenset((
    'DE', 'AT', 'CH', 'FR', 'IT', 'ES', 'NL', 'BE', 'PL', 'CZ', 'HU',
    'RO', 'BG', 'SI', 'SK', 'HR', 'RS', 'UA', 'DK', 'NO', 'SE',
))


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _plate_text(value: Any) -> str:
    """
    Coerce ``'de:b-ab  1234'``, a lower-case plate or a bare value into the
    canonical upper-case, space-collapsed form; ``''`` when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_plate(str(value or ''))


def _loose_regex(example: str) -> 're.Pattern[str]':
    """
    Turn a pack example into the loose matcher regex for its series.

    ASCII letters become ``[A-Z]`` (the pack stores uppercase examples),
    digits become ``\\d``, spaces and hyphens become an optional ``[ -]?``
    (plates are typed with either separator, or none), and every other
    character - dots, middle dots, CJK province characters, hangul class
    characters - stays literal. ``B-AB 1234`` therefore matches
    ``B-AB 1234``, ``B AB 1234`` and ``BAB 1234`` alike.
    """
    parts: List[str] = []
    for char in example:
        if char.isascii() and char.isalpha():
            parts.append('[A-Z]')
        elif char.isdigit():
            parts.append(r'\d')
        elif char in ' -':
            parts.append('[ -]?')
        else:
            parts.append(re.escape(char))
    return re.compile('^' + ''.join(parts) + '$')


def _load_plate_pack() -> Tuple[List[Dict[str, str]], Dict[str, List[Dict[str, str]]]]:
    """
    Parse the shipped plate format pack into ``(entries, by_country)``.

    The pack is a plain-text file at ``obscuralens/data/plate_formats.txt``
    with one ``country|region|series|example|notes`` entry per line,
    ``#``-comments and blank lines ignored. The series column carries the
    entry's pattern flag: ``M`` = current main series, ``O`` = obsolete /
    historical series, ``S`` = special series (the loose matcher derives
    its regex from the example column, which spells the shape with real
    slot characters). Entries are parsed directly (not via
    ``load_data_pack``) because notes are case-sensitive prose, and cached
    at module level for the process lifetime. A missing or unreadable pack
    yields empty structures without raising and without caching, so a later
    call can retry after the file is fixed.
    """
    global _PLATE_CACHE
    if _PLATE_CACHE is not None:
        return _PLATE_CACHE

    entries: List[Dict[str, str]] = []
    by_country: Dict[str, List[Dict[str, str]]] = {}
    path: Path = DATA_DIR / 'plate_formats.txt'
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, ValueError):  # OSError + UnicodeDecodeError
        return entries, by_country

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split('|')
        if len(parts) != 5:
            continue
        country = parts[0].strip().upper()
        region = parts[1].strip()
        series = parts[2].strip().upper() or 'M'
        example = parts[3].strip()
        notes = parts[4].strip()
        if not country or not example:
            continue
        if series not in ('M', 'O', 'S'):
            series = 'M'
        entry = {'country': country, 'region': region, 'series': series,
                 'example': example, 'notes': notes}
        entries.append(entry)
        by_country.setdefault(country, []).append(entry)
    _PLATE_CACHE = (entries, by_country)
    return entries, by_country


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _plate_pack(plate_value: Any) -> Dict[str, Any]:
    """
    Offline curated plate format pack: the matched jurisdictions.

    Parses the country prefix first. With a prefix, only that country's
    entries are tried (a hit scores ``0.9``; a known country whose patterns
    all missed still reports its first entry at ``0.4`` so the analyst sees
    which jurisdiction was claimed). Without a prefix, every entry's loose
    regex runs against the whole text and each hit scores ``0.5`` - three
    letters + four digits fits several US states at once, so the result is
    a candidate list, never a verdict.

    Fields:

    * ``normalized``        - the upper-case, space-collapsed plate text.
    * ``matched_countries`` - up to 8 ``{'country', 'region', 'example',
                              'confidence'}`` candidates, best first.
    * ``matched_count``     - how many jurisdictions matched.
    * ``country_prefix``    - the parsed prefix, when one was present.
    * ``country_known``     - whether the prefix exists in the pack.
    * ``match_note``        - one sentence explaining the matching outcome.
    """
    plate = _plate_text(plate_value)
    if not plate:
        return {}

    parts = split_plate(plate)
    if parts is None:
        return {}
    prefix, body = parts
    entries, by_country = _load_plate_pack()

    out: Dict[str, Any] = {'normalized': plate}
    matched: List[Dict[str, Any]] = []

    if prefix:
        out['country_prefix'] = prefix
        candidates = by_country.get(prefix) or []
        out['country_known'] = bool(candidates)
        for entry in candidates:
            if _loose_regex(entry['example']).match(body):
                matched.append({
                    'country': entry['country'],
                    'region': entry['region'],
                    'example': entry['example'],
                    'confidence': _CONFIDENCE_PREFIXED,
                })
        if not matched and candidates:
            # The prefix names a real jurisdiction but none of its curated
            # patterns fit - a newer/older series or a typo'd body. Report
            # the claimed country at low confidence instead of nothing.
            first = candidates[0]
            matched.append({
                'country': first['country'],
                'region': first['region'],
                'example': first['example'],
                'confidence': _CONFIDENCE_COUNTRY_ONLY,
            })
            out['match_note'] = (
                f"country prefix {prefix} recognised but no curated pattern "
                f"matched the body; format may be a parallel series")
        elif matched:
            out['match_note'] = (
                f"country prefix {prefix} recognised and the body matches "
                f"{len(matched)} curated pattern(s)")
        else:
            out['match_note'] = (
                f"country prefix {prefix} is not in the curated pack; "
                f"the plate body was not pattern-matched")
    else:
        for entry in entries:
            if _loose_regex(entry['example']).match(body):
                matched.append({
                    'country': entry['country'],
                    'region': entry['region'],
                    'example': entry['example'],
                    'confidence': _CONFIDENCE_PATTERN,
                })
        out['match_note'] = (
            "no country prefix: matched by loose pattern only "
            "(weaker evidence - several jurisdictions share common shapes)"
            if matched else
            "no country prefix and no curated pattern matched")

    # Best confidence first; stable pack order for equal scores.
    matched.sort(key=lambda m: -m['confidence'])
    matched = matched[:_MAX_MATCHES]
    out['matched_countries'] = matched
    out['matched_count'] = len(matched)
    return out


def _plate_math(plate_value: Any) -> Dict[str, Any]:
    """
    Pure-Python character composition analysis - the always-available half.

    Derives everything the plate text itself encodes:

    * ``length`` / ``letters_count`` / ``digits_count`` - character census.
    * ``separators``          - which separator characters appear.
    * ``composition_note``    - one sentence describing the composition.
    * ``german_city`` / ``german_city_code`` - only for a ``DE:`` prefix
      whose leading token resolves in the hardcoded 40-entry city table
      (B Berlin, M Munich, S Stuttgart, HH Hamburg, ...).
    * ``style_hint``          - EU-style (leading regional letter block +
      separator) vs North-American-style (compact alphanumeric) heuristic,
      derived from the composition and, when present, a European country
      prefix.
    """
    plate = _plate_text(plate_value)
    if not plate:
        return {}

    parts = split_plate(plate)
    if parts is None:
        return {}
    prefix, body = parts

    letters = sum(1 for ch in body if ch.isascii() and ch.isalpha())
    digits = sum(1 for ch in body if ch.isdigit())
    separators = ''.join(sorted({ch for ch in body if not ch.isalnum()}))

    out: Dict[str, Any] = {
        'length': len(body),
        'letters_count': letters,
        'digits_count': digits,
    }
    if separators:
        out['separators'] = separators
    out['composition_note'] = (
        f"{letters} letter(s), {digits} digit(s), length {len(body)}"
        + (f", separators {separators!r}" if separators else ", no separators"))

    # German city code: only meaningful with the DE: prefix. The leading
    # token (up to the first separator) is the distinguishing sign.
    if prefix == 'DE':
        leading = re.split(r'[ -]', body, maxsplit=1)[0]
        city = _GERMAN_CITY_CODES.get(leading.upper())
        if city:
            out['german_city_code'] = leading.upper()
            out['german_city'] = city

    # EU vs North American heuristic: EU-style plates lead with a regional
    # letter block followed by a separator; North American plates are
    # compact alphanumerics without a leading regional block.
    leading_alpha = bool(re.match(r'^[A-Z]{1,3}[ -]', body))
    if prefix in _EU_STYLE_COUNTRIES or leading_alpha:
        out['style_hint'] = (
            'EU-style plate (regional letter block + separator + body); '
            'country attribution needs the format pack match')
    elif separators and re.match(r'^\d', body):
        out['style_hint'] = (
            'digit-leading plate with separators; many European and Asian '
            'numbering plans use this order')
    else:
        out['style_hint'] = (
            'North-American-style plate (compact alphanumeric, no leading '
            'regional block) or non-latin script; a heuristic only')
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'plate_pack': _plate_pack,
    'plate_math': _plate_math,
}

# Plate intelligence is deliberately fully offline: national registries are
# paywalled or gated behind lawful-purpose attestation everywhere, so no
# keyed source is registered (the registry stays here so a future licensed
# source slots in without touching the tracker or the CLI).
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'plate_pack': ('Offline curated plate format pack '
                   '(obscuralens/data/plate_formats.txt): matched countries'),
    'plate_math': ('Offline composition analysis: letters/digits, German '
                   'city code, EU vs North American heuristic'),
}


def _keep(value: Any) -> bool:
    # A plate that matched zero countries (matched_count == 0) is a real
    # answer, so only None / '' / [] / {} count as "no data". Readers also
    # use explicit None values as the "ran fine, nothing found" marker,
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


def gather_all(plate_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every plate source in parallel and merge the results.

    Args:
        plate_value: license plate text, optionally prefixed with the
            issuing country (``'DE:B-AB 1234'``, ``'GB:AB12 CDE'``,
            ``'US-CA:8ABC123'``); lower case and doubled spaces are
            tolerated
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'plate'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not pass the plate gate.
    """
    keys = keys or {}
    plate = _plate_text(plate_value)
    if not plate:
        raise ValueError(f"invalid license plate: {plate_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(plate))

    for name, fn in _plugin_sources('plate').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(plate))

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

    health.record_batch('plate', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the curated format pack beats the composition math on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the canonical upper-case, space-collapsed form every consumer expects.
    merged['plate'] = plate

    return {'fields': merged, 'sources': status, 'provenance': provenance}
