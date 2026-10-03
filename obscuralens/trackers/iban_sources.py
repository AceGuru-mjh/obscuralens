"""
IBAN (International Bank Account Number) intelligence sources.

An IBAN answers "which bank holds this account": the ISO 13616 mod-97
checksum guards the identifier, the country prefix selects a published
per-country BBAN structure, and the front of the BBAN identifies the bank.
This module mixes two offline sources and one keyless online API:

* ``iban_math``          - pure-Python ISO 13616 arithmetic: mod-97 checksum
                           verdict, country prefix, check digits, BBAN,
                           length, the spaced pretty format (groups of four)
                           and a masked account hint safe for reports.
* ``iban_structure_pack``- offline per-country structure pack shipped at
                           ``obscuralens/data/iban_structures.txt`` (124
                           registry entries, ``CC|length|bank_code_len|
                           account_len|country_name``): country name,
                           expected length, ``structure_ok`` verdict and the
                           bank-code / account-number BBAN slices.
* ``openiban``           - openiban.com keyless validation API
                           (``GET /validate/<IBAN>?getBIC=true``): bank
                           code, bank name, BIC and country, cross-checking
                           the offline verdict (must fail gracefully when
                           unreachable - the offline sources carry the day).

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
from ..utils.http_client import http
from ..utils.validators import normalize_iban, validate_iban

#: Characters of the BBAN tail kept visible in the masked account hint; the
#: country prefix and check digits stay clear so the mask stays identifiable.
_MASK_TAIL = 4

#: Bank names / BIC strings capped for report sanity.
_MAX_BANK_CHARS = 160

#: Parsed IBAN structure pack cache: country code -> registry tuple.
#: ``None`` means "not loaded yet"; a dict (possibly empty) is the cache.
_IBAN_CACHE: Optional[Dict[str, Tuple[int, int, int, str]]] = None


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _iban_text(value: Any) -> str:
    """
    Coerce ``'DE89 3704 0044 0532 0130 00'``, ``'iban:de89...'`` or a bare
    IBAN into the canonical uppercase space-free form; ``''`` when the shape
    is wrong.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_iban(str(value or ''))


def _load_iban_pack() -> Dict[str, Tuple[int, int, int, str]]:
    """
    Parse the shipped IBAN structure pack into a per-country map.

    The pack is a plain-text file at ``obscuralens/data/iban_structures.txt``
    with one ``CC|length|bank_code_len|account_len|country_name`` entry per
    line, ``#``-comments and blank lines ignored, compiled from the SWIFT /
    php-iban ISO 13616 registry mirror (124 country structures). It is
    parsed directly (not via ``load_data_pack``) because country names are
    case-sensitive - "Côte d'Ivoire" and "Åland Islands" must survive - and
    cached at module level for the process lifetime. A missing or unreadable
    pack yields an empty dict without raising and without caching, so a
    later call can retry after the file is fixed.
    """
    global _IBAN_CACHE
    if _IBAN_CACHE is not None:
        return _IBAN_CACHE

    entries: Dict[str, Tuple[int, int, int, str]] = {}
    path: Path = DATA_DIR / 'iban_structures.txt'
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, ValueError):  # OSError + UnicodeDecodeError
        return entries

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split('|')
        if len(parts) != 5:
            continue
        code = parts[0].strip().upper()
        name = parts[4].strip()
        try:
            length = int(parts[1])
            bank_len = int(parts[2])
            account_len = int(parts[3])
        except ValueError:
            continue
        if len(code) == 2 and code.isalpha() and name and length >= 5:
            entries.setdefault(code, (length, bank_len, account_len, name))
    _IBAN_CACHE = entries
    return entries


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _iban_math(iban_value: Any) -> Dict[str, Any]:
    """
    Pure-Python ISO 13616 arithmetic - the always-available offline half.

    Derives everything the identifier itself encodes, for any syntactically
    well-formed IBAN (no registry needed):

    * ``country_code``  - the two-letter ISO 3166-1 prefix.
    * ``check_digits``  - the two modulo-97 guard digits.
    * ``bban``          - the Basic Bank Account Number after the prefix.
    * ``length``        - total character count.
    * ``checksum_valid``- the mod-97 verdict (recomputed here even though
                          the tracker pre-validates, so standalone calls
                          get a real answer for typo'd input too).
    * ``formatted``     - the spaced pretty print form, groups of four:
                          ``'DE89 3704 0044 0532 0130 00'``.
    * ``masked_iban``   - report-safe hint keeping the country prefix, the
                          check digits and the last four BBAN characters
                          visible: ``'DE89**************3000'``.
    """
    iban = _iban_text(iban_value)
    if not iban:
        return {}

    checksum_valid, _reason = validate_iban(iban)
    tail = iban[-_MASK_TAIL:]
    hidden = max(len(iban) - 4 - _MASK_TAIL, 0)
    return {
        'country_code': iban[:2],
        'check_digits': iban[2:4],
        'bban': iban[4:],
        'length': len(iban),
        'checksum_valid': checksum_valid,
        'formatted': ' '.join(iban[i:i + 4] for i in range(0, len(iban), 4)),
        'masked_iban': f"{iban[:4]}{'*' * hidden}{tail}",
    }


def _iban_structure_pack(iban_value: Any) -> Dict[str, Any]:
    """
    Offline per-country ISO 13616 structure pack lookup.

    The pack maps every IBAN country to its registry structure - expected
    total length, bank-identifier slice length, remaining account length and
    the country name - for all 124 published structures including the French
    territorial IBANs and the West/Central African states. From it:

    * ``country_name``     - English country name for the prefix.
    * ``expected_length``  - registry length for the country.
    * ``structure_ok``     - whether the actual length matches the registry
                             (a well-checksummed IBAN of the wrong length
                             is a strong tamper signal).
    * ``bank_code``        - BBAN characters that identify the bank (flat
                             BBAN countries with ``bank_code_len == 0``
                             report no bank code, by design).
    * ``account_number``   - the remaining BBAN characters.
    """
    iban = _iban_text(iban_value)
    if not iban:
        return {}

    entry = _load_iban_pack().get(iban[:2])
    if not entry:
        # The registry subset covers every published IBAN country, so a miss
        # means an exotic / not-yet-registered prefix rather than a pack
        # failure: answer with an explicit "no country name" instead of {}
        # so source health records the execution as OK and the circuit
        # breaker never trips. The merge layer drops None values, so no
        # country fields appear.
        return {'country_name': None}

    length, bank_len, account_len, country_name = entry
    bban = iban[4:]
    out: Dict[str, Any] = {
        'country_name': country_name,
        'expected_length': length,
        'structure_ok': len(iban) == length,
    }
    if bank_len > 0:
        out['bank_code'] = bban[:bank_len]
    if account_len > 0:
        out['account_number'] = bban[bank_len:bank_len + account_len]
    return out


def _openiban(iban_value: Any) -> Dict[str, Any]:
    """
    openiban.com (keyless): online validation with BIC resolution.

    Endpoint: ``GET https://openiban.com/validate/<IBAN>?getBIC=true``.
    Valid accounts answer ``{"valid": true, "bankCode": ..., "bankName":
    ..., "bic": ..., "country": ...}``; an invalid answer (or any transport
    failure - the service is often unreachable) is a clean "no data" so the
    offline sources still carry the report. The offline pack already
    supplies ``bank_code`` / ``country_code``, so this source's unique
    contributions are ``bank_name`` and ``bic``.
    """
    iban = _iban_text(iban_value)
    if not iban:
        return {}

    ok, data, _err = http.get_json(
        f"https://openiban.com/validate/{iban}?getBIC=true")
    if not ok or not isinstance(data, dict):
        return {}
    if not data.get('valid'):
        return {}

    out: Dict[str, Any] = {}
    bank_code = str(data.get('bankCode') or '').strip()
    if bank_code:
        out['bank_code'] = bank_code[:_MAX_BANK_CHARS]
    bank_name = str(data.get('bankName') or '').strip()
    if bank_name:
        out['bank_name'] = bank_name[:_MAX_BANK_CHARS]
    bic = str(data.get('bic') or '').strip()
    if bic:
        out['bic'] = bic[:_MAX_BANK_CHARS]
    country = str(data.get('country') or '').strip().upper()
    if country:
        out['country_code'] = country
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'iban_math': _iban_math,
    'iban_structure_pack': _iban_structure_pack,
    'openiban': _openiban,
}

# IBAN intelligence is fully keyless today; the registry stays here so
# future keyed sources (e.g. paid SEPA name-check APIs) slot in without
# touching the tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'iban_math': 'Offline ISO 13616 mod-97 checksum, pretty format and masked account hint',
    'iban_structure_pack': 'Offline per-country IBAN structure pack (obscuralens/data/'
                           'iban_structures.txt): bank code and country',
    'openiban': 'openiban.com online validation with BIC resolution (keyless)',
}


def _keep(value: Any) -> bool:
    # An IBAN whose registry length mismatches (structure_ok == False) is a
    # real answer, so only None / '' / [] / {} count as "no data". Pack
    # readers also use an explicit None value as the "ran fine, nothing
    # curated" marker, which this same rule filters out of the merged
    # fields.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(iban_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable IBAN source in parallel and merge the results.

    Args:
        iban_value: IBAN such as ``'DE89370400440532013000'`` or the spaced
            printed form; lowercase input and a leading ``'iban:'`` marker
            are tolerated
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'iban'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as an IBAN shape.
            (The mod-97 checksum itself is a reported verdict, not a gate -
            the tracker decides whether to reject failed checksums.)
    """
    keys = keys or {}
    iban = _iban_text(iban_value)
    if not iban:
        raise ValueError(f"invalid IBAN: {iban_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(iban))

    for name, fn in _plugin_sources('iban').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(iban))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=min(len(tasks), 12)) as ex:
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

    health.record_batch('iban', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the standards-derived math beats pack data beats online mirrors.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the canonical uppercase space-free form every consumer expects.
    merged['iban'] = iban

    return {'fields': merged, 'sources': status, 'provenance': provenance}
