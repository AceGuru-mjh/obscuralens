"""
Geo-profiling across stored lookup history (v5.0).

Every OSINT lookup the platform has ever saved carries a geographic
fingerprint: IP lookups resolve to countries, coordinate lookups carry exact
positions, domain registrations carry registrant geographies. This module
aggregates that stored history into the shapes a geo-profiling workflow
needs - without touching the network once:

* :func:`country_breakdown` - a per-country histogram of the investigation
  so far, with the contributing targets. "Which countries does this subject
  actually operate in?" is the first question a geo-profile answers.
* :func:`targets_by_country` - the inverse index: every stored IP target
  that resolved into a given country, with timestamps for chronology.
* :func:`geohash_clusters` - coordinate lookups clustered by geohash prefix
  (default precision 4, roughly 20 x 20 km cells). Two photos posted from
  "different" decimal-degree strings that share a prefix were taken in the
  same neighbourhood; clusters expose that without any map rendering.
* :func:`most_looked_up_regions` - the state / subdivision level ("which
  regions dominate this case"), across IP, coordinate and domain history.
* :func:`to_geojson` - a country breakdown rendered as a GeoJSON
  ``FeatureCollection`` of centroid points, ready to drop into Leaflet,
  mapbox-gl or deck.gl without further processing.
* :func:`geo_profile_summary` - the one-call analyst summary: distinct
  countries, top country and region, coordinate activity, cluster count and
  the day span of the geo-tagged history.

Data sources
------------
Stored query history is read the same way the correlation engine reads it
(:func:`obscuralens.correlation.history_records`), supplemented with the
``coords`` rows the correlation engine skips. Country centroids for map
pins come from the offline ``country_centroids`` data pack
(``CC|lat|lon|name`` lines). Nothing in this module raises on malformed
input: junk records, missing fields, unparseable timestamps and unknown
countries are silently skipped so an aggregate never fails mid-analysis.
"""

import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..correlation import history_records
from ..database import db
from ..utils.coordinate_math import latlon_to_geohash
from ..utils.data_packs import load_data_pack
from ..utils.geo import country_name as geo_country_name

__all__ = [
    'country_breakdown',
    'geohash_clusters',
    'geo_profile_summary',
    'most_looked_up_regions',
    'targets_by_country',
    'to_geojson',
]

#: History row cap used when records are loaded from the database.
_HISTORY_LIMIT = 800

#: Field names treated as country *names* inside stored payload info dicts.
_COUNTRY_NAME_FIELDS = ('country', 'country_name')
#: Field names treated as ISO 3166-1 alpha-2 *codes* inside payload dicts.
_COUNTRY_CODE_FIELDS = ('country_code', 'countryCode', 'country_code2')
#: Field names treated as first-order administrative regions (state level).
_REGION_FIELDS = ('state', 'region', 'region_name', 'regionName',
                  'stateProv', 'principal_subdivision')
#: Kinds whose payloads may carry a state/region field.
_REGION_KINDS = ('ip', 'coords', 'domain')

#: Maximum distinct targets echoed per aggregate entry.
_MAX_TARGETS = 5
#: Maximum distinct targets echoed per geohash cluster.
_MAX_CLUSTER_TARGETS = 10
#: Data pack name for the offline centroid table (``CC|lat|lon|name``).
_CENTROID_PACK = 'country_centroids'

#: Common geolocation spellings normalised onto centroid pack names.
_NAME_ALIASES = {
    'russian federation': 'russia',
    'republic of korea': 'south korea',
    'korea, republic of': 'south korea',
    'czech republic': 'czechia',
    'viet nam': 'vietnam',
    'turkiye': 'turkey',
    'syrian arab republic': 'syria',
    'united states of america': 'united states',
    'great britain': 'united kingdom',
    'uk': 'united kingdom',
    'uae': 'united arab emirates',
    'hong kong sar china': 'hong kong',
    'macau': 'macao',
}

#: Alternate keys a caller-supplied record may carry for the record kind.
_KIND_KEYS = ('kind', 'query_type', 'type')
#: Alternate keys a caller-supplied record may carry for the target value.
_VALUE_KEYS = ('value', 'query_value', 'target')
#: Alternate keys a caller-supplied record may carry for the payload.
_PAYLOAD_KEYS = ('payload', 'result', 'result_data')
#: Alternate keys a caller-supplied record may carry for the timestamp.
_TIME_KEYS = ('created_at', 'timestamp', 'time', 'date', 'queried_at')

#: Strings that are plain decimal numbers (epoch seconds / milliseconds).
_NUMERIC = re.compile(r'^[+-]?\d+(?:\.\d+)?$')

#: Fallback timestamp formats tried when ``datetime.fromisoformat`` fails.
_STRPTIME_FORMATS = (
    '%Y-%m-%dT%H:%M:%S%z',
    '%Y-%m-%d %H:%M:%S%z',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d',
    '%Y/%m/%d %H:%M:%S',
    '%Y/%m/%d',
    '%d %b %Y %H:%M:%S',
    '%d %b %Y',
)

#: Parsed centroid pack cache: ISO code and lowercase name -> (lat, lon).
_CENTROID_BY_CODE: Dict[str, Tuple[float, float]] = {}
_CENTROID_BY_NAME: Dict[str, Tuple[float, float]] = {}
#: Whether the centroid pack has been parsed already (load once, lazily).
_CENTROIDS_LOADED = False


# ---------------------------------------------------------------------------
# History record plumbing
# ---------------------------------------------------------------------------

def _json_payload(raw: Any) -> Dict[str, Any]:
    """
    Decode a stored result payload into a dict (never raises).

    Tracker results reach this function either as an already-decoded dict
    or as the ``result_data`` JSON string the database stores; anything
    else (None, empty, non-object JSON) yields ``{}``.
    """
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _info_of(payload: Any) -> Dict[str, Any]:
    """
    The ``info`` field mapping of a tracker payload (``{}`` for junk).

    Username-style payloads carry their fields at the top level, so the
    payload itself is returned as a fallback when no ``info`` dict exists.
    """
    if not isinstance(payload, dict):
        return {}
    info = payload.get('info')
    if isinstance(info, dict):
        return info
    return payload


def _first_text(source: Dict[str, Any], fields: Tuple[str, ...]) -> str:
    """First field in ``fields`` holding a non-empty string, stripped."""
    for field in fields:
        value = source.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ''


def _first_present(source: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
    """First key of ``keys`` present in ``source`` (None when absent)."""
    for key in keys:
        if key in source:
            return source[key]
    return None


def _normalise_records(records: Any) -> List[Dict[str, Any]]:
    """
    Coerce caller-supplied records into this module's canonical shape.

    The canonical record is ``{'kind', 'value', 'payload', 'timestamp'}``
    with ``payload`` always a decoded dict and ``timestamp`` the raw stored
    value. Correlation-engine records (``created_at`` key), raw database
    rows (``query_type`` / ``query_value`` / ``result_data`` keys) and
    API-shaped records (``result`` / ``timestamp`` keys) are all accepted;
    payloads may be dicts or JSON strings. Anything that is not a dict -
    including iterating a plain dict passed by mistake - is silently
    dropped, so a wrong-shaped argument yields ``[]`` instead of an error.
    """
    if records is None:
        return []
    try:
        candidates = list(records)
    except TypeError:
        return []
    normalised: List[Dict[str, Any]] = []
    for record in candidates:
        if not isinstance(record, dict):
            continue
        raw_payload = _first_present(record, _PAYLOAD_KEYS)
        if raw_payload is None and isinstance(record.get('info'), dict):
            raw_payload = record  # fields live inline on the record itself
        normalised.append({
            'kind': str(_first_present(record, _KIND_KEYS) or '').strip().lower(),
            'value': str(_first_present(record, _VALUE_KEYS) or '').strip(),
            'payload': _json_payload(raw_payload),
            'timestamp': _first_present(record, _TIME_KEYS),
        })
    return normalised


def _coords_rows(limit: int) -> List[Dict[str, Any]]:
    """
    Stored ``coords`` lookups as canonical records (database errors -> []).

    The correlation engine's :func:`history_records` skips the ``coords``
    kind (it extracts no entities from it), so this module owns that query
    and appends the rows in the very same record shape.
    """
    try:
        rows = db.get_history(query_type='coords', limit=limit)
    except Exception:
        return []
    records: List[Dict[str, Any]] = []
    for row in rows or []:
        records.append({
            'kind': 'coords',
            'value': str(getattr(row, 'query_value', '') or '').strip(),
            'payload': _json_payload(getattr(row, 'result_data', None)),
            'timestamp': getattr(row, 'created_at', None),
        })
    return records


def _load_records() -> List[Dict[str, Any]]:
    """
    All geo-relevant history records, newest first.

    Reuses :func:`obscuralens.correlation.history_records` (capped at
    :data:`_HISTORY_LIMIT` rows) and appends the coordinate lookups the
    correlation engine filters out. Database failures degrade to whatever
    could be read - possibly nothing - and never raise.
    """
    records: List[Dict[str, Any]] = []
    try:
        loaded = history_records(limit=_HISTORY_LIMIT)
    except Exception:
        loaded = []
    records.extend(_normalise_records(loaded or []))
    records.extend(_coords_rows(_HISTORY_LIMIT))
    return records


def _records(records: Any = None) -> List[Dict[str, Any]]:
    """
    Resolve the ``records`` argument every public function shares.

    ``None`` loads the stored history through :func:`_load_records`; any
    other value is normalised verbatim, keeping the functions pure and
    offline-testable when a caller passes its own record list.
    """
    if records is None:
        return _load_records()
    return _normalise_records(records)


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def _epoch_moment(number: float) -> Optional[datetime]:
    """
    Epoch seconds (or milliseconds, detected by magnitude) -> aware UTC.

    Values below 1e9 or beyond 1e15 seconds are not plausible lookup times
    and yield ``None``; so do NaN and non-positive numbers.
    """
    if number != number or number <= 0:  # NaN / non-positive guard
        return None
    if number >= 1e12:
        number = number / 1000.0  # millisecond precision
    if number < 1e9 or number >= 1e15:
        return None
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Parse a stored timestamp defensively into a timezone-aware datetime.

    Accepted forms: ``datetime`` objects (naive values are read as UTC),
    epoch numbers and numeric strings (seconds or milliseconds), ISO dates
    and datetimes (with ``Z`` suffix or offset, space or ``T`` separator)
    and a small set of ``dd Mon YYYY`` / slash-separated fallbacks. Values
    that match nothing return ``None``; the function never raises.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return _epoch_moment(float(value))
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if _NUMERIC.match(text):
        return _epoch_moment(float(text))
    candidate = text[:-1] + '+00:00' if text.endswith(('Z', 'z')) else text
    moment: Optional[datetime] = None
    try:
        moment = datetime.fromisoformat(candidate)
    except ValueError:
        moment = None
    if moment is None:
        for fmt in _STRPTIME_FORMATS:
            try:
                moment = datetime.strptime(text, fmt)
            except ValueError:
                continue
            break
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _timestamp_text(value: Any) -> str:
    """Render a stored timestamp as display text ('' when missing)."""
    if isinstance(value, datetime):
        try:
            return value.isoformat()
        except ValueError:  # pragma: no cover - defensive
            return str(value)
    return str(value or '')


# ---------------------------------------------------------------------------
# Country resolution
# ---------------------------------------------------------------------------

def _centroids() -> Tuple[Dict[str, Tuple[float, float]],
                          Dict[str, Tuple[float, float]]]:
    """
    Parse the centroid pack into ``(code_map, name_map)`` lookup tables.

    Pack lines are ``CC|lat|lon|name`` (``load_data_pack`` lowercases
    them); codes are re-uppercased and names stay lowercase so lookups are
    case-insensitive. A missing or malformed pack yields empty maps, which
    simply leaves GeoJSON features without geometry.
    """
    global _CENTROIDS_LOADED, _CENTROID_BY_CODE, _CENTROID_BY_NAME
    if _CENTROIDS_LOADED:
        return _CENTROID_BY_CODE, _CENTROID_BY_NAME
    by_code: Dict[str, Tuple[float, float]] = {}
    by_name: Dict[str, Tuple[float, float]] = {}
    for line in load_data_pack(_CENTROID_PACK):
        parts = line.split('|')
        if len(parts) < 4:
            continue
        try:
            point = (float(parts[1]), float(parts[2]))
        except ValueError:
            continue
        by_code[parts[0].strip().upper()] = point
        by_name[parts[3].strip().lower()] = point
    _CENTROID_BY_CODE = by_code
    _CENTROID_BY_NAME = by_name
    _CENTROIDS_LOADED = True
    return by_code, by_name


def _centroid_for(name: str, code: str) -> Optional[Tuple[float, float]]:
    """
    Approximate ``(lat, lon)`` centroid for a country name or alpha-2 code.

    The ISO code wins when present (unambiguous); the name is lowercased
    and run through the alias table first so 'Russian Federation' still
    pins 'Russia'. Unknown countries return ``None``.
    """
    by_code, by_name = _centroids()
    point = by_code.get(str(code or '').strip().upper())
    if point is None:
        key = str(name or '').strip().lower()
        point = by_name.get(_NAME_ALIASES.get(key, key))
    return point


def _country_of(record: Dict[str, Any]) -> Tuple[str, str]:
    """
    ``(country_name, country_code)`` carried by one stored record.

    IP lookups are the primary carrier (``info.country`` plus
    ``info.country_code``); coordinate reverse-geocode results and domain
    RDAP registration countries ride along through the same keys. A
    code-only record still counts: the code resolves to a display name
    through the ISO table. Empty strings when the record has no country.
    """
    info = _info_of(record.get('payload'))
    name = _first_text(info, _COUNTRY_NAME_FIELDS)
    code = _first_text(info, _COUNTRY_CODE_FIELDS)
    if code:
        code = code.strip().upper()[:2]
    if not name and code:
        name = geo_country_name(code)
    return name, code


def _number(value: Any) -> Optional[float]:
    """Finite float form of a scalar value (None for junk/bools/NaN)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _coords_of(record: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    """
    ``(latitude, longitude)`` of a stored ``coords`` record.

    The tracker always stores ``info.latitude`` / ``info.longitude``; the
    normalised ``'lat, lon'`` history value serves as fallback when the
    payload is missing or truncated. ``(None, None)`` when neither parses.
    """
    info = _info_of(record.get('payload'))
    lat = _number(info.get('latitude'))
    lon = _number(info.get('longitude'))
    if lat is not None and lon is not None:
        return lat, lon
    parts = str(record.get('value') or '').split(',')
    if len(parts) == 2:
        lat = _number(parts[0])
        lon = _number(parts[1])
        if lat is not None and lon is not None:
            return lat, lon
    return None, None


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------

def country_breakdown(records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Aggregate stored lookups into a per-country histogram.

    Every scanned record whose payload carries a country contributes - IP
    lookups are the primary source, coordinate reverse-geocode results and
    domain RDAP registration countries ride along through the same info
    fields. IP records without any resolvable country are counted under
    ``unknown``: a high unknown ratio usually means the geo sources were
    down or rate-limited when those lookups ran.

    Args:
        records: optional pre-loaded records (the output of
            ``correlation.history_records`` or any list of record-shaped
            dicts); ``None`` loads the stored history via
            ``correlation.history_records(limit=800)`` plus the coordinate
            rows that helper skips.

    Returns:
        ``{'countries': [...], 'total_geo_tagged': n, 'total_records': n,
        'unknown': n}`` where each country entry is ``{'country': name,
        'code': cc or '', 'count': n, 'targets': [up to 5 distinct values]}``
        and the list is sorted by count descending (name ascending as
        tie-break).
    """
    scanned = _records(records)
    counts: Dict[str, Dict[str, Any]] = {}
    total_geo_tagged = 0
    unknown = 0

    for record in scanned:
        name, code = _country_of(record)
        if not name:
            if record.get('kind') == 'ip':
                unknown += 1
            continue
        entry = counts.setdefault(name, {'count': 0, 'code': code, 'targets': []})
        entry['count'] += 1
        if code and not entry['code']:
            entry['code'] = code
        target = record.get('value') or ''
        if target and target not in entry['targets'] and len(entry['targets']) < _MAX_TARGETS:
            entry['targets'].append(target)
        total_geo_tagged += 1

    countries: List[Dict[str, Any]] = [
        {
            'country': name,
            'code': entry['code'],
            'count': entry['count'],
            'targets': entry['targets'],
        }
        for name, entry in counts.items()
    ]
    countries.sort(key=lambda item: (-item['count'], item['country'].lower()))
    return {
        'countries': countries,
        'total_geo_tagged': total_geo_tagged,
        'total_records': len(scanned),
        'unknown': unknown,
    }


def targets_by_country(country: str,
                       records: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """
    Every stored IP target that resolved into a given country.

    Matching is a case-insensitive substring test against both the country
    name and its ISO code, so ``'fr'``, ``'FR'`` and ``'France'`` all find
    the same rows, and ``'united'`` matches every variety of the name.

    Args:
        country: country name, fragment or alpha-2 code (empty -> []).
        records: optional pre-loaded records; ``None`` loads the stored
            history the same way :func:`country_breakdown` does.

    Returns:
        List of ``{'kind', 'value', 'timestamp'}`` dicts (newest first as
        stored); empty when nothing matches.
    """
    needle = str(country or '').strip().lower()
    if not needle:
        return []
    matches: List[Dict[str, Any]] = []
    for record in _records(records):
        if record.get('kind') != 'ip':
            continue
        name, code = _country_of(record)
        if not name and not code:
            continue
        if needle in name.lower() or (code and needle in code.lower()):
            matches.append({
                'kind': record.get('kind') or 'ip',
                'value': record.get('value') or '',
                'timestamp': _timestamp_text(record.get('timestamp')),
            })
    return matches


def geohash_clusters(records: Optional[List[Dict[str, Any]]] = None,
                     precision: int = 4) -> List[Dict[str, Any]]:
    """
    Cluster stored coordinate lookups by shared geohash prefix.

    Default precision 4 gives cells of roughly 20 x 20 km: big enough to
    collect a neighbourhood's worth of posts, small enough to separate
    boroughs. Every stored ``coords`` lookup contributes its position (the
    payload's ``latitude`` / ``longitude``, falling back to the normalised
    ``'lat, lon'`` history value), and lookups sharing a prefix form one
    cluster whose centre is the mean of its members.

    Args:
        records: optional pre-loaded records; ``None`` loads the stored
            coordinate lookups directly from the database (the correlation
            engine skips the ``coords`` kind, so this module owns it).
        precision: geohash prefix length, clamped to 1-9.

    Returns:
        List of ``{'geohash': prefix, 'count': n, 'targets': [up to 10
        distinct values], 'center': [lat, lon]}`` dicts sorted by count
        descending (geohash ascending as tie-break); ``center`` is the
        arithmetic mean of the member coordinates, rounded to 6 decimals.
    """
    try:
        width = min(9, max(1, int(precision)))
    except (TypeError, ValueError):
        width = 4
    clusters: Dict[str, Dict[str, Any]] = {}

    for record in _records(records):
        if record.get('kind') != 'coords':
            continue
        lat, lon = _coords_of(record)
        if lat is None or lon is None:
            continue
        try:
            prefix = latlon_to_geohash(lat, lon, width)
        except ValueError:
            continue  # out-of-range or non-finite position: skip it
        cluster = clusters.setdefault(
            prefix, {'count': 0, 'targets': [], 'lat_sum': 0.0, 'lon_sum': 0.0})
        cluster['count'] += 1
        cluster['lat_sum'] += lat
        cluster['lon_sum'] += lon
        target = record.get('value') or ''
        if target and target not in cluster['targets'] \
                and len(cluster['targets']) < _MAX_CLUSTER_TARGETS:
            cluster['targets'].append(target)

    result: List[Dict[str, Any]] = []
    for prefix, cluster in clusters.items():
        count = cluster['count']
        result.append({
            'geohash': prefix,
            'count': count,
            'targets': cluster['targets'],
            'center': [
                round(cluster['lat_sum'] / count, 6),
                round(cluster['lon_sum'] / count, 6),
            ],
        })
    result.sort(key=lambda item: (-item['count'], item['geohash']))
    return result


def most_looked_up_regions(records: Optional[List[Dict[str, Any]]] = None,
                           limit: int = 10) -> List[Dict[str, Any]]:
    """
    Most frequently seen first-order regions (state / subdivision level).

    Scans IP, coordinate and domain lookups for region-ish info fields
    (``state``, ``region``, ``region_name``, ...): IP geo results and
    coordinate reverse-geocode results both fill them. Each entry carries
    the country when known, the lookup count and up to five contributing
    targets - "Île-de-France dominates this case" in one call.

    Args:
        records: optional pre-loaded records; ``None`` loads the stored
            history the same way :func:`country_breakdown` does.
        limit: maximum entries returned (clamped to >= 1).

    Returns:
        List of ``{'region', 'country', 'count', 'targets'}`` dicts,
        biggest first (region name ascending as tie-break); empty when no
        stored payload carries a region.
    """
    try:
        cap = max(1, int(limit))
    except (TypeError, ValueError):
        cap = 10
    counts: Dict[str, Dict[str, Any]] = {}

    for record in _records(records):
        if record.get('kind') not in _REGION_KINDS:
            continue
        info = _info_of(record.get('payload'))
        region = _first_text(info, _REGION_FIELDS)
        if not region:
            continue
        name, _code = _country_of(record)
        entry = counts.setdefault(region, {'count': 0, 'country': name, 'targets': []})
        entry['count'] += 1
        if name and not entry['country']:
            entry['country'] = name
        target = record.get('value') or ''
        if target and target not in entry['targets'] and len(entry['targets']) < _MAX_TARGETS:
            entry['targets'].append(target)

    ranked: List[Dict[str, Any]] = [
        {
            'region': region,
            'country': entry['country'],
            'count': entry['count'],
            'targets': entry['targets'],
        }
        for region, entry in counts.items()
    ]
    ranked.sort(key=lambda item: (-item['count'], item['region'].lower()))
    return ranked[:cap]


def to_geojson(breakdown: Dict[str, Any]) -> Dict[str, Any]:
    """
    Render a :func:`country_breakdown` result as a GeoJSON FeatureCollection.

    Each country becomes one ``Point`` feature at its approximate centroid
    from the ``country_centroids`` pack (code lookup first, name with alias
    normalisation second). Coordinates follow GeoJSON's ``[lon, lat]``
    order so the collection drops straight into Leaflet / mapbox-gl /
    deck.gl. Countries without a resolvable centroid keep their feature
    with a ``null`` geometry rather than being dropped, keeping counts
    honest on the map.

    Args:
        breakdown: the dict returned by :func:`country_breakdown` (any dict
            with a ``'countries'`` list; unknown shapes yield an empty
            collection).

    Returns:
        ``{'type': 'FeatureCollection', 'features': [...]}`` with feature
        properties ``country``, ``count`` and ``targets``.
    """
    features: List[Dict[str, Any]] = []
    countries: Any = []
    if isinstance(breakdown, dict) and isinstance(breakdown.get('countries'), list):
        countries = breakdown['countries']

    for entry in countries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get('country') or '')
        code = str(entry.get('code') or '')
        targets = entry.get('targets')
        if not isinstance(targets, list):
            targets = []
        point = _centroid_for(name, code)
        geometry: Optional[Dict[str, Any]] = None
        if point is not None:
            geometry = {'type': 'Point', 'coordinates': [point[1], point[0]]}
        features.append({
            'type': 'Feature',
            'geometry': geometry,
            'properties': {
                'country': name,
                'count': entry.get('count', 0),
                'targets': targets,
            },
        })
    return {'type': 'FeatureCollection', 'features': features}


def geo_profile_summary(records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    One-call analyst summary of the geographic footprint in stored history.

    Combines the other aggregates into the single dict a dashboard or an
    API endpoint wants: how many distinct countries the investigation
    touches, which country and region dominate, how much coordinate
    activity exists, how many geohash clusters it forms, and over how many
    days that history spans. Timestamps are parsed defensively (epoch
    seconds/milliseconds, ISO forms and a few fallback formats); records
    without a usable timestamp simply do not contribute to the span.

    Args:
        records: optional pre-loaded records; ``None`` loads the stored
            history the same way :func:`country_breakdown` does.

    Returns:
        ``{'distinct_countries': n, 'top_country': {...} or None,
        'top_region': {...} or None, 'coords_lookups': n,
        'geohash_clusters': n, 'span_days': float or None}`` where
        ``top_country`` / ``top_region`` reuse the entry shapes of
        :func:`country_breakdown` / :func:`most_looked_up_regions` and
        ``span_days`` is the day difference between the oldest and newest
        parsed timestamps (None when fewer than two parse).
    """
    scanned = _records(records)
    breakdown = country_breakdown(scanned)
    regions = most_looked_up_regions(scanned, limit=1)
    clusters = geohash_clusters(scanned)

    moments: List[datetime] = []
    for record in scanned:
        moment = _parse_timestamp(record.get('timestamp'))
        if moment is not None:
            moments.append(moment)
    span_days: Optional[float] = None
    if len(moments) >= 2:
        span_days = round(
            (max(moments) - min(moments)).total_seconds() / 86400.0, 2)

    countries = breakdown['countries']
    return {
        'distinct_countries': len(countries),
        'top_country': countries[0] if countries else None,
        'top_region': regions[0] if regions else None,
        'coords_lookups': sum(1 for record in scanned if record.get('kind') == 'coords'),
        'geohash_clusters': len(clusters),
        'span_days': span_days,
    }
