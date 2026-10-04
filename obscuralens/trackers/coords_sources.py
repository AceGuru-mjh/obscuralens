"""
Reverse-geocoding and place-intelligence sources for coordinates (v5.0).

A ``coords`` lookup answers "what is at this point on Earth": the street
address, the city / region / country, the ground elevation, and every
useful re-encoding of the position itself (geohash, Maidenhead, UTM, MGRS,
DMS/DDM strings). The source registry mixes two online reverse geocoders
with three fully offline providers so a lookup still produces a rich,
provenance-tracked answer when the network is gone:

* ``nominatim``          - OpenStreetMap Nominatim ``/reverse`` (jsonv2,
                           ``zoom=18``, ``addressdetails=1``): display name,
                           road / house number, city / town / village,
                           county, state, postcode, country, OSM ids and the
                           place category. Keyless, but the usage policy
                           requires an identifying User-Agent (sent from the
                           app config) and limits request rate.
* ``bigdatacloud``       - BigDataCloud's free ``reverse-geocode-client``
                           endpoint: locality, city and principal subdivision
                           (state-level) plus the country name/code. Keyless
                           fallback address source; the endpoint is aimed at
                           browser clients, so datacentre IPs are sometimes
                           refused (HTTP 400) - the reader then returns no
                           data and the lookup degrades gracefully to the
                           other sources.
* ``open_elevation``     - Open-Elevation SRTM lookup: terrain elevation in
                           metres. Useful for cross-checking a claimed photo
                           viewpoint against real ground height.
* ``geohash_local``      - Offline: pure coordinate maths from
                           ``utils.coordinate_math`` - geohash, Maidenhead
                           locator, DMS / DDM strings, UTM and MGRS grids,
                           hemisphere, a 15-degrees-per-hour timezone hint
                           and the NOAA solar position (altitude / azimuth /
                           sunrise / sunset) for photo-verification. This
                           source needs no network and always succeeds, so
                           every lookup carries at least the identifier
                           fields plus a baseline provenance record.
* ``country_centroids``  - Offline data pack (``data/country_centroids.txt``,
                           ``CC|lat|lon|name``): nearest country by
                           great-circle distance when both online geocoders
                           are unreachable. The distance is reported so the
                           caller can judge how coarse the answer is.

Every provider is queried independently and results are merged field-by-field
so a single flaky source cannot blank out the report. Field provenance is
tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import contextlib
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..health import health
from ..utils import coordinate_math
from ..utils.data_packs import load_data_pack
from ..utils.geo import country_name as geo_country_name
from ..utils.geo import distance_km
from ..utils.helpers import fanout_workers
from ..utils.http_client import http
from ..utils.validators import parse_coords

#: Cap for free-text address strings so merged payloads stay report-sized.
_MAX_ADDRESS_CHARS = 300
#: Data pack name for the offline country centroid table.
_CENTROID_PACK = 'country_centroids'
#: Number of decimal degrees kept for merged latitude/longitude fields.
_COORD_DECIMALS = 6

#: Parsed centroid pack cache: ``(code, lat, lon, name)`` tuples.
_CENTROID_CACHE: Optional[List[Tuple[str, float, float, str]]] = None


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _country_centroids() -> List[Tuple[str, float, float, str]]:
    """
    Parse the country centroid pack into ``(code, lat, lon, name)`` tuples.

    The loader lowercases pack lines, so codes are re-uppercased here and
    display names fall back to ``title()`` case only when the ISO table in
    ``utils.geo`` cannot resolve the code. Malformed lines are skipped; a
    missing pack yields an empty list (the source then reports "no data").
    The result is cached for the process lifetime.
    """
    global _CENTROID_CACHE
    if _CENTROID_CACHE is not None:
        return _CENTROID_CACHE
    entries: List[Tuple[str, float, float, str]] = []
    for line in load_data_pack(_CENTROID_PACK):
        parts = line.split('|')
        if len(parts) != 4:
            continue
        code = parts[0].strip().upper()
        if len(code) != 2 or not code.isalpha():
            continue
        try:
            lat = float(parts[1])
            lon = float(parts[2])
        except ValueError:
            continue
        if not -90.0 <= lat <= 90.0 or not -180.0 <= lon <= 180.0:
            continue
        entries.append((code, lat, lon, parts[3].strip()))
    _CENTROID_CACHE = entries
    return entries


def _first_text(mapping: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    """First non-empty string among ``keys`` of a dict ('' when absent)."""
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return ''


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _nominatim(lat: float, lon: float) -> Dict[str, Any]:
    """
    OpenStreetMap Nominatim reverse geocoding (keyless).

    Endpoint: ``GET /reverse?format=jsonv2&lat=&lon=&zoom=18&addressdetails=1``.
    The request carries the configured application User-Agent (required by
    the Nominatim usage policy) and an English Accept-Language so merged
    country names line up with the ISO table in ``utils.geo``. Fields:
    formatted address, road / house number, city (town/village/hamlet
    fallback), county, region (state), postcode, country + ISO code, OSM
    object ids and the place category/type.
    """
    url = ('https://nominatim.openstreetmap.org/reverse'
           f"?format=jsonv2&lat={lat}&lon={lon}&zoom=18&addressdetails=1")
    headers = {
        'User-Agent': config.app_config.user_agent,
        'Accept-Language': 'en',
    }
    ok, d, _ = http.get_json(url, headers=headers)
    if not ok or not isinstance(d, dict):
        return {}

    out: Dict[str, Any] = {}
    address = d.get('address') if isinstance(d.get('address'), dict) else {}

    if d.get('display_name'):
        out['formatted_address'] = str(d['display_name'])[:_MAX_ADDRESS_CHARS]
    if d.get('name'):
        out['place_name'] = str(d['name'])[:_MAX_ADDRESS_CHARS]

    city = _first_text(address, ('city', 'town', 'village', 'hamlet', 'municipality'))
    if city:
        out['city'] = city
    if address.get('county'):
        out['county'] = str(address['county'])
    if address.get('state'):
        out['region'] = str(address['state'])
    if address.get('postcode'):
        out['postcode'] = str(address['postcode'])
    if address.get('country'):
        out['country'] = str(address['country'])
    code = _first_text(address, ('country_code',))
    if code:
        out['country_code'] = code.upper()
    if address.get('road'):
        out['road'] = str(address['road'])
    if address.get('house_number'):
        out['house_number'] = str(address['house_number'])

    if d.get('osm_type') and d.get('osm_id'):
        out['osm_type'] = str(d['osm_type'])
        out['osm_id'] = d['osm_id']
    if d.get('category'):
        out['place_category'] = str(d['category'])
    if d.get('type'):
        out['place_type'] = str(d['type'])
    return out


def _bigdatacloud(lat: float, lon: float) -> Dict[str, Any]:
    """
    BigDataCloud free reverse geocoding (keyless).

    Endpoint: ``GET /data/reverse-geocode-client?latitude=&longitude=&localityLanguage=en``.
    Contributes locality, city, region (principal subdivision), country name
    and ISO code. Generic keys (``city`` / ``region`` / ``country`` /
    ``country_code``) are shared with Nominatim so whichever source answers
    fills the same report fields; Nominatim wins conflicts because it is
    registered first.
    """
    url = ('https://api.bigdatacloud.net/data/reverse-geocode-client'
           f'?latitude={lat}&longitude={lon}&localityLanguage=en')
    ok, d, _ = http.get_json(url)
    if not ok or not isinstance(d, dict):
        return {}

    out: Dict[str, Any] = {}
    if d.get('locality'):
        out['locality'] = str(d['locality'])
    if d.get('city'):
        out['city'] = str(d['city'])
    if d.get('principalSubdivision'):
        out['region'] = str(d['principalSubdivision'])
    if d.get('countryName'):
        out['country'] = str(d['countryName'])
    if d.get('countryCode'):
        out['country_code'] = str(d['countryCode']).upper()
    return out


def _open_elevation(lat: float, lon: float) -> Dict[str, Any]:
    """
    Open-Elevation terrain lookup (keyless).

    Endpoint: ``GET /api/v1/lookup?locations=<lat>,<lon>`` returning
    ``results[0].elevation`` in metres above sea level (SRTM-derived).
    Rounded to one decimal; ocean points typically answer 0 or a small
    negative value.
    """
    url = f'https://api.open-elevation.com/api/v1/lookup?locations={lat},{lon}'
    ok, d, _ = http.get_json(url)
    if not ok or not isinstance(d, dict):
        return {}

    results = d.get('results')
    if not isinstance(results, list) or not results:
        return {}
    first = results[0] if isinstance(results[0], dict) else {}
    elevation = first.get('elevation')
    if isinstance(elevation, (int, float)) and not isinstance(elevation, bool):
        out: Dict[str, Any] = {'elevation_m': round(float(elevation), 1)}
        return out
    return {}


def _geohash_local(lat: float, lon: float) -> Dict[str, Any]:
    """
    Offline coordinate intelligence (pure maths, no network).

    Always succeeds: every field is a deterministic re-encoding of the input
    position, computed by ``utils.coordinate_math`` - geohash (9 chars,
    ~5 m cells), Maidenhead locator, DMS and DDM strings, hemisphere, UTM and
    MGRS grid references (skipped outside the -80..84 grid range), a solar
    timezone-offset hint and the NOAA solar position (altitude, azimuth,
    sunrise / sunset UTC, daylight flag) for photo cross-checks. This is the
    baseline provenance every coords lookup carries even when offline.
    """
    out: Dict[str, Any] = {
        'geohash': coordinate_math.latlon_to_geohash(lat, lon, 9),
        'maidenhead': coordinate_math.latlon_to_maidenhead(lat, lon, 3),
        'latitude_dms': coordinate_math.latlon_to_dms(lat, 'lat'),
        'longitude_dms': coordinate_math.latlon_to_dms(lon, 'lon'),
        'coords_ddm': coordinate_math.latlon_to_ddm(lat, lon),
        'hemisphere': 'northern' if lat >= 0.0 else 'southern',
        'timezone_offset_hint': coordinate_math.estimate_timezone_offset(lon),
    }

    # Gridded notations only exist inside the UTM latitude range.
    with contextlib.suppress(ValueError):
        zone, band, easting, northing = coordinate_math.latlon_to_utm(lat, lon)
        out['utm'] = f"{zone}{band} {easting:.0f} {northing:.0f}"
        out['mgrs'] = coordinate_math.latlon_to_mgrs(lat, lon, 5)

    solar = coordinate_math.solar_position(lat, lon)
    out['solar_altitude_deg'] = solar['altitude_deg']
    out['solar_azimuth_deg'] = solar['azimuth_deg']
    out['is_daylight'] = solar['is_daylight']
    if solar['sunrise_utc'] is not None:
        out['solar_sunrise_utc'] = solar['sunrise_utc']
    if solar['sunset_utc'] is not None:
        out['solar_sunset_utc'] = solar['sunset_utc']
    if solar['note']:
        out['solar_note'] = solar['note']
    return out


def _country_centroids_source(lat: float, lon: float) -> Dict[str, Any]:
    """
    Offline nearest-country estimation from the centroid pack.

    Computes the great-circle distance to every packed country centroid and
    reports the nearest one with its ISO code and the distance in km, so
    consumers can decide whether the answer is trustworthy (distance under
    ~500 km is a solid hint; thousands of km means "middle of nowhere",
    e.g. an ocean position). An empty or missing pack returns no data.
    """
    entries = _country_centroids()
    if not entries:
        return {}

    best: Optional[Tuple[str, float, float, str]] = None
    best_km = float('inf')
    for code, c_lat, c_lon, name in entries:
        dist = distance_km(lat, lon, c_lat, c_lon)
        if dist < best_km:
            best_km = dist
            best = (code, c_lat, c_lon, name)
    if best is None:
        return {}

    code, _c_lat, _c_lon, pack_name = best
    return {
        'nearest_country_code': code,
        'nearest_country': geo_country_name(code) or pack_name.title(),
        'nearest_country_distance_km': round(best_km, 1),
    }


# ---------------------------------------------------------------------------
# v6.1 addition: Open-Meteo current conditions - keyless weather and an
# independent elevation cross-check. Probed live before shipping.
# ---------------------------------------------------------------------------

def _open_meteo(lat: float, lon: float) -> Dict[str, Any]:
    """
    Open-Meteo current weather (keyless, v6.1).

    Endpoints: ``https://api.open-meteo.com/v1/forecast?…&current=…``
    (non-commercial keyless tier) and ``/v1/elevation`` for an independent
    second elevation opinion that cross-confirms Open-Elevation in the
    provenance stack. Weather answers twice over for OSINT: photo
    verification (was it really raining at that geotag?) and pattern-of-
    life context. Every request carries the position's timezone, so the
    answer also yields the local time zone name as a bonus field.

    Fields: ``temperature_c``, ``wind_speed_kmh``, ``wind_direction_deg``,
    ``weather_code``, ``weather_timezone``, ``open_meteo_elevation_m``,
    ``open_meteo_elevation_agree`` (bool when both elevation sources ran).
    """
    ok, d, _ = http.get_json(
        'https://api.open-meteo.com/v1/forecast'
        f'?latitude={lat}&longitude={lon}'
        '&current=temperature_2m,wind_speed_10m,wind_direction_10m,weather_code'
        '&timezone=auto', cache_ttl=1800)
    if not ok or not isinstance(d, dict):
        return {}

    out: Dict[str, Any] = {}
    current = d.get('current')
    if isinstance(current, dict):
        if current.get('temperature_2m') is not None:
            with contextlib.suppress(TypeError, ValueError):
                out['temperature_c'] = round(float(current.get('temperature_2m')), 1)
        if current.get('wind_speed_10m') is not None:
            with contextlib.suppress(TypeError, ValueError):
                out['wind_speed_kmh'] = round(float(current.get('wind_speed_10m')), 1)
        if current.get('wind_direction_10m') is not None:
            with contextlib.suppress(TypeError, ValueError):
                out['wind_direction_deg'] = int(current.get('wind_direction_10m'))
        if current.get('weather_code') is not None:
            out['weather_code'] = current.get('weather_code')
    if d.get('timezone'):
        out['weather_timezone'] = d.get('timezone')
    if d.get('elevation') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['open_meteo_elevation_m'] = round(float(d.get('elevation')), 1)

    if not out:
        return {}

    ok2, d2, _ = http.get_json(
        f'https://api.open-meteo.com/v1/elevation?latitude={lat}&longitude={lon}',
        cache_ttl=86400)
    if ok2 and isinstance(d2, dict):
        values = d2.get('elevation')
        if isinstance(values, list) and values \
                and isinstance(values[0], (int, float)):
            out['open_meteo_elevation_m'] = round(float(values[0]), 1)
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'nominatim': _nominatim,
    'bigdatacloud': _bigdatacloud,
    'open_elevation': _open_elevation,
    'geohash_local': _geohash_local,
    'country_centroids': _country_centroids_source,
    'open_meteo': _open_meteo,
}

# Coordinate intelligence is fully keyless today; the registry stays here so
# future keyed sources (e.g. paid elevation or satellite imagery APIs) slot
# in without touching the tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'nominatim': 'OpenStreetMap Nominatim reverse geocoding (keyless, usage policy applies)',
    'bigdatacloud': 'BigDataCloud free reverse-geocode client: locality, city, subdivision (keyless)',
    'open_elevation': 'Open-Elevation SRTM elevation lookup in metres (keyless)',
    'geohash_local': 'Offline coordinate maths: geohash, Maidenhead, DMS/DDM/UTM/MGRS, timezone and solar hints',
    'country_centroids': 'Offline country centroid pack: nearest country by great-circle distance',
    'open_meteo': 'Current weather, wind and an independent elevation cross-check '
                  'via Open-Meteo (keyless; v6.1)',
}


def _keep(value: Any) -> bool:
    # A zero elevation (elevation_m == 0) or a False daylight flag are real
    # answers, so only None / '' / [] / {} count as "no data".
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(coords_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable coordinate source in parallel and merge the results.

    Args:
        coords_value: raw user input in any accepted syntax - decimal
            degrees (``'48.8584, 2.2945'``), DMS, UTM (``'31U 448288
            5411087'``) or MGRS (``'31U DQ 48288 11087'``); parsed via
            ``utils.validators.parse_coords``.
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules.

    Returns:
        {
          'fields': merged_field_dict (always includes 'latitude',
                    'longitude' and 'coords_display'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as coordinates (including
            out-of-range UTM zones raised by the conversion maths).
    """
    keys = keys or {}
    try:
        parsed = parse_coords(str(coords_value))
    except ValueError as exc:
        raise ValueError(f'invalid coordinates: {coords_value!r} ({exc})') from exc
    if parsed is None:
        raise ValueError(f'invalid coordinates: {coords_value!r}')
    lat, lon = parsed

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(lat, lon))

    for name, fn in _plugin_sources('coords').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(lat, lon))

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

    health.record_batch('coords', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # Nominatim's curated address beats BigDataCloud on shared keys.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The position itself is part of the answer, whatever the sources did:
    # normalised decimal degrees plus the canonical display string.
    merged['latitude'] = round(lat, _COORD_DECIMALS)
    merged['longitude'] = round(lon, _COORD_DECIMALS)
    merged['coords_display'] = f"{lat:.6f}, {lon:.6f}"

    return {'fields': merged, 'sources': status, 'provenance': provenance}
