"""
Pure coordinate conversion and solar-geometry engine (v5.0).

This module is the mathematics half of the ``coords`` tracker: it converts a
(latitude, longitude) pair into every notation an OSINT analyst meets in the
wild - and back again - with sub-metre accuracy on the WGS-84 ellipsoid. It
is deliberately dependency-free (``math`` and ``re`` only, no network, no
configuration) so the validators layer, the sources layer and the web tools
can all import it cheaply.

Supported notations and their reference algorithms
--------------------------------------------------
* Decimal degrees (DD): ``48.8584, 2.2945``.
* Degrees / minutes / seconds (DMS): ``48°51'30.2"N`` via :func:`latlon_to_dms`.
* Degrees and decimal minutes (DDM): ``48° 51.504 N, 2° 17.670 E``.
* UTM - Universal Transverse Mercator: ``31U 448258 5411957``. Implemented
  after Snyder (USGS Professional Paper 1395, 1987): the forward direction
  uses the standard series in ``A = cos(lat) * dlon``, the inverse direction
  recovers the footpoint latitude through the ``e1`` series. WGS-84
  parameters (a = 6378137, f = 1/298.257223563, k0 = 0.9996), false easting
  500000, southern-hemisphere offset 10000000, zones 1-60, and the NATO zone
  exceptions (Norway 32V for 56-64N / 3-12E; Svalbard 31X..37X rules for
  72-84N).
* MGRS / USNG - Military Grid Reference System: ``31U DQ 48258 11957``.
  100 km grid squares: column letters A-H / J-R / S-Z selected by
  ``zone % 3`` (the 24-letter column cycle repeats every three zones), row
  letters A-V skipping I and O, shifted five rows on even zones so the grid
  staggers. Decoding re-uses the latitude band to pick the correct
  2,000,000 m northing cycle, which is what makes southern-hemisphere
  references unambiguous.
* Geohash: ``u09t5r8n7`` - the standard base32 bit-interleaved encoding
  (alphabet ``0123456789bcdefghjkmnpqrstuvwxyz``), longitude bit first,
  5 bits per character.
* Maidenhead grid locator: ``JN18dv`` - field (A-R, 20x10 degrees), square
  (0-9, 2x1 degrees) and sub-square (a-x, 5x2.5 arc-minutes) pairs.

Derived geointelligence
-----------------------
* :func:`estimate_timezone_offset` - the 15-degrees-per-hour solar estimate.
* :func:`solar_position` - the NOAA simplified solar calculator: altitude,
  azimuth, sunrise/sunset in UTC and a daylight flag. Used for
  photo-verification OSINT: does the shadow direction and length in a photo
  match the claimed time and place?
* :func:`haversine_km` / :func:`bbox_around` - great-circle distance and
  square bounding-box helpers.
* :func:`parse_utm_string` / :func:`parse_mgrs_string` - forgiving regex
  front doors for the two gridded notations.

Accuracy
--------
``latlon_to_utm`` -> ``utm_to_latlon`` round-trips to well under a
millimetre anywhere inside a zone (the Snyder series are exact to about a
millimetre within 3 degrees of the central meridian and to a few centimetres
at the zone edges). Geohash decoding returns the centre of its own cell by
construction, so its error is bounded by half a cell. DMS/DDM formats round
only at the last printed digit.
"""

import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

__all__ = [
    'EARTH_RADIUS_KM', 'GEOHASH_BASE32', 'K0', 'MGRS_ROW_LETTERS', 'UTM_BANDS',
    'WGS84_A', 'WGS84_E2', 'WGS84_EP2', 'WGS84_F',
    'band_latitude_range', 'bbox_around', 'dms_parts', 'estimate_timezone_offset',
    'geohash_bbox', 'geohash_to_latlon', 'haversine_km', 'latitude_band',
    'latlon_to_ddm', 'latlon_to_dms', 'latlon_to_geohash', 'latlon_to_maidenhead',
    'latlon_to_mgrs', 'latlon_to_utm', 'mgrs_to_latlon', 'parse_mgrs_string',
    'parse_utm_string', 'solar_position', 'utm_to_latlon',
]

# ---------------------------------------------------------------------------
# WGS-84 / UTM constants
# ---------------------------------------------------------------------------

#: Semi-major axis of the WGS-84 ellipsoid, metres.
WGS84_A = 6378137.0
#: Flattening of the WGS-84 ellipsoid (1 / 298.257223563).
WGS84_F = 1.0 / 298.257223563
#: First eccentricity squared, ``f * (2 - f)``.
WGS84_E2 = WGS84_F * (2.0 - WGS84_F)
#: Second eccentricity squared, ``e2 / (1 - e2)``.
WGS84_EP2 = WGS84_E2 / (1.0 - WGS84_E2)
#: UTM point scale factor on the central meridian.
K0 = 0.9996
#: Mean Earth radius used by :func:`haversine_km`, kilometres.
EARTH_RADIUS_KM = 6371.0

#: UTM false easting (metres at the central meridian).
_UTM_FALSE_EASTING = 500000.0
#: Northing offset added for the southern hemisphere.
_UTM_SOUTH_OFFSET = 10000000.0
#: Latitude limits of the UTM / MGRS grid (band C at -80, band X to 84).
UTM_MIN_LAT = -80.0
UTM_MAX_LAT = 84.0

#: Latitude band letters, C..X with X doubled (12-degree band, 72-84N).
UTM_BANDS = 'CDEFGHJKLMNPQRSTUVWXX'
#: MGRS 100 km row letters, A..V with I and O skipped (20 rows, 2,000 km cycle).
MGRS_ROW_LETTERS = 'ABCDEFGHJKLMNPQRSTUV'
#: MGRS 100 km column letters per ``zone % 3`` remainder (1, 2, 3).
_MGRS_COLUMNS = {1: 'ABCDEFGH', 2: 'JKLMNPQR', 3: 'STUVWXYZ'}

#: Geohash base32 alphabet (lower-case, no a/i/l/o).
GEOHASH_BASE32 = '0123456789bcdefghjkmnpqrstuvwxyz'
#: Maidenhead field letters, A..R (18 x 18 fields over the globe).
_MAIDENHEAD_FIELDS = 'ABCDEFGHIJKLMNOPQR'

# Meridional-arc series coefficients (Snyder 1987, equations 8-12 / 3-21).
_E2 = WGS84_E2
_E4 = _E2 * _E2
_E6 = _E4 * _E2
_ARC_C1 = 1.0 - _E2 / 4.0 - 3.0 * _E4 / 64.0 - 5.0 * _E6 / 256.0
_ARC_C2 = 3.0 * _E2 / 8.0 + 3.0 * _E4 / 32.0 + 45.0 * _E6 / 1024.0
_ARC_C3 = 15.0 * _E4 / 256.0 + 45.0 * _E6 / 1024.0
_ARC_C4 = 35.0 * _E6 / 3072.0
#: Inverse-series constant ``e1 = (1 - sqrt(1 - e2)) / (1 + sqrt(1 - e2))``.
_E1 = (1.0 - math.sqrt(1.0 - _E2)) / (1.0 + math.sqrt(1.0 - _E2))

#: UTM reference string: optional band letter, easting, northing.
_UTM_RE = re.compile(
    r'^\s*(\d{1,2})\s*([C-HJ-NP-X])?[\s,;]+(\d{1,7}(?:\.\d+)?)'
    r'[\s,;]+(\d{1,8}(?:\.\d+)?)\s*$', re.IGNORECASE)
#: MGRS reference string: grid zone, 100 km square, offset pair.
_MGRS_RE = re.compile(
    r'^\s*(\d{1,2})\s*([C-HJ-NP-X])\s+([A-Z]{2})\s+(\d{1,5})\s+(\d{1,5})\s*$',
    re.IGNORECASE)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _clamp(value: float, low: float, high: float) -> float:
    """Clamp ``value`` into ``[low, high]`` (guards float drift near asin/acos)."""
    return low if value < low else (high if value > high else value)


def _wrap_longitude(lon: float) -> float:
    """Normalise a longitude into ``[-180, 180)``."""
    wrapped = (lon + 180.0) % 360.0 - 180.0
    # (lon + 180) % 360 maps 180.0 to 0.0 -> -180.0, which is the wanted side.
    return wrapped


def _finite_latlon(lat: float, lon: float) -> Tuple[float, float]:
    """Validate numeric lat/lon ranges; raises ValueError for junk input."""
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        raise ValueError(f'non-numeric coordinates: {lat!r}, {lon!r}') from None
    if not math.isfinite(lat) or not math.isfinite(lon):
        raise ValueError('coordinates must be finite numbers')
    if not -90.0 <= lat <= 90.0:
        raise ValueError(f'latitude out of range (-90..90): {lat}')
    if not -180.0 <= lon <= 180.0:
        raise ValueError(f'longitude out of range (-180..180): {lon}')
    return lat, lon


def _coerce_zone(zone: Any) -> int:
    """Coerce a zone value ('31', 31, 31.0) to int; ValueError outside 1-60."""
    try:
        num = int(zone)
    except (TypeError, ValueError):
        raise ValueError(f'invalid UTM zone: {zone!r}') from None
    if not 1 <= num <= 60:
        raise ValueError(f'UTM zone out of range (1-60): {num}')
    return num


def _meridional_arc(lat_deg: float) -> float:
    """
    Meridional arc length from the equator, metres (Snyder eq. 8-12).

    Exact series for the WGS-84 meridian: ``M(lat)`` is the true distance
    along the ellipsoid surface, which the forward UTM projection scales by
    ``k0`` to obtain the northing. Cross-checked against published values
    (45 deg -> 4,984,944 m, poles -> 10,001,966 m).
    """
    phi = math.radians(lat_deg)
    return WGS84_A * (
        _ARC_C1 * phi
        - _ARC_C2 * math.sin(2.0 * phi)
        + _ARC_C3 * math.sin(4.0 * phi)
        - _ARC_C4 * math.sin(6.0 * phi)
    )


# ---------------------------------------------------------------------------
# Latitude bands
# ---------------------------------------------------------------------------

def latitude_band(lat: float) -> str:
    """
    UTM/MGRS latitude band letter (C..X) for a latitude.

    Bands are 8 degrees wide starting at -80 (C), with the final band X
    stretched to 12 degrees so it covers 72-84N. Latitudes outside the UTM
    grid range raise ``ValueError``.
    """
    lat = float(lat)
    if not UTM_MIN_LAT <= lat <= UTM_MAX_LAT:
        raise ValueError(
            f'latitude {lat} outside the UTM grid range ({UTM_MIN_LAT}..{UTM_MAX_LAT})')
    index = int((lat + 80.0) // 8.0)
    return UTM_BANDS[min(index, len(UTM_BANDS) - 1)]


def band_latitude_range(band: str) -> Tuple[float, float]:
    """
    ``(min_lat, max_lat)`` covered by a UTM band letter.

    ``'X'`` returns ``(72.0, 84.0)`` because its band is 12 degrees wide;
    every other letter covers 8 degrees. Invalid letters (I, O, A, B, Y, Z)
    raise ``ValueError``.
    """
    key = str(band or '').strip().upper()
    if key == 'X':
        return (72.0, 84.0)
    index = UTM_BANDS.find(key)
    if index < 0 or index > 18:
        raise ValueError(f'invalid UTM band letter: {band!r}')
    return (-80.0 + 8.0 * index, -72.0 + 8.0 * (index + 1))


# ---------------------------------------------------------------------------
# UTM: forward and inverse (Snyder 1987)
# ---------------------------------------------------------------------------

def _zone_of(lat: float, lon: float) -> int:
    """
    UTM zone number for a wrapped longitude, with the NATO exceptions.

    Norway: latitudes 56-64N and longitudes 3-12E use zone 32V so the
    coastline stays in one grid. Svalbard: 72-84N uses zones 31X (0-9E),
    33X (9-21E), 35X (21-33E) and 37X (33-42E).
    """
    zone = int((lon + 180.0) // 6.0) + 1
    if 56.0 <= lat < 64.0 and 3.0 <= lon < 12.0:
        return 32
    if 72.0 <= lat <= 84.0:
        if lon < 9.0:
            return 31
        if lon < 21.0:
            return 33
        if lon < 33.0:
            return 35
        if lon < 42.0:
            return 37
    return zone


def latlon_to_utm(lat: float, lon: float) -> Tuple[int, str, float, float]:
    """
    Forward UTM projection on WGS-84 (Snyder 1987, eq. 8-9/8-10).

    Args:
        lat: latitude in decimal degrees, ``-80 <= lat <= 84`` (the UTM grid
            range); anything else raises ``ValueError``.
        lon: longitude in decimal degrees; values outside ``[-180, 180]`` are
            rejected (wrap them beforehand if needed).

    Returns:
        ``(zone, band, easting, northing)`` where easting/northing are metres
        (southern hemisphere northings carry the +10,000,000 offset) and the
        band letter is the 8-degree latitude band with the NATO zone
        exceptions applied.

    Example:
        ``latlon_to_utm(48.8584, 2.2945)`` -> ``(31, 'U', 448258.3, 5411957.2)``
        (Eiffel Tower, a few metres of printed precision).
    """
    lat, lon = _finite_latlon(lat, lon)
    if not UTM_MIN_LAT <= lat <= UTM_MAX_LAT:
        raise ValueError(
            f'latitude {lat} outside the UTM grid range ({UTM_MIN_LAT}..{UTM_MAX_LAT}); '
            'use polar stereographic grids for the polar caps')

    zone = _zone_of(lat, lon)
    band = latitude_band(lat)
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)

    phi = math.radians(lat)
    sin_phi = math.sin(phi)
    cos_phi = math.cos(phi)
    tan_phi = math.tan(phi)

    n_radius = WGS84_A / math.sqrt(1.0 - WGS84_E2 * sin_phi * sin_phi)
    t_sq = tan_phi * tan_phi
    c_sq = WGS84_EP2 * cos_phi * cos_phi
    a_term = cos_phi * (math.radians(lon) - lon0)
    a_sq = a_term * a_term
    meridian = _meridional_arc(lat)

    easting = _UTM_FALSE_EASTING + K0 * n_radius * (
        a_term
        + (1.0 - t_sq + c_sq) * a_term * a_sq / 6.0
        + (5.0 - 18.0 * t_sq + t_sq * t_sq + 72.0 * c_sq - 58.0 * WGS84_EP2)
        * a_term * a_sq * a_sq / 120.0
    )

    northing = K0 * (
        meridian
        + n_radius * tan_phi * (
            a_sq / 2.0
            + (5.0 - t_sq + 9.0 * c_sq + 4.0 * c_sq * c_sq) * a_sq * a_sq / 24.0
            + (61.0 - 58.0 * t_sq + t_sq * t_sq + 600.0 * c_sq - 330.0 * WGS84_EP2)
            * a_sq * a_sq * a_sq / 720.0
        )
    )
    if lat < 0.0:
        northing += _UTM_SOUTH_OFFSET

    return zone, band, easting, northing


def utm_to_latlon(zone: Any, easting: float, northing: float,
                  northern: bool = True) -> Tuple[float, float]:
    """
    Inverse UTM projection on WGS-84 (Snyder 1987, eq. 8-17/8-18).

    Args:
        zone: UTM zone number, 1-60 (int or numeric string).
        easting: metres, typically 100,000-900,000 (false easting 500,000 at
            the central meridian).
        northing: metres; southern-hemisphere values are the 0-10,000,000
            grid northings when ``northern`` is False.
        northern: hemisphere flag; ``True`` for zones/bands at or north of
            the equator. The band letter resolves to ``band >= 'N'``.

    Returns:
        ``(latitude, longitude)`` in decimal degrees. Round-trips
        :func:`latlon_to_utm` to sub-millimetre accuracy inside a zone.

    Raises:
        ValueError: invalid zone or non-numeric coordinates.
    """
    zone = _coerce_zone(zone)
    try:
        easting = float(easting)
        northing = float(northing)
    except (TypeError, ValueError):
        raise ValueError(f'non-numeric UTM values: {easting!r}, {northing!r}') from None

    x = easting - _UTM_FALSE_EASTING
    y = northing if northern else northing - _UTM_SOUTH_OFFSET
    lon0 = math.radians((zone - 1) * 6 - 180 + 3)

    # Footpoint latitude from the rectifying latitude (Snyder eq. 3-26/8-16).
    mu = y / (K0 * WGS84_A * _ARC_C1)
    e1_sq = _E1 * _E1
    e1_cu = e1_sq * _E1
    e1_qt = e1_sq * e1_sq
    phi1 = (
        mu
        + (3.0 * _E1 / 2.0 - 27.0 * e1_cu / 32.0) * math.sin(2.0 * mu)
        + (21.0 * e1_sq / 16.0 - 55.0 * e1_qt / 32.0) * math.sin(4.0 * mu)
        + (151.0 * e1_cu / 96.0) * math.sin(6.0 * mu)
        + (1097.0 * e1_qt / 512.0) * math.sin(8.0 * mu)
    )

    sin1 = math.sin(phi1)
    cos1 = math.cos(phi1)
    tan1 = math.tan(phi1)
    denom = 1.0 - WGS84_E2 * sin1 * sin1

    c1 = WGS84_EP2 * cos1 * cos1
    t1 = tan1 * tan1
    n1 = WGS84_A / math.sqrt(denom)
    r1 = WGS84_A * (1.0 - WGS84_E2) / (denom * math.sqrt(denom))
    d_term = x / (n1 * K0)
    d_sq = d_term * d_term

    lat = phi1 - (n1 * tan1 / r1) * (
        d_sq / 2.0
        - (5.0 + 3.0 * t1 + 10.0 * c1 - 4.0 * c1 * c1 - 9.0 * WGS84_EP2)
        * d_sq * d_sq / 24.0
        + (61.0 + 90.0 * t1 + 298.0 * c1 + 45.0 * t1 * t1 - 252.0 * WGS84_EP2
           - 3.0 * c1 * c1)
        * d_sq * d_sq * d_sq / 720.0
    )

    lon = lon0 + (
        d_term
        - (1.0 + 2.0 * t1 + c1) * d_term * d_sq / 6.0
        + (5.0 - 2.0 * c1 + 28.0 * t1 - 3.0 * c1 * c1 + 8.0 * WGS84_EP2
           + 24.0 * t1 * t1)
        * d_term * d_sq * d_sq / 120.0
    ) / cos1

    return math.degrees(lat), math.degrees(lon)


# ---------------------------------------------------------------------------
# MGRS
# ---------------------------------------------------------------------------

def _mgrs_column_set(zone: int) -> str:
    """Column-letter set for a zone: A-H (z%3==1), J-R (z%3==2), S-Z (z%3==0)."""
    remainder = zone % 3
    return _MGRS_COLUMNS[remainder if remainder else 3]


def _mgrs_offsets(easting: Any, northing: Any) -> Tuple[float, float]:
    """
    Scale MGRS digit pairs to metre offsets inside the 100 km square.

    A 5-digit pair is metres, 4 digits are tens of metres, and so on. When
    the values arrive as strings the digit count is read from the string
    itself, so zero-padded references such as ``'07350'`` keep their true
    5-digit precision. When they arrive as integers (the validators path,
    where ``int('07350')`` has already stripped the padding) the two counts
    are reconciled: MGRS always prints both offsets at the same precision,
    so the *longer* digit count wins and the shorter value is treated as
    zero-padded to it. A reference whose offsets both lost leading zeros
    through integer conversion is genuinely ambiguous and documented as
    such in :func:`mgrs_to_latlon`.
    """
    try:
        east_text = str(easting).strip()
        north_text = str(northing).strip()
        e_value = float(int(east_text))
        n_value = float(int(north_text))
    except (TypeError, ValueError):
        raise ValueError(f'non-numeric MGRS offsets: {easting!r}, {northing!r}') from None
    e_digits = len(east_text.lstrip('-'))
    n_digits = len(north_text.lstrip('-'))
    digits = min(5, max(e_digits, n_digits, 1))
    e_scale = 10.0 ** (5 - digits)
    n_scale = 10.0 ** (5 - digits)
    return e_value * e_scale, n_value * n_scale


def mgrs_to_latlon(zone: Any, band: str, square: str, easting: Any,
                   northing: Any) -> Tuple[float, float]:
    """
    Decode an MGRS reference to ``(latitude, longitude)``.

    Args:
        zone: UTM zone number, 1-60.
        band: latitude band letter (C..X); also decides the hemisphere
            (``>= 'N'`` means northern) and which 2,000 km row cycle the
            row letter refers to.
        square: the two 100 km grid letters, e.g. ``'DQ'`` - first the
            column letter (set depends on ``zone % 3``), then the row letter
            (A-V, I/O skipped, shifted 5 rows on even zones).
        easting: the easting offset inside the square - an int or the raw
            digit string (5 digits = metres, 4 digits = tens of metres,
            ...). Strings preserve zero padding, which integers cannot.
        northing: same convention for the northing offset.

    Returns:
        ``(latitude, longitude)`` in decimal degrees, consistent with
        :func:`latlon_to_mgrs` to within the grid quantisation (one metre
        per axis at the 5-digit precision). When both offsets arrive as
        integers that have lost leading zeros, the longer digit count is
        assumed for both (standard MGRS prints equal-length offsets), which
        resolves the common ``'... 83959 07350'`` case exactly.

    Raises:
        ValueError: malformed zone/band/square/offsets, or a reference whose
            row letter cannot be reconciled with the given band.

    Example:
        ``mgrs_to_latlon(31, 'U', 'DQ', 48288, 11087)`` -> about
        ``(48.85, 2.29)`` - central Paris.
    """
    zone = _coerce_zone(zone)
    band = str(band or '').strip().upper()
    square = str(square or '').strip().upper()

    if band not in UTM_BANDS:
        raise ValueError(f'invalid MGRS band letter: {band!r}')
    if len(square) != 2:
        raise ValueError(f'MGRS square must be two letters: {square!r}')

    column_set = _mgrs_column_set(zone)
    column_letter, row_letter = square[0], square[1]
    if column_letter not in column_set:
        raise ValueError(
            f'invalid MGRS column letter {column_letter!r} for zone {zone} '
            f'(allowed: {column_set})')
    if row_letter not in MGRS_ROW_LETTERS:
        raise ValueError(f'invalid MGRS row letter: {row_letter!r}')

    column_index = column_set.index(column_letter)
    row_index = MGRS_ROW_LETTERS.index(row_letter)
    east_offset, north_offset = _mgrs_offsets(easting, northing)

    # Column letters count from 100 km (column A of set 1 covers 100-199 km).
    full_easting = (column_index + 1) * 100000.0 + east_offset
    # Row letters cycle every 2,000 km; even zones start the cycle at 'F'.
    base_northing = row_index * 100000.0 if zone % 2 else (row_index - 5) % 20 * 100000.0

    northern = band >= 'N'
    band_min, band_max = band_latitude_range(band)
    band_mid = (band_min + band_max) / 2.0

    # The row letter alone is ambiguous (five 2,000 km cycles); the band
    # picks the cycle whose decoded latitude actually falls inside it.
    fallback: Optional[Tuple[float, float]] = None
    fallback_error = float('inf')
    for cycle in range(5):
        candidate = base_northing + cycle * 2000000.0 + north_offset
        if not 0.0 <= candidate <= _UTM_SOUTH_OFFSET:
            continue
        lat, lon = utm_to_latlon(zone, full_easting, candidate, northern)
        if band_min - 0.5 <= lat <= band_max + 0.5:
            return lat, lon
        error = abs(lat - band_mid)
        if error < fallback_error:
            fallback = (lat, lon)
            fallback_error = error
    if fallback is not None:
        return fallback
    raise ValueError(
        f'MGRS row letter {row_letter!r} cannot be placed in band {band!r} '
        f'for zone {zone}')


def latlon_to_mgrs(lat: float, lon: float, precision: int = 5) -> str:
    """
    Encode a position as an MGRS / USNG reference string.

    Args:
        lat, lon: decimal degrees (UTM grid range only, ``-80..84`` north).
        precision: number of easting/northing digits, 1-5 (5 = 1 m, 4 = 10 m,
            3 = 100 m, 2 = 1 km, 1 = 10 km). Values outside the range are
            clamped.

    Returns:
        ``'31U DQ 48258 11957'`` style reference (grid zone designator, two
        100 km square letters, then the scaled offset pair, zero-padded).

    Raises:
        ValueError: coordinates outside the UTM grid or numeric ranges.
    """
    precision = min(5, max(1, int(precision)))
    zone, band, easting, northing = latlon_to_utm(lat, lon)

    column_set = _mgrs_column_set(zone)
    column_index = (int(easting // 100000.0) - 1) % 8
    row_index = (int(northing // 100000.0) + (5 if zone % 2 == 0 else 0)) % 20

    scale = 10 ** (5 - precision)
    east_offset = int((easting % 100000.0) // scale)
    north_offset = int((northing % 100000.0) // scale)

    return (f"{zone}{band} {column_set[column_index]}{MGRS_ROW_LETTERS[row_index]} "
            f"{east_offset:0{precision}d} {north_offset:0{precision}d}")


# ---------------------------------------------------------------------------
# DMS / DDM formatting
# ---------------------------------------------------------------------------

def dms_parts(value: float) -> Tuple[int, int, int, float]:
    """
    Split decimal degrees into ``(sign, degrees, minutes, seconds)``.

    ``sign`` is +1 or -1; minutes are whole minutes 0-59; seconds carry the
    fraction. ``dms_parts(-48.8584)`` -> ``(-1, 48, 51, 30.24)``.
    """
    value = float(value)
    sign = -1 if value < 0 else 1
    absolute = abs(value)
    degrees = int(absolute)
    minutes_total = (absolute - degrees) * 60.0
    minutes = int(minutes_total)
    seconds = (minutes_total - minutes) * 60.0
    # Guard float drift such as 29.9999999 that should print as 30.0.
    if seconds > 59.95:
        seconds = 0.0
        minutes += 1
    if minutes >= 60:
        minutes -= 60
        degrees += 1
    return sign, degrees, minutes, seconds


def latlon_to_dms(value: float, axis: str = 'lat') -> str:
    """
    Format one decimal-degree component as a DMS string.

    Args:
        value: latitude or longitude in decimal degrees.
        axis: ``'lat'`` (hemisphere N/S, degrees <= 90) or ``'lon'``
            (hemisphere E/W, degrees <= 180); anything else raises
            ``ValueError``.

    Returns:
        ``'48°51'30.2"N'`` or ``'2°17'40.4"E'`` - degree, arcminute and
        arcsecond symbols, seconds to one decimal, hemisphere suffix.
    """
    axis_key = str(axis or '').strip().lower()
    if axis_key not in ('lat', 'lon'):
        raise ValueError(f"axis must be 'lat' or 'lon': {axis!r}")
    limit = 90.0 if axis_key == 'lat' else 180.0
    value = float(value)
    if not math.isfinite(value) or abs(value) > limit:
        raise ValueError(f'value {value} out of range for axis {axis_key!r}')

    sign, degrees, minutes, seconds = dms_parts(value)
    hemisphere = ('S' if sign < 0 else 'N') if axis_key == 'lat' else 'W' if sign < 0 else 'E'
    return (f"{degrees}°{minutes}'{seconds:.1f}\"{hemisphere}")


def latlon_to_ddm(lat: float, lon: float) -> str:
    """
    Format a position as degrees + decimal minutes (aviation / GeoCache).

    Returns:
        ``'48° 51.504 N, 2° 17.670 E'`` - whole degrees, minutes to three
        decimals, hemisphere letters, comma-separated components.

    Raises:
        ValueError: out-of-range or non-finite components.
    """
    lat, lon = _finite_latlon(lat, lon)

    def component(value: float, is_latitude: bool) -> str:
        sign, degrees, minutes, seconds = dms_parts(value)
        minute_decimal = minutes + seconds / 60.0
        hemisphere = ('N' if sign > 0 else 'S') if is_latitude else 'E' if sign > 0 else 'W'
        return f"{degrees}° {minute_decimal:.3f} {hemisphere}"

    return f"{component(lat, True)}, {component(lon, False)}"


# ---------------------------------------------------------------------------
# Geohash
# ---------------------------------------------------------------------------

def latlon_to_geohash(lat: float, lon: float, precision: int = 9) -> str:
    """
    Encode a position as a base32 geohash (Moumine/Niemeyer algorithm).

    The longitude and latitude bits are interleaved (longitude first), five
    bits per base32 character. Each extra character halves both dimensions,
    so precision 9 gives roughly 4.8 x 4.8 m cells at the equator.

    Args:
        lat, lon: decimal degrees (validated ranges).
        precision: hash length, 1-12 (clamped); the default 9 is the usual
            "building level" choice.

    Returns:
        The geohash string, e.g. ``'u09t5r8n7'`` for central Paris.
    """
    lat, lon = _finite_latlon(lat, lon)
    precision = min(12, max(1, int(precision)))

    lat_min, lat_max = -90.0, 90.0
    lon_min, lon_max = -180.0, 180.0
    chars: list = []
    bit = 0
    char_bits = 0
    even = True  # longitude bits occupy the even positions

    while len(chars) < precision:
        if even:
            mid = (lon_min + lon_max) / 2.0
            if lon >= mid:
                char_bits = (char_bits << 1) | 1
                lon_min = mid
            else:
                char_bits = char_bits << 1
                lon_max = mid
        else:
            mid = (lat_min + lat_max) / 2.0
            if lat >= mid:
                char_bits = (char_bits << 1) | 1
                lat_min = mid
            else:
                char_bits = char_bits << 1
                lat_max = mid
        even = not even
        bit += 1
        if bit == 5:
            chars.append(GEOHASH_BASE32[char_bits])
            bit = 0
            char_bits = 0
    return ''.join(chars)


def geohash_bbox(geohash: str) -> Dict[str, float]:
    """
    Bounding box of a geohash: ``{'south', 'north', 'west', 'east'}``.

    The box is the exact cell the hash describes, so every position that
    encodes to this hash lies inside it. Invalid characters or an empty
    string raise ``ValueError``.
    """
    text = str(geohash or '').strip().lower()
    if not text:
        raise ValueError('empty geohash')
    lat_min, lat_max = -90.0, 90.0
    lon_min, lon_max = -180.0, 180.0
    even = True
    for char in text:
        index = GEOHASH_BASE32.find(char)
        if index < 0:
            raise ValueError(f'invalid geohash character: {char!r}')
        for shift in range(4, -1, -1):
            bit_is_set = bool(index & (1 << shift))
            if even:  # longitude halving
                mid = (lon_min + lon_max) / 2.0
                if bit_is_set:
                    lon_min = mid
                else:
                    lon_max = mid
            else:  # latitude halving
                mid = (lat_min + lat_max) / 2.0
                if bit_is_set:
                    lat_min = mid
                else:
                    lat_max = mid
            even = not even
    return {'south': lat_min, 'north': lat_max, 'west': lon_min, 'east': lon_max}


def geohash_to_latlon(geohash: str) -> Tuple[float, float]:
    """
    Decode a geohash to the centre of its cell, ``(lat, lon)``.

    The centre is the canonical decode: any position inside the cell
    encodes to the same hash, so returning the midpoint bounds the error by
    half a cell (about 2.4 m per axis at precision 9). See
    :func:`geohash_bbox` for the full box.
    """
    box = geohash_bbox(geohash)
    return ((box['south'] + box['north']) / 2.0,
            (box['west'] + box['east']) / 2.0)


# ---------------------------------------------------------------------------
# Maidenhead locator
# ---------------------------------------------------------------------------

def latlon_to_maidenhead(lat: float, lon: float, precision: int = 3) -> str:
    """
    Encode a position as a Maidenhead (WGS grid) locator.

    Structure per precision level (clamped to 1-4):

    * 1 - field: two letters, 20 x 10 degrees (``'JN'``);
    * 2 - + square: two digits, 2 x 1 degrees (``'JN18'``);
    * 3 - + sub-square: two lower-case letters, 5 x 2.5 arc-minutes
      (``'JN18dv'``, the default and the common amateur-radio form);
    * 4 - + extended square: two digits, 30 x 15 arc-seconds.

    Args:
        lat, lon: decimal degrees (validated ranges; longitude wraps).
        precision: 1-4 as described above.

    Returns:
        The locator string, alternating pairs as the precision grows.
    """
    lat, lon = _finite_latlon(lat, lon)
    precision = min(4, max(1, int(precision)))
    lon = _wrap_longitude(lon)

    adj_lon = lon + 180.0
    adj_lat = lat + 90.0

    field_lon = min(17, int(adj_lon // 20.0))
    field_lat = min(17, int(adj_lat // 10.0))
    locator = _MAIDENHEAD_FIELDS[field_lon] + _MAIDENHEAD_FIELDS[field_lat]

    if precision >= 2:
        locator += f"{int((adj_lon % 20.0) // 2.0)}{int(adj_lat % 10.0)}"

    if precision >= 3:
        sub_lon = int(((adj_lon % 2.0) / 2.0) * 24.0)
        sub_lat = int((adj_lat % 1.0) * 24.0)
        locator += chr(ord('a') + min(23, sub_lon)) + chr(ord('a') + min(23, sub_lat))

    if precision >= 4:
        ext_lon = int((((adj_lon % 2.0) / 2.0) * 24.0 % 1.0) * 10.0)
        ext_lat = int(((adj_lat % 1.0) * 24.0 % 1.0) * 10.0)
        locator += f"{ext_lon}{ext_lat}"

    return locator


# ---------------------------------------------------------------------------
# Solar geometry (NOAA simplified)
# ---------------------------------------------------------------------------

def estimate_timezone_offset(lon: float) -> float:
    """
    Rough UTC offset estimate for a longitude, in hours (15 deg per hour).

    This is the nautical/solar approximation ``round(lon / 15)``: it tracks
    mean solar time to within about half an hour and ignores political time
    zone boundaries entirely (China spans one official zone where the solar
    estimate spreads over five). Useful as a *hint* when a photo's shadow
    clock disagrees with a claimed timezone, not as ground truth. The value
    is clamped to ``[-12, +12]``.
    """
    lon = float(lon)
    if not math.isfinite(lon):
        raise ValueError('longitude must be finite')
    offset = round(lon / 15.0)
    return float(min(12, max(-12, offset)))


def _minutes_to_hhmm(minutes: float) -> str:
    """Render minutes-since-midnight (any sign) as a zero-padded 'HH:MM'."""
    total = int(round(minutes)) % 1440
    return f"{total // 60:02d}:{total % 60:02d}"


def solar_position(lat: float, lon: float,
                   when: Optional[datetime] = None) -> Dict[str, Any]:
    """
    NOAA-simplified solar position for photo-verification OSINT.

    Computes the Sun's altitude and azimuth plus sunrise/sunset (UTC) for
    the given place and moment, using the fractional-year Fourier series
    for the equation of time and declination from the NOAA "General Solar
    Position Calculations" sheet (accuracy ~1-2 minutes of time, ~0.1 deg
    of position - ample for judging whether a photo's shadows fit its
    claimed time and location).

    Args:
        lat, lon: decimal degrees (validated; polar latitudes are clamped
            to +-89.9 internally to keep the trigonometry stable).
        when: ``datetime`` to evaluate; naive values are assumed UTC and
            aware values are converted to UTC. ``None`` means now (UTC).

    Returns:
        Dict with flat-ish keys::

            {
              'altitude_deg': float,       # Sun elevation above the horizon
              'azimuth_deg': float,        # Compass bearing of the Sun
              'sunrise_utc': 'HH:MM'|None,  # None on polar day/night
              'sunset_utc': 'HH:MM'|None,
              'is_daylight': bool,          # altitude above -0.833 deg
              'declination_deg': float,
              'note': '',                   # 'polar day' / 'polar night'
            }

    Raises:
        ValueError: invalid coordinates or a non-datetime ``when``.
    """
    lat, lon = _finite_latlon(lat, lon)
    if when is None:
        moment = datetime.now(timezone.utc)
    elif isinstance(when, datetime):
        moment = (when.replace(tzinfo=timezone.utc) if when.tzinfo is None
                  else when.astimezone(timezone.utc))
    else:
        raise ValueError('when must be a datetime or None')

    lat_r = math.radians(max(-89.9, min(89.9, lat)))

    # Fractional year (radians) for the UTC day/hour (NOAA eq. 1).
    day = moment.timetuple().tm_yday
    hour = moment.hour + moment.minute / 60.0 + moment.second / 3600.0
    gamma = 2.0 * math.pi / 365.0 * (day - 1 + (hour - 12.0) / 24.0)

    # Equation of time (minutes) and solar declination (radians), NOAA eq. 2/3.
    eqtime = 229.18 * (
        0.000075
        + 0.001868 * math.cos(gamma) - 0.032077 * math.sin(gamma)
        - 0.014615 * math.cos(2.0 * gamma) - 0.040849 * math.sin(2.0 * gamma)
    )
    decl = (
        0.006918
        - 0.399912 * math.cos(gamma) + 0.070257 * math.sin(gamma)
        - 0.006758 * math.cos(2.0 * gamma) + 0.000907 * math.sin(2.0 * gamma)
        - 0.002697 * math.cos(3.0 * gamma) + 0.00148 * math.sin(3.0 * gamma)
    )

    # True solar time -> current hour angle (degrees, NOAA eq. 4/5).
    solar_time = hour * 60.0 + eqtime + 4.0 * lon
    hour_angle = math.radians(solar_time / 4.0 - 180.0)

    cos_zenith = (_clamp(math.sin(lat_r) * math.sin(decl)
                         + math.cos(lat_r) * math.cos(decl)
                         * math.cos(hour_angle), -1.0, 1.0))
    zenith = math.acos(cos_zenith)
    altitude = math.pi / 2.0 - zenith

    # Azimuth from north, clockwise: robust atan2 form valid near zenith.
    east = -math.cos(decl) * math.sin(hour_angle)
    north = (math.sin(decl) * math.cos(lat_r)
             - math.cos(decl) * math.sin(lat_r) * math.cos(hour_angle))
    azimuth = math.degrees(math.atan2(east, north)) % 360.0

    # Sunrise/sunset hour angle for the -0.833 deg horizon (refraction+solar
    # radius); |argument| > 1 means the Sun never crosses that horizon.
    horizon = math.cos(math.radians(90.833))
    argument = (horizon / (math.cos(lat_r) * math.cos(decl))
                - math.tan(lat_r) * math.tan(decl))
    note = ''
    sunrise: Optional[str] = None
    sunset: Optional[str] = None
    if argument < -1.0:
        note = 'polar day'
    elif argument > 1.0:
        note = 'polar night'
    else:
        ha_sunset = math.degrees(math.acos(_clamp(argument, -1.0, 1.0)))
        sunrise = _minutes_to_hhmm(720.0 - 4.0 * (lon + ha_sunset) - eqtime)
        sunset = _minutes_to_hhmm(720.0 - 4.0 * (lon - ha_sunset) - eqtime)

    altitude_deg = math.degrees(altitude)
    return {
        'altitude_deg': round(altitude_deg, 2),
        'azimuth_deg': round(azimuth, 2),
        'sunrise_utc': sunrise,
        'sunset_utc': sunset,
        'is_daylight': altitude_deg > -0.833,
        'declination_deg': round(math.degrees(decl), 2),
        'note': note,
    }


# ---------------------------------------------------------------------------
# Distance / bounding box
# ---------------------------------------------------------------------------

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Great-circle distance between two points, kilometres (haversine).

    Uses the mean Earth radius :data:`EARTH_RADIUS_KM` (6371 km); accuracy
    is about 0.3 percent versus the ellipsoid, which is ample for the
    nearest-country and spread computations in this package. Inputs are
    range-checked and raise ``ValueError`` on junk, unlike the softer
    ``geo.distance_km`` helper.
    """
    lat1, lon1 = _finite_latlon(lat1, lon1)
    lat2, lon2 = _finite_latlon(lat2, lon2)
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (math.sin(d_phi / 2.0) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2)
    return 2.0 * EARTH_RADIUS_KM * math.asin(math.sqrt(_clamp(a, 0.0, 1.0)))


def bbox_around(lat: float, lon: float, km: float) -> Dict[str, float]:
    """
    Square bounding box around a point, ``center +/- delta`` degrees.

    The latitude delta is ``km / 111.32`` (one degree is ~111.32 km of
    meridian); the longitude delta divides by ``111.32 * cos(lat)`` so the
    box stays roughly square in kilometres, with the cosine clamped to keep
    polar latitudes finite. Longitude bounds are *not* wrapped across the
    antimeridian - callers rendering on a flat map can wrap if needed.

    Args:
        lat, lon: box centre, decimal degrees.
        km: half-width of the box in kilometres (> 0).

    Returns:
        ``{'min_lat', 'max_lat', 'min_lon', 'max_lon', 'center_lat',
        'center_lon', 'radius_km'}``.
    """
    lat, lon = _finite_latlon(lat, lon)
    km = float(km)
    if not math.isfinite(km) or km <= 0.0:
        raise ValueError(f'radius must be a positive number of km: {km!r}')

    delta_lat = km / 111.32
    cosine = max(abs(math.cos(math.radians(lat))), 0.01)
    delta_lon = km / (111.32 * cosine)
    return {
        'min_lat': lat - delta_lat,
        'max_lat': lat + delta_lat,
        'min_lon': lon - delta_lon,
        'max_lon': lon + delta_lon,
        'center_lat': lat,
        'center_lon': lon,
        'radius_km': km,
    }


# ---------------------------------------------------------------------------
# Parsing front doors
# ---------------------------------------------------------------------------

def parse_utm_string(text: str) -> Optional[Tuple[int, str, float, float]]:
    """
    Parse a UTM reference string into ``(zone, band, easting, northing)``.

    Accepts ``'31U 448288 5411087'``, ``'31U 448288.5, 5411087.5'`` and the
    band-less ``'31 448288 5411087'`` (band ``''``, northern hemisphere
    assumed - only sensible when the context fixes the hemisphere).

    Returns:
        The typed tuple, or ``None`` when the string matches no UTM syntax.
        Zone validity (1-60) is checked by :func:`utm_to_latlon`, not here.
    """
    match = _UTM_RE.match(str(text or ''))
    if not match:
        return None
    zone, band, easting, northing = match.groups()
    return (int(zone), (band or '').upper(), float(easting), float(northing))


def parse_mgrs_string(text: str) -> Optional[Tuple[int, str, str, int, int]]:
    """
    Parse an MGRS reference string into ``(zone, band, square, e, n)``.

    Accepts the spaced military form ``'31U DQ 48288 11087'`` (1-5 offset
    digits each) case-insensitively. Digits are kept as integers because
    their *count* encodes the precision, exactly as on paper maps.

    Returns:
        The typed tuple, or ``None`` when the string matches no MGRS syntax.
    """
    match = _MGRS_RE.match(str(text or ''))
    if not match:
        return None
    zone, band, square, easting, northing = match.groups()
    return (int(zone), band.upper(), square.upper(), int(easting), int(northing))
