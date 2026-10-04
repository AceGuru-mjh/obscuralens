"""
Spatial analytics over geographic evidence (v6.0 Part 2).

The coords tracker already turns "48.8584, 2.2945" into every notation an
analyst meets; this module answers the questions *about a set* of
coordinates that a single lookup never can: how far apart are these
observations, what is the bounding box, which points cluster together,
which point is the outlier, how long is the implied travel route, and is
this point inside the geofence that matters.

Distances delegate to :func:`obscuralens.utils.coordinate_math.haversine_km`
(the platform's mean-Earth-radius great-circle implementation, ~0.3% versus
the ellipsoid) rather than re-implementing a drifting copy; the bearing
formula - which coordinate_math only computes for the Sun - is implemented
here in eight lines. Clustering reuses :func:`obscuralens.analytics.cluster.dbscan`
after projecting lat/lon onto a local kilometre plane centred on the
centroid.

Design contract (mirrored across the analytics package):

* **Defensive by default.** ``None``, non-numeric and out-of-range
  coordinates are dropped (never an exception); a function that needs at
  least one valid point returns ``None`` / an empty structure when it got
  none.
* **Approximations stated, not hidden.** The centroid is a planar mean of
  decimal degrees - ample for regional evidence sets, documented as
  distorted across the antimeridian and near the poles.
* **Pure functions.** No state, no I/O, no network.
"""

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..utils.coordinate_math import haversine_km
from .cluster import dbscan
from .stats import quartiles

__all__ = [
    'GeoPoint',
    'bounding_box',
    'centroid',
    'cluster_points',
    'distance_matrix',
    'geofence_check',
    'geo_summary',
    'outlier_points',
    'pairwise_distances',
    'route_length',
]

#: Kilometres per degree of latitude / of equatorial longitude.
_KM_PER_DEGREE = 111.32

#: Default DBSCAN radius for :func:`cluster_points`, in kilometres.
_DEFAULT_EPS_KM = 25.0

#: Floor for |cos(latitude)| when projecting to a local km plane, so polar
#: points stay finite (same guard style as coordinate_math.bbox_around).
_COS_FLOOR = 0.01


@dataclass
class GeoPoint:
    """One geographic observation.

    Attributes:
        lat: Latitude in decimal degrees, ``[-90, 90]``.
        lon: Longitude in decimal degrees, ``[-180, 180]``.
        label: Free-form annotation (place name, sighting note); empty
            string when unlabelled.
    """

    lat: float
    lon: float
    label: str = ''


# ---------------------------------------------------------------------------
# Input coercion
# ---------------------------------------------------------------------------

def _to_float(value: Any) -> Optional[float]:
    """Coerce one item to a finite float, or None when impossible.

    ``bool`` is rejected even though it subclasses ``int`` - ``True`` is a
    flag, not a coordinate.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _coerce_point(item: Any) -> Optional[GeoPoint]:
    """Coerce one argument into a validated :class:`GeoPoint`.

    Accepted shapes: an existing :class:`GeoPoint` (re-validated); a dict
    with ``'lat'``/``'lon'`` keys and an optional ``'label'``; a
    ``(lat, lon)`` or ``(lat, lon, label)`` tuple/list. Out-of-range or
    non-finite coordinates yield ``None`` - a bad point is dropped, not
    fatal.
    """
    if isinstance(item, GeoPoint):
        lat = _to_float(item.lat)
        lon = _to_float(item.lon)
        label = item.label if isinstance(item.label, str) else ''
    elif isinstance(item, dict):
        lat = _to_float(item.get('lat'))
        lon = _to_float(item.get('lon'))
        raw_label = item.get('label')
        label = raw_label if isinstance(raw_label, str) else ''
    elif isinstance(item, (list, tuple)) and 2 <= len(item) <= 3:
        lat = _to_float(item[0])
        lon = _to_float(item[1])
        label = item[2] if len(item) > 2 and isinstance(item[2], str) else ''
    else:
        return None
    if lat is None or lon is None:
        return None
    if not -90.0 <= lat <= 90.0 or not -180.0 <= lon <= 180.0:
        return None
    return GeoPoint(lat, lon, label)


def _as_points(points: Any) -> List[GeoPoint]:
    """Coerce a point-collection argument into validated GeoPoints."""
    if points is None or isinstance(points, (str, bytes)):
        return []
    if isinstance(points, GeoPoint):
        point = _coerce_point(points)
        return [point] if point is not None else []
    if isinstance(points, dict):
        point = _coerce_point(points)
        return [point] if point is not None else []
    try:
        iterator = iter(points)
    except TypeError:
        return []
    collected: List[GeoPoint] = []
    for item in iterator:
        point = _coerce_point(item)
        if point is not None:
            collected.append(point)
    return collected


def _distance_km(point_a: GeoPoint, point_b: GeoPoint) -> Optional[float]:
    """Haversine distance in km between two validated points (never raises)."""
    try:
        return haversine_km(point_a.lat, point_a.lon, point_b.lat, point_b.lon)
    except (ValueError, TypeError, OverflowError):  # pragma: no cover - pre-validated
        return None


def _label_of(point: GeoPoint, index: int) -> str:
    """Display label for one point: its label, else ``point_<index>``."""
    return point.label if point.label else f'point_{index}'


def _unique_labels(points: List[GeoPoint]) -> List[str]:
    """Per-point display labels, uniquified for matrix keys.

    Empty labels become ``point_<i>``; duplicates get ``_<i>`` appended so
    :func:`distance_matrix` always has injective keys.
    """
    labels: List[str] = []
    seen: Dict[str, int] = {}
    for index, point in enumerate(points):
        label = _label_of(point, index)
        if label in seen:
            labels.append(f'{label}_{index}')
        else:
            seen[label] = index
            labels.append(label)
    return labels


# ---------------------------------------------------------------------------
# Shape of a point set
# ---------------------------------------------------------------------------

def bounding_box(points: Any) -> Optional[Dict[str, Any]]:
    """Axis-aligned bounding box plus centre and kilometre spans.

    The "where does this evidence sit on the map" answer: minimum and
    maximum of both axes, the box centre, the north-south and east-west
    spans in kilometres (the east-west span measured at the centre
    latitude, where a degree of longitude is worth
    ``111.32 * cos(lat)`` km) and the corner-to-corner diagonal.

    Args:
        points: Iterable of :class:`GeoPoint`-like items (see
            :func:`_coerce_point` for accepted shapes). Invalid items are
            dropped.

    Returns:
        Dict with ``'min_lat'``, ``'max_lat'``, ``'min_lon'``,
        ``'max_lon'``, ``'center_lat'``, ``'center_lon'``, ``'lat_span_km'``,
        ``'lon_span_km'`` and ``'diagonal_km'``, or ``None`` when no valid
        point survived. Never raises.

    Example:
        >>> box = bounding_box([(48.0, 2.0), (49.0, 3.0)])
        >>> round(box['lat_span_km'], 1)
        111.3
    """
    collected = _as_points(points)
    if not collected:
        return None
    min_lat = min(point.lat for point in collected)
    max_lat = max(point.lat for point in collected)
    min_lon = min(point.lon for point in collected)
    max_lon = max(point.lon for point in collected)
    center_lat = (min_lat + max_lat) / 2.0
    center_lon = (min_lon + max_lon) / 2.0
    lat_span_km = (max_lat - min_lat) * _KM_PER_DEGREE
    cosine = max(abs(math.cos(math.radians(center_lat))), _COS_FLOOR)
    lon_span_km = (max_lon - min_lon) * _KM_PER_DEGREE * cosine
    corner_a = GeoPoint(min_lat, min_lon)
    corner_b = GeoPoint(max_lat, max_lon)
    diagonal = _distance_km(corner_a, corner_b)
    return {
        'min_lat': min_lat,
        'max_lat': max_lat,
        'min_lon': min_lon,
        'max_lon': max_lon,
        'center_lat': center_lat,
        'center_lon': center_lon,
        'lat_span_km': round(lat_span_km, 3),
        'lon_span_km': round(lon_span_km, 3),
        'diagonal_km': round(diagonal, 3) if diagonal is not None else None,
    }


def centroid(points: Any) -> Optional[Tuple[float, float]]:
    """Planar mean of the coordinates: ``(lat, lon)``.

    A plain average of decimal degrees. For a regional evidence set
    (city, district, country) this is indistinguishable from the
    spherical mean and one line of arithmetic; it *does* distort for sets
    spanning the antimeridian (mean of +179 and -179 is 0, not 180) or
    sitting near the poles - callers showing hemispheric spreads should
    read the bounding box instead.

    Args:
        points: Iterable of :class:`GeoPoint`-like items; invalid items
            are dropped.

    Returns:
        ``(mean_lat, mean_lon)`` or ``None`` for an empty set. Never
        raises.

    Example:
        >>> centroid([(0.0, 0.0), (2.0, 4.0)])
        (1.0, 2.0)
    """
    collected = _as_points(points)
    if not collected:
        return None
    count = len(collected)
    mean_lat = sum(point.lat for point in collected) / count
    mean_lon = sum(point.lon for point in collected) / count
    return (round(mean_lat, 6), round(mean_lon, 6))


def pairwise_distances(points: Any) -> List[Dict[str, Any]]:
    """Every unordered pair of points with its great-circle distance.

    Args:
        points: Iterable of :class:`GeoPoint`-like items; invalid items
            are dropped. Fewer than two valid points yield ``[]``.

    Returns:
        List of ``{'a', 'b', 'label_a', 'label_b', 'km'}`` dicts (``a``/``b``
        are indices into the cleaned point list) sorted by distance
        ascending, ties broken by label. Never raises.

    Example:
        >>> pairs = pairwise_distances([(0.0, 0.0), (0.0, 1.0)])
        >>> round(pairs[0]['km'], 1)
        111.2
    """
    collected = _as_points(points)
    pairs: List[Dict[str, Any]] = []
    for i in range(len(collected)):
        for j in range(i + 1, len(collected)):
            distance = _distance_km(collected[i], collected[j])
            if distance is None:
                continue
            pairs.append({
                'a': i,
                'b': j,
                'label_a': _label_of(collected[i], i),
                'label_b': _label_of(collected[j], j),
                'km': round(distance, 3),
            })
    pairs.sort(key=lambda pair: (pair['km'], pair['label_a'], pair['label_b']))
    return pairs


def route_length(points: Any) -> Optional[float]:
    """Total length of the polyline through the points, in kilometres.

    The travel-distance implied by visiting the points in the given order
    (a stalking route, a courier round, a flight path). The order is the
    argument's order - no reordering happens here.

    Args:
        points: Iterable of :class:`GeoPoint`-like items; invalid items
            are dropped.

    Returns:
        Sum of consecutive great-circle segment lengths in km, ``None``
        for fewer than two valid points. Never raises.

    Example:
        >>> length = route_length([(0.0, 0.0), (0.0, 1.0), (0.0, 2.0)])
        >>> round(length, 1)
        222.4
    """
    collected = _as_points(points)
    if len(collected) < 2:
        return None
    total = 0.0
    for first, second in zip(collected, collected[1:]):
        distance = _distance_km(first, second)
        if distance is not None:
            total += distance
    return round(total, 3)


# ---------------------------------------------------------------------------
# Clustering, fences, outliers
# ---------------------------------------------------------------------------

def cluster_points(points: Any, eps_km: float = 25.0,
                   min_points: int = 2) -> List[Dict[str, Any]]:
    """DBSCAN clustering of the points in kilometre space.

    Each coordinate is projected onto a local tangent plane centred on
    the set's centroid (east-west scaled by ``cos(centroid latitude)``,
    both axes in kilometres) and fed to
    :func:`obscuralens.analytics.cluster.dbscan`, so the ``eps_km``
    radius means what it says on the label regardless of latitude.
    Cluster centroids and radii are then computed back on the sphere.

    Noise points (DBSCAN label -1) are excluded from the result - they
    are the isolated observations, and :func:`outlier_points` is the tool
    that speaks about them.

    Args:
        points: Iterable of :class:`GeoPoint`-like items; invalid items
            are dropped.
        eps_km: Cluster radius in kilometres (default 25; non-finite or
            non-positive values yield an empty result).
        min_points: Minimum cluster membership including the seed point
            (default 2; values below 1 are clamped to 1).

    Returns:
        List of ``{'centroid', 'members', 'size', 'radius_km', 'labels'}``
        dicts sorted by size descending: ``centroid`` is the
        ``(lat, lon)`` mean of the members, ``members`` their display
        labels, ``labels`` their indices into the cleaned point list,
        ``size`` the count and ``radius_km`` the greatest member distance
        from the centroid. Empty list when nothing clusters. Never
        raises.

    Example:
        >>> clusters = cluster_points([(0.0, 0.0), (0.01, 0.01),
        ...                            (0.02, 0.02), (40.0, 40.0)])
        >>> clusters[0]['size']
        3
    """
    collected = _as_points(points)
    radius = _to_float(eps_km)
    if radius is None or radius <= 0.0 or not collected:
        return []
    core = min_points if isinstance(min_points, int) and min_points >= 1 else 1

    center = centroid(collected)
    if center is None:  # pragma: no cover - collected is non-empty here
        return []
    center_lat, center_lon = center
    cosine = max(abs(math.cos(math.radians(center_lat))), _COS_FLOOR)
    plane: List[List[float]] = []
    for point in collected:
        east = (point.lon - center_lon) * _KM_PER_DEGREE * cosine
        north = (point.lat - center_lat) * _KM_PER_DEGREE
        plane.append([east, north])

    result = dbscan(plane, eps=radius, min_samples=core)
    clusters: List[Dict[str, Any]] = []
    for cluster_id in range(len(result.sizes)):
        member_indices = [index for index, label in enumerate(result.assignments)
                          if label == cluster_id]
        if not member_indices:  # pragma: no cover - sizes come from labels
            continue
        members = [collected[index] for index in member_indices]
        mean_lat = sum(point.lat for point in members) / len(members)
        mean_lon = sum(point.lon for point in members) / len(members)
        center_point = GeoPoint(mean_lat, mean_lon)
        radius_km = 0.0
        for member in members:
            distance = _distance_km(center_point, member)
            if distance is not None and distance > radius_km:
                radius_km = distance
        clusters.append({
            'centroid': (round(mean_lat, 6), round(mean_lon, 6)),
            'members': [_label_of(point, index)
                        for point, index in zip(members, member_indices)],
            'size': len(members),
            'radius_km': round(radius_km, 3),
            'labels': member_indices,
        })
    clusters.sort(key=lambda cluster: (-cluster['size'], cluster['centroid']))
    return clusters


def geofence_check(point: Any, center: Any, radius_km: float) -> Dict[str, Any]:
    """Is one point inside a circular geofence?

    Answers "was this sighting inside the exclusion zone" with the
    great-circle distance to the fence centre and the initial bearing
    from the centre to the point (compass degrees, north = 0, east = 90).
    coordinate_math computes bearings only for the Sun, so the standard
    eight-line formula lives here.

    Args:
        point: The probe point (:class:`GeoPoint`-like).
        center: The fence centre (:class:`GeoPoint`-like).
        radius_km: Fence radius in kilometres; non-finite or non-positive
            values disable the check (``'inside': False``).

    Returns:
        Dict with ``'inside'`` (bool), ``'distance_km'`` (float, rounded
        to 3 decimals) and ``'bearing'`` (degrees in ``[0, 360)``,
        rounded to 1). Unusable input yields ``{'inside': False,
        'distance_km': None, 'bearing': None}``. Never raises.

    Example:
        >>> verdict = geofence_check((48.86, 2.35), (48.86, 2.35), 10.0)
        >>> verdict['inside'], verdict['bearing']
        (True, 0.0)
    """
    invalid: Dict[str, Any] = {'inside': False, 'distance_km': None, 'bearing': None}
    probe = _coerce_point(point)
    fence = _coerce_point(center)
    radius = _to_float(radius_km)
    if probe is None or fence is None or radius is None or radius <= 0.0:
        return invalid
    distance = _distance_km(fence, probe)
    if distance is None:  # pragma: no cover - both points are validated
        return invalid

    phi1 = math.radians(fence.lat)
    phi2 = math.radians(probe.lat)
    delta_lon = math.radians(probe.lon - fence.lon)
    y = math.sin(delta_lon) * math.cos(phi2)
    x = (math.cos(phi1) * math.sin(phi2)
         - math.sin(phi1) * math.cos(phi2) * math.cos(delta_lon))
    bearing = (math.degrees(math.atan2(y, x)) + 360.0) % 360.0
    return {
        'inside': distance <= radius,
        'distance_km': round(distance, 3),
        'bearing': round(bearing, 1),
    }


def outlier_points(points: Any, factor: float = 1.5) -> List[Dict[str, Any]]:
    """Tukey-fence outliers by distance from the set's centroid.

    Every point's great-circle distance to the centroid forms a sample;
    points whose distance falls outside ``Q1 - factor*IQR`` /
    ``Q3 + factor*IQR`` are flagged - the observation that wandered off
    from where the evidence concentrates.

    Args:
        points: Iterable of :class:`GeoPoint`-like items; invalid items
            are dropped.
        factor: Fence width in IQR units (default 1.5); non-finite or
            non-positive values fall back to 1.5.

    Returns:
        List of ``{'index', 'label', 'distance_km', 'score'}`` dicts
        sorted by distance descending. ``score`` is the distance beyond
        the violated fence in IQR units (or the raw deviation from the
        median when the IQR is zero, mirroring the anomaly module's
        convention). Empty when nothing is flagged. Never raises.

    Example:
        >>> strays = outlier_points([(0.0, 0.0), (0.01, 0.01),
        ...                          (0.02, 0.02), (40.0, 40.0)])
        >>> strays[0]['label']
        'point_3'
    """
    collected = _as_points(points)
    center = centroid(collected)
    if center is None:
        return []
    width = _to_float(factor)
    if width is None or width <= 0.0:
        width = 1.5
    center_point = GeoPoint(center[0], center[1])

    distances: List[Optional[float]] = []
    for point in collected:
        distances.append(_distance_km(center_point, point))
    usable = [value for value in distances if value is not None]
    quart = quartiles(usable)
    if quart is None:
        return []
    q1, _median, q3 = quart
    spread = q3 - q1
    lower = q1 - width * spread
    upper = q3 + width * spread
    median = _median

    strays: List[Dict[str, Any]] = []
    for index, distance in enumerate(distances):
        if distance is None or lower <= distance <= upper:
            continue
        if spread > 0.0:
            score = ((distance - upper) if distance > upper else (lower - distance)) / spread
        else:
            score = abs(distance - median)
        strays.append({
            'index': index,
            'label': _label_of(collected[index], index),
            'distance_km': round(distance, 3),
            'score': round(score, 4),
        })
    strays.sort(key=lambda stray: (-stray['distance_km'], stray['label']))
    return strays


def distance_matrix(points: Any) -> Dict[str, Dict[str, Optional[float]]]:
    """Symmetric label-keyed matrix of great-circle distances.

    Args:
        points: Iterable of :class:`GeoPoint`-like items; invalid items
            are dropped.

    Returns:
        ``{label: {label: km}}`` with every label mapped to every label
        (self-distances 0.0). Labels are uniquified (empty labels become
        ``point_<i>``, duplicates gain an index suffix). Empty dict for
        an empty set. Never raises.

    Example:
        >>> matrix = distance_matrix([(0.0, 0.0, 'home'), (0.0, 1.0, 'work')])
        >>> round(matrix['home']['work'], 1)
        111.2
    """
    collected = _as_points(points)
    labels = _unique_labels(collected)
    matrix: Dict[str, Dict[str, Optional[float]]] = {
        label: dict.fromkeys(labels, None) for label in labels
    }
    for label in labels:
        matrix[label][label] = 0.0
    for i in range(len(collected)):
        for j in range(i + 1, len(collected)):
            distance = _distance_km(collected[i], collected[j])
            matrix[labels[i]][labels[j]] = (round(distance, 3)
                                            if distance is not None else None)
            matrix[labels[j]][labels[i]] = matrix[labels[i]][labels[j]]
    return matrix


def geo_summary(points: Any) -> Dict[str, Any]:
    """One-shot spatial dossier for a set of coordinates.

    The single call the report layer makes: point count, bounding box,
    centroid, farthest pair, average pairwise spacing, cluster census and
    the route length through the points in order.

    Args:
        points: Iterable of :class:`GeoPoint`-like items; invalid items
            are dropped.

    Returns:
        Dict with keys ``'point_count'``, ``'bounding_box'``, ``'centroid'``,
        ``'farthest_pair'`` (the largest :func:`pairwise_distances` entry,
        or ``None``), ``'average_pair_distance_km'``, ``'cluster_count'``,
        ``'clusters'`` (from :func:`cluster_points`) and
        ``'route_length_km'``. Empty input yields the zeroed envelope.
        Never raises.

    Example:
        >>> summary = geo_summary([(0.0, 0.0), (0.01, 0.01)])
        >>> summary['point_count'], summary['cluster_count']
        (2, 1)
    """
    collected = _as_points(points)
    pairs = pairwise_distances(collected)
    clusters = cluster_points(collected)
    if pairs:
        average = round(sum(pair['km'] for pair in pairs) / len(pairs), 3)
        farthest = dict(pairs[0])
    else:
        average = None
        farthest = None
    return {
        'point_count': len(collected),
        'bounding_box': bounding_box(collected),
        'centroid': centroid(collected),
        'farthest_pair': farthest,
        'average_pair_distance_km': average,
        'cluster_count': len(clusters),
        'clusters': clusters,
        'route_length_km': route_length(collected),
    }
