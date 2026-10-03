"""
Coordinates Tracker Module (v5.0)
Aggregates place intelligence (Nominatim, BigDataCloud, Open-Elevation) for a
geographic position.

Coordinates answer "what is here": the street address and administrative
hierarchy, the ground elevation, the gridded notations (UTM / MGRS /
geohash / Maidenhead), and the solar geometry that photo-verification OSINT
needs. One ``track()`` call parses any accepted syntax (decimal degrees,
DMS, UTM, MGRS), fans out to every enabled source, merges answers
field-by-field with provenance, records source health metrics and saves the
outcome to query history.

Sources (see ``coords_sources`` for details):

* ``nominatim``         - OpenStreetMap reverse geocoding: address, city,
  region, country, OSM ids, place category (keyless).
* ``bigdatacloud``      - BigDataCloud free client endpoint: locality, city,
  principal subdivision, country (keyless).
* ``open_elevation``    - Open-Elevation SRTM terrain height in metres
  (keyless).
* ``geohash_local``     - offline coordinate maths: geohash, Maidenhead,
  DMS/DDM strings, UTM, MGRS, timezone hint and solar position.
* ``country_centroids`` - offline nearest-country pack for offline lookups.

``CoordsTracker.track`` returns::

    {
      'coords': '48.858400, 2.294500',  # normalised display form
      'info': {...merged fields...},    # always includes latitude/longitude
      'field_sources': {field: [source, ...]},
      'sources_ok': ['geohash_local', 'nominatim'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (``'banana'``, out-of-range numbers, unparseable grids)
short-circuit to a failure dict without touching the network, metrics or
query history. Everything else is saved via ``db.save_query('coords',
'lat,lon', ...)`` so ``obscuralens history`` can replay the lookup. Because
the offline ``geohash_local`` source always succeeds, ``info`` still
carries the latitude/longitude and every re-encoding even when all online
sources fail - the lookup is only a failure when the input cannot be
parsed at all.
"""

import concurrent.futures as futures
from typing import Any, Dict, List, Tuple

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import parse_coords, validate_coords
from .coords_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class CoordsTracker:
    """Multi-source geographic coordinates tracker.

    A single ``track()`` call parses the input in any accepted notation,
    fans out to every enabled keyless source, merges the answers
    field-by-field with provenance, records source health metrics and saves
    the outcome to query history::

        from obscuralens.trackers.coords_tracker import CoordsTracker

        report = CoordsTracker().track('48.8584, 2.2945')
        if report['success']:
            print(report['info'].get('formatted_address'),
                  report['info'].get('geohash'))

    Accepted input syntaxes (see ``utils.validators``): decimal degrees
    ``'48.8584, 2.2945'``, DMS ``"N 48° 51' 29\", E 2° 17' 40\""`` , UTM
    ``'31U 448288 5411087'`` and MGRS ``'31U DQ 48288 11087'``.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``coords_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in coordinate source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'coords': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid coordinates'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track a geographic position across all data sources.

        Args:
            value: coordinates in decimal degrees, DMS, UTM or MGRS form,
                e.g. ``'48.8584, 2.2945'`` or ``'31U DQ 48288 11087'``

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Unparseable identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history. Successful lookups always include
            ``latitude`` / ``longitude`` in ``info`` (plus the offline
            re-encodings), even when every online source fails.
        """
        valid, error = validate_coords(value or '')
        if not valid:
            return self._failure(value, error)

        try:
            parsed = parse_coords(value or '')
        except ValueError as exc:
            # validate_coords accepts the syntax, but the gridded conversion
            # maths rejected it (e.g. UTM zone 61); that is a parse failure.
            return self._failure(value, str(exc))
        if parsed is None:
            return self._failure(value, 'coordinates could not be parsed')

        lat, lon = parsed
        gathered = gather_all(value, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        display = f"{lat:.6f}, {lon:.6f}"
        result: Dict[str, Any] = {
            'coords': display,
            'info': fields,
            'field_sources': gathered.get('provenance', {}),
            'sources_ok': sorted(ok_sources),
            'sources_failed': failed,
            'field_count': len([v for v in fields.values()
                                if v is not None and v != '' and v != [] and v != {}]),
            'success': bool(ok_sources),
            'errors': [],
        }

        if not ok_sources:
            result['errors'].append('all data sources failed')
        elif failed:
            result['errors'].append(f"{len(failed)} source(s) unavailable")

        # The history value is the normalised 'lat,lon' pair, so replayed
        # lookups re-parse losslessly from decimal degrees.
        db.save_query('coords', display, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple coordinate positions concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of coordinate strings (invalid entries yield
                failure dicts)
            workers: Parallel worker count

        Returns:
            List of tracking results, in input order (blanks are dropped)
        """
        targets = [t for t in (str(v).strip() for v in values or []) if t]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self.track, t): idx
                          for idx, t in enumerate(targets)}
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        'coords': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results

    def nearby(self, lat: float, lon: float, km: float) -> Dict[str, float]:
        """
        Bounding box around a tracked position (convenience wrapper).

        Delegates to ``coordinate_math.bbox_around``; useful for building
        map viewport parameters from a lookup result.
        """
        from ..utils import coordinate_math

        return coordinate_math.bbox_around(lat, lon, km)

    def distance(self, first: Tuple[float, float], second: Tuple[float, float]) -> float:
        """
        Great-circle distance in km between two ``(lat, lon)`` pairs.

        Delegates to ``coordinate_math.haversine_km``; handy for measuring
        the gap between two tracked positions in one call.
        """
        from ..utils import coordinate_math

        return coordinate_math.haversine_km(first[0], first[1], second[0], second[1])
