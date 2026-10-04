"""
MMSI Tracker Module
Aggregates maritime station intelligence (offline ITU-R M.1085 structure
decode, curated MID flag-country pack) for a Maritime Mobile Service
Identity.

An MMSI answers "which station is this on the water": the leading digits
classify the station (individual ship, coast station, group identity,
handheld VHF, AIS aid to navigation), the Maritime Identification Digit in
the middle names the flag country through the offline curated pack, and
the remaining digits are the station serial. One ``track()`` call fans out
to every enabled source, merges answers field-by-field with provenance,
records source health metrics and saves the outcome to query history.

Sources (all offline, see ``mmsi_sources`` for details):

* ``mmsi_math`` - ITU-R M.1085 structure decode: station class, MID,
  serial digits, ITU series label and the conservative trailing-zero note.
* ``mid_pack``  - curated MID pack: the flag country for the station's MID.

``MMSITracker.track`` returns::

    {
      'mmsi': '366910000',             # normalised nine-digit string
      'info': {...merged fields...},   # always includes 'mmsi'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['mmsi_math', 'mid_pack'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (wrong digit count, non-digits) short-circuit to a
failure dict without touching the network, metrics or query history.
Everything else is saved via ``db.save_query('mmsi', <digits>, ...)`` so
``obscuralens history`` can replay the lookup. Both sources are pure
offline computation, so MMSI reports work with the network down - that is
the point of the pack.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_mmsi, validate_mmsi
from .mmsi_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class MMSITracker:
    """Multi-source MMSI (Maritime Mobile Service Identity) tracker.

    A single ``track()`` call fans out to every enabled source, merges the
    answers field-by-field with provenance, records source health metrics
    and saves the outcome to query history::

        from obscuralens.trackers.mmsi_tracker import MMSITracker

        report = MMSITracker().track('366910000')
        if report['success']:
            print(report['info'].get('station_type'),
                  report['info'].get('country'))

    Because both sources are pure offline computation (math decomposition
    plus a curated pack shipped inside the package), a report always
    succeeds for a well-formed MMSI, with or without network access.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``mmsi_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in MMSI source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'mmsi': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid MMSI'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track an MMSI across all data sources.

        Args:
            value: nine-digit MMSI; integers, hyphen/space separated forms
                (``'366-910-000'``) and a ``'MMSI:'`` prefix marker are
                tolerated

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers (wrong digit count or non-digits)
            return a failure dict with ``success=False`` and never reach the
            sources, the metrics or query history.
        """
        valid, error = validate_mmsi(value if value is not None else '')
        if not valid:
            return self._failure(value, error)

        digits = normalize_mmsi(value)
        gathered = gather_all(digits, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'mmsi': digits,
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

        db.save_query('mmsi', digits, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple MMSIs concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of MMSI strings or integers (invalid entries yield
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
                        'mmsi': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
