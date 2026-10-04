"""
Flight Tracker Module
Aggregates flight intelligence (offline airline pack, offline designator
anatomy, optional aviationstack live status) for a flight designator.

A flight designator answers "which airline operates this flight": the
carrier code resolves to the airline's name, country and radio callsign
(offline curated pack), the numeric run carries airline-specific numbering
conventions, and - when an aviationstack key is configured - the live
rotation confirms status, airports and aircraft. One ``track()`` call fans
out to every enabled source, merges answers field-by-field with provenance,
records source health metrics and saves the outcome to query history.

Sources (see ``flight_sources`` for details):

* ``airline_pack``  - offline curated airline pack: airline name, country,
  IATA/ICAO codes and the radio callsign for 134 well-documented carriers.
* ``flight_math``   - offline designator anatomy: IATA/ICAO renderings, the
  ``{ICAO}{number}`` radio callsign, odd/even direction convention and the
  number-band convention notes (all labelled as conventions, not evidence).
* ``aviationstack`` - keyed live-flight API: status, departure/arrival
  airports and scheduled times, aircraft registration (only with a key).

``FlightTracker.track`` returns::

    {
      'flight': 'BA2490',              # normalised designator
      'info': {...merged fields...},   # always includes 'flight'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['airline_pack', 'flight_math'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (wrong carrier shape, too many digits) short-circuit to
a failure dict without touching the network, metrics or query history.
Everything else is saved via ``db.save_query('flight', <designator>, ...)``
so ``obscuralens history`` can replay the lookup. Both offline sources are
pure computation plus a shipped pack, so flight reports work with the
network down - that is the point of the pack.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_flight, validate_flight
from .flight_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class FlightTracker:
    """Multi-source flight designator (IATA/ICAO flight number) tracker.

    A single ``track()`` call fans out to every enabled source, merges the
    answers field-by-field with provenance, records source health metrics
    and saves the outcome to query history::

        from obscuralens.trackers.flight_tracker import FlightTracker

        report = FlightTracker().track('BA2490')
        if report['success']:
            print(report['info'].get('airline_name'),
                  report['info'].get('callsign'))

    Because both offline sources need nothing but the shipped airline pack,
    a report always succeeds for a well-formed designator, with or without
    network access or an aviationstack key.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def _keys(self) -> Dict[str, str]:
        """Configured API keys for the keyed flight sources."""
        return {
            service: config.get_api_key(service) or ''
            for service in ('aviationstack',)
        }

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``flight_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in flight source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'flight': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid flight designator'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track a flight designator across all data sources.

        Args:
            value: designator such as ``'UA1'``, ``'BA2490'`` or
                ``'DLH400A'``; spaces, hyphens and lower case are tolerated

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history.
        """
        valid, error = validate_flight(value or '')
        if not valid:
            return self._failure(value, error)

        designator = normalize_flight(value)
        gathered = gather_all(designator, keys=self._keys())
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'flight': designator,
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

        db.save_query('flight', designator, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple flight designators concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of designator strings (invalid entries yield
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
                        'flight': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
