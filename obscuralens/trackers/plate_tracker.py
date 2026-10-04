"""
Plate Tracker Module (v6.0)
Aggregates license plate intelligence (offline curated format pack, offline
character composition analysis) for a vehicle registration plate.

A plate value answers "which jurisdiction issued this plate": free-form
registration text, optionally prefixed with the issuing country
(``DE:B-AB 1234``, ``GB:AB12 CDE``, ``US-CA:8ABC123``). The curated format
pack matches the text against 79 national patterns and reports every
jurisdiction whose shape fits (with a confidence per match); the
composition math analyses letters, digits and separators, resolves German
city codes from the distinguishing sign and applies an EU-style vs
North-American-style heuristic. One ``track()`` call fans out to the
offline sources, merges answers field-by-field with provenance, records
source health metrics and saves the outcome to query history.

Sources (see ``plate_sources`` for details):

* ``plate_pack`` - offline curated plate format pack: the parsed country
  prefix, the matched-country candidate list (country, region, example,
  confidence) and a note explaining the matching outcome.
* ``plate_math`` - offline composition analysis: letter/digit counts,
  separators, length, the German city-code special case and the
  EU / North American style heuristic.

``PlateTracker.track`` returns::

    {
      'plate': 'DE:B-AB 1234',        # normalised plate text
      'info': {...merged fields...},  # always includes 'plate'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['plate_pack', 'plate_math'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (too short, too long, non-printable characters)
short-circuit to a failure dict without touching the network, metrics or
query history. Everything else is saved via ``db.save_query('plate',
<plate>, ...)`` so ``obscuralens history`` can replay the lookup. Both
sources are offline by design - national plate registries are paywalled or
gated behind lawful-purpose attestation everywhere, so a plate report here
is honest format intelligence, never an owner lookup.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_plate, validate_plate
from .plate_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class PlateTracker:
    """Multi-source license plate tracker (fully offline).

    A single ``track()`` call fans out to the enabled sources, merges the
    answers field-by-field with provenance, records source health metrics
    and saves the outcome to query history::

        from obscuralens.trackers.plate_tracker import PlateTracker

        report = PlateTracker().track('DE:B-AB 1234')
        if report['success']:
            print([m['country'] for m in report['info']['matched_countries']])
            print(report['info'].get('german_city'))

    Because both sources need nothing but the shipped format pack and the
    plate text itself, a report always succeeds for a well-formed plate,
    with or without network access.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``plate_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in plate source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'plate': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid license plate'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track a license plate across the offline data sources.

        Args:
            value: plate text, optionally prefixed with the issuing country
                (``'DE:B-AB 1234'``, ``'GB:AB12 CDE'``, ``'US-CA:8ABC123'``);
                lower case and doubled spaces are tolerated

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history.
        """
        valid, error = validate_plate(value or '')
        if not valid:
            return self._failure(value, error)

        plate = normalize_plate(value)
        gathered = gather_all(plate, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'plate': plate,
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

        db.save_query('plate', plate, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple license plates concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of plate strings (invalid entries yield failure
                dicts)
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
                        'plate': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
