"""
VIN Tracker Module
Aggregates vehicle intelligence (offline ISO 3779 decomposition, curated WMI
pack, NHTSA vPIC enrichment) for a Vehicle Identification Number.

A VIN answers "which vehicle is this": the World Manufacturer Identifier
resolves to a manufacturer and assembly country (offline curated pack), the
transliterated check digit at position 9 guards against typos, the year code
at position 10 narrows the model year to two 30-year-cycle candidates, the
plant code names the factory and the trailing six digits are the production
serial. One ``track()`` call fans out to every enabled source, merges answers
field-by-field with provenance, records source health metrics and saves the
outcome to query history.

Sources (see ``vin_sources`` for details):

* ``vin_math``   - ISO 3779 decomposition: WMI, region hint, year code with
  both model-year candidates, check digit verdict, plant code, serial and
  the full position map; manufacturer and country come from the shipped
  WMI pack.
* ``nhtsa_vpic`` - keyless NHTSA vPIC decoder: make, model, model year,
  vehicle type, body class, engine/drive/fuel details and the assembly
  plant city/state/country for North American market vehicles.

``VINTracker.track`` returns::

    {
      'vin': '1M8GDM9AXKP042788',       # normalised 17-character VIN
      'info': {...merged fields...},    # always includes 'vin'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['vin_math', 'nhtsa_vpic'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (wrong length, disallowed characters, failed check
digit) short-circuit to a failure dict without touching the network,
metrics or query history. Everything else is saved via
``db.save_query('vin', <vin>, ...)`` so ``obscuralens history`` can replay
the lookup. The offline math source always succeeds, so VIN reports work
with the network down - that is the point of the pack.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_vin, validate_vin
from .vin_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class VINTracker:
    """Multi-source VIN (Vehicle Identification Number) tracker.

    A single ``track()`` call fans out to every enabled source, merges the
    answers field-by-field with provenance, records source health metrics
    and saves the outcome to query history::

        from obscuralens.trackers.vin_tracker import VINTracker

        report = VINTracker().track('1M8GDM9AXKP042788')
        if report['success']:
            print(report['info'].get('manufacturer'),
                  report['info'].get('model_year_candidates'))

    Because the offline math source needs no registry to decompose the
    identifier (and the curated WMI pack ships inside the package), a report
    always succeeds for a well-formed VIN, with or without network access.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``vin_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in VIN source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'vin': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid VIN'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track a VIN across all data sources.

        Args:
            value: 17-character VIN; hyphens, spaces and lower case are
                tolerated

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers (wrong shape or failed ISO 3779
            check digit) return a failure dict with ``success=False`` and
            never reach the sources, the metrics or query history.
        """
        valid, error = validate_vin(value or '')
        if not valid:
            return self._failure(value, error)

        vin = normalize_vin(value)
        gathered = gather_all(vin, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'vin': vin,
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

        db.save_query('vin', vin, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple VINs concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of VIN strings (invalid entries yield failure
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
                        'vin': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
