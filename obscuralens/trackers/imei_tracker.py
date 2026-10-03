"""
IMEI Tracker Module
Aggregates device intelligence (offline decomposition, curated TAC pack) for
an IMEI or IMEISV identifier.

An IMEI answers "which device is this": the TAC prefix resolves to a
manufacturer and model family (offline curated pack), the reporting body
identifier names the certification body (PTCRB / BABT / TAF / ...), the
serial number distinguishes the physical handset and the check digit guards
against typos with the Luhn rule. One ``track()`` call fans out to every
enabled source, merges answers field-by-field with provenance, records
source health metrics and saves the outcome to query history.

Sources (all offline, see ``imei_sources`` for details):

* ``imei_math`` - 3GPP TS 23.003 decomposition: TAC, reporting body, SNR,
  check digit, IMEISV software version digit, Luhn validity, pretty format.
* ``tac_pack``  - curated TAC pack: manufacturer + model family hint for the
  first-8 match (iPhones, Galaxies, Pixels, Xiaomi, IoT modems, ...).

``IMEITracker.track`` returns::

    {
      'imei': '356938035643809',        # normalised digit string
      'info': {...merged fields...},    # always includes 'imei'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['imei_math', 'tac_pack'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (wrong digit count, non-digits, failed Luhn check)
short-circuit to a failure dict without touching the network, metrics or
query history. Everything else is saved via ``db.save_query('imei', <digit
string>, ...)`` so ``obscuralens history`` can replay the lookup. Both
sources are pure offline computation, so IMEI reports work with the network
down - that is the point of the pack.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_imei, validate_imei
from .imei_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class IMEITracker:
    """Multi-source IMEI / IMEISV tracker.

    A single ``track()`` call fans out to every enabled source, merges the
    answers field-by-field with provenance, records source health metrics
    and saves the outcome to query history::

        from obscuralens.trackers.imei_tracker import IMEITracker

        report = IMEITracker().track('356938035643809')
        if report['success']:
            print(report['info'].get('manufacturer'),
                  report['info'].get('model'))

    Because both sources are pure offline computation (math decomposition
    plus a curated pack shipped inside the package), a report always
    succeeds for a well-formed IMEI, with or without network access.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``imei_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in IMEI source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'imei': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid IMEI'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track an IMEI or IMEISV across all data sources.

        Args:
            value: IMEI such as ``'356938035643809'`` or IMEISV (16 digits);
                spaces, dashes and dots are tolerated

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers (wrong shape or failed Luhn check)
            return a failure dict with ``success=False`` and never reach the
            sources, the metrics or query history.
        """
        valid, error = validate_imei(value or '')
        if not valid:
            return self._failure(value, error)

        digits = normalize_imei(value)
        gathered = gather_all(digits, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'imei': digits,
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

        db.save_query('imei', digits, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple IMEIs concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of IMEI/IMEISV strings (invalid entries yield
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
                        'imei': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
