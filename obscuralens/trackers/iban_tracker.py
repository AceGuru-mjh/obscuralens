"""
IBAN Tracker Module
Aggregates banking intelligence (offline mod-97 arithmetic, structure pack,
openiban) for an International Bank Account Number.

An IBAN answers "which bank holds this account": the ISO 13616 mod-97
checksum validates the identifier before anything else happens, the country
prefix selects a published per-country BBAN structure (offline registry
pack), the front of the BBAN identifies the bank, and openiban's keyless API
cross-checks the verdict and resolves the BIC. One ``track()`` call fans out
to every enabled source, merges answers field-by-field with provenance,
records source health metrics and saves the outcome to query history.

Sources (see ``iban_sources`` for details):

* ``iban_math``         - offline mod-97 checksum verdict, country prefix,
  check digits, BBAN, length, spaced pretty format and masked account hint.
* ``iban_structure_pack`` - offline per-country registry pack: country name,
  expected length, ``structure_ok`` verdict, bank code and account number.
* ``openiban``          - openiban.com online validation with BIC resolution
  (fails gracefully when unreachable - the offline sources carry the day).

``IBANTracker.track`` returns::

    {
      'iban': 'DE89370400440532013000',  # canonical uppercase space-free
      'info': {...merged fields...},     # always includes 'iban'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['iban_math', 'iban_structure_pack'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

The checksum is validated FIRST (``validators.validate_iban``: format plus
mod-97), so typo'd identifiers such as ``'DE89370400440532013001'``
short-circuit to a failure dict without touching the network, metrics or
query history. Everything else is saved via ``db.save_query('iban',
<canonical iban>, ...)`` so ``obscuralens history`` can replay the lookup.
Two of the three sources are pure offline computation, so IBAN reports still
succeed when every online API is unreachable.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_iban, validate_iban
from .iban_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class IBANTracker:
    """Multi-source IBAN tracker.

    A single ``track()`` call validates the mod-97 checksum, fans out to
    every enabled source, merges the answers field-by-field with provenance,
    records source health metrics and saves the outcome to query history::

        from obscuralens.trackers.iban_tracker import IBANTracker

        report = IBANTracker().track('DE89370400440532013000')
        if report['success']:
            print(report['info'].get('bank_code'),
                  report['info'].get('country_name'))

    Because ``iban_math`` and ``iban_structure_pack`` are pure offline
    computation, a report still succeeds (checksum verdict, structure
    verdict, bank code, country) when openiban is unreachable.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``iban_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in IBAN source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'iban': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid IBAN'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track an IBAN across all data sources.

        The mod-97 checksum is validated before anything else: a typo'd
        IBAN is rejected on the spot instead of being decomposed and saved.

        Args:
            value: IBAN such as ``'DE89370400440532013000'`` or the spaced
                printed form ``'DE89 3704 0044 0532 0130 00'``; lowercase
                input and a leading ``'iban:'`` marker are tolerated

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers (bad shape or failed mod-97
            checksum) return a failure dict with ``success=False`` and never
            reach the sources, the metrics or query history.
        """
        valid, error = validate_iban(value or '')
        if not valid:
            return self._failure(value, error)

        iban = normalize_iban(value)
        gathered = gather_all(iban, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'iban': iban,
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

        db.save_query('iban', iban, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple IBANs concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of IBAN strings (invalid entries yield failure
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
                        'iban': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
