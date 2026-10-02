"""
ASN Tracker Module
Aggregates routing intelligence (RIPEstat, BGPView) for an autonomous system number.

An AS number answers "who is this network": the registry holder, the country
of registration, the website and abuse contact, the prefixes announced to
the global table and the ASes it peers with. One ``track()`` call fans out
to every enabled source, merges answers field-by-field with provenance,
records source health metrics and saves the outcome to query history.

Sources (all keyless, see ``asn_sources`` for details):

* ``ripestat`` - RIPE NCC holder/description plus announced prefixes with
  an IPv4/IPv6 split.
* ``bgpview``  - BGPView record (name, country, website, email), separated
  v4/v6 prefix lists and the de-duplicated peer graph.

``ASNTracker.track`` returns::

    {
      'asn': 15169,                     # normalised integer AS number
      'info': {...merged fields...},    # always includes 'asn'/'asn_display'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['bgpview', 'ripestat'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (``'AS0'``, ``'banana'``, out-of-range numbers) short-
circuit to a failure dict without touching the network, metrics or query
history. Everything else is saved via ``db.save_query('asn', str(num), ...)``
so ``obscuralens history`` can replay the lookup.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_asn, validate_asn
from .asn_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class ASNTracker:
    """Multi-source autonomous system tracker.

    A single ``track()`` call fans out to every enabled keyless source,
    merges the answers field-by-field with provenance, records source health
    metrics and saves the outcome to query history::

        from obscuralens.trackers.asn_tracker import ASNTracker

        report = ASNTracker().track('AS15169')
        if report['success']:
            print(report['info'].get('asn_name'),
                  report['info'].get('announced_prefix_count'))
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``asn_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in ASN source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'asn': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid AS number'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track an AS number across all data sources.

        Args:
            value: AS number such as ``'AS15169'`` or ``'15169'``

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history.
        """
        valid, error = validate_asn(value or '')
        if not valid:
            return self._failure(value, error)

        num = normalize_asn(value)
        gathered = gather_all(num, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'asn': num,
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

        db.save_query('asn', str(num), result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple AS numbers concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of AS numbers (invalid entries yield failure dicts)
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
                        'asn': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
