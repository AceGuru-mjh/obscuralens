"""
CVE Tracker Module
Aggregates vulnerability intelligence (NVD, OSV, cvelistV2, EPSS) for a CVE identifier.

Sources (all keyless, see ``cve_sources`` for details):

* ``nvd``        - description, best CVSS metric (V3.1 > V3.0 > V2), CWE,
                   references and affected CPEs; optional API key for rate
                   limits.
* ``osv``        - affected packages (de-duplicated) and CVSS vector.
* ``cvelistV2``  - the CNA-published record straight from the CVEProject
                   repository (title, state, affected products).
* ``epss``       - FIRST.org exploitation probability, rescaled to 0..100.

``CVETracker.track`` returns::

    {
      'cve': 'CVE-2021-44228',          # normalised identifier
      'info': {...merged fields...},    # always includes 'cve'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['nvd', 'osv', ...],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers short-circuit to a failure dict without touching the
network, metrics or query history. Successful and failed lookups alike are
saved to history via ``db.save_query('cve', ...)`` so ``obscuralens
history`` can replay them.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_cve, validate_cve
from .cve_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class CVETracker:
    """Multi-source CVE tracker.

    A single ``track()`` call fans out to every enabled keyless source (plus
    an optional NVD API key when configured), merges the answers
    field-by-field with provenance, records source health metrics and saves
    the outcome to query history::

        from obscuralens.trackers.cve_tracker import CVETracker

        report = CVETracker().track('cve-2021-44228')
        if report['success']:
            print(report['info'].get('cvss_score'),
                  report['field_sources'].get('cvss_score'))
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def _keys(self) -> Dict[str, str]:
        """API keys relevant to CVE lookups (only NVD accepts an optional one)."""
        return {
            service: config.get_api_key(service) or ''
            for service in ('nvd',)
        }

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``cve_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in CVE source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, identifier: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'cve': identifier if isinstance(identifier, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid CVE identifier'],
        }

    def track(self, identifier: str) -> Dict[str, Any]:
        """
        Track a CVE identifier across all data sources.

        Args:
            identifier: CVE id such as ``CVE-2021-44228``; case-insensitive,
                surrounding whitespace is ignored

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history.
        """
        valid, error = validate_cve(identifier or '')
        if not valid:
            return self._failure(identifier, error)

        cve = normalize_cve(identifier)
        gathered = gather_all(cve, self._keys())
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'cve': cve,
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

        db.save_query('cve', cve, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, identifiers: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple CVE identifiers concurrently.

        Each identifier goes through ``track`` independently, so one invalid
        or failing entry never poisons the rest of the batch.

        Args:
            identifiers: List of CVE ids (invalid entries yield failure dicts)
            workers: Parallel worker count

        Returns:
            List of tracking results, in input order (blanks are dropped)
        """
        targets = [t for t in (str(i).strip() for i in identifiers or []) if t]
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
                        'cve': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
