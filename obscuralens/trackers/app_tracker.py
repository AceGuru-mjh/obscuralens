"""
App Tracker Module (v6.0)
Aggregates software package intelligence (offline ecosystem metadata, pypi /
npm / crates.io / Docker Hub / GitHub registry records, OSV vulnerability
queries) for an ``<ecosystem>:<name>`` package coordinate.

An app coordinate answers "what is this software": the ecosystem names the
registry that owns the name (Python Package Index, npm registry, crates.io,
Docker Hub or GitHub), and the registry record carries the version, summary,
author, license, download footprint, maintenance timestamps and - through
OSV - the known vulnerabilities. One ``track()`` call fans out to the
applicable sources (the ecosystem filters the task list: only pack_meta,
the one matching registry reader and, when applicable, osv are scheduled),
merges answers field-by-field with provenance, records source health metrics
and saves the outcome to query history.

Sources (see ``app_sources`` for details):

* ``pack_meta`` - offline ecosystem metadata: registry URL template,
  package-name conventions, mirror notes, namespace and package name.
* ``pypi`` / ``npm`` / ``crates`` / ``dockerhub`` / ``github`` - the one
  keyless registry reader matching the coordinate's ecosystem.
* ``osv`` - keyless OSV.dev vulnerability query for PyPI / npm / crates.io
  packages (vulnerability count plus per-CVE id/summary/severity records).

``AppTracker.track`` returns::

    {
      'app': 'pypi:requests',          # normalised <ecosystem>:<name>
      'info': {...merged fields...},   # always includes 'app' and ecosystem
      'field_sources': {field: [source, ...]},
      'sources_ok': ['pack_meta', 'pypi', 'osv'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (missing ecosystem prefix, unknown ecosystem, a name
that violates the ecosystem grammar) short-circuit to a failure dict
without touching the network, metrics or query history. Everything else is
saved via ``db.save_query('app', <coordinate>, ...)`` so
``obscuralens history`` can replay the lookup. The offline metadata source
always succeeds, so app reports work with the network down - that is the
point of the built-in table.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_app, validate_app
from .app_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class AppTracker:
    """Multi-source software package tracker.

    A single ``track()`` call fans out to every applicable source, merges the
    answers field-by-field with provenance, records source health metrics
    and saves the outcome to query history::

        from obscuralens.trackers.app_tracker import AppTracker

        report = AppTracker().track('pypi:requests')
        if report['success']:
            print(report['info'].get('ecosystem'),
                  report['info'].get('latest_version'))

    Because the offline ``pack_meta`` source needs nothing but the
    coordinate itself, a report always succeeds for a well-formed app value,
    with or without network access.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``app_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in app source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'app': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid app coordinate'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track a software package coordinate across the applicable sources.

        Args:
            value: package coordinate such as ``'pypi:requests'``,
                ``'npm:@babel/core'``, ``'crate:serde'``,
                ``'docker:library/nginx'`` or ``'github:owner/repo'``;
                the ecosystem prefix is case-insensitive

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history.
        """
        valid, error = validate_app(value or '')
        if not valid:
            return self._failure(value, error)

        app = normalize_app(value)
        gathered = gather_all(app, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'app': app,
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

        db.save_query('app', app, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple package coordinates concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of package coordinate strings (invalid entries
                yield failure dicts)
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
                        'app': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
