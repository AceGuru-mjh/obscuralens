"""
Domain Tracker Module
Aggregates registration, DNS, Certificate Transparency and HTTP data for a domain.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from .domain_sources import gather_all


class DomainTracker:
    """Domain Tracker with multi-source aggregation"""

    def __init__(self):
        self.timeout = config.app_config.request_timeout

    def track(self, domain: str) -> Dict[str, Any]:
        """
        Track a domain across all data sources.

        Args:
            domain: Domain name to track

        Returns:
            Dictionary containing merged fields, per-source status and errors
        """
        domain = domain.strip().lower()
        gathered = gather_all(domain)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'domain': domain,
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

        db.save_query('domain', domain, result, result['success'],
                      '; '.join(result['errors']))

        return result

    def batch_track(self, domains: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple domains concurrently.

        Args:
            domains: List of domain names
            workers: Parallel worker count

        Returns:
            List of tracking results, in input order
        """
        targets = [d.strip() for d in domains if d.strip()]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self.track, d): i for i, d in enumerate(targets)}
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        'domain': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
