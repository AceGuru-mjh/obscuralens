"""
IP Tracker Module
Aggregates every available data source for an IP address.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..database import db
from ..utils.http_client import http
from .ip_sources import gather_all


class IPTracker:
    """Enhanced IP Tracker with multi-source aggregation"""

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def track(self, ip: str) -> Dict[str, Any]:
        """
        Track an IP address across all data sources.

        Args:
            ip: IP address to track

        Returns:
            Dictionary containing merged fields, per-source status and errors
        """
        shodan_key = config.get_api_key('shodan') or ''
        vt_key = config.get_api_key('virustotal') or ''

        gathered = gather_all(ip, shodan_key, vt_key)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}

        result: Dict[str, Any] = {
            'ip': ip,
            'info': fields,
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

        db.save_query('ip', ip, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def get_own_ip(self) -> str:
        """Get your own public IP address"""
        response = http.get('https://api.ipify.org/')
        response.raise_for_status()
        return response.text.strip()

    def own_info(self) -> Dict[str, Any]:
        """Full report for the machine's own public IP."""
        try:
            ip = self.get_own_ip()
        except Exception:
            return {'success': False, 'error': 'could not determine public IP'}
        result = self.track(ip)
        result['is_self'] = True
        return result

    def batch_track(self, ips: List[str], workers: int = 5) -> List[Dict[str, Any]]:
        """
        Track multiple IP addresses concurrently.

        Args:
            ips: List of IP addresses
            workers: Parallel worker count

        Returns:
            List of tracking results, in input order
        """
        targets = [ip.strip() for ip in ips if ip.strip()]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self.track, ip): i for i, ip in enumerate(targets)}
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        'ip': targets[idx],
                        'info': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
