"""
URL Tracker Module
Aggregates redirect-chain, archive and reputation data for a URL target.

A URL report answers "where does this link land, who has seen it before and
is it dangerous": the manual redirect walk from ``http_probe``, the urlscan.io
scan history, Wayback Machine captures and - when keys are configured -
Google Safe Browsing and VirusTotal verdicts. The result also exposes the
host as a ``domain`` key whenever it is a real domain, so investigation
pipelines can pivot from a phishing URL straight into a domain scan.

Usage::

    from obscuralens.trackers.url_tracker import URLTracker

    result = URLTracker().track('https://suspicious.example/login')
    if result['success']:
        print(result['info']['final_url'])
        for signal in URLTracker.risk_signals(result):
            print('!', signal)
"""

import concurrent.futures as futures
from typing import Any, Dict, List, Tuple

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import url_parts, validate_url
from .url_sources import gather_all

__all__ = ['URLTracker']


class URLTracker:
    """Enhanced URL Tracker with multi-source aggregation"""

    #: Services whose API keys unlock the keyed URL sources.
    KEYED_SERVICES = ('google_safe_browsing', 'virustotal')

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    @staticmethod
    def is_trackable(url: str) -> bool:
        """Whether the target is a URL this tracker can process."""
        return validate_url((url or '').strip())[0]

    def _keys(self) -> Dict[str, str]:
        """API keys for the keyed URL sources ('' when not configured)."""
        return {
            service: config.get_api_key(service) or ''
            for service in self.KEYED_SERVICES
        }

    def _invalid_result(self, url: str, error: str) -> Dict[str, Any]:
        """
        Result dict for a target that never reached the sources.

        Kept structurally identical to a successful result so callers and
        reports can render both without branching on shape.
        """
        return {
            'url': url,
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid URL'],
        }

    def track(self, url: str) -> Dict[str, Any]:
        """
        Track a URL across all data sources.

        The target is validated first (http/https/ftp, sane host and port);
        an invalid URL returns the failure shape immediately and is never
        sent to the sources or written to history.

        Args:
            url: URL to track

        Returns:
            Dictionary containing merged fields, per-source status and errors
        """
        url = (url or '').strip()
        valid, error = validate_url(url)
        if not valid:
            # No db.save_query here: invalid input is a caller bug, not a scan.
            return self._invalid_result(url, error)

        gathered = gather_all(url, self._keys())
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'url': url,
            'info': fields,
            'field_sources': gathered.get('provenance', {}),
            'sources_ok': sorted(ok_sources),
            'sources_failed': failed,
            'field_count': len([v for v in fields.values()
                                if v is not None and v != '' and v != [] and v != {}]),
            'success': bool(ok_sources),
            'errors': [],
        }

        # Domain pivot: expose the host when it is a registrable domain so
        # `investigate` can chain url -> domain scans without re-parsing.
        if fields.get('domain'):
            result['domain'] = fields['domain']

        if not ok_sources:
            result['errors'].append('all data sources failed')
        elif failed:
            result['errors'].append(f"{len(failed)} source(s) unavailable")

        db.save_query('url', url, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def track_many(self, urls: List[str]) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Track several URLs sequentially, separating valid from invalid ones.

        Useful for paste-bin style input where one bad line should not abort
        a batch of otherwise good targets.

        Returns:
            (results_for_valid_targets, errors_for_invalid_targets)
        """
        results: List[Dict[str, Any]] = []
        invalid: List[str] = []
        for candidate in urls:
            candidate = (candidate or '').strip()
            if not candidate:
                continue
            if self.is_trackable(candidate):
                results.append(self.track(candidate))
            else:
                invalid.append(candidate)
        return results, invalid

    @staticmethod
    def risk_signals(result: Dict[str, Any]) -> List[str]:
        """
        Short human-readable flags for the riskiest properties of a scan.

        Intended for quick triage in the CLI/TUI: entries are ordered from
        most to least severe and the list is empty when the URL looks
        unremarkable (or when the scan failed outright).

        Args:
            result: a tracker result (as returned by :meth:`track`)

        Returns:
            List of one-line risk descriptions
        """
        info = result.get('info') or {}
        signals: List[str] = []

        if info.get('gsb_malicious'):
            threat_types = ', '.join(info.get('gsb_threat_types') or ['THREAT'])
            signals.append(f"flagged by Google Safe Browsing ({threat_types})")

        if info.get('vt_malicious') or info.get('vt_suspicious'):
            signals.append(
                f"VirusTotal: {info.get('vt_malicious', 0)} malicious / "
                f"{info.get('vt_suspicious', 0)} suspicious engines")

        verdicts = info.get('urlscan_malicious_verdicts')
        if isinstance(verdicts, int) and verdicts > 0:
            signals.append(f"{verdicts} urlscan.io scan(s) judged malicious")

        reputation = info.get('vt_reputation')
        if isinstance(reputation, int) and reputation < 0:
            signals.append(f"negative VirusTotal reputation ({reputation})")

        hops = info.get('redirect_count')
        if isinstance(hops, int) and hops >= 3:
            signals.append(f"{hops} redirects before landing")

        target_host = (url_parts(result.get('url') or '') or {}).get('host')
        final_host = (url_parts(info.get('final_url') or '') or {}).get('host')
        if final_host and target_host and final_host != target_host:
            signals.append(f"lands on a different host ({final_host})")

        if info.get('http_status') in (403, 451):
            signals.append(f"HTTP {info.get('http_status')} at final destination")

        return signals

    def batch_track(self, urls: List[str], workers: int = 5) -> List[Dict[str, Any]]:
        """
        Track multiple URLs concurrently.

        Args:
            urls: List of URLs
            workers: Parallel worker count

        Returns:
            List of tracking results, in input order
        """
        targets = [u.strip() for u in urls if u and u.strip()]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self.track, u): i for i, u in enumerate(targets)}
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = self._invalid_result(targets[idx],
                                                        type(e).__name__)
        return results
