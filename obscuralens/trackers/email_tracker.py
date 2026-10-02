"""
Email Tracker Module
Aggregates DNS, disposable-mail, breach and verification data for an address.
"""

import concurrent.futures as futures
import re
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..health import health
from .email_sources import FREE_SOURCES, KEYED_SOURCES, _pattern_analysis


def _keep(value: Any) -> bool:
    """Values worth storing. Explicit False is kept - it is a real answer
    (e.g. disposable=False, mx_exists=False), unlike None/empty."""
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


class EmailTracker:
    """Email Tracker with multi-source aggregation"""

    def __init__(self):
        self.timeout = config.app_config.request_timeout

    def track(self, email: str) -> Dict[str, Any]:
        """
        Track an email address across all data sources.

        Args:
            email: Email address to track

        Returns:
            Dictionary with merged fields, per-source status and errors
        """
        email = email.strip().lower()
        domain = email.split('@')[1] if '@' in email else ''
        local_part = email.split('@')[0] if '@' in email else email

        tasks: Dict[str, Any] = {}
        if config.is_source_enabled('dns') and health.source_allowed('dns'):
            tasks['dns'] = lambda: FREE_SOURCES['dns'](domain) if domain else {}
        if config.is_source_enabled('disposable') and health.source_allowed('disposable'):
            tasks['disposable'] = lambda: FREE_SOURCES['disposable'](domain, email)
        if config.is_source_enabled('openpgp') and health.source_allowed('openpgp'):
            tasks['openpgp'] = lambda: FREE_SOURCES['openpgp'](email)
        if config.is_source_enabled('domain_rdap') and health.source_allowed('domain_rdap'):
            tasks['domain_rdap'] = lambda: FREE_SOURCES['domain_rdap'](domain) if domain else {}
        if config.is_source_enabled('gravatar') and health.source_allowed('gravatar'):
            tasks['gravatar'] = lambda: FREE_SOURCES['gravatar'](email)
        if config.is_source_enabled('emailrep') and health.source_allowed('emailrep'):
            tasks['emailrep'] = lambda: FREE_SOURCES['emailrep'](email)
        if config.is_source_enabled('github_commits') \
                and health.source_allowed('github_commits'):
            tasks['github_commits'] = lambda: FREE_SOURCES['github_commits'](email)
        if config.is_source_enabled('patterns'):
            tasks['patterns'] = lambda: _pattern_analysis(email, local_part, domain)

        for name, fn in _plugin_sources('email').items():
            source_name = f"plugin:{name}"
            if config.is_source_enabled(source_name) and health.source_allowed(source_name):
                tasks[source_name] = (lambda f=fn: f(email))

        if config.is_configured('haveibeenpwned'):
            key = config.get_api_key('haveibeenpwned')
            tasks['haveibeenpwned'] = lambda: KEYED_SOURCES['haveibeenpwned'](email, key)
            tasks['hibp_pastes'] = lambda: KEYED_SOURCES['hibp_pastes'](email, key)
        if config.is_configured('hunter'):
            key = config.get_api_key('hunter')
            tasks['hunter'] = lambda: KEYED_SOURCES['hunter'](email, key)

        status: Dict[str, Dict[str, Any]] = {}
        fields: Dict[str, Any] = {}
        provenance: Dict[str, List[str]] = {}
        results: Dict[str, Dict[str, Any]] = {}

        if tasks:
            with futures.ThreadPoolExecutor(
                    max_workers=min(len(tasks), config.app_config.max_workers)) as ex:
                future_map = {ex.submit(fn): name for name, fn in tasks.items()}
                for future in futures.as_completed(future_map):
                    name = future_map[future]
                    try:
                        data = future.result() or {}
                        results[name] = data
                        status[name] = {'ok': bool(data), 'error': '' if data else 'no data'}
                    except Exception as e:
                        results[name] = {}
                        status[name] = {'ok': False, 'error': type(e).__name__}

            health.record_batch('email', status)

            # Deterministic merge: task registration order sets priority.
            for name in tasks:
                for key, value in (results.get(name) or {}).items():
                    if _keep(value):
                        provenance.setdefault(key, []).append(name)
                        fields.setdefault(key, value)

        is_valid_format = bool(
            re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

        fields['email'] = email
        fields['domain'] = domain
        fields['local_part'] = local_part
        fields['valid_format'] = is_valid_format
        fields['mx_exists'] = bool(fields.get('mx_records'))

        ok_sources = [n for n, s in status.items() if s['ok']]
        failed = {n: s['error'] for n, s in status.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'email': email,
            'info': fields,
            'field_sources': provenance,
            'sources_ok': sorted(ok_sources),
            'sources_failed': failed,
            'field_count': len([v for v in fields.values() if _keep(v)]),
            'breached': fields.get('hibp_breached', False),
            'success': any(s['ok'] for s in status.values()),
            'errors': [],
        }

        db.save_query('email', email, result, result['success'], '')

        return result

    def batch_track(self, emails: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """Track multiple email addresses concurrently."""
        targets = [e.strip() for e in emails if e.strip()]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self.track, e): i for i, e in enumerate(targets)}
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        'email': targets[idx], 'info': {}, 'field_sources': {},
                        'sources_ok': [], 'sources_failed': {}, 'field_count': 0,
                        'breached': False, 'success': False, 'errors': [type(e).__name__],
                    }
        return results
