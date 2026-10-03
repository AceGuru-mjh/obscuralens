"""
MAC Tracker Module
Aggregates vendor intelligence (offline OUI pack, macvendors, maclookup) for
an EUI-48 MAC address.

A MAC address answers "which organisation made this NIC": the OUI prefix
resolves to a vendor (offline curated IEEE pack plus two keyless registry
APIs), and the address bits themselves reveal the unicast/multicast class,
whether the address is globally unique or locally administered (the tell for
privacy MAC randomization and virtual NICs), the EUI-64 expansion and the
derived IPv6 interface identifier. One ``track()`` call fans out to every
enabled source, merges answers field-by-field with provenance, records
source health metrics and saves the outcome to query history.

Sources (see ``mac_sources`` for details):

* ``oui_pack``   - offline curated IEEE OUI pack (Raspberry Pi, Cisco,
  Apple, VMware, QEMU, ...): vendor lookups work with the network down.
* ``macvendors`` - api.macvendors.com plain-text lookup against the full
  IEEE registry.
* ``maclookup``  - api.maclookup.app JSON record: company, country,
  registered address, assignment block type.
* ``mac_math``   - offline bit decomposition: OUI, I/G and U/L flags,
  transmission/assignment classes, reserved blocks, EUI-64 + IPv6 hints.

``MACTracker.track`` returns::

    {
      'mac': 'b8:27:eb:aa:bb:cc',        # canonical lowercase colon form
      'info': {...merged fields...},     # always includes 'mac'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['mac_math', 'oui_pack'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (``'banana'``, half an address, 802.15.4-style 8-octet
forms) short-circuit to a failure dict without touching the network, metrics
or query history. Everything else is saved via ``db.save_query('mac',
<canonical mac>, ...)`` so ``obscuralens history`` can replay the lookup.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_mac, validate_mac
from .mac_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class MACTracker:
    """Multi-source MAC address tracker.

    A single ``track()`` call fans out to every enabled keyless source,
    merges the answers field-by-field with provenance, records source health
    metrics and saves the outcome to query history::

        from obscuralens.trackers.mac_tracker import MACTracker

        report = MACTracker().track('B8:27:EB:AA:BB:CC')
        if report['success']:
            print(report['info'].get('vendor'),
                  report['info'].get('is_locally_administered'))

    Because the ``oui_pack`` and ``mac_math`` sources are pure offline
    computation, a report still succeeds (vendor when curated, bit
    decomposition always) when every online API is unreachable.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``mac_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in MAC source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'mac': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid MAC address'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track a MAC address across all data sources.

        Args:
            value: MAC address such as ``'B8:27:EB:AA:BB:CC'``,
                ``'b8-27-eb-aa-bb-cc'`` or Cisco dotted ``'b827.ebdc.aabb'``

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history.
        """
        valid, error = validate_mac(value or '')
        if not valid:
            return self._failure(value, error)

        mac = normalize_mac(value)
        gathered = gather_all(mac, keys=None)
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'mac': mac,
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

        db.save_query('mac', mac, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple MAC addresses concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of MAC addresses (invalid entries yield failure dicts)
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
                        'mac': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
