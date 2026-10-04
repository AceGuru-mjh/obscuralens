"""
BSSID Tracker Module (v6.0)
Aggregates WiFi access point intelligence (offline IEEE OUI vendor pack,
EUI-48 bit decomposition, crowd-sourced geolocation) for a BSSID.

A BSSID answers "which access point is this": the EUI-48 address of a WiFi
radio, whose first three octets (the OUI) name the hardware vendor in the
IEEE registry, whose address bits carry the multicast and
locally-administered flags (a randomized privacy MAC or a virtual NIC sets
the local bit, so its OUI identifies nothing), and which crowd-sourced
databases - mylnikov.org keyless, WiGLE with an API key - place on the map
when the community has observed the network. One ``track()`` call fans out
to every enabled source, merges answers field-by-field with provenance,
records source health metrics and saves the outcome to query history.

Sources (see ``bssid_sources`` for details):

* ``oui_vendor`` - offline curated IEEE OUI pack: the access point vendor
  and OUI prefix.
* ``bssid_math`` - offline EUI-48 decomposition: multicast / locally-
  administered bit flags with their transmission and assignment classes,
  the EUI-64 expansion, the modified-EUI-64 IPv6 interface identifier and
  link-local hint, plus a randomization hint when the local bit is set.
* ``mylnikov``   - keyless crowd-sourced geolocation: latitude, longitude,
  accuracy range and observation time.
* ``wigle``      - keyed WiGLE network search: SSID, coordinates,
  encryption type and last-seen timestamp (needs a
  ``OBSCURALENS_WIGLE_API_KEY``).

``BSSIDTracker.track`` returns::

    {
      'bssid': '00:1a:2b:3c:4d:5e',   # normalised colon-separated BSSID
      'info': {...merged fields...},  # always includes 'bssid'
      'field_sources': {field: [source, ...]},
      'sources_ok': ['oui_vendor', 'bssid_math'],
      'sources_failed': {name: error},
      'field_count': int,
      'success': bool,
      'errors': [str, ...],
    }

Invalid identifiers (wrong length, non-hex characters) short-circuit to a
failure dict without touching the network, metrics or query history.
Everything else is saved via ``db.save_query('bssid', <bssid>, ...)`` so
``obscuralens history`` can replay the lookup. Both offline sources always
succeed, so BSSID reports work with the network down - that is the point
of the pack and the bit math.
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import normalize_bssid, validate_bssid
from .bssid_sources import FREE_SOURCES, KEYED_SOURCES, SOURCE_CATALOG, gather_all


class BSSIDTracker:
    """Multi-source WiFi BSSID (access point) tracker.

    A single ``track()`` call fans out to every enabled source, merges the
    answers field-by-field with provenance, records source health metrics
    and saves the outcome to query history::

        from obscuralens.trackers.bssid_tracker import BSSIDTracker

        report = BSSIDTracker().track('00:1A:2B:3C:4D:5E')
        if report['success']:
            print(report['info'].get('vendor'),
                  report['info'].get('lat'), report['info'].get('lon'))

    Because both offline sources need nothing but the shipped OUI pack and
    the address bits themselves, a report always succeeds for a well-formed
    BSSID, with or without network access or a WiGLE key.
    """

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    def _keys(self) -> Dict[str, str]:
        """Configured API keys for the keyed BSSID sources."""
        return {
            service: config.get_api_key(service) or ''
            for service in ('wigle',)
        }

    def source_names(self) -> List[str]:
        """
        Sorted names of every built-in source this tracker can use.

        Plugin-contributed sources are not included; they are discovered
        per lookup by ``bssid_sources.gather_all``.
        """
        return sorted(set(FREE_SOURCES) | set(KEYED_SOURCES))

    def source_catalog(self) -> Dict[str, str]:
        """Human-readable descriptions of every built-in BSSID source."""
        return dict(SOURCE_CATALOG)

    def _failure(self, value: Any, error: str) -> Dict[str, Any]:
        """
        Uniform failure payload for identifiers that never reach the sources.

        Nothing is written to history and no source metrics are recorded,
        because no lookup was actually attempted.
        """
        return {
            'bssid': value if isinstance(value, str) else '',
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [error or 'invalid BSSID'],
        }

    def track(self, value: str) -> Dict[str, Any]:
        """
        Track a WiFi BSSID across all data sources.

        Args:
            value: BSSID in colon (``00:1A:2B:3C:4D:5E``), dash, Cisco
                dotted or bare hex notation; lower case is tolerated

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid identifiers return a failure dict with
            ``success=False`` and never reach the sources, the metrics or
            query history.
        """
        valid, error = validate_bssid(value or '')
        if not valid:
            return self._failure(value, error)

        bssid = normalize_bssid(value)
        gathered = gather_all(bssid, keys=self._keys())
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'bssid': bssid,
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

        db.save_query('bssid', bssid, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, values: List[str], workers: int = 4) -> List[Dict[str, Any]]:
        """
        Track multiple BSSIDs concurrently.

        Each value goes through ``track`` independently, so one invalid or
        failing entry never poisons the rest of the batch.

        Args:
            values: List of BSSID strings (invalid entries yield failure
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
                        'bssid': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
