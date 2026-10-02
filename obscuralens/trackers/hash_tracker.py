"""
Hash Tracker Module
Aggregates every available data source for a file hash (MD5/SHA-1/SHA-256/…).

The tracker is a thin orchestration layer: validation and per-source querying
live in :mod:`obscuralens.trackers.hash_sources` (MalwareBazaar, CIRCL
hashlookup, AlienVault OTX keyless; VirusTotal keyed). This module validates
the input, fans the query out through ``gather_all``, records metrics and
persists the result to history.

Example:
    >>> from obscuralens.trackers.hash_tracker import HashTracker
    >>> result = HashTracker().track(
    ...     'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    >>> result['algorithm'], result['success']
    ('sha256', True)

Batches keep input order and skip blank entries:

    >>> results = HashTracker().batch_track([md5, sha256, 'oops'], workers=4)
    >>> len(results), results[2]['success']
    (3, False)
"""

import concurrent.futures as futures
from typing import Any, Dict, List

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import validate_hash
from .hash_sources import SOURCE_CATALOG, gather_all


class HashTracker:
    """
    Enhanced file hash tracker with multi-source aggregation.

    Sources consulted on every valid lookup:

    * ``malwarebazaar`` — abuse.ch sample database (keyless, optional Auth-Key)
    * ``hashlookup`` — CIRCL known-file corpus, md5/sha1/sha256 (keyless)
    * ``otx`` — AlienVault OTX pulses (keyless, optional API key)
    * ``virustotal`` — VirusTotal file report (keyed; only with a key set)

    ``app.disabled_sources`` can switch any of them off, and additional
    sources contributed by user plugins for the ``hash`` kind are picked up
    automatically by ``gather_all``.

    Result envelope returned by :meth:`track` (mirrors the other trackers):

    * ``hash`` — the normalised (lowercased) target digest
    * ``info`` — merged field dictionary (see :meth:`track`)
    * ``field_sources`` — provenance: {field: [source, ...]}
    * ``sources_ok`` — sorted list of sources that returned data
    * ``sources_failed`` — {source: error} for broken/empty sources
    * ``field_count`` — number of non-empty merged fields
    * ``success`` — True when at least one source produced data
    * ``errors`` — human-readable problem list ('' when clean)
    """

    def __init__(self):
        """Bind shared settings; the heavy lifting happens per lookup."""
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    @classmethod
    def sources(cls) -> Dict[str, str]:
        """Human-readable catalogue of hash sources (for `obscuralens sources`)."""
        return dict(SOURCE_CATALOG)

    def _keys(self) -> Dict[str, str]:
        """API keys for the keyed hash sources (VirusTotal only for now)."""
        return {
            service: config.get_api_key(service) or ''
            for service in ('virustotal',)
        }

    @staticmethod
    def _invalid_result(raw: str, reason: str) -> Dict[str, Any]:
        """
        Uniform failure envelope for rejected input.

        No source ran, so no metrics are recorded and no history row is
        written — the caller learns exactly why the hash was refused.
        """
        return {
            'hash': raw,
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': [f'invalid hash: {reason}'],
        }

    def track(self, h: str) -> Dict[str, Any]:
        """
        Track a file hash across all data sources.

        The input is validated first (hex digest of a supported length —
        md5/sha1/sha224/sha256/sha384/sha512). Invalid input short-circuits
        before any HTTP traffic, metric recording or history write.

        Args:
            h: file hash to track

        Returns:
            Dictionary containing merged fields, per-source status and errors.
            On success the ``info`` mapping is the merged field set; identity
            fields ``hash`` (lowercased input) and ``algorithm`` (detected
            digest type) are always present:

            * malwarebazaar: malware_family, file_name, file_size,
              file_type_mime, first_seen, last_seen, malware_tags, imphash,
              mb_sha256, mb_md5, mb_sha1
            * hashlookup: hl_file_name, hl_file_size, hl_file_type, ssdeep,
              tlsh, known_file
            * otx: otx_pulses, otx_whitelisted, otx_last_pulse, otx_tags
            * virustotal (keyed): reputation, vt_type, vt_size,
              vt_meaningful_name, vt_magic, vt_created, malicious, suspicious,
              vt_threat_label, malicious_score

        Failure semantics: a source that errors or returns no data lands in
        ``sources_failed`` but never fails the whole lookup — ``success`` is
        True as long as at least one source produced data.
        """
        raw = h or ''
        valid, reason = validate_hash(raw)
        if not valid:
            return self._invalid_result(raw, reason)

        target = raw.strip().lower()
        gathered = gather_all(target, self._keys())
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'hash': target,
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

        db.save_query('hash', target, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    def batch_track(self, hashes: List[str], workers: int = 5) -> List[Dict[str, Any]]:
        """
        Track multiple file hashes concurrently.

        Blank entries (empty or whitespace-only strings, None) are skipped;
        every other input — including invalid hashes, which fail fast inside
        ``track`` — keeps its position, so the output is always aligned with
        the filtered input order.

        Args:
            hashes: List of file hashes
            workers: Parallel worker count

        Returns:
            List of tracking results, in input order. A per-item exception
            (unexpected: ``track`` itself never raises) degrades to a failure
            envelope at that position instead of aborting the batch.
        """
        targets = [h.strip() for h in hashes if h and h.strip()]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self.track, h): i for i, h in enumerate(targets)}
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        'hash': targets[idx],
                        'info': {},
                        'field_sources': {},
                        'sources_ok': [],
                        'sources_failed': {},
                        'field_count': 0,
                        'success': False,
                        'errors': [type(e).__name__],
                    }
        return results
