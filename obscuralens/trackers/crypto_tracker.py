"""
Crypto Tracker Module
Aggregates on-chain intelligence for cryptocurrency addresses (new v4.0
target kind ``crypto``).

Supported inputs are validated by :func:`validate_crypto_address` (btc, eth,
xmr, doge, ltc, xrp, ada, sol). Chains without any aggregated data source
(xmr only, since v5.2 brought XRPScan, Koios and the Solana JSON-RPC) still
produce a report - the detected chain and address are always recorded - but
``sources_ok`` will be empty and ``success`` False unless a keyless source
applies.

Amount conversions (satoshi -> BTC, wei -> ETH) happen inside the source
readers, with rounding applied there: 8 decimals for the BTC family, 6 for
Ethereum (12 for Blockchair's wei granularity). The tracker only merges and
counts; it never re-derives numbers, so every value in ``info`` can be traced
back through ``field_sources`` to the API that reported it.

Example:
    >>> from obscuralens.trackers.crypto_tracker import CryptoTracker
    >>> result = CryptoTracker().track('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    >>> result['info']['chain']
    'btc'
"""

import concurrent.futures as futures
from typing import Any, Dict, List, Optional

from ..config import config
from ..core.metrics import metrics
from ..database import db
from ..utils.validators import detect_crypto_chain, validate_crypto_address
from .crypto_sources import gather_all

__all__ = ['AGGREGATED_CHAINS', 'CryptoTracker']

#: Chains the aggregated keyless/keyed sources can currently enrich.
#: As of v6.1 that is every validated chain except xmr (Monero balances are
#: unobservable by design) - tron/atom/near joined via TronGrid, the
#: cosmos.directory REST proxy and the NEAR public RPC.
AGGREGATED_CHAINS = ('btc', 'eth', 'doge', 'ltc', 'xrp', 'ada', 'tron',
                     'atom', 'near', 'sol')


class CryptoTracker:
    """
    Enhanced Crypto Tracker with multi-source aggregation.

    The result envelope mirrors the other v3/v4 trackers so the CLI, MCP
    server, web UI and reporting pipeline can treat every kind uniformly::

        {
          'address': <input address>,
          'info': <merged source fields>,
          'field_sources': {field: [source, ...]},
          'sources_ok': [names],
          'sources_failed': {name: error},
          'field_count': int,
          'success': bool,
          'errors': [],
        }
    """

    #: chains with at least one aggregated data source
    SUPPORTED_CHAINS = AGGREGATED_CHAINS

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.headers = {'User-Agent': config.app_config.user_agent}

    # -- helpers ------------------------------------------------------------

    def _keys(self) -> Dict[str, str]:
        """
        API keys for the keyed crypto sources (currently only Etherscan).

        Missing keys map to ``''`` rather than being absent, so callers can
        rely on a stable shape; ``gather_all`` treats an empty key as "source
        off".
        """
        return {
            service: config.get_api_key(service) or ''
            for service in ('etherscan',)
        }

    @staticmethod
    def _empty_result(address: str, errors: List[str]) -> Dict[str, Any]:
        """
        A well-formed failure envelope that callers can render like any
        other result. Used for invalid input (no sources are queried and
        nothing is written to history) and per-batch exceptions.
        """
        return {
            'address': address,
            'info': {},
            'field_sources': {},
            'sources_ok': [],
            'sources_failed': {},
            'field_count': 0,
            'success': False,
            'errors': errors,
        }

    @staticmethod
    def chain_of(address: str) -> Optional[str]:
        """
        Best-effort chain detection for a raw address string.

        Returns the chain slug (``btc``/``eth``/...) or ``None`` when the
        string matches no known format. Handy for CLI routing before a full
        track, e.g. to warn that an xmr address has no source coverage.
        """
        return detect_crypto_chain((address or '').strip())

    @classmethod
    def supported_chains(cls) -> List[str]:
        """Chains the aggregated sources can enrich right now."""
        return list(cls.SUPPORTED_CHAINS)

    @classmethod
    def is_supported(cls, address: str) -> bool:
        """
        Whether :meth:`track` can do more than chain-labelling for this
        address: it must be syntactically valid *and* belong to a chain with
        at least one aggregated source.
        """
        chain = cls.chain_of(address)
        return chain in cls.SUPPORTED_CHAINS

    # -- single target ------------------------------------------------------

    def track(self, address: str) -> Dict[str, Any]:
        """
        Track a cryptocurrency address across all data sources.

        Args:
            address: crypto address (btc/eth/xmr/doge/ltc/xrp/ada); case is
                preserved because addresses are case-sensitive

        Returns:
            Dictionary containing merged fields, per-source status and
            errors. Invalid input returns ``success`` False with
            ``errors == ['invalid crypto address']`` and is *not* saved to
            query history; valid input always records a ``crypto`` history
            row, even when every source fails (the detected chain and
            address are still part of ``info``).
        """
        address = (address or '').strip()
        valid, _reason = validate_crypto_address(address)
        if not valid:
            return self._empty_result(address, ['invalid crypto address'])

        gathered = gather_all(address, self._keys())
        fields = gathered['fields']
        sources = gathered['sources']

        ok_sources = [n for n, s in sources.items() if s['ok']]
        failed = {n: s['error'] for n, s in sources.items() if not s['ok']}
        metrics.record_sources(len(ok_sources), len(failed))

        result: Dict[str, Any] = {
            'address': address,
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

        db.save_query('crypto', address, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")

        return result

    # -- batch --------------------------------------------------------------

    def batch_track(self, addresses: List[str], workers: int = 5) -> List[Dict[str, Any]]:
        """
        Track multiple crypto addresses concurrently.

        Args:
            addresses: List of crypto addresses (mixed chains allowed);
                blank entries are dropped
            workers: Parallel worker count

        Returns:
            List of tracking results, in input order. Invalid entries keep
            their position with a failure envelope instead of aborting the
            batch, and a per-address exception is contained the same way
            (mirrors IPTracker.batch_track).
        """
        targets = [a.strip() for a in addresses if a.strip()]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self.track, a): i for i, a in enumerate(targets)}
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = self._empty_result(targets[idx],
                                                      [type(e).__name__])
        return results
