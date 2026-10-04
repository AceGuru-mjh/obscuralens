"""
Multi-source cryptocurrency address intelligence.

Every provider is queried independently; results are merged field-by-field so a
single flaky source cannot blank out the whole report. Sources marked keyless
work without an API key; keyed sources (Etherscan) layer on when a key is
configured. ``app.disabled_sources`` can switch any source off.

* ``blockchain.info`` (BTC, keyless) - balance, received/sent totals, tx
  count and a first/last-seen window from the recent transaction list.
* ``blockstream.info`` (BTC, keyless) - Esplora funded/spent sums, tx and
  mempool counters, newest confirmed activity.
* ``blockchair`` (BTC/ETH/LTC/DOGE, keyless) - address type, balance and
  first/last seen dates.
* ``mempool.space`` (BTC, keyless) - funded/spent sums cross-confirming
  blockchain.info plus a pending-mempool counter.
* ``blockcypher`` (BTC/ETH/LTC/DOGE, keyless, v5.2) - BlockCypher balance
  API: balance, received/sent totals, tx count and unconfirmed counters.
* ``xrpscan`` (XRP, keyless, v5.2) - XRPScan account root object: XRP
  balance, sequence, owner count and the latest affecting transaction.
* ``koios`` (ADA, keyless, v5.2) - Koios address_info (POST): lovelace
  balance, stake address, script flag and UTXO-derived last activity.
* ``solana`` (SOL, keyless, v5.2) - the public mainnet JSON-RPC:
  ``getBalance`` + ``getAccountInfo`` (lamports, owner program, executable
  flag, data size).

Because the blockchains speak in integer minor units (satoshis, wei, koinu,
lovelace, lamports), each reader normalises amounts to human-readable floats
before returning: BTC-family values are divided by 1e8 and rounded to 8
decimals, ETH values by 1e18 (rounded to 6 decimals, except Blockchair which
keeps 12 to preserve the sat/wei granularity it reports), ADA lovelace by 1e6
and SOL lamports by 1e9. Conversion helpers tolerate ``None``, strings
and garbage by returning ``None`` instead of raising.

Chain routing: each reader calls :func:`detect_crypto_chain` first and bails
out immediately for unsupported chains, so a Bitcoin address never wastes a
round trip on an Ethereum API. As of v5.2 every validated chain except xmr
(Monero balances are unobservable by design) has at least one aggregated
source; xmr addresses still produce a valid report with the detected chain
and address recorded.

Field provenance is tracked: ``gather_all`` returns which source(s) supplied
each value, so a report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import contextlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.http_client import http
from ..utils.validators import detect_crypto_chain

# ---------------------------------------------------------------------------
# Unit conversion helpers (never raise, never lie about precision)
# ---------------------------------------------------------------------------

def _sats_to_btc(value: Any) -> Optional[float]:
    """
    Convert satoshi-style integer minor units to a coin amount.

    Used for BTC (blockchain.info / blockstream / blockchair), LTC and DOGE
    (blockchair), which all report balances in 1e-8 units. Accepts ints,
    numeric strings or ``None``; anything unparseable yields ``None``.

    >>> _sats_to_btc(150000000)
    1.5
    """
    try:
        return round(int(value) / 1e8, 8)
    except (TypeError, ValueError):
        return None


def _wei_to_eth(value: Any, precision: int = 6) -> Optional[float]:
    """
    Convert wei to an ETH amount.

    The integer wei value is parsed first (so huge string balances survive
    float rounding) and only the final quotient is rounded. Etherscan results
    use the default 6 decimals; Blockchair keeps 12 because its dashboards
    expose finer granularity.

    >>> _wei_to_eth('1500000000000000000')
    1.5
    """
    try:
        return round(int(value) / 10 ** 18, precision)
    except (TypeError, ValueError):
        return None


def _epoch_to_iso(epoch: Any) -> Optional[str]:
    """
    Render an epoch-seconds timestamp as an ISO 8601 UTC string.

    Returns ``None`` for missing/garbage values instead of raising, so a
    malformed ``time``/``timeStamp`` field in one transaction never kills the
    whole source read.

    >>> _epoch_to_iso(1231006505)
    '2009-01-03T18:15:05Z'
    """
    try:
        moment = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None
    return moment.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _tx_times(txs: Any) -> List[int]:
    """
    Collect integer epoch timestamps from a transaction list.

    Both blockchain.info (``time``) and Etherscan (``timeStamp``) name the
    field differently upstream, but the readers normalise to the bare integer
    list before calling this. Non-dict entries and unparsable values are
    skipped silently.
    """
    times: List[int] = []
    if not isinstance(txs, list):
        return times
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        raw = tx.get('time') if 'time' in tx else tx.get('timeStamp')
        if raw is None:
            continue
        try:
            times.append(int(raw))
        except (TypeError, ValueError):
            continue
    return times


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _blockchain_info(address: str) -> Dict[str, Any]:
    """
    blockchain.info rawaddr endpoint (keyless, BTC only).

    ``https://blockchain.info/rawaddr/{addr}?limit=5&cors=true`` reports
    totals in satoshis plus a short recent-transaction window. The response
    is cached slightly longer than the default TTL because address balances
    move slowly and the endpoint aggressively rate limits anonymous clients.

    Fields: ``chain`` (always 'btc' here), ``btc_balance``,
    ``btc_total_received``, ``btc_total_sent``, ``btc_tx_count``,
    ``first_seen`` / ``last_seen`` (ISO dates derived from the min/max tx
    time in the returned window).
    """
    if detect_crypto_chain(address) != 'btc':
        return {}

    ok, d, _ = http.get_json(
        f"https://blockchain.info/rawaddr/{address}?limit=5&cors=true",
        cache_ttl=300)
    if not ok or not isinstance(d, dict) or not d.get('address'):
        return {}

    times = _tx_times(d.get('txs'))
    first_seen = _epoch_to_iso(min(times)) if times else None
    last_seen = _epoch_to_iso(max(times)) if times else None

    balance = d.get('final_balance')
    if balance is None:
        balance = d.get('balance')

    return {
        'chain': 'btc',
        'btc_balance': _sats_to_btc(balance),
        'btc_total_received': _sats_to_btc(d.get('total_received')),
        'btc_total_sent': _sats_to_btc(d.get('total_sent')),
        'btc_tx_count': d.get('n_tx'),
        'first_seen': first_seen,
        'last_seen': last_seen,
    }


def _blockstream(address: str) -> Dict[str, Any]:
    """
    Blockstream.info Esplora API (keyless, BTC only).

    Two requests per address:
      * ``/api/address/{addr}`` - confirmed (chain_stats) and pending
        (mempool_stats) counters; funded/spent sums are in satoshis.
      * ``/api/address/{addr}/txs`` - newest-first transaction list used for
        the most recent confirmed activity.

    Field names carry the ``blockstream_`` prefix so they merge alongside
    blockchain.info values without collisions: ``blockstream_funded_btc``,
    ``blockstream_spent_btc``, ``blockstream_tx_count``,
    ``blockstream_mempool_txs``, ``blockstream_last_activity``.
    """
    if detect_crypto_chain(address) != 'btc':
        return {}

    ok, d, _ = http.get_json(f"https://blockstream.info/api/address/{address}")
    if not ok or not isinstance(d, dict):
        return {}

    chain_stats = d.get('chain_stats') or {}
    mempool_stats = d.get('mempool_stats') or {}
    if not isinstance(chain_stats, dict):
        chain_stats = {}
    if not isinstance(mempool_stats, dict):
        mempool_stats = {}

    out: Dict[str, Any] = {
        'blockstream_funded_btc': _sats_to_btc(chain_stats.get('funded_txo_sum')),
        'blockstream_spent_btc': _sats_to_btc(chain_stats.get('spent_txo_sum')),
        'blockstream_tx_count': chain_stats.get('tx_count'),
        'blockstream_mempool_txs': mempool_stats.get('tx_count'),
    }

    # Second request is best-effort: a failure here must not discard the
    # counters we already extracted.
    ok, txs, _ = http.get_json(
        f"https://blockstream.info/api/address/{address}/txs")
    if ok and isinstance(txs, list):
        for tx in txs:  # newest first
            if not isinstance(tx, dict):
                continue
            status = tx.get('status') or {}
            if not isinstance(status, dict):
                continue
            if status.get('block_time'):
                activity = _epoch_to_iso(status['block_time'])
                if activity:
                    out['blockstream_last_activity'] = activity
                break

    return out


#: detect_crypto_chain slug -> Blockchair dashboard slug.
_BLOCKCHAIR_CHAINS = {
    'btc': 'bitcoin',
    'eth': 'ethereum',
    'ltc': 'litecoin',
    'doge': 'dogecoin',
}


def _blockchair(address: str) -> Dict[str, Any]:
    """
    Blockchair address dashboard (keyless, rate-limited; BTC/ETH/LTC/DOGE).

    ``https://api.blockchair.com/{chain}/dashboards/address/{addr}`` returns
    ``data.data[addr].address`` with the address type, balance in
    chain-native minor units (satoshi / wei / koinu), first/last seen dates
    for both receiving and spending, and transaction counters.

    Conversion: BTC-family balances / 1e8 (8 decimals), ETH / 1e18 with 12
    decimals kept. When ``transactions_count`` is absent the receiving and
    spending counters are summed.
    """
    chain = detect_crypto_chain(address)
    slug = _BLOCKCHAIR_CHAINS.get(chain or '')
    if not slug:
        return {}

    ok, d, _ = http.get_json(
        f"https://api.blockchair.com/{slug}/dashboards/address/{address}")
    if not ok or not isinstance(d, dict):
        return {}

    data = d.get('data')
    if not isinstance(data, dict):
        return {}

    node = data.get(address)
    if node is None and len(data) == 1:
        # Some responses key the dashboard by a canonicalised address form.
        node = next(iter(data.values()))
    if not isinstance(node, dict):
        return {}

    a = node.get('address') or {}
    if not isinstance(a, dict) or not a:
        return {}

    # Blockchair keeps 12 decimals so fine wei granularity survives the split.
    balance = (_wei_to_eth(a.get('balance'), 12) if chain == 'eth'
               else _sats_to_btc(a.get('balance')))

    tx_count = a.get('transactions_count')
    if tx_count is None:
        received = a.get('receiving_transaction_count')
        spent = a.get('spending_transaction_count')
        if received is not None or spent is not None:
            tx_count = (received or 0) + (spent or 0)

    return {
        'blockchair_type': a.get('type'),
        'blockchair_balance': balance,
        'blockchair_first_seen_receiving': a.get('first_seen_receiving'),
        'blockchair_first_seen_spending': a.get('first_seen_spending'),
        'blockchair_last_seen_receiving': a.get('last_seen_receiving'),
        'blockchair_last_seen_spending': a.get('last_seen_spending'),
        'blockchair_tx_count': tx_count,
    }


def _etherscan(address: str, api_key: str) -> Dict[str, Any]:
    """
    Etherscan account module (KEYED, ETH only).

    Two GETs:
      * ``action=balance`` -> ``result`` is the wei balance as a string.
      * ``action=txlist`` (ascending, 5 per page) -> ``result`` is a list of
        transactions whose ``timeStamp`` fields bound the observed activity.

    Etherscan signals errors with ``status`` != '1', so both responses are
    gated on that flag; a failed half leaves the other half intact.

    Fields: ``eth_balance``, ``eth_tx_first_seen``, ``eth_tx_last_seen``,
    ``eth_tx_sample_count``.
    """
    if detect_crypto_chain(address) != 'eth':
        return {}
    if not api_key:
        return {}

    out: Dict[str, Any] = {}

    ok, d, _ = http.get_json(
        "https://api.etherscan.io/api"
        f"?module=account&action=balance&address={address}"
        f"&tag=latest&apikey={api_key}")
    if ok and isinstance(d, dict) and str(d.get('status')) == '1':
        out['eth_balance'] = _wei_to_eth(d.get('result'))

    ok, d, _ = http.get_json(
        "https://api.etherscan.io/api"
        f"?module=account&action=txlist&address={address}"
        "&startblock=0&endblock=99999999&sort=asc&page=1&offset=5"
        f"&apikey={api_key}")
    if ok and isinstance(d, dict) and str(d.get('status')) == '1':
        txs = d.get('result')
        if isinstance(txs, list):
            out['eth_tx_sample_count'] = len(txs)
            times = _tx_times(txs)
            if times:
                out['eth_tx_first_seen'] = _epoch_to_iso(min(times))
                out['eth_tx_last_seen'] = _epoch_to_iso(max(times))

    return out


# ---------------------------------------------------------------------------
# v5.0 keyless additions
# ---------------------------------------------------------------------------

def _mempool_space(address: str) -> Dict[str, Any]:
    """
    mempool.space address statistics (keyless, BTC only).

    Endpoint: ``https://mempool.space/api/address/{addr}`` - one request
    returning ``chain_stats`` (``funded_txo_sum`` / ``spent_txo_sum`` /
    ``tx_count`` in satoshis) and ``mempool_stats`` for the unconfirmed
    backlog. The service runs an Esplora-compatible API, so its counters
    line up 1:1 with the Blockstream reader.

    Balance facts deliberately reuse the blockchain.info field names
    (``btc_balance`` / ``btc_total_received`` / ``btc_total_sent`` /
    ``btc_tx_count``, funded minus spent, satoshis converted to BTC) so
    ``gather_all`` provenance stacks the independent providers instead of
    picking one; distinctly-named extras carry the ``mempool_`` prefix
    (``mempool_pending`` unconfirmed tx count and the exact integer
    ``mempool_balance_sats``). Non-BTC addresses return ``{}`` without a
    round trip; transport failures yield ``{}``.
    """
    if detect_crypto_chain(address) != 'btc':
        return {}

    ok, d, _ = http.get_json(f"https://mempool.space/api/address/{address}")
    if not ok or not isinstance(d, dict):
        return {}

    chain_stats = d.get('chain_stats') or {}
    mempool_stats = d.get('mempool_stats') or {}
    if not isinstance(chain_stats, dict):
        chain_stats = {}
    if not isinstance(mempool_stats, dict):
        mempool_stats = {}

    try:
        funded = int(chain_stats.get('funded_txo_sum') or 0)
        spent = int(chain_stats.get('spent_txo_sum') or 0)
    except (TypeError, ValueError):
        return {}

    return {
        'chain': 'btc',
        'btc_balance': _sats_to_btc(funded - spent),
        'btc_total_received': _sats_to_btc(funded),
        'btc_total_sent': _sats_to_btc(spent),
        'btc_tx_count': chain_stats.get('tx_count'),
        'mempool_pending': mempool_stats.get('tx_count'),
        'mempool_balance_sats': funded - spent,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

#: detect_crypto_chain slug -> BlockCypher API path.
_BLOCKCYPHER_CHAINS = {
    'btc': 'btc/main',
    'eth': 'eth/main',
    'ltc': 'ltc/main',
    'doge': 'doge/main',
}


def _blockcypher(address: str) -> Dict[str, Any]:
    """
    BlockCypher balance API (keyless, rate-limited; BTC/ETH/LTC/DOGE, v5.2).

    ``https://api.blockcypher.com/v1/{chain}/main/addrs/{addr}/balance``
    answers with satoshi/wei totals: ``total_received``, ``total_sent``,
    ``balance``, ``final_balance`` (confirmed + unconfirmed), ``n_tx`` and
    ``unconfirmed_n_tx``. Values convert with the per-chain helpers, so an
    ETH account keeps 6 decimals while the BTC family keeps 8.
    """
    chain = detect_crypto_chain(address)
    slug = _BLOCKCYPHER_CHAINS.get(chain or '')
    if not slug:
        return {}

    ok, d, _ = http.get_json(
        f"https://api.blockcypher.com/v1/{slug}/addrs/{address}/balance",
        cache_ttl=300)
    if not ok or not isinstance(d, dict) or 'address' not in d:
        return {}

    to_amount = (_wei_to_eth if chain == 'eth' else _sats_to_btc)
    out: Dict[str, Any] = {
        'chain': chain,
        'blockcypher_balance': to_amount(
            d.get('final_balance') if chain != 'eth' else d.get('balance')),
        'blockcypher_total_received': to_amount(d.get('total_received')),
        'blockcypher_total_sent': to_amount(d.get('total_sent')),
        'blockcypher_tx_count': d.get('n_tx'),
    }
    if d.get('unconfirmed_n_tx'):
        out['blockcypher_pending_txs'] = d.get('unconfirmed_n_tx')
    return out


def _xrpscan(address: str) -> Dict[str, Any]:
    """
    XRPScan account API (keyless, XRP only, v5.2).

    ``https://api.xrpscan.com/api/v1/account/{addr}`` exposes the ledger's
    AccountRoot object: XRP balance, sequence number, owner count and the
    latest affecting transaction hash with its ledger index. Accounts that
    were never funded answer HTTP 404, which leaves ``{}`` (honest no-data).
    """
    if detect_crypto_chain(address) != 'xrp':
        return {}

    ok, d, _ = http.get_json(
        f"https://api.xrpscan.com/api/v1/account/{address}", cache_ttl=300)
    if not ok or not isinstance(d, dict) or 'Account' not in d:
        return {}

    out: Dict[str, Any] = {'chain': 'xrp'}
    with contextlib.suppress(TypeError, ValueError):
        out['xrp_balance'] = round(float(d.get('xrpBalance')), 6)
    if d.get('sequence') is not None:
        out['xrp_sequence'] = d.get('sequence')
    if d.get('ownerCount') is not None:
        out['xrp_owner_count'] = d.get('ownerCount')
    if d.get('previousAffectingTransactionID'):
        out['xrp_last_tx'] = d.get('previousAffectingTransactionID')
    if d.get('previousAffectingTransactionLedgerVersion') is not None:
        out['xrp_last_ledger'] = d.get('previousAffectingTransactionLedgerVersion')
    return out


def _koios(address: str) -> Dict[str, Any]:
    """
    Koios Cardano address_info (keyless POST, ADA only, v5.2).

    Koios is an open Cardano API pool. ``POST
    https://api.koios.rest/api/v1/address_info`` with ``{"_addresses":
    [addr]}`` returns per-address rows carrying the lovelace ``balance``, the
    associated ``stake_address``, a ``script_address`` flag and the UTXO set
    (whose ``block_time`` entries bound the observed activity). An address
    with no on-chain history answers an empty list - still a fact, reported
    as an empty result rather than a failure.
    """
    if detect_crypto_chain(address) != 'ada':
        return {}

    ok, rows, _ = http.post_json(
        "https://api.koios.rest/api/v1/address_info",
        payload={"_addresses": [address]})
    if not ok or not isinstance(rows, list) or not rows:
        return {}

    d = rows[0]
    if not isinstance(d, dict):
        return {}

    out: Dict[str, Any] = {'chain': 'ada'}
    with contextlib.suppress(TypeError, ValueError):
        out['ada_balance'] = round(int(d.get('balance')) / 1e6, 6)
    if d.get('stake_address'):
        out['ada_stake_address'] = d.get('stake_address')
    if d.get('script_address') is not None:
        out['ada_script_address'] = bool(d.get('script_address'))
    utxos = d.get('utxo_set')
    if isinstance(utxos, list):
        out['ada_utxo_count'] = len(utxos)
        times = []
        for utxo in utxos:
            if isinstance(utxo, dict) and utxo.get('block_time') is not None:
                try:
                    times.append(int(utxo['block_time']))
                except (TypeError, ValueError):
                    continue
        if times:
            out['ada_last_activity'] = _epoch_to_iso(max(times))
    return out


def _solana(address: str) -> Dict[str, Any]:
    """
    Solana public mainnet JSON-RPC (keyless, SOL only, v5.2).

    Two POSTs to ``https://api.mainnet-beta.solana.com``:
      * ``getBalance`` - lamports (1 SOL = 1e9 lamports).
      * ``getAccountInfo`` - owner program, executable flag, data size and
        rent epoch; ``value: null`` marks an account with no on-chain state,
        which surfaces as ``sol_account_active: False`` rather than a failure.
    """
    if detect_crypto_chain(address) != 'sol':
        return {}

    ok, d, _ = http.post_json(
        "https://api.mainnet-beta.solana.com",
        payload={'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance',
                 'params': [address]})
    if not ok or not isinstance(d, dict):
        return {}
    result = d.get('result')
    if not isinstance(result, dict):
        return {}

    try:
        lamports = int(result.get('value'))
    except (TypeError, ValueError):
        return {}

    out: Dict[str, Any] = {
        'chain': 'sol',
        'sol_lamports': lamports,
        'sol_balance': round(lamports / 1e9, 9),
    }

    ok, d, _ = http.post_json(
        "https://api.mainnet-beta.solana.com",
        payload={'jsonrpc': '2.0', 'id': 1, 'method': 'getAccountInfo',
                 'params': [address]})
    if ok and isinstance(d, dict):
        info = (d.get('result') or {}).get('value')
        if isinstance(info, dict):
            out['sol_account_active'] = True
            if info.get('owner'):
                out['sol_owner'] = info['owner']
            if info.get('executable') is not None:
                out['sol_executable'] = bool(info.get('executable'))
            if info.get('space') is not None:
                with contextlib.suppress(TypeError, ValueError):
                    out['sol_data_size'] = int(info['space'])
            if info.get('lamports') is not None:
                try:
                    out['sol_lamports'] = int(info['lamports'])
                    out['sol_balance'] = round(int(info['lamports']) / 1e9, 9)
                except (TypeError, ValueError):
                    pass
        else:
            out['sol_account_active'] = False
    return out


FREE_SOURCES: Dict[str, Any] = {
    'blockchain.info': _blockchain_info,
    'blockstream.info': _blockstream,
    'blockchair': _blockchair,
    'mempool.space': _mempool_space,
    'blockcypher': _blockcypher,
    'xrpscan': _xrpscan,
    'koios': _koios,
    'solana': _solana,
}

KEYED_SOURCES: Dict[str, Any] = {
    'etherscan': _etherscan,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'blockchain.info': 'Bitcoin balance, received/sent totals, tx count, '
                       'first/last activity (BTC only, keyless)',
    'blockstream.info': 'Esplora funded/spent sums, tx and mempool counters, '
                        'last confirmed activity (BTC only, keyless)',
    'blockchair': 'Address type, balance and first/last seen dates '
                  '(BTC/ETH/LTC/DOGE, keyless, rate-limited)',
    'mempool.space': 'Funded/spent sums, tx count and pending mempool '
                     'counter (BTC only, keyless)',
    'blockcypher': 'Balance, received/sent totals and tx counters '
                   '(BTC/ETH/LTC/DOGE, keyless, rate-limited; v5.2)',
    'xrpscan': 'XRP balance, sequence, owner count and latest affecting '
               'transaction (XRP only, keyless; v5.2)',
    'koios': 'Lovelace balance, stake address, script flag and UTXO-derived '
             'activity (ADA only, keyless; v5.2)',
    'solana': 'Lamports balance, owner program, executable flag and data '
              'size via the public JSON-RPC (SOL only, keyless; v5.2)',
    'etherscan': 'Ethereum balance and transaction timestamps (keyed)',
}


def _keep(value: Any) -> bool:
    # Explicit False and 0 are real answers; empty string/list/dict are not.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(address: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable source in parallel and merge the results.

    Args:
        address: target crypto address (any supported chain)
        keys: optional {service: api_key} map for keyed sources

    Returns:
        {
          'fields': merged_field_dict,
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Every result states the ``address`` it describes and the detected
    ``chain`` (injected after the merge), so even a report where all sources
    failed still tells the caller what was looked at.
    """
    keys = keys or {}
    address = (address or '').strip()
    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(address))

    for name, fn in _plugin_sources('crypto').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(address))

    key_map = {
        'etherscan': ('etherscan', lambda k: _etherscan(address, k)),
    }
    for service, (source_name, factory) in key_map.items():
        key = keys.get(service)
        if key and config.is_source_enabled(source_name) \
                and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=factory, k=key: f(k))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=min(len(tasks), 12)) as ex:
            future_map = {ex.submit(fn): name for name, fn in tasks.items()}
            for future in futures.as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result() or {}
                    results[name] = data
                    status[name] = {'ok': bool(data), 'error': '' if data else 'no data'}
                except Exception as e:  # a broken source must not kill the scan
                    results[name] = {}
                    status[name] = {'ok': False, 'error': type(e).__name__}

    health.record_batch('crypto', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # Chain and address identify the target itself; record them even when no
    # source produced anything (xmr is chain-labelled only by design).
    merged['address'] = address
    provenance.setdefault('address', ['crypto_sources'])
    chain = detect_crypto_chain(address)
    if chain:
        merged['chain'] = chain
        provenance.setdefault('chain', ['crypto_sources'])

    return {'fields': merged, 'sources': status, 'provenance': provenance}
