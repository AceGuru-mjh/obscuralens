"""Crypto source readers, aggregation and tracker tests.

All HTTP goes through the ``fake_http`` fixture (conftest monkeypatches the
shared HTTP client), so nothing here touches the network. Payloads mirror the
real APIs: blockchain.info/blockstream report satoshis, Etherscan reports wei
strings, Blockchair reports chain-native integer units.
"""

from obscuralens.config import config
from obscuralens.database import db
from obscuralens.trackers import crypto_sources as cs
from obscuralens.trackers.crypto_tracker import CryptoTracker

# Fixture targets (validated against obscuralens.utils.validators).
BTC_ADDR = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
BTC_BECH32 = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
ETH_ADDR = '0xd8dA6BF26964aF9D7eEd9e03E5341D472B53327a'
DOGE_ADDR = 'D4hbECBjg7Xf1QcbfABV2bYz958XPBR1Ea'
XMR_ADDR = '48' + 'A' * 93  # syntactically valid, no aggregated coverage

# Epoch anchors and their ISO 8601 renderings.
T_GENESIS, ISO_GENESIS = 1231006505, '2009-01-03T18:15:05Z'
T_MID, ISO_MID = 1500000000, '2017-07-14T02:40:00Z'
T_LATE, ISO_LATE = 1600000000, '2020-09-13T12:26:40Z'


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def test_sats_to_btc_conversion_and_guards():
    assert cs._sats_to_btc(150000000) == 1.5
    assert cs._sats_to_btc('123456789') == 1.23456789
    assert cs._sats_to_btc(0) == 0.0
    assert cs._sats_to_btc(None) is None
    assert cs._sats_to_btc('not-a-number') is None
    assert cs._sats_to_btc([]) is None


def test_wei_to_eth_conversion_and_guards():
    assert cs._wei_to_eth('1500000000000000000') == 1.5
    assert cs._wei_to_eth(123456789012345678, 12) == 0.123456789012
    assert cs._wei_to_eth(None) is None
    assert cs._wei_to_eth('NaN wei') is None


def test_epoch_to_iso_rendering_and_guards():
    assert cs._epoch_to_iso(T_GENESIS) == ISO_GENESIS
    assert cs._epoch_to_iso('1600000000') == ISO_LATE
    assert cs._epoch_to_iso(None) is None
    assert cs._epoch_to_iso('when?') is None


# ---------------------------------------------------------------------------
# blockchain.info reader
# ---------------------------------------------------------------------------

def test_blockchain_info_parses_and_converts_satoshis(fake_http):
    fake_http.json = lambda url, **kw: (True, {
        'address': BTC_ADDR,
        'n_tx': 3,
        'total_received': 150000000,
        'total_sent': 50000000,
        'balance': 100000000,
        'final_balance': 100000000,
        'txs': [{'time': T_GENESIS}, {'time': T_LATE}, {'time': T_MID}],
    }, '')

    out = cs._blockchain_info(BTC_ADDR)

    assert out['chain'] == 'btc'
    assert out['btc_balance'] == 1.0          # 100,000,000 sats
    assert out['btc_total_received'] == 1.5   # 150,000,000 sats
    assert out['btc_total_sent'] == 0.5       # 50,000,000 sats
    assert out['btc_tx_count'] == 3
    assert out['first_seen'] == ISO_GENESIS   # min tx time
    assert out['last_seen'] == ISO_LATE       # max tx time
    assert 'blockchain.info/rawaddr/' in fake_http.calls[0][1]


def test_blockchain_info_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    assert cs._blockchain_info(BTC_ADDR) == {}


def test_blockchain_info_skips_non_btc_without_http_call(fake_http):
    assert cs._blockchain_info(ETH_ADDR) == {}
    assert cs._blockchain_info(DOGE_ADDR) == {}
    assert fake_http.calls == []


# ---------------------------------------------------------------------------
# blockstream.info reader
# ---------------------------------------------------------------------------

def _blockstream_dispatch(address_stats, txs=None, txs_ok=True):
    def dispatch(url, **kwargs):
        if url.endswith('/txs'):
            return (txs_ok, txs, '' if txs_ok else 'timeout')
        return (True, address_stats, '')
    return dispatch


def test_blockstream_parses_stats_and_last_activity(fake_http):
    fake_http.json = _blockstream_dispatch(
        {'address': BTC_ADDR,
         'chain_stats': {'funded_txo_sum': 200000000, 'spent_txo_sum': 50000000,
                         'tx_count': 4},
         'mempool_stats': {'funded_txo_sum': 0, 'spent_txo_sum': 0, 'tx_count': 1}},
        txs=[{'txid': 'aa', 'status': {'confirmed': True, 'block_time': T_LATE}},
             {'txid': 'bb', 'status': {'confirmed': True, 'block_time': T_GENESIS}}])

    out = cs._blockstream(BTC_ADDR)

    assert out['blockstream_funded_btc'] == 2.0
    assert out['blockstream_spent_btc'] == 0.5
    assert out['blockstream_tx_count'] == 4
    assert out['blockstream_mempool_txs'] == 1
    assert out['blockstream_last_activity'] == ISO_LATE  # newest first
    # Distinct field names: no collision with blockchain.info keys.
    assert not any(k.startswith('btc_') for k in out)


def test_blockstream_keeps_stats_when_tx_request_fails(fake_http):
    fake_http.json = _blockstream_dispatch(
        {'chain_stats': {'funded_txo_sum': 100000000, 'spent_txo_sum': 0,
                         'tx_count': 1},
         'mempool_stats': {'tx_count': 0}},
        txs=None, txs_ok=False)

    out = cs._blockstream(BTC_ADDR)

    assert out['blockstream_funded_btc'] == 1.0
    assert out['blockstream_tx_count'] == 1
    assert 'blockstream_last_activity' not in out


def test_blockstream_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'connection failed')
    assert cs._blockstream(BTC_ADDR) == {}


# ---------------------------------------------------------------------------
# blockchair reader
# ---------------------------------------------------------------------------

def test_blockchair_btc_parses_and_maps_chain_slug(fake_http):
    def dispatch(url, **kwargs):
        assert 'api.blockchair.com/bitcoin/dashboards/address/' in url
        return (True, {'data': {BTC_ADDR: {'address': {
            'type': 'pubkey',
            'balance': 123456789,
            'first_seen_receiving': '2009-01-03',
            'first_seen_spending': None,
            'last_seen_receiving': '2021-02-17',
            'last_seen_spending': '2021-02-18',
            'receiving_transaction_count': 2,
            'spending_transaction_count': 3,
        }}}}, '')

    fake_http.json = dispatch
    out = cs._blockchair(BTC_ADDR)

    assert out['blockchair_type'] == 'pubkey'
    assert out['blockchair_balance'] == 1.23456789  # satoshi -> BTC
    assert out['blockchair_first_seen_receiving'] == '2009-01-03'
    assert out['blockchair_last_seen_spending'] == '2021-02-18'
    assert out['blockchair_tx_count'] == 5  # 2 receiving + 3 spending


def test_blockchair_eth_uses_wei_math(fake_http):
    fake_http.json = lambda url, **kw: (True, {'data': {ETH_ADDR: {'address': {
        'type': 'account',
        'balance': 123456789012345678,
        'first_seen_receiving': '2016-01-01',
        'transactions_count': 4,
    }}}}, '')

    out = cs._blockchair(ETH_ADDR)

    assert 'api.blockchair.com/ethereum/dashboards/address/' in fake_http.calls[0][1]
    assert out['blockchair_balance'] == 0.123456789012  # wei / 1e18, 12 decimals
    assert out['blockchair_tx_count'] == 4  # explicit counter wins over the sum


def test_blockchair_unsupported_chain_returns_empty(fake_http):
    assert cs._blockchair(XMR_ADDR) == {}
    assert fake_http.calls == []


def test_blockchair_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'http 402')
    assert cs._blockchair(DOGE_ADDR) == {}


# ---------------------------------------------------------------------------
# etherscan reader (keyed)
# ---------------------------------------------------------------------------

def test_etherscan_parses_balance_and_tx_window(fake_http):
    def dispatch(url, **kwargs):
        assert 'apikey=SECRET' in url
        if 'action=balance' in url:
            return (True, {'status': '1', 'result': '1500000000000000000'}, '')
        if 'action=txlist' in url:
            return (True, {'status': '1', 'result': [
                {'hash': '0x1', 'timeStamp': '1438921913'},
                {'hash': '0x2', 'timeStamp': '1500000000'},
                {'hash': '0x3', 'timeStamp': '1600000000'},
            ]}, '')
        return (False, None, 'unexpected url')

    fake_http.json = dispatch
    out = cs._etherscan(ETH_ADDR, 'SECRET')

    assert out['eth_balance'] == 1.5                 # wei string -> ETH
    assert out['eth_tx_first_seen'] == '2015-08-07T04:31:53Z'
    assert out['eth_tx_last_seen'] == ISO_LATE
    assert out['eth_tx_sample_count'] == 3


def test_etherscan_error_status_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (
        True, {'status': '0', 'result': 'Error! Invalid address format'}, '')
    assert cs._etherscan(ETH_ADDR, 'SECRET') == {}


def test_etherscan_requires_eth_chain_and_key(fake_http):
    assert cs._etherscan(BTC_ADDR, 'SECRET') == {}
    assert cs._etherscan(ETH_ADDR, '') == {}
    assert fake_http.calls == []


# ---------------------------------------------------------------------------
# gather_all: routing, merge, provenance, gating
# ---------------------------------------------------------------------------

def test_chain_routing_skips_btc_sources_for_eth(fake_http):
    fake_http.json = lambda url, **kw: (True, {'data': {ETH_ADDR: {'address': {
        'type': 'account', 'balance': 0, 'transactions_count': 0,
    }}}}, '')

    out = cs.gather_all(ETH_ADDR)  # no keys: etherscan stays off

    urls = [u for _, u in fake_http.calls]
    assert urls == ['https://api.blockchair.com/ethereum/dashboards/address/' + ETH_ADDR]
    assert out['sources']['blockchair']['ok'] is True
    assert out['sources']['blockchain.info']['ok'] is False
    assert out['fields']['chain'] == 'eth'
    assert out['fields']['address'] == ETH_ADDR


def test_gather_all_merges_provenance_and_isolates_failures(monkeypatch):
    monkeypatch.setattr(cs, 'FREE_SOURCES', {
        'alpha': lambda addr: {'btc_balance': 1.0, 'chain': 'btc'},
        'beta': lambda addr: {'btc_balance': 9.9, 'btc_tx_count': 7},
        'broken': lambda addr: (_ for _ in ()).throw(RuntimeError('boom')),
        'empty': lambda addr: {},
    })

    out = cs.gather_all(BTC_ADDR)

    # Registration order wins conflicts.
    assert out['fields']['btc_balance'] == 1.0
    assert out['fields']['btc_tx_count'] == 7
    # Provenance records every provider of a field.
    assert out['provenance']['btc_balance'] == ['alpha', 'beta']
    assert out['provenance']['btc_tx_count'] == ['beta']
    # A raising source is reported, never propagated.
    assert out['sources']['broken'] == {'ok': False, 'error': 'RuntimeError'}
    assert out['sources']['empty'] == {'ok': False, 'error': 'no data'}
    assert out['sources']['alpha']['ok'] is True
    # chain/address are injected after the merge.
    assert out['fields']['chain'] == 'btc'
    assert out['fields']['address'] == BTC_ADDR
    assert out['provenance']['address'] == ['crypto_sources']


def test_gather_all_injects_chain_and_address_without_sources(monkeypatch):
    monkeypatch.setattr(cs, 'FREE_SOURCES', {})
    out = cs.gather_all(XMR_ADDR)

    assert out['fields'] == {'address': XMR_ADDR, 'chain': 'xmr'}
    assert out['sources'] == {}
    assert out['provenance']['chain'] == ['crypto_sources']


def test_gather_all_respects_disabled_sources(monkeypatch):
    monkeypatch.setattr(cs, 'FREE_SOURCES', {
        'one': lambda addr: {'btc_balance': 1.0},
        'two': lambda addr: {'btc_tx_count': 2},
    })
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['two'])

    out = cs.gather_all(BTC_ADDR)

    assert 'two' not in out['sources']
    assert 'btc_tx_count' not in out['fields']
    assert out['fields']['btc_balance'] == 1.0


def test_keyed_etherscan_runs_only_with_key(monkeypatch):
    monkeypatch.setattr(cs, 'FREE_SOURCES', {})
    seen = {}

    def fake_etherscan(address, api_key):
        seen['key'] = api_key
        return {'eth_balance': 2.5}

    monkeypatch.setattr(cs, '_etherscan', fake_etherscan)

    out = cs.gather_all(ETH_ADDR)
    assert 'etherscan' not in out['sources']
    assert seen == {}

    out = cs.gather_all(ETH_ADDR, {'etherscan': 'sekrit'})
    assert out['sources']['etherscan']['ok'] is True
    assert seen['key'] == 'sekrit'
    assert out['fields']['eth_balance'] == 2.5
    assert out['provenance']['eth_balance'] == ['etherscan']


def test_keyed_etherscan_disabled_by_config(monkeypatch):
    monkeypatch.setattr(cs, 'FREE_SOURCES', {})
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['etherscan'])

    out = cs.gather_all(ETH_ADDR, {'etherscan': 'sekrit'})

    assert 'etherscan' not in out['sources']
    assert 'eth_balance' not in out['fields']


# ---------------------------------------------------------------------------
# CryptoTracker
# ---------------------------------------------------------------------------

def test_tracker_result_shape_and_partial_failure(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.crypto_tracker.gather_all',
                        lambda address, keys=None: {
                            'fields': {'chain': 'eth', 'eth_balance': 2.5},
                            'sources': {'etherscan': {'ok': True, 'error': ''},
                                        'blockchair': {'ok': False, 'error': 'no data'}},
                            'provenance': {'eth_balance': ['etherscan'],
                                           'chain': ['crypto_sources']},
                        })
    result = CryptoTracker().track(ETH_ADDR)

    assert result['address'] == ETH_ADDR
    assert result['info']['eth_balance'] == 2.5
    assert result['sources_ok'] == ['etherscan']
    assert result['sources_failed'] == {'blockchair': 'no data'}
    assert result['field_sources']['eth_balance'] == ['etherscan']
    assert result['field_count'] == 2
    assert result['success'] is True
    assert result['errors'] == ['1 source(s) unavailable']
    assert db.get_query_by_id(
        db.search_history(ETH_ADDR)[0].id).query_type == 'crypto'


def test_tracker_invalid_address_short_circuits(monkeypatch, tmp_env):
    calls = []

    def spy(address, keys=None):
        calls.append(address)
        return {'fields': {}, 'sources': {}, 'provenance': {}}

    monkeypatch.setattr('obscuralens.trackers.crypto_tracker.gather_all', spy)
    result = CryptoTracker().track('not-a-crypto-address')

    assert calls == []  # no sources queried
    assert result['address'] == 'not-a-crypto-address'
    assert result['info'] == {}
    assert result['sources_ok'] == []
    assert result['field_count'] == 0
    assert result['success'] is False
    assert result['errors'] == ['invalid crypto address']
    assert db.search_history('not-a-crypto-address') == []  # not saved


def test_tracker_passes_etherscan_key_from_config(monkeypatch, tmp_env):
    seen = {}

    def spy(address, keys=None):
        seen['keys'] = keys
        return {'fields': {}, 'sources': {}, 'provenance': {}}

    monkeypatch.setattr('obscuralens.trackers.crypto_tracker.gather_all', spy)
    monkeypatch.setattr(config.api_config, 'etherscan_api_key', 'KEY123')

    CryptoTracker().track(ETH_ADDR)
    assert seen['keys'] == {'etherscan': 'KEY123'}


def test_tracker_helpers():
    assert CryptoTracker.chain_of(BTC_ADDR) == 'btc'
    assert CryptoTracker.chain_of('nope') is None
    assert CryptoTracker.supported_chains() == ['btc', 'eth', 'doge', 'ltc']


def test_tracker_all_sources_fail(fake_http, tmp_env):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    result = CryptoTracker().track(BTC_ADDR)

    assert result['success'] is False
    assert result['sources_ok'] == []
    assert set(result['sources_failed']) == {
        'blockchain.info', 'blockstream.info', 'blockchair', 'mempool.space'}
    assert set(result['sources_failed'].values()) == {'no data'}
    assert result['errors'] == ['all data sources failed']
    # Chain and address are still recorded.
    assert result['info'] == {'address': BTC_ADDR, 'chain': 'btc'}
    assert result['field_count'] == 2


def test_tracker_full_btc_pipeline(fake_http, tmp_env, monkeypatch):
    monkeypatch.setattr(config.api_config, 'etherscan_api_key', '')

    def dispatch(url, **kwargs):
        if 'blockchain.info/rawaddr/' in url:
            return (True, {
                'address': BTC_ADDR, 'n_tx': 3,
                'total_received': 150000000, 'total_sent': 50000000,
                'balance': 100000000, 'final_balance': 100000000,
                'txs': [{'time': T_GENESIS}, {'time': T_LATE}],
            }, '')
        if 'blockstream.info/api/address/' in url and url.endswith('/txs'):
            return (True, [{'txid': 'aa', 'status': {
                'confirmed': True, 'block_time': T_LATE}}], '')
        if 'blockstream.info/api/address/' in url:
            return (True, {
                'chain_stats': {'funded_txo_sum': 200000000,
                                'spent_txo_sum': 50000000, 'tx_count': 4},
                'mempool_stats': {'tx_count': 1},
            }, '')
        if 'blockchair.com/bitcoin/dashboards/address/' in url:
            return (True, {'data': {BTC_ADDR: {'address': {
                'type': 'pubkey', 'balance': 123456789,
                'first_seen_receiving': '2009-01-03',
                'last_seen_spending': '2021-02-18',
                'receiving_transaction_count': 2,
                'spending_transaction_count': 3,
            }}}}, '')
        if 'mempool.space/api/address/' in url:
            return (True, {
                'address': BTC_ADDR,
                'chain_stats': {'funded_txo_sum': 150000000,
                                'spent_txo_sum': 50000000, 'tx_count': 3},
                'mempool_stats': {'funded_txo_sum': 0, 'spent_txo_sum': 0,
                                  'tx_count': 0},
            }, '')
        return (False, None, 'unexpected url: ' + url)

    fake_http.json = dispatch
    result = CryptoTracker().track(BTC_ADDR)

    assert result['success'] is True
    assert result['sources_ok'] == ['blockchain.info', 'blockchair',
                                    'blockstream.info', 'mempool.space']
    assert result['sources_failed'] == {}
    assert result['errors'] == []
    assert result['info']['chain'] == 'btc'
    assert result['info']['address'] == BTC_ADDR
    assert result['info']['btc_balance'] == 1.0
    assert result['info']['btc_total_received'] == 1.5
    assert result['info']['blockstream_funded_btc'] == 2.0
    assert result['info']['blockstream_last_activity'] == ISO_LATE
    assert result['info']['blockchair_balance'] == 1.23456789
    assert result['info']['blockchair_tx_count'] == 5
    assert result['info']['mempool_pending'] == 0
    assert result['info']['first_seen'] == ISO_GENESIS
    assert result['info']['last_seen'] == ISO_LATE
    assert result['field_sources']['btc_balance'] == ['blockchain.info',
                                                      'mempool.space']
    assert result['field_count'] >= 12
    assert db.get_query_by_id(
        db.search_history(BTC_ADDR)[0].id).query_type == 'crypto'


def test_batch_track_preserves_order(fake_http, tmp_env):
    balances = {BTC_BECH32: 250000000, BTC_ADDR: 100000000}

    def dispatch(url, **kwargs):
        target = next((a for a in balances if a in url), None)
        if target is None:
            return (False, None, 'unexpected url: ' + url)
        sats = balances[target]
        if 'blockchain.info/rawaddr/' in url:
            return (True, {'address': target, 'n_tx': 1,
                           'total_received': sats, 'total_sent': 0,
                           'balance': sats, 'final_balance': sats,
                           'txs': [{'time': T_LATE}]}, '')
        if 'blockstream.info/api/address/' in url and url.endswith('/txs'):
            return (True, [], '')
        if 'blockstream.info/api/address/' in url:
            return (True, {'chain_stats': {'funded_txo_sum': sats,
                                           'spent_txo_sum': 0, 'tx_count': 1},
                           'mempool_stats': {'tx_count': 0}}, '')
        if 'blockchair.com/bitcoin/dashboards/address/' in url:
            return (True, {'data': {target: {'address': {
                'type': 'v0 p2wpkh', 'balance': sats,
                'receiving_transaction_count': 1,
                'spending_transaction_count': 0,
            }}}}, '')
        return (False, None, 'unexpected url: ' + url)

    fake_http.json = dispatch
    results = CryptoTracker().batch_track([BTC_BECH32, '  ', BTC_ADDR])

    assert len(results) == 2  # blank entry dropped, order preserved
    assert results[0]['address'] == BTC_BECH32
    assert results[1]['address'] == BTC_ADDR
    assert results[0]['info']['btc_balance'] == 2.5
    assert results[1]['info']['btc_balance'] == 1.0
    assert all(r['success'] for r in results)


def test_batch_track_keeps_invalid_entries_in_place(fake_http, tmp_env):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    results = CryptoTracker().batch_track(['not-an-address', BTC_ADDR])

    assert results[0]['address'] == 'not-an-address'
    assert results[0]['success'] is False
    assert results[0]['errors'] == ['invalid crypto address']
    assert results[1]['address'] == BTC_ADDR
    assert results[1]['success'] is False  # sources all fail, but it ran
    assert results[1]['errors'] == ['all data sources failed']
