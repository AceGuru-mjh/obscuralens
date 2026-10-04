"""
v6.1 additions: the new keyless sources (proxycheck, CISA KEV,
XposedOrNot, HSTS preload, ransomware.live, CAIDA AS-Rank, PeeringDB,
adsb.lol, Open-Meteo, Ethplorer, Avalanche C-chain, xrplcluster, TronGrid,
NEAR RPC, cosmos.directory), the three new crypto chains (TRON / ATOM /
NEAR), eight new username platforms, the unified fan-out worker count, the
per-host rate-limit overrides, evidence confidence scoring and the search
dork builder.

Everything runs offline: the ``fake_http`` fixture stands in for the JSON
GET/POST layer.
"""

import json

import pytest

from obscuralens.config import config
from obscuralens.health import health
from obscuralens.trackers import asn_sources as asn
from obscuralens.trackers import coords_sources as crd
from obscuralens.trackers import crypto_sources as cs
from obscuralens.trackers import cve_sources as cvs
from obscuralens.trackers import domain_sources as ds
from obscuralens.trackers import email_sources as ems
from obscuralens.trackers import flight_sources as fls
from obscuralens.trackers import ip_sources as ips
from obscuralens.trackers import username_sources as usrc
from obscuralens.trackers.username_tracker import STATUS_RELIABLE, UsernameTracker
from obscuralens.utils.validators import detect_crypto_chain

ETH_ADDR = '0xd8dA6BF26964aF9D7eEd9e03E5347D11D7512B2f'
TRON_ADDR = 'TJRabPrwbZy45sbavfcjinPJC18kjpRTv8'
XRP_ADDR = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'
NEAR_ADDR = 'near.near'


def _fake_domain_checker(kind, value):
    """Deterministic domain result for the investigate confidence test."""
    return {
        'domain': value, 'info': {'domain': value},
        'field_sources': {'domain': ['rdap'],
                          'registrar': ['rdap', 'doh.google']},
        'sources_ok': ['rdap'], 'sources_failed': {},
        'field_count': 2, 'success': True, 'errors': [],
    }


@pytest.fixture(autouse=True)
def _reset_source_health():
    """Circuit-breaker streaks must not leak between tests."""
    health.reset()
    yield
    health.reset()


# ---------------------------------------------------------------------------
# New chain detection (TRON / ATOM / NEAR)
# ---------------------------------------------------------------------------

class TestNewChainDetection:
    def test_tron_addresses(self):
        assert detect_crypto_chain(TRON_ADDR) == 'tron'
        assert detect_crypto_chain('T' + 'z' * 33) == 'tron'
        assert detect_crypto_chain('TX1234') is None  # too short
        # Base58 excludes 0/O/I/l; a T + zeros string is not base58.
        assert detect_crypto_chain('T' + '0' * 33) is None

    def test_tron_wins_over_solana_overlap(self):
        # A 34-char T-prefixed base58 string sits inside Solana's space;
        # TRON must claim it first.
        assert detect_crypto_chain('TLjfbTbpW5E7W2kFEs5Tj6qPsCoZh6e93M') == 'tron'

    def test_atom_addresses(self):
        addr20 = 'cosmos1' + 'q' * 32 + 'mque96'      # 45 chars, 20-byte
        addr32 = 'cosmos1' + 'q' * 52 + 'a7pzv5'      # 65 chars, 32-byte
        assert detect_crypto_chain(addr20) == 'atom'
        assert detect_crypto_chain(addr32) == 'atom'
        assert detect_crypto_chain('cosmos1xyz') is None

    def test_near_named_accounts(self):
        assert detect_crypto_chain('near.near') == 'near'
        assert detect_crypto_chain('app.alice.near') == 'near'
        assert detect_crypto_chain('alice.example') != 'near'
        assert detect_crypto_chain('near') != 'near'  # no dot -> username

    def test_near_implicit_64_hex_stays_hash(self):
        # Implicit NEAR accounts are indistinguishable from SHA-256 digests
        # and deliberately remain with the hash kind.
        assert detect_crypto_chain('a' * 64) is None

    def test_detect_kind_routes_near_account_to_crypto(self):
        from obscuralens.investigate import detect_kind
        assert detect_kind('alice.near') == 'crypto'
        assert detect_kind('example.com') == 'domain'

    def test_supported_chains_grew(self):
        from obscuralens.trackers.crypto_tracker import AGGREGATED_CHAINS
        assert {'tron', 'atom', 'near'} <= set(AGGREGATED_CHAINS)


# ---------------------------------------------------------------------------
# Crypto readers
# ---------------------------------------------------------------------------

class TestEthplorerReader:
    def test_parse(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'address': ETH_ADDR.lower(),
            'ETH': {'balance': '1500000000000000000',
                    'price': {'rate': 2694.2, 'currency': 'USD'}},
            'tokens': [
                {'tokenInfo': {'symbol': 'USDC'}},
                {'tokenInfo': {'symbol': 'LINK'}},
            ],
            'countTxs': 412,
        }, '')
        out = cs._ethplorer(ETH_ADDR)
        assert out['eth_balance'] == 1.5
        assert out['ethplorer_price_usd'] == 2694.2
        assert out['ethplorer_token_count'] == 2
        assert out['ethplorer_token_symbols'] == ['USDC', 'LINK']
        assert out['ethplorer_tx_count'] == 412

    def test_rate_limit_maps_to_no_data(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {'error': {
            'code': 429, 'message': 'Request limit is reached'}}, '')
        assert cs._ethplorer(ETH_ADDR) == {}

    def test_transport_failure(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert cs._ethplorer(ETH_ADDR) == {}

    def test_btc_address_short_circuits(self, fake_http):
        assert cs._ethplorer('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa') == {}
        assert fake_http.calls == []


class TestAvaxCchainReader:
    def test_parse_hex_balances(self, fake_http):
        def post(url, payload=None, **kw):
            if payload and payload.get('method') == 'eth_getBalance':
                return True, {'jsonrpc': '2.0', 'id': 1,
                              'result': '0x567e54eba2cb26026'}, ''
            return True, {'jsonrpc': '2.0', 'id': 2,
                          'result': '0x1a'}, ''
        fake_http.post = post
        out = cs._avax_cchain(ETH_ADDR)
        assert out['avax_balance'] > 0
        assert out['avax_nonce'] == 0x1a
        assert out['avax_active'] is True

    def test_zero_footprint_is_a_real_answer(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (
            True, {'jsonrpc': '2.0', 'id': 1, 'result': '0x0'}, '')
        out = cs._avax_cchain(ETH_ADDR)
        assert out['avax_balance'] == 0.0
        assert out['avax_active'] is False

    def test_transport_failure(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (False, None, 'timeout')
        assert cs._avax_cchain(ETH_ADDR) == {}


class TestXrplPublicReader:
    def test_parse_account_root(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {
            'result': {'account_data': {
                'Account': XRP_ADDR, 'Balance': '56775133590',
                'Sequence': 44196, 'OwnerCount': 1}}},
            '')
        out = cs._xrpl_public(XRP_ADDR)
        assert out['xrp_balance'] == 56775.13359
        assert out['xrp_sequence'] == 44196
        assert out['xrp_owner_count'] == 1

    def test_never_funded_maps_to_no_data(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {
            'result': {'error': 'actNotFound', 'error_code': 19}}, '')
        assert cs._xrpl_public(XRP_ADDR) == {}


class TestTronReader:
    def test_parse_account(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {
            'address': TRON_ADDR, 'balance': 1090973764629,
            'type': 'Contract', 'account_name': 'TetherToken',
            'create_time': 1541666520000}, '')
        out = cs._tron(TRON_ADDR)
        assert out['tron_balance'] == 1090973.764629
        assert out['tron_account_type'] == 'contract'
        assert out['tron_account_name'] == 'TetherToken'
        assert out['tron_account_active'] is True
        assert out['first_seen'] == '2018-11-08T08:42:00Z'

    def test_never_activated_is_a_real_negative(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {}, '')
        out = cs._tron(TRON_ADDR)
        assert out == {'chain': 'tron', 'tron_balance': 0.0,
                       'tron_account_active': False}

    def test_error_object_maps_to_no_data(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {
            'Error': 'class org.tron.core.services.http.JsonFormat$Parse'
                     'Exception : invalid address'}, '')
        assert cs._tron(TRON_ADDR) == {}


class TestNearReader:
    def test_parse_account(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {
            'jsonrpc': '2.0', 'result': {
                'amount': '69272533175526725087568221638',
                'locked': '0', 'code_hash': 'HiyC5tB1gBDpgR',
                'storage_usage': 2263199}}, '')
        out = cs._near(NEAR_ADDR)
        assert out['near_balance'] == round(69272533175526725087568221638 / 1e24, 6)
        assert out['near_locked'] == 0.0
        assert out['near_code_hash'] == 'HiyC5tB1gBDpgR'
        assert out['near_storage_bytes'] == 2263199
        assert out['near_account_exists'] is True

    def test_unknown_account_is_a_real_negative(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {
            'jsonrpc': '2.0', 'error': {
                'name': 'SERVER_ERROR',
                'cause': {'name': 'UNKNOWN_ACCOUNT',
                          'info': {'requested_account_id': 'zzz.near'}}}}, '')
        out = cs._near('zzz.near')
        assert out == {'chain': 'near', 'near_account_exists': False}

    def test_transport_failure(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (False, None, 'timeout')
        assert cs._near(NEAR_ADDR) == {}


class TestCosmosReader:
    ADDR = 'cosmos1' + 'q' * 32 + 'mque96'

    def test_parse_balances_and_account(self, fake_http):
        def get(url, **kw):
            if 'bank' in url:
                return True, {'balances': [
                    {'denom': 'uatom', 'amount': '42100000'},
                    {'denom': 'ibc/ABC123', 'amount': '10'}]}, ''
            return True, {'account': {
                '@type': '/cosmos.auth.v1beta1.BaseAccount',
                'account_number': '5', 'sequence': '12'}}, ''
        fake_http.json = get
        out = cs._cosmos(self.ADDR)
        assert out['atom_balance'] == 42.1
        assert out['atom_account_active'] is True
        assert out['atom_token_count'] == 2
        assert out['atom_account_number'] == '5'
        assert out['atom_sequence'] == '12'

    def test_empty_balance_list_is_zero_not_failure(self, fake_http):
        def get(url, **kw):
            if 'bank' in url:
                return True, {'balances': []}, ''
            return True, {'account': {}}, ''
        fake_http.json = get
        out = cs._cosmos(self.ADDR)
        assert out['atom_balance'] == 0.0
        assert out['atom_account_active'] is False


class TestCryptoRegistry:
    def test_registries_are_consistent(self):
        assert {'ethplorer', 'avax_cchain', 'xrpl_public', 'tron', 'near',
                'cosmos'} <= set(cs.FREE_SOURCES)
        assert set(cs.SOURCE_CATALOG) >= set(cs.FREE_SOURCES)

    def test_registry_order_puts_btc_sources_first(self):
        # Insertion order = merge priority; the standards-derived readers
        # come first by design.
        names = list(cs.FREE_SOURCES)
        assert names.index('blockchain.info') < names.index('ethplorer')


# ---------------------------------------------------------------------------
# proxycheck.io IP reader
# ---------------------------------------------------------------------------

class TestProxycheckReader:
    def test_parse(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'status': 'ok', '8.8.8.8': {
                'proxy': 'no', 'vpn': 'yes', 'type': 'Business',
                'provider': 'Google LLC', 'asn': 'AS15169', 'risk': 0}}, '')
        out = ips._proxycheck('8.8.8.8')
        assert out['proxycheck_proxy'] is False
        assert out['proxycheck_vpn'] is True
        assert out['proxycheck_type'] == 'business'
        assert out['proxycheck_provider'] == 'Google LLC'
        assert out['proxycheck_asn'] == 15169
        assert out['proxycheck_risk'] == 0

    def test_quota_error_maps_to_no_data(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'status': 'error',
            'message': 'No valid IP Addresses supplied.'}, '')
        assert ips._proxycheck('203.0.113.7') == {}

    def test_registered_in_catalog(self):
        assert 'proxycheck' in ips.FREE_SOURCES
        assert 'proxycheck' in ips.SOURCE_CATALOG


# ---------------------------------------------------------------------------
# CISA KEV CVE reader
# ---------------------------------------------------------------------------

KEV_FIXTURE = {
    'title': 'CISA Catalog of Known Exploited Vulnerabilities',
    'count': 2,
    'vulnerabilities': [
        {'cveID': 'CVE-2021-44228', 'vendorProject': 'Apache',
         'knownRansomwareCampaignUse': 'Known',
         'knownVulnerabilityExploit': 'Known',
         'dueDate': '2021-12-24', 'notes': 'Log4Shell.'},
        {'cveID': 'CVE-2020-1472', 'knownRansomwareCampaignUse': 'Unknown',
         'knownVulnerabilityExploit': 'Known', 'dueDate': '2020-09-01',
         'notes': 'Zerologon.'},
    ],
}


class TestKevReader:
    def test_hit(self, fake_http):
        fake_http.json = lambda url, **kw: (True, KEV_FIXTURE, '')
        out = cvs._kev('cve-2021-44228')
        assert out['kev_listed'] is True
        assert out['kev_ransomware_use'] is True
        assert out['kev_due_date'] == '2021-12-24'
        assert out['kev_note'] == 'Log4Shell.'

    def test_miss_is_a_real_negative(self, fake_http):
        fake_http.json = lambda url, **kw: (True, KEV_FIXTURE, '')
        out = cvs._kev('CVE-2099-0001')
        assert out == {'kev_listed': False}

    def test_transport_failure(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert cvs._kev('CVE-2021-44228') == {}

    def test_registered(self):
        assert 'kev' in cvs.FREE_SOURCES
        assert 'kev' in cvs.SOURCE_CATALOG


# ---------------------------------------------------------------------------
# XposedOrNot email reader
# ---------------------------------------------------------------------------

class TestXposedOrNotReader:
    def test_breached(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'BreachMetrics': {'risk': [{'risk_label': 'Critical',
                                        'risk_score': 100}],
                              'passwords_strength': [{'EasyToCrack': 103}]},
            'ExposedBreaches': [{'breach': 'Collection1'},
                                 {'breach': 'MyFitnessPal'}],
            'PastesSummary': {'cnt': 4}}, '')
        out = ems._xposedornot('john@gmail.com')
        assert out['xposedornot_breached'] is True
        assert out['xposedornot_breaches'] == 2
        assert out['xposedornot_breach_sites'] == ['Collection1',
                                                   'MyFitnessPal']
        assert out['xposedornot_risk_score'] == 100
        assert out['xposedornot_pastes'] == 4
        assert out['xposedornot_passwords_weak'] == 103

    def test_clean_address_is_a_real_negative(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'BreachMetrics': None, 'ExposedBreaches': None,
            'PastesSummary': {'cnt': 0}}, '')
        out = ems._xposedornot('nobody@example.com')
        assert out['xposedornot_breached'] is False

    def test_transport_failure(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert ems._xposedornot('john@gmail.com') == {}

    def test_registered(self):
        assert 'xposedornot' in ems.FREE_SOURCES


# ---------------------------------------------------------------------------
# HSTS preload + ransomware.live domain readers
# ---------------------------------------------------------------------------

class TestHstsPreloadReader:
    def test_preloaded(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'name': 'gmail.com', 'status': 'preloaded',
            'bulk': False, 'preloadedDomain': ''}, '')
        out = ds._hstspreload('mail.google.com')
        assert out['hsts_preloaded'] is True
        assert out['hsts_preload_status'] == 'preloaded'

    def test_unknown_status(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'name': 'example.com', 'status': 'unknown',
            'bulk': False, 'preloadedDomain': ''}, '')
        out = ds._hstspreload('example.com')
        assert out['hsts_preloaded'] is False

    def test_registered(self):
        assert 'hstspreload' in ds.FREE_SOURCES
        assert 'hstspreload' in ds.SOURCE_CATALOG


class TestRansomwareLiveReader:
    def test_hit(self, fake_http):
        fake_http.json = lambda url, **kw: (True, [
            {'domain': 'other.org', 'group_name': 'lockbit'},
            {'domain': 'vicksburg.org', 'group_name': 'qilin',
             'post_title': 'Genesis Credit Union', 'discovered':
             '2026-10-03T14:05:35.886097+00:00'}], '')
        out = ds._ransomware_live('vicksburg.org')
        assert out['ransomware_listed'] is True
        assert out['ransomware_group'] == 'qilin'
        assert out['ransomware_post_title'] == 'Genesis Credit Union'
        assert out['ransomware_discovered'] == '2026-10-03'

    def test_miss_is_a_real_negative(self, fake_http):
        fake_http.json = lambda url, **kw: (True, [
            {'domain': 'other.org', 'group_name': 'lockbit'}], '')
        out = ds._ransomware_live('example.com')
        assert out == {'ransomware_listed': False}

    def test_registered(self):
        assert 'ransomware_live' in ds.FREE_SOURCES


# ---------------------------------------------------------------------------
# CAIDA AS-Rank + PeeringDB ASN readers
# ---------------------------------------------------------------------------

class TestAsrankReader:
    def test_parse(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {'data': {'asn': {
            'rank': 1556, 'asn': '15169', 'asnName': 'GOOGLE',
            'source': 'ARIN', 'ixp': False, 'seen': True,
            'cone': {'number': 4231}}}}, '')
        out = asn._asrank('AS15169')
        assert out['asrank_rank'] == 1556
        assert out['asrank_source'] == 'ARIN'
        assert out['asrank_cone'] == 4231
        assert out['asrank_ixp'] is False

    def test_unknown_asn_maps_to_no_data(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {'data': {'asn': None}}, '')
        assert asn._asrank('AS9999999') == {}


class TestPeeringdbReader:
    def test_parse(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {'data': [{
            'name': 'Google LLC', 'website': 'https://about.google/',
            'info_traffic': '1-5 Tbps', 'info_type': 'NSP',
            'policy_general': 'Selective', 'ix_count': 145,
            'netixlan_updated': '2025-01-01T00:00:00Z'}]}, '')
        out = asn._peeringdb('AS15169')
        assert out['pdb_name'] == 'Google LLC'
        assert out['pdb_traffic_volume'] == '1-5 Tbps'
        assert out['pdb_ix_count'] == 145

    def test_404_maps_to_no_data(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'not found')
        assert asn._peeringdb('AS999999') == {}


# ---------------------------------------------------------------------------
# adsb.lol flight reader
# ---------------------------------------------------------------------------

class TestAdsbLolReader:
    def test_airborne(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'ac': [{'hex': 'a4ee82', 'flight': 'BAW117 ', 'r': 'G-XLEA',
                    't': 'A35K', 'alt_baro': 35000, 'gs': 480.5,
                    'track': 92.4, 'lat': 51.4, 'lon': -0.9,
                    'squawk': '1234', 'seen': 2.3}], 'total': 1}, '')
        out = fls._adsb_lol('BAW117')
        assert out['adsb_currently_airborne'] is True
        assert out['adsb_callsign'] == 'BAW117'
        assert out['adsb_registration'] == 'G-XLEA'
        assert out['adsb_altitude_ft'] == 35000
        assert out['adsb_ground_speed_kn'] == 480.5
        assert out['adsb_latitude'] == 51.4

    def test_not_airborne_is_a_real_negative(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'ac': [], 'msg': 'No error', 'total': 0}, '')
        out = fls._adsb_lol('BA2490')
        assert out == {'adsb_currently_airborne': False}

    def test_transport_failure_is_not_a_negative(self, fake_http):
        # Honesty rule: a failed request must NOT claim "not airborne".
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert fls._adsb_lol('BA2490') == {}

    def test_registered(self):
        assert 'adsb_lol' in fls.FREE_SOURCES


# ---------------------------------------------------------------------------
# Open-Meteo coords reader
# ---------------------------------------------------------------------------

class TestOpenMeteoReader:
    def test_parse_current_weather(self, fake_http):
        def get(url, **kw):
            if '/v1/elevation' in url:
                return True, {'elevation': [422.0]}, ''
            return True, {'latitude': 47.37, 'longitude': 8.54,
                          'timezone': 'Europe/Zurich', 'elevation': 413.0,
                          'current': {'temperature_2m': 18.34,
                                      'wind_speed_10m': 12.5,
                                      'wind_direction_10m': 180,
                                      'weather_code': 3}}, ''
        fake_http.json = get
        out = crd._open_meteo(47.37, 8.54)
        assert out['temperature_c'] == 18.3
        assert out['wind_speed_kmh'] == 12.5
        assert out['wind_direction_deg'] == 180
        assert out['weather_timezone'] == 'Europe/Zurich'
        # The dedicated elevation endpoint wins over the coarse grid value.
        assert out['open_meteo_elevation_m'] == 422.0

    def test_transport_failure(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert crd._open_meteo(0.0, 0.0) == {}


# ---------------------------------------------------------------------------
# New username platforms
# ---------------------------------------------------------------------------

class TestStackExchangePlatform:
    def test_verdict_exact_match(self):
        data = {'items': [
            {'display_name': 'torvalds', 'reputation': 1234,
             'creation_date': 1257188981, 'last_access_date': 1764317045,
             'badge_counts': {'gold': 13, 'silver': 13, 'bronze': 0}},
        ]}
        assert usrc._stackexchange_verdict(data, 'torvalds') is True
        assert usrc._stackexchange_verdict(data, 'Torvalds') is True

    def test_verdict_substring_only_is_a_miss(self):
        data = {'items': [{'display_name': 'torvalds_fan'}]}
        assert usrc._stackexchange_verdict(data, 'torvalds') is False

    def test_verdict_empty_items(self):
        assert usrc._stackexchange_verdict({'items': []}, 'torvalds') is False

    def test_verdict_garbage(self):
        assert usrc._stackexchange_verdict(None, 'x') is None
        assert usrc._stackexchange_verdict({'items': None}, 'x') is None

    def test_profile_extraction(self):
        data = {'items': [
            {'display_name': 'torvalds', 'reputation': 1234,
             'location': 'Portland', 'website_url': 'https://x.dev',
             'creation_date': 1257188981,
             'badge_counts': {'gold': 1, 'silver': 2, 'bronze': 3}}]}
        profile = usrc._stackexchange_profile(data)
        assert profile['name'] == 'torvalds'
        assert profile['reputation'] == 1234
        assert profile['joined'] == '2009-11-02'
        assert '1 gold' in profile['badges']


class TestDuolingoPlatform:
    def test_verdict(self):
        assert usrc._duolingo_verdict({'users': [{'id': 1}]}) is True
        assert usrc._duolingo_verdict({'users': []}) is False
        assert usrc._duolingo_verdict({'users': None}) is None
        assert usrc._duolingo_verdict(None) is None

    def test_profile_extraction(self):
        profile = usrc._duolingo_profile({'users': [{
            'username': 'tourist', 'bio': 'learning!',
            'courses': [{'learningLanguage': 'es', 'fromLanguage': 'en'}],
        }]})
        assert profile['name'] == 'tourist'
        assert profile['courses'] == 1
        assert profile['learning'] == 'ES<-EN'


class TestNewHtmlPlatformRules:
    def test_kofi_homepage_fallback_is_not_found(self):
        from tests.conftest import FakeResponse
        body = ('<html><head><title>Ko-fi | Make money doing what you love'
                '</title></head></html>')
        verdict = usrc._rule_kofi('zzz', body, body.lower(),
                                  FakeResponse(text=body))
        assert verdict[0] == 'not_found'

    def test_kofi_real_page_title_is_found(self):
        from tests.conftest import FakeResponse
        body = '<html><head><title>Buy Grace a Coffee</title></head></html>'
        verdict = usrc._rule_kofi('grace', body, body.lower(),
                                  FakeResponse(text=body))
        assert verdict[0] == 'found'

    def test_codeforces_generic_title_is_not_found(self):
        from tests.conftest import FakeResponse
        body = '<html><head><title>Codeforces</title></head></html>'
        verdict = usrc._rule_codeforces('zzz', body, body.lower(),
                                        FakeResponse(text=body))
        assert verdict[0] == 'not_found'

    def test_codeforces_profile_title_is_found(self):
        from tests.conftest import FakeResponse
        body = '<html><head><title>tourist - Codeforces</title></head></html>'
        verdict = usrc._rule_codeforces('tourist', body, body.lower(),
                                        FakeResponse(text=body))
        assert verdict[0] == 'found'

    def test_empty_title_falls_through(self):
        from tests.conftest import FakeResponse
        assert usrc._rule_kofi('x', '', '', FakeResponse()) is None
        assert usrc._rule_codeforces('x', '', '', FakeResponse()) is None


class TestPlatformRegistry:
    def test_platform_count_grew_to_112(self):
        assert len(UsernameTracker().platforms) == 112

    def test_new_platforms_registered(self):
        names = {p['name'] for p in UsernameTracker().platforms}
        assert {'Calendly', 'Gumroad', 'OpenSea', 'Bandcamp', 'Ko-fi',
                'Codeforces', 'Stack Exchange', 'Duolingo'} <= names

    def test_status_reliable_members_all_exist(self):
        names = {p['name'] for p in UsernameTracker().platforms}
        assert names >= STATUS_RELIABLE
        assert {'Calendly', 'Gumroad', 'OpenSea', 'Bandcamp'} <= STATUS_RELIABLE

    def test_verdict_rules_registered(self):
        assert 'Ko-fi' in usrc.HTML_VERDICT_RULES
        assert 'Codeforces' in usrc.HTML_VERDICT_RULES

    def test_catalog_covers_new_platforms(self):
        for name in ('Calendly', 'Gumroad', 'OpenSea', 'Bandcamp', 'Ko-fi',
                     'Codeforces', 'Stack Exchange', 'Duolingo'):
            assert name in usrc.SOURCE_CATALOG, name


# ---------------------------------------------------------------------------
# Unified fan-out workers
# ---------------------------------------------------------------------------

class TestFanoutWorkers:
    def test_default_cap_is_max_workers(self, monkeypatch):
        from obscuralens.utils.helpers import fanout_workers
        monkeypatch.setattr(config.app_config, 'max_workers', 12)
        assert fanout_workers(40) == 12
        assert fanout_workers(4) == 4

    def test_respects_user_config(self, monkeypatch):
        from obscuralens.utils.helpers import fanout_workers
        monkeypatch.setattr(config.app_config, 'max_workers', 24)
        assert fanout_workers(40) == 24

    def test_pathological_config_is_capped(self, monkeypatch):
        from obscuralens.utils.helpers import fanout_workers
        monkeypatch.setattr(config.app_config, 'max_workers', 9999)
        assert fanout_workers(40) == 32

    def test_never_below_one(self):
        from obscuralens.utils.helpers import fanout_workers
        assert fanout_workers(0) == 1


# ---------------------------------------------------------------------------
# Per-host rate limit overrides
# ---------------------------------------------------------------------------

class TestHostRateOverrides:
    def test_overrides_exist(self):
        from obscuralens.core.ratelimit import HOST_RATE_OVERRIDES
        assert 'api.ethplorer.io' in HOST_RATE_OVERRIDES
        assert 'api.ransomware.live' in HOST_RATE_OVERRIDES

    def test_rate_for_slower_host_uses_override(self):
        from obscuralens.core.ratelimit import RateLimiter
        limiter = RateLimiter(rate=8.0)
        assert limiter.rate_for('api.ransomware.live') == 0.02

    def test_rate_for_unknown_host_uses_default(self):
        from obscuralens.core.ratelimit import RateLimiter
        limiter = RateLimiter(rate=8.0)
        assert limiter.rate_for('api.example.test') == 8.0

    def test_disabled_throttling_disables_overrides(self):
        from obscuralens.core.ratelimit import RateLimiter
        limiter = RateLimiter(rate=0.0)
        assert limiter.rate_for('api.ransomware.live') == 0.0

    def test_snapshot_lists_overridden_hosts(self):
        from obscuralens.core.ratelimit import RateLimiter
        limiter = RateLimiter(rate=8.0)
        limiter.acquire('api.ethplorer.io')
        assert 'api.ethplorer.io' in limiter.snapshot()['overridden_hosts']


# ---------------------------------------------------------------------------
# Evidence confidence scoring
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_noisy_or_compounding(self):
        from obscuralens.correlation.confidence import field_confidence
        scored = field_confidence({
            'city': ['ipwho.is', 'ip-api.com'],   # two aggregators
            'asn': ['ripestat'],                  # one authority
        })
        two = scored['city']['score']
        one = scored['asn']['score']
        assert two > one  # corroboration compounds
        assert scored['city']['sources'] == 2
        assert scored['city']['named'] == ['ipwho.is', 'ip-api.com']

    def test_two_aggregators_still_below_one_authority(self):
        from obscuralens.correlation.confidence import (
            _TIER_AUTHORITY,
            field_confidence,
        )
        scored = field_confidence({
            'a': ['x1', 'x2', 'x3', 'x4', 'x5'],  # unknown -> default tier
        })
        # Five default-trust sources (0.8) still beat one authority (0.9).
        assert scored['a']['score'] > _TIER_AUTHORITY

    def test_attach_confidence_block(self):
        from obscuralens.correlation.confidence import attach_confidence
        payload = {'field_sources': {'city': ['ipwho.is', 'ip-api.com'],
                                     'asn': ['ripestat']}}
        attach_confidence(payload)
        block = payload['confidence']
        assert 0.0 <= block['overall'] <= 1.0
        assert block['fields_scored'] == 2
        assert block['corroborated'] == 1
        assert block['band'] in ('certain', 'very-high', 'high', 'moderate',
                                 'low', 'very-low')

    def test_attach_skips_payloads_without_provenance(self):
        from obscuralens.correlation.confidence import attach_confidence
        payload = {'info': {'city': 'Zurich'}}
        attach_confidence(payload)
        assert 'confidence' not in payload

    def test_attach_never_raises_on_garbage(self):
        from obscuralens.correlation.confidence import attach_confidence
        assert attach_confidence(None) is None
        assert attach_confidence({'field_sources': 'not-a-dict'}) == \
            {'field_sources': 'not-a-dict'}

    def test_plugin_sources_get_default_trust(self):
        from obscuralens.correlation.confidence import source_trust
        assert source_trust('plugin:mine') == 0.8

    def test_exported_from_package(self):
        from obscuralens.correlation import attach_confidence, field_confidence, source_trust  # noqa: F401

    def test_investigate_annotates_results(self):
        from obscuralens.investigate import investigate
        payload = investigate('example.com', pivot=False,
                              checker=_fake_domain_checker)
        first = payload['results']['domain']
        assert 'confidence' in first
        assert first['confidence']['corroborated'] == 1


# ---------------------------------------------------------------------------
# Search dork builder
# ---------------------------------------------------------------------------

class TestDorkBuilder:
    def test_domain_dorks(self):
        from obscuralens.utils.dorks import dorks_for
        links = dorks_for('domain', 'example.com')
        assert len(links) >= 6
        queries = ' '.join(link['query'] for link in links)
        assert 'site:example.com' in queries
        assert 'ext:env' in queries
        for link in links:
            assert link['url'].startswith('https://')
            assert 'example.com' in link['url'] or '%20' in link['url'] \
                or link['url'].endswith('example.com')

    def test_cve_dorks_include_exploit_hunting(self):
        from obscuralens.utils.dorks import dorks_for
        links = dorks_for('cve', 'CVE-2021-44228')
        assert any('exploit' in link['query'] for link in links)

    def test_username_dorks_scope_platforms(self):
        from obscuralens.utils.dorks import dorks_for
        links = dorks_for('username', 'torvalds')
        queries = ' '.join(link['query'] for link in links)
        assert 'site:reddit.com' in queries

    def test_unknown_kind_answers_empty(self):
        from obscuralens.utils.dorks import dorks_for
        assert dorks_for('vin', '1M8GDM9AXKP042788') == []

    def test_auto_detection(self):
        from obscuralens.utils.dorks import dorks_for_target
        links = dorks_for_target('example.com')
        assert links and 'site:example.com' in ' '.join(
            link['query'] for link in links)

    def test_unrecognised_target_answers_empty(self):
        from obscuralens.utils.dorks import dorks_for_target
        assert dorks_for_target('??##') == []

    def test_urls_are_encoded(self):
        from obscuralens.utils.dorks import dorks_for
        links = dorks_for('domain', 'example.com')
        google = [link for link in links if link['engine'] == 'Google'][0]
        assert '%20' in google['url'] or 'site%3A' in google['url']


class TestDorksCli:
    def test_table_output(self, capsys):
        from obscuralens import commands
        assert commands.run(['dorks', 'example.com']) == 0
        out = capsys.readouterr().out
        assert 'SEARCH DORKS' in out
        assert 'google.com/search' in out

    def test_json_output(self, capsys):
        from obscuralens import commands
        assert commands.run(['dorks', 'CVE-2021-44228', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['target'] == 'CVE-2021-44228'
        assert payload['dorks']

    def test_list_flag(self, capsys):
        from obscuralens import commands
        assert commands.run(['dorks', '--list']) == 0
        out = capsys.readouterr().out
        assert 'DORK-ENABLED KINDS' in out

    def test_missing_target_is_rejected(self, capsys):
        from obscuralens import commands
        assert commands.run(['dorks']) == 2

    def test_handler_registered(self):
        from obscuralens import commands
        assert commands._HANDLERS['dorks'] is commands._cmd_dorks
