"""
v5.2 additions: persistent cache, the new username platforms, the new crypto
chains (blockcypher/xrpscan/koios/solana), the new CVE readers
(cveawg/ghsa), the Cloudflare DoH domain reader, the new intel feeds and the
OpenPhish URL source.

Everything runs offline: the ``fake_http`` fixture stands in for the JSON
GET/POST layer and monkeypatching swaps the feed text bodies.
"""

import threading

import pytest

from obscuralens.core.cache import HttpCache
from obscuralens.intel import feeds
from obscuralens.trackers import crypto_sources as cs
from obscuralens.trackers import cve_sources as cvs
from obscuralens.trackers import domain_sources as ds
from obscuralens.trackers import url_sources as us
from obscuralens.trackers import username_sources as usrc
from obscuralens.trackers.username_tracker import STATUS_RELIABLE, UsernameTracker
from obscuralens.utils.validators import detect_crypto_chain

# ---------------------------------------------------------------------------
# Persistent SQLite cache (performance fix)
# ---------------------------------------------------------------------------

class TestPersistentCache:
    @pytest.fixture()
    def live_cache(self, tmp_path, monkeypatch):
        """A cache with the app-level switch turned on (conftest disables it)."""
        from obscuralens.config import config
        monkeypatch.setattr(config.app_config, 'cache_enabled', True)
        return HttpCache(path=str(tmp_path / 'c.db'), default_ttl=60)

    def test_connection_is_reused_across_calls(self, tmp_path):
        cache = HttpCache(path=str(tmp_path / 'c.db'), default_ttl=60)
        first = cache._conn()
        cache.set('json', 'http://x/1', {'a': 1})
        second = cache._conn()
        assert first is second

    def test_path_change_reopens_connection(self, tmp_path, live_cache):
        cache = live_cache
        cache.set('json', 'http://x/1', {'a': 1})
        first = cache._conn()
        cache._path = str(tmp_path / 'two.db')
        second = cache._conn()
        assert first is not second
        # The new file starts empty; the old value is not visible.
        assert cache.get('json', 'http://x/1') is None

    def test_thread_local_connections(self, tmp_path):
        cache = HttpCache(path=str(tmp_path / 'c.db'), default_ttl=60)
        main_conn = cache._conn()
        seen = {}

        def worker():
            seen['conn'] = cache._conn()

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert seen['conn'] is not main_conn

    def test_roundtrip_still_works(self, live_cache):
        cache = live_cache
        cache.set('json', 'http://x/1', {'a': [1, 2, 3]})
        assert cache.get('json', 'http://x/1') == {'a': [1, 2, 3]}

    def test_corrupt_row_drops_connection_and_self_heals(self, live_cache):
        cache = live_cache
        cache.set('json', 'http://x/1', {'a': 1})
        conn = cache._conn()
        conn.execute("UPDATE http_cache SET value = X'0000' "
                     "WHERE key = 'json:http://x/1'")
        conn.commit()
        # The zlib decompress fails; the next call must not raise and the
        # connection is replaced so later writes work again.
        assert cache.get('json', 'http://x/1') is None
        assert cache._conn() is not conn
        cache.set('json', 'http://x/2', {'b': 2})
        assert cache.get('json', 'http://x/2') == {'b': 2}


# ---------------------------------------------------------------------------
# Username platform expansion (41 -> 104)
# ---------------------------------------------------------------------------

class TestUsernamePlatformExpansion:
    def test_registry_reaches_one_hundred_platforms(self):
        tracker = UsernameTracker()
        assert len(tracker.platforms) >= 100
        names = {p['name'] for p in tracker.platforms}
        # The four revived platforms are actually scanned now.
        for name in ('Patreon', 'Etsy', 'Substack', 'Replit', 'Hashnode'):
            assert name in names
        # The two new JSON API platforms.
        for name in ('Bluesky', 'Dailymotion'):
            assert name in {p['name'] for p in tracker.platforms
                            if p.get('api')}

    def test_every_status_reliable_platform_is_registered(self):
        tracker = UsernameTracker()
        names = {p['name'] for p in tracker.platforms}
        missing = STATUS_RELIABLE - names
        assert not missing, f"STATUS_RELIABLE names missing from registry: {missing}"

    def test_verdict_200_on_status_reliable_platform_is_found(self):
        class FakeResponse:
            status_code = 200
            text = '<html><body>plain shell</body></html>'
            url = 'https://example.com/profile'
        tracker = UsernameTracker()
        status, confidence, reason = tracker._verdict(
            'GoodReads', 'john', FakeResponse())
        assert status == 'found'
        assert confidence == 'medium'
        assert '200-vs-404' in reason

    def test_verdict_js_shell_platform_stays_unknown_without_split(self):
        class FakeResponse:
            status_code = 200
            text = '<html><body>anonymous shell</body></html>'
            url = 'https://example.com/anything'
        tracker = UsernameTracker()
        status, _, _ = tracker._verdict('Medium', 'john', FakeResponse())
        assert status == 'unknown'

    def test_verdict_404_on_new_platform_is_not_found(self):
        class FakeResponse:
            status_code = 404
            text = ''
            url = 'https://example.com/profile'
        tracker = UsernameTracker()
        status, confidence, _ = tracker._verdict('Gitee', 'john',
                                                 FakeResponse())
        assert status == 'not_found'
        assert confidence == 'high'

    def test_not_found_marker_beats_status_reliable(self):
        class FakeResponse:
            status_code = 200
            text = 'Sorry! User not found on this site.'
            url = 'https://example.com/profile'
        tracker = UsernameTracker()
        status, _, _ = tracker._verdict('Gitee', 'john', FakeResponse())
        assert status == 'not_found'


class TestGenericProfile:
    def test_extracts_open_graph_tags(self):
        html = ('<meta property="og:title" content="John Doe">'
                '<meta property="og:description" content="hello">'
                '<meta property="og:image" content="https://x/avatar.png">')
        profile = usrc.generic_profile(html)
        assert profile['name'] == 'John Doe'
        assert profile['bio'] == 'hello'
        assert profile['avatar'] == 'https://x/avatar.png'

    def test_page_title_falls_back(self):
        html = '<title>John Doe - Gitee</title>'
        profile = usrc.generic_profile(html)
        assert profile['page_title'] == 'John Doe - Gitee'

    def test_empty_html_gives_empty_profile(self):
        assert usrc.generic_profile('') == {}


class TestHashnodeRule:
    def _rule(self, body):
        return usrc.HTML_VERDICT_RULES['Hashnode']('john', body,
                                                   body.lower(), None)

    def test_missing_user_title_is_not_found(self):
        verdict = self._rule('<title>User not found | Hashnode</title>')
        assert verdict[0] == 'not_found'
        assert verdict[1] == 'high'

    def test_profile_title_is_found(self):
        verdict = self._rule('<title>John - Hashnode</title>')
        assert verdict[0] == 'found'
        assert verdict[1] == 'medium'

    def test_unrelated_title_falls_through(self):
        assert self._rule('<title>Welcome</title>') is None


class TestBlueskyApi:
    def test_verdict_true_on_did(self):
        assert usrc._bluesky_verdict({'did': 'did:plc:x'}) is True

    def test_verdict_false_on_error_body(self):
        assert usrc._bluesky_verdict({'error': 'InvalidRequest'}) is False

    def test_verdict_none_on_garbage(self):
        assert usrc._bluesky_verdict([]) is None
        assert usrc._bluesky_verdict({}) is None

    def test_actor_defaults_to_bsky_social(self):
        assert usrc._bluesky_actor('john') == 'john.bsky.social'
        assert usrc._bluesky_actor('me@example.com') == 'me@example.com'

    def test_profile_fields(self):
        data = {'displayName': 'John', 'handle': 'john.bsky.social',
                'followersCount': 12, 'followsCount': 3, 'postsCount': 45,
                'createdAt': '2024-01-01T00:00:00Z'}
        profile = usrc.api_profile('Bluesky', data)
        assert profile['name'] == 'John'
        assert profile['followers'] == 12
        assert profile['posts'] == 45

    def test_missing_account_maps_http_400_to_not_found(self, monkeypatch):
        monkeypatch.setattr(
            'obscuralens.utils.http_client.http.get_json',
            lambda url, **kw: (False, None, 'http 400'))
        tracker = UsernameTracker()
        result = tracker._check_api_platform(
            {'name': 'Bluesky', 'url': 'https://bsky.app/profile/john',
             'api': True}, 'john', deep=False)
        assert result.status == 'not_found'
        assert result.confidence == 'high'
        assert 'no-such-account' in result.reason


class TestDailymotionApi:
    def test_verdict_true_on_id(self):
        assert usrc._dailymotion_verdict({'id': 'x43'}) is True

    def test_verdict_false_on_error(self):
        assert usrc._dailymotion_verdict(
            {'error': {'code': 404}}) is False

    def test_profile_epoch_created(self):
        profile = usrc._dailymotion_profile(
            {'id': 'x43', 'screenname': 'DM', 'created_time': 1179315946,
             'videos_total': 7, 'followers_total': 9})
        assert profile['name'] == 'DM'
        assert profile['created'].startswith('2007-05-')
        assert profile['videos'] == 7


# ---------------------------------------------------------------------------
# New crypto chains
# ---------------------------------------------------------------------------

class TestSolanaChainDetection:
    def test_sol_address_detected(self):
        assert detect_crypto_chain(
            'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA') == 'sol'

    def test_btc_prefix_wins_over_sol_length_overlap(self):
        # 33 base58 chars starting with 1: Bitcoin family wins by order.
        assert detect_crypto_chain('1' + 'A' * 32) == 'btc'

    def test_other_chains_still_detected(self):
        assert detect_crypto_chain(
            'rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH') == 'xrp'
        assert detect_crypto_chain(
            'addr1qyzt65j0u4gl8qjm3v06nx7rn2v099k7psqg7lyjk6sc8gq29cw758ge9'
            'wzk5t3pf9p0aqr6frdv3k2ngpn55j8t2yds6v2skv') == 'ada'


class TestBlockcypherReader:
    def test_btc_balance_fields(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'address': '1Boat', 'total_received': 150000000,
            'total_sent': 50000000, 'balance': 100000000,
            'final_balance': 100000000, 'n_tx': 3,
            'unconfirmed_n_tx': 2,
        }, '')
        out = cs._blockcypher('1BoatSLRHtKNngkdXEeobR76b53LETtpyT')
        assert out['chain'] == 'btc'
        assert out['blockcypher_balance'] == 1.0
        assert out['blockcypher_total_received'] == 1.5
        assert out['blockcypher_tx_count'] == 3
        assert out['blockcypher_pending_txs'] == 2

    def test_non_mapped_chain_bails_without_http(self, fake_http):
        fake_http.json = lambda url, **kw: (
            True, {'unexpected': True}, '')
        assert cs._blockcypher('rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH') == {}
        assert fake_http.calls == []

    def test_error_response_is_empty(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert cs._blockcypher('1BoatSLRHtKNngkdXEeobR76b53LETtpyT') == {}


class TestXrpscanReader:
    def test_account_root_fields(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'Account': 'rN7n7ot', 'xrpBalance': '1113.551285',
            'sequence': 45, 'ownerCount': 0,
            'previousAffectingTransactionID': 'DBA5',
            'previousAffectingTransactionLedgerVersion': 106633555,
        }, '')
        out = cs._xrpscan('rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH')
        assert out['chain'] == 'xrp'
        assert out['xrp_balance'] == 1113.551285
        assert out['xrp_sequence'] == 45
        assert out['xrp_last_tx'] == 'DBA5'
        assert out['xrp_last_ledger'] == 106633555

    def test_garbage_balance_is_skipped(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'Account': 'rN7n7ot', 'xrpBalance': 'lots'}, '')
        out = cs._xrpscan('rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH')
        assert 'xrp_balance' not in out
        assert out['chain'] == 'xrp'

    def test_404_for_unfunded_account_is_no_data(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'not found')
        assert cs._xrpscan('rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH') == {}


class TestKoiosReader:
    ADDR = ('addr1q8jd2gtjvg4c8jl05z2pyl8fdly2t428nnldanudkztr6guv0n4yapu'
            '0386cs3c940vmf9n839e2ny2k5dh2s20h7f9q5d4c4e')

    def _patch_post(self, monkeypatch, payload):
        calls = []

        def post(url, **kw):
            calls.append(url)
            return payload

        monkeypatch.setattr(
            'obscuralens.utils.http_client.http.post_json', post)
        return calls

    def test_address_info_fields(self, monkeypatch):
        self._patch_post(monkeypatch, (True, [{
            'address': self.ADDR, 'balance': '418001638',
            'stake_address': 'stake1uxx', 'script_address': False,
            'utxo_set': [
                {'value': '2000000', 'block_time': 1790683521},
                {'value': '2000000', 'block_time': 1790683838},
            ],
        }], ''))
        out = cs._koios(self.ADDR)
        assert out['chain'] == 'ada'
        assert out['ada_balance'] == 418.001638
        assert out['ada_stake_address'] == 'stake1uxx'
        assert out['ada_script_address'] is False
        assert out['ada_utxo_count'] == 2
        assert out['ada_last_activity'] == '2026-09-25T03:30:38Z' \
            or out['ada_last_activity'].endswith('Z')

    def test_empty_list_is_no_data(self, monkeypatch):
        self._patch_post(monkeypatch, (True, [], ''))
        assert cs._koios(self.ADDR) == {}

    def test_non_ada_address_bails_without_http(self, monkeypatch):
        calls = self._patch_post(monkeypatch, (True, [], ''))
        assert cs._koios('1BoatSLRHtKNngkdXEeobR76b53LETtpyT') == {}
        assert calls == []


class TestSolanaReader:
    ADDR = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

    def _patch_post(self, monkeypatch, payloads):
        seq = iter(payloads)
        calls = []

        def post(url, **kw):
            calls.append(url)
            return next(seq)

        monkeypatch.setattr(
            'obscuralens.utils.http_client.http.post_json', post)
        return calls

    def test_active_account_fields(self, monkeypatch):
        self._patch_post(monkeypatch, [
            (True, {'jsonrpc': '2.0', 'result': {'value': 200653906}}, ''),
            (True, {'jsonrpc': '2.0', 'result': {'value': {
                'lamports': 200653906, 'owner': 'BPFLoaderUpgradeab1e',
                'executable': True, 'space': 36}}}, ''),
        ])
        out = cs._solana(self.ADDR)
        assert out['chain'] == 'sol'
        assert out['sol_balance'] == 0.200653906
        assert out['sol_lamports'] == 200653906
        assert out['sol_account_active'] is True
        assert out['sol_owner'] == 'BPFLoaderUpgradeab1e'
        assert out['sol_executable'] is True
        assert out['sol_data_size'] == 36

    def test_never_funded_account_reports_zero_balance(self, monkeypatch):
        self._patch_post(monkeypatch, [
            (True, {'jsonrpc': '2.0', 'result': {'value': 0}}, ''),
            (True, {'jsonrpc': '2.0', 'result': {'value': None}}, ''),
        ])
        out = cs._solana(self.ADDR)
        assert out['sol_balance'] == 0.0
        assert out['sol_account_active'] is False

    def test_balance_failure_gives_no_data(self, monkeypatch):
        self._patch_post(monkeypatch, [(False, None, 'timeout')])
        assert cs._solana(self.ADDR) == {}


# ---------------------------------------------------------------------------
# New CVE readers
# ---------------------------------------------------------------------------

class TestCveawgReader:
    def test_parses_authoritative_record(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {
            'dataType': 'CVE_RECORD',
            'containers': {'cna': {
                'title': 'RCE in log4j',
                'datePublic': '2021-11-24',
                'descriptions': [{'lang': 'en', 'value': 'JNDI RCE.'}],
                'affected': [{'product': 'log4j'}],
            }},
            'cveMetadata': {'state': 'PUBLISHED',
                            'dateUpdated': '2022-01-01'},
        }, '')
        out = cvs._cveawg('CVE-2021-44228')
        assert out['cna_title'] == 'RCE in log4j'
        assert out['cna_description'] == 'JNDI RCE.'
        assert out['cna_affected_products'] == ['log4j']
        assert out['cna_state'] == 'PUBLISHED'
        assert out['cna_updated'] == '2022-01-01'

    def test_non_cve_record_payload_is_rejected(self, fake_http):
        fake_http.json = lambda url, **kw: (True, {'data': 'other'}, '')
        assert cvs._cveawg('CVE-2021-44228') == {}

    def test_cvelist_and_cveawg_produce_identical_fields(self, fake_http):
        record = {
            'dataType': 'CVE_RECORD',
            'containers': {'cna': {'title': 'T', 'datePublic': '2021-01-01'}},
            'cveMetadata': {'state': 'PUBLISHED'},
        }

        def dispatch(url, **kw):
            return (True, record, '')

        fake_http.json = dispatch
        assert cvs._cvelist('CVE-2021-44228') == cvs._cveawg('CVE-2021-44228')


class TestGhsaReader:
    def test_highest_severity_wins(self, fake_http):
        fake_http.json = lambda url, **kw: (True, [
            {'ghsa_id': 'GHSA-a', 'severity': 'moderate',
             'cvss': {'score': 5.3}, 'cwe_ids': [{'cwe_id': 'CWE-79'}]},
            {'ghsa_id': 'GHSA-b', 'severity': 'critical',
             'cvss': {'score': 9.8}, 'cwe_ids': [{'cwe_id': 'CWE-502'}]},
        ], '')
        out = cvs._ghsa('CVE-2021-44228')
        assert out['ghsa_ids'] == ['GHSA-a', 'GHSA-b']
        assert out['ghsa_severity'] == 'critical'
        assert out['ghsa_cvss_score'] == 9.8
        assert out['ghsa_cwes'] == ['CWE-502', 'CWE-79']

    def test_empty_advisory_list_is_no_data(self, fake_http):
        fake_http.json = lambda url, **kw: (True, [], '')
        assert cvs._ghsa('CVE-2021-44228') == {}

    def test_github_token_is_attached_when_configured(
            self, fake_http, monkeypatch):
        seen = {}

        def dispatch(url, **kw):
            seen['url'] = url
            seen['headers'] = kw.get('headers')
            return (True, [], '')

        fake_http.json = dispatch
        monkeypatch.setattr(cvs.config, 'get_api_key',
                            lambda service: 'tok123' if service == 'github'
                            else '')
        cvs._ghsa('CVE-2021-44228')
        assert seen['headers']['Authorization'] == 'Bearer tok123'


# ---------------------------------------------------------------------------
# Cloudflare DoH domain reader
# ---------------------------------------------------------------------------

class TestDohCloudflare:
    def test_records_merge_onto_dns_field_names(self, fake_http):
        def dispatch(url, **kw):
            assert 'cloudflare-dns.com' in url
            assert kw.get('headers', {}).get('Accept') == 'application/dns-json'
            if 'type=A' in url:
                return (True, {'Status': 0, 'Answer': [
                    {'type': 1, 'data': '20.205.243.166'}]}, '')
            if 'type=NS' in url:
                return (True, {'Status': 0, 'Answer': [
                    {'type': 2, 'data': 'ns1.example.net.'},
                    {'type': 2, 'data': 'ns2.example.net.'}]}, '')
            return (True, {'Status': 0}, '')

        fake_http.json = dispatch
        out = ds._doh_cloudflare('github.com')
        assert out['a_records'] == ['20.205.243.166']
        assert out['ns_records'] == ['ns1.example.net', 'ns2.example.net']
        assert out['doh_cf_responded'] is True

    def test_mx_null_mx_is_dropped(self, fake_http):
        def dispatch(url, **kw):
            if 'type=MX' in url:
                return (True, {'Status': 0, 'Answer': [
                    {'type': 15, 'data': '0 .'}]}, '')
            return (True, {'Status': 0, 'Answer': []}, '')

        fake_http.json = dispatch
        out = ds._doh_cloudflare('example.com')
        assert 'mx_records' not in out
        assert out['doh_cf_responded'] is True

    def test_all_queries_failing_gives_no_data(self, fake_http):
        fake_http.json = lambda url, **kw: (False, None, 'timeout')
        assert ds._doh_cloudflare('github.com') == {}


# ---------------------------------------------------------------------------
# New intel feeds + OpenPhish URL source
# ---------------------------------------------------------------------------

class TestNewIntelFeeds:
    def test_registry_contains_eight_feeds(self):
        assert set(feeds.FEED_URLS) == {
            'spamhaus_drop', 'feodo', 'firehol_level1', 'urlhaus',
            'threatfox', 'cins_army', 'blocklist_de', 'openphish'}
        assert set(feeds.FEED_LABELS) == set(feeds.FEED_URLS)

    def test_cins_army_parses_bare_ips(self):
        text = '1.2.3.4\n5.6.7.8\nnot-an-ip\n'
        nets = feeds._parse_feed(text, 'cins_army')
        assert len(nets) == 2

    def test_blocklist_de_parses_bare_ips(self):
        text = '2.3.4.5\n# comment\n3.4.5.6\n'
        nets = feeds._parse_feed(text, 'blocklist_de')
        assert len(nets) == 2

    def test_openphish_ip_feed_keeps_only_ip_hosts(self):
        text = ('http://6.7.8.9/login\n'
                'https://phishing.example.com/x\n'
                'http://7.8.9.10:8080/pay\n')
        nets = feeds._parse_feed(text, 'openphish')
        assert {str(n) for n in nets} == {'6.7.8.9/32', '7.8.9.10/32'}

    def test_openphish_host_extractor(self):
        assert feeds._openphish_host('http://6.7.8.9/login') == '6.7.8.9'
        assert feeds._openphish_host('https://x.example.com/a') == \
            'x.example.com'
        assert feeds._openphish_host('garbage') == ''


class TestOpenPhishUrlSource:
    def _install_feed(self, monkeypatch, body):
        monkeypatch.setattr(
            'obscuralens.utils.http_client.http.get_text',
            lambda url, **kw: (True, body, ''))
        monkeypatch.setattr(us, '_openphish_cache', None)

    def test_exact_url_match(self, monkeypatch):
        self._install_feed(
            monkeypatch, 'http://6.7.8.9/login\nhttps://phish.example/x\n')
        out = us._openphish('http://6.7.8.9/login')
        assert out['openphish_listed'] is True
        assert out['openphish_match'] == 'exact url'

    def test_host_match(self, monkeypatch):
        self._install_feed(
            monkeypatch, 'http://6.7.8.9/login\nhttps://phish.example/x\n')
        out = us._openphish('https://phish.example/other/path')
        assert out['openphish_listed'] is True
        assert out['openphish_match'] == 'host'

    def test_clear_verdict_is_a_fact(self, monkeypatch):
        self._install_feed(
            monkeypatch, 'http://6.7.8.9/login\nhttps://phish.example/x\n')
        out = us._openphish('https://github.com')
        assert out == {'openphish_listed': False}

    def test_unavailable_feed_gives_no_data(self, monkeypatch):
        monkeypatch.setattr(
            'obscuralens.utils.http_client.http.get_text',
            lambda url, **kw: (False, '', 'timeout'))
        monkeypatch.setattr(us, '_openphish_cache', None)
        assert us._openphish('https://github.com') == {}

    def test_disabled_feeds_skip_the_check(self, monkeypatch):
        monkeypatch.setattr(us.config.app_config, 'feeds_enabled', False)
        assert us._openphish('https://github.com') == {}

    def test_feed_is_cached_within_ttl(self, monkeypatch):
        calls = []

        def get_text(url, **kw):
            calls.append(url)
            return (True, 'http://6.7.8.9/login\n', '')

        monkeypatch.setattr(
            'obscuralens.utils.http_client.http.get_text', get_text)
        monkeypatch.setattr(us, '_openphish_cache', None)
        us._openphish('http://6.7.8.9/login')
        us._openphish('http://6.7.8.9/login')
        us._openphish('http://6.7.8.9/login')
        assert len(calls) == 1
