"""
Threat-intel package tests: Tor exit/relay lookups and blocklist feeds.

Fully offline: the shared ``fake_http`` fixture supplies get_json
responses (Onionoo relay details), while ``http.get_text`` — not covered
by that fixture — is monkeypatched with a programmable stand-in that also
counts invocations so cache behaviour can be asserted.
"""

import ipaddress

import pytest

from obscuralens.config import config
from obscuralens.intel import feeds, tor
from obscuralens.utils import http_client

EXIT_URL = tor.EXIT_LIST_URL
ONIONOO_URL = tor.ONIONOO_URL
SPAMHAUS_URL = feeds.FEED_URLS['spamhaus_drop']
FEODO_URL = feeds.FEED_URLS['feodo']
FIREHOL_URL = feeds.FEED_URLS['firehol_level1']

SPAMHAUS_BODY = (
    '; Copyright 2024 The Spamhaus Project Ltd.\n'
    '# regenerated daily\n'
    '1.2.3.0/24 ; SBL251628 ; hijacked range, see SBL record\n'
    '5.6.7.0/24\n'
    'garbage line ; SBL1\n'
)
FEODO_BODY = (
    '# Feodo Tracker ipblocklist\n'
    '1.2.3.4\n'
    '5.6.7.8\n'
    'not-an-ip\n'
)
FIREHOL_BODY = (
    '# firehol_level1\n'
    '1.2.3.0/24\n'
    '2001:db8::/32\n'
    'banana\n'
)

RELAY_PAYLOAD = {
    'relays': [{
        'nickname': 'ExitRelayExample',
        'fingerprint': 'ABCD' * 10,
        'flags': ['Running', 'Exit', 'Fast', 'Guard'],
        'first_seen': '2019-01-02T03:04:05',
        'last_seen': '2024-06-01T00:00:00',
        'advertised_bandwidth': 12_500_000,
        'or_addresses': ['1.2.3.4:443'] + [f'10.0.0.{i}:9001' for i in range(1, 7)],
    }],
    'bridges': [],
}


class FakeText:
    """Programmable http.get_text stand-in that records every call."""

    def __init__(self, bodies=None, ok=False, error='timeout'):
        self.bodies = dict(bodies or {})
        self.ok = ok
        self.error = error
        self.calls = []

    def install(self, monkeypatch):
        monkeypatch.setattr(http_client.http, 'get_text', self)
        return self

    def __call__(self, url, **kwargs):
        self.calls.append(url)
        if url in self.bodies:
            return True, self.bodies[url], ''
        return self.ok, '', self.error

    @property
    def count(self):
        return len(self.calls)


@pytest.fixture(autouse=True)
def _clean_intel_caches():
    """Isolate every test from the module-level intel caches."""
    tor._reset_cache()
    feeds._reset_cache()
    yield
    tor._reset_cache()
    feeds._reset_cache()


def _no_relays(fake_http):
    fake_http.json = lambda url, **kw: (True, {'relays': [], 'bridges': []}, '')


def _install_feeds(monkeypatch, exit_body='9.9.9.9\n', spamhaus=SPAMHAUS_BODY,
                   feodo=FEODO_BODY, firehol=FIREHOL_BODY):
    return FakeText({
        EXIT_URL: exit_body,
        SPAMHAUS_URL: spamhaus,
        FEODO_URL: feodo,
        FIREHOL_URL: firehol,
    }).install(monkeypatch)


# ---------------------------------------------------------------------------
# Tor exit list
# ---------------------------------------------------------------------------

def test_load_exit_nodes_parses_valid_addresses(monkeypatch):
    fake = FakeText({EXIT_URL: '1.2.3.4\n5.6.7.8\n2001:db8::1\n'}).install(
        monkeypatch)
    nodes = tor.load_exit_nodes()
    assert nodes == {'1.2.3.4', '5.6.7.8', '2001:db8::1'}
    assert fake.count == 1


def test_load_exit_nodes_drops_garbage_lines(monkeypatch):
    body = ('1.2.3.4\nnot-an-ip\n999.999.1.1\n\n   \n; banner\n# comment\n'
            'Tor Exit List\n5.6.7.8\n')
    FakeText({EXIT_URL: body}).install(monkeypatch)
    assert tor.load_exit_nodes() == {'1.2.3.4', '5.6.7.8'}


def test_load_exit_nodes_force_refetches(monkeypatch):
    fake = FakeText({EXIT_URL: '1.2.3.4\n'}).install(monkeypatch)
    tor.load_exit_nodes()
    tor.load_exit_nodes()  # served from the in-module cache
    assert fake.count == 1
    tor.load_exit_nodes(force=True)
    assert fake.count == 2
    assert tor.load_exit_nodes() == {'1.2.3.4'}


def test_load_exit_nodes_ttl_expiry_refetches(monkeypatch):
    fake = FakeText({EXIT_URL: '1.2.3.4\n'}).install(monkeypatch)
    monkeypatch.setattr(config.app_config, 'feed_cache_ttl', 0)
    tor.load_exit_nodes()
    tor.load_exit_nodes()
    assert fake.count == 2


def test_load_exit_nodes_failure_returns_last_known(monkeypatch):
    FakeText({EXIT_URL: '1.2.3.4\n'}).install(monkeypatch)
    tor.load_exit_nodes()
    FakeText().install(monkeypatch)  # every fetch now fails
    assert tor.load_exit_nodes(force=True) == {'1.2.3.4'}


def test_load_exit_nodes_failure_empty_when_never_fetched(monkeypatch):
    FakeText().install(monkeypatch)
    assert tor.load_exit_nodes() == set()


def test_is_tor_exit_membership(monkeypatch):
    FakeText({EXIT_URL: '1.2.3.4\n5.6.7.8\n'}).install(monkeypatch)
    assert tor.is_tor_exit('1.2.3.4') is True
    assert tor.is_tor_exit('9.9.9.9') is False


def test_is_tor_exit_invalid_address(monkeypatch):
    fake = FakeText().install(monkeypatch)
    assert tor.is_tor_exit('not-an-ip') is False
    assert fake.count == 0  # invalid input never reaches the network


def test_is_tor_exit_failure_is_false(monkeypatch):
    FakeText().install(monkeypatch)
    assert tor.is_tor_exit('1.2.3.4') is False


# ---------------------------------------------------------------------------
# Onionoo relay details
# ---------------------------------------------------------------------------

def test_relay_details_parses_first_relay(fake_http):
    fake_http.json = lambda url, **kw: (True, RELAY_PAYLOAD, '')
    details = tor.relay_details('1.2.3.4')
    assert details['is_relay'] is True
    assert details['nickname'] == 'ExitRelayExample'
    assert details['fingerprint'] == 'ABCD' * 10
    assert details['flags'] == ['Running', 'Exit', 'Fast', 'Guard']
    assert details['first_seen'] == '2019-01-02T03:04:05'
    assert details['last_seen'] == '2024-06-01T00:00:00'
    assert details['bandwidth'] == 12_500_000
    assert len(details['or_addresses']) == 5  # capped from 7
    assert details['or_addresses'][0] == '1.2.3.4:443'
    assert fake_http.calls == [('json', f'{ONIONOO_URL}?lookup=1.2.3.4')]


def test_relay_details_no_relays(fake_http):
    fake_http.json = lambda url, **kw: (True, {'relays': [], 'bridges': []}, '')
    assert tor.relay_details('1.2.3.4') == {'is_relay': False}


def test_relay_details_missing_relays_key(fake_http):
    fake_http.json = lambda url, **kw: (True, {}, '')
    assert tor.relay_details('1.2.3.4') == {'is_relay': False}


def test_relay_details_transport_failure(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    assert tor.relay_details('1.2.3.4') == {'is_relay': False, 'error': 'timeout'}


def test_relay_details_invalid_ip(fake_http):
    details = tor.relay_details('not-an-ip')
    assert details == {'is_relay': False, 'error': 'invalid ip address'}
    assert fake_http.calls == []


def test_relay_details_garbage_relay_entry(fake_http):
    fake_http.json = lambda url, **kw: (True, {'relays': ['oops']}, '')
    assert tor.relay_details('1.2.3.4') == {'is_relay': False}


def test_relay_details_non_dict_payload(fake_http):
    fake_http.json = lambda url, **kw: (True, ['surprise'], '')
    details = tor.relay_details('1.2.3.4')
    assert details['is_relay'] is False
    assert details['error']


def test_tor_sections_listed_relay(fake_http, monkeypatch):
    FakeText({EXIT_URL: '1.2.3.4\n'}).install(monkeypatch)
    fake_http.json = lambda url, **kw: (True, RELAY_PAYLOAD, '')
    pairs = {row[0]: row[1] for row in tor.tor_sections('1.2.3.4')}
    assert pairs['Tor exit node'] == 'Yes'
    assert pairs['Tor relay nickname'] == 'ExitRelayExample'
    assert pairs['Relay flags'] == 'Running, Exit, Fast, Guard'
    assert pairs['Relay bandwidth'] == '12.5 MB/s'
    assert pairs['Relay OR addresses'].startswith('1.2.3.4:443')
    assert len(pairs['Relay OR addresses'].split(', ')) == 5


def test_tor_sections_not_exit_no_relay(fake_http, monkeypatch):
    FakeText({EXIT_URL: '9.9.9.9\n'}).install(monkeypatch)
    fake_http.json = lambda url, **kw: (True, {'relays': []}, '')
    assert tor.tor_sections('1.2.3.4') == [['Tor exit node', 'No']]


def test_tor_sections_lookup_failure(fake_http, monkeypatch):
    FakeText().install(monkeypatch)
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    pairs = {row[0]: row[1] for row in tor.tor_sections('1.2.3.4')}
    assert pairs['Tor exit node'] == 'No'
    assert 'timeout' in pairs['Relay lookup']


def test_tor_sections_invalid_ip_never_raises(fake_http, monkeypatch):
    failing = FakeText().install(monkeypatch)
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    rows = tor.tor_sections('banana')
    assert rows[0] == ['Tor exit node', 'No']
    assert failing.count == 0
    assert fake_http.calls == []


# ---------------------------------------------------------------------------
# Feed parsing
# ---------------------------------------------------------------------------

def test_parse_spamhaus_drop(monkeypatch):
    FakeText({SPAMHAUS_URL: SPAMHAUS_BODY}).install(monkeypatch)
    networks = feeds._load_feed('spamhaus_drop')
    assert ipaddress.ip_network('1.2.3.0/24') in networks
    assert ipaddress.ip_network('5.6.7.0/24') in networks  # bare CIDR line
    assert len(networks) == 2


def test_parse_feodo_bare_ips_become_slash32(monkeypatch):
    FakeText({FEODO_URL: FEODO_BODY}).install(monkeypatch)
    networks = feeds._load_feed('feodo')
    assert ipaddress.ip_network('1.2.3.4/32') in networks
    assert ipaddress.ip_network('5.6.7.8/32') in networks
    assert len(networks) == 2


def test_parse_firehol_cidrs(monkeypatch):
    FakeText({FIREHOL_URL: FIREHOL_BODY}).install(monkeypatch)
    networks = feeds._load_feed('firehol_level1')
    assert ipaddress.ip_network('1.2.3.0/24') in networks
    assert ipaddress.ip_network('2001:db8::/32') in networks
    assert len(networks) == 2


def test_parse_feed_dedupes_entries(monkeypatch):
    FakeText({FEODO_URL: '1.2.3.4\n1.2.3.4\n5.6.7.8\n'}).install(monkeypatch)
    assert len(feeds._load_feed('feodo')) == 2


def test_parse_feed_empty_body_is_cached_not_error(monkeypatch):
    FakeText({FEODO_URL: ''}).install(monkeypatch)
    assert feeds._load_feed('feodo') == []
    item = {i['name']: i for i in feeds.feeds_status()}['feodo']
    assert item['cached'] is True
    assert item['entries'] == 0
    assert item['error'] == ''


def test_load_feed_failure_keeps_last_known(monkeypatch):
    FakeText({SPAMHAUS_URL: SPAMHAUS_BODY}).install(monkeypatch)
    assert len(feeds._load_feed('spamhaus_drop')) == 2
    FakeText().install(monkeypatch)  # every fetch now fails
    assert len(feeds._load_feed('spamhaus_drop', force=True)) == 2


def test_load_feed_failure_first_time_is_empty(monkeypatch):
    FakeText().install(monkeypatch)
    assert feeds._load_feed('feodo') == []
    item = {i['name']: i for i in feeds.feeds_status()}['feodo']
    assert item['cached'] is False
    assert item['error'] == 'timeout'


def test_load_feed_force_refetches(monkeypatch):
    fake = FakeText({SPAMHAUS_URL: SPAMHAUS_BODY}).install(monkeypatch)
    feeds._load_feed('spamhaus_drop')
    feeds._load_feed('spamhaus_drop')  # cache hit, no HTTP
    assert fake.count == 1
    feeds._load_feed('spamhaus_drop', force=True)
    assert fake.count == 2


def test_load_feed_unknown_name_is_empty():
    assert feeds._load_feed('nope') == []


# ---------------------------------------------------------------------------
# check_ip
# ---------------------------------------------------------------------------

def test_check_ip_full_membership(fake_http, monkeypatch):
    _no_relays(fake_http)
    _install_feeds(monkeypatch, exit_body='1.2.3.4\n')
    result = feeds.check_ip('1.2.3.4')
    assert result['tor'] is True
    assert result['spamhaus_drop'] is True  # 1.2.3.0/24 contains 1.2.3.4
    assert result['feodo'] is True
    assert result['firehol_level1'] is True
    assert result['listed_count'] == 4
    assert result['relay'] == {'is_relay': False}


def test_check_ip_clear_address(fake_http, monkeypatch):
    _no_relays(fake_http)
    _install_feeds(monkeypatch)
    result = feeds.check_ip('8.8.8.8')
    assert result['tor'] is False
    assert result['spamhaus_drop'] is False
    assert result['feodo'] is False
    assert result['firehol_level1'] is False
    assert result['listed_count'] == 0
    assert result['relay'] == {'is_relay': False}


def test_check_ip_listed_count_math(fake_http, monkeypatch):
    _no_relays(fake_http)
    _install_feeds(monkeypatch)  # exit list holds 9.9.9.9 only
    result = feeds.check_ip('5.6.7.8')
    assert result['tor'] is False
    assert result['spamhaus_drop'] is True  # bare 5.6.7.0/24 line
    assert result['feodo'] is True
    assert result['firehol_level1'] is False  # only 1.2.3.0/24 + 2001:db8::/32
    assert result['listed_count'] == 2


def test_check_ip_invalid_address(fake_http, monkeypatch):
    failing = FakeText().install(monkeypatch)
    result = feeds.check_ip('banana')
    assert result['tor'] is False
    assert result['spamhaus_drop'] is False
    assert result['feodo'] is False
    assert result['firehol_level1'] is False
    assert result['listed_count'] == 0
    assert failing.count == 0
    assert fake_http.calls == []


def test_check_ip_disabled(fake_http, monkeypatch):
    monkeypatch.setattr(config.app_config, 'feeds_enabled', False)
    failing = FakeText().install(monkeypatch)
    assert feeds.check_ip('1.2.3.4') == {'disabled': True}
    assert failing.count == 0
    assert fake_http.calls == []


def test_check_ip_ipv6_membership(fake_http, monkeypatch):
    _no_relays(fake_http)
    _install_feeds(monkeypatch, exit_body='2001:db8::1\n',
                   firehol='2001:db8::/32\n')
    result = feeds.check_ip('2001:db8::1')
    assert result['tor'] is True
    assert result['firehol_level1'] is True
    assert result['spamhaus_drop'] is False
    assert result['feodo'] is False
    assert result['listed_count'] == 2


def test_check_ip_carries_relay_details(fake_http, monkeypatch):
    _install_feeds(monkeypatch)
    fake_http.json = lambda url, **kw: (True, RELAY_PAYLOAD, '')
    result = feeds.check_ip('1.2.3.4')
    assert result['relay']['is_relay'] is True
    assert result['relay']['nickname'] == 'ExitRelayExample'


# ---------------------------------------------------------------------------
# feeds_status / feeds_sections
# ---------------------------------------------------------------------------

def test_feeds_status_before_any_load():
    status = feeds.feeds_status()
    assert [item['name'] for item in status] == [
        'spamhaus_drop', 'feodo', 'firehol_level1']
    for item in status:
        assert set(item) == {'name', 'url', 'entries', 'cached', 'error'}
        assert item['entries'] == 0
        assert item['cached'] is False
        assert item['error'] == ''


def test_feeds_status_after_load(fake_http, monkeypatch):
    _no_relays(fake_http)
    _install_feeds(monkeypatch)
    feeds.check_ip('1.2.3.4')
    status = {item['name']: item for item in feeds.feeds_status()}
    assert status['spamhaus_drop']['entries'] == 2
    assert status['spamhaus_drop']['cached'] is True
    assert status['spamhaus_drop']['error'] == ''
    assert status['feodo']['entries'] == 2
    assert status['feodo']['url'] == FEODO_URL
    assert status['firehol_level1']['entries'] == 2


def test_feeds_failure_path(fake_http, monkeypatch):
    _no_relays(fake_http)
    failing = FakeText().install(monkeypatch)
    result = feeds.check_ip('1.2.3.4')
    assert result['tor'] is False
    assert result['spamhaus_drop'] is False
    assert result['feodo'] is False
    assert result['firehol_level1'] is False
    assert result['listed_count'] == 0
    assert failing.count == 4  # exit list + three feeds
    status = {item['name']: item for item in feeds.feeds_status()}
    for name in ('spamhaus_drop', 'feodo', 'firehol_level1'):
        assert status[name]['error'] == 'timeout'
        assert status[name]['cached'] is False
        assert status[name]['entries'] == 0


def test_feeds_sections_rows(fake_http, monkeypatch):
    _no_relays(fake_http)
    _install_feeds(monkeypatch)
    feeds.check_ip('1.2.3.4')
    rows = feeds.feeds_sections()
    assert len(rows) == 3
    assert all(len(row) == 3 for row in rows)
    pairs = {row[0]: row for row in rows}
    assert pairs['Spamhaus DROP'][1] == '2'
    assert pairs['Spamhaus DROP'][2] == 'cached'
    assert pairs['Feodo Tracker'][1] == '2'
    assert pairs['FireHOL Level 1'][1] == '2'


def test_feeds_sections_not_loaded():
    rows = feeds.feeds_sections()
    assert len(rows) == 3
    assert rows[0] == ['Spamhaus DROP', '0', 'not loaded']


def test_feeds_sections_error_state(monkeypatch):
    FakeText().install(monkeypatch)
    feeds._load_feed('spamhaus_drop')
    rows = {row[0]: row for row in feeds.feeds_sections()}
    assert rows['Spamhaus DROP'][2] == 'error: timeout'


# ---------------------------------------------------------------------------
# intel_sections + caching
# ---------------------------------------------------------------------------

def test_intel_sections_combined(fake_http, monkeypatch):
    _install_feeds(monkeypatch)
    fake_http.json = lambda url, **kw: (True, RELAY_PAYLOAD, '')
    rows = feeds.intel_sections('5.6.7.8')
    pairs = {row[0]: row[1] for row in rows}
    assert pairs['Tor exit node'] == 'No'  # exit list holds 9.9.9.9
    assert pairs['Tor relay nickname'] == 'ExitRelayExample'
    assert pairs['Spamhaus DROP'] == 'listed'
    assert pairs['Feodo Tracker'] == 'listed'
    assert pairs['FireHOL Level 1'] == 'clear'
    assert pairs['Feeds listed'] == '2'
    assert len(fake_http.calls) == 1  # exactly one Onionoo lookup


def test_intel_sections_disabled(monkeypatch):
    monkeypatch.setattr(config.app_config, 'feeds_enabled', False)
    assert feeds.intel_sections('1.2.3.4') == [['Threat intel', 'disabled']]


def test_intel_sections_invalid_ip_never_raises(fake_http, monkeypatch):
    failing = FakeText().install(monkeypatch)
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    rows = feeds.intel_sections('banana')
    pairs = {row[0]: row[1] for row in rows}
    assert pairs['Tor exit node'] == 'No'
    assert pairs['Feeds listed'] == '0'
    assert failing.count == 0


def test_second_check_does_not_refetch(fake_http, monkeypatch):
    _no_relays(fake_http)
    fake = _install_feeds(monkeypatch)
    feeds.check_ip('1.2.3.4')
    assert fake.count == 4  # exit list + three feeds
    feeds.check_ip('1.2.3.4')
    assert fake.count == 4  # everything served from the module caches
    # the per-address Onionoo lookup runs per check (the shared HTTP cache
    # would dedupe it in production; it is disabled under pytest)
    assert len(fake_http.calls) == 2
