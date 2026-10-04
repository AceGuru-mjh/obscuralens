"""ASN source readers, merge/provenance and tracker behaviour tests."""

import pytest

from obscuralens.config import config
from obscuralens.trackers import asn_sources
from obscuralens.trackers import asn_tracker as asn_tracker_module
from obscuralens.trackers.asn_tracker import ASNTracker

# ---------------------------------------------------------------------------
# Payload builders (shaped like the real provider responses)
# ---------------------------------------------------------------------------

def _overview(holder='GOOGLE - Google LLC', desc='Google LLC, Mountain View, CA',
              website='https://www.google.com'):
    return {'data': {'resource': 'AS15169', 'holder': holder, 'name': 'Google LLC',
                     'desc': desc, 'website': website, 'announced': True}}


def _prefixes(v4=2, v6=1):
    return {'data': {'prefixes':
                     [{'prefix': f'8.8.{i}.0/24', 'timely': True} for i in range(v4)] +
                     [{'prefix': f'2001:4860:4860:{i}::/48', 'timely': True}
                      for i in range(v6)]}}


RIPE_OVERVIEW = _overview()
RIPE_PREFIXES = _prefixes()

BGPVIEW_ASN = {
    'data': {
        'asn': 15169,
        'name': 'GOOGLE',
        'description_short': 'Google LLC (United States)',
        'description_long': 'Google LLC, 1600 Amphitheatre Parkway',
        'country_code': 'US',
        'website': 'https://www.google.com',
        'email_address': 'network-abuse@google.com',
    }
}

BGPVIEW_PREFIXES = {
    'data': {
        'ipv4_prefixes': [
            {'prefix': '8.8.4.0/24', 'name': 'GOOGLE-DNS', 'description': 'Public DNS',
             'country_code': 'US'},
            {'prefix': '8.8.8.0/24', 'name': 'GOOGLE-DNS', 'description': 'Public DNS',
             'country_code': 'US'},
        ],
        'ipv6_prefixes': [
            {'prefix': '2001:4860:4860::/48', 'name': 'GOOGLE-DNS'},
        ],
    }
}

BGPVIEW_PEERS = {
    'data': {
        'ipv4_peers': [
            {'asn': 174, 'name': 'Cogent Communications'},
            {'asn': 3356, 'name': 'Lumen'},
        ],
        'ipv6_peers': [
            {'asn': 174, 'name': 'Cogent Communications'},
            {'asn': 6939, 'name': 'Hurricane Electric'},
        ],
    }
}

# v6.1: CAIDA AS-Rank and PeeringDB fixtures.
ASRANK_ASN = {
    'data': {
        'asn': {
            'rank': 1556,
            'asn': '15169',
            'asnName': 'GOOGLE',
            'source': 'ARIN',
            'cliqueMember': True,
            'ixp': False,
            'seen': True,
            'cone': {'number': 4231},
        }
    }
}

PEERINGDB_NET = {
    'data': [{
        'id': 433,
        'org_id': 574,
        'name': 'Google LLC',
        'name_long': '',
        'website': 'https://about.google/intl/en/',
        'info_type': 'NSP',
        'info_traffic': '1-5 Tbps',
        'policy_general': 'Selective',
        'ix_count': 145,
        'netixlan_updated': '2025-01-01T00:00:00Z',
    }]
}


def _all_sources(url, **kwargs):
    """Dispatch any of the ASN source URLs to a fixture payload."""
    if 'as-overview' in url:
        return True, RIPE_OVERVIEW, ''
    if 'announced-prefixes' in url:
        return True, RIPE_PREFIXES, ''
    if '/peers' in url:
        return True, BGPVIEW_PEERS, ''
    if '/prefixes' in url:
        return True, BGPVIEW_PREFIXES, ''
    if 'api.asrank.caida.org' in url:
        return True, ASRANK_ASN, ''
    if 'peeringdb.com/api/net' in url:
        return True, PEERINGDB_NET, ''
    if 'api.bgpview.io/asn/' in url:
        return True, BGPVIEW_ASN, ''
    return False, None, f'unexpected url {url}'


@pytest.fixture()
def recording_db(monkeypatch):
    """Replace the tracker's db with a call recorder."""
    calls = []

    class _Db:
        def save_query(self, query_type, query_value, result_data,
                       success=True, error_message=''):
            calls.append({'type': query_type, 'value': query_value,
                          'success': success, 'error': error_message})
            return len(calls)

    monkeypatch.setattr(asn_tracker_module, 'db', _Db())
    return calls


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def test_parsing_helpers():
    assert asn_sources._as_number('AS15169') == 15169
    assert asn_sources._as_number('15169') == 15169
    assert asn_sources._as_number(3356) == 3356
    assert asn_sources._as_number('banana') == 0
    assert asn_sources._unique(['a', 'b', 'a', 'b']) == ['a', 'b']
    assert asn_sources._peer_labels([{'asn': 174, 'name': 'Cogent'}]) == ['AS174 Cogent']
    # Peers without a name and junk entries degrade to bare labels / skips.
    assert asn_sources._peer_labels([{'asn': 1299}, 'junk', {}]) == ['AS1299']
    assert asn_sources._prefixes_of([{'prefix': '8.8.8.0/24'}, {'timely': True}]) == ['8.8.8.0/24']


# ---------------------------------------------------------------------------
# RIPEstat reader
# ---------------------------------------------------------------------------

def test_ripestat_overview_and_prefixes(fake_http):
    fake_http.json = _all_sources
    out = asn_sources._ripestat('AS15169')

    assert out['asn_name'] == 'GOOGLE - Google LLC'
    assert out['asn_description'] == 'Google LLC, Mountain View, CA'
    assert out['asn_website'] == 'https://www.google.com'
    assert out['announced_prefixes'] == ['8.8.0.0/24', '8.8.1.0/24',
                                         '2001:4860:4860:0::/48']
    assert out['announced_prefix_count'] == 3
    assert out['announced_v4_count'] == 2
    assert out['announced_v6_count'] == 1


def test_ripestat_normalises_input_for_urls(fake_http):
    fake_http.json = _all_sources
    asn_sources._ripestat('AS15169')
    urls = [u for kind, u in fake_http.calls if kind == 'json']
    assert any('resource=AS15169' in u for u in urls)
    assert len(urls) == 2


def test_ripestat_description_truncated(fake_http):
    long_desc = 'x' * 400
    fake_http.json = lambda url, **kw: (True, _overview(desc=long_desc), '') \
        if 'as-overview' in url else (True, _prefixes(0, 0), '')
    out = asn_sources._ripestat('AS15169')
    assert len(out['asn_description']) == 300


def test_ripestat_prefix_list_capped(fake_http):
    fake_http.json = lambda url, **kw: (True, _overview(), '') \
        if 'as-overview' in url else (True, _prefixes(60, 0), '')
    out = asn_sources._ripestat('AS15169')
    assert len(out['announced_prefixes']) == 50
    assert out['announced_prefix_count'] == 60
    assert out['announced_v4_count'] == 60
    assert out['announced_v6_count'] == 0


def test_ripestat_half_failure_degrades(fake_http):
    def dispatch(url, **kwargs):
        if 'as-overview' in url:
            return True, RIPE_OVERVIEW, ''
        return False, None, 'timeout'

    fake_http.json = dispatch
    out = asn_sources._ripestat('AS15169')
    assert out['asn_name'] == 'GOOGLE - Google LLC'
    assert 'announced_prefixes' not in out

    def dispatch2(url, **kwargs):
        if 'announced-prefixes' in url:
            return True, RIPE_PREFIXES, ''
        return False, None, 'timeout'

    fake_http.json = dispatch2
    out = asn_sources._ripestat('AS15169')
    assert out['announced_prefix_count'] == 3
    assert 'asn_name' not in out


def test_ripestat_http_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'connection failed')
    assert asn_sources._ripestat('AS15169') == {}


# ---------------------------------------------------------------------------
# BGPView reader
# ---------------------------------------------------------------------------

def test_bgpview_identity_fields(fake_http):
    fake_http.json = _all_sources
    out = asn_sources._bgpview('AS15169')

    assert out['bgpview_name'] == 'GOOGLE'
    # description_short is preferred over description_long.
    assert out['bgpview_description'] == 'Google LLC (United States)'
    assert out['asn_country'] == 'US'
    assert out['asn_website'] == 'https://www.google.com'
    assert out['asn_email'] == 'network-abuse@google.com'


def test_bgpview_description_falls_back_to_long(fake_http):
    payload = dict(BGPVIEW_ASN)
    payload['data'] = dict(payload['data'])
    payload['data']['description_short'] = None

    def dispatch(url, **kwargs):
        if 'api.bgpview.io/asn/' in url and '/prefixes' not in url and '/peers' not in url:
            return True, payload, ''
        return False, None, 'down'

    fake_http.json = dispatch
    out = asn_sources._bgpview('AS15169')
    assert out['bgpview_description'] == 'Google LLC, 1600 Amphitheatre Parkway'


def test_bgpview_prefix_parsing_and_caps(fake_http):
    payload = {'data': {
        'ipv4_prefixes': [{'prefix': f'8.8.{i}.0/24'} for i in range(35)],
        'ipv6_prefixes': [{'prefix': f'2001:4860:4860:{i}::/48'} for i in range(20)],
    }}

    def dispatch(url, **kwargs):
        if '/prefixes' in url:
            return True, payload, ''
        return False, None, 'down'

    fake_http.json = dispatch
    out = asn_sources._bgpview('AS15169')
    assert len(out['bgpview_ipv4_prefixes']) == 30
    assert out['ipv4_prefix_count'] == 35
    assert len(out['bgpview_ipv6_prefixes']) == 15
    assert out['ipv6_prefix_count'] == 20


def test_bgpview_peers_dedup_and_labels(fake_http):
    fake_http.json = _all_sources
    out = asn_sources._bgpview('AS15169')
    # AS174 appears in both families and is counted once.
    assert out['peers'] == ['AS174 Cogent Communications', 'AS3356 Lumen',
                            'AS6939 Hurricane Electric']
    assert out['peer_count'] == 3


def test_bgpview_peer_cap(fake_http):
    many = {'data': {
        'ipv4_peers': [{'asn': 65000 + i, 'name': f'AS{i} Networks'} for i in range(25)],
        'ipv6_peers': [],
    }}

    def dispatch(url, **kwargs):
        if '/peers' in url:
            return True, many, ''
        return False, None, 'down'

    fake_http.json = dispatch
    out = asn_sources._bgpview('AS15169')
    assert len(out['peers']) == 20
    assert out['peer_count'] == 25


def test_bgpview_partial_failure_degrades(fake_http):
    def dispatch(url, **kwargs):
        if 'api.bgpview.io/asn/15169' in url and '/prefixes' not in url and '/peers' not in url:
            return True, BGPVIEW_ASN, ''
        return False, None, 'http 404'

    fake_http.json = dispatch
    out = asn_sources._bgpview('AS15169')
    assert out['asn_country'] == 'US'
    assert 'peers' not in out
    assert 'ipv4_prefix_count' not in out


def test_bgpview_http_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    assert asn_sources._bgpview('AS15169') == {}


# ---------------------------------------------------------------------------
# gather_all: merge, provenance, failure isolation
# ---------------------------------------------------------------------------

def _fake_sources():
    return {
        'ripestat': lambda asn: {'asn_name': 'RIPE holder', 'asn_website': 'ripe.example'},
        'bgpview': lambda asn: {'asn_name': 'BGPView name', 'asn_country': 'US'},
        'broken': lambda asn: (_ for _ in ()).throw(RuntimeError('boom')),
        'empty': lambda asn: {},
    }


def test_gather_all_invalid_value_raises():
    with pytest.raises(ValueError, match='invalid AS number'):
        asn_sources.gather_all('banana')
    with pytest.raises(ValueError):
        asn_sources.gather_all('')


def test_gather_all_injects_identifier(monkeypatch):
    monkeypatch.setattr(asn_sources, 'FREE_SOURCES',
                        {'one': lambda asn: {'asn_name': 'X'}})
    out = asn_sources.gather_all('AS15169')
    assert out['fields']['asn'] == 15169
    assert out['fields']['asn_display'] == 'AS15169'

    out = asn_sources.gather_all('15169')
    assert out['fields']['asn'] == 15169
    assert out['fields']['asn_display'] == 'AS15169'


def test_gather_all_merges_with_provenance(monkeypatch):
    monkeypatch.setattr(asn_sources, 'FREE_SOURCES', _fake_sources())
    out = asn_sources.gather_all('AS15169')

    # Registration order wins conflicts (ripestat is registered first).
    assert out['fields']['asn_name'] == 'RIPE holder'
    # Provenance records every provider of a field.
    assert out['provenance']['asn_name'] == ['ripestat', 'bgpview']
    assert out['provenance']['asn_country'] == ['bgpview']
    # Injected identifier fields are always present.
    assert out['fields']['asn'] == 15169
    assert out['fields']['asn_display'] == 'AS15169'
    # Failure and empty status are reported, never raised.
    assert out['sources']['broken']['ok'] is False
    assert out['sources']['broken']['error'] == 'RuntimeError'
    assert out['sources']['empty']['ok'] is False
    assert out['sources']['ripestat']['ok'] is True


def test_gather_all_failure_isolation(monkeypatch):
    monkeypatch.setattr(asn_sources, 'FREE_SOURCES', _fake_sources())
    out = asn_sources.gather_all('AS15169')
    assert out['fields']['asn_country'] == 'US'
    assert out['fields']['asn_website'] == 'ripe.example'


def test_gather_all_respects_disabled_sources(monkeypatch):
    monkeypatch.setattr(asn_sources, 'FREE_SOURCES', _fake_sources())
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['bgpview'])
    out = asn_sources.gather_all('AS15169')
    assert 'bgpview' not in out['sources']
    assert out['fields']['asn_name'] == 'RIPE holder'


def test_registries_are_consistent():
    assert set(asn_sources.FREE_SOURCES) == {'ripestat', 'bgpview',
                                             'asrank', 'peeringdb'}
    assert asn_sources.KEYED_SOURCES == {}
    assert set(asn_sources.SOURCE_CATALOG) == set(asn_sources.FREE_SOURCES)


# ---------------------------------------------------------------------------
# ASNTracker
# ---------------------------------------------------------------------------

def test_tracker_success_shape(fake_http, recording_db):
    fake_http.json = _all_sources
    result = ASNTracker().track('AS15169')

    assert result['asn'] == 15169
    assert result['success'] is True
    assert result['sources_ok'] == ['asrank', 'bgpview', 'peeringdb', 'ripestat']
    assert result['sources_failed'] == {}
    assert result['errors'] == []
    assert result['field_count'] > 5
    # Identifier fields are part of the merged info.
    assert result['info']['asn'] == 15169
    assert result['info']['asn_display'] == 'AS15169'
    assert result['info']['asn_name'] == 'GOOGLE - Google LLC'
    assert result['info']['asn_country'] == 'US'
    assert result['info']['peers'][0] == 'AS174 Cogent Communications'
    # Both sources supply the website; provenance lists them in order.
    assert result['field_sources']['asn_website'] == ['ripestat', 'bgpview']
    assert result['field_sources']['peers'] == ['bgpview']
    # Query history got exactly one successful row keyed by the bare number.
    assert len(recording_db) == 1
    assert recording_db[0]['type'] == 'asn'
    assert recording_db[0]['value'] == '15169'
    assert recording_db[0]['success'] is True


def test_tracker_accepts_bare_number(fake_http, recording_db):
    fake_http.json = _all_sources
    result = ASNTracker().track('15169')
    assert result['asn'] == 15169
    assert result['success'] is True
    assert recording_db[0]['value'] == '15169'


def test_tracker_all_sources_failed(fake_http, recording_db):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    result = ASNTracker().track('AS15169')
    assert result['success'] is False
    assert result['errors'] == ['all data sources failed']
    assert result['info'] == {'asn': 15169, 'asn_display': 'AS15169'}
    assert result['field_count'] == 2
    assert recording_db[0]['success'] is False
    assert recording_db[0]['error'] == 'all data sources failed'


def test_tracker_invalid_value_skips_everything(fake_http, recording_db):
    fake_http.json = _all_sources
    result = ASNTracker().track('AS0')

    assert result['success'] is False
    assert result['info'] == {}
    assert result['field_count'] == 0
    assert result['sources_ok'] == []
    assert result['errors'] and 'out of range' in result['errors'][0]
    assert fake_http.calls == []
    assert recording_db == []


def test_tracker_non_numeric_value(fake_http, recording_db):
    result = ASNTracker().track('coffee')
    assert result['success'] is False
    assert 'Invalid AS number' in result['errors'][0]
    assert recording_db == []


def test_batch_track_preserves_order(fake_http, recording_db):
    fake_http.json = _all_sources
    results = ASNTracker().batch_track(['AS15169', 'bogus', '3356'])

    assert len(results) == 3
    assert results[0]['asn'] == 15169
    assert results[0]['success'] is True
    assert results[1]['success'] is False
    assert results[2]['asn'] == 3356
    assert results[2]['success'] is True
    # Two valid lookups were saved; the invalid one never reached history.
    assert len(recording_db) == 2


def test_tracker_helpers():
    tracker = ASNTracker()
    assert tracker.source_names() == ['asrank', 'bgpview', 'peeringdb',
                                     'ripestat']
    assert set(tracker.source_catalog()) == set(asn_sources.SOURCE_CATALOG)
    assert 'keyless' in tracker.source_catalog()['ripestat']
