"""IP source readers and merge/provenance tests."""


from obscuralens.config import config
from obscuralens.trackers import ip_sources


def test_shodan_internetdb_parses(fake_http):
    fake_http.json = lambda url, **kw: (True, {
        'ip': '8.8.8.8', 'ports': [53, 443], 'vulns': ['CVE-2020-1234'],
        'cpes': ['cpe:/a:google:dns'], 'hostnames': ['dns.google'],
        'tags': ['dns'],
    }, '')
    out = ip_sources._shodan_internetdb('8.8.8.8')
    assert out['ports'] == [53, 443]
    assert out['vulns'] == ['CVE-2020-1234']
    assert out['hostnames'] == ['dns.google']


def test_shodan_internetdb_no_information(fake_http):
    fake_http.json = lambda url, **kw: (
        True, {'detail': 'No information available'}, '')
    assert ip_sources._shodan_internetdb('10.0.0.1') == {}


def test_ipwho_is_flattens_nested_payload(fake_http):
    fake_http.json = lambda url, **kw: (True, {
        'success': True, 'type': 'IPv4', 'country': 'Australia',
        'city': 'Sydney', 'latitude': -33.8, 'longitude': 151.2,
        'connection': {'asn': 13335, 'org': 'Cloudflare', 'isp': 'CF',
                       'domain': 'cloudflare.com'},
        'timezone': {'id': 'Australia/Sydney', 'abbr': 'AEST'},
        'flag': {'emoji': '🇦🇺'},
    }, '')
    out = ip_sources._ipwho_is('1.1.1.1')
    assert out['asn'] == 13335
    assert out['org'] == 'Cloudflare'
    assert out['timezone'] == 'Australia/Sydney'


def _fake_sources():
    return {
        'alpha': lambda ip: {'country': 'A-land', 'is_eu': False},
        'beta': lambda ip: {'country': 'B-land', 'city': 'Bee'},
        'broken': lambda ip: (_ for _ in ()).throw(RuntimeError('boom')),
        'empty': lambda ip: {},
    }


def test_ripestat_parses(fake_http):
    def dispatch(url, **kwargs):
        if 'prefix-overview' in url:
            return True, {'data': {
                'resource': '8.8.8.0/24',
                'announced': True,
                'asns': [{'asn': 15169, 'holder': 'GOOGLE - Google LLC'}],
                'block': {'desc': 'Administered by ARIN'},
            }}, ''
        if '/rir/' in url:
            return True, {'data': {'rirs': [{'rir': 'ARIN'}]}}, ''
        return False, None, 'unexpected url'

    fake_http.json = dispatch
    out = ip_sources._ripestat('8.8.8.8')
    assert out['prefix'] == '8.8.8.0/24'
    assert out['asn'] == 15169
    assert 'GOOGLE' in out['bgp_description']
    assert out['ip_block'] == 'Administered by ARIN'
    assert out['rir'] == 'ARIN'


def test_ripestat_degrades_gracefully(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    assert ip_sources._ripestat('8.8.8.8') == {}


def test_greynoise_hit_parses(fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=200,
        json_data={'ip': '1.2.3.4', 'noise': True, 'riot': False,
                   'classification': 'malicious',
                   'name': 'Mirai', 'last_seen': '2026-09-01',
                   'message': 'seen scanning'})
    out = ip_sources._greynoise('1.2.3.4')
    assert out['gn_noise'] is True
    assert out['gn_riot'] is False
    assert out['gn_classification'] == 'malicious'
    assert out['gn_name'] == 'Mirai'
    assert out['gn_message'] == 'seen scanning'


def test_greynoise_not_observed_is_real_answer(fake_http, fake_response):
    """A 404 'not observed' body is valuable intel, not a failure."""
    fake_http.get = lambda url, **kw: fake_response(
        status_code=404,
        json_data={'ip': '8.8.8.8', 'noise': False, 'riot': False,
                   'message': 'IP not observed scanning the internet.'})
    out = ip_sources._greynoise('8.8.8.8')
    assert out['gn_noise'] is False
    assert out['gn_riot'] is False
    assert out['gn_message'] == 'IP not observed scanning the internet.'
    # Absent classification/name are dropped, not rendered as empty.
    assert 'gn_classification' not in out
    assert 'gn_name' not in out


def test_greynoise_other_status_is_no_data(fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=429, json_data={'error': 'rate limited'})
    assert ip_sources._greynoise('1.2.3.4') == {}


def test_greynoise_network_error_is_no_data(fake_http):
    def boom(url, **kwargs):
        raise ConnectionError('down')

    fake_http.get = boom
    assert ip_sources._greynoise('1.2.3.4') == {}


def test_greynoise_attaches_configured_key(fake_http, fake_response,
                                           monkeypatch):
    seen = {}

    def capture(url, **kwargs):
        seen.update(kwargs.get('headers') or {})
        return fake_response(status_code=200, json_data={'noise': False})

    fake_http.get = capture
    monkeypatch.setattr(config, 'get_api_key',
                        lambda service: 'secret' if service == 'greynoise' else None)
    out = ip_sources._greynoise('1.2.3.4')
    assert seen.get('key') == 'secret'
    assert out['gn_noise'] is False


def test_greynoise_runs_without_key_in_gather(monkeypatch):
    """The source must run keyless: previously it never ran at all because
    IPTracker._keys() never supplied the key its keyed registration needed."""
    monkeypatch.setattr(ip_sources, 'FREE_SOURCES', {
        'greynoise': lambda ip: {'gn_noise': False},
    })
    out = ip_sources.gather_all('8.8.8.8', {})
    assert out['sources']['greynoise']['ok'] is True
    assert out['fields']['gn_noise'] is False


def test_gather_all_merges_deterministically(monkeypatch):
    monkeypatch.setattr(ip_sources, 'FREE_SOURCES', _fake_sources())
    out = ip_sources.gather_all('1.2.3.4')

    # Registration order wins conflicts.
    assert out['fields']['country'] == 'A-land'
    # Explicit False is kept.
    assert out['fields']['is_eu'] is False
    # Provenance records every provider of a field.
    assert out['provenance']['country'] == ['alpha', 'beta']
    assert out['provenance']['city'] == ['beta']
    # Failure and empty status are reported, never raised.
    assert out['sources']['broken']['ok'] is False
    assert out['sources']['broken']['error'] == 'RuntimeError'
    assert out['sources']['empty']['ok'] is False
    assert out['sources']['alpha']['ok'] is True


def test_gather_all_respects_disabled_sources(monkeypatch):
    monkeypatch.setattr(ip_sources, 'FREE_SOURCES', _fake_sources())
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['beta'])
    out = ip_sources.gather_all('1.2.3.4')
    assert 'beta' not in out['sources']
    assert out['fields']['country'] == 'A-land'


def test_gather_all_coordinate_spread(monkeypatch):
    monkeypatch.setattr(ip_sources, 'FREE_SOURCES', {
        'one': lambda ip: {'latitude': 1.0, 'longitude': 2.0, 'city': 'X'},
        'two': lambda ip: {'latitude': 3.0, 'longitude': 4.0, 'city': 'Y'},
    })
    out = ip_sources.gather_all('1.2.3.4')
    coords = out['fields']['coordinates_by_source']
    assert {c['source'] for c in coords} == {'one', 'two'}
    assert out['fields']['city_disagreement'] == ['X', 'Y']


def test_keyed_source_runs_when_key_present(monkeypatch):
    monkeypatch.setattr(ip_sources, 'FREE_SOURCES', {})
    seen = {}

    def fake_abuseipdb(ip, key):
        seen['key'] = key
        return {'abuse_confidence': 0}

    monkeypatch.setattr(ip_sources, '_abuseipdb', fake_abuseipdb)
    out = ip_sources.gather_all('1.2.3.4', {'abuseipdb': 'secret'})
    assert seen['key'] == 'secret'
    assert out['fields']['abuse_confidence'] == 0
