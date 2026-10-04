"""URL source and tracker tests (all offline, HTTP faked via conftest)."""

import base64
from datetime import datetime, timezone

from obscuralens.config import config
from obscuralens.trackers import url_sources as us
from obscuralens.trackers.url_tracker import URLTracker

# ---------------------------------------------------------------------------
# http_probe
# ---------------------------------------------------------------------------

def test_http_probe_walks_multi_hop_redirect_chain(fake_http, fake_response):
    """301 -> 302 -> 200 with a relative Location on the first hop."""
    pages = {
        'http://start.example/path': fake_response(
            status_code=301, headers={'Location': '/mid'},
            url='http://start.example/path'),
        'http://start.example/mid': fake_response(
            status_code=302, headers={'Location': 'https://final.example/landed'},
            url='http://start.example/mid'),
        'https://final.example/landed': fake_response(
            status_code=200,
            text='<html><head><title>  Final\n  Page </title></head></html>',
            headers={'Server': 'nginx', 'Content-Type': 'text/html; charset=utf-8'},
            url='https://final.example/landed'),
    }
    fake_http.get = lambda url, **kw: pages[url]

    out = us._http_probe('http://start.example/path')
    assert out['redirect_count'] == 2
    assert out['redirect_chain'] == [
        {'url': 'http://start.example/mid', 'status': 301},
        {'url': 'https://final.example/landed', 'status': 302},
    ]
    assert out['http_status'] == 200
    assert out['final_url'] == 'https://final.example/landed'
    assert out['http_title'] == 'Final Page'   # whitespace collapsed, stripped
    assert out['http_server'] == 'nginx'
    assert out['content_type'] == 'text/html; charset=utf-8'
    # structural fields describe the *target* URL, not the landing page
    assert out['scheme'] == 'http'
    assert out['host'] == 'start.example'
    assert out['host_is_ip'] is False


def test_http_probe_target_structure_for_ip_host(fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=200, text='plain body, no title', headers={},
        url='https://172.16.32.64:8443/admin')

    out = us._http_probe('https://172.16.32.64:8443/admin')
    assert out['host_is_ip'] is True
    assert out['scheme'] == 'https'
    assert out['host'] == '172.16.32.64'
    assert out['port'] == 8443
    assert out['redirect_count'] == 0
    assert out['redirect_chain'] == []
    assert 'http_title' not in out
    assert 'http_server' not in out


def test_http_probe_stops_at_hop_cap(fake_http, fake_response):
    """An endless redirect loop is cut off after MAX_REDIRECT_HOPS."""
    def getter(url, **kw):
        if kw.get('allow_redirects'):
            return fake_response(status_code=200, text='<title>Settled</title>',
                                 url=url)
        return fake_response(status_code=301, headers={'Location': url + 'x'},
                             url=url)

    fake_http.get = getter
    out = us._http_probe('http://loop.example/a')
    assert out['redirect_count'] == us.MAX_REDIRECT_HOPS
    assert len(out['redirect_chain']) == us.MAX_REDIRECT_HOPS
    assert out['redirect_chain'][0] == {'url': 'http://loop.example/ax', 'status': 301}
    # the permissive final fetch settles the walk on a real page
    assert out['http_status'] == 200
    assert out['http_title'] == 'Settled'


def test_http_probe_ignores_bogus_redirect_location(fake_http, fake_response):
    """A Location we cannot follow (e.g. mailto:) stops the walk, not the reader."""
    fake_http.get = lambda url, **kw: fake_response(
        status_code=302, headers={'Location': 'mailto:evil@example.com'}, url=url)
    out = us._http_probe('https://odd.example/x')
    assert out['redirect_count'] == 0
    assert out['http_status'] == 302
    assert out['final_url'] == 'https://odd.example/x'


def test_http_probe_returns_empty_on_transport_error(fake_http):
    def boom(url, **kw):
        raise RuntimeError('connection reset')

    fake_http.get = boom
    assert us._http_probe('https://down.example/') == {}


# ---------------------------------------------------------------------------
# urlscan
# ---------------------------------------------------------------------------

def test_urlscan_parses_history_and_verdicts(fake_http):
    payload = {
        'total': 3,
        'results': [
            {'task': {'url': 'https://t.example/a', 'time': '2026-10-01T11:18:49.508Z',
                      'uuid': 'u1'},
             'page': {'url': 'https://t.example/a', 'domain': 't.example',
                      'country': 'US', 'title': 'Landing'},
             'stats': {},
             'verdicts': {'overall': {'malicious': True}}},
            {'task': {'url': 'https://t.example/a', 'time': '2026-09-30T10:00:00.000Z',
                      'uuid': 'u2'},
             'page': {'url': 'https://t.example/a', 'domain': 't.example',
                      'country': 'DE', 'title': 'Landing'},
             'stats': {},
             'verdicts': {'overall': {'malicious': False}}},
            {'task': {'url': 'https://t.example/a', 'time': '2026-09-29T09:00:00.000Z',
                      'uuid': 'u3'},
             'page': {'url': 'https://t.example/a', 'domain': 't.example',
                      'country': 'US'},
             'stats': {},
             'verdicts': {}},
        ],
    }
    fake_http.json = lambda url, **kw: (True, payload, '')

    out = us._urlscan('https://t.example/a')
    assert out['urlscan_total'] == 3
    assert out['urlscan_last_scan'] == '2026-10-01T11:18:49.508Z'
    assert out['urlscan_last_title'] == 'Landing'
    assert out['urlscan_malicious_verdicts'] == 1
    assert out['urlscan_countries'] == ['DE', 'US']


def test_urlscan_quotes_the_query(fake_http):
    seen = []

    def dispatch(url, **kw):
        seen.append(url)
        return (True, {'results': []}, '')

    fake_http.json = dispatch
    assert us._urlscan('https://t.example/a?x=1') == {}
    assert seen and 'urlscan.io/api/v1/search/' in seen[0]
    # the full URL is embedded quoted, so it cannot break the query string
    assert 'https://t.example/a?x=1' not in seen[0]


def test_urlscan_empty_or_failing(fake_http):
    fake_http.json = lambda url, **kw: (True, {'results': []}, '')
    assert us._urlscan('https://t.example/a') == {}

    fake_http.json = lambda url, **kw: (True, {'total': 0, 'results': []}, '')
    assert us._urlscan('https://t.example/a') == {}

    fake_http.json = lambda url, **kw: (False, None, 'timeout')
    assert us._urlscan('https://t.example/a') == {}


# ---------------------------------------------------------------------------
# wayback
# ---------------------------------------------------------------------------

def test_wayback_parses_capture_history(fake_http):
    header = ['urlkey', 'timestamp', 'original', 'mimetype', 'statuscode',
              'digest', 'length']
    data = [header,
            ['net,t.example)/a', '20010115000000', 'http://t.example/a',
             'text/html', '200', 'digest1', '123'],
            ['net,t.example)/a', '20230401120000', 'http://t.example/a',
             'text/html', '404', 'digest1', '123'],
            ['net,t.example)/a', '20150620110000', 'http://t.example/a',
             'text/html', '200', 'digest1', '123']]
    fake_http.json = lambda url, **kw: (True, data, '')

    out = us._wayback('http://t.example/a')
    assert out['wayback_captures'] == 3
    assert out['wayback_first_capture'] == '2001-01-15'
    assert out['wayback_last_capture'] == '2023-04-01'
    assert out['wayback_status_codes'] == [200, 404]


def test_wayback_tolerates_malformed_rows(fake_http):
    data = [['urlkey', 'timestamp', 'original', 'mimetype', 'statuscode'],
            'not-a-list',
            ['net,x)/', '20200101000000', 'http://x/', 'text/html', '301'],
            ['too-short']]
    fake_http.json = lambda url, **kw: (True, data, '')

    out = us._wayback('http://x/')
    assert out['wayback_captures'] == 1
    assert out['wayback_first_capture'] == '2020-01-01'
    assert out['wayback_last_capture'] == '2020-01-01'
    assert out['wayback_status_codes'] == [301]


def test_wayback_without_captures(fake_http):
    fake_http.json = lambda url, **kw: (True, [], '')
    assert us._wayback('https://never.example/') == {}

    header = ['urlkey', 'timestamp', 'original', 'mimetype', 'statuscode']
    fake_http.json = lambda url, **kw: (True, [header], '')
    assert us._wayback('https://never.example/') == {}


def test_wayback_date_helper():
    assert us._wayback_date('20230102030405') == '2023-01-02'
    assert us._wayback_date('20230102') == '2023-01-02'
    assert us._wayback_date('garbage') is None
    assert us._wayback_date(None) is None
    assert us._wayback_date(20230102) is None


# ---------------------------------------------------------------------------
# google_safe_browsing (keyed, POST)
# ---------------------------------------------------------------------------

def test_gsb_flags_threats_and_sends_expected_payload(monkeypatch):
    seen = {}

    def fake_post(url, payload=None, **kw):
        seen['url'] = url
        seen['payload'] = payload
        return (True, {'matches': [{'threatType': 'MALWARE'},
                                   {'threatType': 'SOCIAL_ENGINEERING'}]}, '')

    monkeypatch.setattr(us.http, 'post_json', fake_post)

    out = us._google_safe_browsing('https://bad.example/', 'gsb-key')
    assert out['gsb_threat_types'] == ['MALWARE', 'SOCIAL_ENGINEERING']
    assert out['gsb_malicious'] is True
    assert 'key=gsb-key' in seen['url']

    payload = seen['payload']
    assert payload['client'] == {'clientId': 'obscuralens', 'clientVersion': '4.0'}
    assert payload['threatInfo']['threatEntries'] == [{'url': 'https://bad.example/'}]
    assert payload['threatInfo']['platformTypes'] == ['ANY_PLATFORM']
    assert 'MALWARE' in payload['threatInfo']['threatTypes']
    assert 'POTENTIALLY_HARMFUL_APPLICATION' in payload['threatInfo']['threatTypes']


def test_gsb_clean_url_is_a_verdict_not_a_failure(monkeypatch):
    monkeypatch.setattr(us.http, 'post_json',
                        lambda url, payload=None, **kw: (True, {}, ''))
    out = us._google_safe_browsing('https://good.example/', 'k')
    assert out['gsb_malicious'] is False
    assert out['gsb_threat_types'] == []
    assert out  # non-empty dict: the source still counts as 'ok'


def test_gsb_transport_failure_returns_empty(monkeypatch):
    def boom(url, payload=None, **kw):
        raise RuntimeError('no network')

    monkeypatch.setattr(us.http, 'post_json', boom)
    assert us._google_safe_browsing('https://x.example/', 'k') == {}


# ---------------------------------------------------------------------------
# virustotal (keyed, GET with base64url identifier)
# ---------------------------------------------------------------------------

def test_virustotal_parses_attributes(fake_http):
    url = 'https://susp.example/download.exe'
    expected_id = base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii')
    expected_id = expected_id.rstrip('=')
    seen = {}

    def dispatch(request_url, **kw):
        seen['url'] = request_url
        seen['headers'] = kw.get('headers')
        return (True, {'data': {'attributes': {
            'last_analysis_stats': {'malicious': 3, 'suspicious': 1,
                                    'undetected': 60, 'harmless': 10},
            'reputation': -12,
            'last_analysis_date': '1700000000',
            'title': 'Free Money',
            'categories': {'alpha': 'phishing', 'beta': 'phishing'},
        }}}, '')

    fake_http.json = dispatch

    out = us._virustotal(url, 'vt-key')
    assert expected_id in seen['url']                       # correct VT url_id
    assert seen['headers'] == {'x-apikey': 'vt-key'}        # key sent as header
    assert out['vt_malicious'] == 3
    assert out['vt_suspicious'] == 1
    assert out['vt_reputation'] == -12
    assert out['malicious_score'] == 5                      # (3+1)/(3+1+60+10)
    expected_date = datetime.fromtimestamp(
        1700000000, tz=timezone.utc).strftime('%Y-%m-%d')
    assert out['vt_last_analysis'] == expected_date
    assert out['vt_title'] == 'Free Money'
    assert out['vt_categories'] == ['phishing']


def test_virustotal_identifier_is_unpadded_base64url(fake_http):
    """VT url ids are the base64url of the URL with '=' padding stripped."""
    raw = 'https://ab.co/xy'      # 16 bytes: base64 pads with '=='
    padded = base64.urlsafe_b64encode(raw.encode('utf-8')).decode('ascii')
    assert padded.endswith('==')                      # this URL does pad
    assert us._vt_url_id(raw) == padded.rstrip('=')

    seen = []
    fake_http.json = lambda u, **kw: seen.append(u) or (
        True, {'data': {'attributes': {}}}, '')
    out = us._virustotal(raw, 'k')
    assert seen[0].endswith(f"/urls/{padded.rstrip('=')}")
    assert out['vt_malicious'] == 0
    assert out['malicious_score'] == 0


def test_virustotal_failure_returns_empty(fake_http):
    fake_http.json = lambda url, **kw: (False, None, 'http 404')
    assert us._virustotal('https://gone.example/', 'k') == {}


# ---------------------------------------------------------------------------
# gather_all: merge, provenance, gating
# ---------------------------------------------------------------------------

def test_gather_all_merges_and_tracks_provenance(monkeypatch):
    monkeypatch.setattr(us, 'FREE_SOURCES', {
        'one': lambda url: {'http_status': 200, 'http_title': 'T'},
        'two': lambda url: {'http_status': 500},
        'broken': lambda url: (_ for _ in ()).throw(ValueError('x')),
    })
    monkeypatch.setattr(us, 'KEYED_SOURCES', {})

    out = us.gather_all('https://example.com/page')
    assert out['fields']['http_status'] == 200       # earlier source wins
    assert out['fields']['http_title'] == 'T'
    assert out['provenance']['http_status'] == ['one', 'two']
    assert out['sources']['one']['ok'] is True
    assert out['sources']['broken']['ok'] is False   # failure isolation
    assert out['sources']['broken']['error'] == 'ValueError'
    # target identity is injected after the merge
    assert out['fields']['url'] == 'https://example.com/page'
    assert out['fields']['domain'] == 'example.com'
    assert out['provenance']['domain'] == ['target']


def test_gather_all_keyed_gating(monkeypatch):
    calls = []
    monkeypatch.setattr(us, 'FREE_SOURCES', {})
    monkeypatch.setattr(us, 'KEYED_SOURCES', {
        'google_safe_browsing': lambda url, key: calls.append(('gsb', url, key))
                                              or {'gsb_malicious': True},
        'virustotal': lambda url, key: calls.append(('vt', url, key))
                                        or {'vt_malicious': 1},
    })

    # no keys configured -> keyed sources never run
    out = us.gather_all('https://example.com/')
    assert out['sources'] == {}
    assert 'vt_malicious' not in out['fields']
    assert calls == []

    # a key for one service unlocks only that service
    out = us.gather_all('https://example.com/', keys={'virustotal': 'vt-key'})
    assert out['sources'] == {'virustotal': {'ok': True, 'error': ''}}
    assert out['fields']['vt_malicious'] == 1
    assert calls == [('vt', 'https://example.com/', 'vt-key')]


def test_gather_all_respects_disabled_sources(monkeypatch):
    monkeypatch.setattr(us, 'FREE_SOURCES', {
        'http_probe': lambda url: {'a': 1},
        'urlscan': lambda url: {'b': 2},
    })
    monkeypatch.setattr(us, 'KEYED_SOURCES', {})
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['urlscan'])

    out = us.gather_all('https://example.com/')
    assert 'urlscan' not in out['sources']
    assert 'b' not in out['fields']
    assert 'http_probe' in out['sources']


def test_gather_all_skips_domain_for_ip_and_bare_hosts(monkeypatch):
    monkeypatch.setattr(us, 'FREE_SOURCES', {})
    monkeypatch.setattr(us, 'KEYED_SOURCES', {})

    out = us.gather_all('http://192.0.2.10/admin')
    assert out['fields']['url'] == 'http://192.0.2.10/admin'
    assert 'domain' not in out['fields']            # IP host is not a domain

    out = us.gather_all('http://localhost:8080/panel')
    assert 'domain' not in out['fields']            # single-label host


def test_source_registry_is_complete():
    assert set(us.FREE_SOURCES) == {'http_probe', 'urlscan', 'wayback',
                                    'openphish'}
    assert set(us.KEYED_SOURCES) == {'google_safe_browsing', 'virustotal'}
    for name in list(us.FREE_SOURCES) + list(us.KEYED_SOURCES):
        assert name in us.SOURCE_CATALOG


# ---------------------------------------------------------------------------
# URLTracker
# ---------------------------------------------------------------------------

def test_tracker_pulls_keys_from_config(monkeypatch):
    monkeypatch.setattr(config, 'get_api_key',
                        lambda service: {'google_safe_browsing': 'gsb-key',
                                         'virustotal': 'vt-key'}.get(service))
    assert URLTracker()._keys() == {'google_safe_browsing': 'gsb-key',
                                    'virustotal': 'vt-key'}


def test_tracker_result_shape_and_history(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.url_tracker.gather_all',
                        lambda url, keys=None: {
                            'fields': {'url': 'https://example.com/x',
                                       'domain': 'example.com',
                                       'final_url': 'https://example.com/x',
                                       'http_status': 200},
                            'sources': {'http_probe': {'ok': True, 'error': ''},
                                        'urlscan': {'ok': False, 'error': 'no data'}},
                            'provenance': {'http_status': ['http_probe']},
                        })

    result = URLTracker().track('https://example.com/x')
    assert result['url'] == 'https://example.com/x'
    assert result['domain'] == 'example.com'        # pivot key derived from info
    assert result['success'] is True
    assert result['sources_ok'] == ['http_probe']
    assert result['sources_failed'] == {'urlscan': 'no data'}
    assert result['field_sources']['http_status'] == ['http_probe']
    assert result['field_count'] == 4
    assert result['errors'] == ['1 source(s) unavailable']

    from obscuralens.database import db
    record = db.get_query_by_id(db.search_history('https://example.com/x')[0].id)
    assert record.query_type == 'url'


def test_tracker_invalid_url_skips_sources_and_db(monkeypatch, tmp_env):
    saved = []
    gathered = []
    monkeypatch.setattr('obscuralens.trackers.url_tracker.db.save_query',
                        lambda *a, **k: saved.append(a))
    monkeypatch.setattr('obscuralens.trackers.url_tracker.gather_all',
                        lambda *a, **k: gathered.append(a) or
                        {'fields': {}, 'sources': {}, 'provenance': {}})

    result = URLTracker().track('example.com')     # bare domain: not a URL
    assert result['success'] is False
    assert result['info'] == {}
    assert result['sources_ok'] == []
    assert result['errors'] == ['Invalid URL format (expected scheme://host/path)']
    assert saved == []                              # invalid target never persisted
    assert gathered == []                           # and never reaches the sources


def test_tracker_all_sources_failed(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.url_tracker.gather_all',
                        lambda url, keys=None: {
                            'fields': {'url': url},
                            'sources': {'http_probe': {'ok': False, 'error': 'timeout'}},
                            'provenance': {},
                        })
    result = URLTracker().track('https://quiet.example/')
    assert result['success'] is False
    assert result['errors'] == ['all data sources failed']
    assert 'domain' not in result


def test_tracker_end_to_end(fake_http, fake_response, monkeypatch, tmp_env):
    """Full pipeline: free sources via fake_http, keyed via patched handlers."""
    target = 'https://shop.example.com/checkout'
    pages = {
        target: fake_response(status_code=302, url=target,
                              headers={'Location': 'https://cdn.example.com/landed'}),
        'https://cdn.example.com/landed': fake_response(
            status_code=200, url='https://cdn.example.com/landed',
            text='<html><title>Checkout</title></html>',
            headers={'Server': 'cloudflare', 'Content-Type': 'text/html'}),
    }
    fake_http.get = lambda url, **kw: pages[url]

    def json_dispatch(url, **kw):
        if 'urlscan.io' in url:
            return (True, {'total': 1, 'results': [
                {'task': {'url': target, 'time': '2026-02-01T00:00:00.000Z',
                          'uuid': 'u'},
                 'page': {'url': target, 'domain': 'shop.example.com',
                          'country': 'US', 'title': 'Checkout'},
                 'stats': {}, 'verdicts': {'overall': {'malicious': True}}}]}, '')
        if 'web.archive.org' in url:
            return (True, [['urlkey', 'timestamp', 'original', 'mimetype',
                            'statuscode'],
                           ['k', '20200101000000', target, 'text/html', '200'],
                           ['k', '20240505000000', target, 'text/html', '200']], '')
        if 'virustotal.com' in url:
            return (True, {'data': {'attributes': {
                'last_analysis_stats': {'malicious': 2, 'suspicious': 0,
                                        'undetected': 68},
                'reputation': -5, 'last_analysis_date': '1700000000'}}}, '')
        return (False, None, 'unrouted')

    fake_http.json = json_dispatch
    monkeypatch.setattr(us.http, 'post_json',
                        lambda url, payload=None, **kw: (True, {}, ''))
    monkeypatch.setattr(config, 'get_api_key', lambda service: 'key')

    result = URLTracker().track(target)
    assert result['url'] == target
    assert result['domain'] == 'shop.example.com'
    assert result['success'] is True
    assert result['sources_ok'] == ['google_safe_browsing', 'http_probe',
                                    'urlscan', 'virustotal', 'wayback']

    info = result['info']
    assert info['final_url'] == 'https://cdn.example.com/landed'
    assert info['redirect_count'] == 1
    assert info['http_title'] == 'Checkout'
    assert info['http_server'] == 'cloudflare'
    assert info['urlscan_malicious_verdicts'] == 1
    assert info['wayback_captures'] == 2
    assert info['vt_malicious'] == 2
    assert info['gsb_malicious'] is False
    assert info['domain'] == 'shop.example.com'
    assert result['field_count'] >= 10


def test_tracker_risk_signals():
    dangerous = {
        'url': 'https://short.example/link',
        'info': {
            'gsb_malicious': True,
            'gsb_threat_types': ['MALWARE'],
            'vt_malicious': 4,
            'vt_suspicious': 1,
            'vt_reputation': -30,
            'urlscan_malicious_verdicts': 2,
            'redirect_count': 4,
            'final_url': 'https://other.example/landed',
        },
    }
    signals = ' | '.join(URLTracker.risk_signals(dangerous))
    assert 'Google Safe Browsing' in signals
    assert 'MALWARE' in signals
    assert 'VirusTotal' in signals
    assert 'urlscan.io' in signals
    assert '4 redirects' in signals
    assert 'different host' in signals

    clean = {'url': 'https://ok.example/', 'info': {'http_status': 200}}
    assert URLTracker.risk_signals(clean) == []


def test_batch_track_preserves_input_order(monkeypatch, tmp_env):
    monkeypatch.setattr(URLTracker, 'track',
                        lambda self, url: {'url': url, 'success': True,
                                           'info': {}, 'field_sources': {},
                                           'sources_ok': [], 'sources_failed': {},
                                           'field_count': 0, 'errors': []})
    tracker = URLTracker()
    urls = ['https://a.example/1', 'https://b.example/2', 'https://c.example/3']
    results = tracker.batch_track(urls, workers=3)
    assert [r['url'] for r in results] == urls      # input order, not completion
    assert all(r['success'] for r in results)

    # blank entries are dropped instead of producing bogus results
    results = tracker.batch_track(['', '   ', 'https://a.example/1'])
    assert [r['url'] for r in results] == ['https://a.example/1']


def test_track_many_separates_valid_from_invalid(monkeypatch, tmp_env):
    monkeypatch.setattr(URLTracker, 'track',
                        lambda self, url: {'url': url, 'success': True,
                                           'info': {}, 'field_sources': {},
                                           'sources_ok': [], 'sources_failed': {},
                                           'field_count': 0, 'errors': []})
    results, invalid = URLTracker().track_many(
        ['https://a.example/1', 'nope', '', 'https://b.example/2'])
    assert [r['url'] for r in results] == ['https://a.example/1',
                                           'https://b.example/2']
    assert invalid == ['nope']


def test_is_trackable():
    assert URLTracker.is_trackable('https://example.com/x') is True
    assert URLTracker.is_trackable('ftp://files.example/pub') is True
    assert URLTracker.is_trackable('example.com') is False
    assert URLTracker.is_trackable('') is False
