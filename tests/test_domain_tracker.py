"""Domain source and tracker tests."""

from obscuralens.config import config
from obscuralens.trackers import domain_sources as ds
from obscuralens.trackers.domain_tracker import DomainTracker


def test_certspotter_parses_records(fake_http):
    fake_http.json = lambda url, **kw: (True, [
        {'cert_sha256': 'a', 'dns_names': ['example.com', '*.www.example.com'],
         'not_before': '2024-01-01T00:00:00Z', 'revoked': False},
        {'cert_sha256': 'b', 'dns_names': ['mail.example.com'],
         'not_before': '2025-06-01T00:00:00Z', 'revoked': True},
    ], '')
    out = ds._certspotter('example.com')
    assert out['ct_certificates'] == 2
    assert out['ct_revoked'] == 1
    assert out['ct_subdomains'] == ['mail.example.com', 'www.example.com']
    assert out['ct_last_seen'] == '2025-06-01T00:00:00Z'


def test_http_probe_extracts_headers(fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=200, text='<html><title> My Site </title></html>',
        headers={'Server': 'nginx', 'Strict-Transport-Security': 'max-age=1',
                 'X-Content-Type-Options': 'nosniff'},
        url='https://example.com/')
    fake_http.fetch = lambda url, **kw: (200, 'User-agent: *', '')
    out = ds._http_probe('example.com')
    assert out['http_status'] == 200
    assert out['http_title'] == 'My Site'
    assert out['server'] == 'nginx'
    assert out['robots_txt'] is True
    assert 'strict-transport-security' in out['security_headers']
    assert 'content-security-policy' in out['missing_security_headers']


def test_gather_all_merges_and_tracks_provenance(monkeypatch):
    monkeypatch.setattr(ds, 'FREE_SOURCES', {
        'one': lambda domain: {'registrar': 'R1', 'dnssec': True},
        'two': lambda domain: {'registrar': 'R2', 'http_status': 200},
        'broken': lambda domain: (_ for _ in ()).throw(ValueError('x')),
    })
    out = ds.gather_all('example.com')
    assert out['fields']['registrar'] == 'R1'
    assert out['fields']['http_status'] == 200
    assert out['provenance']['registrar'] == ['one', 'two']
    assert out['sources']['broken']['ok'] is False


def test_gather_all_respects_disabled_sources(monkeypatch):
    monkeypatch.setattr(ds, 'FREE_SOURCES', {
        'one': lambda domain: {'a': 1},
        'two': lambda domain: {'b': 2},
    })
    monkeypatch.setattr(config.app_config, 'disabled_sources', ['two'])
    out = ds.gather_all('example.com')
    assert 'two' not in out['sources']
    assert 'b' not in out['fields']


def test_tracker_result_shape_and_history(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.domain_tracker.gather_all',
                        lambda domain: {
                            'fields': {'registrar': 'R', 'dnssec': False},
                            'sources': {'rdap': {'ok': True, 'error': ''},
                                        'dns': {'ok': False, 'error': 'no data'}},
                            'provenance': {'registrar': ['rdap'], 'dnssec': ['dns']},
                        })
    result = DomainTracker().track('Example.COM')
    assert result['domain'] == 'example.com'
    assert result['success'] is True
    assert result['sources_failed'] == {'dns': 'no data'}
    assert result['field_sources']['registrar'] == ['rdap']
    assert result['field_count'] == 2

    from obscuralens.database import db
    assert db.get_query_by_id(db.search_history('example.com')[0].id).query_type == 'domain'


def test_tracker_failure_result(monkeypatch, tmp_env):
    monkeypatch.setattr('obscuralens.trackers.domain_tracker.gather_all',
                        lambda domain: {
                            'fields': {},
                            'sources': {'rdap': {'ok': False, 'error': 'timeout'}},
                            'provenance': {},
                        })
    result = DomainTracker().track('nope.example')
    assert result['success'] is False
    assert result['errors'] == ['all data sources failed']
