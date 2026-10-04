"""HTTP client tests: caching, error mapping, metrics."""

import pytest
import requests.exceptions

from obscuralens.config import config
from obscuralens.core.metrics import metrics
from obscuralens.utils.http_client import HttpClient


@pytest.fixture()
def client(tmp_env, monkeypatch):
    monkeypatch.setattr(config.app_config, 'requests_per_second', 0.0)
    return HttpClient(timeout=5)


def test_get_json_parses_and_caches(client, tmp_env, monkeypatch,
                                    fake_response):
    monkeypatch.setattr(config.app_config, 'cache_enabled', True)
    monkeypatch.setattr(config.app_config, 'cache_path',
                        str(tmp_env / 'client_cache.db'))
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return fake_response(json_data={'answer': 42})

    monkeypatch.setattr(client, 'get', fake_get)

    ok, data, err = client.get_json('https://cache.test/a')
    assert ok is True and data == {'answer': 42} and err == ''

    # Second call is served from the cache: no extra HTTP request.
    ok, data, err = client.get_json('https://cache.test/a')
    assert ok is True and data == {'answer': 42}
    assert len(calls) == 1


def test_get_json_maps_errors(client, monkeypatch):
    def timeout(url, **kwargs):
        raise requests.exceptions.Timeout()

    monkeypatch.setattr(client, 'get', timeout)
    assert client.get_json('https://x.test', use_cache=False) == (
        False, None, 'timeout')

    def dns_error(url, **kwargs):
        raise requests.exceptions.ConnectionError()

    monkeypatch.setattr(client, 'get', dns_error)
    assert client.get_json('https://x.test', use_cache=False) == (
        False, None, 'connection failed')


def test_get_json_404_is_not_found(client, monkeypatch, fake_response):
    monkeypatch.setattr(client, 'get',
                        lambda url, **kw: fake_response(status_code=404))
    assert client.get_json('https://x.test', use_cache=False) == (
        False, None, 'not found')


def test_get_text_and_fetch(client, monkeypatch, fake_response):
    monkeypatch.setattr(client, 'get',
                        lambda url, **kw: fake_response(text='body'))
    ok, text, err = client.get_text('https://x.test', use_cache=False)
    assert ok is True and text == 'body'

    status, text, err = client.fetch('https://x.test', use_cache=False)
    assert status == 200 and text == 'body'


def test_fetch_caches_success(client, tmp_env, monkeypatch, fake_response):
    monkeypatch.setattr(config.app_config, 'cache_enabled', True)
    monkeypatch.setattr(config.app_config, 'cache_path',
                        str(tmp_env / 'fetch_cache.db'))
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return fake_response(text='cached-body')

    monkeypatch.setattr(client, 'get', fake_get)
    client.fetch('https://fetch.test/a')
    status, text, _ = client.fetch('https://fetch.test/a')
    assert status == 200 and text == 'cached-body'
    assert len(calls) == 1


def test_metrics_count_requests(client, monkeypatch, fake_response):
    metrics.reset()
    monkeypatch.setattr(client.session, 'get',
                        lambda url, **kw: fake_response(json_data={'a': 1}))
    client.get_json('https://metrics.test/a', use_cache=False)
    assert metrics.snapshot()['requests'] == 1


def test_cache_key_includes_header_digest_and_is_stable():
    """_cache_key must mix headers into the key deterministically.

    The header digest uses SHA-256 (not the old SHA-1) and is stable for
    identical inputs while differing when the header set changes.
    """
    url = 'https://api.test/endpoint'
    no_headers = HttpClient._cache_key(url, None)
    with_headers = HttpClient._cache_key(url, {'X-Key': 'abc'})
    with_headers_again = HttpClient._cache_key(url, {'X-Key': 'abc'})

    assert no_headers == url  # headerless lookups key on the URL alone
    assert with_headers != url  # headers participate in the key
    assert with_headers == with_headers_again  # deterministic
    # SHA-256 digest is exactly 12 hex chars appended after '#'.
    suffix = with_headers.split('#', 1)[1]
    assert len(suffix) == 12
    assert all(c in '0123456789abcdef' for c in suffix)


def test_cache_key_distinguishes_header_orders():
    """Equivalent header dicts (different insertion order) share one key."""
    a = HttpClient._cache_key('https://api.test/x',
                              {'A': '1', 'B': '2'})
    b = HttpClient._cache_key('https://api.test/x',
                              {'B': '2', 'A': '1'})
    assert a == b
