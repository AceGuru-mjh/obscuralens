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


class TestCacheKey:
    """`_cache_key`: a stable, header-aware identifier - not a MAC.

    The digest moved from SHA-1 to SHA-256 (bandit B324 flags SHA-1 whatever
    its purpose). These pin the observable contract so the change stays
    behaviour-preserving: same shape, same 12-hex truncation, order-insensitive.
    """

    def test_url_without_headers_is_returned_verbatim(self):
        assert HttpClient._cache_key('https://x.test/a', None) == 'https://x.test/a'
        assert HttpClient._cache_key('https://x.test/a', {}) == 'https://x.test/a'

    def test_headers_append_a_12_hex_digest(self):
        key = HttpClient._cache_key('https://x.test/a', {'A': '1'})
        assert key.startswith('https://x.test/a#')
        digest = key.split('#', 1)[1]
        assert len(digest) == 12
        assert all(c in '0123456789abcdef' for c in digest)

    def test_digest_is_sha256_of_the_sorted_header_repr(self):
        import hashlib
        headers = {'A': '1', 'B': '2'}
        expected = hashlib.sha256(
            repr(sorted(headers.items())).encode('utf-8'),
            usedforsecurity=False).hexdigest()[:12]
        key = HttpClient._cache_key('https://x.test/a', headers)
        assert key == f'https://x.test/a#{expected}'
        # And it is specifically *not* the old SHA-1 digest.
        sha1 = hashlib.sha1(  # noqa: S324 - asserting the migration happened
            repr(sorted(headers.items())).encode('utf-8')).hexdigest()[:12]
        assert not key.endswith(sha1)

    def test_header_order_does_not_change_the_key(self):
        first = HttpClient._cache_key('u', {'A': '1', 'B': '2'})
        second = HttpClient._cache_key('u', {'B': '2', 'A': '1'})
        assert first == second

    def test_different_headers_produce_different_keys(self):
        a = HttpClient._cache_key('u', {'Authorization': 'Bearer one'})
        b = HttpClient._cache_key('u', {'Authorization': 'Bearer two'})
        assert a != b

    def test_key_is_deterministic_across_calls(self):
        headers = {'X-Key': 'v'}
        assert HttpClient._cache_key('u', headers) == \
            HttpClient._cache_key('u', headers)

    def test_the_same_url_with_and_without_headers_differs(self):
        # Two callers of one URL with different auth must not share a cache
        # entry - that is the whole reason the suffix exists.
        assert HttpClient._cache_key('u', None) != \
            HttpClient._cache_key('u', {'Authorization': 'Bearer t'})
