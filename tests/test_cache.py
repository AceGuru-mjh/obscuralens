"""HTTP cache tests."""

from obscuralens.config import config
from obscuralens.core.cache import HttpCache


def _enabled_cache(tmp_path, monkeypatch, ttl=60):
    monkeypatch.setattr(config.app_config, 'cache_enabled', True)
    return HttpCache(path=str(tmp_path / 'cache.db'), default_ttl=ttl)


def test_set_get_roundtrip(tmp_env, monkeypatch):
    cache = _enabled_cache(tmp_env, monkeypatch)
    assert cache.get('json', 'https://x.test/a') is None
    assert cache.set('json', 'https://x.test/a', {'a': 1}) is True
    assert cache.get('json', 'https://x.test/a') == {'a': 1}
    stats = cache.stats()
    assert stats['entries'] == 1
    assert stats['fresh'] == 1
    assert stats['hits'] == 1
    assert stats['misses'] == 1


def test_expired_entries_are_dropped(tmp_env, monkeypatch):
    cache = _enabled_cache(tmp_env, monkeypatch, ttl=60)
    cache.set('json', 'https://x.test/expired', {'a': 1}, ttl=-1)
    assert cache.get('json', 'https://x.test/expired') is None
    assert cache.stats()['entries'] == 0


def test_disabled_cache_is_a_noop(tmp_env, monkeypatch):
    monkeypatch.setattr(config.app_config, 'cache_enabled', False)
    cache = HttpCache(path=str(tmp_env / 'cache.db'))
    assert cache.set('json', 'https://x.test/a', {'a': 1}) is False
    assert cache.get('json', 'https://x.test/a') is None


def test_large_payload_is_not_cached(tmp_env, monkeypatch):
    cache = _enabled_cache(tmp_env, monkeypatch)
    big = {'blob': 'x' * 1_600_000}
    assert cache.set('json', 'https://x.test/big', big) is False


def test_clear_and_stats(tmp_env, monkeypatch):
    cache = _enabled_cache(tmp_env, monkeypatch)
    cache.set('json', 'https://x.test/a', {'a': 1})
    cache.set('text', 'https://x.test/b', 'hello')
    assert cache.stats()['entries'] == 2
    assert cache.clear() == 2
    assert cache.stats()['entries'] == 0
