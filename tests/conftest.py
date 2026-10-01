"""
Shared test fixtures.

The environment is redirected to a temporary directory *before* the package is
imported so tests never touch the user's config, database, cache or reports,
and never make real network calls (unit tests mock the shared HTTP client).
"""

import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix='obscuralens-tests-'))

os.environ['OBSCURALENS_CONFIG_DIR'] = str(_TMP)
os.environ['OBSCURALENS_SQLITE_PATH'] = str(_TMP / 'test.db')
os.environ['OBSCURALENS_CACHE_PATH'] = str(_TMP / 'http_cache.db')
os.environ['OBSCURALENS_REPORT_DIR'] = str(_TMP / 'reports')
os.environ['OBSCURALENS_CHART_DIR'] = str(_TMP / 'reports' / 'charts')
os.environ['OBSCURALENS_CACHE_ENABLED'] = '0'
os.environ['OBSCURALENS_REQUESTS_PER_SECOND'] = '0'
os.environ['OBSCURALENS_SAVE_HISTORY'] = '1'
os.environ['NO_COLOR'] = '1'

# Make the project root importable when running pytest from elsewhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402


@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    """Point every on-disk artefact at a per-test temporary directory."""
    from obscuralens.config import config
    monkeypatch.setattr(config.app_config, 'cache_path',
                        str(tmp_path / 'http_cache.db'))
    monkeypatch.setattr(config.app_config, 'cache_enabled', False)
    monkeypatch.setattr(config.app_config, 'report_dir', str(tmp_path / 'reports'))
    monkeypatch.setattr(config.app_config, 'chart_dir',
                        str(tmp_path / 'reports' / 'charts'))
    monkeypatch.setattr(config.app_config, 'disabled_sources', [])
    monkeypatch.setattr(config.app_config, 'requests_per_second', 0.0)
    return tmp_path


class FakeResponse:
    """Minimal requests.Response stand-in."""

    def __init__(self, status_code=200, text='', json_data=None,
                 url='https://example.test/', headers=None):
        self.status_code = status_code
        self.text = text
        self._json = json_data
        self.url = url
        from requests.structures import CaseInsensitiveDict
        self.headers = CaseInsensitiveDict(headers or {})
        self.content = text.encode('utf-8')

    def json(self):
        if self._json is None:
            raise ValueError('no json')
        return self._json

    def raise_for_status(self):
        import requests.exceptions as exc
        if self.status_code >= 400:
            error = exc.HTTPError(f'http {self.status_code}')
            error.response = self
            raise error


@pytest.fixture()
def fake_response():
    """Factory for minimal requests.Response stand-ins."""
    return FakeResponse


@pytest.fixture()
def fake_http(monkeypatch):
    """
    Install programmable fakes on the shared HTTP client.

    Usage:
        fake_http.json = lambda url: (True, {'ok': 1}, '')
        fake_http.get = lambda url, **kw: FakeResponse(text='hi')
    """
    from obscuralens.utils import http_client as client_module

    class FakeHttp:
        def __init__(self):
            self.json = lambda url, **kwargs: (False, None, 'not configured')
            self.get = lambda url, **kwargs: FakeResponse()
            self.fetch = lambda url, **kwargs: (404, '', '')
            self.calls = []

        def install(self):
            instance = client_module.http

            def _get_json(url, **kwargs):
                self.calls.append(('json', url))
                return self.json(url, **kwargs)

            def _get(url, **kwargs):
                self.calls.append(('get', url))
                return self.get(url, **kwargs)

            def _fetch(url, **kwargs):
                self.calls.append(('fetch', url))
                return self.fetch(url, **kwargs)

            monkeypatch.setattr(instance, 'get_json', _get_json)
            monkeypatch.setattr(instance, 'get', _get)
            monkeypatch.setattr(instance, 'fetch', _fetch)

    fake = FakeHttp()
    fake.install()
    return fake
