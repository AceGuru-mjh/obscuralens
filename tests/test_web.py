"""
Optional web UI / REST API tests.

FastAPI (and httpx, required by its TestClient) are optional extras, so the
whole module is skipped cleanly when they are not installed. No test makes a
network call: every tracker's ``track`` method is monkeypatched at the class
level so all five kinds share the same stub.
"""

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from obscuralens.web import create_app  # noqa: E402

IP_RESULT = {
    'ip': '8.8.8.8',
    'info': {'country': 'United States', 'city': 'Mountain View'},
    'field_sources': {'country': ['ipwho.is']},
    'sources_ok': ['ipwho.is'],
    'sources_failed': {},
    'field_count': 2,
    'success': True,
    'errors': [],
}

INVESTIGATION_PAYLOAD = {
    'target': 'example.com',
    'kind': 'domain',
    'order': ['domain'],
    'results': {'domain': {'domain': 'example.com', 'info': {}}},
    'entities': [{'id': 'domain:example.com', 'type': 'domain',
                  'value': 'example.com', 'role': 'target',
                  'label': 'example.com'}],
    'links': [{'from': 'domain:example.com', 'to': 'ip:1.2.3.4',
               'label': 'a_record'}],
    'errors': [],
}


@pytest.fixture()
def client(monkeypatch):
    """TestClient with every tracker stubbed out (no network)."""
    import obscuralens.trackers as trackers

    def fake_track(self, target, **kwargs):
        return dict(IP_RESULT, ip=target)

    for name in ('IPTracker', 'PhoneTracker', 'UsernameTracker',
                 'EmailTracker', 'DomainTracker'):
        monkeypatch.setattr(getattr(trackers, name), 'track', fake_track)

    return TestClient(create_app())


def test_health(client):
    resp = client.get('/api/health')
    assert resp.status_code == 200
    assert resp.json()['status'] == 'ok'
    assert resp.json()['version']


def test_dashboard_html(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert 'text/html' in resp.headers['content-type']
    assert 'ObscuraLens' in resp.text
    assert '/api/lookup/' in resp.text


def test_lookup_ip_returns_stub(client):
    resp = client.get('/api/lookup/ip/8.8.8.8')
    assert resp.status_code == 200
    payload = resp.json()
    assert payload['ip'] == '8.8.8.8'
    assert payload['info']['country'] == 'United States'
    assert payload['success'] is True


def test_lookup_unknown_kind_is_400(client):
    resp = client.get('/api/lookup/nope/8.8.8.8')
    assert resp.status_code == 400
    assert resp.json()['detail'] == 'unknown kind'


def test_lookup_invalid_target_is_400(client):
    resp = client.get('/api/lookup/ip/not-an-ip')
    assert resp.status_code == 400


def test_lookup_tracker_error_is_200(client, monkeypatch):
    import obscuralens.trackers as trackers

    def boom(self, target, **kwargs):
        raise RuntimeError('upstream exploded')

    monkeypatch.setattr(trackers.IPTracker, 'track', boom)
    resp = client.get('/api/lookup/ip/8.8.8.8')
    assert resp.status_code == 200
    payload = resp.json()
    assert payload['success'] is False
    assert 'upstream exploded' in payload['error']


def test_investigate_returns_payload(client, monkeypatch):
    import obscuralens.investigate as investigate_module

    monkeypatch.setattr(investigate_module, 'investigate',
                        lambda target, **kwargs: INVESTIGATION_PAYLOAD)
    resp = client.get('/api/investigate', params={'target': 'example.com'})
    assert resp.status_code == 200
    payload = resp.json()
    assert payload['kind'] == 'domain'
    assert payload['links'][0]['label'] == 'a_record'


def test_investigate_unknown_target_is_400(client):
    resp = client.get('/api/investigate', params={'target': 'not a target!'})
    assert resp.status_code == 400


def test_sources_lists_known_names(client):
    resp = client.get('/api/sources')
    assert resp.status_code == 200
    payload = resp.json()
    assert 'certspotter' in payload['domain']
    assert 'ipwho.is' in payload['ip']


def test_stats_has_all_sections(client):
    resp = client.get('/api/stats')
    assert resp.status_code == 200
    payload = resp.json()
    assert set(payload) == {'database', 'cache', 'network', 'source_health'}
    assert 'total_queries' in payload['database']
    assert 'entries' in payload['cache']


def test_watch_roundtrip(client, tmp_env):
    from obscuralens.watchlist import watchlist

    for entry in watchlist.list():
        watchlist.remove(entry.id)

    resp = client.post('/api/watch', json={'target': '8.8.8.8', 'label': 'dns'})
    assert resp.status_code == 201
    watch_id = resp.json()['id']

    resp = client.get('/api/watch')
    assert resp.status_code == 200
    entries = resp.json()
    assert entries[0]['id'] == watch_id
    assert entries[0]['target'] == '8.8.8.8'
    assert entries[0]['label'] == 'dns'

    resp = client.delete(f'/api/watch/{watch_id}')
    assert resp.status_code == 200
    assert resp.json()['removed'] == 1

    resp = client.delete('/api/watch/8.8.8.8')
    assert resp.status_code == 404


def test_watch_add_invalid_target_is_400(client, tmp_env):
    resp = client.post('/api/watch', json={'target': 'not a target!'})
    assert resp.status_code == 400


def test_serve_open_browser_waits_for_readiness(monkeypatch):
    """`serve(open_browser=True)` opens the URL only after /api/health answers."""
    import sys
    import threading

    import obscuralens.web.app as web_app

    opened = []
    attempts = []

    class FakeCM:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(*args, **kwargs):
        attempts.append(True)
        # First probe fails (server still booting), second succeeds.
        if len(attempts) < 2:
            raise OSError('connection refused')
        return FakeCM()

    class FakeThread:
        def __init__(self, target=None, daemon=None):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    monkeypatch.setattr('webbrowser.open', lambda url: opened.append(url))
    monkeypatch.setattr(threading, 'Thread', FakeThread)

    fake_uvicorn = type(sys)('uvicorn')
    fake_uvicorn.run = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, 'uvicorn', fake_uvicorn)

    web_app.serve(host='127.0.0.1', port=8123, open_browser=True)
    assert len(attempts) >= 2
    assert opened == ['http://127.0.0.1:8123']


def test_serve_without_open_browser_opens_nothing(monkeypatch, capsys):
    import obscuralens.web.app as web_app

    opened = []
    monkeypatch.setattr('webbrowser.open', lambda url: opened.append(url))

    import sys
    fake_uvicorn = type(sys)('uvicorn')
    fake_uvicorn.run = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, 'uvicorn', fake_uvicorn)

    web_app.serve(host='127.0.0.1', port=8124, open_browser=False)
    assert opened == []
    assert 'http://127.0.0.1:8124' in capsys.readouterr().out


def test_serve_cli_accepts_open_flag():
    from obscuralens.commands import build_parser

    args = build_parser().parse_args(['serve', '--open'])
    assert args.open is True
    args = build_parser().parse_args(['serve'])
    assert args.open is False
