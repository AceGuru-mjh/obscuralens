# ---------------------------------------------------------------------------
# ObscuraLens v6.0 -- tests for the live stream / profile / compare / map
# endpoints and the database save hook that feeds the event bus.
#
# The SSE endpoint exposes a ``?max_events=`` test hook that ends the stream
# cleanly (and switches the heartbeat to 50 ms) so TestClient reads terminate;
# production requests never send it. No test touches the network.
# ---------------------------------------------------------------------------


import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from obscuralens.web import create_app  # noqa: E402


@pytest.fixture()
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture()
def bus():
    """Fresh event bus isolated from any previously registered instance."""
    from obscuralens.web import app as app_module
    return app_module.event_bus


# --------------------------------------------------------------------------- #
# the in-process event bus
# --------------------------------------------------------------------------- #

class TestEventBus:

    def test_subscribe_returns_queue(self, bus):
        queue = bus.subscribe()
        try:
            assert queue is not None
            assert bus.subscriber_count() >= 1
        finally:
            bus.unsubscribe(queue)

    def test_publish_reaches_subscriber(self, bus):
        import asyncio
        queue = bus.subscribe()
        try:
            bus.publish('lookup', {'kind': 'ip', 'value': '8.8.8.8'})
            topic, data = asyncio.run(
                asyncio.wait_for(queue.get(), timeout=1))
            assert topic == 'lookup'
            assert data['kind'] == 'ip'
        finally:
            bus.unsubscribe(queue)

    def test_multiple_subscribers_all_receive(self, bus):
        import asyncio
        queues = [bus.subscribe() for _ in range(3)]
        try:
            bus.publish('watch', {'changed': True})
            for queue in queues:
                topic, _ = asyncio.run(
                    asyncio.wait_for(queue.get(), timeout=1))
                assert topic == 'watch'
        finally:
            for queue in queues:
                bus.unsubscribe(queue)

    def test_unsubscribe_stops_delivery(self, bus):
        import asyncio
        queue = bus.subscribe()
        bus.unsubscribe(queue)
        bus.publish('lookup', {'x': 1})

        async def _drain():
            return await asyncio.wait_for(queue.get(), timeout=0.2)

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(_drain())

    def test_publish_bad_payload_never_raises(self, bus):
        # Any payload shape must survive the bus (defensive contract).
        bus.publish('weird', object())
        bus.publish('none', None)


# --------------------------------------------------------------------------- #
# the database save hook
# --------------------------------------------------------------------------- #

class TestSaveHook:

    def test_hook_fires_on_save(self, tmp_env):
        from obscuralens import database as db_module
        seen = []

        def hook(kind, value, success):
            seen.append((kind, value, success))

        db_module.set_save_hook(hook)
        try:
            db_module.db.save_query('ip', '8.8.8.8', {'info': {}}, True, '')
            assert seen == [('ip', '8.8.8.8', True)]
        finally:
            db_module.set_save_hook(None)

    def test_broken_hook_never_loses_the_lookup(self, tmp_env):
        from obscuralens import database as db_module

        def boom(kind, value, success):
            raise RuntimeError('observer crashed')

        db_module.set_save_hook(boom)
        try:
            row_id = db_module.db.save_query(
                'ip', '1.1.1.1', {'info': {'a': 1}}, True, '')
            assert row_id > 0
            history = db_module.db.get_history('ip', limit=5)
            assert any(row and '1.1.1.1' in str(row) for row in history)
        finally:
            db_module.set_save_hook(None)

    def test_clearing_hook_with_none(self, tmp_env):
        from obscuralens import database as db_module
        db_module.set_save_hook(None)
        # saving without any hook installed is the default core behaviour
        db_module.db.save_query('ip', '2.2.2.2', {'info': {}}, True, '')


# --------------------------------------------------------------------------- #
# GET /api/stream (server-sent events)
# --------------------------------------------------------------------------- #

class TestStreamEndpoint:

    def test_stream_opens_with_connected_frame(self, client):
        response = client.get('/api/stream?max_events=1', timeout=10)
        assert response.status_code == 200
        assert response.headers['content-type'].startswith('text/event-stream')
        text = response.text
        assert text.startswith('event: connected')
        assert 'data: ' in text

    def test_stream_heartbeat_frames(self, client):
        response = client.get('/api/stream?max_events=2', timeout=10)
        text = response.text
        # two frames: connected + one heartbeat (50 ms test heartbeat)
        assert 'event: heartbeat' in text

    def test_stream_carries_published_lookup(self, client, bus):
        import threading
        import time

        def publisher():
            time.sleep(0.05)
            bus.publish('lookup', {'kind': 'ip', 'value': '9.9.9.9'})

        worker = threading.Thread(target=publisher)
        worker.start()
        try:
            # A slow heartbeat (200 ms) keeps the stream alive long enough
            # for the publisher's 50 ms event to land inside the window.
            response = client.get(
                '/api/stream?max_events=4&heartbeat_ms=200', timeout=15)
        finally:
            worker.join()
        text = response.text
        assert 'event: lookup' in text
        assert '9.9.9.9' in text

    def test_stream_topic_filter(self, client, bus):
        import threading
        import time

        def publisher():
            time.sleep(0.05)
            bus.publish('watch', {'changed': True})
            bus.publish('lookup', {'kind': 'ip', 'value': '3.3.3.3'})

        worker = threading.Thread(target=publisher)
        worker.start()
        try:
            response = client.get(
                '/api/stream?max_events=4&heartbeat_ms=200&topics=lookup',
                timeout=15)
        finally:
            worker.join()
        text = response.text
        assert 'event: lookup' in text
        assert 'event: watch' not in text

    def test_subscribe_endpoint_sets_topics(self, client):
        response = client.post('/api/stream/subscribe',
                               json={'topics': ['lookup', 'watch']})
        assert response.status_code == 200
        body = response.json()
        assert body['topics'] == ['lookup', 'watch']
        assert body['count'] == 2
        # clean up: clear the module-level filter again
        clear = client.post('/api/stream/subscribe', json={'topics': '*'})
        assert clear.status_code in (200, 400)

    def test_subscribe_rejects_missing_topics(self, client):
        response = client.post('/api/stream/subscribe', json={})
        assert response.status_code == 400

    def test_subscribe_rejects_non_list(self, client):
        response = client.post('/api/stream/subscribe',
                               json={'topics': 42})
        assert response.status_code == 400


# --------------------------------------------------------------------------- #
# GET /api/profile/{kind}/{target}
# --------------------------------------------------------------------------- #

class TestProfileEndpoint:

    def _seed_history(self):
        from obscuralens.database import db
        for value in ('8.8.8.8', '8.8.8.8', '8.8.4.4'):
            db.save_query('ip', value, {
                'info': {'country': 'United States',
                         'city': 'Mountain View', 'ip': value},
            }, True, '')

    def test_profile_aggregates_history(self, client, tmp_env):
        self._seed_history()
        response = client.get('/api/profile/ip/8.8.8.8')
        assert response.status_code == 200
        body = response.json()
        assert body['found'] is True
        assert body['query_count'] >= 2
        assert 'first_seen' in body and 'last_seen' in body
        assert 'field_frequency' in body and 'recent' in body

    def test_profile_unknown_target_reports_not_found(self, client, tmp_env):
        response = client.get('/api/profile/ip/255.255.255.255')
        assert response.status_code == 200
        assert response.json()['found'] is False

    def test_profile_rejects_unknown_kind(self, client):
        response = client.get('/api/profile/nosuch/1.2.3.4')
        assert response.status_code == 400

    def test_profile_invalid_target_reports_not_found(self, client):
        # The profile endpoint does not re-validate the target syntax (it is
        # a history search, not a live lookup): an unparsable target simply
        # has no stored history.
        response = client.get('/api/profile/ip/not-an-ip')
        assert response.status_code == 200
        assert response.json()['found'] is False


# --------------------------------------------------------------------------- #
# GET /api/compare
# --------------------------------------------------------------------------- #

class TestCompareEndpoint:

    def test_compare_reports_field_diffs(self, client, monkeypatch):
        from obscuralens.trackers import ip_tracker as ip_mod

        def fake_a(value):
            return {'ip': value, 'info': {'country': 'United States',
                                          'city': 'Mountain View'},
                    'field_sources': {}, 'sources_ok': ['x'],
                    'sources_failed': {}, 'field_count': 2,
                    'success': True, 'errors': []}

        def fake_b(value):
            return {'ip': value, 'info': {'country': 'Germany',
                                          'org': 'Example GmbH'},
                    'field_sources': {}, 'sources_ok': ['x'],
                    'sources_failed': {}, 'field_count': 2,
                    'success': True, 'errors': []}

        monkeypatch.setattr(ip_mod.IPTracker, 'track',
                            lambda self, v: fake_a(v) if v == '8.8.8.8'
                            else fake_b(v))
        response = client.get(
            '/api/compare?kind_a=ip&target_a=8.8.8.8&kind_b=ip&target_b=1.1.1.1')
        assert response.status_code == 200
        body = response.json()
        assert 'a' in body and 'b' in body and 'counts' in body
        differing = {d['field'] for d in body['differing']}
        assert 'country' in differing
        added = {d['field'] for d in body['added']}
        removed = {d['field'] for d in body['removed']}
        assert 'org' in added
        assert 'city' in removed
        assert body['counts']['differing'] >= 1

    def test_compare_identical_targets_no_diff(self, client, monkeypatch):
        from obscuralens.trackers import ip_tracker as ip_mod

        def fake(value):
            return {'ip': value, 'info': {'country': 'United States'},
                    'field_sources': {}, 'sources_ok': ['x'],
                    'sources_failed': {}, 'field_count': 1,
                    'success': True, 'errors': []}

        monkeypatch.setattr(ip_mod.IPTracker, 'track',
                            lambda self, v: fake(v))
        response = client.get(
            '/api/compare?kind_a=ip&target_a=8.8.8.8&kind_b=ip&target_b=8.8.8.8')
        assert response.status_code == 200
        body = response.json()
        assert body['added'] == []
        assert body['removed'] == []
        assert body['differing'] == []

    def test_compare_missing_params_is_validation_error(self, client):
        # FastAPI answers 422 for missing required query parameters.
        assert client.get('/api/compare').status_code == 422
        assert client.get('/api/compare?kind_a=ip').status_code == 422

    def test_compare_unknown_kind_is_400(self, client):
        response = client.get(
            '/api/compare?kind_a=ip&target_a=8.8.8.8&kind_b=nosuch&target_b=x')
        assert response.status_code == 400


# --------------------------------------------------------------------------- #
# GET /api/map/points
# --------------------------------------------------------------------------- #

class TestMapPointsEndpoint:

    def test_map_points_from_history(self, client, tmp_env):
        from obscuralens.database import db
        db.save_query('coords', '48.8584, 2.2945', {
            'info': {'lat': 48.8584, 'lon': 2.2945, 'city': 'Paris'},
        }, True, '')
        db.save_query('ip', '8.8.8.8', {
            'info': {'latitude': 37.4056, 'longitude': -122.0775},
        }, True, '')
        response = client.get('/api/map/points?limit=100')
        assert response.status_code == 200
        points = response.json().get('points', response.json())
        if isinstance(points, dict):
            points = points.get('points', [])
        assert any(abs(p.get('lat', 0) - 48.8584) < 0.01 for p in points)
        assert any(p.get('kind') == 'ip' for p in points)

    def test_map_points_shape(self, client):
        # The endpoint always answers a well-formed envelope; with no
        # coordinate-bearing history the point list is simply empty.
        response = client.get('/api/map/points?limit=100')
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body.get('points'), list)
        assert 'count' in body and 'limit' in body

    def test_map_points_rejects_bad_limit(self, client):
        # FastAPI answers 422 for a non-integer limit.
        assert client.get('/api/map/points?limit=abc').status_code == 422


# --------------------------------------------------------------------------- #
# static JS engine modules (source-level checks; no runtime JS here)
# --------------------------------------------------------------------------- #

class TestStaticJsEngines:

    def _read(self, name):
        from pathlib import Path
        path = (Path(__file__).resolve().parent.parent
                / 'obscuralens' / 'web' / 'static' / 'js' / name)
        return path.read_text(encoding='utf-8')

    def test_maps_module_exports(self):
        source = self._read('maps.js')
        assert 'export const worldMap' in source
        assert 'equirectangular' in source
        assert 'mercator' in source
        assert 'addMarker' in source
        assert 'addCircle' in source
        assert 'addLine' in source
        assert 'fitBounds' in source

    def test_charts2_module_exports(self):
        source = self._read('charts2.js')
        for fn in ('boxplot', 'radar', 'heatmap', 'treemap', 'sparkline',
                   'gauge', 'stackedBar', 'scatter', 'violin'):
            assert fn in source, fn
        assert 'export const charts2' in source

    def test_sse_module_exports(self):
        source = self._read('sse.js')
        assert 'class SseClient' in source
        assert 'export const sse' in source
        assert 'EventSource' in source
