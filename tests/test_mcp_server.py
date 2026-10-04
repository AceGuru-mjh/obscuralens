"""MCP stdio server tests (all trackers mocked; fully offline)."""

import io
import json

import pytest

from obscuralens import mcp_server
from obscuralens.mcp_server import call_tool, handle_request, main

TOOL_NAMES = {
    'ip_lookup', 'phone_lookup', 'username_lookup', 'email_lookup',
    'domain_lookup', 'investigate', 'watch_list', 'watch_check',
    # v4.0 tools
    'url_lookup', 'crypto_lookup', 'hash_lookup', 'cve_lookup', 'asn_lookup',
    'risk_report', 'correlate', 'timeline', 'threat_intel', 'source_health',
    # v5.0 tools
    'mac_lookup', 'iban_lookup', 'imei_lookup', 'coords_lookup',
    'tools_encode', 'tools_decode', 'tools_jwt', 'tools_hash_id',
    'tools_extract', 'tools_squat', 'tools_exif', 'tools_stego',
    'tools_coords_convert', 'tools_geo_profile', 'tools_patterns',
    'tools_batch',
    # v6.0 tools
    'vin_lookup', 'flight_lookup', 'mmsi_lookup',
    'app_lookup', 'bssid_lookup', 'plate_lookup',
    # v6.0 part 2: analytics tools
    'analytics_stats', 'analytics_anomalies', 'analytics_keywords',
    'analytics_language', 'analytics_similarity', 'analytics_graph',
    'analytics_history',
    # v6.1 tools
    'tools_dorks',
    # v6.0 part 4: automation & sharing tools
    'notify_channels', 'notify_broadcast', 'automation_tasks',
    'automation_run_due', 'export_stix',
    # v6.0 part 5: ecosystem tools
    'export_misp', 'analytics_clusters', 'analytics_trend',
    'analytics_forecast', 'history_search', 'watch_add', 'watch_remove',
    'case_list', 'case_create', 'data_pack_lookup',

}

#: Tools dispatched through the built-in ``call_tool`` branches instead
#: of the ``_HANDLERS`` registry (the first 18 tools of the file).
BUILTIN_TOOLS = frozenset({
    'ip_lookup', 'phone_lookup', 'username_lookup', 'email_lookup',
    'domain_lookup', 'investigate', 'watch_list', 'watch_check',
    'url_lookup', 'crypto_lookup', 'hash_lookup', 'cve_lookup',
    'asn_lookup', 'risk_report', 'correlate', 'timeline',
    'threat_intel', 'source_health',
})


def _request(method, params=None, msg_id=1):
    message = {'jsonrpc': '2.0', 'id': msg_id, 'method': method}
    if params is not None:
        message['params'] = params
    return message


def _text(response):
    return response['result']['content'][0]['text']


def test_initialize_mirrors_protocol_version():
    response = handle_request(_request(
        'initialize', {'protocolVersion': '2025-03-26'}))
    result = response['result']
    assert result['protocolVersion'] == '2025-03-26'
    assert result['capabilities'] == {'tools': {}}
    assert result['serverInfo'] == {
        'name': 'obscuralens', 'version': mcp_server.__version__}


def test_initialize_defaults_protocol_version():
    response = handle_request(_request('initialize', {}))
    assert response['result']['protocolVersion'] == '2024-11-05'


def test_tools_list_contains_all_tools_with_valid_schemas():
    response = handle_request(_request('tools/list'))
    tools = response['result']['tools']
    assert {tool['name'] for tool in tools} == TOOL_NAMES
    no_target_required = ('watch_list', 'watch_check', 'correlate', 'timeline',
                          'threat_intel', 'source_health', 'risk_report',
                          # v5.0 tools take mac/iban/... instead of target
                          'mac_lookup', 'iban_lookup', 'imei_lookup',
                          'coords_lookup', 'tools_encode', 'tools_decode',
                          'tools_jwt', 'tools_hash_id', 'tools_extract',
                          'tools_squat', 'tools_exif', 'tools_stego',
                          'tools_coords_convert', 'tools_geo_profile',
                          'tools_patterns', 'tools_batch',
                          # v6.0 tools take vin/flight/mmsi/app/bssid/plate
                          # instead of target
                          'vin_lookup', 'flight_lookup', 'mmsi_lookup',
                          'app_lookup', 'bssid_lookup', 'plate_lookup',
                          # v6.0 part 2 analytics tools take values/text/
                          # entities instead of target
                          'analytics_stats', 'analytics_anomalies',
                          'analytics_keywords', 'analytics_language',
                          'analytics_similarity', 'analytics_graph',
                          'analytics_history',
                          # v6.0 part 4 automation & sharing tools take
                          # no target (or kind/target instead)
                          'notify_channels', 'notify_broadcast',
                          'automation_tasks', 'automation_run_due',
                          'export_stix',
                          # v6.0 part 5 ecosystem tools take kind/target,
                          # points, values, query, identifier, name or
                          # pack/key instead of target
                          'export_misp', 'analytics_clusters',
                          'analytics_trend', 'analytics_forecast',
                          'history_search', 'watch_remove', 'case_list',
                          'case_create', 'data_pack_lookup')
    for tool in tools:
        assert isinstance(tool['description'], str) and tool['description']
        schema = tool['inputSchema']
        assert schema['type'] == 'object'
        assert isinstance(schema['properties'], dict)
        for prop in schema['properties'].values():
            assert 'type' in prop
        if tool['name'] not in no_target_required:
            assert 'target' in schema['required']


def test_ping_returns_empty_result():
    response = handle_request(_request('ping'))
    assert response['result'] == {}


def test_notifications_return_none():
    assert handle_request(_request('notifications/initialized')) is None
    assert handle_request(_request('notifications/cancelled')) is None


def test_unknown_method_returns_method_not_found():
    response = handle_request(_request('does/not/exist', msg_id=7))
    assert response['id'] == 7
    assert response['error']['code'] == -32601
    assert response['error']['message'] == 'method not found'


def test_tools_call_invalid_params_returns_invalid_params():
    assert handle_request(_request('tools/call', {}))['error']['code'] == -32602
    response = handle_request(_request(
        'tools/call', {'name': 'ip_lookup', 'arguments': 'nope'}))
    assert response['error']['code'] == -32602


def test_tools_call_unknown_tool_is_error():
    response = handle_request(_request(
        'tools/call', {'name': 'nope', 'arguments': {}}))
    assert response['result']['isError'] is True
    assert 'unknown tool' in _text(response)


LOOKUP_CASES = [
    ('ip_lookup', 'IPTracker', {'target': '8.8.8.8'}, 'ip-ok'),
    ('phone_lookup', 'PhoneTracker', {'target': '+628123', 'region': 'ID'},
     'phone-ok'),
    ('username_lookup', 'UsernameTracker', {'target': 'alice', 'fast': True},
     'username-ok'),
    ('email_lookup', 'EmailTracker', {'target': 'a@example.com'}, 'email-ok'),
    ('domain_lookup', 'DomainTracker', {'target': 'example.com'}, 'domain-ok'),
]


@pytest.mark.parametrize('tool,class_name,arguments,stub', LOOKUP_CASES)
def test_call_tool_lookups(monkeypatch, tool, class_name, arguments, stub):
    import obscuralens.trackers as trackers

    def fake_track(self, *args, **kwargs):
        return {'stub': stub}

    monkeypatch.setattr(getattr(trackers, class_name), 'track', fake_track)
    response = handle_request(_request(
        'tools/call', {'name': tool, 'arguments': arguments}))
    assert response['result']['isError'] is False
    assert stub in _text(response)
    assert call_tool(tool, arguments) == {'stub': stub}


def test_call_tool_investigate(monkeypatch):
    import obscuralens.investigate as investigate_module

    monkeypatch.setattr(
        investigate_module, 'investigate',
        lambda target, **kwargs: {'target': target, 'kind': 'stub-kind'})
    response = handle_request(_request(
        'tools/call',
        {'name': 'investigate', 'arguments': {'target': 'example.com'}}))
    assert response['result']['isError'] is False
    assert 'stub-kind' in _text(response)


def test_call_tool_watch_list_and_check(monkeypatch):
    from obscuralens.watchlist import WatchDiff, WatchEntry, watchlist

    entry = WatchEntry(id=1, target='8.8.8.8', kind='ip', label='dns')
    monkeypatch.setattr(watchlist, 'list', lambda: [entry])
    assert call_tool('watch_list', {})['entries'][0]['target'] == '8.8.8.8'

    diff = WatchDiff(watch_id=1, target='8.8.8.8', kind='ip',
                     checked_at='2026-10-01T00:00:00', is_first=True,
                     added={'country': 'US'}, removed={}, changed={})
    monkeypatch.setattr(watchlist, 'check',
                        lambda identifier=None: [diff])
    result = call_tool('watch_check', {'identifier': '1'})
    assert result['diffs'][0]['added'] == {'country': 'US'}


def test_main_end_to_end(monkeypatch):
    lines = [
        json.dumps(_request(
            'initialize', {'protocolVersion': '2024-11-05'}, msg_id=1)),
        json.dumps(_request('tools/list', msg_id=2)),
    ]
    stdin = io.StringIO('\n'.join(lines) + '\n')
    stdout = io.StringIO()
    monkeypatch.setattr('sys.stdin', stdin)
    monkeypatch.setattr('sys.stdout', stdout)

    assert main() == 0

    out_lines = [line for line in stdout.getvalue().splitlines() if line]
    assert len(out_lines) == 2
    first, second = json.loads(out_lines[0]), json.loads(out_lines[1])
    assert first['result']['serverInfo']['name'] == 'obscuralens'
    assert len(second['result']['tools']) == 63  # 18 builtin-dispatched + 45 registry tools


# --------------------------------------------------------------------------- #
# v6.0 part 5: ecosystem tools (export_misp, analytics_clusters/trend/forecast,
# history_search, watch_add/watch_remove, case_list/case_create,
# data_pack_lookup)
# --------------------------------------------------------------------------- #

def _history_record(query_type='ip', query_value='8.8.8.8',
                    result_data=None, created_at='2026-10-01T00:00:00',
                    success=True, record_id=1):
    """One fake ``QueryRecord`` for monkeypatched ``db`` seams."""
    from obscuralens.database import QueryRecord
    if result_data is None:
        result_data = json.dumps({
            'ip': query_value, 'info': {'country': 'US', 'org': 'Google'},
            'sources_ok': ['ripe'], 'sources_failed': {}, 'errors': [],
            'success': True, 'field_count': 2,
        })
    return QueryRecord(id=record_id, query_type=query_type,
                       query_value=query_value, result_data=result_data,
                       created_at=created_at, success=success,
                       error_message='')


class TestExportMisp:

    def test_builds_event_from_stored_lookup(self, monkeypatch):
        from obscuralens.database import db
        monkeypatch.setattr(
            db, 'get_history',
            lambda query_type=None, limit=100: [_history_record()])
        result = call_tool('export_misp', {'kind': 'ip', 'target': '8.8.8.8'})
        event = result['Event']
        assert event['orgc']['name'] == 'ObscuraLens'
        assert event['threat_level_id'] == '3'
        categories = {attr['category'] for attr in event['Attribute']}
        assert 'Network activity' in categories
        assert any(attr['value'] == '8.8.8.8' for attr in event['Attribute'])
        assert {'obscuralens:ip'} == {tag['name'] for tag in event['Tag']}

    def test_match_is_case_insensitive(self, monkeypatch):
        from obscuralens.database import db
        monkeypatch.setattr(
            db, 'get_history',
            lambda query_type=None, limit=100: [
                _history_record(query_type='domain',
                                query_value='example.com')])
        result = call_tool('export_misp',
                           {'kind': 'domain', 'target': 'EXAMPLE.COM'})
        assert result['Event']['orgc']['name'] == 'ObscuraLens'

    def test_skips_corrupt_result_data_rows(self, monkeypatch):
        from obscuralens.database import db
        monkeypatch.setattr(
            db, 'get_history',
            lambda query_type=None, limit=100: [
                _history_record(record_id=1, result_data='not-json{{{'),
                _history_record(record_id=2, result_data='"just a string"'),
                _history_record(record_id=3),
            ])
        result = call_tool('export_misp', {'kind': 'ip', 'target': '8.8.8.8'})
        assert result['Event']['Attribute']

    def test_no_stored_lookup_raises(self, monkeypatch):
        from obscuralens.database import db
        monkeypatch.setattr(db, 'get_history',
                            lambda query_type=None, limit=100: [])
        with pytest.raises(ValueError) as excinfo:
            call_tool('export_misp', {'kind': 'ip', 'target': '1.2.3.4'})
        assert 'no stored ip lookup' in str(excinfo.value)
        assert 'run the lookup first' in str(excinfo.value)

    def test_unknown_kind_finds_no_history(self, monkeypatch):
        from obscuralens.database import db
        seen = {}

        def fake_get_history(query_type=None, limit=100):
            seen['query_type'] = query_type
            return []

        monkeypatch.setattr(db, 'get_history', fake_get_history)
        with pytest.raises(ValueError):
            call_tool('export_misp', {'kind': 'mystery', 'target': 'x'})
        assert seen['query_type'] == 'mystery'

    def test_missing_kind_or_target_raises(self):
        with pytest.raises(ValueError, match='kind is required'):
            call_tool('export_misp', {'target': '8.8.8.8'})
        with pytest.raises(ValueError, match='target is required'):
            call_tool('export_misp', {'kind': 'ip'})

    def test_error_round_trip_via_json_rpc(self, monkeypatch):
        from obscuralens.database import db
        monkeypatch.setattr(db, 'get_history',
                            lambda query_type=None, limit=100: [])
        response = handle_request(_request(
            'tools/call',
            {'name': 'export_misp',
             'arguments': {'kind': 'ip', 'target': '1.2.3.4'}}))
        assert response['result']['isError'] is True
        assert 'no stored ip lookup' in _text(response)


class TestAnalyticsClusters:

    POINTS = [[52.0, 13.0], [52.01, 13.01], [52.02, 13.02],
              [40.0, -3.0], [40.01, -3.01], [40.02, -3.02],
              [0.0, 0.0]]

    def test_two_clusters_plus_noise(self):
        result = call_tool('analytics_clusters', {'points': self.POINTS})
        assert result['point_count'] == 7
        assert result['eps_km'] == 25.0
        assert result['min_points'] == 3
        assert result['cluster_count'] == 2
        assert sorted(c['size'] for c in result['clusters']) == [3, 3]
        first = result['clusters'][0]
        assert set(first) >= {'centroid', 'members', 'size', 'radius_km',
                              'labels'}

    def test_min_points_raises_bar_above_group_size(self):
        result = call_tool('analytics_clusters',
                           {'points': self.POINTS, 'min_points': 4})
        assert result['min_points'] == 4
        assert result['cluster_count'] == 0
        assert result['clusters'] == []

    def test_unusable_rows_are_dropped(self):
        raw = [[52.0, 13.0], ['a', 'b'], [1], None,
               [52.01, 13.01], [52.02, 13.02], True, 'x']
        result = call_tool('analytics_clusters', {'points': raw})
        assert result['point_count'] == 3
        assert result['cluster_count'] == 1

    def test_non_list_points_raises(self):
        with pytest.raises(ValueError, match='non-empty list'):
            call_tool('analytics_clusters', {'points': '52.0,13.0'})

    def test_empty_points_raises(self):
        with pytest.raises(ValueError, match='non-empty list'):
            call_tool('analytics_clusters', {'points': []})

    def test_no_usable_rows_raises(self):
        with pytest.raises(ValueError, match='no usable'):
            call_tool('analytics_clusters', {'points': [['a', 'b'], [1]]})

    def test_non_positive_eps_falls_back_to_default(self):
        result = call_tool('analytics_clusters',
                           {'points': self.POINTS, 'eps_km': -5})
        assert result['eps_km'] == 25.0


class TestAnalyticsTrend:

    def test_rising_series_with_changepoint(self):
        result = call_tool('analytics_trend', {'values': [1, 2, 3, 4, 20]})
        assert result['count'] == 5
        summary = result['summary']
        assert summary['count'] == 5
        assert summary['direction'] == 'rising'
        assert summary['changepoint_count'] >= 1
        assert summary['span_days'] == 4.0

    def test_flat_series(self):
        summary = call_tool('analytics_trend',
                            {'values': [5, 5, 5, 5]})['summary']
        assert summary['direction'] == 'flat'
        assert summary['changepoint_count'] == 0

    def test_two_value_series_is_well_formed(self):
        result = call_tool('analytics_trend', {'values': [1, 3]})
        assert result['count'] == 2
        assert result['summary']['direction'] == 'rising'

    def test_missing_or_empty_values_raise(self):
        with pytest.raises(ValueError, match='values is required'):
            call_tool('analytics_trend', {})
        with pytest.raises(ValueError, match='values is required'):
            call_tool('analytics_trend', {'values': []})

    def test_non_numeric_values_raise(self):
        with pytest.raises(ValueError, match='at least one number'):
            call_tool('analytics_trend', {'values': ['a', None]})


class TestAnalyticsForecast:

    def test_linear_series_forecasts(self):
        result = call_tool('analytics_forecast', {'values': [1, 2, 3, 4]})
        assert result == {'forecasts': [5.0, 6.0, 7.0], 'slope': 1.0,
                          'intercept': 1.0, 'trend': 'rising',
                          'confidence': 'low', 'n': 4}

    def test_falling_series(self):
        result = call_tool('analytics_forecast', {'values': [4, 3, 2, 1]})
        assert result['trend'] == 'falling'
        assert result['forecasts'] == [0.0, -1.0, -2.0]

    def test_horizon_clamped_high_and_low(self):
        high = call_tool('analytics_forecast',
                         {'values': [1, 2, 3], 'horizon': 99})
        assert len(high['forecasts']) == 24
        low = call_tool('analytics_forecast',
                        {'values': [1, 2, 3], 'horizon': 0})
        assert len(low['forecasts']) == 1

    def test_non_integer_horizon_uses_default(self):
        result = call_tool('analytics_forecast',
                           {'values': [1, 2, 3], 'horizon': 'many'})
        assert len(result['forecasts']) == 3

    def test_single_value_yields_unknown_trend(self):
        result = call_tool('analytics_forecast', {'values': [42]})
        assert result['forecasts'] == []
        assert result['trend'] == 'unknown'
        assert result['confidence'] == 'low'
        assert result['n'] == 1

    def test_missing_values_raises(self):
        with pytest.raises(ValueError, match='values is required'):
            call_tool('analytics_forecast', {})


class TestHistorySearch:

    def test_search_delegates_to_search_history(self, monkeypatch):
        from obscuralens.database import db
        seen = {}

        def fake_search(search_term, limit=100):
            seen['term'], seen['limit'] = search_term, limit
            return [_history_record(record_id=1, query_value='8.8.8.8'),
                    _history_record(record_id=2, query_type='domain',
                                    query_value='8-8.example',
                                    created_at=None, success=False)]

        monkeypatch.setattr(db, 'search_history', fake_search)
        result = call_tool('history_search', {'query': '8.8'})
        assert seen == {'term': '8.8', 'limit': 25}
        assert result['count'] == 2
        first = result['results'][0]
        assert first == {'id': 1, 'kind': 'ip', 'target': '8.8.8.8',
                         'created_at': '2026-10-01T00:00:00',
                         'success': True}
        assert 'result_data' not in first
        assert result['results'][1]['created_at'] == ''
        assert result['results'][1]['success'] is False

    def test_kind_filter_uses_get_history(self, monkeypatch):
        from obscuralens.database import db
        seen = {}

        def fake_get_history(query_type=None, limit=100):
            seen['query_type'], seen['limit'] = query_type, limit
            return [_history_record(record_id=1, query_value='8.8.8.8'),
                    _history_record(record_id=2, query_value='1.1.1.1')]

        def fail_search(search_term, limit=100):  # pragma: no cover
            raise AssertionError('search_history must not be used with kind')

        monkeypatch.setattr(db, 'get_history', fake_get_history)
        monkeypatch.setattr(db, 'search_history', fail_search)
        result = call_tool('history_search',
                           {'query': '8.8', 'kind': 'ip', 'limit': 50})
        assert seen == {'query_type': 'ip', 'limit': 50}
        assert result['count'] == 1
        assert result['results'][0]['target'] == '8.8.8.8'

    def test_kind_filter_match_is_case_insensitive(self, monkeypatch):
        from obscuralens.database import db
        monkeypatch.setattr(
            db, 'get_history',
            lambda query_type=None, limit=100: [
                _history_record(record_id=1, query_value='8.8.8.8')])
        result = call_tool('history_search', {'query': '8.8', 'kind': 'IP'})
        assert result['count'] == 1

    def test_limit_clamped_to_bounds(self, monkeypatch):
        from obscuralens.database import db
        seen = {}

        def fake_search(search_term, limit=100):
            seen['limit'] = limit
            return []

        monkeypatch.setattr(db, 'search_history', fake_search)
        call_tool('history_search', {'query': 'x', 'limit': 500})
        assert seen['limit'] == 100
        call_tool('history_search', {'query': 'x', 'limit': 0})
        assert seen['limit'] == 1
        call_tool('history_search', {'query': 'x', 'limit': 'many'})
        assert seen['limit'] == 25

    def test_missing_query_raises(self):
        with pytest.raises(ValueError, match='query is required'):
            call_tool('history_search', {})

    def test_round_trip_via_json_rpc(self, monkeypatch):
        from obscuralens.database import db
        monkeypatch.setattr(
            db, 'search_history',
            lambda search_term, limit=100: [_history_record()])
        response = handle_request(_request(
            'tools/call',
            {'name': 'history_search', 'arguments': {'query': '8.8'}}))
        assert response['result']['isError'] is False
        payload = json.loads(_text(response))
        assert payload['count'] == 1
        assert payload['results'][0]['kind'] == 'ip'


class TestWatchAdd:

    def test_add_returns_entry(self, monkeypatch):
        from obscuralens.watchlist import WatchEntry, watchlist
        entry = WatchEntry(id=7, target='8.8.8.8', kind='ip', label='dns',
                           created_at='2026-10-01T00:00:00')
        monkeypatch.setattr(watchlist, 'add',
                            lambda target, kind=None, label='': 7)
        monkeypatch.setattr(watchlist, 'get', lambda identifier: entry)
        result = call_tool('watch_add',
                           {'target': '8.8.8.8', 'label': 'dns'})
        assert result['ok'] is True
        assert result['id'] == 7
        assert result['entry']['target'] == '8.8.8.8'
        assert result['entry']['kind'] == 'ip'

    def test_add_passes_kind_and_label(self, monkeypatch):
        from obscuralens.watchlist import watchlist
        seen = {}

        def fake_add(target, kind=None, label=''):
            seen.update(target=target, kind=kind, label=label)
            return 1

        monkeypatch.setattr(watchlist, 'add', fake_add)
        monkeypatch.setattr(watchlist, 'get', lambda identifier: None)
        call_tool('watch_add', {'target': 'example.com', 'kind': 'domain',
                                'label': 'watched'})
        assert seen == {'target': 'example.com', 'kind': 'domain',
                        'label': 'watched'}

    def test_add_without_entry_lookup_still_ok(self, monkeypatch):
        from obscuralens.watchlist import watchlist
        monkeypatch.setattr(watchlist, 'add',
                            lambda target, kind=None, label='': 9)
        monkeypatch.setattr(watchlist, 'get', lambda identifier: None)
        result = call_tool('watch_add', {'target': '8.8.8.8'})
        assert result == {'ok': True, 'id': 9}

    def test_duplicate_target_raises(self, monkeypatch):
        from obscuralens.watchlist import watchlist

        def fake_add(target, kind=None, label=''):
            raise ValueError('already watched')

        monkeypatch.setattr(watchlist, 'add', fake_add)
        with pytest.raises(ValueError, match='already watched'):
            call_tool('watch_add', {'target': '8.8.8.8'})

    def test_missing_target_raises(self):
        with pytest.raises(ValueError, match='target is required'):
            call_tool('watch_add', {})


class TestWatchRemove:

    def test_remove_by_numeric_id_string_coerced(self, monkeypatch):
        from obscuralens.watchlist import watchlist
        seen = {}

        def fake_remove(identifier):
            seen['identifier'] = identifier
            return 1

        monkeypatch.setattr(watchlist, 'remove', fake_remove)
        result = call_tool('watch_remove', {'identifier': '7'})
        assert seen['identifier'] == 7
        assert result == {'ok': True, 'removed': 1}

    def test_remove_by_target_value(self, monkeypatch):
        from obscuralens.watchlist import watchlist
        seen = {}

        def fake_remove(identifier):
            seen['identifier'] = identifier
            return 1

        monkeypatch.setattr(watchlist, 'remove', fake_remove)
        result = call_tool('watch_remove',
                           {'identifier': '8.8.8.8'})
        assert seen['identifier'] == '8.8.8.8'
        assert result['ok'] is True

    def test_remove_no_match_is_ok_false(self, monkeypatch):
        from obscuralens.watchlist import watchlist
        monkeypatch.setattr(watchlist, 'remove', lambda identifier: 0)
        result = call_tool('watch_remove', {'identifier': 999})
        assert result == {'ok': False, 'removed': 0}

    def test_missing_or_invalid_identifier_raises(self):
        for bad in ({}, {'identifier': None}, {'identifier': ''},
                    {'identifier': True}):
            with pytest.raises(ValueError, match='identifier is required'):
                call_tool('watch_remove', bad)


class TestCaseList:

    def test_list_cases(self, monkeypatch):
        from obscuralens.cases import cases
        seen = {}

        def fake_list(include_archived=False):
            seen['include_archived'] = include_archived
            return [{'id': 1, 'name': 'alpha', 'status': 'open',
                     'item_count': 2, 'note_count': 1, 'tag_count': 0}]

        monkeypatch.setattr(cases, 'list_cases', fake_list)
        result = call_tool('case_list', {})
        assert seen['include_archived'] is False
        assert result['count'] == 1
        assert result['cases'][0]['name'] == 'alpha'

    def test_include_archived_flag_propagates(self, monkeypatch):
        from obscuralens.cases import cases
        seen = {}

        def fake_list(include_archived=False):
            seen['include_archived'] = include_archived
            return []

        monkeypatch.setattr(cases, 'list_cases', fake_list)
        result = call_tool('case_list', {'include_archived': True})
        assert seen['include_archived'] is True
        assert result == {'count': 0, 'cases': []}

    def test_non_boolean_flag_falls_back_to_false(self, monkeypatch):
        from obscuralens.cases import cases
        seen = {}

        def fake_list(include_archived=False):
            seen['include_archived'] = include_archived
            return []

        monkeypatch.setattr(cases, 'list_cases', fake_list)
        call_tool('case_list', {'include_archived': 'yes'})
        assert seen['include_archived'] is False


class TestCaseCreate:

    def test_create_case(self, monkeypatch):
        from obscuralens.cases import cases
        monkeypatch.setattr(
            cases, 'create_case',
            lambda name, description='': {
                'id': 3, 'name': name, 'description': description,
                'status': 'open'})
        result = call_tool('case_create',
                           {'name': 'beta', 'description': 'desc'})
        assert result['ok'] is True
        assert result['case']['id'] == 3
        assert result['case']['description'] == 'desc'
        assert 'item' not in result

    def test_create_case_with_target_adds_item(self, monkeypatch):
        from obscuralens.cases import cases
        seen = {}

        def fake_create(name, description=''):
            return {'id': 5, 'name': name, 'description': description,
                    'status': 'open'}

        def fake_add_item(case_id, kind, value, note=''):
            seen.update(case_id=case_id, kind=kind, value=value)
            return {'id': 11, 'case_id': case_id, 'kind': 'ip',
                    'value': value, 'note': ''}

        monkeypatch.setattr(cases, 'create_case', fake_create)
        monkeypatch.setattr(cases, 'add_item', fake_add_item)
        result = call_tool('case_create',
                           {'name': 'gamma', 'target': '8.8.8.8'})
        assert seen == {'case_id': 5, 'kind': 'auto', 'value': '8.8.8.8'}
        assert result['item']['kind'] == 'ip'
        assert result['case']['id'] == 5

    def test_duplicate_name_raises_with_existing_id(self, monkeypatch):
        from obscuralens.cases import cases
        monkeypatch.setattr(
            cases, 'create_case',
            lambda name, description='': {'error': 'case exists', 'id': 5})
        with pytest.raises(ValueError) as excinfo:
            call_tool('case_create', {'name': 'dup'})
        assert 'case exists' in str(excinfo.value)
        assert '5' in str(excinfo.value)

    def test_rejected_item_raises_with_reason(self, monkeypatch):
        from obscuralens.cases import cases
        monkeypatch.setattr(
            cases, 'create_case',
            lambda name, description='': {'id': 6, 'name': name,
                                          'status': 'open'})
        monkeypatch.setattr(
            cases, 'add_item',
            lambda case_id, kind, value, note='': {'error': 'duplicate'})
        with pytest.raises(ValueError, match='duplicate'):
            call_tool('case_create', {'name': 'delta', 'target': '8.8.8.8'})

    def test_missing_name_raises(self):
        with pytest.raises(ValueError, match='name is required'):
            call_tool('case_create', {})

    def test_blank_target_is_ignored(self, monkeypatch):
        from obscuralens.cases import cases
        monkeypatch.setattr(
            cases, 'create_case',
            lambda name, description='': {'id': 8, 'name': name,
                                          'status': 'open'})

        def fail_add_item(case_id, kind, value, note=''):  # pragma: no cover
            raise AssertionError('blank target must not add an item')

        monkeypatch.setattr(cases, 'add_item', fail_add_item)
        result = call_tool('case_create', {'name': 'eps', 'target': '   '})
        assert 'item' not in result


class TestDataPackLookup:

    @pytest.mark.parametrize('pack,key,field,expected', [
        ('country', 'ID', 'name', 'Republic of Indonesia'),
        ('country', 'id', 'code', 'ID'),
        ('port', 443, 'service', 'https'),
        ('port', '22', 'service', 'ssh'),
        ('language', 'en', 'name', 'English'),
        ('currency', 'EUR', 'name', 'Euro'),
        ('currency', 'eur', 'minor_units', 2),
        ('http_status', 404, 'phrase', 'Not Found'),
        ('http_status', '500', 'category', 'server_error'),
        ('cwe', 'CWE-79', 'cwe_id', 'CWE-79'),
        ('cwe', '79', 'cwe_id', 'CWE-79'),
        ('airline', 'GA', 'name', 'Garuda Indonesia'),
        ('wmi', 'WBA', 'manufacturer', 'BMW'),
        ('wmi', 'wba', 'country', 'Germany'),
        ('mid', '310', 'country', 'Bermuda'),
        ('mid', 310, 'country', 'Bermuda'),
    ])
    def test_pack_hits(self, pack, key, field, expected):
        result = call_tool('data_pack_lookup',
                           {'pack': pack, 'key': key})
        assert result['pack'] == pack
        assert result['record'][field] == expected
        assert 'found' not in result

    @pytest.mark.parametrize('pack,key', [
        ('country', 'XX'), ('port', 99999), ('language', 'zz'),
        ('currency', 'XYZ'), ('http_status', 999), ('cwe', 'CWE-99999'),
        ('airline', 'ZZ'), ('wmi', 'ZZZ'), ('mid', '000'),
    ])
    def test_pack_misses_report_found_false(self, pack, key):
        result = call_tool('data_pack_lookup', {'pack': pack, 'key': key})
        assert result == {'pack': pack, 'key': key, 'found': False}

    def test_unknown_pack_raises(self):
        with pytest.raises(ValueError) as excinfo:
            call_tool('data_pack_lookup', {'pack': 'nope', 'key': 'ID'})
        assert 'unknown pack' in str(excinfo.value)
        assert 'country' in str(excinfo.value)
        assert 'mid' in str(excinfo.value)

    def test_pack_is_case_insensitive(self):
        result = call_tool('data_pack_lookup',
                           {'pack': 'HTTP_STATUS', 'key': 404})
        assert result['record']['phrase'] == 'Not Found'

    def test_missing_pack_or_key_raises(self):
        with pytest.raises(ValueError, match='pack is required'):
            call_tool('data_pack_lookup', {'key': 'ID'})
        for bad_key in (None, '', '   ', True):
            with pytest.raises(ValueError, match='key is required'):
                call_tool('data_pack_lookup',
                          {'pack': 'country', 'key': bad_key})


class TestEcosystemRoundTrips:
    """JSON-RPC round trips for the v6.0 part-5 tools."""

    @pytest.mark.parametrize('name,arguments,needle', [
        ('analytics_forecast', {'values': [1, 2, 3, 4]}, 'forecasts'),
        ('analytics_trend', {'values': [5, 6, 5, 6, 20]}, 'changepoint_count'),
        ('analytics_clusters', {'points': [[52.0, 13.0], [52.01, 13.01],
                                            [52.02, 13.02]]},
         'cluster_count'),
        ('data_pack_lookup', {'pack': 'country', 'key': 'ID'},
         'Republic of Indonesia'),
        ('watch_remove', {'identifier': 999}, 'removed'),
    ])
    def test_round_trip(self, name, arguments, needle):
        response = handle_request(_request(
            'tools/call', {'name': name, 'arguments': arguments}))
        assert response['id'] == 1
        content = response['result']['content']
        assert content[0]['type'] == 'text'
        assert response['result']['isError'] is False
        payload = json.loads(_text(response))
        assert needle in _text(response)
        assert isinstance(payload, dict)

    def test_round_trip_missing_argument_is_clean_error(self):
        response = handle_request(_request(
            'tools/call', {'name': 'analytics_forecast', 'arguments': {}}))
        assert response['result']['isError'] is True
        payload = json.loads(_text(response))
        assert 'values is required' in payload['error']


class TestEcosystemRegistry:
    """TOOLS/_HANDLERS consistency for the 63-tool surface."""

    def test_tools_list_contains_all_63_names(self):
        tools = handle_request(_request('tools/list'))['result']['tools']
        assert len(tools) == 63
        assert {tool['name'] for tool in tools} == TOOL_NAMES

    def test_handlers_registry_matches_registry_dispatched_tools(self):
        names = {tool['name'] for tool in mcp_server.TOOLS}
        assert len(names) == 63
        assert set(mcp_server._HANDLERS) == names - BUILTIN_TOOLS
        assert not set(mcp_server._HANDLERS) & BUILTIN_TOOLS
        # Registry order follows the TOOLS advertisement order.
        advertised = [name for name in (t['name'] for t in mcp_server.TOOLS)
                      if name in mcp_server._HANDLERS]
        assert advertised == list(mcp_server._HANDLERS)

    def test_every_tool_entry_has_complete_schema(self):
        for tool in mcp_server.TOOLS:
            assert set(tool) == {'name', 'description', 'inputSchema'}
            assert isinstance(tool['description'], str) and tool['description']
            schema = tool['inputSchema']
            assert schema['type'] == 'object'
            assert schema['additionalProperties'] is False
            for prop in schema['properties'].values():
                assert 'type' in prop
            for required in schema.get('required', []):
                assert required in schema['properties']
