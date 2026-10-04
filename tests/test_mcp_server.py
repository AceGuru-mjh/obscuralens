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

}


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
                          'export_stix')
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
    assert len(second['result']['tools']) == 53  # 8 core + 10 v4.0 + 16 v5.0 + 6 v6.0 + 7 v6.0-part2 + 1 v6.1 + 5 v6.0-part4 tools
