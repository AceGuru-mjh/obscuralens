"""Non-interactive CLI tests (all trackers mocked)."""

import csv
import io
import json

import pytest

from obscuralens import commands
from obscuralens.database import db


class FakeTracker:
    def __init__(self, result, success=None):
        self.result = result
        self.track_kwargs = None
        self.batch_size = 0
        if success is not None:
            self.result = dict(result, success=success)

    def track(self, target, **kwargs):
        self.track_kwargs = kwargs
        return dict(self.result)

    def batch_track(self, targets, *args, **kwargs):
        self.batch_size = len(targets)
        return [dict(self.result) for _ in targets]


IP_RESULT = {
    'ip': '8.8.8.8',
    'info': {'country': 'United States', 'city': 'Mountain View',
             'latitude': 37.4, 'longitude': -122.0},
    'field_sources': {'country': ['ipwho.is']},
    'sources_ok': ['ipwho.is'], 'sources_failed': {},
    'field_count': 3, 'success': True, 'errors': [],
}


@pytest.fixture()
def fake_tracker(monkeypatch):
    tracker = FakeTracker(IP_RESULT)
    monkeypatch.setattr(commands, '_tracker', lambda kind: tracker)
    return tracker


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        commands.run(['--version'])
    assert exc.value.code == 0
    assert 'ObscuraLens' in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert commands.run([]) == 1
    assert 'usage' in capsys.readouterr().out.lower()


def test_ip_json_output(fake_tracker, capsys):
    code = commands.run(['ip', '8.8.8.8', '-f', 'json'])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ip'] == '8.8.8.8'
    assert payload['field_sources']['country'] == ['ipwho.is']


def test_ip_table_output(fake_tracker, capsys):
    code = commands.run(['ip', '8.8.8.8'])
    assert code == 0
    out = capsys.readouterr().out
    assert 'LOCATION' in out.upper()
    assert 'United States' in out


def test_ip_output_to_file(fake_tracker, tmp_path, capsys):
    target_file = tmp_path / 'out.json'
    code = commands.run(['ip', '8.8.8.8', '-f', 'json', '-o', str(target_file)])
    assert code == 0
    assert json.loads(target_file.read_text(encoding='utf-8'))['ip'] == '8.8.8.8'


def test_invalid_ip_returns_2(fake_tracker, capsys):
    assert commands.run(['ip', 'not-an-ip']) == 2
    assert 'Invalid IP' in capsys.readouterr().err


def test_all_sources_failed_returns_1(monkeypatch, capsys):
    tracker = FakeTracker(dict(IP_RESULT, success=False, sources_ok=[],
                               sources_failed={'ipwho.is': 'timeout'}))
    monkeypatch.setattr(commands, '_tracker', lambda kind: tracker)
    assert commands.run(['ip', '8.8.8.8', '-f', 'json']) == 1
    assert 'all data sources failed' in capsys.readouterr().err


def test_username_passes_options(fake_tracker):
    code = commands.run(['username', 'alice', '--fast',
                         '--platforms', 'keybase,lichess'])
    assert code == 0
    assert fake_tracker.track_kwargs['deep'] is False
    assert fake_tracker.track_kwargs['platforms'] == ['keybase', 'lichess']


def test_username_unknown_platform_returns_2(fake_tracker, capsys):
    assert commands.run(['username', 'alice', '--platforms', 'nope']) == 2
    assert 'unknown platform' in capsys.readouterr().err


def test_batch_csv(fake_tracker, tmp_path, capsys):
    targets = tmp_path / 'targets.txt'
    targets.write_text('8.8.8.8\n1.1.1.1\n', encoding='utf-8')
    code = commands.run(['batch', 'ip', str(targets), '-f', 'csv'])
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 2
    assert rows[0]['target'] == '8.8.8.8'
    assert fake_tracker.batch_size == 2


def test_batch_missing_file_returns_2(fake_tracker, tmp_path, capsys):
    assert commands.run(['batch', 'ip', str(tmp_path / 'nope.txt')]) == 2
    assert 'file not found' in capsys.readouterr().err


def test_sources_command(capsys):
    assert commands.run(['sources', 'domain']) == 0
    out = capsys.readouterr().out
    assert 'certspotter' in out


def test_keys_command_json(capsys):
    assert commands.run(['keys', '-f', 'json']) == 0
    rows = json.loads(capsys.readouterr().out)
    assert {row['service'] for row in rows} >= {'shodan', 'abuseipdb'}


def test_cache_stats_and_clear(capsys):
    assert commands.run(['cache', 'stats', '-f', 'json']) == 0
    stats = json.loads(capsys.readouterr().out)
    assert 'enabled' in stats
    assert commands.run(['cache', 'clear']) == 0
    assert 'Removed' in capsys.readouterr().out


def test_config_command(capsys):
    assert commands.run(['config', '-f', 'json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['app']['request_timeout'] >= 1
    assert 'config_dir' in payload


def test_history_command(tmp_env, capsys):
    db.save_query('ip', '198.51.100.7', {'info': {'country': 'Testland'}})
    assert commands.run(['history', '--search', '198.51.100.7', '-f', 'json']) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]['value'] == '198.51.100.7'

    record_id = rows[0]['id']
    assert commands.run(['history', '--id', str(record_id), '-f', 'json']) == 0
    record = json.loads(capsys.readouterr().out)
    assert record['result']['info']['country'] == 'Testland'


def test_history_missing_record_returns_1(capsys):
    assert commands.run(['history', '--id', '999999999']) == 1
    assert 'not found' in capsys.readouterr().err


INVESTIGATION_PAYLOAD = {
    'target': 'example.com',
    'kind': 'domain',
    'order': ['domain'],
    'results': {'domain': {
        'domain': 'example.com',
        'info': {'domain': 'example.com'},
        'sources_ok': ['dns'], 'sources_failed': {}, 'field_count': 1,
        'success': True, 'errors': [],
    }},
    'entities': [{'id': 'domain:example.com', 'type': 'domain',
                  'value': 'example.com', 'role': 'target',
                  'label': 'example.com'}],
    'links': [{'from': 'domain:example.com', 'to': 'ip:1.2.3.4',
               'label': 'a_record'}],
    'errors': [],
}


def test_investigate_json(monkeypatch, capsys):
    monkeypatch.setattr(commands, 'investigate',
                        lambda target, **kwargs: INVESTIGATION_PAYLOAD)
    assert commands.run(['investigate', 'example.com', '-f', 'json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['kind'] == 'domain'
    assert payload['links'][0]['label'] == 'a_record'


def test_investigate_table_and_mermaid(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(commands, 'investigate',
                        lambda target, **kwargs: INVESTIGATION_PAYLOAD)
    assert commands.run(['investigate', 'example.com']) == 0
    out = capsys.readouterr().out
    assert 'INVESTIGATION SUMMARY' in out.upper()

    graph = tmp_path / 'graph.mmd'
    assert commands.run(['investigate', 'example.com', '-f', 'mermaid',
                         '--graph', str(graph)]) == 0
    assert capsys.readouterr().out.startswith('graph LR')
    assert 'a_record' in graph.read_text(encoding='utf-8')


def test_investigate_unknown_target_returns_2(capsys):
    assert commands.run(['investigate', 'not a target!']) == 2
    assert 'cannot determine target type' in capsys.readouterr().err


def test_watch_add_list_remove(tmp_env, capsys):
    from obscuralens.watchlist import watchlist
    for entry in watchlist.list():
        watchlist.remove(entry.id)

    assert commands.run(['watch', 'add', '8.8.8.8', '--label', 'dns']) == 0
    assert 'Watching #' in capsys.readouterr().out

    assert commands.run(['watch', 'list', '-f', 'json']) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]['target'] == '8.8.8.8'
    assert rows[0]['kind'] == 'ip'

    assert commands.run(['watch', 'remove', str(rows[0]['id'])]) == 0
    assert 'Removed 1' in capsys.readouterr().out
    assert commands.run(['watch', 'remove', 'nope']) == 1


def test_watch_check_json(monkeypatch, capsys):
    from obscuralens.watchlist import WatchDiff
    diff = WatchDiff(watch_id=1, target='8.8.8.8', kind='ip',
                     checked_at='2026-10-01T00:00:00', is_first=False,
                     added={'ports': '[53, 443, 853]'}, removed={},
                     changed={'country': {'from': 'US', 'to': 'NL'}},
                     success=True, error='')
    monkeypatch.setattr(commands.watchlist, 'check',
                        lambda identifier=None: [diff])
    assert commands.run(['watch', 'check', '-f', 'json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]['changed']['country']['to'] == 'NL'
    assert payload[0]['added']['ports'] == '[53, 443, 853]'


def test_plugins_list_json(monkeypatch, capsys):
    from obscuralens.plugins import PluginInfo
    infos = [PluginInfo(name='demo', path='C:/plugins/demo.py',
                        kinds=['ip'], sources={'ip': ['Demo']}, error='')]
    monkeypatch.setattr(commands, 'loaded_plugins', lambda: infos)
    assert commands.run(['plugins', 'list', '-f', 'json']) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]['name'] == 'demo'
    assert rows[0]['kinds'] == 'ip'
