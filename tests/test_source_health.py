"""Source health / circuit breaker tests (sqlite redirected via conftest)."""

import sqlite3
import threading

import pytest

from obscuralens.config import config
from obscuralens.health import SourceHealth, health
from obscuralens.health import source_health as source_health_module


@pytest.fixture(autouse=True)
def clean_table():
    """Isolate every test in an empty source_health table."""
    health.reset()
    yield
    health.reset()


def _direct(sql, params=()):
    """Run SQL straight against the shared test database."""
    conn = sqlite3.connect(config.db_config.sqlite_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _row(source, kind):
    rows = [r for r in health.get_health(source) if r['kind'] == kind]
    assert len(rows) == 1
    return rows[0]


def test_singleton_is_shared_instance():
    assert isinstance(health, SourceHealth)
    assert SourceHealth().get_health() == health.get_health()


def test_record_ok_creates_row():
    assert health.record('ip', 'ripestat', True) is True
    row = _row('ripestat', 'ip')
    assert row['ok_count'] == 1
    assert row['fail_count'] == 0
    assert row['consecutive_failures'] == 0
    assert row['last_ok']
    assert row['last_failure'] is None
    assert row['state'] == 'healthy'
    assert row['reliability'] == 100.0


def test_record_fail_updates_streak_and_error():
    health.record('ip', 'ripestat', False, 'timeout after 30s')
    row = _row('ripestat', 'ip')
    assert row['ok_count'] == 0
    assert row['fail_count'] == 1
    assert row['consecutive_failures'] == 1
    assert row['last_failure']
    assert row['last_error'] == 'timeout after 30s'
    assert row['reliability'] == 0.0
    assert row['state'] == 'healthy'  # below the default threshold of 4


def test_consecutive_failures_reset_on_success():
    health.record('ip', 'ripestat', False, 'boom')
    health.record('ip', 'ripestat', False, 'boom 2')
    assert _row('ripestat', 'ip')['consecutive_failures'] == 2
    health.record('ip', 'ripestat', True)
    row = _row('ripestat', 'ip')
    assert row['consecutive_failures'] == 0
    assert row['ok_count'] == 1
    assert row['fail_count'] == 2
    # the last error is kept as history even after a success
    assert row['last_error'] == 'boom 2'


def test_record_truncates_long_errors():
    health.record('ip', 'ripestat', False, 'x' * 300)
    assert len(_row('ripestat', 'ip')['last_error']) == 200


def test_record_skips_blank_source_or_kind():
    assert health.record('ip', '', True) is False
    assert health.record('', 'ripestat', True) is False
    assert health.record(None, 'ripestat', True) is False
    assert health.get_health() == []


def test_record_disabled_is_noop(monkeypatch):
    monkeypatch.setattr(config.app_config, 'source_health_enabled', False)
    assert health.record('ip', 'ripestat', True) is False
    monkeypatch.setattr(config.app_config, 'source_health_enabled', True)
    assert health.get_health() == []


def test_record_batch_records_sources():
    status_map = {
        'ripestat': {'ok': True, 'error': ''},
        'bgpview': {'ok': False, 'error': 'http 502'},
    }
    assert health.record_batch('asn', status_map) == 2
    assert _row('ripestat', 'asn')['ok_count'] == 1
    failed = _row('bgpview', 'asn')
    assert failed['fail_count'] == 1
    assert failed['last_error'] == 'http 502'


def test_record_batch_prefixes_plugin_kind():
    status_map = {
        'ripestat': {'ok': True, 'error': ''},
        'plugin:shodan-extra': {'ok': False, 'error': 'nope'},
    }
    assert health.record_batch('ip', status_map) == 2
    assert _row('ripestat', 'ip')['kind'] == 'ip'
    assert _row('plugin:shodan-extra', 'plugin:ip')['fail_count'] == 1


def test_record_batch_skips_non_dict_status():
    assert health.record_batch('ip', {'ripestat': 'nope', 'x': 5}) == 0
    assert health.get_health() == []


def test_record_batch_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(config.app_config, 'source_health_enabled', False)
    assert health.record_batch('ip', {'ripestat': {'ok': True}}) == 0
    monkeypatch.setattr(config.app_config, 'source_health_enabled', True)
    assert health.get_health() == []


def test_reliability_math():
    for _ in range(3):
        health.record('ip', 'a', True)
    health.record('ip', 'a', False, 'x')
    for _ in range(2):
        health.record('ip', 'b', True)
    health.record('ip', 'b', False, 'x')
    assert _row('a', 'ip')['reliability'] == 75.0
    assert _row('b', 'ip')['reliability'] == 66.7


def test_state_untested_for_unused_row():
    _direct('INSERT OR REPLACE INTO source_health (source, kind) '
            "VALUES ('ghost', 'ip')")
    row = _row('ghost', 'ip')
    assert row['state'] == 'untested'
    assert row['reliability'] == 0.0
    assert health.is_available('ghost') == (True, '')


def test_circuit_trips_at_threshold(monkeypatch):
    monkeypatch.setattr(config.app_config, 'source_failure_threshold', 2)
    monkeypatch.setattr(config.app_config, 'source_cooldown_seconds', 3600)
    health.record('ip', 'ripestat', False, 'boom')
    assert health.is_available('ripestat') == (True, '')  # streak 1 < 2
    health.record('ip', 'ripestat', False, 'boom 2')
    available, reason = health.is_available('ripestat')
    assert available is False
    assert 'circuit open' in reason
    assert '2 consecutive failures' in reason
    assert 'cooldown' in reason
    assert health.source_allowed('ripestat') is False
    assert _row('ripestat', 'ip')['state'] == 'tripped'


def test_circuit_success_resets_streak(monkeypatch):
    monkeypatch.setattr(config.app_config, 'source_failure_threshold', 2)
    monkeypatch.setattr(config.app_config, 'source_cooldown_seconds', 3600)
    health.record('ip', 'ripestat', False, 'a')
    health.record('ip', 'ripestat', False, 'b')
    assert health.is_available('ripestat')[0] is False
    health.record('ip', 'ripestat', True)
    assert health.is_available('ripestat') == (True, '')
    assert _row('ripestat', 'ip')['state'] == 'healthy'


def test_cooldown_expiry_reopens_circuit(monkeypatch):
    monkeypatch.setattr(config.app_config, 'source_failure_threshold', 2)
    monkeypatch.setattr(config.app_config, 'source_cooldown_seconds', 3600)
    health.record('ip', 'ripestat', False, 'a')
    health.record('ip', 'ripestat', False, 'b')
    assert health.is_available('ripestat')[0] is False
    _direct("UPDATE source_health SET last_failure = '2020-01-01T00:00:00+00:00' "
            "WHERE source = 'ripestat'")
    assert health.is_available('ripestat') == (True, '')
    assert _row('ripestat', 'ip')['state'] == 'healthy'


def test_is_available_unknown_source_fails_open():
    assert health.is_available('never-seen') == (True, '')
    assert health.is_available('never-seen', 'ip') == (True, '')
    assert health.source_allowed('never-seen') is True


def test_is_available_kind_scoped(monkeypatch):
    monkeypatch.setattr(config.app_config, 'source_failure_threshold', 1)
    monkeypatch.setattr(config.app_config, 'source_cooldown_seconds', 3600)
    health.record('ip', 'ripestat', False, 'boom')
    health.record('domain', 'ripestat', True)
    assert health.is_available('ripestat', 'ip')[0] is False
    assert health.is_available('ripestat', 'domain') == (True, '')
    # without a kind, any tripped row trips the source
    assert health.is_available('ripestat')[0] is False


def test_disabled_health_always_available(monkeypatch):
    monkeypatch.setattr(config.app_config, 'source_failure_threshold', 1)
    monkeypatch.setattr(config.app_config, 'source_cooldown_seconds', 3600)
    health.record('ip', 'ripestat', False, 'boom')
    assert health.is_available('ripestat')[0] is False
    monkeypatch.setattr(config.app_config, 'source_health_enabled', False)
    assert health.is_available('ripestat') == (True, '')
    assert health.source_allowed('ripestat') is True


def test_get_health_filters_by_source():
    health.record('ip', 'ripestat', True)
    health.record('ip', 'bgpview', True)
    health.record('asn', 'bgpview', False, 'x')
    rows = health.get_health('ripestat')
    assert len(rows) == 1
    assert rows[0]['source'] == 'ripestat'
    assert {r['kind'] for r in health.get_health('bgpview')} == {'ip', 'asn'}
    assert len(health.get_health('nobody')) == 0


def test_reset_scopes():
    health.record('ip', 'a', True)
    health.record('ip', 'b', True)
    health.record('asn', 'b', True)
    assert health.reset('a') == 1
    assert health.get_health('a') == []
    assert health.reset('b', 'asn') == 1
    assert len(health.get_health('b')) == 1
    assert health.reset() == 1  # the remaining (b, ip) row
    assert health.get_health() == []


def test_prune_removes_untested_rows():
    _direct('INSERT OR REPLACE INTO source_health (source, kind) '
            "VALUES ('ghost', 'ip')")
    health.record('ip', 'ripestat', True)
    assert health.prune(keep=500) == 1
    assert {r['source'] for r in health.get_health()} == {'ripestat'}


def test_prune_keeps_most_used_rows():
    for index in range(5):
        for _ in range(index + 1):
            health.record('ip', f'src{index}', True)
    assert health.prune(keep=2) == 3
    rows = health.get_health()
    assert len(rows) == 2
    assert {r['source'] for r in rows} == {'src3', 'src4'}


def test_health_sections_shape_and_ordering():
    health.record('ip', 'ripestat', True)
    health.record('ip', 'bgpview', False, 'timeout')
    sections = health.health_sections()
    assert isinstance(sections, list) and len(sections) == 2
    grid, table = sections
    assert grid['type'] == 'grid'
    assert grid['data']['Sources tracked'] == 2
    assert grid['data']['Tripped'] == 0
    assert grid['data']['Average reliability'] == '50.0%'
    assert table['type'] == 'table'
    assert table['columns'] == ['Source', 'Kind', 'OK', 'Fail', 'Reliability',
                                'State', 'Last error']
    # sorted by fail_count desc -> the failing source leads
    assert table['rows'][0][0] == 'bgpview'
    assert table['rows'][0][6] == 'timeout'
    assert table['rows'][1][0] == 'ripestat'
    assert table['rows'][1][4] == '100.0%'


def test_health_sections_empty():
    sections = health.health_sections()
    assert len(sections) == 1
    assert sections[0]['type'] == 'grid'
    assert sections[0]['data']['Sources tracked'] == 0
    assert sections[0]['data']['Average reliability'] == '0.0%'


def test_health_sections_caps_at_100_rows():
    conn = sqlite3.connect(config.db_config.sqlite_path)
    try:
        conn.executemany(
            'INSERT OR REPLACE INTO source_health '
            '(source, kind, ok_count, fail_count) VALUES (?, ?, 1, ?)',
            [(f'src{index:03d}', 'ip', index % 5) for index in range(105)])
        conn.commit()
    finally:
        conn.close()
    sections = health.health_sections()
    table = [s for s in sections if s['type'] == 'table'][0]
    assert len(table['rows']) == 100
    assert table['rows'][0][3] >= table['rows'][-1][3]  # fail_count desc


def test_sqlite_error_returns_safe_defaults(monkeypatch):
    def boom():
        raise sqlite3.OperationalError('database gone')

    monkeypatch.setattr(source_health_module, '_connect', boom)
    assert health.get_health() == []
    assert health.is_available('ripestat') == (True, '')
    assert health.record('ip', 'ripestat', True) is False
    assert health.record_batch('ip', {'ripestat': {'ok': True}}) == 0
    assert health.reset() == 0
    assert health.prune() == 0
    assert health.health_sections() == []


def test_concurrent_records_are_thread_safe():
    failures = []

    def worker(index):
        try:
            for step in range(10):
                health.record('ip', f'src{index}', step % 3 != 0)
        except Exception as exc:  # test sentinel: any escape is a failure
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    for index in range(4):
        row = _row(f'src{index}', 'ip')
        assert row['ok_count'] + row['fail_count'] == 10
