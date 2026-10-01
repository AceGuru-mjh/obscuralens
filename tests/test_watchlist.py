"""Watchlist tests: fully offline, one temporary SQLite file per test."""

import json
from pathlib import Path

import pytest

from obscuralens.config import config
from obscuralens.watchlist import WatchlistManager, diff_snapshots, flatten, watchlist_path


@pytest.fixture()
def manager(tmp_env):
    return WatchlistManager(path=str(tmp_env / 'watch.db'))


def test_add_detects_kinds(manager):
    cases = {
        '8.8.8.8': 'ip',
        'example.com': 'domain',
        'alice@example.com': 'email',
        'alice': 'username',
        '+62812345678': 'phone',
    }
    for target in cases:
        assert manager.add(target) > 0

    by_target = {entry.target: entry.kind for entry in manager.list()}
    assert by_target == cases


def test_add_duplicate_raises(manager):
    assert manager.add('8.8.8.8', kind='ip', label='dns') > 0
    with pytest.raises(ValueError, match='already watched'):
        manager.add('8.8.8.8')

    manager.add('example.com')
    # Domains are normalised to lower case before the UNIQUE check.
    with pytest.raises(ValueError, match='already watched'):
        manager.add('EXAMPLE.COM')


def test_add_unknown_target_raises(manager):
    for bad in ('', '   ', 'not a target!'):
        with pytest.raises(ValueError, match='unrecognised target'):
            manager.add(bad)


def test_get_and_remove_by_id_and_target(manager):
    ip_id = manager.add('8.8.8.8', label='dns')
    manager.add('alice')

    entry = manager.get(ip_id)
    assert entry is not None
    assert entry.target == '8.8.8.8'
    assert entry.kind == 'ip'
    assert entry.label == 'dns'
    assert entry.snapshots == 0
    assert manager.get('alice').kind == 'username'
    assert manager.get('nobody') is None
    assert manager.get(999999) is None

    assert manager.remove('alice') == 1
    assert manager.remove('alice') == 0
    assert manager.remove(ip_id) == 1
    assert manager.remove(ip_id) == 0
    assert manager.list() == []


def test_check_records_first_and_diffs_successive(manager):
    manager.add('8.8.8.8')
    state = {'result': {'info': {'country': 'US', 'city': 'NYC', 'lat': 1.5,
                                 'current_time': 't1'}}}
    checker = lambda kind, target: state['result']  # noqa: E731

    first = manager.check(checker=checker)
    assert len(first) == 1
    assert first[0].is_first is True
    assert first[0].success is True
    assert first[0].added == {'country': '"US"', 'city': '"NYC"', 'lat': '1.5'}
    assert first[0].removed == {}
    assert first[0].changed == {}

    state['result'] = {'info': {'country': 'US', 'city': 'LA', 'org': 'ACME',
                                'current_time': 't2'}}
    second = manager.check(checker=checker)[0]
    assert second.is_first is False
    assert second.success is True
    assert second.added == {'org': '"ACME"'}
    assert second.removed == {'lat': '1.5'}
    assert second.changed == {'city': {'from': 'NYC', 'to': 'LA'}}

    checked = manager.get('8.8.8.8')
    assert checked.snapshots == 2
    assert checked.last_checked is not None


def test_volatile_fields_do_not_diff(manager):
    manager.add('8.8.8.8')
    state = {'result': {'info': {'country': 'US', 'current_time': '2026-01-01',
                                 'response_time': 0.1, 'domain_age_days': 5}}}
    checker = lambda kind, target: state['result']  # noqa: E731
    manager.check(checker=checker)

    state['result'] = {'info': {'country': 'US', 'current_time': '2026-01-02',
                                'response_time': 0.9, 'domain_age_days': 6}}
    diff = manager.check(checker=checker)[0]
    assert diff.is_first is False
    assert diff.added == {}
    assert diff.removed == {}
    assert diff.changed == {}


def test_checker_failure_reports_error_and_stores_nothing(manager):
    manager.add('8.8.8.8')

    def boom(kind, target):
        raise RuntimeError('source down')

    diff = manager.check(checker=boom)[0]
    assert diff.success is False
    assert diff.error == 'RuntimeError'
    assert diff.added == {}
    assert diff.removed == {}
    assert diff.changed == {}

    entry = manager.get('8.8.8.8')
    assert entry.snapshots == 0
    assert entry.last_checked is None
    assert manager.history('8.8.8.8') == []

    # A later successful check is still treated as the first snapshot.
    retry = manager.check(
        checker=lambda kind, target: {'info': {'country': 'US'}})[0]
    assert retry.is_first is True
    assert retry.added == {'country': '"US"'}


def test_username_results_diff_by_platform(manager):
    manager.add('alice')
    state = {'result': {'results': [
        {'platform': 'github', 'status': 'found'},
        {'platform': 'gitlab', 'status': 'not_found'},
    ]}}
    checker = lambda kind, target: state['result']  # noqa: E731

    first = manager.check(checker=checker)[0]
    assert first.added == {'platform:github': 'found',
                           'platform:gitlab': 'not_found'}

    state['result'] = {'results': [
        {'platform': 'github', 'status': 'found'},
        {'platform': 'gitlab', 'status': 'found'},
        {'platform': 'keybase', 'status': 'unknown'},
    ]}
    second = manager.check(checker=checker)[0]
    assert second.added == {'platform:keybase': 'unknown'}
    assert second.removed == {}
    assert second.changed == {'platform:gitlab':
                              {'from': 'not_found', 'to': 'found'}}


def test_history_returns_snapshots_newest_first(manager):
    watch_id = manager.add('8.8.8.8')
    for city in ('NYC', 'LA', 'SF'):
        manager.check(
            checker=lambda kind, target, city=city: {'info': {'city': city}})

    history = manager.history(watch_id)
    cities = [json.loads(json.loads(row['data'])['city']) for row in history]
    assert cities == ['SF', 'LA', 'NYC']
    assert set(history[0]) == {'id', 'created_at', 'data'}
    assert manager.history(watch_id, limit=2) == history[:2]
    assert manager.get(watch_id).snapshots == 3
    assert manager.history('nobody') == []


def test_check_all_and_single_entry(manager):
    ip_id = manager.add('8.8.8.8')
    manager.add('alice')
    results = {
        'ip': {'info': {'country': 'US'}},
        'username': {'results': [{'platform': 'github', 'status': 'found'}]},
    }

    def checker(kind, target):
        return results[kind]

    everything = manager.check(checker=checker)
    assert len(everything) == 2
    assert {diff.target for diff in everything} == {'8.8.8.8', 'alice'}
    assert manager.get(ip_id).last_checked is not None

    only = manager.check(ip_id, checker=checker)
    assert len(only) == 1
    assert only[0].watch_id == ip_id
    assert only[0].is_first is False
    assert manager.check(999999, checker=checker) == []


def test_flatten_and_diff_helpers():
    assert flatten({'info': {'city': 'NYC', 'count': 3,
                             'current_time': 'now'}}) == {
        'city': '"NYC"', 'count': '3'}
    assert flatten({'results': [{'platform': 'github', 'status': 'found'},
                                {'platform': 'gitlab', 'status': 'unknown'}]}) == {
        'platform:github': 'found', 'platform:gitlab': 'unknown'}
    assert flatten('not a dict') == {}

    added, removed, changed = diff_snapshots(
        {'a': '"old"', 'gone': '1'}, {'a': '"new"', 'b': '2'})
    assert added == {'b': '2'}
    assert removed == {'gone': '1'}
    assert changed == {'a': {'from': 'old', 'to': 'new'}}


def test_manager_defaults_to_configured_path(tmp_env):
    assert watchlist_path() == Path(config.db_config.sqlite_path)
    assert Path(WatchlistManager().path) == watchlist_path()
