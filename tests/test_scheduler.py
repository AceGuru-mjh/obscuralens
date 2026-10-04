"""Scheduler tests (v6.0 part 4): schedule maths (compute_next_run for
interval/daily/weekly), task CRUD, due selection, every executor action,
run-due bookkeeping, the background tick loop, daemon start/stop and the
``automation`` CLI wiring. Fully offline - every executor seam (the
watchlist manager, the pipeline engine, the notification probe) is
monkeypatched at its import site, and the persisted state is isolated in
a per-test directory exactly like tests/test_notifications.py."""

import json
import threading
from datetime import datetime, timedelta

import pytest

from obscuralens.automation import scheduler
from obscuralens.automation.scheduler import (
    DEFAULT_TICK_INTERVAL,
    SCHEDULE_TYPES,
    TASK_ACTIONS,
    WEEKDAY_NAMES,
    TaskSpec,
    compute_next_run,
)


@pytest.fixture()
def fresh_state(tmp_path, monkeypatch):
    """Isolate scheduler.json in a per-test directory.

    The state file lives next to ``config.db_config.sqlite_path`` (the
    same convention as alerts.json / notifications.json), so pointing the
    sqlite path at a per-test path moves the scheduler state with it.
    """
    from obscuralens.config import config
    monkeypatch.setattr(config.db_config, 'sqlite_path',
                        str(tmp_path / 'scheduler.db'))
    return tmp_path


@pytest.fixture()
def notify_probe(monkeypatch):
    """Capture notify_test channel probes and report success."""
    from obscuralens.automation import notifications
    calls = []
    monkeypatch.setattr(notifications, 'test_channel',
                        lambda name: calls.append(name)
                        or {'ok': True, 'error': ''})
    return calls


def _add(name='probe', action='notify_test', params=None, **extra):
    """Register one task through the public add_task API."""
    spec = {'name': name, 'action': action, 'params': params or {}, **extra}
    return scheduler.add_task(spec)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec='seconds')


# --------------------------------------------------------------------------- #
# compute_next_run (pure scheduling maths)
# --------------------------------------------------------------------------- #

class TestComputeNextRun:

    def test_interval_adds_seconds(self):
        now = datetime(2024, 6, 1, 8, 0, 0)
        result = compute_next_run(
            {'schedule': 'interval', 'interval_seconds': 3600}, now)
        assert result == '2024-06-01T09:00:00'

    def test_interval_accepts_iso_string_now(self):
        # ``now`` may be a datetime *or* an ISO string (see _as_datetime).
        result = compute_next_run(
            {'schedule': 'interval', 'interval_seconds': 60},
            '2024-06-01T08:00:00')
        assert result == '2024-06-01T08:01:00'

    def test_daily_today_slot_still_ahead(self):
        result = compute_next_run(
            {'schedule': 'daily', 'at_time': '09:00'},
            datetime(2024, 6, 1, 8, 0, 0))
        assert result == '2024-06-01T09:00:00'

    def test_daily_today_slot_already_passed(self):
        result = compute_next_run(
            {'schedule': 'daily', 'at_time': '09:00'},
            datetime(2024, 6, 1, 10, 0, 0))
        assert result == '2024-06-02T09:00:00'

    def test_daily_boundary_exactly_at_time_goes_tomorrow(self):
        # The implementation treats "exactly now" as passed (<=), so the
        # 09:00:00 daily slot fires tomorrow when read at 09:00:00 sharp.
        result = compute_next_run(
            {'schedule': 'daily', 'at_time': '09:00'},
            datetime(2024, 6, 1, 9, 0, 0))
        assert result == '2024-06-02T09:00:00'

    def test_daily_invalid_at_time_defaults_to_nine(self):
        result = compute_next_run(
            {'schedule': 'daily', 'at_time': '25:99'},
            datetime(2024, 6, 1, 10, 0, 0))
        assert result == '2024-06-02T09:00:00'

    def test_weekly_later_this_week(self):
        # 2024-06-05 is a Wednesday (weekday 2); Friday slot at 09:00.
        result = compute_next_run(
            {'schedule': 'weekly', 'at_time': '09:00', 'weekday': 4},
            datetime(2024, 6, 5, 8, 0, 0))
        assert result == '2024-06-07T09:00:00'

    def test_weekly_today_slot_still_ahead_runs_today(self):
        result = compute_next_run(
            {'schedule': 'weekly', 'at_time': '09:00', 'weekday': 4},
            datetime(2024, 6, 7, 8, 0, 0))  # Friday morning
        assert result == '2024-06-07T09:00:00'

    def test_weekly_passed_slot_rolls_to_next_week(self):
        result = compute_next_run(
            {'schedule': 'weekly', 'at_time': '09:00', 'weekday': 4},
            datetime(2024, 6, 7, 10, 0, 0))  # Friday, slot passed
        assert result == '2024-06-14T09:00:00'

    def test_weekday_zero_is_monday(self):
        # Wednesday 2024-06-05 + weekday 0 => Monday 2024-06-10.
        result = compute_next_run(
            {'schedule': 'weekly', 'at_time': '09:00', 'weekday': 0},
            datetime(2024, 6, 5, 8, 0, 0))
        assert result == '2024-06-10T09:00:00'

    def test_invalid_schedule_falls_back_to_interval(self):
        now = datetime(2024, 6, 1, 8, 0, 0)
        result = compute_next_run(
            {'schedule': 'monthly', 'interval_seconds': 30}, now)
        assert result == '2024-06-01T08:00:30'

    def test_taskspec_instance_accepted(self):
        now = datetime(2024, 6, 1, 8, 0, 0)
        spec = TaskSpec(name='t', action='report', interval_seconds=10)
        assert compute_next_run(spec, now) == '2024-06-01T08:00:10'

    def test_aware_datetime_now_is_converted(self):
        from datetime import timezone
        aware = datetime(2024, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
        result = compute_next_run(
            {'schedule': 'interval', 'interval_seconds': 60}, aware)
        assert isinstance(result, str)
        assert datetime.fromisoformat(result)  # naive local ISO

    def test_unparseable_now_falls_back_to_current_time(self):
        before = datetime.now()
        result = compute_next_run(
            {'schedule': 'interval', 'interval_seconds': 3600},
            'not-a-timestamp')
        # The fallback anchors on the current time, then adds the period.
        parsed = datetime.fromisoformat(result)
        assert before + timedelta(seconds=3595) <= parsed \
            <= datetime.now() + timedelta(seconds=3605)

    def test_vocabularies_are_stable(self):
        assert SCHEDULE_TYPES == ('interval', 'daily', 'weekly')
        assert TASK_ACTIONS == ('watch_check', 'pipeline', 'report',
                                'feed_refresh', 'notify_test')
        assert WEEKDAY_NAMES[0] == 'Monday'
        assert WEEKDAY_NAMES[6] == 'Sunday'
        assert DEFAULT_TICK_INTERVAL == 30.0


# --------------------------------------------------------------------------- #
# Task CRUD
# --------------------------------------------------------------------------- #

class TestTaskCrud:

    def test_add_and_list_round_trip(self, fresh_state):
        result = _add(name='nightly-watch', action='watch_check',
                      schedule='daily', at_time='03:30',
                      params={'target': '8.8.8.8'})
        assert result['ok'] is True
        assert result['error'] == ''
        tasks = scheduler.list_tasks()
        assert len(tasks) == 1
        task = tasks[0]
        assert task['name'] == 'nightly-watch'
        assert task['action'] == 'watch_check'
        assert task['schedule'] == 'daily'
        assert task['at_time'] == '03:30'
        assert task['params'] == {'target': '8.8.8.8'}
        assert task['enabled'] is True
        assert task['run_count'] == 0
        assert task['error_count'] == 0
        assert task['last_error'] == ''
        assert task['last_run'] is None
        # add_task pre-computes the first next_run from the schedule.
        assert task['next_run']
        datetime.fromisoformat(task['next_run'])

    def test_add_taskspec_instance(self, fresh_state):
        spec = TaskSpec(name='spec-task', action='report',
                        params={'title': 'Weekly'}, schedule='weekly',
                        at_time='09:00', weekday=1)
        result = scheduler.add_task(spec)
        assert result['ok'] is True
        stored = scheduler.get_task('spec-task')
        assert stored['schedule'] == 'weekly'
        assert stored['weekday'] == 1
        assert stored['params'] == {'title': 'Weekly'}

    def test_get_task_case_insensitive_and_missing(self, fresh_state):
        _add(name='Probe-Task')
        assert scheduler.get_task('PROBE-TASK')['action'] == 'notify_test'
        assert scheduler.get_task('nope') is None

    def test_remove_task_round_trip_and_unknown(self, fresh_state):
        _add(name='gone')
        result = scheduler.remove_task('GONE')
        assert result == {'ok': True, 'error': '', 'removed': 'gone'}
        assert scheduler.list_tasks() == []
        missing = scheduler.remove_task('gone')
        assert missing['ok'] is False
        assert 'not found' in missing['error']
        assert missing['removed'] == ''

    def test_duplicate_name_rejected(self, fresh_state):
        _add(name='dupe')
        result = _add(name='dupe')
        assert result['ok'] is False
        assert 'already exists' in result['error']
        assert result['task'] is None
        assert len(scheduler.list_tasks()) == 1

    @pytest.mark.parametrize('spec, fragment', [
        ({'action': 'report'}, 'name is required'),
        ({'name': 'x', 'action': 'explode'}, 'unknown task action'),
        ({'name': 'x', 'action': 'report', 'schedule': 'monthly'},
         'unknown schedule'),
        ({'name': 'x', 'action': 'report', 'schedule': 'daily',
          'at_time': '25:00'}, 'at_time'),
        ({'name': 'x', 'action': 'report', 'interval_seconds': 0},
         'interval_seconds'),
        ({'name': 'x', 'action': 'report', 'schedule': 'weekly',
          'weekday': 7}, 'weekday'),
        ({'name': 'x', 'action': 'report', 'params': ['nope']},
         'params must be a mapping'),
        ({'name': 'n' * 81, 'action': 'report'}, 'too long'),
    ])
    def test_invalid_specs_rejected(self, fresh_state, spec, fragment):
        result = scheduler.add_task(spec)
        assert result['ok'] is False
        assert fragment in result['error']
        assert result['task'] is None
        assert scheduler.list_tasks() == []

    def test_corrupt_state_self_heals_next_run(self, fresh_state):
        _add(name='heal-me', action='report', interval_seconds=120)
        path = fresh_state / 'scheduler.json'
        state = json.loads(path.read_text(encoding='utf-8'))
        state['tasks'][0]['next_run'] = 'garbage'
        path.write_text(json.dumps(state), encoding='utf-8')
        task = scheduler.get_task('heal-me')
        assert task['next_run'] != 'garbage'
        datetime.fromisoformat(task['next_run'])

    def test_empty_state_is_fresh(self, fresh_state):
        assert scheduler.list_tasks() == []
        assert scheduler.get_task('anything') is None


# --------------------------------------------------------------------------- #
# due_tasks
# --------------------------------------------------------------------------- #

class TestDueTasks:

    def test_not_due_task_excluded(self, fresh_state):
        _add(name='later', action='report', interval_seconds=3600)
        assert scheduler.due_tasks(datetime.now()) == []

    def test_due_task_included(self, fresh_state):
        _add(name='now', action='report', interval_seconds=60)
        soon = datetime.now() + timedelta(hours=1)
        due = scheduler.due_tasks(soon)
        assert [task.name for task in due] == ['now']

    def test_disabled_task_excluded(self, fresh_state):
        _add(name='off', action='report', interval_seconds=60,
             enabled=False)
        far = datetime.now() + timedelta(days=365)
        assert scheduler.due_tasks(far) == []

    def test_empty_state_yields_nothing(self, fresh_state):
        assert scheduler.due_tasks() == []
        assert scheduler.due_tasks('2024-06-01T09:00:00') == []


# --------------------------------------------------------------------------- #
# run_task (executor dispatch)
# --------------------------------------------------------------------------- #

class _FakeDiff:
    """A watchlist diff stand-in with the attribute protocol."""

    def __init__(self, target='8.8.8.8', kind='ip', is_first=False,
                 success=True, added=None, removed=None, changed=None):
        self.target = target
        self.kind = kind
        self.is_first = is_first
        self.success = success
        self.added = added
        self.removed = removed
        self.changed = changed


class _FakeWatchlist:
    """A watchlist manager stand-in recording check() calls."""

    def __init__(self, diffs):
        self.diffs = diffs
        self.calls = []

    def check(self, identifier=None):
        self.calls.append(identifier)
        return self.diffs


class TestRunTask:

    def test_watch_check_counts_buckets(self, fresh_state, monkeypatch):
        fake = _FakeWatchlist([
            _FakeDiff(target='8.8.8.8', is_first=True),
            _FakeDiff(target='example.com', kind='domain',
                      changed={'registrar': ('a', 'b')}),
            _FakeDiff(target='dead.example', kind='domain', success=False),
        ])
        monkeypatch.setattr('obscuralens.watchlist.watchlist', fake)
        result = scheduler.run_task({'name': 'watch', 'action': 'watch_check'})
        assert result['ok'] is True
        assert result['error'] == ''
        assert '3 watch(es) checked' in result['summary']
        assert '1 first snapshot(s)' in result['summary']
        assert '1 changed' in result['summary']
        assert '1 failed' in result['summary']
        assert 'domain example.com' in result['summary']

    def test_watch_check_empty_watchlist(self, fresh_state, monkeypatch):
        fake = _FakeWatchlist([])
        monkeypatch.setattr('obscuralens.watchlist.watchlist', fake)
        result = scheduler.run_task({'name': 'watch', 'action': 'watch_check'})
        assert result['ok'] is True
        assert result['summary'] == 'watchlist is empty (nothing to check)'

    def test_watch_check_single_target_param(self, fresh_state, monkeypatch):
        fake = _FakeWatchlist([_FakeDiff()])
        monkeypatch.setattr('obscuralens.watchlist.watchlist', fake)
        scheduler.run_task({'name': 'watch', 'action': 'watch_check',
                            'params': {'target': '8.8.8.8'}})
        assert fake.calls == ['8.8.8.8']

    def test_pipeline_inline_spec(self, fresh_state, monkeypatch):
        from obscuralens.pipelines import engine
        calls = []

        def fake_run_pipeline(spec, variables=None, trackers=None):
            calls.append(spec)
            return {'name': 'mini', 'steps': [1, 2], 'errors': [],
                    'findings': [{'message': 'x'}]}

        monkeypatch.setattr(engine, 'run_pipeline', fake_run_pipeline)
        result = scheduler.run_task(
            {'name': 'pipe', 'action': 'pipeline',
             'params': {'spec': {'name': 'mini', 'steps': []}}})
        assert result['ok'] is True
        assert calls == [{'name': 'mini', 'steps': []}]
        assert result['summary'] == ("pipeline 'mini': 2 step(s), "
                                     "1 finding(s), 0 error(s)")

    def test_pipeline_by_path(self, fresh_state, tmp_path, monkeypatch):
        from obscuralens.pipelines import engine
        calls = []
        pipeline_file = tmp_path / 'daily.yaml'
        pipeline_file.write_text('name: daily\nsteps: []\n', encoding='utf-8')
        monkeypatch.setattr(
            engine, 'run_pipeline',
            lambda spec, variables=None, trackers=None:
                calls.append(spec) or {'name': 'daily', 'steps': [],
                                       'errors': [], 'findings': []})
        result = scheduler.run_task(
            {'name': 'pipe', 'action': 'pipeline',
             'params': {'path': str(pipeline_file)}})
        assert result['ok'] is True
        assert calls == [pipeline_file]
        assert "pipeline 'daily'" in result['summary']

    def test_pipeline_not_found(self, fresh_state):
        result = scheduler.run_task(
            {'name': 'pipe', 'action': 'pipeline',
             'params': {'name': 'ghost-pipeline-xyz'}})
        assert result['ok'] is False
        assert "pipeline 'ghost-pipeline-xyz' not found" in result['error']

    def test_report_writes_markdown_file(self, fresh_state, tmp_path,
                                         monkeypatch):
        from obscuralens.config import config
        report_dir = tmp_path / 'reports'
        monkeypatch.setattr(config.app_config, 'report_dir', str(report_dir))
        result = scheduler.run_task(
            {'name': 'weekly-report', 'action': 'report',
             'params': {'title': 'My weekly brief'}})
        assert result['ok'] is True
        assert 'report written' in result['summary']
        written = list(report_dir.glob('scheduled-weekly-report-*.md'))
        assert len(written) == 1
        text = written[0].read_text(encoding='utf-8')
        assert text.startswith('# My weekly brief')
        assert '## Summary' in text
        assert '## Kind frequency' in text

    def test_notify_test_success_and_missing_param(self, fresh_state,
                                                   notify_probe):
        result = scheduler.run_task(
            {'name': 'probe', 'action': 'notify_test',
             'params': {'channel': 'team-chat'}})
        assert result['ok'] is True
        assert notify_probe == ['team-chat']
        assert "test notification delivered to 'team-chat'" \
            in result['summary']
        missing = scheduler.run_task(
            {'name': 'probe', 'action': 'notify_test', 'params': {}})
        assert missing['ok'] is False
        assert 'needs a channel param' in missing['error']

    def test_unknown_action_returns_not_ok(self, fresh_state):
        result = scheduler.run_task(
            TaskSpec(name='boom', action='explode'))
        assert result['ok'] is False
        assert 'unknown task action' in result['error']
        assert result['summary'] == ''

    def test_executor_exception_never_propagates(self, fresh_state,
                                                 monkeypatch):
        from obscuralens.pipelines import engine

        def broken_run_pipeline(spec, variables=None, trackers=None):
            raise RuntimeError('boom')

        monkeypatch.setattr(engine, 'run_pipeline', broken_run_pipeline)
        result = scheduler.run_task(
            {'name': 'pipe', 'action': 'pipeline', 'params': {'spec': {}}})
        assert result['ok'] is False
        assert 'RuntimeError' in result['error']
        assert 'boom' in result['error']

    def test_run_task_by_name_and_unknown_name(self, fresh_state,
                                               notify_probe):
        _add(name='by-name', params={'channel': 'hook'})
        result = scheduler.run_task('BY-NAME')
        assert result['ok'] is True
        assert notify_probe == ['hook']
        unknown = scheduler.run_task('ghost-task')
        assert unknown['ok'] is False
        assert "task 'ghost-task' not found" in unknown['error']
        empty = scheduler.run_task({})
        assert empty['ok'] is False
        assert 'task spec needs a name' in empty['error']

    def test_result_timestamps_and_shape(self, fresh_state, notify_probe):
        _add(name='probe', params={'channel': 'hook'})
        result = scheduler.run_task('probe')
        assert set(result) == {'ok', 'started', 'finished', 'error',
                               'summary'}
        datetime.fromisoformat(result['started'])
        datetime.fromisoformat(result['finished'])
        # run_task never touches the persisted bookkeeping.
        task = scheduler.get_task('probe')
        assert task['run_count'] == 0
        assert task['last_run'] is None


# --------------------------------------------------------------------------- #
# run_due (bookkeeping)
# --------------------------------------------------------------------------- #

class TestRunDue:

    def test_bookkeeping_updated_on_success(self, fresh_state, notify_probe):
        _add(name='daily-probe', interval_seconds=60,
             params={'channel': 'hook'})
        # A future due-check moment: the task's stored next_run (computed
        # from the real now at add time) has arrived by then.
        moment = datetime.now() + timedelta(hours=1)
        results = scheduler.run_due(moment)
        assert len(results) == 1
        assert results[0]['task'] == 'daily-probe'
        assert results[0]['action'] == 'notify_test'
        assert results[0]['ok'] is True
        task = scheduler.get_task('daily-probe')
        assert task['run_count'] == 1
        assert task['error_count'] == 0
        assert task['last_error'] == ''
        datetime.fromisoformat(task['last_run'])
        # next_run is anchored to the due-check moment, not wall-clock.
        assert task['next_run'] == _iso(moment + timedelta(seconds=60))

    def test_error_bookkeeping_accumulates(self, fresh_state):
        _add(name='broken-probe', interval_seconds=60)  # no channel param
        soon = datetime.now() + timedelta(hours=1)
        first = scheduler.run_due(soon)
        assert first[0]['ok'] is False
        task = scheduler.get_task('broken-probe')
        assert task['error_count'] == 1
        assert 'channel' in task['last_error']
        # A second due run (past the recomputed next_run) accumulates.
        scheduler.run_due(datetime.now() + timedelta(hours=2))
        task = scheduler.get_task('broken-probe')
        assert task['error_count'] == 2
        assert task['run_count'] == 2

    def test_not_due_task_is_not_run(self, fresh_state, notify_probe):
        _add(name='idle', interval_seconds=3600, params={'channel': 'hook'})
        past = datetime.now() - timedelta(hours=2)
        assert scheduler.run_due(past) == []
        assert notify_probe == []
        task = scheduler.get_task('idle')
        assert task['run_count'] == 0

    def test_multiple_due_tasks_all_run(self, fresh_state, notify_probe):
        _add(name='one', interval_seconds=60, params={'channel': 'hook'})
        _add(name='two', interval_seconds=60, params={'channel': 'hook'})
        results = scheduler.run_due(datetime.now() + timedelta(hours=1))
        assert [result['task'] for result in results] == ['one', 'two']
        assert notify_probe == ['hook', 'hook']


# --------------------------------------------------------------------------- #
# tick_loop / background thread
# --------------------------------------------------------------------------- #

class TestTickLoop:

    def test_preset_stop_event_exits_without_running(self, monkeypatch):
        calls = []
        monkeypatch.setattr(scheduler, 'run_due',
                            lambda now=None: calls.append(now) or [])
        stop_event = threading.Event()
        stop_event.set()
        scheduler.tick_loop(stop_event, interval=0.01)
        assert calls == []  # never woke up to run anything

    def test_runs_once_then_stops_cleanly(self, monkeypatch):
        calls = []
        monkeypatch.setattr(scheduler, 'run_due',
                            lambda now=None: calls.append(now) or [])
        stop_event = threading.Event()
        worker = threading.Thread(target=scheduler.tick_loop,
                                  args=(stop_event, 0.01))
        worker.start()
        for _ in range(200):  # wait for the immediate first iteration
            if calls:
                break
            stop_event.wait(0.01)
        stop_event.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert len(calls) >= 1


class TestStartBackground:

    def test_start_returns_daemon_thread(self, fresh_state):
        try:
            thread = scheduler.start_background(0.5)
            assert isinstance(thread, threading.Thread)
            assert thread.daemon is True
            assert thread.name == 'obscuralens-scheduler'
            assert thread.is_alive()
        finally:
            assert scheduler.stop_background() is True
            assert not thread.is_alive()
        # stopping with nothing running is a safe no-op returning True
        assert scheduler.stop_background() is True

    def test_idempotent_second_call_returns_same_thread(self, fresh_state):
        try:
            first = scheduler.start_background(0.5)
            second = scheduler.start_background(0.5)
            assert second is first
            assert first.is_alive()
        finally:
            scheduler.stop_background()

    def test_restart_after_stop(self, fresh_state):
        first = scheduler.start_background(0.5)
        scheduler.stop_background()
        assert not first.is_alive()
        try:
            second = scheduler.start_background(0.5)
            assert second is not first
            assert second.is_alive()
        finally:
            scheduler.stop_background()


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

class TestSchedulerCli:

    def test_tasks_empty_table(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(['automation', 'tasks']) == 0
        out = capsys.readouterr().out
        assert 'No tasks yet' in out

    def test_tasks_json_lists_tasks(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='cli-task', action='report', schedule='daily',
             at_time='07:15')
        assert commands.run(['automation', 'tasks', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['count'] == 1
        assert payload['tasks'][0]['name'] == 'cli-task'
        assert payload['tasks'][0]['schedule'] == 'daily'
        assert 'watch_check' in payload['actions']

    def test_add_daily_via_cli(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(
            ['automation', 'add', '--name', 'daily-watch',
             '--action', 'watch_check', '--daily', '--at', '09:00']) == 0
        task = scheduler.get_task('daily-watch')
        assert task['schedule'] == 'daily'
        assert task['at_time'] == '09:00'
        assert task['enabled'] is True

    def test_add_interval_with_params_via_cli(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(
            ['automation', 'add', '--name', 'hourly-probe',
             '--action', 'notify_test', '--interval', '3600',
             '--params', '{"channel": "team-chat"}']) == 0
        task = scheduler.get_task('hourly-probe')
        assert task['schedule'] == 'interval'
        assert task['interval_seconds'] == 3600
        assert task['params'] == {'channel': 'team-chat'}

    def test_add_rejects_duplicate_and_bad_json(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='dup')
        assert commands.run(
            ['automation', 'add', '--name', 'dup', '--action',
             'report']) == 1
        assert 'already exists' in capsys.readouterr().err
        assert commands.run(
            ['automation', 'add', '--name', 'bad-json', '--action',
             'report', '--params', 'not-json']) == 2
        assert 'JSON' in capsys.readouterr().err

    def test_remove_via_cli(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='cli-remove')
        assert commands.run(['automation', 'remove', 'cli-remove']) == 0
        assert scheduler.list_tasks() == []
        assert commands.run(['automation', 'remove', 'ghost']) == 1
        assert 'not found' in capsys.readouterr().err

    def test_run_via_cli_json(self, fresh_state, notify_probe, capsys):
        from obscuralens import commands
        _add(name='cli-run', params={'channel': 'hook'})
        assert commands.run(
            ['automation', 'run', 'cli-run', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['ok'] is True
        assert payload['summary']
        assert notify_probe == ['hook']

    def test_run_via_cli_unknown_returns_1(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(['automation', 'run', 'ghost']) == 1

    def test_run_due_via_cli_empty(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(['automation', 'run-due']) == 0
        assert 'Nothing was due' in capsys.readouterr().out

    def test_next_via_cli_json(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='cli-next', interval_seconds=120)
        assert commands.run(['automation', 'next', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['count'] == 1
        entry = payload['tasks'][0]
        assert entry['name'] == 'cli-next'
        assert entry['stored_next_run']
        assert entry['recomputed_next_run']

    def test_automation_without_action_returns_2(self, capsys):
        from obscuralens import commands
        assert commands.run(['automation']) == 2
        assert 'usage' in capsys.readouterr().err
