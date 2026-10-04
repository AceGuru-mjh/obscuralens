"""
Pure-stdlib task scheduler (v6.0 Part 4).

OSINT is a waiting game: a watchlist target changes at 3am, a threat
feed rotates hourly, a case report is due every Monday. This module
gives the platform a cron-shaped brain without a single new dependency
- :mod:`threading`, :mod:`datetime` and a JSON state file, exactly the
persistence pattern proven by :mod:`obscuralens.advanced.alerts`.

**Timezone contract: every timestamp in this module is local wall-clock
time** (``datetime.now()`` / ``time.localtime``), matching how a human
reads a cron line. ``at_time`` means "09:00 where the analyst sits".

Task lifecycle (persisted in ``scheduler.json`` beside the SQLite
database):

* :func:`add_task` / :func:`remove_task` / :func:`list_tasks` /
  :func:`get_task` - CRUD over named tasks; names are unique.
* :func:`compute_next_run` - pure function: when a task should next run
  (``interval`` → ``now + N seconds``; ``daily`` → the next ``HH:MM``;
  ``weekly`` → the next ``weekday`` at ``HH:MM``; today's slot already
  passed means tomorrow / next week).
* :func:`due_tasks` - which tasks are due at a given moment.
* :func:`run_task` - dispatch one task to its executor (every executor
  is individually try/except-wrapped: a broken pipe never poisons the
  loop) and return ``{'ok', 'started', 'finished', 'error',
  'summary'}``.
* :func:`run_due` - run everything due, then persist ``last_run`` /
  ``run_count`` / ``error_count`` / ``last_error`` / ``next_run``.
* :func:`tick_loop` / :func:`start_background` /
  :func:`stop_background` - the daemon wiring for ``obscuralens
  automation start``: a background thread that wakes every ``interval``
  seconds and calls :func:`run_due`.

Five executor actions ship today:

* ``watch_check`` - re-check every watchlist entry (or one target) via
  :mod:`obscuralens.watchlist` and count the diffs.
* ``pipeline`` - execute a YAML pipeline through
  :func:`obscuralens.pipelines.engine.run_pipeline` (by path, by name
  inside the configured pipeline directory, or by inline ``spec``).
* ``report`` - render a markdown dossier from the query history into
  the configured ``reports`` directory.
* ``feed_refresh`` - force-refresh every threat-intel blocklist feed in
  :mod:`obscuralens.intel.feeds`.
* ``notify_test`` - probe one notification channel through
  :mod:`obscuralens.automation.notifications`.
"""

import contextlib
import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

__all__ = [
    'DEFAULT_TICK_INTERVAL',
    'SCHEDULE_TYPES',
    'TASK_ACTIONS',
    'WEEKDAY_NAMES',
    'TaskSpec',
    'add_task',
    'compute_next_run',
    'due_tasks',
    'get_task',
    'list_tasks',
    'remove_task',
    'run_due',
    'run_task',
    'start_background',
    'stop_background',
    'tick_loop',
]

#: Executor actions a task can dispatch to.
TASK_ACTIONS: Tuple[str, ...] = (
    'watch_check',   # re-run watchlist checks
    'pipeline',      # execute a YAML pipeline
    'report',        # write a markdown history report
    'feed_refresh',  # force-refresh intel blocklist feeds
    'notify_test',   # probe a notification channel
)

#: Supported schedule shapes.
SCHEDULE_TYPES: Tuple[str, ...] = ('interval', 'daily', 'weekly')

#: Weekday labels for validation errors (Monday = 0, matching
#: :meth:`datetime.date.weekday`).
WEEKDAY_NAMES: Tuple[str, ...] = (
    'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
    'Saturday', 'Sunday',
)

#: Default wake-up period of the background tick loop, in seconds.
DEFAULT_TICK_INTERVAL = 30.0

#: Filename of the persisted state, placed beside the SQLite database.
_STATE_FILENAME = 'scheduler.json'

#: Serialises every read/modify/write of the state file.
_LOCK = threading.Lock()

#: Guards creation/teardown of the background thread.
_THREAD_LOCK = threading.Lock()

#: The background tick thread (None until :func:`start_background`).
_THREAD: Optional[threading.Thread] = None

#: Stop event owned by the background tick thread.
_STOP_EVENT: Optional[threading.Event] = None


# ---------------------------------------------------------------------------
# Task value object
# ---------------------------------------------------------------------------

@dataclass
class TaskSpec:
    """
    One scheduled task.

    Attributes:
        name: unique human label ('nightly-watch', 'monday-report'...).
        action: one of :data:`TASK_ACTIONS`.
        params: executor payload - e.g. ``{'target': '8.8.8.8'}`` for a
            watch check, ``{'path': 'pipelines/daily.yaml'}`` for a
            pipeline run, ``{'channel': 'team-chat'}`` for a
            notification probe.
        schedule: ``'interval'`` (every ``interval_seconds``),
            ``'daily'`` (at ``at_time`` every day) or ``'weekly'`` (at
            ``at_time`` on ``weekday``).
        interval_seconds: period for the ``interval`` schedule.
        at_time: ``'HH:MM'`` local time for daily/weekly schedules.
        weekday: 0 = Monday ... 6 = Sunday (weekly schedule).
        enabled: master switch - disabled tasks are never due.
        last_run: ISO local timestamp of the last execution.
        next_run: ISO local timestamp of the next scheduled run.
        run_count: how many times the task has executed.
        error_count: how many executions failed.
        last_error: the most recent failure reason ('' when healthy).
    """

    name: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    schedule: str = 'interval'
    interval_seconds: int = 3600
    at_time: str = '09:00'
    weekday: int = 0
    enabled: bool = True
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    run_count: int = 0
    error_count: int = 0
    last_error: str = ''


def _as_datetime(moment: Any) -> datetime:
    """
    Coerce a ``now`` argument into a naive local datetime.

    ``None`` means "right now"; strings go through
    :meth:`datetime.datetime.fromisoformat`; aware datetimes are
    converted to local wall-clock and stripped of tzinfo so every
    comparison in this module happens in one timezone - the analyst's.
    Unparseable input falls back to the current time (never raises).
    """
    if moment is None:
        return datetime.now()
    if isinstance(moment, datetime):
        if moment.tzinfo is not None:
            return moment.astimezone().replace(tzinfo=None)
        return moment
    try:
        parsed = datetime.fromisoformat(str(moment))
    except (TypeError, ValueError):
        return datetime.now()
    if parsed.tzinfo is not None:
        return parsed.astimezone().replace(tzinfo=None)
    return parsed


def _now_iso() -> str:
    """Current **local** time as a second-resolution ISO string."""
    return datetime.now().isoformat(timespec='seconds')


def _parse_at_time(raw: Any) -> Optional[Tuple[int, int]]:
    """
    Parse an ``'HH:MM'`` (or ``'HH:MM:SS'`` / ``H`` int) clock time.

    Returns:
        ``(hour, minute)`` or ``None`` when the value is not a valid
        local clock time.
    """
    if isinstance(raw, int) and not isinstance(raw, bool):
        return (raw, 0) if 0 <= raw <= 23 else None
    text = str(raw or '').strip()
    if not text:
        return None
    parts = text.split(':')
    if len(parts) > 3 or not parts[0].isdigit():
        return None
    try:
        hour = int(parts[0])
        minute = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        second = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    except ValueError:  # pragma: no cover - isdigit guards above
        return None
    if 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59:
        return (hour, minute)
    return None


def _coerce_task(spec: Any) -> TaskSpec:
    """
    Best-effort :class:`TaskSpec` from a dict / TaskSpec / anything.

    Unknown fields fall back to the dataclass defaults; this never
    raises because it is also the repair path for corrupt state files.
    """
    if isinstance(spec, TaskSpec):
        return spec
    data = spec if isinstance(spec, dict) else {}
    schedule = str(data.get('schedule') or 'interval').strip().lower()
    if schedule not in SCHEDULE_TYPES:
        schedule = 'interval'
    clock = _parse_at_time(data.get('at_time')) or (9, 0)
    try:
        interval_seconds = max(1, int(data.get('interval_seconds', 3600)))
    except (TypeError, ValueError):
        interval_seconds = 3600
    try:
        weekday = int(data.get('weekday') or 0) % 7
    except (TypeError, ValueError):
        weekday = 0
    params = data.get('params')
    if not isinstance(params, dict):
        params = {}
    return TaskSpec(
        name=str(data.get('name') or ''),
        action=str(data.get('action') or '').strip().lower(),
        params=params,
        schedule=schedule,
        interval_seconds=interval_seconds,
        at_time=f'{clock[0]:02d}:{clock[1]:02d}',
        weekday=weekday,
        enabled=bool(data.get('enabled', True)),
        last_run=(str(data.get('last_run'))
                  if data.get('last_run') is not None else None),
        next_run=(str(data.get('next_run'))
                  if data.get('next_run') is not None else None),
        run_count=int(data.get('run_count') or 0),
        error_count=int(data.get('error_count') or 0),
        last_error=str(data.get('last_error') or ''),
    )


# ---------------------------------------------------------------------------
# Scheduling maths (pure functions, unit-testable)
# ---------------------------------------------------------------------------

def compute_next_run(spec: Union[TaskSpec, Dict[str, Any]],
                     now: Any = None) -> str:
    """
    When should this task next run, as a local ISO timestamp.

    Pure function - no state, no clock when ``now`` is given:

    * ``interval`` → ``now + interval_seconds``.
    * ``daily`` → the next occurrence of ``at_time``; when today's slot
      has already passed (or is exactly now), tomorrow's.
    * ``weekly`` → the next occurrence of ``weekday`` at ``at_time``
      (today counts only when the slot is still in the future).

    Args:
        spec: a :class:`TaskSpec` or its dict form.
        now: ``None`` (current local time), a ``datetime`` or an ISO
            string; aware values are converted to local wall-clock.

    Returns:
        ``'YYYY-MM-DDTHH:MM:SS'`` local-time ISO string.
    """
    task = _coerce_task(spec)
    moment = _as_datetime(now)
    if task.schedule == 'interval':
        return (moment + timedelta(seconds=task.interval_seconds)
                ).isoformat(timespec='seconds')
    hour, minute = _parse_at_time(task.at_time) or (9, 0)
    candidate = moment.replace(hour=hour, minute=minute, second=0,
                               microsecond=0)
    if task.schedule == 'weekly':
        days_ahead = (task.weekday - moment.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= moment:
            candidate += timedelta(days=7)
        return candidate.isoformat(timespec='seconds')
    # daily
    if candidate <= moment:
        candidate += timedelta(days=1)
    return candidate.isoformat(timespec='seconds')


def _task_is_due(task: TaskSpec, moment: datetime) -> bool:
    """Whether ``task``'s stored ``next_run`` has arrived by ``moment``."""
    if not task.enabled or not task.next_run:
        return False
    try:
        due_at = datetime.fromisoformat(str(task.next_run))
    except (TypeError, ValueError):
        return False
    if due_at.tzinfo is not None:  # foreign-timezone state self-heals
        due_at = due_at.astimezone().replace(tzinfo=None)
    return due_at <= moment


def due_tasks(now: Any = None) -> List[TaskSpec]:
    """
    Every enabled task whose ``next_run`` has arrived.

    Args:
        now: ``None`` (current local time), a ``datetime`` or an ISO
            string; aware values are converted to local wall-clock.

    Returns:
        TaskSpec list in stored order; a task with a missing or
        unparseable ``next_run`` is never due (use :func:`add_task` or
        :func:`run_task` to repair it).
    """
    moment = _as_datetime(now)
    with _LOCK:
        state = _load()
    return [task for task in (_coerce_task(item) for item in state['tasks'])
            if task.name and _task_is_due(task, moment)]


# ---------------------------------------------------------------------------
# Persistence (pattern copied from advanced/alerts.py)
# ---------------------------------------------------------------------------

def _state_path() -> Path:
    """
    Location of the persisted scheduler state (``scheduler.json``).

    The file lives next to the SQLite database configured in
    ``config.db_config.sqlite_path`` so all local state shares one data
    directory; when that path is unusable the plain ``data`` directory
    is the fallback. The directory itself is created on first write.
    """
    raw = ''
    with contextlib.suppress(Exception):
        from ..config import config  # lazy: configuration on first use
        raw = str(config.db_config.sqlite_path or '')
    if raw:
        return Path(raw).expanduser().parent / _STATE_FILENAME
    return Path('data') / _STATE_FILENAME


def _default_state() -> Dict[str, Any]:
    """The state used when no ``scheduler.json`` exists yet: no tasks."""
    return {'tasks': []}


def _load() -> Dict[str, Any]:
    """
    Read the state file, falling back to defaults on any problem.

    Lock-free primitive: callers hold :data:`_LOCK`. Tasks with an
    unparseable ``next_run`` are self-healed by recomputing it from the
    task's schedule, so hand-edited or corrupt state degrades into a
    working schedule instead of a silently-dead task.
    """
    try:
        raw = _state_path().read_text(encoding='utf-8')
        data = json.loads(raw)
    except (OSError, ValueError):
        return _default_state()
    if not isinstance(data, dict):
        return _default_state()
    state = _default_state()
    tasks = data.get('tasks')
    if isinstance(tasks, list):
        for item in tasks:
            if not isinstance(item, dict):
                continue
            task = _coerce_task(item)
            if not task.name:
                continue
            try:
                datetime.fromisoformat(str(task.next_run))
            except (TypeError, ValueError):
                item = {**item, 'next_run': compute_next_run(task)}
            state['tasks'].append(item)
    return state


def _save(state: Dict[str, Any]) -> None:
    """
    Persist the state file atomically (write to a temp name, then replace).

    Lock-free primitive: callers hold :data:`_LOCK`. A failed write is
    swallowed - a read-only data directory must never break a run.
    """
    path = _state_path()
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2),
                       encoding='utf-8')
        tmp.replace(path)


# ---------------------------------------------------------------------------
# Task CRUD
# ---------------------------------------------------------------------------

def add_task(task: Union[Dict[str, Any], TaskSpec]) -> Dict[str, Any]:
    """
    Register a new scheduled task.

    Args:
        task: mapping with ``name``/``action`` plus optional ``params``,
            ``schedule``, ``interval_seconds``, ``at_time``, ``weekday``
            and ``enabled`` - or a ready :class:`TaskSpec`.

    Returns:
        ``{'ok': True, 'error': '', 'task': {...}}`` or
        ``{'ok': False, 'error': reason, 'task': None}`` when the spec
        is invalid or the name already exists. The stored task carries
        a freshly computed ``next_run``.
    """
    if isinstance(task, TaskSpec):
        data = asdict(task)
        data['params'] = dict(task.params)
    else:
        data = task if isinstance(task, dict) else {}
    name = str(data.get('name') or '').strip()
    if not name:
        return {'ok': False, 'error': 'task name is required', 'task': None}
    if len(name) > 80:
        return {'ok': False, 'error': 'task name too long (max 80 chars)',
                'task': None}
    action = str(data.get('action') or '').strip().lower()
    if action not in TASK_ACTIONS:
        return {'ok': False,
                'error': (f"unknown task action {action!r} "
                          f"(expected one of {', '.join(TASK_ACTIONS)})"),
                'task': None}
    schedule = str(data.get('schedule') or 'interval').strip().lower()
    if schedule not in SCHEDULE_TYPES:
        return {'ok': False,
                'error': (f"unknown schedule {schedule!r} "
                          f"(expected one of {', '.join(SCHEDULE_TYPES)})"),
                'task': None}
    try:
        interval_seconds = int(data.get('interval_seconds', 3600))
    except (TypeError, ValueError):
        interval_seconds = 3600
    if schedule == 'interval' and interval_seconds < 1:
        return {'ok': False,
                'error': 'interval_seconds must be >= 1', 'task': None}
    at_time = str(data.get('at_time') or '09:00').strip()
    if schedule in ('daily', 'weekly') and _parse_at_time(at_time) is None:
        return {'ok': False,
                'error': f"at_time must be 'HH:MM' (got {at_time!r})",
                'task': None}
    try:
        weekday = int(data.get('weekday') or 0)
    except (TypeError, ValueError):
        weekday = 0
    if schedule == 'weekly' and not 0 <= weekday <= 6:
        return {'ok': False,
                'error': (f"weekday must be 0 ({WEEKDAY_NAMES[0]}) to 6 "
                          f"({WEEKDAY_NAMES[6]})"), 'task': None}
    params = data.get('params')
    if params is not None and not isinstance(params, dict):
        return {'ok': False, 'error': 'params must be a mapping', 'task': None}
    spec = TaskSpec(
        name=name,
        action=action,
        params=dict(params or {}),
        schedule=schedule,
        interval_seconds=max(1, interval_seconds),
        at_time=at_time,
        weekday=weekday,
        enabled=bool(data.get('enabled', True)),
    )
    stored = asdict(spec)
    stored['params'] = dict(spec.params)
    stored['next_run'] = compute_next_run(spec)
    with _LOCK:
        state = _load()
        existing = {str(item.get('name') or '') for item in state['tasks']}
        if name in existing:
            return {'ok': False,
                    'error': f"task '{name}' already exists", 'task': None}
        state['tasks'].append(stored)
        _save(state)
    return {'ok': True, 'error': '', 'task': stored}


def remove_task(name: str) -> Dict[str, Any]:
    """
    Delete one scheduled task.

    Returns:
        ``{'ok', 'error', 'removed'}`` where ``removed`` is the task
        name on success or ``''`` when nothing matched.
    """
    wanted = str(name or '').strip().lower()
    with _LOCK:
        state = _load()
        kept = [item for item in state['tasks']
                if str(item.get('name') or '').strip().lower() != wanted]
        if len(kept) == len(state['tasks']):
            return {'ok': False, 'error': f"task '{name}' not found",
                    'removed': ''}
        state['tasks'] = kept
        _save(state)
    return {'ok': True, 'error': '', 'removed': wanted}


def list_tasks() -> List[Dict[str, Any]]:
    """
    Every scheduled task as a JSON-ready dict (asdict of TaskSpec).

    Includes the bookkeeping fields ``last_run`` / ``next_run`` /
    ``run_count`` / ``error_count`` / ``last_error`` so a UI can render
    the full health picture without a second call.
    """
    with _LOCK:
        state = _load()
    tasks: List[Dict[str, Any]] = []
    for item in state['tasks']:
        task = _coerce_task(item)
        if not task.name:
            continue
        stored = asdict(task)
        stored['params'] = dict(task.params)
        tasks.append(stored)
    return tasks


def get_task(name: str) -> Optional[Dict[str, Any]]:
    """
    One task by name (case-insensitive), or ``None``.

    Returns:
        The same dict shape as :func:`list_tasks` entries.
    """
    wanted = str(name or '').strip().lower()
    for item in list_tasks():
        if str(item.get('name') or '').strip().lower() == wanted:
            return item
    return None


# ---------------------------------------------------------------------------
# Executors (each one defensive: returns (summary, error))
# ---------------------------------------------------------------------------

def _watch_summary(diff: Any) -> str:
    """One-line description of a watch diff (attribute or mapping)."""
    target = getattr(diff, 'target', None)
    if target is None and isinstance(diff, dict):
        target = diff.get('target')
    kind = getattr(diff, 'kind', None) or (
        diff.get('kind') if isinstance(diff, dict) else '') or '?'
    added = getattr(diff, 'added', None)
    removed = getattr(diff, 'removed', None)
    changed = getattr(diff, 'changed', None)
    if added is None and isinstance(diff, dict):
        added, removed, changed = (diff.get('added'), diff.get('removed'),
                                   diff.get('changed'))
    shifts = sum(1 for bucket in (added, removed, changed) if bucket)
    return f"{kind} {target} ({shifts} change bucket(s))"


def _execute_watch_check(task: TaskSpec) -> Tuple[str, str]:
    """
    Re-run watchlist checks through :class:`WatchlistManager.check`.

    ``params``: optional ``target``/``identifier`` (one watch by id or
    target; omitted means every watch). The summary counts first
    snapshots, real diffs and failures.
    """
    from ..watchlist import watchlist
    identifier = task.params.get('target') or task.params.get('identifier')
    diffs = watchlist.check(identifier if identifier else None)
    if not diffs:
        return 'watchlist is empty (nothing to check)', ''
    firsts = [d for d in diffs if getattr(d, 'is_first', False)]
    failed = [d for d in diffs if not getattr(d, 'success', True)]
    changed = [d for d in diffs
               if not getattr(d, 'is_first', False)
               and (getattr(d, 'added', None) or getattr(d, 'removed', None)
                    or getattr(d, 'changed', None))]
    summary = (f'{len(diffs)} watch(es) checked: {len(firsts)} first '
               f'snapshot(s), {len(changed)} changed, {len(failed)} failed')
    if changed:
        summary += '; ' + '; '.join(_watch_summary(d) for d in changed[:5])
    return summary, ''


def _find_pipeline_file(raw: str) -> Optional[Path]:
    """Resolve a pipeline by name inside the configured directory."""
    from ..config import config
    folder = Path(str(config.app_config.pipeline_dir or 'pipelines'))
    for candidate in (folder / raw, folder / f'{raw}.yaml',
                      folder / f'{raw}.yml'):
        with contextlib.suppress(OSError):
            if candidate.is_file():
                return candidate
    return None


def _pipeline_summary(report: Dict[str, Any]) -> str:
    """Compact one-liner for a pipeline run report."""
    name = report.get('name') or '(unnamed)'
    steps = len(report.get('steps') or [])
    errors = len(report.get('errors') or [])
    findings = len(report.get('findings') or [])
    return (f"pipeline '{name}': {steps} step(s), {findings} finding(s), "
            f"{errors} error(s)")


def _execute_pipeline(task: TaskSpec) -> Tuple[str, str]:
    """
    Execute a pipeline through ``run_pipeline``.

    ``params``: ``spec`` (inline pipeline mapping), or ``path``/``name``
    (file path, or a name resolved inside ``app.pipeline_dir`` with the
    ``.yaml``/``.yml`` extensions tried).
    """
    from ..pipelines.engine import run_pipeline
    inline = task.params.get('spec')
    if isinstance(inline, dict):
        return _pipeline_summary(run_pipeline(inline)), ''
    raw = str(task.params.get('path') or task.params.get('pipeline')
              or task.params.get('name') or '').strip()
    if not raw:
        return '', 'pipeline task needs a path, name or spec param'
    candidate = Path(raw)
    if not candidate.is_file():
        found = _find_pipeline_file(raw)
        if found is None:
            return '', f"pipeline '{raw}' not found"
        candidate = found
    return _pipeline_summary(run_pipeline(candidate)), ''


def _row_field(row: Any, name: str, default: Any = '') -> Any:
    """Read one field from a dataclass row or a mapping (never raises)."""
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)


def _history_markdown(rows: List[Any], title: str) -> str:
    """
    Render the query history as a markdown dossier (pure function).

    The report carries a summary block (total/success rate), a kind
    frequency table and a recent-lookups table; values are escaped so
    hostile target strings cannot break the table layout.
    """
    now = _now_iso()
    total = len(rows)
    successes = sum(1 for row in rows if bool(_row_field(row, 'success')))
    rate = f'{(100.0 * successes / total):.1f}%' if total else 'n/a'
    frequency: Dict[str, int] = {}
    for row in rows:
        kind = str(_row_field(row, 'query_type') or '?')
        frequency[kind] = frequency.get(kind, 0) + 1
    lines = [
        f'# {title}',
        '',
        f'Generated: {now} (local time)',
        '',
        '## Summary',
        '',
        f'- Lookups in window: {total}',
        f'- Successful: {successes} ({rate})',
        f'- Kinds seen: {len(frequency)}',
        '',
        '## Kind frequency',
        '',
        '| Kind | Lookups |',
        '| --- | --- |',
    ]
    for kind, count in sorted(frequency.items(), key=lambda kv: -kv[1]):
        lines.append(f'| {kind.replace("|", "/")} | {count} |')
    lines += ['', '## Recent lookups', '',
              '| Kind | Target | OK | Recorded |',
              '| --- | --- | --- | --- |']
    for row in rows[:50]:
        kind = str(_row_field(row, 'query_type') or '?').replace('|', '/')
        target = str(_row_field(row, 'query_value') or '')[:60].replace('|', '/')
        ok = 'yes' if _row_field(row, 'success') else 'no'
        recorded = str(_row_field(row, 'created_at') or '')[:19]
        lines.append(f'| {kind} | {target} | {ok} | {recorded} |')
    lines.append('')
    return '\n'.join(lines)


def _execute_report(task: TaskSpec) -> Tuple[str, str]:
    """
    Write a markdown dossier of the query history into ``reports``/.

    ``params``: optional ``limit`` (history rows, default 100, capped at
    1000) and ``title``. The filename embeds the task name and a local
    timestamp: ``scheduled-<task>-<YYYYmmdd-HHMMSS>.md``.
    """
    from ..config import config
    from ..database import db
    try:
        limit = max(1, min(1000, int(task.params.get('limit') or 100)))
    except (TypeError, ValueError):
        limit = 100
    rows = db.get_history(limit=limit)
    title = str(task.params.get('title')
                or f'ObscuraLens scheduled report: {task.name}')
    markdown = _history_markdown(rows, title)
    report_dir = Path(str(config.app_config.report_dir or 'reports'))
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    safe_name = ''.join(ch if ch.isalnum() or ch in '-_' else '-'
                        for ch in task.name) or 'task'
    path = report_dir / f'scheduled-{safe_name}-{stamp}.md'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding='utf-8')
    return (f'report written: {path} ({len(rows)} lookup(s), '
            f'{len(markdown)} chars)'), ''


def _execute_feed_refresh(task: TaskSpec) -> Tuple[str, str]:
    """
    Force-refresh the threat-intel blocklist feeds.

    ``params``: optional ``feeds`` list restricting the refresh to a
    subset of ``feeds.FEED_URLS`` (unknown names are dropped). Uses the
    module's cache loader with ``force=True``; the summary reports the
    cached network totals afterwards.
    """
    from ..intel import feeds
    known = getattr(feeds, 'FEED_URLS', {})
    if not isinstance(known, dict) or not known:
        return '', 'no blocklist feeds configured'
    requested = task.params.get('feeds')
    if isinstance(requested, str):
        requested = [chunk.strip() for chunk in requested.split(',')
                     if chunk.strip()]
    names = [str(name) for name in (requested or known)
             if str(name) in known]
    if not names:
        return '', 'no known feeds requested'
    loader = getattr(feeds, '_load_feed', None)
    if not callable(loader):
        return '', 'feed refresh API unavailable'
    for name in names:
        loader(name, force=True)
    status = feeds.feeds_status() if callable(getattr(feeds, 'feeds_status',
                                                      None)) else []
    entries = sum(int(item.get('entries') or 0)
                  for item in status if isinstance(item, dict))
    errors = sum(1 for item in status if isinstance(item, dict)
                 and item.get('error'))
    return (f'{len(names)} feed(s) refreshed; {entries} network(s) cached, '
            f'{errors} feed(s) in error'), ''


def _execute_notify_test(task: TaskSpec) -> Tuple[str, str]:
    """
    Probe one notification channel via ``notifications.test_channel``.

    ``params``: ``channel`` - the channel name to test.
    """
    from . import notifications
    channel = str(task.params.get('channel') or '').strip()
    if not channel:
        return '', 'notify_test task needs a channel param'
    result = notifications.test_channel(channel)
    if result.get('ok'):
        return f"test notification delivered to '{channel}'", ''
    return '', str(result.get('error') or 'test notification failed')


#: action -> executor (each returns ``(summary, error)`` and is
#: additionally wrapped by :func:`run_task`, so a raising executor is a
#: bug report, never a crashed scheduler).
_EXECUTORS: Dict[str, Callable[[TaskSpec], Tuple[str, str]]] = {
    'watch_check': _execute_watch_check,
    'pipeline': _execute_pipeline,
    'report': _execute_report,
    'feed_refresh': _execute_feed_refresh,
    'notify_test': _execute_notify_test,
}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _resolve_task(task: Union[str, Dict[str, Any], TaskSpec]
                  ) -> Tuple[Optional[TaskSpec], str]:
    """
    Coerce the ``task`` argument of :func:`run_task` into a value object.

    Accepts a :class:`TaskSpec`, a task mapping or a plain task name
    (looked up in the persisted state).
    """
    if isinstance(task, TaskSpec):
        return task, ''
    if isinstance(task, dict):
        coerced = _coerce_task(task)
        if not coerced.name:
            return None, 'task spec needs a name'
        return coerced, ''
    wanted = str(task or '').strip().lower()
    if not wanted:
        return None, 'task is required'
    for item in list_tasks():
        if str(item.get('name') or '').strip().lower() == wanted:
            return _coerce_task(item), ''
    return None, f"task '{task}' not found"


def run_task(task: Union[str, Dict[str, Any], TaskSpec]) -> Dict[str, Any]:
    """
    Execute one task now, regardless of its schedule.

    Every executor is individually wrapped: a broken watchlist, a
    missing pipeline file or a dead notification channel surfaces as
    ``error`` in the result, never as an exception into the caller (the
    CLI, the web layer or the background loop).

    Args:
        task: task name, full task mapping or :class:`TaskSpec`.

    Returns:
        ``{'ok': bool, 'started': iso, 'finished': iso, 'error': str,
        'summary': str}`` - timestamps are local time; ``summary`` is
        the executor's one-line human report. This call does **not**
        update the persisted schedule state (that is :func:`run_due`'s
        job, so manual runs cannot corrupt the cron bookkeeping).
    """
    started = _now_iso()
    resolved, error = _resolve_task(task)
    if resolved is None:
        return {'ok': False, 'started': started, 'finished': _now_iso(),
                'error': error, 'summary': ''}
    executor = _EXECUTORS.get(resolved.action)
    if executor is None:
        summary, error = '', (f"unknown task action {resolved.action!r} "
                              f"(expected one of {', '.join(TASK_ACTIONS)})")
    else:
        try:
            summary, error = executor(resolved)
        except Exception as exc:  # noqa: BLE001 - contract: never raise
            summary, error = '', f'{type(exc).__name__}: {exc}'
            logger.warning('scheduled task %s failed: %s', resolved.name, exc)
    return {'ok': not error, 'started': started, 'finished': _now_iso(),
            'error': str(error or ''), 'summary': str(summary or '')}


def run_due(now: Any = None) -> List[Dict[str, Any]]:
    """
    Run every due task and update the persisted schedule bookkeeping.

    For each due task the state gains ``last_run`` (the run's finish
    time), ``run_count`` +1, ``error_count`` +1 and ``last_error`` on
    failure, and a fresh ``next_run`` anchored to the due-check moment
    (so a fixed ``now`` argument yields deterministic schedules in
    tests, and slow tasks never skip a slot they have already earned).

    Args:
        now: ``None`` (current local time), a ``datetime`` or an ISO
            string; aware values are converted to local wall-clock.

    Returns:
        List of per-task results: ``{'task', 'action', 'ok', 'started',
        'finished', 'error', 'summary'}``.
    """
    moment = _as_datetime(now)
    results: List[Dict[str, Any]] = []
    for task in due_tasks(moment):
        outcome = run_task(task)
        with _LOCK:
            state = _load()
            for item in state['tasks']:
                if str(item.get('name') or '').strip().lower() \
                        != task.name.lower():
                    continue
                item['last_run'] = outcome['finished']
                try:
                    item['run_count'] = int(item.get('run_count') or 0) + 1
                except (TypeError, ValueError):
                    item['run_count'] = 1
                if outcome['ok']:
                    item['last_error'] = ''
                else:
                    try:
                        item['error_count'] = int(
                            item.get('error_count') or 0) + 1
                    except (TypeError, ValueError):
                        item['error_count'] = 1
                    item['last_error'] = outcome['error'][:400]
                item['next_run'] = compute_next_run(task, moment)
            _save(state)
        results.append({'task': task.name, 'action': task.action, **outcome})
    return results


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------

def tick_loop(stop_event: threading.Event,
              interval: float = DEFAULT_TICK_INTERVAL) -> None:
    """
    The daemon main loop: wake every ``interval`` seconds, run whatever
    is due, log the outcome, repeat until ``stop_event`` is set.

    One iteration runs immediately on entry (so ``obscuralens
    automation start`` catches up on overdue tasks at once), then the
    loop sleeps. The interval is clamped to at least half a second; any
    exception inside an iteration is logged and swallowed - the loop
    itself must outlive every task.

    Args:
        stop_event: cooperative shutdown signal (typically owned by
            :func:`start_background`).
        interval: wake-up period in seconds (default 30).
    """
    logger.info('scheduler tick loop started (interval=%.1fs)', interval)
    try:
        interval = max(0.5, float(interval))
    except (TypeError, ValueError):
        interval = DEFAULT_TICK_INTERVAL
    while not stop_event.is_set():
        try:
            for outcome in run_due():
                logger.info('scheduled task %s (%s): %s',
                            outcome.get('task'), outcome.get('action'),
                            outcome.get('summary') or outcome.get('error'))
        except Exception as exc:  # noqa: BLE001 - the loop must survive
            logger.warning('scheduler tick failed: %s', exc)
        if stop_event.wait(interval):
            break
    logger.info('scheduler tick loop stopped')


def start_background(interval: float = DEFAULT_TICK_INTERVAL
                     ) -> threading.Thread:
    """
    Start the scheduler daemon thread (idempotent).

    A second call while the thread is alive returns the existing thread
    unchanged - no duplicate loops, no doubled notifications. The thread
    is a daemon, so an interpreter exit never hangs on the scheduler.

    Args:
        interval: wake-up period in seconds (default 30).

    Returns:
        The live :class:`threading.Thread` (named
        ``obscuralens-scheduler``).
    """
    global _THREAD, _STOP_EVENT
    with _THREAD_LOCK:
        if _THREAD is not None and _THREAD.is_alive():
            return _THREAD
        _STOP_EVENT = threading.Event()
        thread = threading.Thread(
            target=tick_loop, args=(_STOP_EVENT, interval),
            name='obscuralens-scheduler', daemon=True)
        _THREAD = thread
        thread.start()
        return thread


def stop_background(timeout: float = 5.0) -> bool:
    """
    Signal the daemon thread to stop and wait briefly for it.

    Safe to call when nothing is running: a no-op returning True.

    Args:
        timeout: how long to wait for the thread to finish (seconds).

    Returns:
        ``True`` when no thread was running or it stopped within the
        timeout; ``False`` when it is still winding down (it is a
        daemon, so the interpreter can still exit cleanly).
    """
    global _THREAD, _STOP_EVENT
    with _THREAD_LOCK:
        event = _STOP_EVENT
        thread = _THREAD
        _STOP_EVENT = None
        _THREAD = None
    if event is not None:
        event.set()
    if thread is None:
        return True
    with contextlib.suppress(RuntimeError):  # join on a running thread
        thread.join(timeout=max(0.0, timeout))
    return not thread.is_alive()
