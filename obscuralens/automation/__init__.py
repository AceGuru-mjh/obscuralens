"""
ObscuraLens automation package (v6.0 Part 4).

Part 3 gave the platform eyes (live web views, SSE streams); this
package gives it hands. Two modules, both pure standard library:

* :mod:`obscuralens.automation.notifications` - the multi-channel
  notification centre: named channels (webhook / Telegram / Discord /
  Slack / SMTP) with event subscriptions, severity floors, local-time
  quiet hours and a 5-minute dedup window, all persisted in
  ``notifications.json`` beside the SQLite database and all delivered
  through the shared defensive HTTP client or :mod:`smtplib`.
* :mod:`obscuralens.automation.scheduler` - the cron-shaped task
  engine: interval/daily/weekly :class:`TaskSpec` schedules with a
  deterministic :func:`compute_next_run`, five wrapped executors
  (watchlist re-checks, YAML pipelines, markdown history reports,
  threat-feed refreshes, notification probes) and an idempotent daemon
  thread for ``obscuralens automation start``.

Both modules follow the house persistence pattern proven by
:mod:`obscuralens.advanced.alerts` (atomic JSON state file +
``threading.Lock``) and the house safety contract: nothing here ever
raises into a caller - every user-facing entry point returns
``{'ok': bool, 'error': str}``-shaped dicts, and a dead webhook, an
empty watchlist or a read-only data directory is recorded, not
propagated.

Import cost is deliberately tiny: the package imports only stdlib at
module level; trackers, pipelines, the database and the intel feeds are
pulled in lazily by the executors that need them.

Use :func:`automation_summary` for a machine-readable capability
inventory - handy for the web/MCP layers that want to advertise what
this build offers without importing every symbol.
"""

from typing import Any, Dict, List

from . import notifications, scheduler
from .notifications import (
    CHANNEL_TYPES,
    DEDUP_SECONDS,
    MAX_EVENT_LOG,
    SEVERITY_LEVELS,
    NotificationChannel,
    add_channel,
    broadcast,
    clear_log,
    format_event,
    get_channel,
    list_channels,
    notify_kind_event,
    recent,
    remove_channel,
    send,
    test_channel,
)
from .scheduler import (
    DEFAULT_TICK_INTERVAL,
    SCHEDULE_TYPES,
    TASK_ACTIONS,
    WEEKDAY_NAMES,
    TaskSpec,
    add_task,
    compute_next_run,
    due_tasks,
    get_task,
    list_tasks,
    remove_task,
    run_due,
    run_task,
    start_background,
    stop_background,
    tick_loop,
)

__all__ = [
    'CHANNEL_TYPES',
    'DEFAULT_TICK_INTERVAL',
    'DEDUP_SECONDS',
    'MAX_EVENT_LOG',
    'SCHEDULE_TYPES',
    'SEVERITY_LEVELS',
    'TASK_ACTIONS',
    'WEEKDAY_NAMES',
    'NotificationChannel',
    'TaskSpec',
    'add_channel',
    'add_task',
    'automation_summary',
    'broadcast',
    'clear_log',
    'compute_next_run',
    'due_tasks',
    'format_event',
    'get_channel',
    'get_task',
    'list_channels',
    'list_tasks',
    'notifications',
    'notify_kind_event',
    'recent',
    'remove_channel',
    'remove_task',
    'run_due',
    'run_task',
    'scheduler',
    'send',
    'start_background',
    'stop_background',
    'test_channel',
    'tick_loop',
]

#: Capability inventory: module name -> exported callables/classes.
_CAPABILITIES: Dict[str, List[str]] = {
    'notifications': [
        'NotificationChannel', 'add_channel', 'remove_channel',
        'list_channels', 'get_channel', 'send', 'broadcast',
        'test_channel', 'format_event', 'notify_kind_event', 'recent',
        'clear_log',
    ],
    'scheduler': [
        'TaskSpec', 'add_task', 'remove_task', 'list_tasks', 'get_task',
        'compute_next_run', 'due_tasks', 'run_task', 'run_due',
        'tick_loop', 'start_background', 'stop_background',
    ],
}


def automation_summary() -> Dict[str, Any]:
    """
    Machine-readable inventory of the automation package's capabilities.

    Intended for the web UI's capability banner, the MCP server's tool
    discovery and smoke tests: one call answers "what automation can
    this build do?" without importing or introspecting every module.

    Returns:
        Dict with keys:

        * ``'package'`` - dotted package name.
        * ``'modules'`` - mapping of module name to its exported
          callables/classes.
        * ``'module_count'`` / ``'function_count'`` - inventory tallies.
        * ``'channel_types'`` / ``'task_actions'`` / ``'schedule_types'``
          - the protocol vocabularies a UI can render pickers from.
        * ``'severities'`` - the notification severity ladder.
        * ``'stdlib_only'`` - always True (the zero-dependency
          guarantee).
        * ``'python_requires'`` - minimum supported interpreter.

    Example:
        >>> summary = automation_summary()
        >>> summary['module_count'], summary['stdlib_only']
        (2, True)
    """
    return {
        'package': 'obscuralens.automation',
        'modules': {name: list(entries)
                    for name, entries in _CAPABILITIES.items()},
        'module_count': len(_CAPABILITIES),
        'function_count': sum(len(entries)
                              for entries in _CAPABILITIES.values()),
        'channel_types': list(CHANNEL_TYPES),
        'task_actions': list(TASK_ACTIONS),
        'schedule_types': list(SCHEDULE_TYPES),
        'severities': list(SEVERITY_LEVELS),
        'dedup_seconds': DEDUP_SECONDS,
        'max_event_log': MAX_EVENT_LOG,
        'tick_interval_default': DEFAULT_TICK_INTERVAL,
        'stdlib_only': True,
        'python_requires': '3.9',
    }
