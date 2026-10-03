"""
Opt-in local notifications: webhook alerts plus an on-disk event log (v5.0).

Long-running OSINT sessions fail in boring ways: a source trips its
circuit breaker, a watched target changes, a batch row comes back
invalid. Nobody wants to babysit a terminal for that - but nobody wants
an OSINT tool phoning home either. This module is the compromise:

**Opt-in local notifications; webhook endpoints receive only what you
configure.** Nothing leaves the machine until an analyst explicitly
calls :func:`configure` with a webhook URL and an event whitelist. Until
then the module only writes a local event log - and that log is the
audit trail of every notification the system *would* have sent.

* :func:`configure` - set the webhook URL (empty string disables all
  delivery) and the event whitelist drawn from :data:`EVENT_TYPES`.
* :func:`get_config` - the current ``{'webhook_url', 'events',
  'enabled'}`` snapshot.
* :func:`notify` - record an event in the persistent ring buffer (last
  100 entries, ``data/alerts.json`` beside the SQLite database) and, when
  the event type is whitelisted and delivery is enabled, POST a compact
  JSON summary to the webhook. Delivery is strictly best-effort: a dead
  endpoint is recorded as ``'delivery': 'failed: <reason>'`` on the event
  entry and never raises into the caller's lookup flow.
* :func:`recent` / :func:`clear_events` - inspect and reset the local
  event log.
* :func:`test` - send a one-off test notification and report whether the
  webhook answered.
* :func:`summarize` - the human one-liner built from an event payload
  (target, kind, error, score...) that goes into the webhook ``text``
  field, so any chat platform that renders ``{"text": ...}`` works
  unmodified.

The POST payload shape (``text`` / ``event`` / ``payload`` / ``source``)
is deliberately Slack-compatible: point it at a channel webhook, a
Discord relay or your own collector and it just works.
"""

import contextlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    'EVENT_TYPES',
    'MAX_EVENT_LOG',
    'clear_events',
    'configure',
    'get_config',
    'notify',
    'recent',
    'summarize',
    'test',
]

#: Event types that can be whitelisted for webhook delivery.
EVENT_TYPES: Tuple[str, ...] = (
    'lookup_failed',   # a tracker lookup returned success=False
    'watch_diff',      # a watchlist target changed between snapshots
    'risk_high',       # a lookup scored in the high/critical band
    'source_tripped',  # a data source hit its failure circuit breaker
    'case_created',    # a new investigation case was opened
)

#: How many event entries the on-disk ring buffer keeps (oldest dropped).
MAX_EVENT_LOG = 100

#: Filename of the persisted state, placed beside the SQLite database.
_STATE_FILENAME = 'alerts.json'

#: Serialises every read/modify/write of the state file.
_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _state_path() -> Path:
    """
    Location of the persisted alerts state (``alerts.json``).

    The file lives next to the SQLite database configured in
    ``config.db_config.sqlite_path`` so all local state shares one data
    directory; when that path is unusable the plain ``data`` directory is
    the fallback. The directory itself is created on first write.
    """
    raw = ''
    with contextlib.suppress(Exception):
        from ..config import config  # lazy: configuration on first use
        raw = str(config.db_config.sqlite_path or '')
    if raw:
        return Path(raw).expanduser().parent / _STATE_FILENAME
    return Path('data') / _STATE_FILENAME


def _default_state() -> Dict[str, Any]:
    """
    The state used when no ``alerts.json`` exists yet (or it is corrupt).

    Delivery is disabled (no webhook URL) and the whitelist covers every
    event type, so the first ``configure(url)`` call starts delivery for
    all events unless the caller narrows the list.
    """
    return {
        'webhook_url': '',
        'events': list(EVENT_TYPES),
        'log': [],
    }


def _load() -> Dict[str, Any]:
    """
    Read the state file, falling back to defaults on any problem.

    Lock-free primitive: callers hold :data:`_LOCK`.
    """
    try:
        raw = _state_path().read_text(encoding='utf-8')
        data = json.loads(raw)
    except (OSError, ValueError):
        return _default_state()
    if not isinstance(data, dict):
        return _default_state()
    state = _default_state()
    url = data.get('webhook_url')
    state['webhook_url'] = url if isinstance(url, str) else ''
    events = data.get('events')
    if isinstance(events, (list, tuple)):
        state['events'] = [str(item) for item in events
                           if str(item or '').strip().lower() in EVENT_TYPES]
    log = data.get('log')
    if isinstance(log, list):
        state['log'] = [entry for entry in log if isinstance(entry, dict)]
    return state


def _save(state: Dict[str, Any]) -> None:
    """
    Persist the state file atomically (write to a temp name, then replace).

    Lock-free primitive: callers hold :data:`_LOCK`. A failed write is
    swallowed - a read-only data directory must never break lookups.
    """
    path = _state_path()
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2),
                       encoding='utf-8')
        tmp.replace(path)


def _now_iso() -> str:
    """Current UTC time as a second-resolution ISO string."""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def _deliver(url: str, body: Dict[str, Any]) -> Tuple[bool, str]:
    """
    POST one JSON body to the webhook (best-effort, never raises).

    Args:
        url: the configured webhook endpoint
        body: the JSON payload to send

    Returns:
        ``(ok, detail)`` where ``detail`` is ``'ok'`` on success or a
        short human reason for the failure (connection refused, HTTP
        status, invalid URL scheme...).
    """
    if not str(url).startswith(('http://', 'https://')):
        return False, 'invalid webhook url'
    from ..utils.http_client import http  # lazy: pulls requests machinery
    try:
        ok, _data, err = http.post_json(url, body)
    except Exception as exc:  # transport-level surprises stay local
        return False, f"{type(exc).__name__}: {exc}"
    if ok:
        return True, 'ok'
    return False, str(err or 'delivery failed')


def summarize(payload: Any) -> str:
    """
    Build the human one-liner for an event payload.

    The webhook ``text`` field carries this string, so the notification
    reads like a note from a colleague rather than a JSON dump:
    ``"target 8.8.8.8 (ip) · error: all sources failed"``. Recognised
    keys are ``target``/``value``, ``kind``, ``error``, ``score``,
    ``source``, ``old``/``new`` (watch diffs) and ``case``; anything else
    falls back to a generic label.
    """
    payload = payload if isinstance(payload, dict) else {}
    target = str(payload.get('target') or payload.get('value') or '').strip()
    kind = str(payload.get('kind') or '').strip()
    parts: List[str] = []
    if target:
        parts.append(f"target {target}" + (f" ({kind})" if kind else ""))
    elif kind:
        parts.append(kind)
    error = str(payload.get('error') or '').strip()
    if error:
        parts.append(f"error: {error[:80]}")
    score = payload.get('score')
    if score is not None:
        parts.append(f"risk score {score}")
    source = str(payload.get('source') or '').strip()
    if source:
        parts.append(f"source {source}")
    old = payload.get('old')
    new = payload.get('new')
    if old is not None or new is not None:
        parts.append(f"changed: {old} -> {new}")
    case = str(payload.get('case') or payload.get('case_name') or '').strip()
    if case:
        parts.append(f"case {case}")
    if not parts:
        parts.append('notification')
    return ' · '.join(parts)[:200]


def notify(event_type: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Record an event and (when configured for it) deliver it to the webhook.

    Every call appends ``{'ts', 'event', 'payload'}`` to the persistent
    ring buffer (capped at :data:`MAX_EVENT_LOG`) regardless of delivery:
    the log is the complete history of what the system wanted to say.
    Delivery happens only when a webhook URL is configured *and* the event
    type is whitelisted; the outcome is stamped on the entry as
    ``'delivery': 'ok' | 'failed: <reason>' | 'skipped: <why>'``.

    Args:
        event_type: one of :data:`EVENT_TYPES` (unknown types are still
            logged, they simply never deliver)
        payload: the event details (target, kind, error, score...); a
            non-dict argument is treated as ``{}``

    Returns:
        The logged event entry, including its delivery outcome. Never
        raises - a dead webhook is a fact to record, not an error to
        propagate into a lookup.
    """
    event_type = str(event_type or '').strip()
    payload = payload if isinstance(payload, dict) else {}
    entry: Dict[str, Any] = {'ts': _now_iso(), 'event': event_type,
                             'payload': payload}

    with _LOCK:
        state = _load()
        url = str(state.get('webhook_url') or '')
        whitelisted = {str(item).strip().lower() for item in state.get('events') or []}

    if url and event_type.lower() in whitelisted:
        body = {
            'text': summarize(payload),
            'event': event_type,
            'payload': payload,
            'source': 'ObscuraLens',
        }
        ok, detail = _deliver(url, body)
        entry['delivery'] = 'ok' if ok else f"failed: {detail}"
    elif not url:
        entry['delivery'] = 'skipped: alerts disabled (no webhook configured)'
    else:
        entry['delivery'] = 'skipped: event not whitelisted'

    with _LOCK:
        state = _load()
        log = state.setdefault('log', [])
        if not isinstance(log, list):
            log = []
            state['log'] = log
        log.append(entry)
        if len(log) > MAX_EVENT_LOG:
            del log[:len(log) - MAX_EVENT_LOG]
        _save(state)
    return entry


# ---------------------------------------------------------------------------
# Configuration and introspection
# ---------------------------------------------------------------------------

def configure(webhook_url: str, events: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Configure webhook delivery (an empty URL disables it entirely).

    Args:
        webhook_url: the endpoint that receives notification POSTs; an
            empty or whitespace string turns delivery off while keeping
            the local event log running
        events: the event types to deliver, drawn from
            :data:`EVENT_TYPES` (case-insensitive; unknown names are
            dropped). ``None`` whitelists every event type.

    Returns:
        The new configuration snapshot (same shape as :func:`get_config`).
    """
    url = str(webhook_url or '').strip()
    if events is None:
        chosen = list(EVENT_TYPES)
    else:
        try:
            candidates = list(events)
        except TypeError:
            candidates = []
        chosen = []
        for item in candidates:
            name = str(item or '').strip().lower()
            if name in EVENT_TYPES and name not in chosen:
                chosen.append(name)
    with _LOCK:
        state = _load()
        state['webhook_url'] = url
        state['events'] = chosen
        _save(state)
    return get_config()


def get_config() -> Dict[str, Any]:
    """
    The current notification configuration.

    Returns:
        ``{'webhook_url': str, 'events': [str], 'enabled': bool}`` where
        ``enabled`` is true only when a non-empty webhook URL is set.
        Reads never create the state file; an unconfigured machine simply
        reports defaults.
    """
    with _LOCK:
        state = _load()
    return {
        'webhook_url': str(state.get('webhook_url') or ''),
        'events': list(state.get('events') or []),
        'enabled': bool(state.get('webhook_url')),
    }


def recent(limit: int = 20) -> List[Dict[str, Any]]:
    """
    The most recent logged events, newest first.

    Args:
        limit: how many entries to return (0 or negative yields ``[]``)

    Returns:
        List of ``{'ts', 'event', 'payload', 'delivery'}`` dicts.
    """
    try:
        limit = max(0, int(limit))
    except (TypeError, ValueError):
        limit = 20
    with _LOCK:
        state = _load()
    log = state.get('log') or []
    if not limit:
        return []
    return list(reversed(log[-limit:]))


def clear_events() -> int:
    """
    Empty the local event log.

    Returns:
        The number of entries that were removed.
    """
    with _LOCK:
        state = _load()
        log = state.get('log') or []
        removed = len(log)
        state['log'] = []
        _save(state)
    return removed


def test() -> Dict[str, Any]:
    """
    Send a one-off test notification to the configured webhook.

    Unlike :func:`notify` the test bypasses the event whitelist - it is
    an explicit user action from the settings screen. The attempt (and
    its outcome) is still recorded in the event log under the event name
    ``'test'`` so the audit trail stays complete.

    Returns:
        ``{'delivered': bool, 'error': str, 'webhook_url': str, 'ts': str}``.
        When no webhook is configured the call is refused with
        ``delivered=False`` and an explanatory error, and nothing is sent.
    """
    with _LOCK:
        state = _load()
        url = str(state.get('webhook_url') or '')
    if not url:
        return {'delivered': False,
                'error': 'no webhook configured (call configure() first)',
                'webhook_url': '', 'ts': _now_iso()}

    payload = {'kind': 'system', 'target': 'self-test',
               'message': 'ObscuraLens webhook wiring test'}
    body = {
        'text': 'ObscuraLens test notification - your webhook works.',
        'event': 'test',
        'payload': payload,
        'source': 'ObscuraLens',
    }
    ok, detail = _deliver(url, body)
    entry = {'ts': _now_iso(), 'event': 'test', 'payload': payload,
             'delivery': 'ok' if ok else f"failed: {detail}"}
    with _LOCK:
        state = _load()
        log = state.setdefault('log', [])
        if not isinstance(log, list):
            log = []
            state['log'] = log
        log.append(entry)
        if len(log) > MAX_EVENT_LOG:
            del log[:len(log) - MAX_EVENT_LOG]
        _save(state)
    return {'delivered': ok, 'error': '' if ok else detail,
            'webhook_url': url, 'ts': entry['ts']}
