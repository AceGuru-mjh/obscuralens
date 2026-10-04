"""
Multi-channel notification centre (v6.0 Part 4).

The v5.0 :mod:`obscuralens.advanced.alerts` module proved the pattern: a
local JSON event log plus one best-effort webhook. Long monitoring
sessions, however, want more than one pipe - an analyst runs Telegram on
their phone, Discord for the team, Slack for the case channel and an SMTP
gateway for the audit mailbox. This module is the v6.0 generalisation:

**Five channel types, one defensive send path.**

* ``webhook`` - generic JSON POST (``{'event', 'title', 'body',
  'severity', 'fields', 'ts'}``) for collectors and home automation.
* ``telegram`` - Bot API ``sendMessage``; the target is the composite
  string ``bot_token:chat_id`` (split on the *first* colon, because bot
  tokens themselves contain one).
* ``discord`` - incoming webhook URL; the message is
  ``**[severity] title**\\nbody`` truncated to the 2000-character limit.
* ``slack`` - incoming webhook URL; ``*[severity] title*\\nbody``.
* ``smtp`` - :mod:`smtplib` delivery of a UTF-8 ``text/plain`` message;
  the target is ``host:port:from:to[:user:pass]`` (see
  :func:`_parse_smtp_target` for the field-by-field contract).

Channel lifecycle (persisted in ``notifications.json`` beside the SQLite
database, exactly like ``alerts.json``):

* :func:`add_channel` / :func:`remove_channel` / :func:`list_channels` /
  :func:`get_channel` - CRUD over named channels; names are unique.
* :func:`send` - the core: event subscription filter, severity floor,
  quiet-hours window, 5-minute dedup window, then format + dispatch +
  history entry. Never raises; always returns
  ``{'ok', 'error', 'channel', 'skipped', 'reason'}``.
* :func:`broadcast` - fan one event out to every configured channel and
  aggregate ``{'sent', 'failed', 'skipped', 'results'}``.
* :func:`test_channel` - explicit user test that bypasses the filters
  (still logged, so the audit trail stays complete).
* :func:`format_event` / :func:`notify_kind_event` - lookup-shaped
  convenience wrappers around :func:`broadcast`.
* :func:`recent` / :func:`clear_log` - inspect and reset the ring buffer
  (last 100 entries).

Fallback wiring: a channel may leave ``target`` empty when the matching
global key is configured (``telegram_api_key`` for the composite
``bot_token:chat_id``, ``slack_webhook_url``, ``discord_webhook_url``,
``smtp_credentials`` in ``secrets.yaml``); :func:`send` resolves the
fallback transparently. Nothing leaves the machine until an analyst
configures a channel - the module ships with zero channels.
"""

import contextlib
import html
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

__all__ = [
    'CHANNEL_TYPES',
    'DEDUP_SECONDS',
    'MAX_EVENT_LOG',
    'SEVERITY_LEVELS',
    'NotificationChannel',
    'add_channel',
    'broadcast',
    'clear_log',
    'format_event',
    'get_channel',
    'list_channels',
    'notify_kind_event',
    'recent',
    'remove_channel',
    'send',
    'test_channel',
]

#: Supported channel types (the ``type`` field of a channel spec).
CHANNEL_TYPES: Tuple[str, ...] = (
    'webhook',   # generic JSON POST
    'telegram',  # Bot API sendMessage
    'discord',   # incoming webhook URL
    'slack',     # incoming webhook URL
    'smtp',      # smtplib delivery
)

#: Severity ladder, weakest to strongest. ``min_severity`` on a channel
#: filters events below that rung; unknown severities rank as ``info``.
SEVERITY_LEVELS: Tuple[str, ...] = (
    'info', 'low', 'medium', 'high', 'critical',
)

#: How many history entries the on-disk ring buffer keeps (oldest dropped).
MAX_EVENT_LOG = 100

#: Dedup window: an identical (per the channel's ``dedup_key`` recipe)
#: message is not re-sent within this many seconds.
DEDUP_SECONDS = 300

#: Maximum characters for the message text carried by chat payloads.
_MAX_TEXT_CHARS = 4000

#: Filename of the persisted state, placed beside the SQLite database.
_STATE_FILENAME = 'notifications.json'

#: Serialises every read/modify/write of the state file.
_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Channel value object
# ---------------------------------------------------------------------------

@dataclass
class NotificationChannel:
    """
    One configured notification channel.

    Attributes:
        name: unique human label ('pagerduty-oncall', 'team-chat'...).
        type: one of :data:`CHANNEL_TYPES`.
        target: where the message goes - webhook URL, Telegram
            ``bot_token:chat_id``, chat webhook URL or SMTP
            ``host:port:from:to[:user:pass]``; empty means "use the
            matching global config key" (see module docstring).
        events: event types this channel subscribes to (case-insensitive;
            empty subscribes to everything).
        enabled: master switch - disabled channels are never contacted.
        min_severity: weakest :data:`SEVERITY_LEVELS` rung worth waking
            this channel for (default ``info`` = everything).
        quiet_hours: optional ``(start, end)`` local-time hour pair; the
            window wraps past midnight, so ``(22, 6)`` silences 22:00 to
            06:00, and a degenerate ``(h, h)`` pair disables the window.
        dedup_key: optional recipe that defines "the same message":
            ``'event'``, ``'title'`` or ``'event+title'`` (default for
            any unrecognised value); ``None`` disables deduplication.
        note: free-form operator note shown in listings.
    """

    name: str
    type: str
    target: str = ''
    events: List[str] = field(default_factory=list)
    enabled: bool = True
    min_severity: str = 'info'
    quiet_hours: Optional[Tuple[int, int]] = None
    dedup_key: Optional[str] = None
    note: str = ''


def _severity_rank(severity: Any) -> int:
    """
    Numeric rank of a severity label (0 = info, 4 = critical).

    Unknown or missing labels rank as ``info`` (rank 0): an unlabelled
    event is still a fact, and permissive-by-default keeps new event
    types deliverable instead of silently dropped.
    """
    label = str(severity or '').strip().lower()
    try:
        return SEVERITY_LEVELS.index(label)
    except ValueError:
        return 0


def _normalize_events(raw: Any) -> List[str]:
    """Lower-case, de-blanked event subscription list (never raises)."""
    if isinstance(raw, str):
        candidates: List[Any] = raw.split(',')
    elif isinstance(raw, (list, tuple, set)):
        candidates = list(raw)
    else:
        candidates = []
    events: List[str] = []
    for item in candidates:
        name = str(item or '').strip().lower()
        if name and name not in events:
            events.append(name)
    return events


def _normalize_quiet_hours(raw: Any) -> Optional[Tuple[int, int]]:
    """
    Coerce a quiet-hours spec into an ``(start, end)`` hour tuple.

    Accepts ``None``, a 2-list/tuple of hour ints or an hour-ish string
    range (``[22, 6]``, ``'22-6'``, ``'22:00-06:00'``). Invalid values
    yield ``None`` (window disabled); a degenerate ``(h, h)`` pair
    survives as itself and :func:`_in_quiet_hours` treats it as "no
    window".
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        parts = [chunk for chunk in raw.replace('-', ':').split(':')
                 if chunk.strip()]
        raw = parts[:2] if len(parts) >= 2 else None
    if not isinstance(raw, (list, tuple)) or len(raw) != 2:
        return None
    hours: List[int] = []
    for item in raw:
        try:
            hour = int(str(item).strip())
        except (TypeError, ValueError):
            return None
        if not 0 <= hour <= 23:
            return None
        hours.append(hour)
    if len(hours) != 2:
        return None
    return (hours[0], hours[1])


def _normalize_channel(spec: Any) -> Tuple[Optional[NotificationChannel], str]:
    """
    Validate a raw channel mapping into a :class:`NotificationChannel`.

    Returns:
        ``(channel, '')`` on success or ``(None, reason)`` when the spec
        is structurally unusable (missing name, unknown type, empty
        target with no config fallback...).
    """
    if not isinstance(spec, dict):
        return None, 'channel spec must be a mapping'
    name = str(spec.get('name') or '').strip()
    if not name:
        return None, 'channel name is required'
    if len(name) > 80:
        return None, 'channel name too long (max 80 chars)'
    channel_type = str(spec.get('type') or '').strip().lower()
    if channel_type not in CHANNEL_TYPES:
        return None, (f"unknown channel type {channel_type!r} "
                      f"(expected one of {', '.join(CHANNEL_TYPES)})")
    target = str(spec.get('target') or '').strip()
    if not target and channel_type != 'webhook' \
            and not _config_fallback(channel_type):
        # webhook has no global fallback key; the chat/mail types do.
        return None, (f"channel target is required for {channel_type} "
                      f"(or set the global config key first)")
    min_severity = str(spec.get('min_severity') or 'info').strip().lower()
    if min_severity not in SEVERITY_LEVELS:
        min_severity = 'info'
    dedup_key = str(spec.get('dedup_key') or '').strip().lower() or None
    if dedup_key is not None and dedup_key not in ('event', 'title',
                                                   'event+title'):
        dedup_key = 'event+title'
    channel = NotificationChannel(
        name=name,
        type=channel_type,
        target=target,
        events=_normalize_events(spec.get('events')),
        enabled=bool(spec.get('enabled', True)),
        min_severity=min_severity,
        quiet_hours=_normalize_quiet_hours(spec.get('quiet_hours')),
        dedup_key=dedup_key,
        note=str(spec.get('note') or '')[:200],
    )
    return channel, ''


def _channel_to_dict(channel: NotificationChannel,
                     extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """JSON-ready mapping for one channel (plus optional runtime extras)."""
    data = asdict(channel)
    data['events'] = list(channel.events)
    data['quiet_hours'] = list(channel.quiet_hours) if channel.quiet_hours else None
    if extra:
        data.update(extra)
    return data


def _spec_to_channel(spec: Dict[str, Any]) -> NotificationChannel:
    """Rebuild a channel from its persisted dict (lossy fields tolerated)."""
    min_severity = str(spec.get('min_severity') or 'info').strip().lower()
    dedup_key = str(spec.get('dedup_key') or '').strip().lower() or None
    if dedup_key is not None and dedup_key not in ('event', 'title',
                                                   'event+title'):
        dedup_key = 'event+title'
    return NotificationChannel(
        name=str(spec.get('name') or ''),
        type=str(spec.get('type') or '').strip().lower(),
        target=str(spec.get('target') or ''),
        events=_normalize_events(spec.get('events')),
        enabled=bool(spec.get('enabled', True)),
        min_severity=min_severity if min_severity in SEVERITY_LEVELS else 'info',
        quiet_hours=_normalize_quiet_hours(spec.get('quiet_hours')),
        dedup_key=dedup_key,
        note=str(spec.get('note') or '')[:200],
    )


# ---------------------------------------------------------------------------
# Persistence (pattern copied from advanced/alerts.py)
# ---------------------------------------------------------------------------

def _state_path() -> Path:
    """
    Location of the persisted notifications state (``notifications.json``).

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
    The state used when no ``notifications.json`` exists yet (or it is
    corrupt): zero channels, empty history, empty dedup cache. The module
    is inert until an analyst calls :func:`add_channel`.
    """
    return {'channels': [], 'log': [], 'dedup': {}}


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
    channels = data.get('channels')
    if isinstance(channels, list):
        state['channels'] = [item for item in channels if isinstance(item, dict)]
    log = data.get('log')
    if isinstance(log, list):
        state['log'] = [entry for entry in log if isinstance(entry, dict)]
    dedup = data.get('dedup')
    if isinstance(dedup, dict):
        state['dedup'] = {str(key): value for key, value in dedup.items()
                          if isinstance(value, dict)}
    return state


def _save(state: Dict[str, Any]) -> None:
    """
    Persist the state file atomically (write to a temp name, then replace).

    Lock-free primitive: callers hold :data:`_LOCK`. A failed write is
    swallowed - a read-only data directory must never break a lookup.
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
# Target resolution and delivery
# ---------------------------------------------------------------------------

def _config_fallback(channel_type: str) -> str:
    """
    The global config credential for a channel type (``''`` when unset).

    Mapping: telegram → ``telegram_api_key`` (composite
    ``bot_token:chat_id``), slack → ``slack_webhook_url``, discord →
    ``discord_webhook_url``, smtp → ``smtp_credentials`` (the same
    ``host:port:from:to[:user:pass]`` format as a channel target).
    Reads never raise; any configuration problem simply yields an empty
    fallback.
    """
    try:
        from ..config import config  # lazy: configuration on first use
        api = config.api_config
        if channel_type == 'telegram':
            return str(getattr(api, 'telegram_api_key', '') or '').strip()
        if channel_type == 'slack':
            return str(getattr(api, 'slack_webhook_url', '') or '').strip()
        if channel_type == 'discord':
            return str(getattr(api, 'discord_webhook_url', '') or '').strip()
        if channel_type == 'smtp':
            return str(getattr(api, 'smtp_credentials', '') or '').strip()
    except Exception:  # pragma: no cover - defensive by contract
        return ''
    return ''


def _resolve_target(channel: NotificationChannel) -> str:
    """Channel target with the global config fallback applied."""
    target = str(channel.target or '').strip()
    if target:
        return target
    return _config_fallback(channel.type)


def _post(url: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    POST one JSON body via the shared HTTP client (best-effort).

    Returns:
        ``(ok, detail)`` where ``detail`` is ``'ok'`` on success or a
        short human reason for the failure (transport error, HTTP
        status, invalid URL scheme...). Never raises.
    """
    if not str(url).startswith(('http://', 'https://')):
        return False, 'invalid url'
    from ..utils.http_client import http  # lazy: pulls requests machinery
    try:
        ok, _data, err = http.post_json(url, payload)
    except Exception as exc:  # transport-level surprises stay local
        return False, f"{type(exc).__name__}: {exc}"
    if ok:
        return True, 'ok'
    return False, str(err or 'delivery failed')


def _parse_smtp_target(target: str) -> Tuple[Dict[str, str], str]:
    """
    Split an SMTP target string into its connection parameters.

    Format (colon-separated, in order)::

        host:port:from:to[:user:pass]

    Examples::

        smtp.example.com:587:alerts@corp.example:analyst@corp.example
        smtp.example.com:587:alerts@corp.example:analyst@corp.example:user:secret
        localhost

    Defaults when fields are omitted: port 25, ``from``/``to``
    ``obscuralens@localhost``; login is only attempted when *both* a
    user and a password are present.

    Returns:
        ``(params, '')`` with keys ``host``/``port``/``from``/``to``/
        ``user``/``password``, or ``({}, reason)`` when no host exists.
    """
    parts = [chunk.strip() for chunk in str(target or '').split(':')]
    host = parts[0] if parts else ''
    if not host:
        return {}, 'smtp target missing host'
    port = 25
    if len(parts) > 1 and parts[1].isdigit():
        port = int(parts[1])
    from_addr = parts[2] if len(parts) > 2 else 'obscuralens@localhost'
    to_addr = parts[3] if len(parts) > 3 else from_addr
    if not to_addr:
        to_addr = from_addr
    user = parts[4] if len(parts) > 4 else ''
    password = parts[5] if len(parts) > 5 else ''
    return {'host': host, 'port': str(port), 'from': from_addr,
            'to': to_addr, 'user': user, 'password': password}, ''


def _send_smtp(target: str, title: str, body: str) -> Tuple[bool, str]:
    """
    Deliver one UTF-8 ``text/plain`` mail via :mod:`smtplib`.

    STARTTLS is attempted opportunistically (a server without it keeps
    working in the clear) and ``login`` only runs when both a user and a
    password are present in the target string. Everything is wrapped so
    a dead relay is reported, never raised.
    """
    params, error = _parse_smtp_target(target)
    if error:
        return False, error
    try:
        import smtplib
        from email.mime.text import MIMEText
    except ImportError as exc:  # pragma: no cover - stdlib always present
        return False, f'mail machinery unavailable: {exc}'
    message = MIMEText(body or '(empty body)', 'plain', 'utf-8')
    message['Subject'] = (title or 'ObscuraLens notification')[:200]
    message['From'] = params['from']
    message['To'] = params['to']
    try:
        with smtplib.SMTP(params['host'], int(params['port']),
                          timeout=15) as client:
            with contextlib.suppress(smtplib.SMTPException, OSError):
                client.ehlo()
                client.starttls()
                client.ehlo()
            if params['user'] and params['password']:
                client.login(params['user'], params['password'])
            client.sendmail(params['from'], [params['to']],
                            message.as_string())
        return True, 'ok'
    except Exception as exc:  # refused, timed out, auth rejected...
        return False, f'{type(exc).__name__}: {exc}'


def _clip(text: str, limit: int) -> str:
    """Clip a string to ``limit`` characters with an ellipsis marker."""
    text = str(text or '')
    if len(text) <= limit:
        return text
    return text[:max(0, limit - 1)] + '…'


def _dispatch(channel: NotificationChannel, target: str, event_type: str,
              title: str, body: str, severity: str,
              fields: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """
    Format one message for the channel's protocol and deliver it.

    Pure transport: no filters, no dedup, no state writes (those belong
    to :func:`send`). Returns ``(ok, detail)``; never raises.
    """
    title = str(title or '').strip() or 'ObscuraLens notification'
    body = str(body or '')
    severity = str(severity or 'info').strip().lower() or 'info'
    if channel.type == 'webhook':
        payload = {
            'event': event_type,
            'title': title,
            'body': body,
            'severity': severity,
            'fields': fields if isinstance(fields, dict) else {},
            'ts': _now_iso(),
        }
        return _post(target, payload)
    if channel.type == 'telegram':
        if ':' not in target:
            return False, "telegram target must be 'bot_token:chat_id'"
        token, chat_id = target.split(':', 1)
        if not token.strip() or not chat_id.strip():
            return False, 'telegram target missing token or chat_id'
        url = f'https://api.telegram.org/bot{token.strip()}/sendMessage'
        text = _clip(f'<b>{html.escape(title)}</b>\n{html.escape(body)}',
                     _MAX_TEXT_CHARS)
        payload = {'chat_id': chat_id.strip(), 'text': text,
                   'parse_mode': 'HTML'}
        return _post(url, payload)
    if channel.type == 'discord':
        content = _clip(f'**[{severity}] {title}**\n{body}', 2000)
        return _post(target, {'content': content})
    if channel.type == 'slack':
        text = _clip(f'*[{severity}] {title}*\n{body}', 29000)
        return _post(target, {'text': text})
    if channel.type == 'smtp':
        return _send_smtp(target, title, body)
    return False, f'unknown channel type {channel.type!r}'


# ---------------------------------------------------------------------------
# Quiet hours and dedup
# ---------------------------------------------------------------------------

def _in_quiet_hours(quiet: Optional[Tuple[int, int]],
                    now: Optional[datetime] = None) -> bool:
    """
    Whether ``now`` (local wall clock) falls inside a quiet-hours window.

    The window is ``[start, end)`` on the hour and wraps past midnight:
    ``(22, 6)`` silences 22:00 through 05:59. ``None`` or a degenerate
    ``(h, h)`` pair never silences anything.
    """
    if not quiet or len(quiet) != 2:
        return False
    start, end = int(quiet[0]), int(quiet[1])
    if start == end:
        return False
    hour = (now or datetime.now()).hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # wraps midnight


def _dedup_cache_key(channel: NotificationChannel, event_type: str,
                     title: str) -> str:
    """Cache key for a message under the channel's ``dedup_key`` recipe."""
    recipe = channel.dedup_key or 'event+title'
    if recipe == 'event':
        return f'event:{event_type}'
    if recipe == 'title':
        return f'title:{title}'
    return f'event:{event_type}|title:{title}'


def _dedup_blocked(state: Dict[str, Any], channel: NotificationChannel,
                   cache_key: str, now: datetime) -> Tuple[bool, int]:
    """
    Whether ``cache_key`` for this channel was sent inside the window.

    Returns:
        ``(blocked, seconds_since_last_send)``; ``(False, 0)`` when no
        recent match exists (including unparseable cache entries, which
        simply expire).
    """
    entries = state.get('dedup', {}).get(channel.name)
    if not isinstance(entries, dict):
        return False, 0
    raw = str(entries.get(cache_key) or '')
    try:
        last = datetime.fromisoformat(raw)
    except ValueError:
        return False, 0
    elapsed = (now - last).total_seconds()
    if 0 <= elapsed < DEDUP_SECONDS:
        return True, int(elapsed)
    return False, 0


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def _record(state: Dict[str, Any], channel: NotificationChannel,
            event_type: str, title: str, severity: str,
            delivery: str) -> None:
    """Append one entry to the in-memory ring buffer (caller holds _LOCK)."""
    log = state.setdefault('log', [])
    if not isinstance(log, list):
        log = []
        state['log'] = log
    log.append({
        'ts': _now_iso(),
        'event': str(event_type or '')[:60],
        'channel': channel.name,
        'title': str(title or '')[:120],
        'severity': str(severity or 'info').lower(),
        'delivery': str(delivery)[:200],
    })
    if len(log) > MAX_EVENT_LOG:
        del log[:len(log) - MAX_EVENT_LOG]


# ---------------------------------------------------------------------------
# Channel CRUD
# ---------------------------------------------------------------------------

def add_channel(channel: Union[Dict[str, Any], NotificationChannel]
                ) -> Dict[str, Any]:
    """
    Register a new notification channel.

    Args:
        channel: mapping with ``name``/``type``/``target`` (plus optional
            ``events``/``enabled``/``min_severity``/``quiet_hours``/
            ``dedup_key``/``note``) or a ready :class:`NotificationChannel`.

    Returns:
        ``{'ok': True, 'error': '', 'channel': {...}}`` or
        ``{'ok': False, 'error': reason, 'channel': None}`` when the spec
        is invalid or the name already exists.
    """
    if isinstance(channel, NotificationChannel):
        normalized, error = _normalize_channel(_channel_to_dict(channel))
    else:
        normalized, error = _normalize_channel(channel)
    if normalized is None:
        return {'ok': False, 'error': error, 'channel': None}
    with _LOCK:
        state = _load()
        existing = {str(item.get('name') or '')
                    for item in state['channels']}
        if normalized.name in existing:
            return {'ok': False,
                    'error': f"channel '{normalized.name}' already exists",
                    'channel': None}
        stored = _channel_to_dict(normalized)
        state['channels'].append(stored)
        _save(state)
    return {'ok': True, 'error': '', 'channel': stored}


def remove_channel(name: str) -> Dict[str, Any]:
    """
    Delete one channel (its history stays behind - the log is the audit
    trail of everything that *was* sent).

    Args:
        name: channel name (case-insensitive).

    Returns:
        ``{'ok', 'error', 'removed'}`` where ``removed`` is the channel
        name on success or ``''`` when nothing matched.
    """
    wanted = str(name or '').strip().lower()
    with _LOCK:
        state = _load()
        kept = [item for item in state['channels']
                if str(item.get('name') or '').strip().lower() != wanted]
        if len(kept) == len(state['channels']):
            return {'ok': False, 'error': f"channel '{name}' not found",
                    'removed': ''}
        state['channels'] = kept
        if isinstance(state.get('dedup'), dict):
            state['dedup'].pop(wanted, None)
        _save(state)
    return {'ok': True, 'error': '', 'removed': wanted}


def _stored_channels(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Channel dicts of a loaded state, defensively filtered."""
    channels = state.get('channels')
    if not isinstance(channels, list):
        return []
    return [item for item in channels if isinstance(item, dict)]


def list_channels() -> List[Dict[str, Any]]:
    """
    Every configured channel as a JSON-ready dict.

    Each dict carries the :class:`NotificationChannel` fields plus the
    runtime ``last_sent`` timestamp (``''`` when never used).
    """
    with _LOCK:
        state = _load()
    return [_channel_to_dict(_spec_to_channel(item),
                             {'last_sent': str(item.get('last_sent') or '')})
            for item in _stored_channels(state)]


def get_channel(name: str) -> Optional[Dict[str, Any]]:
    """
    One channel by name (case-insensitive), or ``None``.

    Returns:
        The same dict shape as :func:`list_channels` entries.
    """
    wanted = str(name or '').strip().lower()
    for item in list_channels():
        if str(item.get('name') or '').strip().lower() == wanted:
            return item
    return None


# ---------------------------------------------------------------------------
# Send / broadcast / test
# ---------------------------------------------------------------------------

def _resolve_channel(channel: Union[str, Dict[str, Any], NotificationChannel]
                     ) -> Tuple[Optional[NotificationChannel], str]:
    """
    Coerce the ``channel`` argument of :func:`send` into a value object.

    Accepts a :class:`NotificationChannel`, a full channel mapping or a
    plain channel name (looked up in the persisted state).
    """
    if isinstance(channel, NotificationChannel):
        return channel, ''
    if isinstance(channel, dict):
        normalized, error = _normalize_channel(channel)
        if normalized is None:
            return None, error or 'invalid channel spec'
        return normalized, ''
    wanted = str(channel or '').strip().lower()
    if not wanted:
        return None, 'channel is required'
    with _LOCK:
        state = _load()
    for item in _stored_channels(state):
        if str(item.get('name') or '').strip().lower() == wanted:
            return _spec_to_channel(item), ''
    return None, f"channel '{channel}' not found"


def send(channel: Union[str, Dict[str, Any], NotificationChannel],
         event_type: str, title: str, body: str, severity: str = 'info',
         fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Deliver one event to one channel (subscription, severity, quiet
    hours and dedup filters first).

    Filter order: unknown channel → disabled → event not subscribed →
    severity below the channel floor → no usable target → quiet hours →
    duplicate inside :data:`DEDUP_SECONDS`. Only then is the message
    formatted and dispatched. Every outcome - sent, failed or skipped -
    is appended to the persistent history, so :func:`recent` is the
    complete account of what this module wanted to say.

    Args:
        channel: channel name, full channel mapping or value object.
        event_type: free-form event label ('lookup', 'watch_diff'...).
        title: one-line headline (kept under 120 chars in the log).
        body: message body (clipped per protocol limits on dispatch).
        severity: one of :data:`SEVERITY_LEVELS` (default ``info``).
        fields: optional structured extras for the webhook payload.

    Returns:
        ``{'ok': bool, 'error': str, 'channel': name, 'skipped': bool,
        'reason': str}``. Never raises: a dead endpoint is a fact to
        record, not an error to propagate.
    """
    resolved, error = _resolve_channel(channel)
    if resolved is None:
        return {'ok': False, 'error': error, 'channel': str(channel),
                'skipped': False, 'reason': ''}
    event_type = str(event_type or '').strip().lower()
    severity = str(severity or 'info').strip().lower() or 'info'
    base = {'channel': resolved.name, 'error': '', 'reason': '',
            'skipped': False}

    def _skip(reason: str) -> Dict[str, Any]:
        outcome = dict(base)
        outcome.update({'ok': False, 'skipped': True, 'reason': reason})
        with _LOCK:
            state = _load()
            _record(state, resolved, event_type, title, severity,
                    f'skipped: {reason}')
            _save(state)
        return outcome

    if not resolved.enabled:
        return _skip('channel disabled')
    if resolved.events and event_type not in resolved.events:
        return _skip('event not subscribed')
    if _severity_rank(severity) < _severity_rank(resolved.min_severity):
        return _skip(f'severity below channel floor '
                     f'({resolved.min_severity})')
    target = _resolve_target(resolved)
    if not target:
        return {'ok': False, 'error': 'no target configured',
                'channel': resolved.name, 'skipped': False, 'reason': ''}
    if _in_quiet_hours(resolved.quiet_hours):
        return _skip('quiet hours')

    now = datetime.now()
    cache_key = _dedup_cache_key(resolved, event_type, str(title or ''))
    with _LOCK:
        state = _load()
        blocked, elapsed = _dedup_blocked(state, resolved, cache_key, now)
    if blocked:
        return _skip(f'deduplicated (sent {elapsed}s ago)')

    ok, detail = _dispatch(resolved, target, event_type, title, body,
                           severity, fields)
    with _LOCK:
        state = _load()
        _record(state, resolved, event_type, title, severity,
                'ok' if ok else f'failed: {detail}')
        if ok:
            for item in state['channels']:
                if str(item.get('name') or '').strip().lower() \
                        == resolved.name.lower():
                    item['last_sent'] = _now_iso()
                    break
            dedup = state.setdefault('dedup', {})
            if isinstance(dedup, dict):
                entries = dedup.setdefault(resolved.name, {})
                if isinstance(entries, dict):
                    entries[cache_key] = now.isoformat(timespec='seconds')
        _save(state)
    outcome = dict(base)
    outcome.update({'ok': ok, 'error': '' if ok else detail})
    return outcome


def broadcast(event_type: str, title: str, body: str, severity: str = 'info',
              fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Fan one event out to every configured channel.

    Disabled, filtered or quiet-hours channels count as skipped (the
    attempt is still logged per channel); delivery failures are
    collected with their reason but never abort the loop.

    Args:
        event_type: free-form event label.
        title: headline shown in every chat payload.
        body: message body.
        severity: one of :data:`SEVERITY_LEVELS` (default ``info``).
        fields: optional structured extras for webhook payloads.

    Returns:
        ``{'sent': n, 'failed': [{'channel', 'error'}], 'skipped': n,
        'total': n, 'results': [per-channel send() dicts]}``.
    """
    results: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    sent = skipped = 0
    for spec in list_channels():
        outcome = send(spec, event_type, title, body, severity, fields)
        results.append(outcome)
        if outcome.get('ok'):
            sent += 1
        elif outcome.get('skipped'):
            skipped += 1
        else:
            failures.append({'channel': outcome.get('channel'),
                             'error': outcome.get('error') or 'send failed'})
    return {'sent': sent, 'failed': failures, 'skipped': skipped,
            'total': len(results), 'results': results}


def test_channel(name: str) -> Dict[str, Any]:
    """
    Send a one-off test message to a configured channel.

    An explicit user action from the settings screen, so the event
    subscription, severity floor, quiet-hours and dedup filters are all
    bypassed - the question being answered is "does the pipe work?",
    not "would this event have gone out?". The attempt is still recorded
    in the history under the event name ``'test'``.

    Args:
        name: the channel to probe (case-insensitive).

    Returns:
        ``{'ok', 'error', 'channel'}`` - ``ok`` reflects delivery only.
    """
    resolved, error = _resolve_channel(name)
    if resolved is None:
        return {'ok': False, 'error': error, 'channel': str(name or '')}
    target = _resolve_target(resolved)
    if not target:
        return {'ok': False, 'error': 'no target configured',
                'channel': resolved.name}
    title = 'ObscuraLens test notification'
    body = (f"Channel '{resolved.name}' ({resolved.type}) works. "
            f"Sent {datetime.now().isoformat(timespec='seconds')} local time.")
    ok, detail = _dispatch(resolved, target, 'test', title, body, 'info',
                           {'channel': resolved.name, 'type': resolved.type})
    with _LOCK:
        state = _load()
        _record(state, resolved, 'test', title, 'info',
                'ok' if ok else f'failed: {detail}')
        _save(state)
    return {'ok': ok, 'error': '' if ok else detail, 'channel': resolved.name}


# ---------------------------------------------------------------------------
# Lookup-shaped convenience wrappers
# ---------------------------------------------------------------------------

def format_event(kind: str, target: str, summary: str,
                 fields: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    """
    Format a lookup/watch event into a ``(title, body)`` pair.

    The title is the scan-friendly one-liner (``"ip · 8.8.8.8"`` style);
    the body carries the summary plus up to 15 ``key: value`` lines from
    ``fields`` (values clipped to 200 characters), mirroring the spirit
    of ``advanced.alerts.summarize`` with an independent implementation.

    Args:
        kind: target kind ('ip', 'domain', ...).
        target: the investigated indicator.
        summary: one-sentence human summary of what happened.
        fields: optional structured extras rendered as body lines.

    Returns:
        ``(title, body)`` strings, always safe to send.
    """
    kind = str(kind or 'target').strip() or 'target'
    target = str(target or '').strip()
    title = f'{kind} · {target}' if target else kind
    lines: List[str] = []
    summary = str(summary or '').strip()
    if summary:
        lines.append(summary)
    if isinstance(fields, dict) and fields:
        lines.append('')
        for key, value in list(fields.items())[:15]:
            text = value if isinstance(value, str) else json.dumps(
                value, ensure_ascii=False, default=str)
            lines.append(f'{key}: {_clip(text, 200)}')
    body = '\n'.join(lines) if lines else '(no details)'
    return title, body


def notify_kind_event(kind: str, target: str, summary: str) -> Dict[str, Any]:
    """
    Broadcast a lookup-shaped event to every channel.

    Thin sugar over :func:`format_event` + :func:`broadcast` with event
    type ``'lookup'`` and severity ``info``: the hook trackers and the
    web layer call this when an interesting target was just resolved.

    Args:
        kind: target kind ('ip', 'domain', ...).
        target: the investigated indicator.
        summary: one-sentence human summary.

    Returns:
        The :func:`broadcast` aggregate.
    """
    title, body = format_event(kind, target, summary,
                               {'kind': kind, 'target': target})
    return broadcast('lookup', title, body, 'info',
                     {'kind': kind, 'target': target})


def recent(limit: int = 20) -> List[Dict[str, Any]]:
    """
    The most recent history entries, newest first.

    Args:
        limit: how many entries to return (0 or negative yields ``[]``).

    Returns:
        List of ``{'ts', 'event', 'channel', 'title', 'severity',
        'delivery'}`` dicts covering sends, failures and skips alike.
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


def clear_log() -> int:
    """
    Empty the notification history (channels are untouched).

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
