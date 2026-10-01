"""
Target watchlist with snapshot history and change detection.

Adds OSINT targets to a local SQLite watchlist, stores a JSON snapshot for
every successful check, and diffs successive runs so the CLI can report what
appeared, disappeared or changed since the previous lookup.
"""

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import config
from .utils.validators import validate_domain, validate_email, validate_ip, validate_phone, validate_username

# Fields that change on every lookup and would otherwise show up as noise.
VOLATILE_KEYS = {
    'current_time',
    'domain_age_days',
    'expires_in_days',
    'response_time',
    'last_update',
    'last_online',
    'timezone_utc',
    'elapsed_ms',
}

_ENTRY_SELECT = '''
    SELECT w.id, w.target, w.kind, w.label, w.created_at, w.last_checked,
           COUNT(s.id) AS snapshots
    FROM watchlist w
    LEFT JOIN watch_snapshots s ON s.watch_id = w.id
'''


def watchlist_path() -> Path:
    """Database path for the watchlist (shared with the query history)."""
    return Path(config.db_config.sqlite_path)


@dataclass
class WatchEntry:
    """A watched target."""
    id: Optional[int] = None
    target: str = ""
    kind: str = ""
    label: str = ""
    created_at: Optional[str] = None
    last_checked: Optional[str] = None
    snapshots: int = 0


@dataclass
class WatchDiff:
    """Change report for one watch check."""
    watch_id: int
    target: str
    kind: str
    checked_at: str
    is_first: bool
    added: Dict[str, str]
    removed: Dict[str, str]
    changed: Dict[str, Any]  # field -> {'from': old, 'to': new}
    success: bool = True
    error: str = ""


def _detect_kind(target: str) -> Optional[str]:
    """Best-effort kind detection for a bare target string."""
    if validate_ip(target)[0]:
        return 'ip'
    if validate_email(target)[0]:
        return 'email'
    if validate_phone(target)[0]:
        return 'phone'
    # The validators are intentionally loose, so a single label can look like
    # both a username and a domain; a dot tips the balance towards domain.
    if '.' in target and validate_domain(target)[0]:
        return 'domain'
    if validate_username(target)[0]:
        return 'username'
    return None


def _default_checker(kind: str, target: str) -> Dict[str, Any]:
    """Run the tracker matching kind (imported lazily to avoid cycles)."""
    from .trackers import DomainTracker, EmailTracker, IPTracker, PhoneTracker, UsernameTracker
    trackers = {
        'ip': IPTracker,
        'phone': PhoneTracker,
        'username': UsernameTracker,
        'email': EmailTracker,
        'domain': DomainTracker,
    }
    tracker_class = trackers.get(kind)
    if tracker_class is None:
        raise ValueError(f'unsupported kind: {kind}')
    return tracker_class().track(target)


def flatten(result: Dict[str, Any]) -> Dict[str, str]:
    """
    Reduce a tracker result to a flat field -> string mapping.

    Username results are keyed per platform; info blocks are keyed per field
    with JSON-encoded values. Volatile fields are dropped so they cannot
    produce false diffs.
    """
    if not isinstance(result, dict):
        return {}

    results = result.get('results')
    if isinstance(results, list):
        flat = {}
        for item in results:
            if not isinstance(item, dict):
                continue
            platform = item.get('platform', '')
            flat[f'platform:{platform}'] = str(item.get('status', 'unknown'))
        return flat

    info = result.get('info')
    if isinstance(info, dict):
        source: Dict[str, Any] = info
    else:
        return {'result': json.dumps(result, sort_keys=True, default=str)}

    return {key: json.dumps(value, sort_keys=True, default=str)
            for key, value in source.items() if key not in VOLATILE_KEYS}


def _decode(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def diff_snapshots(old: Dict[str, str],
                   new: Dict[str, str]
                   ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, Any]]:
    """Diff two flattened snapshots into (added, removed, changed)."""
    added = {key: value for key, value in new.items() if key not in old}
    removed = {key: value for key, value in old.items() if key not in new}
    changed: Dict[str, Any] = {}
    for key, value in old.items():
        if key not in new or value == new[key]:
            continue
        changed[key] = {'from': _decode(value), 'to': _decode(new[key])}
    return added, removed, changed


def _row_to_entry(row: sqlite3.Row) -> WatchEntry:
    return WatchEntry(
        id=row['id'],
        target=row['target'],
        kind=row['kind'],
        label=row['label'] or '',
        created_at=row['created_at'],
        last_checked=row['last_checked'],
        snapshots=int(row['snapshots']),
    )


class WatchlistManager:
    """SQLite-backed watchlist and snapshot store."""

    def __init__(self, path: Optional[str] = None):
        self.path = str(path) if path else str(watchlist_path())
        self._init_database()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        try:
            yield conn
        finally:
            conn.close()

    def _init_database(self) -> None:
        """Create the watchlist and snapshot tables/indexes if missing."""
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    label TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_checked TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS watch_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    watch_id INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_watch_snapshots_watch_id
                ON watch_snapshots(watch_id)
            ''')
            conn.commit()

    def add(self, target: str, kind: Optional[str] = None,
            label: str = '') -> int:
        """Add a target, auto-detecting its kind when not given."""
        value = (target or '').strip()
        if not value:
            raise ValueError('unrecognised target')

        detected = kind.strip().lower() if kind else _detect_kind(value)
        if not detected:
            raise ValueError('unrecognised target')
        if detected in ('ip', 'email', 'domain'):
            value = value.lower()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'INSERT INTO watchlist (target, kind, label) VALUES (?, ?, ?)',
                    (value, detected, label))
                conn.commit()
            except sqlite3.IntegrityError:
                raise ValueError('already watched') from None
            return cursor.lastrowid

    def remove(self, identifier: Any) -> int:
        """Delete a watch by id (int) or target (str); returns rows removed."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if isinstance(identifier, int):
                cursor.execute('DELETE FROM watchlist WHERE id = ?',
                               (identifier,))
            else:
                cursor.execute('DELETE FROM watchlist WHERE target = ?',
                               (str(identifier).strip(),))
            conn.commit()
            return cursor.rowcount

    def list(self) -> List[WatchEntry]:
        """All watches with their snapshot counts, oldest first."""
        with self._get_connection() as conn:
            rows = conn.execute(
                _ENTRY_SELECT + ' GROUP BY w.id ORDER BY w.id').fetchall()
        return [_row_to_entry(row) for row in rows]

    def get(self, identifier: Any) -> Optional[WatchEntry]:
        """Fetch one watch by id (int) or target (str)."""
        with self._get_connection() as conn:
            if isinstance(identifier, int):
                row = conn.execute(
                    _ENTRY_SELECT + ' WHERE w.id = ? GROUP BY w.id',
                    (identifier,)).fetchone()
            else:
                row = conn.execute(
                    _ENTRY_SELECT + ' WHERE w.target = ? GROUP BY w.id',
                    (str(identifier).strip(),)).fetchone()
        return _row_to_entry(row) if row else None

    def check(self, identifier: Any = None,
              checker: Optional[Callable[[str, str], Dict[str, Any]]] = None
              ) -> List[WatchDiff]:
        """Check one watch (id or target) or every watch; returns diffs."""
        checker = checker or _default_checker
        if identifier is None:
            entries: List[WatchEntry] = self.list()
        else:
            entry = self.get(identifier)
            entries = [entry] if entry else []
        return [self._check_entry(entry, checker) for entry in entries]

    def _check_entry(self, entry: WatchEntry,
                     checker: Callable[[str, str], Dict[str, Any]]
                     ) -> WatchDiff:
        checked_at = datetime.now(timezone.utc).isoformat(timespec='seconds')

        try:
            result = checker(entry.kind, entry.target)
        except Exception as exc:  # one broken check must not kill the run
            return WatchDiff(
                watch_id=entry.id, target=entry.target, kind=entry.kind,
                checked_at=checked_at, is_first=False, added={}, removed={},
                changed={}, success=False, error=type(exc).__name__)

        flat = flatten(result)
        previous = self._latest_snapshot(entry.id)
        if previous is None:
            added, removed, changed = dict(flat), {}, {}
            is_first = True
        else:
            added, removed, changed = diff_snapshots(previous, flat)
            is_first = False

        self._store_snapshot(entry.id, flat, checked_at)
        return WatchDiff(
            watch_id=entry.id, target=entry.target, kind=entry.kind,
            checked_at=checked_at, is_first=is_first, added=added,
            removed=removed, changed=changed, success=True)

    def _latest_snapshot(self, watch_id: int) -> Optional[Dict[str, str]]:
        with self._get_connection() as conn:
            row = conn.execute('''
                SELECT data FROM watch_snapshots
                WHERE watch_id = ? ORDER BY id DESC LIMIT 1
            ''', (watch_id,)).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row['data'])
        except (TypeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _store_snapshot(self, watch_id: int, flat: Dict[str, str],
                        checked_at: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                'INSERT INTO watch_snapshots (watch_id, data) VALUES (?, ?)',
                (watch_id, json.dumps(flat, sort_keys=True)))
            conn.execute(
                'UPDATE watchlist SET last_checked = ? WHERE id = ?',
                (checked_at, watch_id))
            conn.commit()

    def history(self, identifier: Any, limit: int = 20) -> List[Dict[str, Any]]:
        """Raw snapshots for a watch, newest first (handy for the CLI)."""
        entry = self.get(identifier)
        if entry is None:
            return []
        with self._get_connection() as conn:
            rows = conn.execute('''
                SELECT id, created_at, data FROM watch_snapshots
                WHERE watch_id = ? ORDER BY id DESC LIMIT ?
            ''', (entry.id, limit)).fetchall()
        return [{'id': row['id'], 'created_at': row['created_at'],
                 'data': row['data']} for row in rows]


# Global watchlist instance
watchlist = WatchlistManager()
