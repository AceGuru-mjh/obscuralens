"""
Persisted per-source reliability statistics and a circuit breaker.

The health table lives in the same SQLite database as the query history
(``config.db_config.sqlite_path``) and tracks, per ``(source, kind)`` pair:

  * ok / fail counters plus a derived reliability percentage
  * the current failure streak (``consecutive_failures``)
  * timestamps of the last success / failure and the last error text

A circuit breaker uses the failure streak together with
``app_config.source_failure_threshold`` and
``app_config.source_cooldown_seconds`` to keep failing sources out of the
request path until the cooldown elapses.  Everything fails open: unknown
sources, disabled health tracking and SQLite errors never block a lookup.

Thread safety: every operation opens a short-lived connection and writes
are serialised with a module lock, so the singleton can be shared across
the gather thread pool.

NOTE: :meth:`SourceHealth.source_allowed` deliberately does NOT consult
``config.is_source_enabled`` (the ``disabled_sources`` list).  Source gating
stays with the callers (``gather_all``), which already enforce it, so the
two concerns remain independent and composable.
"""

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import config

logger = logging.getLogger(__name__)

#: Writes are serialised so the gather thread pool cannot race the upserts.
_LOCK = threading.Lock()

_SCHEMA = '''
    CREATE TABLE IF NOT EXISTS source_health (
        source TEXT,
        kind TEXT,
        ok_count INTEGER DEFAULT 0,
        fail_count INTEGER DEFAULT 0,
        consecutive_failures INTEGER DEFAULT 0,
        last_ok TIMESTAMP,
        last_failure TIMESTAMP,
        last_error TEXT DEFAULT '',
        PRIMARY KEY (source, kind)
    )
'''


def _now() -> str:
    """Current UTC time as an ISO-8601 string (the stored timestamp format)."""
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    """Open a short-lived connection, creating the table when missing."""
    path = Path(config.db_config.sqlite_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    return conn


def _parse_ts(value: Any) -> Optional[datetime]:
    """Parse a stored timestamp; None when blank or malformed."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _as_utc(moment: datetime) -> datetime:
    """Treat naive timestamps as UTC so subtraction stays type-safe."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def _tripped(row: Dict[str, Any]) -> Optional[float]:
    """Remaining cooldown seconds when the circuit for this row is open.

    The circuit is open while the failure streak has reached
    ``source_failure_threshold`` AND the last failure is younger than
    ``source_cooldown_seconds``.  Returns None (closed) otherwise.
    """
    threshold = int(config.app_config.source_failure_threshold or 0)
    if threshold <= 0:
        return None
    consecutive = int(row.get('consecutive_failures') or 0)
    if consecutive < threshold:
        return None
    last_failure = _parse_ts(row.get('last_failure'))
    if last_failure is None:
        return None
    cooldown = float(config.app_config.source_cooldown_seconds or 0)
    elapsed = (datetime.now(timezone.utc) - _as_utc(last_failure)).total_seconds()
    remaining = cooldown - elapsed
    return remaining if remaining > 0 else None


class SourceHealth:
    """Persisted per-source reliability statistics with a circuit breaker.

    Every public method returns a safe default instead of raising when
    SQLite fails: ``[]`` for reads, ``(True, '')`` for availability checks
    and ``False`` / ``0`` for writes.
    """

    # -- writes ----------------------------------------------------------

    def record(self, kind: str, source: str, ok: bool,
               error: str = '') -> bool:
        """Upsert one outcome for a (source, kind) pair.

        ``ok`` bumps ``ok_count``, resets the failure streak and stamps
        ``last_ok``; failures bump ``fail_count`` and the streak, stamp
        ``last_failure`` and store the error text (capped at 200 chars).
        Returns False (and writes nothing) when health tracking is disabled
        or the database is unavailable.
        """
        if not config.app_config.source_health_enabled:
            return False
        source = str(source or '').strip()[:200]
        kind = str(kind or '').strip()[:100]
        if not source or not kind:
            return False
        now = _now()
        error = str(error or '')[:200]
        try:
            with _LOCK:
                conn = _connect()
                try:
                    cur = conn.cursor()
                    cur.execute(
                        'SELECT ok_count, fail_count, consecutive_failures '
                        'FROM source_health WHERE source = ? AND kind = ?',
                        (source, kind))
                    row = cur.fetchone()
                    if row is None:
                        cur.execute(
                            'INSERT INTO source_health '
                            '(source, kind, ok_count, fail_count, '
                            ' consecutive_failures, last_ok, last_failure, last_error) '
                            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                            (source, kind, 1 if ok else 0, 0 if ok else 1,
                             0 if ok else 1, now if ok else None,
                             None if ok else now, '' if ok else error))
                    elif ok:
                        cur.execute(
                            'UPDATE source_health SET ok_count = ok_count + 1, '
                            'consecutive_failures = 0, last_ok = ? '
                            'WHERE source = ? AND kind = ?',
                            (now, source, kind))
                    else:
                        cur.execute(
                            'UPDATE source_health SET fail_count = fail_count + 1, '
                            'consecutive_failures = consecutive_failures + 1, '
                            'last_failure = ?, last_error = ? '
                            'WHERE source = ? AND kind = ?',
                            (now, error, source, kind))
                    conn.commit()
                finally:
                    conn.close()
            return True
        except sqlite3.Error as exc:
            logger.warning('source_health: cannot record %s/%s: %s',
                           kind, source, exc)
            return False

    def record_batch(self, kind: str, status_map: Dict[str, Any]) -> int:
        """Record a ``gather_all``-style ``sources`` dict; returns rows written.

        ``status_map`` maps source names to ``{'ok': bool, 'error': str}``.
        ``plugin:*`` sources are included with their kind prefixed
        (``plugin:<kind>``) so plugin reliability stands apart.  Non-dict
        values are skipped; a no-op when health tracking is disabled.
        """
        if not config.app_config.source_health_enabled:
            return 0
        if not isinstance(status_map, dict):
            return 0
        kind = str(kind or '')
        recorded = 0
        for source, status in status_map.items():
            if not isinstance(status, dict):
                continue
            row_kind = kind
            if str(source).startswith('plugin:'):
                row_kind = f'plugin:{kind}'
            if self.record(row_kind, source, bool(status.get('ok')),
                           str(status.get('error') or '')):
                recorded += 1
        return recorded

    def reset(self, source: Optional[str] = None,
              kind: Optional[str] = None) -> int:
        """Delete health rows — all rows when ``source`` is None.

        ``kind`` further narrows the deletion when given.  Returns the
        number of rows removed (0 on database errors).
        """
        try:
            with _LOCK:
                conn = _connect()
                try:
                    cur = conn.cursor()
                    if source and kind:
                        cur.execute('DELETE FROM source_health '
                                    'WHERE source = ? AND kind = ?',
                                    (str(source), str(kind)))
                    elif source:
                        cur.execute('DELETE FROM source_health '
                                    'WHERE source = ?', (str(source),))
                    elif kind:
                        cur.execute('DELETE FROM source_health '
                                    'WHERE kind = ?', (str(kind),))
                    else:
                        cur.execute('DELETE FROM source_health')
                    deleted = max(cur.rowcount, 0)
                    conn.commit()
                finally:
                    conn.close()
            return deleted
        except sqlite3.Error as exc:
            logger.warning('source_health: cannot reset: %s', exc)
            return 0

    def prune(self, keep: int = 500) -> int:
        """Drop untested rows, then over-cap rows with the lowest usage.

        Rows with ``ok_count + fail_count == 0`` are always removed.  When
        more than ``keep`` rows remain afterwards, the least-used ones are
        deleted (ties broken alphabetically for determinism).  ``keep <= 0``
        disables the cap.  Returns the number of deleted rows.
        """
        try:
            with _LOCK:
                conn = _connect()
                try:
                    cur = conn.cursor()
                    cur.execute('DELETE FROM source_health '
                                'WHERE (ok_count + fail_count) = 0')
                    deleted = max(cur.rowcount, 0)
                    cur.execute('SELECT COUNT(*) FROM source_health')
                    total = int(cur.fetchone()[0])
                    keep = int(keep or 0)
                    if keep > 0 and total > keep:
                        cur.execute(
                            'DELETE FROM source_health WHERE rowid IN ('
                            '  SELECT rowid FROM source_health'
                            '  ORDER BY (ok_count + fail_count) ASC,'
                            '           source ASC, kind ASC'
                            '  LIMIT ?)', (total - keep,))
                        deleted += max(cur.rowcount, 0)
                    conn.commit()
                finally:
                    conn.close()
            return deleted
        except sqlite3.Error as exc:
            logger.warning('source_health: cannot prune: %s', exc)
            return 0

    # -- reads -----------------------------------------------------------

    def get_health(self, source: Optional[str] = None) -> List[Dict[str, Any]]:
        """Health rows (optionally filtered by source) with derived fields.

        Each row gains ``reliability`` (percent of successful calls, 0.0
        when untested) and ``state`` — 'healthy', 'tripped' while the
        circuit breaker is open, or 'untested' when both counters are 0.
        """
        try:
            rows = self._fetch_rows(source=source)
        except sqlite3.Error as exc:
            logger.warning('source_health: cannot read health table: %s', exc)
            return []
        return [self._with_derived(row) for row in rows]

    def is_available(self, source: str,
                     kind: Optional[str] = None) -> Tuple[bool, str]:
        """Circuit-breaker check returning ``(available, reason)``.

        A source is tripped when ANY of its rows has a failure streak at or
        above ``source_failure_threshold`` AND the last failure is younger
        than ``source_cooldown_seconds``; the reason then reads
        ``circuit open (<streak> consecutive failures, cooldown <n>s)``.
        Unknown sources, disabled health tracking and database errors all
        fail open with ``(True, '')``.
        """
        if not config.app_config.source_health_enabled:
            return (True, '')
        try:
            rows = self._fetch_rows(source=source, kind=kind)
        except sqlite3.Error as exc:
            logger.warning('source_health: cannot check circuit for %s: %s',
                           source, exc)
            return (True, '')
        for row in rows:
            remaining = _tripped(row)
            if remaining is not None:
                consecutive = int(row.get('consecutive_failures') or 0)
                return (False, f'circuit open ({consecutive} consecutive '
                               f'failures, cooldown {int(remaining)}s)')
        return (True, '')

    def source_allowed(self, source: str,
                       kind: Optional[str] = None) -> bool:
        """Availability flag only — ``is_available(source, kind)[0]``.

        This intentionally does NOT check ``config.is_source_enabled``: the
        ``disabled_sources`` list is enforced by the callers (gather_all
        already gates on it), so circuit breaking and source disabling stay
        independent concerns.
        """
        return self.is_available(source, kind)[0]

    def health_sections(self) -> List[Dict[str, Any]]:
        """Report sections: a summary grid plus a worst-100 reliability table."""
        try:
            rows = self._fetch_rows()
        except sqlite3.Error as exc:
            logger.warning('source_health: cannot build sections: %s', exc)
            return []
        derived = [self._with_derived(row) for row in rows]
        tripped = sum(1 for row in derived if row['state'] == 'tripped')
        attempted = [row for row in derived
                     if int(row['ok_count']) + int(row['fail_count']) > 0]
        average = (round(sum(row['reliability'] for row in attempted)
                         / len(attempted), 1) if attempted else 0.0)
        sections: List[Dict[str, Any]] = [{
            'title': 'Source Health', 'type': 'grid',
            'data': {
                'Sources tracked': len(derived),
                'Tripped': tripped,
                'Average reliability': f'{average}%',
            },
        }]
        if derived:
            ordered = sorted(
                derived,
                key=lambda row: (-int(row['fail_count']), str(row['source'])))
            sections.append({
                'title': 'Source Reliability (worst 100)', 'type': 'table',
                'columns': ['Source', 'Kind', 'OK', 'Fail', 'Reliability',
                            'State', 'Last error'],
                'rows': [[row['source'], row['kind'], row['ok_count'],
                          row['fail_count'], f"{row['reliability']}%",
                          row['state'], row['last_error'] or '']
                         for row in ordered[:100]],
            })
        return sections

    # -- internals -------------------------------------------------------

    def _fetch_rows(self, source: Optional[str] = None,
                    kind: Optional[str] = None) -> List[Dict[str, Any]]:
        """Raw table rows ordered by (source, kind); may raise sqlite3.Error."""
        query = 'SELECT * FROM source_health'
        conditions, params = [], []
        if source:
            conditions.append('source = ?')
            params.append(str(source))
        if kind:
            conditions.append('kind = ?')
            params.append(str(kind))
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        query += ' ORDER BY source ASC, kind ASC'
        conn = _connect()
        try:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def _with_derived(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Copy a raw row, adding the derived reliability and state."""
        out = dict(row)
        ok = int(row.get('ok_count') or 0)
        fail = int(row.get('fail_count') or 0)
        total = ok + fail
        out['reliability'] = round(ok / total * 100, 1) if total else 0.0
        if total == 0:
            out['state'] = 'untested'
        elif _tripped(row) is not None:
            out['state'] = 'tripped'
        else:
            out['state'] = 'healthy'
        return out


#: Shared singleton used by trackers, the CLI and the reporting layer.
health = SourceHealth()
