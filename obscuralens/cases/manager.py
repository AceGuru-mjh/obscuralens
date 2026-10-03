"""
Case management store for ObscuraLens v4.0.

A *case* groups indicators (items), free-form notes and tags for one
investigation. The store is SQLite-backed and shares its database file with
the query history (``config.db_config.sqlite_path``), mirroring the
connection conventions of ``database.py`` / ``watchlist.py``:

  * short-lived connections with a 15s busy timeout and ``sqlite3.Row``
    row factory, so concurrent CLI/web/TUI processes do not fight over locks
  * ``CREATE TABLE IF NOT EXISTS`` so any build can open any database file
  * ``PRAGMA foreign_keys = ON`` on every connection (cascading deletes)
  * every mutation bumps ``cases.updated_at`` (single "recent activity"
    ordering for the case list)

Error contract: every public operation swallows ``sqlite3.Error`` and reports
``{'error': ...}`` (dict results), ``None`` (optional results), ``[]`` (list
results) or ``False`` (bool results) instead of raising to the caller. The
only exception is ``export_case`` with an unsupported format, which raises
``ValueError`` so bad CLI input fails loudly.
"""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import config

# Kinds accepted for case items. ``add_item(kind='auto')`` detects the kind
# via ``investigate.detect_kind`` and falls back to 'other'; plain 'other'
# stores any free-form indicator that no tracker understands.
KNOWN_KINDS = ('ip', 'phone', 'username', 'email', 'domain', 'crypto', 'hash',
               'url', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords', 'other')

# Values allowed for cases.status (enforced by the table CHECK too).
CASE_STATUSES = ('open', 'closed', 'archived')

# Kinds whose values are case-insensitive in the real world; stored
# lower-cased so the UNIQUE constraint cannot be bypassed with caps.
_LOWERED_KINDS = ('ip', 'email', 'domain')


def cases_path() -> Path:
    """SQLite file backing case management (shared with query history)."""
    return Path(config.db_config.sqlite_path)


def cases_enabled() -> bool:
    """Whether case management is switched on in the configuration."""
    return bool(config.app_config.cases_enabled)


def _md_cell(value: Any) -> str:
    """Render a table cell for the Markdown export (pipes escaped)."""
    text = '' if value is None else str(value)
    return text.replace('|', '\\|').replace('\n', ' ')


def _render_case_markdown(case: Dict[str, Any]) -> str:
    """Render a ``get_case`` payload as a Markdown document."""
    lines: List[str] = [f"# Case {case.get('id')}: {case.get('name', '')}", '']
    description = case.get('description') or ''
    if description:
        lines += [str(description), '']
    lines += [
        '| Field | Value |',
        '| --- | --- |',
        f"| Status | {case.get('status', '')} |",
        f"| Created | {case.get('created_at') or ''} |",
        f"| Updated | {case.get('updated_at') or ''} |",
        '',
    ]
    tags = case.get('tags') or []
    lines.append(f"**Tags:** {', '.join(tags) if tags else '(none)'}")
    lines.append('')

    items = case.get('items') or []
    lines.append(f"## Items ({len(items)})")
    lines.append('')
    if items:
        lines += ['| Kind | Value | Note | Added |', '| --- | --- | --- | --- |']
        for item in items:
            lines.append('| {} | {} | {} | {} |'.format(
                _md_cell(item.get('kind')), _md_cell(item.get('value')),
                _md_cell(item.get('note')), _md_cell(item.get('added_at'))))
    else:
        lines.append('_(no items)_')
    lines.append('')

    notes = case.get('notes') or []
    lines.append(f"## Notes ({len(notes)})")
    lines.append('')
    if notes:
        for note in notes:
            lines.append(f"### {note.get('created_at') or '(undated)'}")
            lines.append('')
            lines.append(str(note.get('body') or ''))
            lines.append('')
    else:
        lines.append('_(no notes)_')
    return '\n'.join(lines).rstrip() + '\n'


class CaseManager:
    """SQLite-backed case, item, note and tag store."""

    def __init__(self, path: Optional[str] = None):
        self.path = str(path) if path else str(cases_path())
        self._init_database()

    # -- plumbing ---------------------------------------------------------

    @contextmanager
    def _get_connection(self):
        """Open a short-lived connection (mirrors database.py)."""
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        try:
            yield conn
        finally:
            conn.close()

    def _init_database(self) -> None:
        """Create the case tables and indexes if they are missing."""
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cases (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        description TEXT DEFAULT '',
                        status TEXT DEFAULT 'open'
                            CHECK (status IN ('open', 'closed', 'archived')),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS case_items (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id INTEGER NOT NULL
                            REFERENCES cases(id) ON DELETE CASCADE,
                        kind TEXT NOT NULL,
                        value TEXT NOT NULL,
                        note TEXT DEFAULT '',
                        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE (case_id, kind, value)
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS case_notes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id INTEGER NOT NULL
                            REFERENCES cases(id) ON DELETE CASCADE,
                        body TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS case_tags (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id INTEGER NOT NULL
                            REFERENCES cases(id) ON DELETE CASCADE,
                        tag TEXT NOT NULL,
                        UNIQUE (case_id, tag)
                    )
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_case_items_case
                        ON case_items(case_id)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_case_items_value
                        ON case_items(value)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_case_notes_case
                        ON case_notes(case_id)
                ''')
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_case_tags_case
                        ON case_tags(case_id)
                ''')
                conn.commit()
        except (sqlite3.Error, OSError):
            # A broken database location must never crash the import; every
            # operation re-reports the underlying error to its caller.
            pass

    @staticmethod
    def _touch(cursor: sqlite3.Cursor, case_id: int) -> None:
        """Bump cases.updated_at; the caller owns the transaction."""
        cursor.execute(
            'UPDATE cases SET updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            (case_id,))

    @staticmethod
    def _detect_kind(value: str) -> str:
        """Best-effort kind detection with an 'other' fallback."""
        try:
            from ..investigate import detect_kind
        except ImportError:
            return 'other'
        try:
            return detect_kind(value) or 'other'
        except Exception:
            return 'other'

    @staticmethod
    def _case_exists(cursor: sqlite3.Cursor, case_id: int) -> bool:
        cursor.execute('SELECT id FROM cases WHERE id = ?', (case_id,))
        return cursor.fetchone() is not None

    # -- case lifecycle ---------------------------------------------------

    def create_case(self, name: str, description: str = '') -> Dict[str, Any]:
        """
        Create a case and return its full row.

        Duplicate names are not an error: ``{'error': 'case exists',
        'id': <existing id>}`` is returned so the CLI can open the existing
        case instead.
        """
        name = str(name or '').strip()
        if not name:
            return {'error': 'case name cannot be empty'}
        description = str(description or '')
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM cases WHERE name = ?', (name,))
                existing = cursor.fetchone()
                if existing is not None:
                    return {'error': 'case exists', 'id': existing['id']}
                cursor.execute(
                    'INSERT INTO cases (name, description) VALUES (?, ?)',
                    (name, description))
                case_id = cursor.lastrowid
                conn.commit()
                cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
                return dict(cursor.fetchone())
        except sqlite3.IntegrityError:
            # Lost a race against a concurrent insert with the same name.
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT id FROM cases WHERE name = ?', (name,))
                    row = cursor.fetchone()
                    if row is not None:
                        return {'error': 'case exists', 'id': row['id']}
            except sqlite3.Error:
                pass
            return {'error': 'case exists'}
        except sqlite3.Error as e:
            return {'error': f'database error: {e}'}

    def list_cases(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        """
        List cases (newest activity first) with item/note/tag counts and a
        per-kind item breakdown. Archived cases are hidden unless requested.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                where = '' if include_archived else " WHERE c.status != 'archived'"
                cursor.execute(f'''
                    SELECT c.*,
                        (SELECT COUNT(*) FROM case_items i
                            WHERE i.case_id = c.id) AS item_count,
                        (SELECT COUNT(*) FROM case_notes n
                            WHERE n.case_id = c.id) AS note_count,
                        (SELECT COUNT(*) FROM case_tags t
                            WHERE t.case_id = c.id) AS tag_count
                    FROM cases c{where}
                    ORDER BY c.updated_at DESC, c.id DESC
                ''')
                rows = [dict(row) for row in cursor.fetchall()]
                cursor.execute('''
                    SELECT case_id, kind, COUNT(*) AS count
                    FROM case_items GROUP BY case_id, kind
                ''')
                by_kind: Dict[int, Dict[str, int]] = {}
                for row in cursor.fetchall():
                    by_kind.setdefault(row['case_id'], {})[row['kind']] = row['count']
            for row in rows:
                row['items_by_kind'] = by_kind.get(row['id'], {})
            return rows
        except sqlite3.Error:
            return []

    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Return one case with its items, notes and tags (None if unknown)."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
                row = cursor.fetchone()
                if row is None:
                    return None
                case = dict(row)
                cursor.execute('''
                    SELECT * FROM case_items WHERE case_id = ?
                    ORDER BY added_at, id
                ''', (case_id,))
                case['items'] = [dict(item) for item in cursor.fetchall()]
                cursor.execute('''
                    SELECT * FROM case_notes WHERE case_id = ?
                    ORDER BY created_at, id
                ''', (case_id,))
                case['notes'] = [dict(note) for note in cursor.fetchall()]
                cursor.execute('''
                    SELECT tag FROM case_tags WHERE case_id = ? ORDER BY tag
                ''', (case_id,))
                case['tags'] = [row['tag'] for row in cursor.fetchall()]
                case['item_count'] = len(case['items'])
                case['note_count'] = len(case['notes'])
                case['tag_count'] = len(case['tags'])
                return case
        except sqlite3.Error:
            return None

    def _set_status(self, case_id: int, status: str) -> Optional[Dict[str, Any]]:
        """Set a case status and return the refreshed row (None if unknown)."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE cases
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (status, case_id))
                if cursor.rowcount == 0:
                    return None
                conn.commit()
                cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
                return dict(cursor.fetchone())
        except sqlite3.Error:
            return None

    def close_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Mark a case as closed."""
        return self._set_status(case_id, 'closed')

    def reopen_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Re-open a closed or archived case."""
        return self._set_status(case_id, 'open')

    def archive_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Archive a case (hidden from the default listing)."""
        return self._set_status(case_id, 'archived')

    def delete_case(self, case_id: int) -> bool:
        """Delete a case; items, notes and tags cascade. Unknown id -> False."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM cases WHERE id = ?', (case_id,))
                deleted = cursor.rowcount > 0
                conn.commit()
                return deleted
        except sqlite3.Error:
            return False

    # -- items ------------------------------------------------------------

    def add_item(self, case_id: int, kind: str, value: str,
                 note: str = '') -> Dict[str, Any]:
        """
        Add an indicator to a case.

        ``kind='auto'`` detects the kind (ip/domain/email/phone/username via
        ``investigate.detect_kind``) and falls back to ``other``. Items cannot
        be added to closed or archived cases; duplicates (same kind + value,
        compared case-insensitively) are rejected.
        """
        value = str(value or '').strip()
        if not value:
            return {'error': 'item value cannot be empty'}
        kind = str(kind or '').strip().lower()
        if kind == 'auto':
            kind = self._detect_kind(value)
        if kind not in KNOWN_KINDS:
            return {'error': f'unknown kind: {kind}'}
        if kind in _LOWERED_KINDS:
            value = value.lower()
        note = str(note or '')
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT status FROM cases WHERE id = ?', (case_id,))
                row = cursor.fetchone()
                if row is None:
                    return {'error': 'case not found'}
                if row['status'] == 'closed':
                    return {'error': 'case closed'}
                if row['status'] == 'archived':
                    return {'error': 'case archived'}
                cursor.execute('''
                    SELECT id FROM case_items
                    WHERE case_id = ? AND kind = ? AND LOWER(value) = LOWER(?)
                ''', (case_id, kind, value))
                if cursor.fetchone() is not None:
                    return {'error': 'duplicate'}
                cursor.execute('''
                    INSERT INTO case_items (case_id, kind, value, note)
                    VALUES (?, ?, ?, ?)
                ''', (case_id, kind, value, note))
                item_id = cursor.lastrowid
                self._touch(cursor, case_id)
                conn.commit()
                cursor.execute('SELECT * FROM case_items WHERE id = ?', (item_id,))
                return dict(cursor.fetchone())
        except sqlite3.IntegrityError:
            return {'error': 'duplicate'}
        except sqlite3.Error as e:
            return {'error': f'database error: {e}'}

    def remove_item(self, case_id: int, item_id: int) -> bool:
        """Remove one item from a case (False when it does not exist)."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM case_items WHERE id = ? AND case_id = ?
                ''', (item_id, case_id))
                removed = cursor.rowcount > 0
                if removed:
                    self._touch(cursor, case_id)
                conn.commit()
                return removed
        except sqlite3.Error:
            return False

    # -- notes and tags ---------------------------------------------------

    def add_note(self, case_id: int, body: str) -> Dict[str, Any]:
        """
        Append a free-form note to a case.

        Notes stay allowed on closed/archived cases so investigators can
        record closing remarks, but the case must still exist.
        """
        body = str(body or '').strip()
        if not body:
            return {'error': 'note body cannot be empty'}
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if not self._case_exists(cursor, case_id):
                    return {'error': 'case not found'}
                cursor.execute(
                    'INSERT INTO case_notes (case_id, body) VALUES (?, ?)',
                    (case_id, body))
                note_id = cursor.lastrowid
                self._touch(cursor, case_id)
                conn.commit()
                cursor.execute('SELECT * FROM case_notes WHERE id = ?', (note_id,))
                return dict(cursor.fetchone())
        except sqlite3.Error as e:
            return {'error': f'database error: {e}'}

    def add_tag(self, case_id: int, tag: str) -> Dict[str, Any]:
        """Tag a case (tags are normalised to lower case; duplicates reject)."""
        tag = str(tag or '').strip().lower()
        if not tag:
            return {'error': 'tag cannot be empty'}
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if not self._case_exists(cursor, case_id):
                    return {'error': 'case not found'}
                cursor.execute('''
                    SELECT id FROM case_tags
                    WHERE case_id = ? AND LOWER(tag) = LOWER(?)
                ''', (case_id, tag))
                if cursor.fetchone() is not None:
                    return {'error': 'duplicate'}
                cursor.execute(
                    'INSERT INTO case_tags (case_id, tag) VALUES (?, ?)',
                    (case_id, tag))
                tag_id = cursor.lastrowid
                self._touch(cursor, case_id)
                conn.commit()
                return {'id': tag_id, 'case_id': case_id, 'tag': tag}
        except sqlite3.IntegrityError:
            return {'error': 'duplicate'}
        except sqlite3.Error as e:
            return {'error': f'database error: {e}'}

    def remove_tag(self, case_id: int, tag: str) -> bool:
        """Remove a tag (case-insensitive); False when it was not there."""
        tag = str(tag or '').strip().lower()
        if not tag:
            return False
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM case_tags WHERE case_id = ? AND LOWER(tag) = LOWER(?)
                ''', (case_id, tag))
                removed = cursor.rowcount > 0
                if removed:
                    self._touch(cursor, case_id)
                conn.commit()
                return removed
        except sqlite3.Error:
            return False

    # -- search, stats and export -----------------------------------------

    def find_cases(self, value: str) -> List[Dict[str, Any]]:
        """
        Find cases containing an item whose value matches (case-insensitive).

        Each hit is the case row plus a ``matched`` list of the items that
        carry the requested value.
        """
        value = str(value or '').strip()
        if not value:
            return []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT DISTINCT c.* FROM cases c
                    JOIN case_items i ON i.case_id = c.id
                    WHERE LOWER(i.value) = LOWER(?)
                    ORDER BY c.updated_at DESC, c.id DESC
                ''', (value,))
                rows = [dict(row) for row in cursor.fetchall()]
                for row in rows:
                    cursor.execute('''
                        SELECT kind, value, note FROM case_items
                        WHERE case_id = ? AND LOWER(value) = LOWER(?)
                        ORDER BY added_at, id
                    ''', (row['id'], value))
                    row['matched'] = [dict(match) for match in cursor.fetchall()]
                return rows
        except sqlite3.Error:
            return []

    def case_stats(self) -> Dict[str, Any]:
        """Aggregate counts: cases by status plus total items and notes."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) AS total,
                        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open,
                        SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) AS closed,
                        SUM(CASE WHEN status = 'archived' THEN 1 ELSE 0 END) AS archived
                    FROM cases
                ''')
                row = cursor.fetchone()
                cursor.execute('SELECT COUNT(*) AS n FROM case_items')
                items_total = cursor.fetchone()['n']
                cursor.execute('SELECT COUNT(*) AS n FROM case_notes')
                notes_total = cursor.fetchone()['n']
                return {
                    'total': row['total'] or 0,
                    'open': row['open'] or 0,
                    'closed': row['closed'] or 0,
                    'archived': row['archived'] or 0,
                    'items_total': items_total,
                    'notes_total': notes_total,
                }
        except sqlite3.Error as e:
            return {'error': f'database error: {e}'}

    def export_case(self, case_id: int, fmt: str = 'markdown') -> Optional[str]:
        """
        Export a case as Markdown or JSON text.

        Raises ``ValueError`` for any other format (bad CLI input should fail
        loudly); returns None when the case does not exist or the database
        fails.
        """
        fmt = str(fmt or 'markdown').strip().lower()
        if fmt not in ('markdown', 'json'):
            raise ValueError(
                f"unsupported export format {fmt!r} (use 'markdown' or 'json')")
        case = self.get_case(case_id)
        if case is None:
            return None
        if fmt == 'json':
            return json.dumps(case, indent=2, default=str)
        return _render_case_markdown(case)

    # -- report sections ----------------------------------------------------

    def cases_sections(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        """Report sections listing every case plus aggregate statistics."""
        sections: List[Dict[str, Any]] = []
        stats = self.case_stats()
        if 'error' not in stats:
            sections.append({
                'title': 'Case Statistics', 'type': 'grid', 'data': {
                    'Total cases': stats['total'],
                    'Open': stats['open'],
                    'Closed': stats['closed'],
                    'Archived': stats['archived'],
                    'Items': stats['items_total'],
                    'Notes': stats['notes_total'],
                },
            })
        rows = []
        for case in self.list_cases(include_archived=include_archived):
            kinds = case.get('items_by_kind') or {}
            kinds_text = ', '.join(f'{kind}:{count}'
                                   for kind, count in sorted(kinds.items()))
            rows.append([
                case['id'], case['name'], case.get('status', ''),
                case.get('item_count', 0), case.get('note_count', 0),
                case.get('tag_count', 0), kinds_text or '-',
                case.get('created_at', ''),
            ])
        sections.append({
            'title': 'Cases', 'type': 'table',
            'columns': ['ID', 'Name', 'Status', 'Items', 'Notes', 'Tags',
                        'Kinds', 'Created'],
            'rows': rows,
        })
        return sections

    def case_sections(self, case_id: int) -> List[Dict[str, Any]]:
        """Report sections for one case (empty list when unknown)."""
        case = self.get_case(case_id)
        if case is None:
            return []
        items = case.get('items') or []
        notes = case.get('notes') or []
        tags = case.get('tags') or []
        return [
            {
                'title': f"Case {case['id']}: {case['name']}", 'type': 'grid',
                'data': {
                    'Status': case.get('status'),
                    'Description': case.get('description') or '(none)',
                    'Created': case.get('created_at'),
                    'Updated': case.get('updated_at'),
                    'Tags': ', '.join(tags) if tags else '(none)',
                },
            },
            {
                'title': f'Items ({len(items)})', 'type': 'table',
                'columns': ['Kind', 'Value', 'Note', 'Added'],
                'rows': [[item.get('kind'), item.get('value'),
                          item.get('note') or '', item.get('added_at')]
                         for item in items],
            },
            {
                'title': f'Notes ({len(notes)})', 'type': 'table',
                'columns': ['Created', 'Body'],
                'rows': [[note.get('created_at'), note.get('body')]
                         for note in notes],
            },
        ]


# Shared singleton, mirroring `db` in database.py. Created lazily enough to
# pick up OBSCURALENS_SQLITE_PATH (tests redirect it before importing).
cases = CaseManager()


def cases_sections(include_archived: bool = False) -> List[Dict[str, Any]]:
    """Report sections listing every case (uses the shared singleton)."""
    return cases.cases_sections(include_archived=include_archived)


def case_sections(case_id: int) -> List[Dict[str, Any]]:
    """Report sections for one case (uses the shared singleton)."""
    return cases.case_sections(case_id)
