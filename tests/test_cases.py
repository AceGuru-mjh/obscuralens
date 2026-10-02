"""Case management tests: one temporary SQLite file per test, fully offline."""

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest

from obscuralens.cases import cases as cases_singleton
from obscuralens.cases.manager import (
    KNOWN_KINDS,
    CaseManager,
    case_sections,
    cases_enabled,
    cases_path,
    cases_sections,
)
from obscuralens.config import config


@pytest.fixture()
def manager(tmp_env, monkeypatch):
    """A CaseManager on its own temporary database file."""
    monkeypatch.setattr(config.db_config, 'sqlite_path', str(tmp_env / 'cases.db'))
    return CaseManager()


def test_module_singleton_and_helpers():
    assert isinstance(cases_singleton, CaseManager)
    # The singleton binds to the redirected OBSCURALENS_SQLITE_PATH set by
    # conftest before the package was imported.
    assert cases_singleton.path == os.environ['OBSCURALENS_SQLITE_PATH']
    assert cases_path() == Path(os.environ['OBSCURALENS_SQLITE_PATH'])
    assert cases_enabled() is True
    assert KNOWN_KINDS == ('ip', 'phone', 'username', 'email', 'domain',
                           'crypto', 'hash', 'url', 'cve', 'asn', 'other')


def test_create_case_and_duplicate(manager):
    case = manager.create_case('Phishing Probe', 'look-alike domain report')
    assert 'error' not in case
    assert case['name'] == 'Phishing Probe'
    assert case['description'] == 'look-alike domain report'
    assert case['status'] == 'open'
    assert case['id'] > 0
    assert case['created_at']
    assert case['updated_at']

    again = manager.create_case('Phishing Probe', 'different description')
    assert again == {'error': 'case exists', 'id': case['id']}
    # The original description is untouched by the duplicate attempt.
    assert manager.get_case(case['id'])['description'] == 'look-alike domain report'
    assert 'error' in manager.create_case('')


def test_empty_database_lists_and_stats(manager):
    assert manager.list_cases() == []
    assert manager.case_stats() == {
        'total': 0, 'open': 0, 'closed': 0, 'archived': 0,
        'items_total': 0, 'notes_total': 0,
    }
    assert manager.cases_sections()[-1]['rows'] == []
    assert manager.get_case(1) is None


def test_list_cases_counts_and_kind_breakdown(manager):
    first = manager.create_case('First')
    manager.create_case('Second')
    manager.add_item(first['id'], 'ip', '8.8.8.8')
    manager.add_item(first['id'], 'ip', '1.1.1.1')
    manager.add_item(first['id'], 'domain', 'example.com')
    manager.add_note(first['id'], 'note body')
    manager.add_tag(first['id'], 'phishing')

    rows = {case['name']: case for case in manager.list_cases()}
    assert rows['First']['item_count'] == 3
    assert rows['First']['note_count'] == 1
    assert rows['First']['tag_count'] == 1
    assert rows['First']['items_by_kind'] == {'ip': 2, 'domain': 1}
    assert rows['Second']['item_count'] == 0
    assert rows['Second']['items_by_kind'] == {}
    assert rows['Second']['note_count'] == 0


def test_get_case_bundle(manager):
    case = manager.create_case('Bundle', 'description here')
    manager.add_item(case['id'], 'ip', '8.8.8.8', note='resolver')
    manager.add_note(case['id'], 'body text')
    manager.add_tag(case['id'], 'Phishing')  # tags normalise to lower case

    bundle = manager.get_case(case['id'])
    assert bundle['description'] == 'description here'
    assert bundle['item_count'] == 1
    assert bundle['items'][0]['kind'] == 'ip'
    assert bundle['items'][0]['value'] == '8.8.8.8'
    assert bundle['items'][0]['note'] == 'resolver'
    assert bundle['note_count'] == 1
    assert bundle['notes'][0]['body'] == 'body text'
    assert bundle['tags'] == ['phishing']
    assert manager.get_case(424242) is None


def test_lifecycle_close_reopen_archive(manager):
    case = manager.create_case('Life')
    case_id = case['id']

    closed = manager.close_case(case_id)
    assert closed['status'] == 'closed'

    reopened = manager.reopen_case(case_id)
    assert reopened['status'] == 'open'

    archived = manager.archive_case(case_id)
    assert archived['status'] == 'archived'
    # Archived cases are hidden from the default listing ...
    assert all(row['id'] != case_id for row in manager.list_cases())
    # ... but visible when explicitly requested.
    assert any(row['id'] == case_id
               for row in manager.list_cases(include_archived=True))

    assert manager.close_case(99999) is None
    assert manager.reopen_case(99999) is None
    assert manager.archive_case(99999) is None


def test_delete_case_cascades_and_reports(manager):
    case = manager.create_case('Cascade')
    manager.add_item(case['id'], 'ip', '1.1.1.1')
    manager.add_note(case['id'], 'note')
    manager.add_tag(case['id'], 'tag')

    conn = sqlite3.connect(manager.path)
    try:
        assert conn.execute('SELECT COUNT(*) FROM case_items').fetchone()[0] == 1
    finally:
        conn.close()

    assert manager.delete_case(case['id']) is True
    assert manager.delete_case(case['id']) is False

    conn = sqlite3.connect(manager.path)
    try:
        for table in ('case_items', 'case_notes', 'case_tags'):
            assert conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
    finally:
        conn.close()
    assert manager.get_case(case['id']) is None


def test_add_item_auto_detects_kinds(manager):
    case = manager.create_case('Auto')
    expected = {
        '8.8.8.8': 'ip',
        'example.com': 'domain',
        'alice@example.com': 'email',
        'alice': 'username',
        '+62812345678': 'phone',
        '### not a target ###': 'other',
    }
    for value, kind in expected.items():
        result = manager.add_item(case['id'], 'auto', value)
        assert 'error' not in result, result
        assert result['kind'] == kind
        assert result['value'] == value


def test_add_item_rejects_bad_input(manager):
    case = manager.create_case('Bad')
    assert 'error' in manager.add_item(case['id'], 'banana', 'x')
    assert 'error' in manager.add_item(case['id'], 'ip', '')
    assert 'error' in manager.add_item(99999, 'ip', '8.8.8.8')
    # 'other' is the explicit catch-all kind.
    ok = manager.add_item(case['id'], 'other', 'free-form indicator')
    assert ok['kind'] == 'other'


def test_add_item_duplicate_detection(manager):
    case = manager.create_case('Dup')
    assert 'error' not in manager.add_item(case['id'], 'ip', '8.8.8.8')
    assert manager.add_item(case['id'], 'ip', '8.8.8.8') == {'error': 'duplicate'}
    # Values are compared case-insensitively (and normalised for
    # ip/email/domain kinds), so caps cannot bypass the duplicate check.
    manager.add_item(case['id'], 'domain', 'example.com')
    assert manager.add_item(case['id'], 'domain', 'EXAMPLE.com') == {'error': 'duplicate'}
    # The same value under a different kind is a distinct item.
    assert 'error' not in manager.add_item(case['id'], 'other', '8.8.8.8')


def test_closed_and_archived_cases_reject_items(manager):
    case = manager.create_case('Locked')
    manager.close_case(case['id'])
    assert manager.add_item(case['id'], 'ip', '8.8.8.8') == {'error': 'case closed'}

    manager.reopen_case(case['id'])
    assert 'error' not in manager.add_item(case['id'], 'ip', '8.8.8.8')

    manager.archive_case(case['id'])
    assert manager.add_item(case['id'], 'ip', '1.1.1.1') == {'error': 'case archived'}
    # Closing remarks stay allowed on archived cases.
    assert 'error' not in manager.add_note(case['id'], 'final note')


def test_remove_item(manager):
    case = manager.create_case('Remove')
    item = manager.add_item(case['id'], 'ip', '8.8.8.8')
    assert manager.remove_item(case['id'], item['id']) is True
    assert manager.remove_item(case['id'], item['id']) is False
    assert manager.get_case(case['id'])['items'] == []


def test_notes(manager):
    case = manager.create_case('Notes')
    note = manager.add_note(case['id'], 'first observation')
    assert note['body'] == 'first observation'
    assert note['case_id'] == case['id']
    assert 'error' in manager.add_note(case['id'], '   ')
    assert 'error' in manager.add_note(99999, 'ghost note')
    assert manager.get_case(case['id'])['notes'][0]['body'] == 'first observation'


def test_tags(manager):
    case = manager.create_case('Tags')
    assert manager.add_tag(case['id'], 'Phishing')['tag'] == 'phishing'
    assert manager.add_tag(case['id'], 'phishing') == {'error': 'duplicate'}
    assert manager.get_case(case['id'])['tags'] == ['phishing']

    assert manager.remove_tag(case['id'], 'PHISHING') is True
    assert manager.remove_tag(case['id'], 'phishing') is False
    assert manager.get_case(case['id'])['tags'] == []

    assert 'error' in manager.add_tag(99999, 'x')
    assert 'error' in manager.add_tag(case['id'], '')


def test_find_cases_case_insensitive(manager):
    first = manager.create_case('First')
    second = manager.create_case('Second')
    manager.add_item(first['id'], 'ip', '8.8.8.8')
    manager.add_item(second['id'], 'domain', 'Example.COM')  # stored lower-cased

    hits = manager.find_cases('8.8.8.8')
    assert [case['name'] for case in hits] == ['First']
    assert hits[0]['matched'][0]['kind'] == 'ip'

    hits = manager.find_cases('example.com')
    assert [case['name'] for case in hits] == ['Second']

    assert manager.find_cases('nothing.example') == []
    assert manager.find_cases('') == []


def test_case_stats(manager):
    first = manager.create_case('A')
    manager.create_case('B')
    manager.create_case('C')
    manager.add_item(first['id'], 'ip', '8.8.8.8')
    manager.add_note(first['id'], 'n')
    manager.close_case(first['id'])
    archived_id = manager.create_case('D')['id']
    manager.archive_case(archived_id)

    stats = manager.case_stats()
    assert stats['total'] == 4
    assert stats['open'] == 2
    assert stats['closed'] == 1
    assert stats['archived'] == 1
    assert stats['items_total'] == 1
    assert stats['notes_total'] == 1


def test_mutations_touch_updated_at(manager):
    case = manager.create_case('Touched')
    case_id = case['id']
    conn = sqlite3.connect(manager.path)
    try:
        conn.execute(
            "UPDATE cases SET updated_at = '2000-01-01 00:00:00' WHERE id = ?",
            (case_id,))
        conn.commit()
    finally:
        conn.close()

    manager.add_item(case_id, 'ip', '8.8.8.8')
    refreshed = manager.get_case(case_id)
    assert refreshed['updated_at'] > '2000-01-01'

    # Status changes bump it as well.
    conn = sqlite3.connect(manager.path)
    try:
        conn.execute(
            "UPDATE cases SET updated_at = '2000-01-01 00:00:00' WHERE id = ?",
            (case_id,))
        conn.commit()
    finally:
        conn.close()
    manager.close_case(case_id)
    assert manager.get_case(case_id)['updated_at'] > '2000-01-01'


def test_export_markdown(manager):
    case = manager.create_case('Phishing Probe', 'look-alike domain report')
    manager.add_item(case['id'], 'ip', '8.8.8.8', note='dns resolver')
    manager.add_item(case['id'], 'auto', 'alice@example.com')
    manager.add_tag(case['id'], 'phishing')
    manager.add_note(case['id'], 'opened after customer report')

    text = manager.export_case(case['id'])
    assert '# Case' in text
    assert 'Phishing Probe' in text
    assert 'look-alike domain report' in text
    assert '| Status | open |' in text
    assert '**Tags:** phishing' in text
    assert '| Kind | Value | Note | Added |' in text
    assert '8.8.8.8' in text
    assert 'dns resolver' in text
    assert 'alice@example.com' in text
    assert 'opened after customer report' in text
    assert manager.export_case(99999) is None


def test_export_json_round_trip(manager):
    case = manager.create_case('Json Case')
    manager.add_item(case['id'], 'ip', '8.8.8.8', note='resolver')
    manager.add_note(case['id'], 'note body')
    manager.add_tag(case['id'], 'phishing')

    text = manager.export_case(case['id'], fmt='json')
    data = json.loads(text)
    assert data['name'] == 'Json Case'
    assert data['items'][0]['value'] == '8.8.8.8'
    assert data['notes'][0]['body'] == 'note body'
    assert data['tags'] == ['phishing']


def test_export_invalid_format_raises(manager):
    case = manager.create_case('Fmt')
    with pytest.raises(ValueError, match='unsupported export format'):
        manager.export_case(case['id'], fmt='pdf')


def test_cases_sections_shape(manager):
    manager.create_case('Sectioned', 'desc')
    manager.add_item(manager.list_cases()[0]['id'], 'ip', '8.8.8.8')

    sections = manager.cases_sections()
    stats_grid = sections[0]
    assert stats_grid['type'] == 'grid'
    assert stats_grid['title'] == 'Case Statistics'
    assert stats_grid['data']['Total cases'] == 1

    table = sections[-1]
    assert table['type'] == 'table'
    assert {'title', 'type', 'columns', 'rows'} <= set(table)
    assert table['columns'][0] == 'ID'
    assert table['rows'][0][1] == 'Sectioned'

    detail = manager.case_sections(manager.list_cases()[0]['id'])
    assert detail[0]['type'] == 'grid'
    assert detail[0]['title'].startswith('Case ')
    assert detail[1]['type'] == 'table'
    assert detail[1]['title'] == 'Items (1)'
    assert detail[1]['columns'] == ['Kind', 'Value', 'Note', 'Added']
    assert detail[1]['rows'][0][:3] == ['ip', '8.8.8.8', '']
    assert detail[1]['rows'][0][3]  # added_at timestamp


def test_module_level_section_helpers():
    # The module-level helpers use the shared singleton (empty test DB).
    sections = cases_sections()
    assert isinstance(sections, list)
    assert sections[-1]['type'] == 'table'
    assert case_sections(999999) == []


def test_sqlite_errors_reported_not_raised(manager, monkeypatch):
    @contextmanager
    def broken_connection():
        raise sqlite3.OperationalError('disk exploded')
        yield  # pragma: no cover

    monkeypatch.setattr(manager, '_get_connection', broken_connection)

    assert 'error' in manager.create_case('Boom')
    assert manager.list_cases() == []
    assert manager.get_case(1) is None
    assert manager.close_case(1) is None
    assert manager.reopen_case(1) is None
    assert manager.archive_case(1) is None
    assert manager.delete_case(1) is False
    assert 'error' in manager.add_item(1, 'ip', '8.8.8.8')
    assert manager.remove_item(1, 1) is False
    assert 'error' in manager.add_note(1, 'note')
    assert 'error' in manager.add_tag(1, 'tag')
    assert manager.remove_tag(1, 'tag') is False
    assert manager.find_cases('8.8.8.8') == []
    assert 'error' in manager.case_stats()
    assert manager.export_case(1) is None
