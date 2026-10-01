"""Database history tests."""

from obscuralens.config import config
from obscuralens.database import db


def test_save_get_search_roundtrip(tmp_env):
    query_id = db.save_query('unittest', 'unit_value_1',
                             {'info': {'a': 1, 'b': 2}}, success=True)
    assert query_id > 0

    record = db.get_query_by_id(query_id)
    assert record is not None
    assert record.query_value == 'unit_value_1'
    assert db.count_fields(record.result_data) == 2

    found = db.search_history('unit_value_1')
    assert any(r.id == query_id for r in found)

    history = db.get_history(query_type='unittest', limit=10)
    assert any(r.id == query_id for r in history)

    assert db.delete_history(query_id) is True
    assert db.get_query_by_id(query_id) is None


def test_statistics_shape(tmp_env):
    db.save_query('unittest', 'stats_value', {'info': {'x': 1}})
    stats = db.get_statistics()
    assert stats['total_queries'] >= 1
    assert 'unittest' in stats['queries_by_type']
    assert 0 <= stats['success_rate'] <= 100
    db.clear_history('unittest')


def test_max_history_entries_is_enforced(tmp_env, monkeypatch):
    monkeypatch.setattr(config.app_config, 'max_history_entries', 5)
    for i in range(9):
        db.save_query('unittest_prune', f'prune_{i}', {'info': {'i': i}})

    with db._get_connection() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM query_history WHERE query_type = 'unittest_prune'"
        ).fetchone()[0]
    assert count <= 5
    db.clear_history('unittest_prune')


def test_save_disabled_returns_minus_one(tmp_env, monkeypatch):
    monkeypatch.setattr(config.app_config, 'save_history', False)
    assert db.save_query('unittest', 'ignored', {}) == -1
