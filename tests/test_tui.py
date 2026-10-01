"""Optional Textual terminal UI tests (skipped when Textual is absent)."""

import pytest

pytest.importorskip("textual")

from obscuralens import tui  # noqa: E402


def test_module_exposes_entry_points():
    from obscuralens.tui import main, run_tui

    assert callable(run_tui)
    assert callable(main)


def test_create_app_class_builds_app():
    from textual.app import App

    app_class = tui.create_app_class()
    assert issubclass(app_class, App)

    app = app_class()
    assert isinstance(app, App)
    assert app.TITLE == 'ObscuraLens'


def test_resolve_kind():
    assert tui._resolve_kind('auto', '8.8.8.8') == 'ip'
    assert tui._resolve_kind('auto', 'github') == 'username'
    assert tui._resolve_kind('domain', '8.8.8.8') == 'domain'
    assert tui._resolve_kind('auto', '') is None


def test_render_result_uses_fields():
    result = {
        'info': {'country': 'United States', 'city': 'Mountain View'},
        'sources_failed': ['rdap'],
        'field_sources': {'country': ['ipwho.is']},
    }
    text = tui._render_result('ip', result)
    assert 'Country' in text
    assert 'United States' in text
    assert 'Field Sources' not in text  # plumbing keys are hidden
    assert 'Unavailable: rdap' in text
