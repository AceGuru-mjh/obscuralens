"""
Case management for ObscuraLens v4.0.

Investigators accumulate indicators (items), notes and tags inside a *case* so
a long-running investigation survives between sessions. Cases live in the same
SQLite file as the query history (``config.db_config.sqlite_path``) and every
mutation bumps ``cases.updated_at`` so the CLI can sort by recent activity.
"""

from .manager import (
    KNOWN_KINDS,
    CaseManager,
    case_sections,
    cases,
    cases_enabled,
    cases_path,
    cases_sections,
)

__all__ = [
    'KNOWN_KINDS',
    'CaseManager',
    'case_sections',
    'cases',
    'cases_enabled',
    'cases_path',
    'cases_sections',
]
