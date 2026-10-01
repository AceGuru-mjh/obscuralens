"""
Live integration tests.

These hit real public services and are excluded from the default run
(`pytest -m "not integration"`). Run them explicitly with:

    pytest -m integration

They exist to catch schema drift in upstream APIs, which unit tests with
fixtures cannot do.
"""

import pytest

pytestmark = pytest.mark.integration


def test_live_ip_lookup():
    from obscuralens.trackers import IPTracker
    result = IPTracker().track('1.1.1.1')
    assert result['success'], result.get('sources_failed')
    assert result['field_count'] >= 5
    assert result['info'].get('country')


def test_live_domain_lookup():
    from obscuralens.trackers import DomainTracker
    result = DomainTracker().track('example.com')
    assert result['success']
    assert result['info'].get('domain_created')


def test_live_username_api_platforms():
    from obscuralens.trackers import UsernameTracker
    result = UsernameTracker().track(
        'torvalds', deep=False, platforms=['keybase', 'lichess'])
    assert result['found_count'] >= 1
    assert result['total_checked'] == 2


def test_live_email_lookup():
    from obscuralens.trackers import EmailTracker
    result = EmailTracker().track('test@gmail.com')
    assert result['success']
    assert result['info'].get('mx_records')
