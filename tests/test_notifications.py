"""Notification centre tests (v6.0 part 4): channel CRUD, filters,
dispatch formats for all five protocols, dedup, broadcast aggregation,
history and the CLI wiring. Fully offline - HTTP is monkeypatched at the
notifications module's ``_post`` seam and SMTP at ``smtplib.SMTP``."""

import json

import pytest

from obscuralens.automation import notifications
from obscuralens.automation.notifications import (
    CHANNEL_TYPES,
    SEVERITY_LEVELS,
    _in_quiet_hours,
    _severity_rank,
)


@pytest.fixture()
def fresh_state(tmp_path, monkeypatch):
    """Isolate notifications.json in a per-test directory.

    The state file lives next to ``config.db_config.sqlite_path`` (the
    same convention as alerts.json), so pointing the sqlite path at a
    per-test path moves the notification state with it.
    """
    from obscuralens.config import config
    monkeypatch.setattr(config.db_config, 'sqlite_path',
                        str(tmp_path / 'notifications.db'))
    return tmp_path


@pytest.fixture()
def post_spy(monkeypatch):
    """Capture every (url, payload) handed to the HTTP seam."""
    calls = []

    def fake_post(url, payload):
        calls.append((url, payload))
        return True, 'ok'

    monkeypatch.setattr(notifications, '_post', fake_post)
    return calls


def _add(name='hook', type_='webhook', target='https://hooks.example/x',
         **extra):
    return notifications.add_channel(
        {'name': name, 'type': type_, 'target': target, **extra})


# --------------------------------------------------------------------------- #
# channel CRUD
# --------------------------------------------------------------------------- #

class TestChannelCRUD:

    def test_add_and_list_round_trip(self, fresh_state):
        result = _add(events='lookup, watch_diff', min_severity='low',
                      quiet_hours='22-07', note='team hook')
        assert result['ok'] is True
        channels = notifications.list_channels()
        assert len(channels) == 1
        channel = channels[0]
        assert channel['name'] == 'hook'
        assert channel['type'] == 'webhook'
        assert channel['target'] == 'https://hooks.example/x'
        assert channel['events'] == ['lookup', 'watch_diff']
        assert channel['min_severity'] == 'low'
        assert channel['quiet_hours'] == [22, 7]
        assert channel['note'] == 'team hook'
        assert channel['enabled'] is True

    def test_get_channel_case_insensitive(self, fresh_state):
        _add(name='Team-Chat', type_='slack')
        assert notifications.get_channel('TEAM-CHAT')['type'] == 'slack'
        assert notifications.get_channel('nope') is None

    def test_remove_channel(self, fresh_state):
        _add()
        removed = notifications.remove_channel('HOOK')
        assert removed['ok'] is True
        assert removed['removed'] == 'hook'
        assert notifications.list_channels() == []

    def test_remove_missing_channel_fails_cleanly(self, fresh_state):
        result = notifications.remove_channel('ghost')
        assert result['ok'] is False
        assert 'not found' in result['error']

    def test_duplicate_name_rejected(self, fresh_state):
        assert _add()['ok'] is True
        result = _add()
        assert result['ok'] is False
        assert 'already exists' in result['error']

    def test_unknown_type_rejected_with_reason(self, fresh_state):
        result = _add(type_='carrier-pigeon')
        assert result['ok'] is False
        assert 'unknown channel type' in result['error']
        assert 'webhook' in result['error']  # the vocabulary is listed

    def test_missing_name_rejected(self, fresh_state):
        result = notifications.add_channel({'type': 'webhook',
                                            'target': 'https://x.example/'})
        assert result['ok'] is False
        assert 'name is required' in result['error']

    def test_non_mapping_spec_rejected(self, fresh_state):
        result = notifications.add_channel('nope')
        assert result['ok'] is False
        assert 'mapping' in result['error']

    def test_telegram_target_required_without_fallback(self, fresh_state,
                                                       monkeypatch):
        from obscuralens.config import config
        monkeypatch.setattr(config.api_config, 'telegram_api_key', '')
        result = _add(type_='telegram', target='')
        assert result['ok'] is False
        assert 'target is required' in result['error']

    def test_webhook_without_target_is_accepted(self, fresh_state):
        result = _add(target='')
        assert result['ok'] is True  # webhook has no global fallback key

    def test_state_file_written_beside_sqlite_path(self, fresh_state):
        _add()
        state_file = fresh_state / 'notifications.json'
        assert state_file.is_file()
        data = json.loads(state_file.read_text(encoding='utf-8'))
        assert data['channels'][0]['name'] == 'hook'

    def test_corrupt_state_file_falls_back_to_empty(self, fresh_state):
        (fresh_state / 'notifications.json').write_text('{not json',
                                                         encoding='utf-8')
        assert notifications.list_channels() == []

    def test_persisted_channels_survive_reload(self, fresh_state):
        _add(name='first')
        _add(name='second', type_='slack')
        names = {c['name'] for c in notifications.list_channels()}
        assert names == {'first', 'second'}


# --------------------------------------------------------------------------- #
# severity / events / quiet hours filters
# --------------------------------------------------------------------------- #

class TestFilters:

    def test_severity_rank_ladder(self):
        assert _severity_rank('info') == 0
        assert _severity_rank('critical') == 4
        assert _severity_rank('nonsense') == 0
        assert _severity_rank(None) == 0

    def test_quiet_hours_wraps_midnight(self):
        from datetime import datetime
        assert _in_quiet_hours((22, 6), datetime(2024, 1, 1, 23, 5)) is True
        assert _in_quiet_hours((22, 6), datetime(2024, 1, 1, 5, 59)) is True
        assert _in_quiet_hours((22, 6), datetime(2024, 1, 1, 12, 0)) is False
        assert _in_quiet_hours((22, 6), datetime(2024, 1, 1, 6, 0)) is False
        assert _in_quiet_hours((22, 6), datetime(2024, 1, 1, 22, 0)) is True

    def test_quiet_hours_same_day_window(self):
        from datetime import datetime
        assert _in_quiet_hours((9, 17), datetime(2024, 1, 1, 12)) is True
        assert _in_quiet_hours((9, 17), datetime(2024, 1, 1, 8)) is False
        assert _in_quiet_hours((9, 17), datetime(2024, 1, 1, 17)) is False

    def test_degenerate_and_missing_windows_never_silence(self):
        from datetime import datetime
        assert _in_quiet_hours(None, datetime(2024, 1, 1, 3)) is False
        assert _in_quiet_hours((5, 5), datetime(2024, 1, 1, 5)) is False

    def test_send_skips_unsubscribed_event(self, fresh_state, post_spy):
        _add(events=['watch_diff'])
        result = notifications.send('hook', 'lookup', 't', 'b')
        assert result['ok'] is False
        assert result['skipped'] is True
        assert result['reason'] == 'event not subscribed'
        assert post_spy == []  # never touched the wire

    def test_send_skips_below_severity_floor(self, fresh_state, post_spy):
        _add(min_severity='high')
        result = notifications.send('hook', 'lookup', 't', 'b',
                                    severity='medium')
        assert result['skipped'] is True
        assert 'severity below channel floor' in result['reason']

    def test_send_skips_disabled_channel(self, fresh_state, post_spy):
        _add(enabled=False)
        result = notifications.send('hook', 'lookup', 't', 'b')
        assert result['skipped'] is True
        assert result['reason'] == 'channel disabled'

    def test_send_skips_inside_quiet_hours(self, fresh_state, post_spy,
                                            monkeypatch):
        _add(quiet_hours='22-06')
        monkeypatch.setattr(notifications, '_in_quiet_hours',
                            lambda quiet, now=None: True)
        result = notifications.send('hook', 'lookup', 't', 'b')
        assert result['skipped'] is True
        assert result['reason'] == 'quiet hours'

    def test_send_unknown_channel_reports_error(self, fresh_state):
        result = notifications.send('ghost', 'lookup', 't', 'b')
        assert result['ok'] is False
        assert 'not found' in result['error']


# --------------------------------------------------------------------------- #
# dispatch formats (one test per protocol)
# --------------------------------------------------------------------------- #

class TestDispatch:

    def test_webhook_payload_shape(self, fresh_state, post_spy):
        _add()
        result = notifications.send('hook', 'lookup', 'Title', 'Body',
                                    'high', {'kind': 'ip'})
        assert result['ok'] is True
        url, payload = post_spy[0]
        assert url == 'https://hooks.example/x'
        assert payload['event'] == 'lookup'
        assert payload['title'] == 'Title'
        assert payload['body'] == 'Body'
        assert payload['severity'] == 'high'
        assert payload['fields'] == {'kind': 'ip'}
        assert payload['ts']

    def test_telegram_payload_shape(self, fresh_state, post_spy):
        _add(name='tg', type_='telegram', target='ABC123:chat9')
        result = notifications.send('tg', 'lookup', 'Title', 'Body')
        assert result['ok'] is True
        url, payload = post_spy[0]
        assert url == 'https://api.telegram.org/botABC123/sendMessage'
        assert payload['chat_id'] == 'chat9'
        assert '<b>Title</b>' in payload['text']
        assert payload['parse_mode'] == 'HTML'

    def test_telegraph_target_without_colon_fails(self, fresh_state, post_spy):
        _add(name='tg', type_='telegram', target='not-a-pair')
        result = notifications.send('tg', 'lookup', 't', 'b')
        assert result['ok'] is False
        assert 'bot_token:chat_id' in result['error']

    def test_discord_content_format(self, fresh_state, post_spy):
        _add(name='dc', type_='discord')
        result = notifications.send('dc', 'lookup', 'Title', 'Body', 'high')
        assert result['ok'] is True
        _url, payload = post_spy[0]
        assert payload['content'].startswith('**[high] Title**')
        assert 'Body' in payload['content']

    def test_slack_text_format(self, fresh_state, post_spy):
        _add(name='sl', type_='slack')
        result = notifications.send('sl', 'lookup', 'Title', 'Body', 'low')
        assert result['ok'] is True
        _url, payload = post_spy[0]
        assert payload['text'].startswith('*[low] Title*')

    def test_smtp_message_headers(self, fresh_state, monkeypatch):
        import smtplib
        sent = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                sent.append(('init', host, port))

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def ehlo(self):
                pass

            def starttls(self):
                pass

            def login(self, user, password):
                sent.append(('login', user))

            def sendmail(self, from_addr, to_addrs, message):
                sent.append(('mail', from_addr, to_addrs, message))

        monkeypatch.setattr(smtplib, 'SMTP', FakeSMTP)
        _add(name='mail', type_='smtp',
             target='smtp.example.com:587:alerts@x.example:analyst@x.example')
        result = notifications.send('mail', 'lookup', 'Alert title', 'Body')
        assert result['ok'] is True
        init, _, _ = sent[0]
        assert init == 'init'
        mail = [entry for entry in sent if entry[0] == 'mail'][0]
        assert mail[1] == 'alerts@x.example'
        assert mail[2] == ['analyst@x.example']
        assert 'Subject: Alert title' in mail[3]
        assert 'From: alerts@x.example' in mail[3]
        assert 'To: analyst@x.example' in mail[3]

    def test_config_fallback_used_when_target_empty(self, fresh_state,
                                                    post_spy, monkeypatch):
        from obscuralens.config import config
        monkeypatch.setattr(config.api_config, 'slack_webhook_url',
                            'https://hooks.slack.example/fallback')
        _add(name='fb', type_='slack', target='')
        result = notifications.send('fb', 'lookup', 't', 'b')
        assert result['ok'] is True
        url, _payload = post_spy[0]
        assert url == 'https://hooks.slack.example/fallback'

    def test_successful_send_updates_last_sent_and_history(
            self, fresh_state, post_spy):
        _add()
        notifications.send('hook', 'lookup', 'Title', 'Body')
        channel = notifications.get_channel('hook')
        assert channel['last_sent']  # ISO stamp
        entries = notifications.recent()
        assert len(entries) == 1
        assert entries[0]['channel'] == 'hook'
        assert entries[0]['delivery'] == 'ok'


# --------------------------------------------------------------------------- #
# dedup window
# --------------------------------------------------------------------------- #

class TestDedup:

    def test_second_identical_send_is_deduplicated(self, fresh_state,
                                                   post_spy):
        _add()
        first = notifications.send('hook', 'lookup', 'Title', 'Body')
        second = notifications.send('hook', 'lookup', 'Title', 'Body')
        assert first['ok'] is True
        assert second['ok'] is False
        assert second['skipped'] is True
        assert 'deduplicated' in second['reason']
        assert len(post_spy) == 1  # exactly one wire touch

    def test_zero_window_disables_dedup(self, fresh_state, post_spy,
                                        monkeypatch):
        monkeypatch.setattr(notifications, 'DEDUP_SECONDS', 0)
        _add()
        assert notifications.send('hook', 'lookup', 'T', 'B')['ok'] is True
        assert notifications.send('hook', 'lookup', 'T', 'B')['ok'] is True
        assert len(post_spy) == 2

    def test_different_title_passes_default_recipe(self, fresh_state,
                                                   post_spy):
        _add()
        assert notifications.send('hook', 'lookup', 'A', 'B')['ok'] is True
        assert notifications.send('hook', 'lookup', 'C', 'B')['ok'] is True
        assert len(post_spy) == 2

    def test_event_recipe_blocks_same_event_new_title(self, fresh_state,
                                                      post_spy):
        _add(dedup_key='event')
        assert notifications.send('hook', 'lookup', 'A', 'B')['ok'] is True
        result = notifications.send('hook', 'lookup', 'C', 'B')
        assert result['skipped'] is True
        assert 'deduplicated' in result['reason']

    def test_failed_send_does_not_populate_dedup(self, fresh_state,
                                                 monkeypatch):
        _add(name='dead', target='ftp://not-http')
        first = notifications.send('dead', 'lookup', 'T', 'B')
        assert first['ok'] is False
        # the failed attempt is not remembered, so a fixed pipe retries
        monkeypatch.setattr(notifications, '_post',
                            lambda url, payload: (True, 'ok'))
        second = notifications.send('dead', 'lookup', 'T', 'B')
        assert second['ok'] is True


# --------------------------------------------------------------------------- #
# broadcast / test_channel / history
# --------------------------------------------------------------------------- #

class TestBroadcast:

    def test_broadcast_aggregates_success_and_failure(self, fresh_state,
                                                       monkeypatch):
        _add(name='good')
        _add(name='bad', type_='telegram', target='no-colon-here')

        def fake_post(url, payload):
            return url.startswith('https://hooks'), 'ok' \
                if url.startswith('https://hooks') else 'invalid target'

        monkeypatch.setattr(notifications, '_post', fake_post)
        result = notifications.broadcast('lookup', 'T', 'B')
        assert result['total'] == 2
        assert result['sent'] == 1
        assert result['skipped'] == 0
        assert len(result['failed']) == 1
        assert result['failed'][0]['channel'] == 'bad'

    def test_broadcast_with_no_channels_is_total_zero(self, fresh_state):
        result = notifications.broadcast('lookup', 'T', 'B')
        assert result == {'sent': 0, 'failed': [], 'skipped': 0,
                          'total': 0, 'results': []}

    def test_broadcast_counts_skips(self, fresh_state, post_spy):
        _add(name='sub', events=['watch_diff'])
        _add(name='all')
        result = notifications.broadcast('lookup', 'T', 'B')
        assert result['sent'] == 1
        assert result['skipped'] == 1
        assert len(post_spy) == 1

    def test_test_channel_bypasses_filters(self, fresh_state, post_spy,
                                           monkeypatch):
        _add(events=['nothing-else'], quiet_hours='00-23')
        monkeypatch.setattr(notifications, '_in_quiet_hours',
                            lambda quiet, now=None: True)
        result = notifications.test_channel('hook')
        assert result['ok'] is True
        assert len(post_spy) == 1

    def test_test_channel_unknown_name(self, fresh_state):
        result = notifications.test_channel('ghost')
        assert result['ok'] is False
        assert 'not found' in result['error']

    def test_recent_is_newest_first_and_limitable(self, fresh_state,
                                                  post_spy):
        _add()
        notifications.send('hook', 'lookup', 'Same title', 'B')
        notifications.send('hook', 'lookup', 'Same title', 'B')  # deduped
        entries = notifications.recent()
        assert [entry['title'] for entry in entries] == ['Same title'] * 2
        assert entries[0]['delivery'].startswith('skipped')
        assert entries[1]['delivery'] == 'ok'
        assert len(notifications.recent(limit=1)) == 1
        assert notifications.recent(limit=0) == []

    def test_clear_log_removes_history_only(self, fresh_state, post_spy):
        _add()
        notifications.send('hook', 'lookup', 'T', 'B')
        assert notifications.clear_log() == 1
        assert notifications.recent() == []
        assert len(notifications.list_channels()) == 1

    def test_format_event_title_and_body(self):
        title, body = notifications.format_event(
            'ip', '8.8.8.8', 'flagged by two feeds',
            {'country': 'US', 'tags': ['abuse', 'proxy']})
        assert title == 'ip · 8.8.8.8'
        assert 'flagged by two feeds' in body
        assert 'country: US' in body
        assert 'tags:' in body and 'abuse' in body and 'proxy' in body

    def test_notify_kind_event_broadcasts_lookup(self, fresh_state,
                                                 post_spy):
        _add()
        result = notifications.notify_kind_event('domain', 'example.com',
                                                 'young registration')
        assert result['sent'] == 1
        _url, payload = post_spy[0]
        assert payload['event'] == 'lookup'
        assert 'domain · example.com' in payload['title']

    def test_vocabularies_are_stable(self):
        assert CHANNEL_TYPES == ('webhook', 'telegram', 'discord', 'slack',
                                 'smtp')
        assert SEVERITY_LEVELS == ('info', 'low', 'medium', 'high',
                                   'critical')


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

class TestNotifyCLI:

    def test_channels_listing_table(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='hook')
        assert commands.run(['notify', 'channels']) == 0
        out = capsys.readouterr().out
        assert 'NOTIFICATION CHANNELS' in out
        assert 'hook' in out

    def test_channels_listing_json(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='hook')
        assert commands.run(['notify', 'channels', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['count'] == 1
        assert payload['channels'][0]['name'] == 'hook'
        assert 'telegram' in payload['channel_types']

    def test_channels_empty_hint(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(['notify', 'channels']) == 0
        assert 'No channels yet' in capsys.readouterr().out

    def test_add_and_remove_via_cli(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(
            ['notify', 'add', '--type', 'webhook', '--name', 'myhook',
             '--target', 'https://hooks.example/x', '--events',
             'lookup,watch', '--min-severity', 'low',
             '--quiet-hours', '22-07']) == 0
        out = capsys.readouterr().out
        assert "myhook" in out
        channel = notifications.get_channel('myhook')
        assert channel['events'] == ['lookup', 'watch']
        assert channel['quiet_hours'] == [22, 7]
        assert commands.run(['notify', 'remove', 'myhook']) == 0
        assert notifications.list_channels() == []

    def test_add_rejected_type_returns_1(self, fresh_state, capsys):
        from obscuralens import commands
        # argparse rejects unknown --type values before the handler runs
        with pytest.raises(SystemExit):
            commands.run(['notify', 'add', '--type', 'pigeon', '--name', 'x'])

    def test_add_duplicate_name_returns_1(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='dupe')
        assert commands.run(
            ['notify', 'add', '--type', 'webhook', '--name', 'dupe',
             '--target', 'https://x.example/']) == 1
        assert 'already exists' in capsys.readouterr().err

    def test_remove_unknown_returns_1(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(['notify', 'remove', 'ghost']) == 1
        assert 'not found' in capsys.readouterr().err

    def test_test_via_cli_reports_failure(self, fresh_state, capsys):
        from obscuralens import commands
        _add(name='dead', target='ftp://nope')
        assert commands.run(['notify', 'test', 'dead']) == 1
        assert 'failed' in capsys.readouterr().out.lower()

    def test_recent_via_cli(self, fresh_state, post_spy, capsys):
        from obscuralens import commands
        _add()
        notifications.send('hook', 'lookup', 'Title', 'Body')
        assert commands.run(['notify', 'recent', '--limit', '5']) == 0
        out = capsys.readouterr().out
        assert 'RECENT NOTIFICATIONS' in out
        assert 'Title' in out

    def test_broadcast_via_cli_json(self, fresh_state, capsys):
        from obscuralens import commands
        assert commands.run(
            ['notify', 'broadcast', '--title', 'Heads up',
             '--body', 'something moved', '--severity', 'high',
             '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['total'] == 0  # no channels configured
        assert payload['sent'] == 0

    def test_notify_without_action_returns_2(self, capsys):
        from obscuralens import commands
        assert commands.run(['notify']) == 2
        assert 'usage' in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Web API wiring
# --------------------------------------------------------------------------- #

class TestNotifyWeb:

    @pytest.fixture()
    def client(self, fresh_state):
        pytest.importorskip('fastapi')
        pytest.importorskip('httpx')
        from fastapi.testclient import TestClient

        from obscuralens.web import create_app
        return TestClient(create_app())

    def test_channels_endpoint_round_trip(self, client):
        response = client.get('/api/notify/channels')
        assert response.status_code == 200
        assert response.json()['count'] == 0
        created = client.post('/api/notify/channels', json={
            'name': 'web-hook', 'type': 'webhook',
            'target': 'https://hooks.example/x'})
        assert created.status_code == 200
        assert created.json()['channel']['name'] == 'web-hook'
        listing = client.get('/api/notify/channels').json()
        assert listing['count'] == 1
        assert 'telegram' in listing['channel_types']

    def test_add_channel_bad_type_400(self, client):
        response = client.post('/api/notify/channels',
                               json={'name': 'x', 'type': 'pigeon'})
        assert response.status_code == 400
        assert 'unknown channel type' in response.json()['detail']

    def test_delete_channel_404_for_unknown(self, client):
        assert client.delete('/api/notify/channels/ghost').status_code == 404

    def test_test_channel_404_for_unknown(self, client):
        response = client.post('/api/notify/channels/ghost/test')
        assert response.status_code == 404

    def test_recent_endpoint(self, client):
        response = client.get('/api/notify/recent?limit=5')
        assert response.status_code == 200
        assert response.json() == {'count': 0, 'recent': []}

    def test_broadcast_requires_title_and_body(self, client):
        assert client.post('/api/notify/broadcast',
                           json={'title': 't'}).status_code == 400
        assert client.post('/api/notify/broadcast',
                           json={'body': 'b'}).status_code == 400

    def test_broadcast_empty_channel_set(self, client):
        response = client.post('/api/notify/broadcast',
                               json={'title': 't', 'body': 'b'})
        assert response.status_code == 200
        assert response.json()['total'] == 0


# --------------------------------------------------------------------------- #
# MCP wiring
# --------------------------------------------------------------------------- #

class TestNotifyMCP:

    def test_notify_channels_tool(self, fresh_state):
        from obscuralens.mcp_server import call_tool
        _add(name='hook')
        result = call_tool('notify_channels', {})
        assert result['count'] == 1
        assert result['channels'][0]['name'] == 'hook'
        assert 'webhook' in result['channel_types']
        assert 'critical' in result['severities']

    def test_notify_broadcast_tool_requires_title(self, fresh_state):
        from obscuralens.mcp_server import call_tool
        with pytest.raises(ValueError):
            call_tool('notify_broadcast', {'body': 'b'})

    def test_notify_broadcast_tool_no_channels(self, fresh_state):
        from obscuralens.mcp_server import call_tool
        result = call_tool('notify_broadcast',
                           {'title': 't', 'body': 'b', 'severity': 'high'})
        assert result['total'] == 0

    def test_notify_broadcast_tool_delivers(self, fresh_state, post_spy):
        from obscuralens.mcp_server import call_tool
        _add()
        result = call_tool('notify_broadcast', {
            'title': 'Escalation', 'body': 'details',
            'event_type': 'pipeline', 'severity': 'high'})
        assert result['sent'] == 1
        _url, payload = post_spy[0]
        assert payload['title'] == 'Escalation'
        assert payload['severity'] == 'high'
