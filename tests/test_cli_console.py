"""Interactive console (ObscuraLensCLI) tests driven by scripted input.

Every tracker is replaced with a stub returning canned envelopes, every
prompt is fed from an explicit answer list, and ``clear_screen`` is
disabled — so the whole menu forest runs with zero network and zero tty.
"""

import json
import sys
from pathlib import Path

import pytest

import obscuralens.cli as cli_module
from obscuralens.cli import ObscuraLensCLI

# ---------------------------------------------------------------------------
# Scripted input
# ---------------------------------------------------------------------------

class Script:
    """Feed scripted answers to the console; fail loudly when it over-asks."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.prompts = []

    def _pop(self, prompt):
        self.prompts.append(str(prompt))
        if not self.answers:
            raise AssertionError(
                'the console asked for more input than the script provides '
                f'(prompt {prompt!r}; earlier prompts: {self.prompts[:-1]})')
        return self.answers.pop(0)

    def input(self, prompt=''):
        return self._pop(prompt)

    def get_input(self, prompt, required=True):
        return self._pop(prompt)

    def confirm(self, prompt):
        return self._pop(prompt).strip().lower() in ('y', 'yes')

    def install(self, monkeypatch):
        monkeypatch.setattr('builtins.input', self.input)
        monkeypatch.setattr(cli_module, 'get_input', self.get_input)
        monkeypatch.setattr(cli_module, 'confirm_action', self.confirm)
        monkeypatch.setattr(cli_module, 'clear_screen', lambda: None)
        return self


@pytest.fixture()
def console(monkeypatch):
    """console(*answers) installs a scripted input session."""
    def make(*answers):
        return Script(answers).install(monkeypatch)
    return make


# ---------------------------------------------------------------------------
# Tracker / db / watchlist doubles
# ---------------------------------------------------------------------------

class StubTracker:
    def __init__(self, result, own_ip=None):
        self.result = result
        self.own_ip = own_ip
        self.platforms = ['Reddit', 'Keybase', 'GitHub']
        self.calls = []
        self.batch_calls = []

    def track(self, target, *args, **kwargs):
        self.calls.append((target, args, kwargs))
        return dict(self.result)

    def batch_track(self, targets, *args, **kwargs):
        self.batch_calls.append(list(targets))
        return [dict(self.result) for _ in targets]

    def get_own_ip(self):
        if isinstance(self.own_ip, Exception):
            raise self.own_ip
        return self.own_ip


IP_OK = {
    'ip': '8.8.8.8',
    'info': {
        'reverse_dns': 'dns.google', 'country': 'United States',
        'city': 'Mountain View', 'latitude': 37.4, 'longitude': -122.0,
        'asn': 'AS15169', 'org': 'Google LLC',
        'coordinates_by_source': [
            {'source': 'ipwho.is', 'lat': 37.4, 'lon': -122.0}],
        'city_disagreement': ['Mountain View', 'San Jose'],
    },
    'field_sources': {'country': ['ipwho.is'], 'city': ['ipwho.is']},
    'sources_ok': ['ipwho.is', 'rdap'],
    'sources_failed': {'ip-api.com': 'timeout'},
    'field_count': 8,
    'success': True,
    'errors': [],
}

IP_FAIL = dict(IP_OK, success=False, sources_ok=[],
               sources_failed={'ipwho.is': 'timeout', 'rdap': 'dns failure'})

PHONE_OK = {
    'phone_number': '+15551234567',
    'info': {
        'e164': '+15551234567', 'international': '+1 555-123-4567',
        'type': 'MOBILE', 'carrier': 'Verizon', 'location': 'New Jersey',
        'valid_format': True, 'is_mobile': True,
        'hints': ['carrier guessed from numbering plan'],
    },
    'sources_ok': ['libphonenumber'], 'sources_failed': {},
    'field_count': 7, 'success': True, 'errors': [],
}

PHONE_FAIL = dict(PHONE_OK, success=False, sources_ok=[],
                  sources_failed={'libphonenumber': 'parse error'})

USERNAME_OK = {
    'username': 'alice',
    'found_count': 1, 'not_found_count': 1, 'unknown_count': 1,
    'total_checked': 3, 'total_fields': 2,
    'results': [
        {'platform': 'Keybase', 'url': 'https://keybase.io/alice',
         'status': 'found', 'confidence': 'high', 'reason': 'api 200',
         'status_code': 200, 'profile': {'name': 'Alice'}},
        {'platform': 'HackerNews', 'url': 'u', 'status': 'not_found',
         'confidence': 'high', 'reason': '404', 'status_code': 404,
         'profile': {}},
        {'platform': 'Reddit', 'url': 'u', 'status': 'unknown',
         'confidence': 'low', 'reason': 'bot wall', 'status_code': 403,
         'error': 'blocked', 'profile': {}},
    ],
    'success': True, 'errors': [],
}

EMAIL_OK = {
    'email': 'user@example.com',
    'info': {
        'email': 'user@example.com', 'domain': 'example.com',
        'valid_format': True, 'mx_exists': True, 'mx_count': 2,
        'disposable': False, 'openpgp': True, 'registrar': 'Example Registrar',
        'hibp_breaches': [
            {'name': 'ExampleBreach', 'date': '2021-02-03', 'pwn_count': 12345,
             'data_classes': ['Emails']},
        ],
        'pastes': [{'date': '2020-05-05', 'entries': 42}],
    },
    'sources_ok': ['dns'], 'sources_failed': {},
    'field_count': 9, 'success': True, 'errors': [],
}

EMAIL_FAIL = dict(EMAIL_OK, success=False, sources_ok=[],
                  sources_failed={'dns': 'no resolver'})


def _domain_result(subdomains=('www.example.com', 'api.example.com')):
    return {
        'domain': 'example.com',
        'info': {
            'domain': 'example.com', 'registrar': 'Example Registrar',
            'domain_age_days': 11000, 'dnssec': True,
            'http_status': 200, 'http_title': 'Example Domain',
            'ct_subdomains': list(subdomains),
            'missing_security_headers': ['content-security-policy'],
        },
        'field_sources': {'registrar': ['rdap']},
        'sources_ok': ['rdap', 'dns'], 'sources_failed': {},
        'field_count': 8, 'success': True, 'errors': [],
    }


DOMAIN_OK = _domain_result()
DOMAIN_FAIL = dict(DOMAIN_OK, success=False, sources_ok=[],
                   sources_failed={'rdap': 'timeout'})


class FakeRecord:
    def __init__(self, rid, qtype, value, payload):
        self.id = rid
        self.query_type = qtype
        self.query_value = value
        self.result_data = json.dumps(payload)
        self.success = True
        self.created_at = '2026-01-01 12:00:00'


class FakeDb:
    def __init__(self, history=(), stats=None):
        self.history = list(history)
        self.stats = stats or {'total_queries': 128, 'success_rate': 96,
                               'recent_queries_7d': 12,
                               'queries_by_type': {'ip': 9, 'domain': 3}}
        self.cleared = False
        self.searched = []

    def get_history(self, limit=25):
        return self.history[:limit]

    def count_fields(self, data):
        return 3

    def get_query_by_id(self, rid):
        for record in self.history:
            if record.id == rid:
                return record
        return None

    def search_history(self, term):
        self.searched.append(term)
        return [r for r in self.history if term in r.query_value]

    def clear_history(self):
        self.cleared = True
        return len(self.history)

    def get_statistics(self):
        return self.stats


class FakeWatchEntry:
    def __init__(self, eid, target, kind, label=None):
        self.id = eid
        self.target = target
        self.kind = kind
        self.label = label
        self.snapshots = 2
        self.last_checked = '2026-01-01 00:00:00'


class FakeWatchDiff:
    def __init__(self, **kwargs):
        self.watch_id = 1
        self.target = '8.8.8.8'
        self.is_first = False
        self.added = {}
        self.removed = {}
        self.changed = {}
        self.success = True
        self.error = ''
        self.__dict__.update(kwargs)


class FakeWatchlist:
    def __init__(self, entries=(), diffs=(), add_id=7, add_error=None):
        self.entries = list(entries)
        self.diffs = list(diffs)
        self.add_id = add_id
        self.add_error = add_error
        self.added = []
        self.checked = []
        self.removed = []

    def list(self):
        return self.entries

    def add(self, target, label=None):
        if self.add_error:
            raise ValueError(self.add_error)
        self.added.append((target, label))
        return self.add_id

    def check(self, identifier=None):
        self.checked.append(identifier)
        return self.diffs

    def remove(self, identifier):
        self.removed.append(identifier)
        return 1 if self.entries else 0


INVESTIGATE_PAYLOAD = {
    'target': 'example.com',
    'kind': 'domain',
    'order': ['domain', 'ip'],
    'results': {
        'domain': DOMAIN_OK,
        'ip': IP_OK,
    },
    'entities': [
        {'id': 'domain:example.com', 'type': 'domain', 'value': 'example.com',
         'role': 'target', 'label': 'example.com'},
        {'id': 'ip:8.8.8.8', 'type': 'ip', 'value': '8.8.8.8', 'role': 'a_record',
         'label': '8.8.8.8'},
    ],
    'links': [{'from': 'domain:example.com', 'to': 'ip:8.8.8.8',
               'label': 'a_record'}],
    'errors': ['rdap source unavailable'],
}


def saved_path(output, marker):
    """Extract the path printed after ``Report/Chart/CSV saved:``."""
    for line in output.splitlines():
        if marker in line:
            return line.split(marker, 1)[1].strip()
    raise AssertionError(f'no {marker!r} line in output')


@pytest.fixture()
def cli(tmp_env, console):
    """A fully stubbed console instance writing to the per-test tmp dir."""
    instance = ObscuraLensCLI()
    instance.ip_tracker = StubTracker(IP_OK, own_ip='9.9.9.9')
    instance.phone_tracker = StubTracker(PHONE_OK)
    instance.username_tracker = StubTracker(USERNAME_OK)
    instance.email_tracker = StubTracker(EMAIL_OK)
    instance.domain_tracker = StubTracker(DOMAIN_OK)
    return instance


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

MAIN_MENU_LABELS = [
    'IP Tracker', 'Phone Number Tracker', 'Username Tracker',
    'Email Tracker', 'Domain Tracker', 'Batch Operations', 'Query History',
    'Statistics', 'Settings', 'API Key Status', 'Watchlist',
    'Universal Investigate', 'Investigation Tools (v4)',
    'v5 Toolbox (tools, batch, report, patterns, geo)',
    'v5 Kinds (MAC / IBAN / IMEI / Coords)', 'Exit',
]

MENU_METHODS = [
    'ip_tracker_menu', 'phone_tracker_menu', 'username_tracker_menu',
    'email_tracker_menu', 'domain_tracker_menu', 'batch_operations_menu',
    'history_menu', 'statistics_menu', 'settings_menu', 'api_status_menu',
    'watchlist_menu', 'investigate_menu', 'v4_tools_menu', 'v5_tools_menu',
    'v5_trackers_menu',
]


class TestMainLoop:
    def test_run_exits_immediately(self, cli, console, capsys):
        console('0')
        cli.run()
        out = capsys.readouterr().out
        assert 'MAIN MENU' in out
        for label in MAIN_MENU_LABELS:
            assert label in out

    def test_invalid_choice_errors_and_reprompts(self, cli, console, capsys):
        console('99', '', '0')
        cli.run()
        out = capsys.readouterr().out
        assert 'Invalid option. Please try again.' in out
        assert out.count('MAIN MENU') >= 2

    @pytest.mark.parametrize('choice,method', [
        ('1', 'ip_tracker_menu'), ('2', 'phone_tracker_menu'),
        ('3', 'username_tracker_menu'), ('4', 'email_tracker_menu'),
        ('5', 'domain_tracker_menu'), ('6', 'batch_operations_menu'),
        ('7', 'history_menu'), ('8', 'statistics_menu'),
        ('9', 'settings_menu'), ('10', 'api_status_menu'),
        ('11', 'watchlist_menu'), ('12', 'investigate_menu'),
        ('13', 'v4_tools_menu'), ('14', 'v5_tools_menu'),
        ('15', 'v5_trackers_menu'),
    ])
    def test_choice_dispatches_to_menu_method(self, cli, console, monkeypatch,
                                              choice, method):
        recorded = []
        for name in MENU_METHODS:
            def hook(_name=name):
                recorded.append(_name)
            monkeypatch.setattr(cli, name, hook)
        console(choice, '0')
        cli.run()
        assert recorded == [method]

    def test_zero_returns_without_calling_exit_program(self, cli, console,
                                                       monkeypatch):
        exit_calls = []
        monkeypatch.setattr(cli, 'exit_program',
                            lambda: exit_calls.append(True))
        console('0')
        cli.run()
        assert exit_calls == []

    def test_show_main_menu_renders_sixteen_items(self, cli, capsys):
        cli.show_main_menu()
        out = capsys.readouterr().out
        for label in MAIN_MENU_LABELS:
            assert label in out
        assert out.count('[') >= 16

    def test_exit_program_prints_farewell_and_exits(self, cli, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.exit_program()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert 'Thank you for using ObscuraLens' in out
        assert 'Stay ethical' in out


class TestMainFunction:
    def test_argv_delegates_to_noninteractive_commands(self, monkeypatch):
        import obscuralens.commands as commands_module
        recorded = []
        monkeypatch.setattr(commands_module, 'run',
                            lambda argv: recorded.append(argv) or 42)
        monkeypatch.setattr(sys, 'argv', ['obscuralens', 'ip', '8.8.8.8'])
        with pytest.raises(SystemExit) as exc:
            cli_module.main()
        assert exc.value.code == 42
        assert recorded == [['ip', '8.8.8.8']]

    def test_keyboard_interrupt_exits_cleanly(self, monkeypatch, capsys):
        def boom(prompt=''):
            raise KeyboardInterrupt
        monkeypatch.setattr('builtins.input', boom)
        monkeypatch.setattr(cli_module, 'clear_screen', lambda: None)
        monkeypatch.setattr(sys, 'argv', ['obscuralens'])
        with pytest.raises(SystemExit) as exc:
            cli_module.main()
        assert exc.value.code == 0
        assert 'Exiting ObscuraLens' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# IP menu
# ---------------------------------------------------------------------------

class TestIPMenu:
    def test_back_returns_without_prompting(self, cli, console):
        console('0')
        cli.ip_tracker_menu()
        assert cli.ip_tracker.calls == []

    def test_invalid_ip_rejected_before_tracking(self, cli, console, capsys):
        console('1', 'not-an-ip', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        assert 'Invalid IP address' in out
        assert cli.ip_tracker.calls == []

    def test_success_displays_results_and_offer(self, cli, console, capsys):
        console('1', '8.8.8.8', '0', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        assert 'Location & Network' in out
        assert 'Mountain View' in out
        assert 'Google Maps' in out and 'OpenStreetMap' in out
        assert 'Coordinates By Source' in out
        assert 'San Jose' in out          # city disagreement warning
        assert 'Export' in out             # offer_ip_extras menu
        assert cli.ip_tracker.calls == [('8.8.8.8', (), {})]

    def test_failure_lists_failed_sources(self, cli, console, capsys):
        cli.ip_tracker = StubTracker(IP_FAIL)
        console('1', '8.8.8.8', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        assert 'Every data source failed.' in out
        assert 'ipwho.is' in out and 'timeout' in out
        assert 'rdap' in out and 'dns failure' in out

    def test_offer_json_report_writes_file(self, cli, console, capsys):
        console('1', '8.8.8.8', '1', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        path = Path(saved_path(out, 'Report saved:'))
        assert path.is_file()
        payload = json.loads(path.read_text(encoding='utf-8'))
        assert payload['title'] == 'IP Report - 8.8.8.8'
        assert payload['data']['ip'] == '8.8.8.8'
        assert payload['data']['sections']

    def test_offer_html_report_writes_file(self, cli, console, capsys):
        console('1', '8.8.8.8', '2', '')
        cli.ip_tracker_menu()
        path = Path(saved_path(capsys.readouterr().out, 'Report saved:'))
        assert path.is_file()
        assert path.read_text(encoding='utf-8').lstrip().startswith('<!')

    def test_offer_pdf_report_writes_file(self, cli, console, capsys):
        console('1', '8.8.8.8', '3', '')
        cli.ip_tracker_menu()
        path = Path(saved_path(capsys.readouterr().out, 'Report saved:'))
        assert path.is_file()
        assert path.read_bytes()[:5] == b'%PDF-'

    def test_offer_coordinates_chart(self, cli, console, capsys, tmp_env):
        console('1', '8.8.8.8', '4', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        path = Path(saved_path(out, 'Chart saved:'))
        assert path.is_file()
        assert path.name == 'lat_8.8.8.8.png'
        assert path.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n'

    def test_offer_chart_without_coordinates_warns(self, cli, console, capsys):
        result = dict(IP_OK)
        result['info'] = {k: v for k, v in IP_OK['info'].items()
                          if k != 'coordinates_by_source'}
        cli.ip_tracker = StubTracker(result)
        console('1', '8.8.8.8', '4', '')
        cli.ip_tracker_menu()
        assert 'No per-source coordinates available.' in capsys.readouterr().out

    def test_offer_field_sources_table(self, cli, console, capsys):
        console('1', '8.8.8.8', '5', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        assert 'Field Sources' in out
        assert 'ipwho.is' in out

    def test_offer_field_sources_missing_warns(self, cli, console, capsys):
        result = dict(IP_OK)
        result['field_sources'] = {}
        cli.ip_tracker = StubTracker(result)
        console('1', '8.8.8.8', '5', '')
        cli.ip_tracker_menu()
        assert 'No provenance data' in capsys.readouterr().out

    def test_offer_export_failure_reported(self, cli, console, capsys):
        class ExplodingGen:
            def generate_json_report(self, *a, **k):
                raise RuntimeError('boom')
            generate_html_report = generate_json_report
            generate_pdf_report = generate_json_report
        cli.report_gen = ExplodingGen()
        console('1', '8.8.8.8', '1', '')
        cli.ip_tracker_menu()
        assert 'Export failed: RuntimeError: boom' in capsys.readouterr().out

    def test_own_ip_without_lookup(self, cli, console, capsys):
        console('2', 'n', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        assert 'Your public IP: 9.9.9.9' in out
        assert cli.ip_tracker.calls == []

    def test_own_ip_with_full_lookup(self, cli, console, capsys):
        console('2', 'y', '0', '')
        cli.ip_tracker_menu()
        out = capsys.readouterr().out
        assert 'Your public IP: 9.9.9.9' in out
        assert 'Location & Network' in out
        assert cli.ip_tracker.calls == [('9.9.9.9', (), {})]

    def test_own_ip_error_handled(self, cli, console, capsys):
        cli.ip_tracker = StubTracker(IP_OK, own_ip=RuntimeError('offline'))
        console('2', '')
        cli.ip_tracker_menu()
        assert 'Could not determine public IP: RuntimeError' \
            in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Phone / username / email / domain menus
# ---------------------------------------------------------------------------

class TestPhoneMenu:
    def test_success_displays_fields(self, cli, console, capsys):
        console('+15551234567', 'US', 'n', '')
        cli.phone_tracker_menu()
        out = capsys.readouterr().out
        assert 'Verizon' in out
        assert 'MOBILE' in out
        assert 'Analyst Notes' in out
        assert cli.phone_tracker.calls == [('+15551234567', ('US',), {})]

    def test_save_report(self, cli, console, capsys):
        console('+15551234567', 'US', 'y', '')
        cli.phone_tracker_menu()
        path = Path(saved_path(capsys.readouterr().out, 'Report saved:'))
        assert path.is_file()
        assert 'Verizon' in path.read_text(encoding='utf-8')

    def test_invalid_phone_rejected(self, cli, console, capsys):
        console('123', 'US', '')
        cli.phone_tracker_menu()
        assert 'Phone number must be 8-15 digits' in capsys.readouterr().out
        assert cli.phone_tracker.calls == []

    def test_failure_lists_sources(self, cli, console, capsys):
        cli.phone_tracker = StubTracker(PHONE_FAIL)
        console('+15551234567', 'US', '')
        cli.phone_tracker_menu()
        out = capsys.readouterr().out
        assert 'Could not parse the number.' in out
        assert 'libphonenumber' in out and 'parse error' in out

    def test_blank_region_defaults_to_id(self, cli, console):
        console('+15551234567', '', 'n', '')
        cli.phone_tracker_menu()
        assert cli.phone_tracker.calls[0][1] == ('ID',)


class TestUsernameMenu:
    def test_success_displays_buckets(self, cli, console, capsys):
        console('alice', 'n', '')
        cli.username_tracker_menu()
        out = capsys.readouterr().out
        assert 'Confirmed:' in out and '1/3 platforms' in out
        assert 'Keybase' in out and 'https://keybase.io/alice' in out
        assert 'Ruled Out (1)' in out
        assert 'Inconclusive (1)' in out
        assert cli.username_tracker.calls == [
            ('alice', (), {'deep': cli_module.config.app_config.deep_username_scan})]

    def test_save_report(self, cli, console, capsys):
        console('alice', 'y', '')
        cli.username_tracker_menu()
        path = Path(saved_path(capsys.readouterr().out, 'Report saved:'))
        assert path.is_file()

    def test_invalid_username_rejected(self, cli, console, capsys):
        console('ab', '')
        cli.username_tracker_menu()
        assert 'Username must be at least 3 characters' in capsys.readouterr().out
        assert cli.username_tracker.calls == []

    def test_failure_message(self, cli, console, capsys):
        cli.username_tracker = StubTracker(dict(USERNAME_OK, success=False))
        console('alice', '')
        cli.username_tracker_menu()
        assert 'Scan failed.' in capsys.readouterr().out


class TestEmailMenu:
    def test_success_displays_breaches_and_pastes(self, cli, console, capsys):
        console('user@example.com', 'n', '')
        cli.email_tracker_menu()
        out = capsys.readouterr().out
        assert 'Key Facts' in out
        assert 'Data Breaches (1)' in out
        assert '12,345' in out
        assert 'Pastes (1)' in out
        assert cli.email_tracker.calls == [('user@example.com', (), {})]

    def test_no_breaches_message(self, cli, console, capsys):
        result = dict(EMAIL_OK)
        result['info'] = {k: v for k, v in EMAIL_OK['info'].items()
                          if k not in ('hibp_breaches', 'pastes')}
        result['info']['hibp_breached'] = False
        cli.email_tracker = StubTracker(result)
        console('user@example.com', 'n', '')
        cli.email_tracker_menu()
        assert 'No data breaches found (HaveIBeenPwned)' \
            in capsys.readouterr().out

    def test_save_report(self, cli, console, capsys):
        console('user@example.com', 'y', '')
        cli.email_tracker_menu()
        assert Path(saved_path(capsys.readouterr().out,
                               'Report saved:')).is_file()

    def test_invalid_email_rejected(self, cli, console, capsys):
        console('not-an-email', '')
        cli.email_tracker_menu()
        assert 'Invalid email format' in capsys.readouterr().out
        assert cli.email_tracker.calls == []

    def test_failure_lists_sources(self, cli, console, capsys):
        cli.email_tracker = StubTracker(EMAIL_FAIL)
        console('user@example.com', '')
        cli.email_tracker_menu()
        out = capsys.readouterr().out
        assert 'All data sources failed.' in out
        assert 'dns' in out


class TestDomainMenu:
    def test_success_displays_key_facts(self, cli, console, capsys):
        console('example.com', '0', '')
        cli.domain_tracker_menu()
        out = capsys.readouterr().out
        assert 'Key Facts' in out
        assert 'Example Registrar' in out
        assert 'Subdomains From Certificate Transparency (2)' in out
        assert 'Missing security headers' in out
        assert cli.domain_tracker.calls == [('example.com', (), {})]

    def test_many_subdomains_truncated(self, cli, console, capsys):
        subs = [f's{i}.example.com' for i in range(45)]
        cli.domain_tracker = StubTracker(_domain_result(subdomains=subs))
        console('example.com', '0', '')
        cli.domain_tracker_menu()
        out = capsys.readouterr().out
        assert 'Subdomains From Certificate Transparency (45)' in out
        assert '... and 5 more' in out

    def test_offer_markdown_report(self, cli, console, capsys):
        console('example.com', '3', '')
        cli.domain_tracker_menu()
        path = Path(saved_path(capsys.readouterr().out, 'Report saved:'))
        assert path.is_file()
        assert path.read_text(encoding='utf-8').lstrip().startswith('#')

    def test_offer_field_sources(self, cli, console, capsys):
        console('example.com', '4', '')
        cli.domain_tracker_menu()
        out = capsys.readouterr().out
        assert 'Field Sources' in out and 'rdap' in out

    def test_invalid_domain_rejected(self, cli, console, capsys):
        console('bad_domain!', '')
        cli.domain_tracker_menu()
        assert 'Invalid domain format' in capsys.readouterr().out
        assert cli.domain_tracker.calls == []

    def test_failure_lists_sources(self, cli, console, capsys):
        cli.domain_tracker = StubTracker(DOMAIN_FAIL)
        console('example.com', '')
        cli.domain_tracker_menu()
        out = capsys.readouterr().out
        assert 'Every data source failed.' in out
        assert 'rdap' in out and 'timeout' in out


# ---------------------------------------------------------------------------
# Batch operations
# ---------------------------------------------------------------------------

class TestBatchOperations:
    def test_back(self, cli, console):
        console('0')
        cli.batch_operations_menu()
        assert cli.ip_tracker.batch_calls == []

    def test_batch_ip_lookup(self, cli, console, capsys):
        console('1', '8.8.8.8', '1.1.1.1', '', 'n', 'n')
        cli.batch_operations_menu()
        out = capsys.readouterr().out
        assert 'United States' in out
        assert cli.ip_tracker.batch_calls == [['8.8.8.8', '1.1.1.1']]

    def test_batch_ip_empty_targets(self, cli, console, capsys):
        console('1', '')
        cli.batch_operations_menu()
        assert 'No IPs entered.' in capsys.readouterr().out
        assert cli.ip_tracker.batch_calls == []

    def test_batch_ip_country_chart(self, cli, console, capsys):
        console('1', '8.8.8.8', '', 'y', 'n')
        cli.batch_operations_menu()
        out = capsys.readouterr().out
        path = Path(saved_path(out, 'Chart saved:'))
        assert path.name == 'batch_countries.png'
        assert path.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n'

    def test_batch_ip_country_chart_without_country_data(self, cli, console,
                                                         capsys):
        result = dict(IP_OK)
        result['info'] = {k: v for k, v in IP_OK['info'].items()
                          if k != 'country'}
        cli.ip_tracker = StubTracker(result)
        console('1', '8.8.8.8', '', 'y', 'n')
        cli.batch_operations_menu()
        assert 'No country data to plot.' in capsys.readouterr().out

    def test_batch_ip_export_csv(self, cli, console, capsys):
        console('1', '8.8.8.8', '', 'n', 'y', '4')
        cli.batch_operations_menu()
        out = capsys.readouterr().out
        path = Path(saved_path(out, 'CSV saved:'))
        assert path.name == 'batch_ip.csv'
        assert 'target' in path.read_text(encoding='utf-8')

    def test_batch_ip_export_json(self, cli, console, capsys):
        console('1', '8.8.8.8', '', 'n', 'y', '1')
        cli.batch_operations_menu()
        assert Path(saved_path(capsys.readouterr().out,
                               'Report saved:')).is_file()

    def test_batch_phone(self, cli, console, capsys):
        console('2', '+15551234567', '', 'US', 'n')
        cli.batch_operations_menu()
        out = capsys.readouterr().out
        assert 'Verizon' in out
        assert cli.phone_tracker.batch_calls == [['+15551234567']]

    def test_batch_phone_empty(self, cli, console, capsys):
        console('2', '')
        cli.batch_operations_menu()
        assert 'No numbers entered.' in capsys.readouterr().out

    def test_batch_username(self, cli, console, capsys):
        console('3', 'alice', '', 'n')
        cli.batch_operations_menu()
        out = capsys.readouterr().out
        assert 'alice: found on 1 platforms' in out
        assert 'Keybase' in out
        assert cli.username_tracker.calls == [('alice', (), {})]

    def test_batch_username_empty(self, cli, console, capsys):
        console('3', '')
        cli.batch_operations_menu()
        assert 'No usernames entered.' in capsys.readouterr().out

    def test_batch_email(self, cli, console, capsys):
        console('4', 'user@example.com', '', 'n')
        cli.batch_operations_menu()
        out = capsys.readouterr().out
        assert 'user@example.com' in out
        assert cli.email_tracker.batch_calls == [['user@example.com']]

    def test_batch_email_empty(self, cli, console, capsys):
        console('4', '')
        cli.batch_operations_menu()
        assert 'No addresses entered.' in capsys.readouterr().out

    def test_batch_domain(self, cli, console, capsys):
        console('5', 'example.com', '', 'n')
        cli.batch_operations_menu()
        out = capsys.readouterr().out
        assert 'Example Registrar' in out
        assert cli.domain_tracker.batch_calls == [['example.com']]

    def test_batch_domain_empty(self, cli, console, capsys):
        console('5', '')
        cli.batch_operations_menu()
        assert 'No domains entered.' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# History / statistics
# ---------------------------------------------------------------------------

HISTORY = [
    FakeRecord(1, 'ip', '8.8.8.8', {'info': {'country': 'Testland'}}),
    FakeRecord(2, 'domain', 'example.com', {'info': {'registrar': 'X'}}),
]


class TestHistoryMenu:
    @pytest.fixture()
    def fake_db(self, cli, monkeypatch):
        db = FakeDb(history=HISTORY)
        monkeypatch.setattr(cli_module, 'db', db)
        return db

    def test_back(self, cli, console, fake_db):
        console('0')
        cli.history_menu()
        assert not fake_db.cleared

    def test_recent_lists_rows(self, cli, console, fake_db, capsys):
        console('1', '', '')
        cli.history_menu()
        out = capsys.readouterr().out
        assert '8.8.8.8' in out and 'example.com' in out
        assert 'ok' in out

    def test_recent_empty(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module, 'db', FakeDb(history=[]))
        console('1', '')
        cli.history_menu()
        assert 'No query history yet.' in capsys.readouterr().out

    def test_recent_inspects_record(self, cli, console, fake_db, capsys):
        console('1', '2', '')
        cli.history_menu()
        out = capsys.readouterr().out
        assert 'Record #2 - domain example.com' in out
        assert 'Testland' not in out  # record 2 is the domain one
        assert 'registrar' in out

    def test_recent_inspect_missing_record(self, cli, console, fake_db,
                                           capsys):
        console('1', '999', '')
        cli.history_menu()
        assert 'Record not found.' in capsys.readouterr().out

    def test_search_history(self, cli, console, fake_db, capsys):
        console('2', '8.8.8.8', '', '')
        cli.history_menu()
        out = capsys.readouterr().out
        assert "Results for '8.8.8.8'" in out
        assert fake_db.searched == ['8.8.8.8']

    def test_search_history_empty(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module, 'db', FakeDb(history=HISTORY))
        console('2', 'zzz-no-match', '', '')
        cli.history_menu()
        assert 'No matching queries.' in capsys.readouterr().out

    def test_clear_confirmed(self, cli, console, fake_db, capsys):
        console('3', 'y', '')
        cli.history_menu()
        assert 'Cleared 2 records' in capsys.readouterr().out
        assert fake_db.cleared

    def test_clear_declined(self, cli, console, fake_db):
        console('3', 'n')
        cli.history_menu()
        assert not fake_db.cleared


class TestStatisticsMenu:
    def test_dashboard_generated_on_confirm(self, cli, console, monkeypatch,
                                            capsys):
        monkeypatch.setattr(cli_module, 'db', FakeDb())
        console('y', '')
        cli.statistics_menu()
        out = capsys.readouterr().out
        assert 'Total queries' in out
        assert 'Response Cache' in out
        assert 'Network (this session)' in out
        path = Path(saved_path(out, 'Dashboard saved:'))
        assert path.name == 'dashboard.png'
        assert path.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n'

    def test_dashboard_declined(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module, 'db', FakeDb())
        console('n', '')
        cli.statistics_menu()
        out = capsys.readouterr().out
        assert 'Dashboard saved' not in out
        assert 'Response Cache' in out

    def test_no_queries_by_type_skips_confirm(self, cli, console, monkeypatch):
        stats = {'total_queries': 0, 'success_rate': 0, 'recent_queries_7d': 0,
                 'queries_by_type': {}}
        monkeypatch.setattr(cli_module, 'db', FakeDb(stats=stats))
        console('')
        cli.statistics_menu()   # no confirm prompt, only the final Enter


# ---------------------------------------------------------------------------
# Settings / API status
# ---------------------------------------------------------------------------

@pytest.fixture()
def config_recorder(monkeypatch):
    """Silence config persistence and record mutations."""
    saved = []
    monkeypatch.setattr(cli_module.config, 'save_config',
                        lambda: saved.append('config'))
    monkeypatch.setattr(cli_module.config, 'save_secrets',
                        lambda: saved.append('secrets'))
    return saved


class TestSettingsMenu:
    def test_view_configuration(self, cli, console, capsys):
        console('1', '')
        cli.settings_menu()
        out = capsys.readouterr().out
        assert 'Application Settings' in out
        assert 'API Keys' in out
        assert 'configured' in out or 'not configured' in out
        assert 'Request timeout' in out

    def test_configure_api_keys_all_skipped(self, cli, console, monkeypatch,
                                            capsys, config_recorder):
        monkeypatch.setattr(cli_module, 'SERVICES', ('shodan', 'virustotal'))
        monkeypatch.setattr(cli_module.config, 'get_api_key',
                            lambda service: None)
        set_calls = []
        monkeypatch.setattr(cli_module.config, 'set_api_key',
                            lambda service, value: set_calls.append(service))
        monkeypatch.setattr('getpass.getpass', lambda prompt: '')
        console('2', '')
        cli.settings_menu()
        out = capsys.readouterr().out
        assert set_calls == []
        assert 'Secrets written to config/secrets.yaml' in out
        assert config_recorder == ['secrets']

    def test_configure_api_keys_saves_entered_key(self, cli, console,
                                                  monkeypatch, capsys,
                                                  config_recorder):
        monkeypatch.setattr(cli_module, 'SERVICES', ('shodan', 'virustotal'))
        monkeypatch.setattr(cli_module.config, 'get_api_key',
                            lambda service: None)
        set_calls = []
        monkeypatch.setattr(cli_module.config, 'set_api_key',
                            lambda service, value: set_calls.append(
                                (service, value)))
        answers = iter(['secret-key', ''])
        monkeypatch.setattr('getpass.getpass', lambda prompt: next(answers))
        console('2', '')
        cli.settings_menu()
        out = capsys.readouterr().out
        assert set_calls == [('shodan', 'secret-key')]
        assert 'shodan key saved' in out

    def test_configure_api_keys_replace_declined(self, cli, console,
                                                 monkeypatch, capsys):
        monkeypatch.setattr(cli_module, 'SERVICES', ('shodan',))
        monkeypatch.setattr(cli_module.config, 'get_api_key',
                            lambda service: 'abcd-12345678')
        set_calls = []
        monkeypatch.setattr(cli_module.config, 'set_api_key',
                            lambda service, value: set_calls.append(service))
        monkeypatch.setattr('getpass.getpass', lambda prompt: '')
        console('2', 'n', '')
        cli.settings_menu()
        out = capsys.readouterr().out
        assert '********5678 (configured)' in out
        assert set_calls == []

    def test_set_output_format(self, cli, console, monkeypatch, capsys,
                               config_recorder):
        monkeypatch.setattr(cli_module.config.app_config, 'output_format',
                            'json')
        console('3', '1', '')
        cli.settings_menu()
        out = capsys.readouterr().out
        assert 'Output format set to table' in out
        assert cli_module.config.app_config.output_format == 'table'
        assert config_recorder == ['config']

    def test_set_output_format_unknown_choice(self, cli, console, capsys,
                                              config_recorder):
        console('3', '9', '')
        cli.settings_menu()
        assert 'Output format set' not in capsys.readouterr().out
        assert config_recorder == []

    def test_toggle_history(self, cli, console, monkeypatch, capsys,
                            config_recorder):
        monkeypatch.setattr(cli_module.config.app_config, 'save_history',
                            False)
        console('4', '')
        cli.settings_menu()
        assert 'History saving enabled' in capsys.readouterr().out
        assert config_recorder == ['config']

    def test_toggle_deep_scan(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module.config.app_config,
                            'deep_username_scan', False)
        console('5', '')
        cli.settings_menu()
        assert 'Deep username scan on' in capsys.readouterr().out

    def test_set_timeout_invalid(self, cli, console, capsys):
        console('6', 'abc', '')
        cli.settings_menu()
        assert 'Enter a number between 5 and 300.' in capsys.readouterr().out

    def test_set_timeout_out_of_range(self, cli, console, capsys):
        console('6', '500', '')
        cli.settings_menu()
        assert 'Enter a number between 5 and 300.' in capsys.readouterr().out

    def test_set_timeout_valid(self, cli, console, monkeypatch, capsys,
                               config_recorder):
        monkeypatch.setattr(cli_module.config.app_config, 'request_timeout',
                            10)
        console('6', '30', '')
        cli.settings_menu()
        out = capsys.readouterr().out
        assert 'Request timeout set to 30s' in out
        assert cli_module.config.app_config.request_timeout == 30
        assert config_recorder == ['config']

    def test_toggle_cache(self, cli, console, monkeypatch, capsys,
                          config_recorder):
        monkeypatch.setattr(cli_module.config.app_config, 'cache_enabled',
                            False)
        console('7', '')
        cli.settings_menu()
        assert 'Response cache enabled' in capsys.readouterr().out

    def test_set_rate_limit_blank_keeps_current(self, cli, console, capsys,
                                                config_recorder):
        console('8', '', '')
        cli.settings_menu()
        assert 'No change.' in capsys.readouterr().out
        assert config_recorder == []

    def test_set_rate_limit_valid(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module.config.app_config,
                            'requests_per_second', 0.0)
        console('8', '8', '')
        cli.settings_menu()
        assert 'Rate limit set to 8.0/s per host' in capsys.readouterr().out

    def test_set_rate_limit_invalid(self, cli, console, capsys):
        console('8', 'abc', '')
        cli.settings_menu()
        assert 'Enter a number between 0 and 100.' in capsys.readouterr().out

    def test_set_proxy(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module.config.app_config, 'proxy', '')
        console('9', 'http://127.0.0.1:8080', '')
        cli.settings_menu()
        assert 'Proxy set to http://127.0.0.1:8080' in capsys.readouterr().out

    def test_set_proxy_blank_clears(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module.config.app_config, 'proxy',
                            'http://old:8080')
        console('9', '', '')
        cli.settings_menu()
        assert 'Proxy cleared' in capsys.readouterr().out

    def test_clear_cache_declined(self, cli, console, monkeypatch):
        monkeypatch.setattr(cli_module, 'cache',
                            type('C', (), {'clear': staticmethod(
                                lambda: pytest.fail('cache cleared'))})())
        console('10', 'n')
        cli.settings_menu()

    def test_clear_cache_confirmed(self, cli, console, monkeypatch, capsys):
        cleared = []
        monkeypatch.setattr(cli_module, 'cache',
                            type('C', (), {'clear': staticmethod(
                                lambda: cleared.append(True) or 5)})())
        console('10', 'y', '')
        cli.settings_menu()
        assert 'Removed 5 cached responses' in capsys.readouterr().out


class TestApiStatusMenu:
    def test_lists_services_and_keyless_hint(self, cli, console, monkeypatch,
                                             capsys):
        monkeypatch.setattr(cli_module, 'SERVICES',
                            ('shodan', 'haveibeenpwned'))
        console('')
        cli.api_status_menu()
        out = capsys.readouterr().out
        assert 'shodan' in out and 'haveibeenpwned' in out
        assert 'Key Set' in out and 'Status' in out
        assert 'Keyless sources for IP' in out


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------

class TestWatchlistMenu:
    @pytest.fixture()
    def watch(self, cli, monkeypatch):
        fake = FakeWatchlist()
        monkeypatch.setattr(cli_module, 'watchlist', fake)
        return fake

    def test_empty_list_back(self, cli, console, watch, capsys):
        console('0', '')
        cli.watchlist_menu()
        assert 'No watched targets yet.' in capsys.readouterr().out

    def test_list_entries_rendered(self, cli, console, monkeypatch, capsys):
        entries = [FakeWatchEntry(3, '8.8.8.8', 'ip', 'dns'),
                   FakeWatchEntry(4, 'example.com', 'domain')]
        monkeypatch.setattr(cli_module, 'watchlist',
                            FakeWatchlist(entries=entries))
        console('0', '')
        cli.watchlist_menu()
        out = capsys.readouterr().out
        assert '8.8.8.8' in out and 'example.com' in out
        assert 'Last Checked' in out

    def test_add_target(self, cli, console, watch, capsys):
        console('1', '8.8.8.8', 'dns', '')
        cli.watchlist_menu()
        out = capsys.readouterr().out
        assert 'Watching #7: 8.8.8.8' in out
        assert watch.added == [('8.8.8.8', 'dns')]

    def test_add_invalid_target_error(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module, 'watchlist',
                            FakeWatchlist(add_error='unsupported target'))
        console('1', '!!!', '', '')
        cli.watchlist_menu()
        assert 'unsupported target' in capsys.readouterr().out

    def test_check_no_entries(self, cli, console, watch, capsys):
        console('2', '', '')
        cli.watchlist_menu()
        assert 'No matching watch entries.' in capsys.readouterr().out

    def test_check_renders_diffs(self, cli, console, monkeypatch, capsys):
        diff = FakeWatchDiff(
            watch_id=3, target='8.8.8.8', is_first=False,
            added={'ports': '[53]'}, removed={'org': 'Old'},
            changed={'country': {'from': 'US', 'to': 'NL'}})
        monkeypatch.setattr(cli_module, 'watchlist',
                            FakeWatchlist(diffs=[diff]))
        console('2', '3', '')
        cli.watchlist_menu()
        out = capsys.readouterr().out
        assert 'Results' in out and 'Added' in out and 'Removed' in out
        assert 'Changes' in out
        assert 'US' in out and 'NL' in out
        assert 'ports' in out

    def test_check_by_target_string(self, cli, console, watch):
        console('2', '8.8.8.8', '')
        cli.watchlist_menu()
        assert watch.checked == ['8.8.8.8']

    def test_remove_found(self, cli, console, monkeypatch, capsys):
        entries = [FakeWatchEntry(3, '8.8.8.8', 'ip')]
        monkeypatch.setattr(cli_module, 'watchlist',
                            FakeWatchlist(entries=entries))
        console('3', '3', '')
        cli.watchlist_menu()
        assert 'Removed 1 watch entry' in capsys.readouterr().out

    def test_remove_missing(self, cli, console, watch, capsys):
        console('3', '42', '')
        cli.watchlist_menu()
        assert 'No matching watch entry.' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Universal investigate
# ---------------------------------------------------------------------------

class TestInvestigateMenu:
    def test_unknown_target_error(self, cli, console, capsys):
        console('not a target!', '')
        cli.investigate_menu()
        out = capsys.readouterr().out
        assert 'Cannot determine target type' in out
        assert 'not a target!' in out

    def test_investigate_ip_without_pivot(self, cli, console, monkeypatch,
                                          capsys):
        calls = []
        monkeypatch.setattr(
            cli_module, 'investigate',
            lambda target, pivot=None: calls.append((target, pivot))
            or INVESTIGATE_PAYLOAD)
        console('8.8.8.8', 'n', 'n', '')
        cli.investigate_menu()
        out = capsys.readouterr().out
        assert 'IP RESULT' in out
        assert 'Mountain View' in out
        assert calls == [('8.8.8.8', False)]

    def test_investigate_with_pivot(self, cli, console, monkeypatch):
        calls = []
        monkeypatch.setattr(
            cli_module, 'investigate',
            lambda target, pivot=None: calls.append((target, pivot))
            or INVESTIGATE_PAYLOAD)
        console('example.com', 'y', 'n', '')
        cli.investigate_menu()
        assert calls == [('example.com', True)]

    def test_entities_and_errors_rendered(self, cli, console, monkeypatch,
                                          capsys):
        monkeypatch.setattr(cli_module, 'investigate',
                            lambda target, pivot=None: INVESTIGATE_PAYLOAD)
        console('example.com', 'n', 'n', '')
        cli.investigate_menu()
        out = capsys.readouterr().out
        assert 'Entities' in out and 'a_record' in out
        assert 'rdap source unavailable' in out

    def test_mermaid_graph_saved(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module, 'investigate',
                            lambda target, pivot=None: INVESTIGATE_PAYLOAD)
        console('example.com', 'n', 'y', '')
        cli.investigate_menu()
        out = capsys.readouterr().out
        path = Path(saved_path(out, 'Graph saved:'))
        assert path.name == 'example.com.mmd'  # dots survive the sanitiser
        assert path.read_text(encoding='utf-8').startswith('graph LR')

    def test_mermaid_declined(self, cli, console, monkeypatch, capsys):
        monkeypatch.setattr(cli_module, 'investigate',
                            lambda target, pivot=None: INVESTIGATE_PAYLOAD)
        console('example.com', 'n', 'n', '')
        cli.investigate_menu()
        assert 'Graph saved' not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# v4 / v5 submenus (dispatched through commands.run)
# ---------------------------------------------------------------------------

@pytest.fixture()
def run_recorder(monkeypatch):
    import obscuralens.commands as commands_module
    recorded = []
    monkeypatch.setattr(commands_module, 'run',
                        lambda argv: recorded.append(list(argv)) or 0)
    return recorded


class TestV4ToolsMenu:
    def test_back(self, cli, console, run_recorder):
        console('0')
        cli.v4_tools_menu()
        assert run_recorder == []

    def test_invalid_choice(self, cli, console, capsys):
        console('99')
        cli.v4_tools_menu()
        assert 'Invalid option.' in capsys.readouterr().out

    @pytest.mark.parametrize('choice,command,target', [
        ('1', 'url', 'https://example.com'),
        ('2', 'crypto', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'),
        ('3', 'hash', '44d88612fea8a8f36de82e1278abb02f'),
        ('4', 'cve', 'CVE-2021-44228'),
        ('5', 'asn', 'AS15169'),
    ])
    def test_simple_tracker_dispatch(self, cli, console, run_recorder,
                                     choice, command, target):
        console(choice, target, '')
        cli.v4_tools_menu()
        assert run_recorder == [[command, target]]

    def test_risk_scoring(self, cli, console, run_recorder):
        console('6', 'ip', '8.8.8.8', '')
        cli.v4_tools_menu()
        assert run_recorder == [['risk', 'ip', '8.8.8.8']]

    def test_risk_without_target_skips(self, cli, console, run_recorder):
        console('6', '', '')
        cli.v4_tools_menu()
        assert run_recorder == []

    def test_result_diff(self, cli, console, run_recorder):
        console('9', '12', '13', '')
        cli.v4_tools_menu()
        assert run_recorder == [['diff', '12', '13']]

    def test_timeline_with_filter(self, cli, console, run_recorder):
        console('7', '8.8.8.8', '')
        cli.v4_tools_menu()
        assert run_recorder == [['timeline', '8.8.8.8']]

    def test_timeline_all(self, cli, console, run_recorder):
        console('7', '', '')
        cli.v4_tools_menu()
        assert run_recorder == [['timeline']]

    def test_correlate_all(self, cli, console, run_recorder):
        console('8', '')
        cli.v4_tools_menu()
        assert run_recorder == [['correlate', '--all']]

    def test_graph_export(self, cli, console, run_recorder):
        console('10', 'example.com', 'gexf', '')
        cli.v4_tools_menu()
        assert run_recorder == [['export', 'gexf', 'example.com']]

    def test_graph_export_default_format(self, cli, console, run_recorder):
        console('10', 'example.com', '', '')
        cli.v4_tools_menu()
        assert run_recorder == [['export', 'graphml', 'example.com']]

    def test_graph_export_without_target_skips(self, cli, console,
                                               run_recorder):
        console('10', '', 'graphml', '')
        cli.v4_tools_menu()
        assert run_recorder == []

    def test_threat_intel(self, cli, console, run_recorder):
        console('11', '8.8.8.8', '')
        cli.v4_tools_menu()
        assert run_recorder == [['intel', 'ip', '8.8.8.8']]

    def test_case_management(self, cli, console, run_recorder):
        console('12', '')
        cli.v4_tools_menu()
        assert run_recorder == [['case', 'list']]

    def test_pipelines(self, cli, console, run_recorder):
        console('13', '')
        cli.v4_tools_menu()
        assert run_recorder == [['pipeline', 'list']]

    def test_experimental_back(self, cli, console, run_recorder):
        console('14', '0')
        cli.v4_tools_menu()
        assert run_recorder == []

    def test_experimental_permute(self, cli, console, run_recorder):
        console('14', '2', 'alice', 'n', '')
        cli.v4_tools_menu()
        assert run_recorder == [['experimental', 'permute', 'alice']]

    def test_experimental_permute_with_scan(self, cli, console, run_recorder):
        console('14', '2', 'alice', 'y', '')
        cli.v4_tools_menu()
        assert run_recorder == [['experimental', 'permute', 'alice', '--scan']]

    def test_experimental_llm(self, cli, console, run_recorder):
        console('14', '1', 'ip', '8.8.8.8', '')
        cli.v4_tools_menu()
        assert run_recorder == [['experimental', 'llm', 'ip', '8.8.8.8']]

    def test_experimental_crawl(self, cli, console, run_recorder):
        console('14', '3', 'https://example.test', '')
        cli.v4_tools_menu()
        assert run_recorder == [['experimental', 'crawl', 'https://example.test']]

    def test_experimental_phish(self, cli, console, run_recorder):
        console('14', '4', 'example.com', '')
        cli.v4_tools_menu()
        assert run_recorder == [['experimental', 'phish', 'example.com']]


class TestV5ToolsMenu:
    def test_back(self, cli, console, run_recorder):
        console('0')
        cli.v5_tools_menu()
        assert run_recorder == []

    def test_invalid_choice(self, cli, console, capsys):
        console('99')
        cli.v5_tools_menu()
        assert 'Invalid option.' in capsys.readouterr().out

    def test_toolbox_encode(self, cli, console, run_recorder):
        console('1', '1', 'hello world', '', '0')
        cli.v5_tools_menu()
        assert run_recorder == [['tools', 'encode', 'hello world']]

    def test_toolbox_back(self, cli, console, run_recorder):
        console('1', '0')
        cli.v5_tools_menu()
        assert run_recorder == []

    def test_toolbox_invalid_tool(self, cli, console, capsys, run_recorder):
        console('1', '99', '0')
        cli.v5_tools_menu()
        assert 'Invalid option.' in capsys.readouterr().out
        assert run_recorder == []

    def test_toolbox_decode_autodetect(self, cli, console, run_recorder):
        console('1', '2', 'aGVsbG8=', 'y', '', '0')
        cli.v5_tools_menu()
        assert run_recorder == [['tools', 'decode', 'aGVsbG8=', '--all']]

    def test_toolbox_decode_explicit_scheme(self, cli, console, run_recorder):
        console('1', '2', 'aGVsbG8=', 'n', 'hex', '', '0')
        cli.v5_tools_menu()
        assert run_recorder == [['tools', 'decode', 'aGVsbG8=',
                                 '--scheme', 'hex']]

    @pytest.mark.parametrize('choice,command,value', [
        ('3', 'jwt', 'eyJhbGciOiJIUzI1NiJ9.x.y'),
        ('4', 'hash-id', '44d88612fea8a8f36de82e1278abb02f'),
        ('5', 'coords', '48.8584, 2.2945'),
        ('8', 'exif', 'photo.jpg'),
        ('9', 'stego', 'photo.png'),
    ])
    def test_toolbox_simple_tools(self, cli, console, run_recorder, choice,
                                  command, value):
        console('1', choice, value, '', '0')
        cli.v5_tools_menu()
        assert run_recorder == [['tools', command, value]]

    def test_toolbox_extract_text(self, cli, console, run_recorder):
        console('1', '6', 'contact me at bob@example.com', '', '0')
        cli.v5_tools_menu()
        assert run_recorder == [['tools', 'extract', 'contact me at '
                                                   'bob@example.com']]

    def test_toolbox_extract_from_file(self, cli, console, run_recorder):
        console('1', '6', '', '/tmp/scan.txt', '', '0')
        cli.v5_tools_menu()
        assert run_recorder == [['tools', 'extract', '--file', '/tmp/scan.txt']]

    def test_toolbox_squat(self, cli, console, run_recorder):
        console('1', '7', 'google.com', '', '0')
        cli.v5_tools_menu()
        assert run_recorder == [['tools', 'squat', 'google.com']]

    def test_batch_lookup(self, cli, console, run_recorder):
        console('2', 'ip', '/tmp/targets.txt', 'n', '')
        cli.v5_tools_menu()
        assert run_recorder == [['batch', 'ip', '/tmp/targets.txt']]

    def test_batch_lookup_with_risk(self, cli, console, run_recorder):
        console('2', 'ip', '/tmp/targets.txt', 'y', '')
        cli.v5_tools_menu()
        assert run_recorder == [['batch', 'ip', '/tmp/targets.txt', '--risk']]

    def test_batch_lookup_missing_kind_skips(self, cli, console, run_recorder):
        console('2', '', '/tmp/targets.txt')
        cli.v5_tools_menu()
        assert run_recorder == []

    def test_report_builder(self, cli, console, run_recorder):
        console('3', 'ip', '8.8.8.8', '')
        cli.v5_tools_menu()
        assert run_recorder == [['report', 'ip', '8.8.8.8']]

    def test_pattern_analysis(self, cli, console, run_recorder):
        console('4', 'domain', 'example.com', '')
        cli.v5_tools_menu()
        assert run_recorder == [['patterns', 'domain', 'example.com']]

    def test_geo_profile(self, cli, console, run_recorder):
        console('5', '')
        cli.v5_tools_menu()
        assert run_recorder == [['geo', 'profile']]

    def test_alerts_show(self, cli, console, run_recorder):
        console('6', '1', '')
        cli.v5_tools_menu()
        assert run_recorder == [['alerts', 'show']]

    def test_alerts_set_with_events(self, cli, console, run_recorder):
        console('6', '2', 'https://hook.test/x', 'watch.add', '')
        cli.v5_tools_menu()
        assert run_recorder == [['alerts', 'set', '--url', 'https://hook.test/x',
                                 '--events', 'watch.add']]

    def test_alerts_set_without_events(self, cli, console, run_recorder):
        console('6', '2', 'https://hook.test/x', '', '')
        cli.v5_tools_menu()
        assert run_recorder == [['alerts', 'set', '--url', 'https://hook.test/x']]

    def test_alerts_set_without_url_skips(self, cli, console, run_recorder):
        console('6', '2', '', '')
        cli.v5_tools_menu()
        assert run_recorder == []

    def test_alerts_test(self, cli, console, run_recorder):
        console('6', '3', '')
        cli.v5_tools_menu()
        assert run_recorder == [['alerts', 'test']]

    def test_alerts_back(self, cli, console, run_recorder):
        console('6', '0')
        cli.v5_tools_menu()
        assert run_recorder == []


class TestV5TrackersMenu:
    def test_back(self, cli, console, run_recorder):
        console('0')
        cli.v5_trackers_menu()
        assert run_recorder == []

    def test_invalid_choice(self, cli, console, capsys):
        console('9')
        cli.v5_trackers_menu()
        assert 'Invalid option.' in capsys.readouterr().out

    @pytest.mark.parametrize('choice,command,target', [
        ('1', 'mac', 'b8:27:eb:11:22:33'),
        ('2', 'iban', 'DE89370400440532013000'),
        ('3', 'imei', '356938035643809'),
        ('4', 'coords', '48.8584, 2.2945'),
    ])
    def test_dispatch(self, cli, console, run_recorder, choice, command,
                      target):
        console(choice, target, '')
        cli.v5_trackers_menu()
        assert run_recorder == [[command, target]]

    def test_empty_target_skips(self, cli, console, run_recorder):
        console('1', '')
        cli.v5_trackers_menu()
        assert run_recorder == []
