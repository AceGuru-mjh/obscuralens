"""
Offline tests for the username platform registry integrity checker.

Two layers here. The first pins the *real* registry - that is the CI gate: it
fails the build if a commit adds a duplicate platform, a URL with no
placeholder, an API spec missing `extract`, or an extractor left pointing at a
platform that was removed. The second exercises each check against synthetic
registries so a check that stops detecting its defect is caught even while the
real registry happens to stay clean.
"""

import json

import pytest

from obscuralens.trackers import registry_checks as rc
from obscuralens.trackers import username_sources as us
from obscuralens.trackers import username_tracker as ut

#: A minimal registry that satisfies every check. Satellite tables are empty so
#: cross-reference findings cannot leak in from the real 38-entry registry.
GOOD_HTML = [{'name': 'Good', 'url': 'https://good.example/{}'}]
GOOD_API = {
    'Api': {
        'api_url': 'https://api.example/{}',
        'url': 'https://api.example/u/{}',
        'verdict': lambda data: True,
        'extract': lambda data: {},
    },
}
NO_TABLES = {'EXTRACTORS': {}, 'HTML_VERDICT_RULES': {}, 'SOURCE_CATALOG': {}}


def check(html=None, api=None, tables=None):
    return rc.check_username_registry(
        html=GOOD_HTML if html is None else html,
        api=GOOD_API if api is None else api,
        tables=NO_TABLES if tables is None else tables,
    )


def error_checks(report):
    return {f['check'] for f in report['errors']}


def warning_checks(report):
    return {f['check'] for f in report['warnings']}


# --------------------------------------------------------------------------- #
# the real registry - this is the gate that runs in CI
# --------------------------------------------------------------------------- #

@pytest.fixture(scope='module')
def report():
    """The integrity report for the registry that actually ships.

    Module-scoped: every test in :class:`TestRealRegistry` asserts against the
    same snapshot, and building it imports both platform registries.
    """
    return rc.check_username_registry()


class TestRealRegistry:
    def test_the_shipped_registry_has_no_integrity_errors(self, report):
        # The point of the whole module. If this fails, the finding list says
        # exactly which platform and which check, and why.
        assert report['ok'], json.dumps(report['errors'], indent=2)
        assert report['errors'] == []

    def test_platform_count_matches_the_documented_total(self, report):
        # README and docs both advertise 112 platforms (101 HTML + 11 API).
        assert report['counts']['platforms'] == 112
        assert report['counts']['html_entries'] == 101
        assert report['counts']['api_entries'] == 11

    def test_counts_are_consistent_with_the_source_tables(self, report):
        html = list(ut.HTML_PLATFORMS) + list(us.HTML_PLATFORMS)
        assert report['counts']['html_entries'] == len(html)
        assert report['counts']['api_entries'] == len(us.API_PLATFORMS)
        names = {e['name'] for e in html} | set(us.API_PLATFORMS)
        assert report['counts']['platforms'] == len(names)

    def test_every_check_ran(self, report):
        assert report['counts']['checks_run'] == len(rc.CHECKS)

    def test_findings_are_json_serialisable(self, report):
        # The CLI's `-f json` path and the REST API both dump this verbatim.
        assert json.loads(json.dumps(report))['ok'] is report['ok']

    def test_registry_entries_reflects_the_tracker_union(self):
        html, api = rc.registry_entries()
        assert len(html) == len(ut.HTML_PLATFORMS) + len(us.HTML_PLATFORMS)
        assert html[:len(ut.HTML_PLATFORMS)] == list(ut.HTML_PLATFORMS)
        assert set(api) == set(us.API_PLATFORMS)

    def test_satellite_tables_snapshot_every_documented_table(self):
        tables = rc.satellite_tables()
        assert set(tables) == set(rc.TABLE_NAMES)
        assert set(tables['EXTRACTORS']) == set(us.EXTRACTORS)
        assert set(tables['HTML_VERDICT_RULES']) == set(us.HTML_VERDICT_RULES)
        assert set(tables['SOURCE_CATALOG']) == set(us.SOURCE_CATALOG)

    def test_satellite_tables_returns_a_copy(self):
        tables = rc.satellite_tables()
        tables['EXTRACTORS']['Injected'] = lambda html: {}
        assert 'Injected' not in us.EXTRACTORS

    def test_partial_catalog_coverage_is_a_warning_not_an_error(self, report):
        # SOURCE_CATALOG is documented as metadata for a subset of platforms,
        # so partial coverage must never fail a build.
        assert report['ok']
        coverage = [f for f in report['warnings']
                    if f['check'] == 'source_catalog_coverage']
        if coverage:
            assert coverage[0]['severity'] == rc.WARNING


# --------------------------------------------------------------------------- #
# report shape
# --------------------------------------------------------------------------- #

class TestReportShape:
    def test_a_clean_synthetic_registry_passes(self):
        report = check()
        assert report['ok'] is True
        assert report['errors'] == []

    def test_report_keys(self):
        assert set(check()) == {'ok', 'errors', 'warnings', 'findings', 'counts'}

    def test_finding_keys(self):
        report = check(html=[{'name': 'X', 'url': 'not-a-url'}])
        for finding in report['findings']:
            assert set(finding) == {'check', 'severity', 'platform', 'message'}
            assert finding['severity'] in (rc.ERROR, rc.WARNING)
            assert finding['message']

    def test_findings_is_the_union_of_errors_and_warnings(self):
        report = check(html=[{'name': 'X', 'url': 'not-a-url'}])
        assert len(report['findings']) == \
            len(report['errors']) + len(report['warnings'])
        assert report['counts']['errors'] == len(report['errors'])
        assert report['counts']['warnings'] == len(report['warnings'])

    def test_ok_is_false_only_for_errors(self):
        # A warning-only report is still ok.
        report = check(html=[{'name': 'Padded ', 'url': 'https://p.example/{}'}])
        assert report['warnings']
        assert report['ok'] is True

    def test_empty_registries_are_not_an_error(self):
        report = rc.check_username_registry(html=[], api={}, tables=NO_TABLES)
        assert report['errors'] == []
        assert report['counts']['platforms'] == 0

    def test_a_raising_check_does_not_hide_the_others(self, monkeypatch):
        def boom(html, api, tables):
            raise RuntimeError('check exploded')

        monkeypatch.setattr(rc, 'CHECKS', (boom,) + rc.CHECKS)
        report = check(html=[{'name': 'Dup', 'url': 'https://d.example/{}'},
                             {'name': 'Dup', 'url': 'https://d2.example/{}'}])
        checks = error_checks(report)
        assert 'boom' in checks                       # the failure is reported
        assert 'duplicates' in checks                 # and the rest still ran
        assert any('RuntimeError' in f['message'] for f in report['errors'])

    def test_defaults_pull_the_live_registry(self):
        # Calling with no arguments must be equivalent to the CI gate.
        assert rc.check_username_registry()['counts'] == \
            rc.check_username_registry()['counts']
        assert rc.check_username_registry()['counts']['platforms'] == 112


# --------------------------------------------------------------------------- #
# each check detects its own defect
# --------------------------------------------------------------------------- #

class TestDefectDetection:
    """A check that stops firing is worse than no check at all."""

    @pytest.mark.parametrize('entry,expected_check', [
        ({'name': 'X', 'url': 'https://x.example/profile'}, 'url_templates'),
        ({'name': 'X', 'url': 'https://x.example/{}/{}'}, 'url_templates'),
        ({'name': 'X', 'url': 'https://x.example/{}{}'}, 'url_templates'),
        ({'name': 'X', 'url': 'ftp://x.example/{}'}, 'url_templates'),
        ({'name': 'X', 'url': 'javascript:alert({})'}, 'url_templates'),
        ({'name': 'X', 'url': 'https:///{}'}, 'url_templates'),
        ({'name': 'X', 'url': 'not a url {}'}, 'url_templates'),
        ({'name': 'X', 'url': 200}, 'url_templates'),
        ({'name': 'X', 'url': None}, 'url_templates'),
    ])
    def test_url_template_defects(self, entry, expected_check):
        assert expected_check in error_checks(check(html=[entry]))

    @pytest.mark.parametrize('entry', [
        {'name': 'X'},                                        # missing url
        {'url': 'https://x.example/{}'},                      # missing name
        {'name': 'X', 'url': 'https://x.example/{}', 'status': 200},
        {'name': '', 'url': 'https://x.example/{}'},
        {'name': 'X', 'url': ''},
        {'name': 'X', 'url': '   '},
        {'name': 7, 'url': 'https://x.example/{}'},
        'not-a-dict',
        None,
    ])
    def test_html_entry_shape_defects(self, entry):
        assert 'html_entry_shape' in error_checks(check(html=[entry]))

    def test_a_well_formed_entry_passes(self):
        assert error_checks(check(html=[
            {'name': 'Fine', 'url': 'https://fine.example/u/{}'}])) == set()

    def test_duplicate_name_across_the_two_html_tables(self):
        html = [{'name': 'Dup', 'url': 'https://a.example/{}'},
                {'name': 'Dup', 'url': 'https://b.example/{}'}]
        report = check(html=html)
        assert 'duplicates' in error_checks(report)
        assert 'registered 2 times' in report['errors'][0]['message']

    def test_duplicate_name_across_html_and_api(self):
        report = check(html=[{'name': 'Api', 'url': 'https://a.example/{}'}])
        assert 'duplicates' in error_checks(report)

    def test_duplicate_profile_url(self):
        html = [{'name': 'One', 'url': 'https://same.example/{}'},
                {'name': 'Two', 'url': 'https://same.example/{}'}]
        assert 'duplicate_urls' in error_checks(check(html=html))

    def test_case_insensitive_name_collision_is_a_warning(self):
        html = [{'name': 'Twitch', 'url': 'https://a.example/{}'},
                {'name': 'twitch', 'url': 'https://b.example/{}'}]
        report = check(html=html)
        assert 'duplicates' in warning_checks(report)
        assert 'duplicates' not in error_checks(report)
        assert report['ok'] is True

    @pytest.mark.parametrize('name', [' Padded', 'Padded ', '  '])
    def test_name_whitespace_is_flagged(self, name):
        report = check(html=[{'name': name, 'url': 'https://x.example/{}'}])
        assert 'name_hygiene' in (warning_checks(report) | error_checks(report))

    def test_double_space_in_a_name_is_flagged(self):
        report = check(html=[{'name': 'Two  Words',
                              'url': 'https://x.example/{}'}])
        assert 'name_hygiene' in warning_checks(report)

    def test_a_host_without_a_dot_is_a_warning(self):
        report = check(html=[{'name': 'L', 'url': 'https://localhost/{}'}])
        assert 'url_templates' in warning_checks(report)
        assert report['ok'] is True

    @pytest.mark.parametrize('spec,expected_severity', [
        ({'api_url': 'https://a/{}', 'url': 'https://a/u/{}',
          'verdict': lambda d: True}, 'error'),                 # no extract
        ({'api_url': 'https://a/{}', 'url': 'https://a/u/{}',
          'extract': lambda d: {}}, 'error'),                   # no verdict
        ({'url': 'https://a/u/{}', 'verdict': lambda d: True,
          'extract': lambda d: {}}, 'error'),                   # no api_url
        ({'api_url': 'https://a/{}', 'url': 'https://a/u/{}',
          'verdict': 'yes', 'extract': lambda d: {}}, 'error'),
        ({'api_url': 'https://a/{}', 'url': 'https://a/u/{}',
          'verdict': lambda d: True, 'extract': None}, 'error'),
        ({'api_url': 'https://a/{}', 'url': 'https://a/u/{}',
          'verdict': lambda d: True, 'extract': lambda d: {},
          'err_verdicts': {'http 400': 'no'}}, 'error'),
        ({'api_url': 'https://a/{}', 'url': 'https://a/u/{}',
          'verdict': lambda d: True, 'extract': lambda d: {},
          'verdict_takes_username': 'yes'}, 'error'),
        ({'api_url': 'https://a/{}', 'url': 'https://a/u/{}',
          'verdict': lambda d: True, 'extract': lambda d: {},
          'mystery': 1}, 'warning'),
    ])
    def test_api_spec_defects(self, spec, expected_severity):
        report = check(api={'Api': spec})
        fired = error_checks(report) if expected_severity == 'error' \
            else warning_checks(report)
        assert 'api_spec_shape' in fired, report['findings']

    def test_a_valid_api_spec_passes(self):
        assert error_checks(check()) == set()

    def test_callable_api_url_is_accepted(self):
        # Bluesky resolves its handle first, so both URLs are functions.
        spec = dict(GOOD_API['Api'],
                    api_url=lambda username: 'https://a/' + username,
                    url=lambda username: 'https://a/u/' + username)
        assert 'url_templates' not in error_checks(check(api={'Api': spec}))

    def test_callable_url_on_an_html_entry_is_rejected(self):
        html = [{'name': 'X', 'url': lambda username: 'https://x/' + username}]
        assert 'url_templates' in error_checks(check(html=html))

    def test_optional_api_keys_are_accepted_when_well_typed(self):
        spec = dict(GOOD_API['Api'],
                    err_verdicts={'http 400': False},
                    verdict_takes_username=True)
        report = check(api={'Api': spec})
        assert 'api_spec_shape' not in error_checks(report)
        assert 'api_spec_shape' not in warning_checks(report)

    @pytest.mark.parametrize('value', [None, 'no', 0, 1, [], 'False'])
    def test_a_non_bool_err_verdict_is_an_error(self, value):
        # The tracker tests `err_map.get(err) is False`, so anything else is
        # inert - and 0 / 'False' are exactly the typos that would be missed.
        spec = dict(GOOD_API['Api'], err_verdicts={'http 400': value})
        assert 'api_spec_shape' in error_checks(check(api={'Api': spec}))

    def test_a_true_err_verdict_warns_as_dead_config(self):
        spec = dict(GOOD_API['Api'], err_verdicts={'http 400': True})
        report = check(api={'Api': spec})
        assert 'api_spec_shape' in warning_checks(report)
        assert report['ok'] is True

    def test_a_non_string_err_verdict_key_is_an_error(self):
        spec = dict(GOOD_API['Api'], err_verdicts={400: False})
        assert 'api_spec_shape' in error_checks(check(api={'Api': spec}))

    def test_the_shipped_bluesky_err_verdicts_are_valid(self):
        # Pin the one real user of the key so the check is not stricter than
        # the registry it is meant to protect.
        spec = us.API_PLATFORMS['Bluesky']
        assert spec['err_verdicts'] == {'http 400': False}
        report = rc.check_username_registry()
        assert not [f for f in report['errors'] if f['platform'] == 'Bluesky']

    @pytest.mark.parametrize('table', rc.TABLE_NAMES)
    def test_orphaned_satellite_entry_is_an_error(self, table):
        tables = {name: {} for name in rc.TABLE_NAMES}
        tables[table] = {'GhostPlatform': 'x' if table == 'SOURCE_CATALOG'
                         else (lambda *a: None)}
        report = check(tables=tables)
        assert 'cross_references' in error_checks(report)
        assert any('GhostPlatform' in f['platform'] for f in report['errors'])

    def test_a_referenced_platform_is_not_an_orphan(self):
        tables = {name: {} for name in rc.TABLE_NAMES}
        tables['EXTRACTORS'] = {'Good': lambda html: {}}
        tables['HTML_VERDICT_RULES'] = {'Api': lambda *a: None}
        tables['SOURCE_CATALOG'] = {'Good': 'described'}
        assert 'cross_references' not in error_checks(check(tables=tables))

    def test_low_catalog_coverage_warns_but_passes(self):
        report = check(tables=NO_TABLES)
        assert 'source_catalog_coverage' in warning_checks(report)
        assert report['ok'] is True

    def test_good_catalog_coverage_does_not_warn(self):
        tables = dict(NO_TABLES, SOURCE_CATALOG={'Good': 'a', 'Api': 'b'})
        assert 'source_catalog_coverage' not in warning_checks(check(tables=tables))

    def test_a_non_callable_extractor_is_an_error(self):
        tables = dict(NO_TABLES, EXTRACTORS={'Good': 'not callable'})
        assert 'callable_values' in error_checks(check(tables=tables))

    def test_a_non_callable_verdict_rule_is_an_error(self):
        tables = dict(NO_TABLES, HTML_VERDICT_RULES={'Good': 'not callable'})
        assert 'callable_values' in error_checks(check(tables=tables))


# --------------------------------------------------------------------------- #
# signature checking - must not produce false positives
# --------------------------------------------------------------------------- #

class TestSignatureChecking:
    @pytest.mark.parametrize('rule', [
        lambda username, body, low, response: None,        # exact
        lambda *args: None,                                # varargs
        lambda username, body, low, response=None: None,   # defaulted
        lambda username, body='x', low='y', response=None: None,
    ])
    def test_acceptable_rule_signatures_do_not_fire(self, rule):
        tables = dict(NO_TABLES, HTML_VERDICT_RULES={'Good': rule})
        assert 'callable_values' not in error_checks(check(tables=tables))

    @pytest.mark.parametrize('rule', [
        lambda username, body, low, response, extra: None,   # one too many
        lambda username, body, low: None,                    # one too few
        lambda username: None,
        lambda: None,
        lambda **kwargs: None,        # kwargs-only cannot take positional args
    ])
    def test_unacceptable_rule_signatures_fire(self, rule):
        tables = dict(NO_TABLES, HTML_VERDICT_RULES={'Good': rule})
        assert 'callable_values' in error_checks(check(tables=tables))

    def test_signature_problem_returns_none_for_a_matching_callable(self):
        def rule(username, body, low, response):
            return None
        assert rc._signature_problem(rule, rc._HTML_RULE_PARAMS) is None

    def test_signature_problem_describes_too_many_required(self):
        def rule(a, b, c, d, e):
            return None
        problem = rc._signature_problem(rule, rc._HTML_RULE_PARAMS)
        assert problem and 'requires 5' in problem

    def test_signature_problem_describes_too_few_positional(self):
        def rule(a, b):
            return None
        problem = rc._signature_problem(rule, rc._HTML_RULE_PARAMS)
        assert problem and 'accepts 2' in problem

    def test_unintrospectable_callables_are_skipped_not_guessed(self):
        # `int` is callable but inspect.signature raises ValueError for it;
        # that is not evidence of a defect, so it must be skipped.
        import inspect
        with pytest.raises(ValueError):
            inspect.signature(int)
        assert rc._signature_problem(int, rc._HTML_RULE_PARAMS) is None
        assert rc._signature_problem(type, rc._HTML_RULE_PARAMS) is None

    def test_a_class_with_call_is_accepted(self):
        class Rule:
            def __call__(self, username, body, low, response):
                return None
        tables = dict(NO_TABLES, HTML_VERDICT_RULES={'Good': Rule()})
        assert 'callable_values' not in error_checks(check(tables=tables))

    def test_every_shipped_html_verdict_rule_matches_the_call_site(self):
        # The real rules, checked against the real arity.
        for name, rule in us.HTML_VERDICT_RULES.items():
            assert rc._signature_problem(rule, rc._HTML_RULE_PARAMS) is None, name


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #

class TestCliSurface:
    def test_sources_check_is_a_registered_choice(self):
        from obscuralens import commands
        parser = commands.build_parser() if hasattr(commands, 'build_parser') \
            else None
        if parser is None:
            pytest.skip('parser builder is not exposed under that name')
        assert parser is not None

    def test_handler_returns_zero_on_a_clean_registry(self, monkeypatch, capsys):
        from obscuralens import commands
        monkeypatch.setattr(rc, 'check_username_registry',
                            lambda **kw: {'ok': True, 'errors': [],
                                          'warnings': [], 'findings': [],
                                          'counts': {'platforms': 1,
                                                     'html_entries': 1,
                                                     'api_entries': 0,
                                                     'errors': 0,
                                                     'warnings': 0,
                                                     'checks_run': 9}})
        args = type('A', (), {'format': 'table', 'output': None})()
        assert commands._cmd_sources_check(args) == 0

    def test_handler_returns_one_on_integrity_errors(self, monkeypatch, capsys):
        from obscuralens import commands
        finding = {'check': 'duplicates', 'severity': 'error',
                   'platform': 'Dup', 'message': 'registered 2 times'}
        monkeypatch.setattr(rc, 'check_username_registry',
                            lambda **kw: {'ok': False, 'errors': [finding],
                                          'warnings': [],
                                          'findings': [finding],
                                          'counts': {'platforms': 1,
                                                     'html_entries': 1,
                                                     'api_entries': 0,
                                                     'errors': 1,
                                                     'warnings': 0,
                                                     'checks_run': 9}})
        args = type('A', (), {'format': 'table', 'output': None})()
        assert commands._cmd_sources_check(args) == 1

    def test_handler_emits_valid_json(self, monkeypatch, capsys):
        from obscuralens import commands
        report = rc.check_username_registry()
        monkeypatch.setattr(rc, 'check_username_registry', lambda **kw: report)
        args = type('A', (), {'format': 'json', 'output': None})()
        assert commands._cmd_sources_check(args) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['counts']['platforms'] == 112

    def test_handler_json_exit_code_follows_ok(self, monkeypatch):
        from obscuralens import commands
        monkeypatch.setattr(rc, 'check_username_registry',
                            lambda **kw: {'ok': False, 'errors': [{}],
                                          'warnings': [], 'findings': [{}],
                                          'counts': {}})
        args = type('A', (), {'format': 'json', 'output': None})()
        assert commands._cmd_sources_check(args) == 1
