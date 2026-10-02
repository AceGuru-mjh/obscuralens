"""Pipeline engine tests: fully offline via injected trackers and fake
correlation modules (the real correlation package is owned by another agent
and is faked through sys.modules so these tests never depend on it)."""

import json
import sys
import types
from pathlib import Path

import pytest

from obscuralens.config import config
from obscuralens.pipelines import engine
from obscuralens.pipelines.engine import (
    PipelineError,
    list_pipelines,
    load_pipeline,
    pipeline_sections,
    resolve_trackers,
    run_pipeline,
    save_pipeline,
)

EXAMPLES = Path(__file__).resolve().parent.parent / 'pipelines' / 'examples'


# --------------------------------------------------------------------------- #
# offline fakes
# --------------------------------------------------------------------------- #

def _fake_ip(target):
    return {
        'ip': target,
        'info': {'abuse_confidence': 85, 'country': 'US',
                 'org': 'Google LLC', 'tags': ['abuse', 'proxy']},
        'field_sources': {},
        'sources_ok': ['ip-api', 'rdap'],
        'sources_failed': {},
        'field_count': 4,
        'success': True,
        'errors': [],
    }


def _fake_domain(target):
    return {
        'domain': target,
        'info': {'registrar': 'Example Registrar, Inc.', 'a_records': ['8.8.8.8'],
                 'domain_age_days': 42},
        'sources_ok': ['rdap'],
        'sources_failed': {},
        'field_count': 3,
        'success': True,
        'errors': [],
    }


def _fake_url(target):
    return {
        'url': target,
        'info': {'gsb_malicious': True, 'final_url': target,
                 'vt_malicious': 12},
        'sources_ok': ['gsb'],
        'sources_failed': {},
        'field_count': 3,
        'success': True,
        'errors': [],
    }


FAKE_TRACKERS = {'ip': _fake_ip, 'domain': _fake_domain, 'url': _fake_url}


def _spec(steps, variables=None, name='test-pipeline', description='for tests'):
    spec = {'name': name, 'description': description, 'steps': steps}
    if variables is not None:
        spec['variables'] = variables
    return spec


def _run(steps, variables=None, trackers=None):
    return run_pipeline(_spec(steps), variables=variables,
                        trackers=trackers if trackers is not None else FAKE_TRACKERS)


@pytest.fixture()
def fake_risk(monkeypatch):
    """Install a fake obscuralens.correlation.risk module (real API shape)."""
    calls = []

    def attach_risk(kind, payload):
        calls.append(payload)
        merged = dict(payload)
        merged['risk_score'] = 42
        return merged

    module = types.ModuleType('obscuralens.correlation.risk')
    module.attach_risk = attach_risk
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.risk', module)
    return calls


@pytest.fixture()
def fake_timeline(monkeypatch):
    """Fake timeline module mirroring build_timeline(payloads, cap=None)."""
    calls = []

    def build_timeline(payloads, cap=None):
        calls.append(payloads)
        events = [{'label': item['kind'], 'ts': '2024-01-01T00:00:00Z'}
                  for item in payloads]
        return {'events': events, 'count': len(events),
                'first': None, 'last': None}

    module = types.ModuleType('obscuralens.correlation.timeline')
    module.build_timeline = build_timeline
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.timeline', module)
    return calls


@pytest.fixture()
def fake_correlation(monkeypatch):
    """Fake correlation engine mirroring build_graph/history_records."""
    graph_calls = []

    def build_graph(records):
        graph_calls.append(records)
        return {'entities': [{'id': f"{record['kind']}:x"} for record in records],
                'links': []}

    def history_records(limit=None):
        return [{'kind': 'ip', 'value': '8.8.8.8', 'payload': {},
                 'created_at': '2024-01-01'}]

    module = types.ModuleType('obscuralens.correlation.engine')
    module.build_graph = build_graph
    module.history_records = history_records
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.engine', module)
    return graph_calls


# --------------------------------------------------------------------------- #
# loading and discovery
# --------------------------------------------------------------------------- #

def test_load_pipeline_reads_shipped_example():
    spec = load_pipeline(EXAMPLES / 'domain-review.yaml')
    assert spec['name'] == 'domain-review'
    assert spec['description']
    assert spec['variables'] == {'target': 'example.com'}
    assert isinstance(spec['steps'], list) and len(spec['steps']) >= 6
    assert spec['steps'][0] == {'lookup': '$target'}
    assert spec['steps'][1] == {'lookup': {'kind': 'ip', 'target': '8.8.8.8'}}


@pytest.mark.parametrize('bad_spec', [
    {'steps': [{'lookup': 'x'}]},               # missing name
    {'name': '', 'steps': []},                  # empty name
    {'name': 'x', 'steps': 'nope'},             # steps not a list
    {'name': 'x', 'steps': [{'lookup': 'x'}, 'plain']},  # step not a mapping
    {'name': 'x', 'steps': [], 'variables': ['no']},     # variables not a map
    ['not', 'a', 'mapping'],
    None,
])
def test_load_pipeline_invalid_specs_raise(bad_spec, tmp_path):
    path = tmp_path / 'bad.yaml'
    path.write_text(json.dumps(bad_spec), encoding='utf-8')
    with pytest.raises(PipelineError):
        load_pipeline(path)
    with pytest.raises(PipelineError):
        run_pipeline(bad_spec, trackers=FAKE_TRACKERS)


def test_load_pipeline_missing_file_and_bad_yaml(tmp_path):
    with pytest.raises(PipelineError, match='not found'):
        load_pipeline(tmp_path / 'missing.yaml')

    broken = tmp_path / 'broken.yaml'
    broken.write_text('name: [unclosed\n  bad yaml: {{{', encoding='utf-8')
    with pytest.raises(PipelineError, match='invalid YAML'):
        load_pipeline(broken)


def test_list_pipelines_explicit_folder(tmp_path):
    folder = tmp_path / 'pipes'
    folder.mkdir()
    (folder / 'zebra.yaml').write_text(
        'name: zebra\ndescription: last\nsteps:\n  - lookup: 8.8.8.8\n',
        encoding='utf-8')
    (folder / 'alpha.yml').write_text(
        'name: alpha\ndescription: first\nsteps:\n  - lookup: 8.8.8.8\n'
        '  - risk: true\n', encoding='utf-8')
    (folder / 'no-name.yaml').write_text('steps: []\n', encoding='utf-8')
    (folder / 'ignored.txt').write_text('name: ignored\n', encoding='utf-8')

    entries = list_pipelines(folder=folder)
    assert [entry['name'] for entry in entries] == ['alpha', 'no-name', 'zebra']
    by_name = {entry['name']: entry for entry in entries}
    assert by_name['alpha']['steps'] == 2
    assert by_name['alpha']['description'] == 'first'
    assert by_name['no-name']['steps'] == 0
    assert by_name['no-name']['name'] == 'no-name'  # file stem fallback
    assert by_name['zebra']['path'].endswith('zebra.yaml')
    assert list_pipelines(folder=tmp_path / 'missing') == []


def test_list_pipelines_discovers_shipped_examples(tmp_path, monkeypatch):
    # A non-existent configured pipeline_dir must still surface the shipped
    # example pipelines via the repository fallback discovery.
    monkeypatch.setattr(config.app_config, 'pipeline_dir',
                        str(tmp_path / 'nowhere'))
    entries = list_pipelines()
    names = [entry['name'] for entry in entries]
    assert {'domain-review', 'ip-triage', 'brand-abuse'} <= set(names)
    for entry in entries:
        if entry['name'] in ('domain-review', 'ip-triage', 'brand-abuse'):
            assert entry['steps'] >= 4
            assert entry['description']

    # A real configured folder is scanned in addition to the shipped ones.
    custom = tmp_path / 'custom'
    custom.mkdir()
    (custom / 'mine.yaml').write_text(
        'name: mine\nsteps:\n  - lookup: 8.8.8.8\n', encoding='utf-8')
    monkeypatch.setattr(config.app_config, 'pipeline_dir', str(custom))
    names = [entry['name'] for entry in list_pipelines()]
    assert 'mine' in names
    assert 'domain-review' in names
    assert len(names) == len(set(names))  # no duplicates


def test_resolve_trackers_has_core_kinds():
    resolved = resolve_trackers()
    for kind in ('ip', 'phone', 'username', 'email', 'domain'):
        assert kind in resolved
    assert set(engine.TRACKER_MAP) >= set(resolved)


# --------------------------------------------------------------------------- #
# interpolation
# --------------------------------------------------------------------------- #

def test_interpolate_replaces_tokens():
    variables = {'host': 'example.com', 'n': 3}
    assert engine._interpolate('https://$host/login', variables) == \
        'https://example.com/login'
    assert engine._interpolate('${host}:${n}', variables) == 'example.com:3'
    # Non-strings pass through untouched.
    assert engine._interpolate(5, variables) == 5


def test_interpolate_missing_variable_warns_and_blanks():
    warnings = []
    assert engine._interpolate('a-$missing-b', {}, warnings) == 'a--b'
    assert warnings == ["variable 'missing' is not defined"]
    # The same missing variable only warns once.
    engine._interpolate('$missing $missing', {}, warnings)
    assert len(warnings) == 1


def test_interpolate_recurses_into_containers():
    variables = {'target': '8.8.8.8'}
    value = {'kind': 'ip', 'target': '$target', 'note': 'see ${target}',
             'list': ['$target', 1, None]}
    assert engine._interpolate(value, variables) == {
        'kind': 'ip', 'target': '8.8.8.8', 'note': 'see 8.8.8.8',
        'list': ['8.8.8.8', 1, None]}


# --------------------------------------------------------------------------- #
# lookup steps
# --------------------------------------------------------------------------- #

def test_run_pipeline_lookup_auto_kind():
    report = run_pipeline(
        _spec([{'lookup': '$target'}], variables={'target': '8.8.8.8'}),
        trackers=FAKE_TRACKERS)
    assert report['results']['ip']['ip'] == '8.8.8.8'
    step = report['steps'][0]
    assert step['action'] == 'lookup' and step['ok'] is True
    assert step['detail'] == 'ip 8.8.8.8: 2 source(s) ok'
    assert report['errors'] == []


def test_run_pipeline_lookup_auto_detects_url_kind():
    report = run_pipeline(
        _spec([{'lookup': '$target'}],
              variables={'target': 'https://phish.example/login'}),
        trackers=FAKE_TRACKERS)
    assert 'url' in report['results']
    assert report['steps'][0]['ok'] is True


def test_run_pipeline_lookup_explicit_kind_and_kind_variable():
    report = run_pipeline(
        _spec([{'lookup': {'kind': '$kind', 'target': 'example.com'}}],
              variables={'kind': 'domain'}),
        trackers=FAKE_TRACKERS)
    assert report['results']['domain']['info']['registrar'] == \
        'Example Registrar, Inc.'


def test_run_pipeline_lookup_undetectable_target():
    report = _run([{'lookup': '!!! not a target'}])
    assert report['results'] == {}
    assert report['steps'][0]['ok'] is False
    assert 'cannot determine kind' in report['steps'][0]['detail']
    assert report['errors']


def test_run_pipeline_lookup_without_tracker():
    report = _run([{'lookup': {'kind': 'mac', 'target': 'aa:bb:cc:dd:ee:ff'}}])
    assert report['steps'][0]['ok'] is False
    assert 'no tracker available' in report['steps'][0]['detail']


def test_run_pipeline_lookup_tracker_exception():
    def exploding(target):
        raise RuntimeError('boom')

    report = _run([{'lookup': {'kind': 'ip', 'target': '8.8.8.8'}},
                   {'risk': False}], trackers={'ip': exploding})
    assert report['steps'][0]['ok'] is False
    assert 'tracker failed (RuntimeError)' in report['steps'][0]['detail']
    # The run continues with the next step.
    assert report['steps'][1]['ok'] is True


def test_run_pipeline_variables_caller_wins():
    report = run_pipeline(
        _spec([{'lookup': '$target'}], variables={'target': 'example.com'}),
        variables={'target': '8.8.8.8'}, trackers=FAKE_TRACKERS)
    assert report['results']['ip']['ip'] == '8.8.8.8'


# --------------------------------------------------------------------------- #
# assert steps
# --------------------------------------------------------------------------- #

def test_assert_equality_and_inequality():
    report = _run([
        {'lookup': '$target'},
        {'assert': {'field': 'gsb_malicious', 'op': '==', 'value': True,
                    'message': 'flagged'}},
    ], variables={'target': 'https://bad.example/'})
    # 'https://bad.example/' auto-detects as a url payload with gsb_malicious.
    assert report['findings'][0]['field'] == 'gsb_malicious'
    assert report['findings'][0]['actual'] is True
    assert report['findings'][0]['message'] == 'flagged'

    report = _run([
        {'lookup': '$target'},
        {'assert': {'field': 'country', 'op': '!=', 'value': 'DE'}},
    ], variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1


def test_assert_numeric_comparisons():
    base = [{'lookup': '$target'}]

    report = _run(base + [{'assert': {'field': 'abuse_confidence', 'op': '>=',
                                      'value': 50}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1

    report = _run(base + [{'assert': {'field': 'abuse_confidence', 'op': '>',
                                      'value': 90}}],
                  variables={'target': '8.8.8.8'})
    assert report['findings'] == []
    assert any('assertion failed' in warning for warning in report['warnings'])

    # Numeric strings compare numerically against numbers.
    report = _run(base + [{'assert': {'field': 'country', 'op': '<',
                                      'value': 'ZZ'}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1

    report = _run(base + [{'assert': {'field': 'abuse_confidence', 'op': '<=',
                                      'value': '85'}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1


def test_assert_contains_in_and_exists():
    base = [{'lookup': '$target'}]

    report = _run(base + [{'assert': {'field': 'org', 'op': 'contains',
                                      'value': 'Google'}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1

    report = _run(base + [{'assert': {'field': 'country', 'op': 'in',
                                      'value': ['US', 'NL']}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1
    # 'in' with a plain string falls back to substring semantics.
    report = _run(base + [{'assert': {'field': 'org', 'op': 'in',
                                      'value': 'Google LLC'}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1

    report = _run(base + [{'assert': {'field': 'registrar', 'op': 'exists',
                                      'value': True}}],
                  variables={'target': 'example.com'})
    assert len(report['findings']) == 1
    # exists: false passes only when the field is absent.
    report = _run(base + [{'assert': {'field': 'nonexistent_field', 'op': 'exists',
                                      'value': False}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1
    report = _run(base + [{'assert': {'field': 'country', 'op': 'exists',
                                      'value': False}}],
                  variables={'target': '8.8.8.8'})
    assert report['findings'] == []


def test_assert_dotted_fields_and_info_fallback():
    base = [{'lookup': '$target'}]
    # Dotted path from the payload root.
    report = _run(base + [{'assert': {'field': 'info.abuse_confidence',
                                      'op': '==', 'value': 85}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1
    # Bare field names fall back to the payload's 'info' block.
    report = _run(base + [{'assert': {'field': 'abuse_confidence',
                                      'op': '==', 'value': 85}}],
                  variables={'target': '8.8.8.8'})
    assert len(report['findings']) == 1


def test_assert_unknown_op_and_missing_field():
    report = _run([{'lookup': '$target'},
                   {'assert': {'field': 'country', 'op': '~=', 'value': 1}}],
                  variables={'target': '8.8.8.8'})
    assert report['steps'][1]['ok'] is False
    assert any('unknown assert op' in error for error in report['errors'])

    report = _run([{'lookup': '$target'},
                   {'assert': {'field': 'ghost_field', 'op': '==',
                               'value': 'x'}}],
                  variables={'target': '8.8.8.8'})
    assert report['findings'] == []
    assert report['steps'][1]['ok'] is False
    assert any('not found in any result' in warning
               for warning in report['warnings'])


# --------------------------------------------------------------------------- #
# risk / timeline / correlate steps (faked correlation modules)
# --------------------------------------------------------------------------- #

def test_risk_step_attaches_scores(fake_risk):
    report = _run([{'lookup': '$target'}, {'risk': True}],
                  variables={'target': '8.8.8.8'})
    assert report['results']['ip']['risk_score'] == 42
    assert fake_risk and fake_risk[0]['ip'] == '8.8.8.8'
    assert report['steps'][1]['ok'] is True
    assert report['steps'][1]['detail'] == 'risk scores attached to 1 result(s)'


def test_risk_step_module_missing_warns(monkeypatch):
    # A None entry in sys.modules makes the import raise ImportError, which
    # keeps this test honest even once the real correlation package lands.
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.risk', None)
    report = _run([{'lookup': '$target'}, {'risk': True}],
                  variables={'target': '8.8.8.8'})
    assert 'risk_score' not in report['results']['ip']
    assert report['steps'][1]['ok'] is False
    assert any('correlation.risk' in warning for warning in report['warnings'])


def test_timeline_step_builds_events(fake_timeline):
    report = _run([{'lookup': '$target'}, {'timeline': True}],
                  variables={'target': '8.8.8.8'})
    assert report['timeline'] == {
        'events': [{'label': 'ip', 'ts': '2024-01-01T00:00:00Z'}],
        'count': 1, 'first': None, 'last': None}
    # The payloads are passed in the {'kind', 'value', 'payload'} record shape.
    assert fake_timeline[0][0]['kind'] == 'ip'
    assert fake_timeline[0][0]['value'] == '8.8.8.8'
    assert fake_timeline[0][0]['payload']['ip'] == '8.8.8.8'
    assert report['steps'][1]['ok'] is True
    assert '1 event(s)' in report['steps'][1]['detail']


def test_timeline_step_module_missing_warns(monkeypatch):
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.timeline', None)
    report = _run([{'lookup': '$target'}, {'timeline': True}],
                  variables={'target': '8.8.8.8'})
    assert report['timeline'] is None
    assert any('correlation.timeline' in warning
               for warning in report['warnings'])


def test_correlate_step_builds_graph_and_history(fake_correlation):
    report = _run([{'lookup': '$target'}, {'correlate': True}],
                  variables={'target': '8.8.8.8'})
    assert fake_correlation and fake_correlation[0][0]['kind'] == 'ip'
    # The graph records combine the current run's results with the history.
    assert len(fake_correlation[0]) == 2
    assert fake_correlation[0][1]['value'] == '8.8.8.8'  # history row
    assert report['correlation']['graph']['entities'][0]['id'] == 'ip:x'
    assert report['correlation']['history'][0]['value'] == '8.8.8.8'
    assert report['steps'][1]['ok'] is True
    assert report['steps'][1]['detail'] == 'correlated: history, graph'


def test_correlate_step_module_missing_warns(monkeypatch):
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.engine', None)
    report = _run([{'lookup': '$target'}, {'correlate': True}],
                  variables={'target': '8.8.8.8'})
    assert report['correlation'] is None
    assert any('correlation.engine' in warning for warning in report['warnings'])


def test_correlation_alternate_signatures(monkeypatch):
    """Older single-argument correlation APIs still work via fallbacks."""
    def attach_risk(*args):
        if len(args) != 1:
            raise TypeError('attach_risk(payload)')
        merged = dict(args[0])
        merged['risk_score'] = 7
        return merged

    risk_module = types.ModuleType('obscuralens.correlation.risk')
    risk_module.attach_risk = attach_risk
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.risk', risk_module)

    def build_timeline(arg):
        if not isinstance(arg, dict):
            raise TypeError('build_timeline(results)')
        return {'events': [{'label': kind} for kind in arg], 'count': len(arg)}

    timeline_module = types.ModuleType('obscuralens.correlation.timeline')
    timeline_module.build_timeline = build_timeline
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.timeline',
                        timeline_module)

    def build_graph(arg):
        if not isinstance(arg, dict):
            raise TypeError('build_graph(results)')
        return {'entities': [{'id': f'{kind}:y'} for kind in arg], 'links': []}

    def history_records(limit=None):
        return []

    engine_module = types.ModuleType('obscuralens.correlation.engine')
    engine_module.build_graph = build_graph
    engine_module.history_records = history_records
    monkeypatch.setitem(sys.modules, 'obscuralens.correlation.engine', engine_module)

    report = _run([{'lookup': '$target'}, {'risk': True}, {'timeline': True},
                   {'correlate': True}], variables={'target': '8.8.8.8'})
    assert report['results']['ip']['risk_score'] == 7
    assert report['timeline'] == {'events': [{'label': 'ip'}], 'count': 1}
    assert report['correlation']['graph']['entities'] == [{'id': 'ip:y'}]
    assert report['correlation']['history'] == []
    assert [step['ok'] for step in report['steps']] == [True, True, True, True]
    assert report['errors'] == []


# --------------------------------------------------------------------------- #
# output steps
# --------------------------------------------------------------------------- #

def test_output_table_writes_file(tmp_path):
    target_file = tmp_path / 'summary.txt'
    report = _run([
        {'lookup': '$target'},
        {'output': {'format': 'table', 'path': str(target_file)}},
    ], variables={'target': '8.8.8.8'})
    text = target_file.read_text(encoding='utf-8')
    assert 'kind' in text and 'ip' in text and '8.8.8.8' in text
    assert 'yes' in text  # success column
    assert report['steps'][1]['ok'] is True
    assert 'written to' in report['steps'][1]['detail']


def test_output_json_round_trips(tmp_path):
    target_file = tmp_path / 'report.json'
    report = _run([
        {'lookup': '$target'},
        {'assert': {'field': 'abuse_confidence', 'op': '>=', 'value': 50,
                    'message': 'flagged'}},
        {'output': {'format': 'json', 'path': str(target_file)}},
    ], variables={'target': '8.8.8.8'})
    data = json.loads(target_file.read_text(encoding='utf-8'))
    assert data['name'] == 'test-pipeline'
    assert data['results']['ip']['ip'] == '8.8.8.8'
    assert data['findings'][0]['message'] == 'flagged'
    # The JSON snapshot cannot contain its own output step.
    assert data['steps'][-1]['action'] == 'assert'
    assert report['steps'][2]['ok'] is True


def test_output_markdown_renders_findings(tmp_path):
    target_file = tmp_path / 'report.md'
    report = _run([
        {'lookup': '$target'},
        {'assert': {'field': 'abuse_confidence', 'op': '>=', 'value': 50,
                    'message': 'address flagged'}},
        {'output': {'format': 'markdown', 'path': str(target_file)}},
    ], variables={'target': '8.8.8.8'})
    text = target_file.read_text(encoding='utf-8')
    assert '# Pipeline: test-pipeline' in text
    assert '## Findings (1)' in text
    assert 'address flagged' in text
    assert '- **ip** `8.8.8.8`' in text
    assert report['steps'][2]['ok'] is True


def test_output_relative_path_uses_report_dir(tmp_env):
    report = _run([
        {'lookup': '$target'},
        {'output': {'format': 'table', 'path': 'run-$target.txt'}},
    ], variables={'target': '8.8.8.8'})
    expected = Path(config.app_config.report_dir) / 'run-8.8.8.8.txt'
    assert expected.is_file()
    assert '8.8.8.8' in expected.read_text(encoding='utf-8')
    assert str(expected) in report['steps'][1]['detail']


def test_output_io_error_is_recorded_not_raised(tmp_path):
    # A directory cannot be opened for writing -> OSError recorded.
    report = _run([
        {'lookup': '$target'},
        {'output': {'format': 'table', 'path': str(tmp_path)}},
    ], variables={'target': '8.8.8.8'})
    assert report['steps'][1]['ok'] is False
    assert any('cannot write output file' in error for error in report['errors'])
    assert 'write to' in report['steps'][1]['detail']


def test_output_unknown_format():
    report = _run([{'lookup': '$target'},
                   {'output': {'format': 'pdf', 'path': ''}}],
                  variables={'target': '8.8.8.8'})
    assert report['steps'][1]['ok'] is False
    assert any('unknown output format' in error for error in report['errors'])


def test_output_without_path_returns_text_in_detail():
    report = _run([{'lookup': '$target'}, {'output': {'format': 'table'}}],
                  variables={'target': '8.8.8.8'})
    detail = report['steps'][1]['detail']
    assert '8.8.8.8' in detail and 'written to' not in detail


# --------------------------------------------------------------------------- #
# whole-run behaviour and helpers
# --------------------------------------------------------------------------- #

def test_unknown_action_records_error_and_continues():
    report = _run([
        {'lookup': '$target'},
        {'explode': True},
        {'risk': False},
    ], variables={'target': '8.8.8.8'})
    assert report['steps'][1]['ok'] is False
    assert report['steps'][1]['action'] == 'explode'
    assert any('unknown action' in error for error in report['errors'])
    # The run continued: step 3 executed (risk disabled -> skipped).
    assert report['steps'][2]['ok'] is True
    assert 'skipped' in report['steps'][2]['detail'] or \
        report['steps'][2]['detail'].startswith('risk')


def test_run_pipeline_end_to_end_report_shape(fake_risk, fake_timeline,
                                              fake_correlation):
    report = _run([
        {'lookup': '$target'},
        {'risk': True},
        {'assert': {'field': 'abuse_confidence', 'op': '>=', 'value': 50,
                    'message': 'address flagged by AbuseIPDB'}},
        {'timeline': True},
        {'correlate': True},
    ], variables={'target': '8.8.8.8'})
    for key in ('name', 'description', 'started', 'finished', 'duration_ms',
                'steps', 'results', 'findings', 'timeline', 'correlation',
                'errors', 'warnings'):
        assert key in report
    assert report['errors'] == []
    assert report['duration_ms'] >= 0
    assert report['finished'] >= report['started']
    assert [step['ok'] for step in report['steps']] == [True] * 5
    assert report['results']['ip']['risk_score'] == 42
    assert len(report['findings']) == 1


def test_run_pipeline_from_yaml_file(tmp_path):
    pipeline_file = tmp_path / 'inline.yaml'
    pipeline_file.write_text(
        'name: inline\n'
        'description: from disk\n'
        'variables:\n'
        '  target: example.com\n'
        'steps:\n'
        '  - lookup: $target\n'
        '  - assert:\n'
        '      field: registrar\n'
        "      op: '=='\n"
        '      value: Example Registrar, Inc.\n',
        encoding='utf-8')
    report = run_pipeline(pipeline_file, variables={'target': '8.8.8.8'},
                          trackers=FAKE_TRACKERS)
    # Caller variable wins over the file default.
    assert report['results']['ip']['ip'] == '8.8.8.8'
    assert report['name'] == 'inline'
    assert report['steps'][0]['detail'] == 'ip 8.8.8.8: 2 source(s) ok'


def test_pipeline_sections_shape(fake_risk):
    report = _run([
        {'lookup': '$target'},
        {'assert': {'field': 'abuse_confidence', 'op': '>=', 'value': 50,
                    'message': 'flagged'}},
    ], variables={'target': '8.8.8.8'})
    sections = pipeline_sections(report)

    summary = sections[0]
    assert summary['type'] == 'grid'
    assert summary['data']['Pipeline'] == 'test-pipeline'
    assert summary['data']['Steps'] == 2

    steps_table = sections[1]
    assert steps_table['type'] == 'table'
    assert steps_table['columns'] == ['#', 'Action', 'OK', 'Detail']
    assert steps_table['rows'][0] == [1, 'lookup', 'yes',
                                      'ip 8.8.8.8: 2 source(s) ok']

    findings = sections[2]
    assert findings['title'] == 'Findings (1)'
    assert findings['columns'] == ['Field', 'Op', 'Expected', 'Actual', 'Message']
    assert findings['rows'][0][0] == 'abuse_confidence'

    # Warnings/errors only appear as sections when present.
    assert all(section['title'] != 'Pipeline Errors' for section in sections)


def test_save_pipeline_round_trip(tmp_path):
    spec = {'description': 'saved', 'variables': {'target': '8.8.8.8'},
            'steps': [{'lookup': '$target'}, {'risk': True}]}
    path = save_pipeline('My Probe', spec, folder=tmp_path)
    assert path.endswith('my-probe.yaml')
    loaded = load_pipeline(path)
    assert loaded['name'] == 'My Probe'
    assert loaded['steps'] == spec['steps']

    with pytest.raises(PipelineError):
        save_pipeline('', spec, folder=tmp_path)
    with pytest.raises(PipelineError):
        save_pipeline('bad', {'steps': 'nope'}, folder=tmp_path)
