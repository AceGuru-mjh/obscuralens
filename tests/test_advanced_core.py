"""Advanced core tests (v6.0 part 6): the three weakest-covered advanced
modules - the parallel batch fan-out engine, opt-in webhook alerts with
their persistent event log, and pattern-of-life analysis over stored
lookup history. Fully offline: tracker resolution, risk enrichment,
webhook delivery (both the module seam and the shared HTTP client) and
history storage are all monkeypatched, so no test ever touches the
network or the user's data directory."""

import copy
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import obscuralens.correlation as correlation_pkg
from obscuralens.advanced import alerts, batch, patterns
from obscuralens.advanced.alerts import EVENT_TYPES, MAX_EVENT_LOG
from obscuralens.advanced.batch import MAX_TARGETS, SUPPORTED_KINDS
from obscuralens.advanced.patterns import WEEKDAYS
from obscuralens.database import QueryRecord, db


def _envelope(**fields):
    """A representative tracker envelope (SDK-shaped) for stub trackers."""
    base = {
        'value': '8.8.8.8',
        'info': {'country': 'US', 'org': 'Google LLC'},
        'field_sources': {'country': ['ipapi']},
        'sources_ok': ['ipapi'],
        'sources_failed': {},
        'field_count': 2,
        'success': True,
        'errors': [],
    }
    base.update(fields)
    return base


def _rec(kind, value, ts):
    """One canonical history record for pattern analysis."""
    return {'kind': kind, 'value': value, 'timestamp': ts}


# --------------------------------------------------------------------------- #
# shared fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture()
def stub_tracker(monkeypatch):
    """Programmable tracker behind ``batch._tracker_for``.

    ``state['envelopes']`` maps target -> result envelope (or an Exception
    instance to raise), ``state['default']`` is the envelope returned for
    unmapped targets, ``state['init_error']`` makes instantiation fail and
    ``state['lookups']`` records every value handed to ``track()``.
    """
    state = {'envelopes': {}, 'default': _envelope(), 'lookups': [],
             'init_error': None}

    class StubTracker:
        def __init__(self):
            if state['init_error'] is not None:
                raise state['init_error']

        def track(self, target):
            state['lookups'].append(target)
            envelope = state['envelopes'].get(target, state['default'])
            if isinstance(envelope, Exception):
                raise envelope
            return copy.deepcopy(envelope)

    def resolve(kind):
        # mirror the real contract: unsupported kinds raise at resolution
        if kind not in SUPPORTED_KINDS:
            raise ValueError(f"unsupported kind {kind!r}; choose one of: "
                             f"{', '.join(SUPPORTED_KINDS)}")
        return StubTracker

    monkeypatch.setattr(batch, '_tracker_for', resolve)
    return state


@pytest.fixture()
def risk_spy(monkeypatch):
    """Capture every attach_risk() call made by the batch engine."""
    calls = []

    def fake_attach_risk(kind, payload):
        calls.append((kind, payload))
        payload['risk'] = {'score': 42, 'verdict': 'high'}
        return payload

    monkeypatch.setattr(correlation_pkg, 'attach_risk', fake_attach_risk)
    return calls


@pytest.fixture()
def alerts_state(tmp_path, monkeypatch):
    """Isolate ``alerts.json`` in a per-test directory.

    The state file lives beside ``config.db_config.sqlite_path`` (the same
    convention as the notifications module), so pointing the sqlite path
    at a per-test path moves the alerts state with it. There is no
    module-level state cache: every call re-reads the file from disk.
    """
    from obscuralens.config import config
    monkeypatch.setattr(config.db_config, 'sqlite_path',
                        str(tmp_path / 'alerts.db'))
    return tmp_path


@pytest.fixture()
def deliver_spy(monkeypatch):
    """Capture every (url, body) handed to ``alerts._deliver``."""
    spy = _DeliverSpy()
    monkeypatch.setattr(alerts, '_deliver', spy)
    return spy


class _DeliverSpy:
    """Callable stand-in for alerts._deliver with a settable outcome."""

    def __init__(self):
        self.calls = []
        self.result = (True, 'ok')

    def __call__(self, url, body):
        self.calls.append((url, body))
        return self.result


@pytest.fixture()
def history_seam(monkeypatch):
    """Programmable history: correlation records plus direct db rows."""
    state = {'engine_records': [], 'engine_error': None, 'db_rows': {},
             'db_error': set(), 'calls': []}

    def fake_history_records(limit=None):
        state['calls'].append(('engine', limit))
        if state['engine_error'] is not None:
            raise state['engine_error']
        return list(state['engine_records'])

    def fake_get_history(query_type=None, limit=100):
        state['calls'].append((query_type, limit))
        if query_type in state['db_error']:
            raise RuntimeError('database unavailable')
        return list(state['db_rows'].get(query_type, []))

    monkeypatch.setattr(correlation_pkg, 'history_records', fake_history_records)
    monkeypatch.setattr(db, 'get_history', fake_get_history)
    return state


# --------------------------------------------------------------------------- #
# batch: tracker resolution and single-target execution
# --------------------------------------------------------------------------- #

class TestTrackerResolution:

    def test_every_supported_kind_has_a_tracker_spec(self):
        assert set(SUPPORTED_KINDS) == set(batch._TRACKER_CLASSES)
        assert len(SUPPORTED_KINDS) == 20

    def test_tracker_for_resolves_a_real_tracker_class(self):
        from obscuralens.trackers.ip_tracker import IPTracker
        assert batch._tracker_for('ip') is IPTracker

    def test_tracker_for_unknown_kind_raises(self):
        with pytest.raises(ValueError) as excinfo:
            batch._tracker_for('nope')
        assert "unsupported kind 'nope'" in str(excinfo.value)

    def test_tracker_for_error_lists_every_kind(self):
        with pytest.raises(ValueError) as excinfo:
            batch._tracker_for('')
        message = str(excinfo.value)
        for kind in SUPPORTED_KINDS:
            assert kind in message


class TestRunOne:

    def test_success_entry_shape(self, stub_tracker):
        entry = batch._run_one('ip', '8.8.8.8', False)
        assert entry == {
            'target': '8.8.8.8',
            'success': True,
            'field_count': 2,
            'error': '',
            'result': stub_tracker['default'],
        }

    def test_tracker_exception_becomes_failure_entry(self, stub_tracker):
        stub_tracker['envelopes']['bad'] = ValueError('invalid ip')
        entry = batch._run_one('ip', 'bad', False)
        assert entry['success'] is False
        assert entry['field_count'] == 0
        assert entry['result'] is None
        assert entry['error'] == 'ValueError: invalid ip'
        assert entry['target'] == 'bad'

    def test_unknown_kind_becomes_failure_entry(self):
        # no stub: the real _tracker_for raises for unsupported kinds and
        # _run_one degrades that into a well-formed failure entry.
        entry = batch._run_one('nope', 'x', False)
        assert entry['success'] is False
        assert entry['result'] is None
        assert 'unsupported kind' in entry['error']

    def test_tracker_instantiation_failure_becomes_failure_entry(self, stub_tracker):
        stub_tracker['init_error'] = RuntimeError('no api key')
        entry = batch._run_one('ip', '8.8.8.8', False)
        assert entry['success'] is False
        assert entry['error'] == 'RuntimeError: no api key'

    def test_error_list_joined_with_semicolons(self, stub_tracker):
        stub_tracker['default'] = _envelope(errors=['a', '', 'b'])
        entry = batch._run_one('ip', 'x', False)
        assert entry['error'] == 'a; b'

    def test_error_scalar_fallback(self, stub_tracker):
        stub_tracker['default'] = _envelope(errors=None, error='boom')
        entry = batch._run_one('ip', 'x', False)
        assert entry['error'] == 'boom'

    def test_non_dict_result_reports_failure_without_error(self, stub_tracker):
        stub_tracker['default'] = None
        entry = batch._run_one('ip', 'x', False)
        assert entry['success'] is False
        assert entry['field_count'] == 0
        assert entry['error'] == ''
        assert entry['result'] is None

    @pytest.mark.parametrize('field_count', ['many', None, {}])
    def test_junk_field_count_degrades_to_zero(self, stub_tracker, field_count):
        stub_tracker['default'] = _envelope(field_count=field_count, success=True)
        entry = batch._run_one('ip', 'x', False)
        assert entry['field_count'] == 0

    def test_risk_block_attached(self, stub_tracker, risk_spy):
        entry = batch._run_one('ip', '8.8.8.8', True)
        assert entry['result']['risk'] == {'score': 42, 'verdict': 'high'}
        assert risk_spy == [('ip', entry['result'])]

    def test_risk_failure_is_suppressed(self, stub_tracker, monkeypatch):
        def exploding_attach_risk(kind, payload):
            raise RuntimeError('scoring unavailable')

        monkeypatch.setattr(correlation_pkg, 'attach_risk', exploding_attach_risk)
        entry = batch._run_one('ip', '8.8.8.8', True)
        assert entry['success'] is True
        assert 'risk' not in entry['result']

    def test_risk_skipped_for_non_dict_result(self, stub_tracker, risk_spy):
        stub_tracker['default'] = None
        entry = batch._run_one('ip', 'x', True)
        assert entry['success'] is False
        assert risk_spy == []


# --------------------------------------------------------------------------- #
# batch: the fan-out engine
# --------------------------------------------------------------------------- #

class TestRunBatch:

    def test_envelope_keys_and_success(self, stub_tracker):
        result = batch.run_batch('ip', ['8.8.8.8', '1.1.1.1'])
        assert set(result) == {'kind', 'risk', 'skipped', 'stopped',
                               'results', 'summary'}
        assert result['kind'] == 'ip'
        assert result['risk'] is False
        assert result['skipped'] == 0
        assert result['stopped'] is False
        assert len(result['results']) == 2
        assert all(entry['success'] for entry in result['results'])

    def test_summary_block(self, stub_tracker):
        result = batch.run_batch('ip', ['a', 'b', 'c'])
        summary = result['summary']
        assert set(summary) == {'total', 'ok', 'failed', 'elapsed',
                                'fields_total'}
        assert summary['total'] == 3
        assert summary['ok'] == 3
        assert summary['failed'] == 0
        assert summary['fields_total'] == 6
        assert summary['elapsed'] >= 0.0

    def test_targets_as_bare_string(self, stub_tracker):
        result = batch.run_batch('ip', '8.8.8.8')
        assert result['summary']['total'] == 1
        assert stub_tracker['lookups'] == ['8.8.8.8']

    def test_targets_from_generator(self, stub_tracker):
        result = batch.run_batch('ip', (t for t in ['a', 'b']))
        assert result['summary']['total'] == 2

    def test_no_targets_yields_empty_run(self, stub_tracker):
        result = batch.run_batch('ip', None)
        assert result['results'] == []
        assert result['summary'] == {'total': 0, 'ok': 0, 'failed': 0,
                                     'elapsed': result['summary']['elapsed'],
                                     'fields_total': 0}
        assert stub_tracker['lookups'] == []

    def test_duplicate_targets_processed_twice(self, stub_tracker):
        # documented behaviour: _clean_targets keeps duplicates verbatim
        # ("a re-run of the same target is a legitimate request").
        result = batch.run_batch('ip', ['a', 'a'])
        assert result['summary']['total'] == 2
        assert stub_tracker['lookups'] == ['a', 'a']

    def test_kind_normalised_lowercase_and_trimmed(self, stub_tracker):
        result = batch.run_batch('  IP ', ['a'])
        assert result['kind'] == 'ip'

    def test_unsupported_kind_returns_error_envelope(self):
        result = batch.run_batch('nope', ['a', 'b'])
        assert result['kind'] == 'nope'
        assert result['results'] == []
        assert result['skipped'] == 0
        assert result['stopped'] is False
        assert result['summary']['total'] == 0
        assert result['error'].startswith("unsupported kind 'nope'")
        assert 'ip' in result['error']

    def test_target_cap_counts_skipped(self, stub_tracker):
        targets = [f'10.0.{i // 250}.{i % 250}' for i in range(MAX_TARGETS + 5)]
        result = batch.run_batch('ip', targets)
        assert result['skipped'] == 5
        assert result['summary']['total'] == MAX_TARGETS
        assert len(stub_tracker['lookups']) == MAX_TARGETS

    def test_mixed_success_and_failure_summary(self, stub_tracker):
        stub_tracker['envelopes']['bad'] = _envelope(success=False, field_count=0,
                                                     errors=['no route'])
        result = batch.run_batch('ip', ['good', 'bad'])
        assert result['summary']['ok'] == 1
        assert result['summary']['failed'] == 1
        assert result['summary']['fields_total'] == 2

    @pytest.mark.parametrize('workers', ['many', None, 0, -3])
    def test_degenerate_worker_counts_still_run(self, stub_tracker, workers):
        result = batch.run_batch('ip', ['a', 'b'], max_workers=workers)
        assert result['summary']['ok'] == 2

    def test_progress_callback_fires_once_per_target(self, stub_tracker):
        seen = []
        result = batch.run_batch('ip', ['a', 'b', 'c'],
                                 progress=lambda done, total, target:
                                 seen.append((done, total, target)))
        assert len(seen) == 3
        assert sorted(done for done, _, _ in seen) == [1, 2, 3]
        assert all(total == 3 for _, total, _ in seen)
        assert {target for _, _, target in seen} == {'a', 'b', 'c'}
        assert result['summary']['total'] == 3

    def test_broken_progress_callback_is_swallowed(self, stub_tracker):
        def broken(done, total, target):
            raise RuntimeError('progress bar exploded')

        result = batch.run_batch('ip', ['a', 'b'], progress=broken)
        assert result['summary']['ok'] == 2

    def test_stop_flag_interrupts_between_items(self, stub_tracker):
        completed = []

        def stop_flag():
            return len(completed) >= 2

        def progress(done, total, target):
            completed.append(target)

        result = batch.run_batch('ip', ['a', 'b', 'c', 'd'],
                                 progress=progress, stop_flag=stop_flag)
        assert result['stopped'] is True
        assert len(result['results']) == 2
        assert result['summary']['total'] == 4
        assert result['summary']['ok'] + result['summary']['failed'] == 2

    def test_stop_flag_requested_before_first_result(self, stub_tracker):
        result = batch.run_batch('ip', ['a', 'b'], stop_flag=lambda: True)
        assert result['stopped'] is True
        assert result['results'] == []

    def test_raising_stop_flag_counts_as_no(self, stub_tracker):
        def stop_flag():
            raise RuntimeError('flag broken')

        result = batch.run_batch('ip', ['a', 'b'], stop_flag=stop_flag)
        assert result['stopped'] is False
        assert result['summary']['ok'] == 2

    def test_risk_flag_forwarded_to_every_target(self, stub_tracker, risk_spy):
        result = batch.run_batch('ip', ['a', 'b'], risk=True)
        assert result['risk'] is True
        assert len(risk_spy) == 2
        assert all(entry['result'].get('risk') for entry in result['results'])

    def test_drive_survives_a_raising_run_one(self, monkeypatch):
        # defensive branch: _run_one itself is not supposed to raise, but a
        # broken future must still degrade into a failure entry.
        def exploding_run_one(kind, target, risk):
            raise RuntimeError('worker exploded')

        monkeypatch.setattr(batch, '_run_one', exploding_run_one)
        result = batch.run_batch('ip', ['a', 'b'])
        assert result['summary']['ok'] == 0
        assert result['summary']['failed'] == 2
        assert all('RuntimeError: worker exploded' in entry['error']
                   for entry in result['results'])

    def test_summary_tolerates_junk_field_counts(self, monkeypatch):
        monkeypatch.setattr(
            batch, '_run_one',
            lambda kind, target, risk: {'target': target, 'success': True,
                                        'field_count': 'many', 'error': '',
                                        'result': None})
        result = batch.run_batch('ip', ['a', 'b'])
        assert result['summary']['ok'] == 2
        assert result['summary']['fields_total'] == 0


class TestRunMixed:

    def test_pairs_of_different_kinds(self, stub_tracker):
        result = batch.run_mixed([{'kind': 'ip', 'target': '8.8.8.8'},
                                  {'kind': 'domain', 'target': 'a.com'}])
        assert result['kind'] == 'mixed'
        assert result['malformed'] == 0
        assert result['skipped'] == 0
        assert len(result['results']) == 2
        assert result['summary']['ok'] == 2

    def test_unknown_kind_pair_becomes_failure_entry(self, stub_tracker):
        # an unknown kind is not "malformed" - the pair is dispatched and
        # _run_one captures the unsupported-kind ValueError per item.
        result = batch.run_mixed([{'kind': 'nope', 'target': 'x'},
                                  {'kind': 'ip', 'target': 'y'}])
        assert result['malformed'] == 0
        entries = {entry['target']: entry for entry in result['results']}
        assert entries['x']['success'] is False
        assert 'unsupported kind' in entries['x']['error']
        assert entries['y']['success'] is True

    @pytest.mark.parametrize('junk', ['ab', 5, {'kind': 'ip'}])
    def test_unusable_pairs_counted_malformed(self, stub_tracker, junk):
        result = batch.run_mixed([junk, {'kind': 'ip', 'target': 'ok'}])
        assert result['malformed'] == 1
        assert result['summary']['total'] == 1

    def test_pair_without_target_counted_malformed(self, stub_tracker):
        # a pair missing the target is malformed; a pair missing the kind
        # is dispatched and fails per-item with an unsupported-kind error.
        result = batch.run_mixed([{'kind': 'ip'}, {'kind': 'ip', 'target': ''},
                                  {'target': 'x.com'}])
        assert result['malformed'] == 2
        assert len(result['results']) == 1
        assert 'unsupported kind' in result['results'][0]['error']

    def test_pair_targets_are_stripped(self, stub_tracker):
        result = batch.run_mixed([{'kind': 'ip', 'target': '  8.8.8.8  '}])
        assert stub_tracker['lookups'] == ['8.8.8.8']
        assert result['results'][0]['target'] == '8.8.8.8'

    def test_pair_kind_is_lowercased(self, stub_tracker):
        batch.run_mixed([{'kind': 'IP', 'target': 'a'}])
        assert stub_tracker['lookups'] == ['a']

    def test_duplicates_processed_twice(self, stub_tracker):
        pair = {'kind': 'ip', 'target': 'a'}
        result = batch.run_mixed([pair, pair])
        assert result['summary']['total'] == 2
        assert stub_tracker['lookups'] == ['a', 'a']

    def test_none_and_non_iterable_pairs(self, stub_tracker):
        assert batch.run_mixed(None)['results'] == []
        assert batch.run_mixed(7)['results'] == []
        assert batch.run_mixed()['malformed'] == 0

    def test_cap_applies_to_cleaned_pairs(self, stub_tracker):
        pairs = [{'kind': 'ip', 'target': f'10.0.0.{i}'} for i in range(MAX_TARGETS + 3)]
        result = batch.run_mixed(pairs)
        assert result['skipped'] == 3
        assert result['summary']['total'] == MAX_TARGETS

    def test_risk_flag_forwarded(self, stub_tracker, risk_spy):
        result = batch.run_mixed([{'kind': 'ip', 'target': 'a'}], risk=True)
        assert result['risk'] is True
        assert len(risk_spy) == 1


class TestCleanTargets:

    def test_none(self):
        assert batch._clean_targets(None) == []

    def test_bare_string(self):
        assert batch._clean_targets(' 8.8.8.8 ') == ['8.8.8.8']

    def test_list_is_stripped_and_empties_dropped(self):
        assert batch._clean_targets([' a ', '', '   ', None, 'b']) == ['a', 'b']

    def test_non_string_items_are_stringified(self):
        assert batch._clean_targets([2, 3.5, True]) == ['2', '3.5', 'True']

    def test_tuple_and_generator(self):
        assert batch._clean_targets(('a', 'b')) == ['a', 'b']
        assert batch._clean_targets(t for t in ['a', '', 'b']) == ['a', 'b']

    def test_non_iterable_yields_empty(self):
        assert batch._clean_targets(42) == []

    def test_duplicates_are_kept_verbatim(self):
        # documented behaviour: no de-duplication in _clean_targets.
        assert batch._clean_targets(['a', 'a', 'a']) == ['a', 'a', 'a']


# --------------------------------------------------------------------------- #
# batch: renderers
# --------------------------------------------------------------------------- #

def _run_result():
    """A synthetic two-row run for renderer tests (one ok, one failed)."""
    return {
        'kind': 'ip',
        'risk': False,
        'skipped': 0,
        'stopped': False,
        'results': [
            {'target': 'a.com', 'success': True, 'field_count': 2, 'error': '',
             'result': {'info': {'country': 'US', 'org': 'Example, Ltd'}}},
            {'target': 'b.com', 'success': False, 'field_count': 0,
             'error': 'boom', 'result': None},
        ],
        'summary': {'total': 2, 'ok': 1, 'failed': 1, 'elapsed': 0.012,
                    'fields_total': 2},
    }


class TestRenderers:

    def test_to_csv_header_and_rows(self):
        text = batch.to_csv(_run_result())
        lines = text.split('\n')
        assert lines[0] == 'target,success,field_count,error,country,org'
        assert lines[1] == 'a.com,true,2,,US,"Example, Ltd"'
        assert lines[2] == 'b.com,false,0,boom,,'
        assert lines[3] == ''

    def test_to_csv_accepts_raw_entry_list(self):
        run = _run_result()
        assert batch.to_csv(run['results']) == batch.to_csv(run)

    def test_to_csv_junk_input_renders_header_only(self):
        assert batch.to_csv({'results': 'nope'}) == 'target,success,field_count,error\n'
        assert batch.to_csv(42).startswith('target,')

    def test_to_json_round_trip(self):
        run = _run_result()
        assert json.loads(batch.to_json(run)) == run

    def test_to_json_non_serialisable_values_fall_back_to_str(self):
        marker = object()
        run = {'results': [{'target': 'x', 'success': True, 'field_count': 0,
                            'error': '', 'result': {'when': marker}}]}
        parsed = json.loads(batch.to_json(run))
        assert parsed['results'][0]['result']['when'].startswith('<object')

    def test_to_markdown_structure(self):
        text = batch.to_markdown(_run_result())
        assert text.startswith('# ObscuraLens batch results')
        assert '**Kind:** `ip`' in text
        assert '| Target | Status | Fields | Error |' in text
        assert '| a.com | ok | 2 |  |' in text
        assert '| b.com | failed | 0 | boom |' in text
        assert '## Summary' in text
        assert '- **Targets processed:** 2' in text
        assert '- **Succeeded:** 1' in text
        assert '- **Failed:** 1' in text
        assert '- **Fields collected:** 2' in text
        assert '- **Elapsed:** 0.012s' in text

    def test_to_markdown_empty_results_placeholder(self):
        run = _run_result()
        run['results'] = []
        text = batch.to_markdown(run)
        assert '| _no targets processed_ |  |  | |' in text

    def test_to_markdown_raw_entry_list_has_no_summary(self):
        text = batch.to_markdown(_run_result()['results'])
        assert text.startswith('# ObscuraLens batch results')
        assert '## Summary' not in text
        assert '**Kind:**' not in text

    def test_to_markdown_skipped_and_stopped_lines(self):
        run = _run_result()
        run['skipped'] = 5
        run['stopped'] = True
        text = batch.to_markdown(run)
        assert '- **Skipped (over cap):** 5' in text
        assert '- **Stopped early:** stop flag requested cancellation' in text

    def test_to_markdown_error_cell_capped_at_60(self):
        run = _run_result()
        run['results'][0]['error'] = 'E' * 100
        text = batch.to_markdown(run)
        row = [line for line in text.split('\n') if line.startswith('| a.com')][0]
        cell = row.split('|')[4].strip()
        assert len(cell) == 61
        assert cell.endswith('…')

    def test_md_cell_caps_at_80_with_ellipsis(self):
        cell = batch._md_cell('x' * 100)
        assert len(cell) == 81
        assert cell == 'x' * 80 + '…'

    def test_md_cell_escapes_pipes_and_newlines(self):
        assert batch._md_cell('a|b\nc') == r'a\|b c'

    @pytest.mark.parametrize('value, expected', [
        (None, ''),
        (True, 'true'),
        (False, 'false'),
        (1, '1'),
        (1.5, '1.5'),
        ('x', 'x'),
        ([], ''),
        (['a', None, 'b'], 'a; b'),
        (('a', 'b'), 'a; b'),
        ({'a': 1}, '{"a": 1}'),
        ({'k': 'é'}, '{"k": "é"}'),
    ])
    def test_stringify_matrix(self, value, expected):
        assert batch._stringify(value) == expected

    def test_stringify_nested_containers(self):
        assert batch._stringify([['a', 'b'], 'c']) == 'a; b; c'

    def test_stringify_object_falls_back_to_str(self):
        marker = object()
        assert batch._stringify(marker) == str(marker)

    def test_stringify_circular_dict_falls_back_to_str(self):
        circular = {}
        circular['self'] = circular
        text = batch._stringify(circular)
        assert text.startswith("{'self'")
        assert text == str(circular)

    def test_top_fields_ranked_by_frequency_then_name(self):
        rows = [
            {'result': {'info': {'b': 1, 'a': 1}}},
            {'result': {'info': {'b': 2}}},
            {'result': {'info': {'c': 3}}},
            {'result': None},
        ]
        assert batch._top_fields(rows) == ['b', 'a', 'c']

    def test_top_fields_limit(self):
        rows = [{'result': {'info': dict.fromkeys('abcdef', 1)}}]
        assert batch._top_fields(rows, 3) == ['a', 'b', 'c']

    def test_top_fields_uses_top_level_fields_without_info(self):
        rows = [{'result': {'country': 'US'}}, {'result': {'country': 'DE'}}]
        assert batch._top_fields(rows) == ['country']

    def test_top_fields_ignores_non_string_keys(self):
        rows = [{'result': {'info': {123: 'x', 'ok': 1}}}]
        assert batch._top_fields(rows) == ['ok']

    def test_result_rows_variants(self):
        run = _run_result()
        assert len(batch._result_rows(run)) == 2
        assert len(batch._result_rows(run['results'])) == 2
        assert batch._result_rows({'summary': {}}) == []
        assert batch._result_rows('junk') == []
        mixed = run['results'] + ['not-a-row']
        assert len(batch._result_rows(mixed)) == 2


class TestSave:

    @pytest.mark.parametrize('fmt', ['csv', 'json', 'markdown'])
    def test_save_each_format(self, tmp_path, fmt):
        run = _run_result()
        path = tmp_path / f'out.{fmt}'
        written = batch.save(str(path), run, fmt=fmt)
        assert written == str(path)
        text = path.read_text(encoding='utf-8')
        renderer = {'csv': batch.to_csv, 'json': batch.to_json,
                    'markdown': batch.to_markdown}[fmt]
        assert text == renderer(run)

    def test_save_md_alias_writes_markdown(self, tmp_path):
        run = _run_result()
        batch.save(str(tmp_path / 'out.md'), run, fmt='md')
        assert (tmp_path / 'out.md').read_text(encoding='utf-8') \
            == batch.to_markdown(run)

    def test_save_creates_parent_directories(self, tmp_path):
        destination = tmp_path / 'nested' / 'deeper' / 'batch.csv'
        written = batch.save(str(destination), _run_result(), fmt='csv')
        assert destination.is_file()
        assert written == str(destination)

    def test_save_unknown_format_raises(self, tmp_path):
        with pytest.raises(ValueError) as excinfo:
            batch.save(str(tmp_path / 'out.txt'), _run_result(), fmt='xml')
        assert "unsupported format 'xml'" in str(excinfo.value)

    def test_save_blank_format_defaults_to_markdown(self, tmp_path):
        run = _run_result()
        batch.save(str(tmp_path / 'out'), run, fmt='')
        assert (tmp_path / 'out').read_text(encoding='utf-8') \
            == batch.to_markdown(run)


# --------------------------------------------------------------------------- #
# batch: CLI
# --------------------------------------------------------------------------- #

class TestBatchCli:

    @staticmethod
    def _targets_file(tmp_path, content='a.com\nb.com\n'):
        source = tmp_path / 'targets.txt'
        source.write_text(content, encoding='utf-8')
        return str(source)

    def test_main_json_to_stdout(self, tmp_path, capsys, stub_tracker):
        code = batch.main(['ip', self._targets_file(tmp_path), '--format', 'json'])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['kind'] == 'ip'
        assert payload['summary']['ok'] == 2
        assert len(payload['results']) == 2

    def test_main_json_output_gets_trailing_newline(self, tmp_path, capsys,
                                                    stub_tracker):
        batch.main(['ip', self._targets_file(tmp_path), '--format', 'json'])
        out = capsys.readouterr().out
        assert out.endswith('}\n')
        assert not out.endswith('\n\n')

    def test_main_csv_to_stdout(self, tmp_path, capsys, stub_tracker):
        code = batch.main(['ip', self._targets_file(tmp_path), '--format', 'csv'])
        assert code == 0
        out = capsys.readouterr().out
        assert out.splitlines()[0] == 'target,success,field_count,error,country,org'
        assert len(out.splitlines()) == 3

    def test_main_markdown_is_the_default_format(self, tmp_path, capsys,
                                                  stub_tracker):
        code = batch.main(['ip', self._targets_file(tmp_path)])
        assert code == 0
        out = capsys.readouterr().out
        assert out.startswith('# ObscuraLens batch results')
        assert '**Kind:** `ip`' in out

    def test_main_output_file_and_stderr_report(self, tmp_path, capsys,
                                                stub_tracker):
        destination = tmp_path / 'nested' / 'out.csv'
        code = batch.main(['ip', self._targets_file(tmp_path), '--format', 'csv',
                           '--output', str(destination)])
        assert code == 0
        captured = capsys.readouterr()
        assert captured.out == ''
        assert 'wrote' in captured.err and '2 ok' in captured.err
        assert destination.read_text(encoding='utf-8').startswith('target,')

    def test_main_risk_flag_enriches_results(self, tmp_path, capsys,
                                             stub_tracker, risk_spy):
        code = batch.main(['ip', self._targets_file(tmp_path, 'a.com\n'),
                           '--risk', '--format', 'json'])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['risk'] is True
        assert payload['results'][0]['result']['risk'] == {'score': 42,
                                                           'verdict': 'high'}
        assert len(risk_spy) == 1

    def test_main_forwards_kind_targets_and_workers(self, tmp_path, monkeypatch):
        seen = {}

        def fake_run_batch(kind, targets, risk=False, max_workers=6,
                           progress=None, stop_flag=None):
            seen.update(kind=kind, targets=targets, risk=risk,
                        max_workers=max_workers)
            return {'kind': kind, 'risk': risk, 'skipped': 0, 'stopped': False,
                    'results': [], 'summary': {'total': 0, 'ok': 0, 'failed': 0,
                                               'elapsed': 0.0, 'fields_total': 0}}

        monkeypatch.setattr(batch, 'run_batch', fake_run_batch)
        code = batch.main(['ip', self._targets_file(tmp_path), '--workers', '3'])
        assert code == 0
        assert seen == {'kind': 'ip', 'targets': ['a.com', 'b.com'],
                        'risk': False, 'max_workers': 3}

    def test_main_unknown_kind_exits_2(self, tmp_path, capsys):
        code = batch.main(['nope', self._targets_file(tmp_path)])
        assert code == 2
        assert 'unsupported kind' in capsys.readouterr().err

    def test_main_missing_targets_exits_2(self, capsys, monkeypatch):
        class FakeTty:
            @staticmethod
            def isatty():
                return True

        monkeypatch.setattr(batch.sys, 'stdin', FakeTty())
        code = batch.main(['ip'])
        assert code == 2
        assert 'no targets to process' in capsys.readouterr().err

    def test_main_unreadable_targets_file_exits_2(self, tmp_path, capsys):
        code = batch.main(['ip', str(tmp_path / 'missing' / 'targets.txt')])
        assert code == 2
        assert 'cannot read targets' in capsys.readouterr().err

    def test_main_reads_stdin_when_dash(self, capsys, monkeypatch, stub_tracker):
        monkeypatch.setattr(batch.sys, 'stdin',
                            io.StringIO('a.com\n# note\n\nb.com\n'))
        code = batch.main(['ip', '-'])
        assert code == 0
        assert stub_tracker['lookups'] == ['a.com', 'b.com']

    def test_read_targets_drops_comments_and_blanks(self, tmp_path):
        source = tmp_path / 'targets.txt'
        source.write_text('# comment\n\n  a.com  \nb.com\n#another\n',
                          encoding='utf-8')
        assert batch._read_targets(str(source)) == ['a.com', 'b.com']

    def test_read_targets_keeps_duplicates(self, tmp_path):
        source = tmp_path / 'targets.txt'
        source.write_text('a.com\na.com\n', encoding='utf-8')
        assert batch._read_targets(str(source)) == ['a.com', 'a.com']


# --------------------------------------------------------------------------- #
# alerts: configuration and state
# --------------------------------------------------------------------------- #

class TestAlertsConfig:

    def test_default_config_shape(self, alerts_state):
        config = alerts.get_config()
        assert config == {'webhook_url': '', 'events': list(EVENT_TYPES),
                          'enabled': False}

    def test_get_config_never_creates_the_state_file(self, alerts_state):
        alerts.get_config()
        assert not (alerts_state / 'alerts.json').exists()

    def test_state_path_sits_beside_the_sqlite_database(self, alerts_state):
        assert alerts._state_path() == alerts_state / 'alerts.json'

    def test_state_path_falls_back_to_data_dir_without_sqlite(self, monkeypatch):
        from obscuralens.config import config
        monkeypatch.setattr(config.db_config, 'sqlite_path', '')
        assert alerts._state_path() == Path('data') / 'alerts.json'

    def test_configure_url_only_whitelists_every_event(self, alerts_state):
        config = alerts.configure('https://hooks.example/x')
        assert config['enabled'] is True
        assert config['webhook_url'] == 'https://hooks.example/x'
        assert config['events'] == list(EVENT_TYPES)

    def test_configure_events_filtered_case_insensitively(self, alerts_state):
        config = alerts.configure('https://hooks.example/x',
                                  events=['lookup_failed', 'nonsense',
                                          'LOOKUP_FAILED', '', '  risk_high '])
        assert config['events'] == ['lookup_failed', 'risk_high']

    def test_configure_non_iterable_events_yields_empty_whitelist(self, alerts_state):
        config = alerts.configure('https://hooks.example/x', events=5)
        assert config['webhook_url'] == 'https://hooks.example/x'
        assert config['events'] == []

    def test_configure_bare_string_events_is_iterated_per_character(self, alerts_state):
        # documented behaviour: events must be an iterable of names; a bare
        # string is consumed char-by-char and matches no event type.
        assert alerts.configure('https://hooks.example/x',
                                events='lookup_failed')['events'] == []

    def test_configure_empty_url_disables_delivery(self, alerts_state):
        alerts.configure('https://hooks.example/x')
        config = alerts.configure('')
        assert config['enabled'] is False
        assert config['webhook_url'] == ''
        assert config['events'] == list(EVENT_TYPES)

    def test_configure_whitespace_url_is_stripped(self, alerts_state):
        config = alerts.configure('  https://hooks.example/x  ')
        assert config['webhook_url'] == 'https://hooks.example/x'

    def test_configuration_persists_on_disk_across_calls(self, alerts_state):
        alerts.configure('https://hooks.example/x', events=['watch_diff'])
        # there is no in-module cache: every call re-reads the file, so
        # this also proves the "restart" round-trip.
        assert alerts.get_config() == {
            'webhook_url': 'https://hooks.example/x',
            'events': ['watch_diff'],
            'enabled': True,
        }
        on_disk = json.loads((alerts_state / 'alerts.json').read_text('utf-8'))
        assert on_disk['webhook_url'] == 'https://hooks.example/x'
        assert on_disk['events'] == ['watch_diff']


class TestLoadFallbacks:

    def test_corrupt_json_falls_back_to_defaults(self, alerts_state):
        (alerts_state / 'alerts.json').write_text('{not json at all', 'utf-8')
        assert alerts.get_config() == {'webhook_url': '', 'events': list(EVENT_TYPES),
                                       'enabled': False}

    @pytest.mark.parametrize('payload', ['[]', '42', '"nope"', 'null'])
    def test_non_dict_json_falls_back_to_defaults(self, alerts_state, payload):
        (alerts_state / 'alerts.json').write_text(payload, 'utf-8')
        assert alerts.get_config()['enabled'] is False
        assert alerts.get_config()['events'] == list(EVENT_TYPES)

    def test_partial_state_is_repaired_field_by_field(self, alerts_state):
        state = {'webhook_url': 5, 'events': ['lookup_failed', 'junk', 7],
                 'log': [{'event': 'keep'}, 'not-a-dict', 3]}
        (alerts_state / 'alerts.json').write_text(json.dumps(state), 'utf-8')
        loaded = alerts.get_config()
        assert loaded['webhook_url'] == ''
        assert loaded['events'] == ['lookup_failed']
        assert [entry['event'] for entry in alerts.recent(10)] == ['keep']

    def test_notify_rewrites_a_corrupt_state_file(self, alerts_state):
        (alerts_state / 'alerts.json').write_text('garbage{{{', 'utf-8')
        entry = alerts.notify('lookup_failed', {'target': '8.8.8.8'})
        assert entry['delivery'].startswith('skipped')
        repaired = json.loads((alerts_state / 'alerts.json').read_text('utf-8'))
        assert repaired['log'][0]['event'] == 'lookup_failed'


# --------------------------------------------------------------------------- #
# alerts: notify + delivery
# --------------------------------------------------------------------------- #

class TestNotify:

    def test_disabled_configuration_skips_delivery_but_logs(self, alerts_state):
        entry = alerts.notify('lookup_failed', {'target': '8.8.8.8', 'kind': 'ip'})
        assert entry['event'] == 'lookup_failed'
        assert entry['payload'] == {'target': '8.8.8.8', 'kind': 'ip'}
        assert entry['delivery'] == \
            'skipped: alerts disabled (no webhook configured)'
        assert entry['ts']
        assert [logged['event'] for logged in alerts.recent()] == ['lookup_failed']

    def test_whitelisted_event_is_delivered(self, alerts_state, deliver_spy):
        alerts.configure('https://hooks.example/x')
        payload = {'target': '8.8.8.8', 'kind': 'ip', 'error': 'no sources'}
        entry = alerts.notify('lookup_failed', payload)
        assert entry['delivery'] == 'ok'
        assert len(deliver_spy.calls) == 1
        url, body = deliver_spy.calls[0]
        assert url == 'https://hooks.example/x'
        assert body['event'] == 'lookup_failed'
        assert body['payload'] == payload
        assert body['source'] == 'ObscuraLens'
        assert body['text'] == alerts.summarize(payload)

    def test_unwhitelisted_event_is_skipped(self, alerts_state, deliver_spy):
        alerts.configure('https://hooks.example/x', events=['watch_diff'])
        entry = alerts.notify('lookup_failed', {'target': '8.8.8.8'})
        assert entry['delivery'] == 'skipped: event not whitelisted'
        assert deliver_spy.calls == []

    def test_unknown_event_type_is_logged_but_never_delivered(self, alerts_state,
                                                              deliver_spy):
        alerts.configure('https://hooks.example/x')
        entry = alerts.notify('made_up_event', {'target': 'x'})
        assert entry['event'] == 'made_up_event'
        assert entry['delivery'] == 'skipped: event not whitelisted'
        assert deliver_spy.calls == []

    def test_event_match_is_case_insensitive(self, alerts_state, deliver_spy):
        alerts.configure('https://hooks.example/x')
        entry = alerts.notify('LOOKUP_FAILED', {'target': '8.8.8.8'})
        assert entry['delivery'] == 'ok'
        assert len(deliver_spy.calls) == 1

    def test_delivery_failure_is_recorded_not_raised(self, alerts_state,
                                                     deliver_spy):
        alerts.configure('https://hooks.example/x')
        deliver_spy.result = (False, 'timeout')
        entry = alerts.notify('lookup_failed', {'target': '8.8.8.8'})
        assert entry['delivery'] == 'failed: timeout'

    def test_non_dict_payload_is_treated_as_empty(self, alerts_state):
        entry = alerts.notify('risk_high', 'not-a-dict')
        assert entry['payload'] == {}
        assert entry['delivery'].startswith('skipped')

    def test_notify_replaces_a_non_list_log(self, alerts_state, monkeypatch):
        # defensive branch: a state file whose log is not a list is repaired
        # in place instead of breaking the append.
        real_load = alerts._load

        def broken_load():
            state = real_load()
            state['log'] = 'junk'
            return state

        monkeypatch.setattr(alerts, '_load', broken_load)
        entry = alerts.notify('lookup_failed', {'target': '8.8.8.8'})
        assert entry['delivery'].startswith('skipped')
        saved = json.loads((alerts_state / 'alerts.json').read_text('utf-8'))
        assert [logged['event'] for logged in saved['log']] == ['lookup_failed']

    def test_empty_event_name_is_recorded_verbatim(self, alerts_state):
        entry = alerts.notify(None, {})
        assert entry['event'] == ''
        assert entry['payload'] == {}


class TestDeliver:

    def test_invalid_url_scheme_is_refused_without_http(self, fake_http):
        ok, detail = alerts._deliver('ftp://hooks.example/x', {'text': 'hi'})
        assert (ok, detail) == (False, 'invalid webhook url')
        assert fake_http.calls == []

    def test_successful_post(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (True, {'ok': 1}, '')
        assert alerts._deliver('https://hooks.example/x', {'text': 'hi'}) \
            == (True, 'ok')
        assert fake_http.calls == [('post', 'https://hooks.example/x')]

    def test_http_failure_detail_is_returned(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (False, None, 'timeout')
        assert alerts._deliver('https://hooks.example/x', {}) == (False, 'timeout')

    def test_http_error_status_detail(self, fake_http):
        fake_http.post = lambda url, payload=None, **kw: (False, None, 'http 404')
        assert alerts._deliver('https://hooks.example/x', {}) == (False, 'http 404')

    def test_transport_exception_is_captured(self, fake_http):
        def exploding_post(url, payload=None, **kw):
            raise RuntimeError('kaboom')

        fake_http.post = exploding_post
        assert alerts._deliver('https://hooks.example/x', {}) \
            == (False, 'RuntimeError: kaboom')


class TestRecentLog:

    def test_recent_empty(self, alerts_state):
        assert alerts.recent() == []

    def test_recent_is_newest_first(self, alerts_state):
        for index in range(3):
            alerts.notify('lookup_failed', {'target': f't{index}'})
        entries = alerts.recent()
        assert [entry['payload']['target'] for entry in entries] == ['t2', 't1', 't0']

    def test_recent_limit(self, alerts_state):
        for index in range(5):
            alerts.notify('lookup_failed', {'target': f't{index}'})
        entries = alerts.recent(2)
        assert [entry['payload']['target'] for entry in entries] == ['t4', 't3']

    @pytest.mark.parametrize('limit', [0, -5])
    def test_recent_non_positive_limit_is_empty(self, alerts_state, limit):
        alerts.notify('lookup_failed', {'target': 't0'})
        assert alerts.recent(limit) == []

    def test_recent_junk_limit_falls_back_to_20(self, alerts_state):
        alerts.notify('lookup_failed', {'target': 't0'})
        assert len(alerts.recent('many')) == 1

    def test_ring_buffer_keeps_last_100_entries(self, alerts_state):
        for index in range(MAX_EVENT_LOG + 5):
            alerts.notify('lookup_failed', {'target': f't{index}'})
        entries = alerts.recent(MAX_EVENT_LOG + 50)
        assert len(entries) == MAX_EVENT_LOG
        assert entries[0]['payload']['target'] == f't{MAX_EVENT_LOG + 4}'
        assert entries[-1]['payload']['target'] == 't5'

    def test_clear_events_returns_count_and_empties(self, alerts_state):
        for index in range(3):
            alerts.notify('lookup_failed', {'target': f't{index}'})
        assert alerts.clear_events() == 3
        assert alerts.recent() == []
        assert alerts.clear_events() == 0

    def test_clear_events_keeps_the_webhook_configuration(self, alerts_state):
        alerts.configure('https://hooks.example/x', events=['watch_diff'])
        alerts.notify('watch_diff', {'target': 'x'})
        alerts.clear_events()
        assert alerts.get_config()['enabled'] is True


class TestTestProbe:

    def test_probe_without_webhook_is_refused(self, alerts_state, deliver_spy):
        result = alerts.test()
        assert result['delivered'] is False
        assert 'no webhook configured' in result['error']
        assert result['webhook_url'] == ''
        assert result['ts']
        assert deliver_spy.calls == []
        assert alerts.recent() == []

    def test_probe_success_round_trip(self, alerts_state, deliver_spy):
        alerts.configure('https://hooks.example/x')
        result = alerts.test()
        assert result['delivered'] is True
        assert result['error'] == ''
        assert result['webhook_url'] == 'https://hooks.example/x'
        assert result['ts']
        assert len(deliver_spy.calls) == 1
        url, body = deliver_spy.calls[0]
        assert url == 'https://hooks.example/x'
        assert body['event'] == 'test'
        assert body['text'] == 'ObscuraLens test notification - your webhook works.'
        logged = alerts.recent()
        assert len(logged) == 1
        assert logged[0]['event'] == 'test'
        assert logged[0]['delivery'] == 'ok'

    def test_probe_failure_is_reported_and_logged(self, alerts_state, deliver_spy):
        alerts.configure('https://hooks.example/x')
        deliver_spy.result = (False, 'dns gone')
        result = alerts.test()
        assert result['delivered'] is False
        assert result['error'] == 'dns gone'
        assert alerts.recent()[0]['delivery'] == 'failed: dns gone'

    def test_probe_bypasses_the_event_whitelist(self, alerts_state, deliver_spy):
        # the whitelist is empty yet the explicit test still delivers.
        alerts.configure('https://hooks.example/x', events=[])
        assert alerts.test()['delivered'] is True
        assert len(deliver_spy.calls) == 1

    def test_probe_appends_to_and_trims_the_ring_buffer(self, alerts_state,
                                                        deliver_spy):
        alerts.configure('https://hooks.example/x')
        state = json.loads((alerts_state / 'alerts.json').read_text('utf-8'))
        state['log'] = [{'event': 'old'}] * MAX_EVENT_LOG
        (alerts_state / 'alerts.json').write_text(json.dumps(state), 'utf-8')
        assert alerts.test()['delivered'] is True
        entries = alerts.recent(MAX_EVENT_LOG + 5)
        assert len(entries) == MAX_EVENT_LOG
        assert entries[0]['event'] == 'test'
        assert entries[-1]['event'] == 'old'

    def test_probe_replaces_a_non_list_log(self, alerts_state, monkeypatch,
                                           deliver_spy):
        real_load = alerts._load

        def broken_load():
            state = real_load()
            state['webhook_url'] = 'https://hooks.example/x'
            state['log'] = 'junk'
            return state

        monkeypatch.setattr(alerts, '_load', broken_load)
        assert alerts.test()['delivered'] is True
        saved = json.loads((alerts_state / 'alerts.json').read_text('utf-8'))
        assert [entry['event'] for entry in saved['log']] == ['test']


class TestSummarize:

    def test_target_with_kind(self):
        assert alerts.summarize({'target': '8.8.8.8', 'kind': 'ip'}) \
            == 'target 8.8.8.8 (ip)'

    def test_target_without_kind(self):
        assert alerts.summarize({'target': '8.8.8.8'}) == 'target 8.8.8.8'

    def test_value_key_fallback(self):
        assert alerts.summarize({'value': 'a.com', 'kind': 'domain'}) \
            == 'target a.com (domain)'

    def test_kind_only(self):
        assert alerts.summarize({'kind': 'ip'}) == 'ip'

    def test_error_is_truncated_to_80_characters(self):
        text = alerts.summarize({'target': 'x', 'error': 'E' * 100})
        assert 'error: ' + 'E' * 80 in text
        assert 'E' * 81 not in text

    def test_score_and_source(self):
        assert alerts.summarize({'target': 'x', 'score': 72, 'source': 'ipapi'}) \
            == 'target x · risk score 72 · source ipapi'

    def test_watch_diff_old_new(self):
        assert alerts.summarize({'old': '1.2.3.4', 'new': '5.6.7.8'}) \
            == 'changed: 1.2.3.4 -> 5.6.7.8'

    def test_case_and_case_name_keys(self):
        assert alerts.summarize({'case': 'INC-42'}) == 'case INC-42'
        assert alerts.summarize({'case_name': 'APT notes'}) == 'case APT notes'

    @pytest.mark.parametrize('payload', [None, 'text', 5, [], {}])
    def test_unrecognised_payloads_fall_back_to_generic(self, payload):
        assert alerts.summarize(payload) == 'notification'

    def test_total_length_capped_at_200(self):
        text = alerts.summarize({'target': 'T' * 300})
        assert len(text) == 200

    def test_realistic_lookup_envelope(self):
        payload = {'target': '8.8.8.8', 'kind': 'ip',
                   'error': 'all sources failed', 'score': 15}
        assert alerts.summarize(payload) == \
            'target 8.8.8.8 (ip) · error: all sources failed · risk score 15'


# --------------------------------------------------------------------------- #
# patterns: record plumbing
# --------------------------------------------------------------------------- #

class TestNormaliseRecords:

    def test_none_and_non_iterable_yield_empty(self):
        assert patterns._normalise_records(None) == []
        assert patterns._normalise_records(42) == []

    def test_non_dict_items_are_dropped(self):
        assert patterns._normalise_records(['a', 5, _rec('ip', 'x', None)]) \
            == [{'kind': 'ip', 'value': 'x', 'timestamp': None}]

    @pytest.mark.parametrize('kind_key, value_key, time_key', [
        ('kind', 'value', 'created_at'),
        ('query_type', 'query_value', 'timestamp'),
        ('type', 'target', 'date'),
        ('kind', 'query_value', 'queried_at'),
        ('kind', 'value', 'time'),
    ])
    def test_alternate_key_families(self, kind_key, value_key, time_key):
        record = {kind_key: 'IP', value_key: ' 8.8.8.8 ', time_key: '2024-01-08'}
        assert patterns._normalise_records([record]) == [
            {'kind': 'ip', 'value': '8.8.8.8', 'timestamp': '2024-01-08'}]

    def test_missing_keys_become_defaults(self):
        assert patterns._normalise_records([{}]) == [
            {'kind': '', 'value': '', 'timestamp': None}]

    def test_generator_input(self):
        records = (_rec('ip', f'10.0.0.{i}', None) for i in range(3))
        assert len(patterns._normalise_records(records)) == 3


class TestTimestampParsing:

    @pytest.mark.parametrize('value, expected_iso', [
        ('2024-01-08T09:00:00Z', '2024-01-08T09:00:00+00:00'),
        ('2024-01-08T09:00:00z', '2024-01-08T09:00:00+00:00'),
        ('2024-01-08T09:00:00+00:00', '2024-01-08T09:00:00+00:00'),
        ('2024-01-08 09:00:00', '2024-01-08T09:00:00+00:00'),
        ('2024-01-08', '2024-01-08T00:00:00+00:00'),
        ('2024/01/08 09:00:00', '2024-01-08T09:00:00+00:00'),
        ('2024/01/08', '2024-01-08T00:00:00+00:00'),
        ('08 Jan 2024 09:00:00', '2024-01-08T09:00:00+00:00'),
        ('08 Jan 2024', '2024-01-08T00:00:00+00:00'),
        (1704704400, '2024-01-08T09:00:00+00:00'),
        (1704704400.0, '2024-01-08T09:00:00+00:00'),
        (1704704400000, '2024-01-08T09:00:00+00:00'),
        ('1704704400', '2024-01-08T09:00:00+00:00'),
        ('1704704400000', '2024-01-08T09:00:00+00:00'),
        ('+1704704400', '2024-01-08T09:00:00+00:00'),
        ('2024-01-08T09:00:00.123456', '2024-01-08T09:00:00+00:00'),
    ])
    def test_accepted_forms(self, value, expected_iso):
        assert patterns._parse_timestamp(value).isoformat(timespec='seconds') \
            == expected_iso

    def test_offset_timestamp_is_preserved(self):
        moment = patterns._parse_timestamp('2024-01-08T11:00:00+02:00')
        assert moment.utcoffset().total_seconds() == 7200

    def test_naive_datetime_read_as_utc(self):
        moment = patterns._parse_timestamp(datetime(2024, 1, 8, 9, 0))
        assert moment.tzinfo is timezone.utc

    def test_aware_datetime_passes_through(self):
        raw = datetime(2024, 1, 8, 9, 0, tzinfo=timezone.utc)
        assert patterns._parse_timestamp(raw) is raw

    @pytest.mark.parametrize('value', [
        None, True, False, '', '   ', 'not a date', '2024-13-45',
        [1, 2], {'t': 1}, 5.0, 0, -1704704400, float('nan'), 1e8, 1e16,
    ])
    def test_unusable_values_yield_none(self, value):
        assert patterns._parse_timestamp(value) is None


# --------------------------------------------------------------------------- #
# patterns: report on synthetic history
# --------------------------------------------------------------------------- #

def _monday_history():
    """Four Monday lookups: a 3-lookup burst at 09:00-09:20 plus one at night."""
    return [
        _rec('ip', '8.8.8.8', '2024-01-08T09:00:00Z'),
        _rec('ip', '8.8.8.8', '2024-01-08T09:10:00Z'),
        _rec('ip', '8.8.8.8', '2024-01-08T09:20:00Z'),
        _rec('ip', '8.8.8.8', '2024-01-08T23:30:00Z'),
    ]


class TestPatternReport:

    def test_report_shape(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        assert set(report) == {'kind', 'value', 'hour_histogram',
                               'weekday_histogram', 'activity_matrix', 'cadence',
                               'bursts', 'peak_window', 'verdict',
                               'records_analyzed'}
        assert report['kind'] == 'ip'
        assert report['value'] == '8.8.8.8'
        assert report['records_analyzed'] == 4

    def test_histogram_shapes_and_counts(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        assert len(report['hour_histogram']) == 24
        assert report['hour_histogram'][9] == 3
        assert report['hour_histogram'][23] == 1
        assert sum(report['hour_histogram']) == 4
        assert len(report['weekday_histogram']) == 7
        assert report['weekday_histogram'][0] == 4  # Monday-first indexing
        assert sum(report['weekday_histogram']) == 4

    def test_activity_matrix_dimensions(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        matrix = report['activity_matrix']
        assert len(matrix) == 7
        assert all(len(row) == 24 for row in matrix)
        assert matrix[0][9] == 3
        assert matrix[0][23] == 1
        assert sum(sum(row) for row in matrix) == 4

    def test_peak_window(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        assert report['peak_window'] == {'hour': 9, 'weekday': 0,
                                         'weekday_name': 'Monday', 'count': 3}

    def test_cadence_statistics(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        cadence = report['cadence']
        assert cadence['lookups'] == 4
        assert cadence['first_seen'] == '2024-01-08T09:00:00+00:00'
        assert cadence['last_seen'] == '2024-01-08T23:30:00+00:00'
        assert cadence['span_days'] == 0.6
        assert cadence['mean_interval_hours'] == 4.83
        assert cadence['median_interval_hours'] == 0.17
        assert cadence['min_interval_minutes'] == 10.0
        assert cadence['max_interval_days'] == 0.59

    def test_bursts_detected(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        assert report['bursts'] == [
            {'start': '2024-01-08T09:00:00+00:00',
             'end': '2024-01-08T09:20:00+00:00', 'count': 3}]

    def test_bursts_require_the_30_minute_window(self):
        records = [_rec('ip', 'x', f'2024-01-08T09:{minute:02d}:00Z')
                   for minute in (0, 35)]
        report = patterns.pattern_report('ip', 'x', records=records)
        assert report['bursts'] == []

    def test_bursts_survive_unsorted_input(self):
        shuffled = list(reversed(_monday_history()))
        report = patterns.pattern_report('ip', '8.8.8.8', records=shuffled)
        assert report['bursts'][0]['start'] == '2024-01-08T09:00:00+00:00'
        assert report['cadence']['first_seen'] == '2024-01-08T09:00:00+00:00'

    def test_verdict_lines(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        assert report['verdict'] == [
            'most active Monday 09:00-10:00 (3 lookups)',
            '1 burst detected (3+ lookups within 30 minutes)',
            'median gap between lookups ~0.17h',
            '1/4 lookups between 22:00 and 06:00',
        ]

    def test_verdict_pluralises_bursts(self):
        records = _monday_history() + [
            _rec('ip', '8.8.8.8', '2024-01-09T10:00:00Z'),
            _rec('ip', '8.8.8.8', '2024-01-09T10:10:00Z'),
            _rec('ip', '8.8.8.8', '2024-01-09T10:20:00Z'),
        ]
        report = patterns.pattern_report('ip', '8.8.8.8', records=records)
        assert '2 bursts detected (3+ lookups within 30 minutes)' in report['verdict']

    def test_verdict_regular_cadence(self):
        records = [_rec('ip', 'x', f'2024-01-08T{hour:02d}:00:00Z')
                   for hour in (9, 11, 13)]
        report = patterns.pattern_report('ip', 'x', records=records)
        assert 'regular cadence ~2h between lookups' in report['verdict']
        assert 'no burst activity detected' in report['verdict']

    def test_verdict_median_gap_when_irregular(self):
        records = [_rec('ip', 'x', '2024-01-08T09:00:00Z'),
                   _rec('ip', 'x', '2024-01-08T10:00:00Z'),
                   _rec('ip', 'x', '2024-01-08T11:00:00Z'),
                   _rec('ip', 'x', '2024-01-08T21:00:00Z')]
        report = patterns.pattern_report('ip', 'x', records=records)
        assert 'median gap between lookups ~1h' in report['verdict']
        assert 'regular cadence' not in ' '.join(report['verdict'])

    def test_verdict_span_days(self):
        records = [_rec('ip', 'x', '2024-01-08T09:00:00Z'),
                   _rec('ip', 'x', '2024-01-10T09:00:00Z')]
        report = patterns.pattern_report('ip', 'x', records=records)
        assert 'activity spans 2 days' in report['verdict']
        assert 'regular cadence ~48h between lookups' in report['verdict']

    def test_kind_filter_is_case_insensitive(self):
        records = [_rec('IP', '8.8.8.8', '2024-01-08T09:00:00Z')]
        report = patterns.pattern_report('IP', '8.8.8.8', records=records)
        assert report['records_analyzed'] == 1

    def test_other_kinds_are_excluded(self):
        records = _monday_history() + [
            _rec('domain', '8.8.8.8.example', '2024-01-08T09:00:00Z')]
        report = patterns.pattern_report('ip', '8.8.8.8', records=records)
        assert report['records_analyzed'] == 4

    def test_value_is_a_substring_match(self):
        records = _monday_history() + [
            _rec('ip', '8.8.4.4', '2024-01-08T09:00:00Z'),
            _rec('ip', '9.9.9.9', '2024-01-08T09:00:00Z')]
        report = patterns.pattern_report('ip', '8.8', records=records)
        assert report['records_analyzed'] == 5

    def test_no_matching_records_yields_wellformed_empty_report(self):
        report = patterns.pattern_report('ip', '8.8.8.8', records=[])
        assert report['records_analyzed'] == 0
        assert report['hour_histogram'] == [0] * 24
        assert report['weekday_histogram'] == [0] * 7
        assert report['activity_matrix'] == [[0] * 24 for _ in range(7)]
        assert report['bursts'] == []
        # documented behaviour: an all-zero matrix still reports a peak at
        # Monday 00:00 with count 0 (the first cell wins the > -1 probe).
        assert report['peak_window'] == {'hour': 0, 'weekday': 0,
                                         'weekday_name': 'Monday', 'count': 0}
        assert report['cadence'] == {'lookups': 0, 'first_seen': None,
                                     'last_seen': None, 'span_days': None,
                                     'mean_interval_hours': None,
                                     'median_interval_hours': None,
                                     'min_interval_minutes': None,
                                     'max_interval_days': None}
        assert report['verdict'] == \
            ['no stored lookups match yet - run a lookup first']

    def test_empty_value_needle_matches_nothing(self):
        report = patterns.pattern_report('ip', '  ', records=_monday_history())
        assert report['records_analyzed'] == 0
        assert report['value'] == ''

    def test_unparseable_timestamps_count_but_do_not_chart(self):
        records = [_rec('ip', 'x', 'not a date'),
                   _rec('ip', 'x', None),
                   _rec('ip', 'x', '2024-01-08T09:00:00Z')]
        report = patterns.pattern_report('ip', 'x', records=records)
        assert report['records_analyzed'] == 3
        assert report['cadence']['lookups'] == 1
        assert sum(report['hour_histogram']) == 1

    def test_offset_timestamps_are_charted_at_wall_clock_hour(self):
        # documented behaviour: histograms use the parsed moment's own
        # hour, so a +02:00 timestamp counts at 11:00, not 09:00 UTC.
        records = [_rec('ip', 'x', '2024-01-08T11:00:00+02:00')]
        report = patterns.pattern_report('ip', 'x', records=records)
        assert report['hour_histogram'][11] == 1
        assert report['hour_histogram'][9] == 0

    def test_records_argument_shortcircuits_storage(self, history_seam):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        assert report['records_analyzed'] == 4
        assert history_seam['calls'] == []


class TestLoadRecords:

    def test_engine_and_direct_rows_are_merged(self, history_seam):
        history_seam['engine_records'] = [
            _rec('ip', '8.8.8.8', '2024-01-08T09:00:00Z')]
        history_seam['db_rows']['phone'] = [
            QueryRecord(query_type='phone', query_value='+15551234567',
                        created_at='2024-01-08T10:00:00Z', result_data='{}')]
        loaded = patterns._load_records()
        assert loaded == [
            {'kind': 'ip', 'value': '8.8.8.8', 'timestamp': '2024-01-08T09:00:00Z'},
            {'kind': 'phone', 'value': '+15551234567',
             'timestamp': '2024-01-08T10:00:00Z'},
        ]

    def test_every_direct_kind_is_queried_with_the_history_limit(self, history_seam):
        patterns._load_records()
        kinds = {call[0] for call in history_seam['calls'] if call[0] != 'engine'}
        assert kinds == set(patterns._DIRECT_KINDS)
        assert ('engine', patterns._HISTORY_LIMIT) in history_seam['calls']
        assert all(limit == patterns._HISTORY_LIMIT
                   for _, limit in history_seam['calls'])

    def test_engine_failure_degrades_to_direct_rows(self, history_seam):
        history_seam['engine_error'] = RuntimeError('correlation unavailable')
        history_seam['db_rows']['mac'] = [
            QueryRecord(query_type='mac', query_value='AA:BB:CC:DD:EE:FF',
                        created_at='2024-01-08T09:00:00Z')]
        assert len(patterns._load_records()) == 1

    def test_database_failure_skips_only_that_kind(self, history_seam):
        history_seam['db_error'].add('phone')
        history_seam['db_rows']['iban'] = [
            QueryRecord(query_type='iban', query_value='DE89...',
                        created_at='2024-01-08T09:00:00Z')]
        loaded = patterns._load_records()
        assert [record['kind'] for record in loaded] == ['iban']

    def test_database_returning_none_yields_no_rows(self, history_seam):
        history_seam['db_rows']['coords'] = None
        assert patterns._load_records() == []

    def test_pattern_report_loads_storage_when_records_is_none(self, history_seam):
        history_seam['engine_records'] = _monday_history()
        report = patterns.pattern_report('ip', '8.8.8.8', records=None)
        assert report['records_analyzed'] == 4

    def test_all_targets_pattern_loads_storage_when_records_is_none(self,
                                                                    history_seam):
        history_seam['engine_records'] = _monday_history()
        rows = patterns.all_targets_pattern(records=None)
        assert [row['value'] for row in rows] == ['8.8.8.8']


class TestAllTargetsPattern:

    @staticmethod
    def _records():
        return (
            [_rec('ip', 'hot.example', '2024-01-08T09:00:00Z')]
            + [_rec('ip', 'hot.example', f'2024-01-0{day}T10:00:00Z')
               for day in (8, 9, 10, 11)]
            + [_rec('ip', 'warm.example', f'2024-01-0{day}T11:00:00Z')
               for day in (8, 9, 10)]
            + [_rec('domain', 'cold.example', '2024-01-08T09:00:00Z')
               for _ in range(2)]
            + [_rec('ip', 'night.example', ts) for ts in
               ('2024-01-08T23:00:00Z', '2024-01-09T23:30:00Z',
                '2024-01-10T01:00:00Z')]
        )

    def test_only_targets_with_three_lookups_qualify(self):
        rows = patterns.all_targets_pattern(records=self._records())
        values = [row['value'] for row in rows]
        assert 'cold.example' not in values
        assert set(values) == {'hot.example', 'warm.example', 'night.example'}

    def test_count_peak_hour_and_night_ratio(self):
        rows = {row['value']: row for row in
                patterns.all_targets_pattern(records=self._records())}
        assert rows['hot.example']['count'] == 5
        assert rows['hot.example']['kind'] == 'ip'
        assert rows['hot.example']['peak_hour'] == 10
        assert rows['hot.example']['night_ratio'] == 0.0
        assert rows['night.example']['peak_hour'] == 23
        assert rows['night.example']['night_ratio'] == 1.0

    def test_sorting_by_count_then_kind_then_value(self):
        rows = patterns.all_targets_pattern(records=self._records())
        assert [row['value'] for row in rows] == \
            ['hot.example', 'night.example', 'warm.example']

    def test_empty_and_valueless_records(self):
        assert patterns.all_targets_pattern(records=[]) == []
        records = [_rec('ip', '', '2024-01-08T09:00:00Z') for _ in range(5)]
        assert patterns.all_targets_pattern(records=records) == []

    def test_unparseable_timestamps_count_without_hour_stats(self):
        records = [_rec('ip', 'x', 'junk') for _ in range(4)]
        rows = patterns.all_targets_pattern(records=records)
        assert rows == [{'kind': 'ip', 'value': 'x', 'count': 4,
                         'peak_hour': None, 'night_ratio': 0.0}]

    def test_cap_at_100_targets(self):
        records = []
        for index in range(105):
            records += [_rec('ip', f'10.0.{index}.1', None) for _ in range(3)]
        rows = patterns.all_targets_pattern(records=records)
        assert len(rows) == patterns._MAX_TARGETS
        assert all(row['count'] == 3 for row in rows)


class TestHeatmapAscii:

    def test_ruler_and_weekday_labels(self):
        art = patterns.heatmap_ascii([[0] * 24 for _ in range(7)])
        lines = art.split('\n')
        assert lines[0] == '     ' + ''.join(str(hour % 10) for hour in range(24))
        assert [line[:3] for line in lines[1:]] == [day[:3] for day in WEEKDAYS]

    def test_density_scale(self):
        art = patterns.heatmap_ascii([[0, 1, 5]])
        assert art == '     012\nMon   :@'

    def test_zero_matrix_renders_blanks(self):
        art = patterns.heatmap_ascii([[0] * 24])
        assert art.split('\n')[1] == 'Mon  ' + ' ' * 24

    def test_peak_cell_is_the_buzziest_symbol(self):
        art = patterns.heatmap_ascii([[0, 3], [0, 0]])
        lines = art.split('\n')
        assert lines[1].endswith('@')
        assert lines[2].endswith(' ')

    @pytest.mark.parametrize('junk', ['matrix', 5, None, {}, [], ['ab', 5]])
    def test_non_matrix_input_yields_empty_string(self, junk):
        assert patterns.heatmap_ascii(junk) == ''

    def test_matrix_of_empty_rows_renders_blank_row(self):
        assert patterns.heatmap_ascii([[]]) == '     \nMon  '

    def test_oversized_matrix_gets_generic_row_labels(self):
        matrix = [[0] * 3 for _ in range(9)]
        lines = patterns.heatmap_ascii(matrix).split('\n')
        assert lines[9].startswith('r08 ')

    def test_short_rows_are_padded_with_blanks(self):
        art = patterns.heatmap_ascii([[1], [1, 1]])
        lines = art.split('\n')
        assert lines[1] == 'Mon  @ '
        assert lines[2] == 'Tue  @@'

    def test_boolean_cells_are_ignored(self):
        assert patterns.heatmap_ascii([[True, False]]) == '     01\nMon    '

    def test_renders_a_pattern_report_matrix(self):
        report = patterns.pattern_report('ip', '8.8.8.8',
                                         records=_monday_history())
        art = patterns.heatmap_ascii(report['activity_matrix'])
        monday = art.split('\n')[1]
        assert monday[5 + 9] == '@'
        assert monday[5 + 23] == '-'
        assert monday.count('@') == 1
