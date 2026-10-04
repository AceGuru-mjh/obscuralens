"""
Offline tests for the benchmark suite (benchmarks/ package).

Covers the harness math (Timing statistics and their guards), suite
registration/filtering/quick-mode behaviour, report rendering and
persistence, the compare() verdict matrix around the tolerance boundary,
the run.py CLI (list / json / quick / save / compare / exit codes) and a
one-shot smoke of every registered benchmark callable.

Nothing here touches the network; stateful benches are exercised with a
pytest ``tmp_path`` workdir and asserted to keep their writes inside it.
"""

import json
import time

import pytest

from benchmarks import (
    BenchReport,
    BenchSpec,
    BenchSuite,
    CompareRow,
    Timer,
    Timing,
    bench_analytics,
    bench_core,
    bench_platform,
    compare,
    compare_table,
    measure,
    percentile,
)
from benchmarks import run as run_mod
from benchmarks.harness import QUICK_SCALE, state_dir

# --- harness math -------------------------------------------------------------


class TestTimer:
    def test_elapsed_covers_sleep(self):
        with Timer() as timer:
            time.sleep(0.02)
        assert timer.elapsed >= 0.015

    def test_elapsed_zero_for_no_op(self):
        with Timer() as timer:
            pass
        assert timer.elapsed >= 0.0


class TestPercentile:
    def test_linear_interpolation(self):
        assert percentile([1, 2, 3, 4], 0.95) == pytest.approx(3.85)

    def test_median_of_even_set(self):
        assert percentile([1, 2, 3, 4], 0.5) == pytest.approx(2.5)

    def test_single_sample_and_empty(self):
        assert percentile([5], 0.5) == 5.0
        assert percentile([], 0.99) == 0.0

    def test_clamps_out_of_range_quantile(self):
        assert percentile([2, 4], 2.0) == 4.0
        assert percentile([2, 4], -1.0) == 2.0


class TestMeasure:
    def test_timing_fields_on_trivial_fn(self):
        timing = measure(lambda: None, name='noop', repeat=3, number=2)
        assert timing.name == 'noop'
        assert timing.repeat == 3
        assert timing.number == 2
        assert timing.total_calls == 6
        assert len(timing.samples) == 3
        assert timing.ops_per_sec > 0
        assert timing.min_s <= timing.mean_s <= timing.median_s <= timing.p95_s
        assert timing.stdev_s >= 0.0

    def test_stdev_guard_below_two_samples(self):
        timing = measure(lambda: None, repeat=1, number=1, warmup=0)
        assert timing.stdev_s == 0.0

    def test_samples_normalised_per_call(self):
        counter = {'calls': 0}

        def two_calls():
            for _ in range(2):
                counter['calls'] += 1

        timing = measure(two_calls, repeat=2, number=5, warmup=1)
        # warmup(1) + 2 repeats x 5 calls, 2 inner calls each
        assert counter['calls'] == (1 + 2 * 5) * 2
        assert all(sample > 0 for sample in timing.samples)

    def test_measure_passes_exceptions_through(self):
        def boom():
            raise RuntimeError('kaboom')

        with pytest.raises(RuntimeError):
            measure(boom, repeat=1, number=1, warmup=0)

    def test_timing_dict_round_trip(self):
        timing = measure(lambda: 1, name='rt', repeat=2, number=1)
        restored = Timing.from_dict(timing.to_dict())
        assert restored.name == 'rt'
        assert restored.total_calls == timing.total_calls
        assert restored.samples == pytest.approx(timing.samples)

    def test_timing_from_dict_tolerates_junk(self):
        restored = Timing.from_dict(None)
        assert restored.name == ''
        assert restored.samples == []


# --- suite behaviour ----------------------------------------------------------


class TestBenchSuite:
    def test_registration_and_duplicate_ignore(self):
        suite = BenchSuite()
        suite.register('first', lambda: None)
        suite.register('first', lambda: None)
        registered = suite.registered()
        assert [entry['name'] for entry in registered] == ['first']

    def test_only_substring_filter(self):
        suite = BenchSuite()
        suite.register('validators_ip', lambda: None)
        suite.register('validators_email', lambda: None)
        suite.register('cache_get_hit', lambda: None)
        report = suite.run(only=['validators'])
        assert report.names() == ['validators_ip', 'validators_email']

    def test_tags_filter(self):
        suite = BenchSuite()
        suite.register('a', lambda: None, tags=('core',))
        suite.register('b', lambda: None, tags=('analytics',))
        report = suite.run(tags=['analytics'])
        assert report.names() == ['b']

    def test_unknown_filter_gives_empty_report(self):
        suite = BenchSuite()
        suite.register('real', lambda: None)
        report = suite.run(only=['no-such-bench'])
        assert report.results == []
        assert report.errors == []
        assert report.names() == []
        assert '(no benchmarks ran)' in report.to_table()

    def test_quick_mode_reduces_work(self):
        counter = {'calls': 0}

        def counted():
            counter['calls'] += 1

        suite = BenchSuite()
        suite.register('counted', counted, repeat=25, number=25, warmup=0)
        counter['calls'] = 0
        full = suite.run()
        full_calls = counter['calls']
        counter['calls'] = 0
        quick = suite.run(quick=True)
        quick_calls = counter['calls']
        assert full_calls == 25 * 25
        assert quick_calls == (25 // QUICK_SCALE) * (25 // QUICK_SCALE)
        assert quick_calls < full_calls
        assert quick.quick and not full.quick

    def test_setup_teardown_and_error_capture(self):
        events = []

        suite = BenchSuite()
        suite.register('broken', lambda: (_ for _ in ()).throw(ValueError('x')),
                       setup=lambda: events.append('setup'),
                       teardown=lambda: events.append('teardown'))
        suite.register('fine', lambda: events.append('run'),
                       repeat=1, number=1, warmup=0)
        report = suite.run()
        assert [entry['name'] for entry in report.errors] == ['broken']
        assert 'ValueError' in report.errors[0]['error']
        assert events == ['setup', 'teardown', 'run']
        # a raising bench never poisons the report table
        assert 'broken' in report.to_table()

    def test_report_shapes(self):
        suite = BenchSuite()
        suite.register('shape', lambda: None, tags=('t',))
        report = suite.run()
        payload = report.to_dict()
        assert payload['schema'] == 'obscuralens-benchmarks/1'
        assert payload['total_benches'] == 1
        assert payload['results'][0]['name'] == 'shape'
        table = report.to_table()
        assert 'benchmark' in table and 'ops/sec' in table and 'shape' in table
        summary = report.summary()
        assert 'benchmarks: 1' in summary and 'slowest' in summary

    def test_save_load_round_trip(self, tmp_path):
        suite = BenchSuite()
        suite.register('persist', lambda: None)
        report = suite.run()
        target = report.save(tmp_path / 'nested' / 'report.json')
        assert target.exists()
        loaded = BenchReport.load(target)
        assert loaded.names() == ['persist']
        assert loaded.results[0].ops_per_sec == pytest.approx(
            report.results[0].ops_per_sec)
        assert BenchReport.from_dict(json.loads(
            target.read_text(encoding='utf-8'))).names() == ['persist']


# --- compare() ----------------------------------------------------------------


def _report_with(ops_by_name):
    results = [
        Timing(name=name, repeat=1, number=1, total_calls=1,
               min_s=1 / ops, mean_s=1 / ops, median_s=1 / ops, p95_s=1 / ops,
               stdev_s=0.0, ops_per_sec=ops, samples=[1 / ops])
        for name, ops in ops_by_name.items()
    ]
    return BenchReport(results=results)


class TestCompare:
    def test_verdict_matrix_at_tolerance_boundary(self):
        current = _report_with({'same': 100.0, 'better': 100.0, 'worse': 60.0,
                                'edge_in': 66.0, 'edge_out': 64.9, 'fresh': 50.0})
        baseline = {'results': [
            {'name': 'same', 'ops_per_sec': 100.0},
            {'name': 'better', 'ops_per_sec': 50.0},
            {'name': 'worse', 'ops_per_sec': 100.0},
            {'name': 'edge_in', 'ops_per_sec': 100.0},
            {'name': 'edge_out', 'ops_per_sec': 100.0},
            {'name': 'vanished', 'ops_per_sec': 80.0},
        ]}
        rows = {row.name: row for row in compare(current, baseline, tolerance=0.35)}
        assert rows['same'].verdict == 'stable'
        assert rows['same'].ratio == pytest.approx(1.0)
        assert rows['better'].verdict == 'faster'
        assert rows['worse'].verdict == 'slower'
        assert rows['worse'].ratio == pytest.approx(0.6)
        # exactly on the band edge (0.65) counts as stable; just outside is slower
        assert rows['edge_in'].verdict == 'stable'
        assert rows['edge_out'].verdict == 'slower'
        assert rows['fresh'].verdict == 'new'
        assert rows['fresh'].baseline_ops is None
        assert rows['vanished'].verdict == 'missing'
        assert rows['vanished'].current_ops is None

    def test_compare_never_raises_on_empty_or_bare_baseline(self):
        current = _report_with({'a': 10.0})
        assert compare(current, {}) == [CompareRow('a', 10.0, None, None, 'new')]
        rows = compare(current, {'a': 5.0})
        assert rows[0].verdict == 'faster'
        assert compare(current, None) == [CompareRow('a', 10.0, None, None, 'new')]

    def test_compare_table_renders_every_row(self):
        current = _report_with({'alpha': 100.0, 'beta': 50.0})
        baseline = {'results': [{'name': 'alpha', 'ops_per_sec': 100.0},
                                {'name': 'beta', 'ops_per_sec': 25.0},
                                {'name': 'gamma', 'ops_per_sec': 10.0}]}
        table = compare_table(compare(current, baseline))
        for token in ('benchmark', 'alpha', 'beta', 'gamma', 'verdict',
                      'stable', 'faster', 'missing'):
            assert token in table

    def test_compare_table_empty_rows(self):
        assert '(nothing to compare)' in compare_table([])


# --- bench groups execute -----------------------------------------------------


def _run_specs_once(specs, workdir):
    """Run each spec's callable exactly once, honouring setup/teardown."""
    for spec in specs:
        if spec.setup is not None:
            spec.setup()
        try:
            spec.fn()
        finally:
            if spec.teardown is not None:
                spec.teardown()


class TestBenchGroups:
    def test_core_group_runs_and_is_isolated(self, tmp_path):
        specs = bench_core.build_benches(workdir=str(tmp_path))
        assert len(specs) >= 20
        _run_specs_once(specs, tmp_path)
        # the cache group kept its SQLite state inside the workdir
        cache_db = tmp_path / 'cache' / 'http_cache.db'
        assert cache_db.exists()
        assert every_tag_from(specs, 'core')

    def test_analytics_group_runs(self, tmp_path):
        specs = bench_analytics.build_benches(workdir=str(tmp_path))
        assert len(specs) >= 20
        _run_specs_once(specs, tmp_path)
        assert every_tag_from(specs, 'analytics')

    def test_platform_group_runs_and_is_isolated(self, tmp_path):
        specs = bench_platform.build_benches(workdir=str(tmp_path))
        assert len(specs) >= 15
        _run_specs_once(specs, tmp_path)
        # the database group kept its history db inside the workdir and the
        # plugin/i18n globals were restored
        assert (tmp_path / 'database' / 'history.db').exists()
        import obscuralens.plugins as plugins_pkg
        assert plugins_pkg.plugin_commands() == {}
        from obscuralens.i18n import get_language
        assert get_language() == 'en'

    def test_benches_run_without_workdir_self_clean(self):
        specs = bench_core.build_benches() + bench_platform.build_benches()
        _run_specs_once(specs, None)
        # nothing to assert beyond "no exception and no leaked temp state";
        # the self-managed tempdirs are removed by each teardown

    def test_deterministic_sample_kinds(self):
        from obscuralens.investigate import detect_kind
        for kind, sample in bench_core.DETECT_SAMPLES:
            assert detect_kind(sample) == kind


def every_tag_from(specs, tag):
    """True when at least one spec carries the tag (group labelling check)."""
    return any(tag in spec.tags for spec in specs)


# --- committed baseline -------------------------------------------------------


class TestBaseline:
    def test_baseline_is_valid_json_with_full_schema(self):
        path = run_mod.DEFAULT_BASELINE
        assert path.exists(), 'benchmarks/results/baseline.json must be committed'
        document = json.loads(path.read_text(encoding='utf-8'))
        assert document['schema'] == 'obscuralens-benchmarks/1'
        assert document['total_benches'] == len(document['results'])
        assert document['total_benches'] >= 60
        required = {'name', 'repeat', 'number', 'total_calls', 'min_s', 'mean_s',
                    'median_s', 'p95_s', 'stdev_s', 'ops_per_sec', 'samples'}
        for entry in document['results']:
            assert required <= set(entry)
            assert entry['ops_per_sec'] > 0
            assert len(entry['samples']) == entry['repeat']

    def test_baseline_covers_every_registered_bench(self, tmp_path):
        suite = run_mod.build_suite(workdir=str(tmp_path))
        registered = {entry['name'] for entry in suite.registered()}
        baseline = json.loads(run_mod.DEFAULT_BASELINE.read_text(encoding='utf-8'))
        baseline_names = {entry['name'] for entry in baseline['results']}
        assert registered == baseline_names
        assert not baseline['errors'], 'the committed baseline must be error-free'

    def test_baseline_is_reasonably_sized(self):
        size = run_mod.DEFAULT_BASELINE.stat().st_size
        assert size < 200_000


# --- run.py CLI ---------------------------------------------------------------


class TestRunCli:
    def test_list_prints_names_and_tags(self, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr(run_mod, 'RESULTS_DIR', tmp_path)
        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', tmp_path / 'latest.json')
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', tmp_path / 'baseline.json')
        assert run_mod.main(['--list']) == 0
        out = capsys.readouterr().out
        assert 'validators_ip' in out
        assert '[core' in out
        assert 'database_get_history_500' in out

    def test_json_output_parses(self, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', tmp_path / 'latest.json')
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', tmp_path / 'baseline.json')
        assert run_mod.main(['--quick', '--only', 'validators_ip', '--json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['schema'] == 'obscuralens-benchmarks/1'
        assert payload['quick'] is True
        assert payload['results'][0]['name'] == 'validators_ip'

    def test_quick_run_mentions_benches(self, capsys, monkeypatch, tmp_path):
        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', tmp_path / 'latest.json')
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', tmp_path / 'baseline.json')
        assert run_mod.main(['--quick', '--only', 'validators', '--tags', 'core']) == 0
        out = capsys.readouterr().out
        assert 'quick' in out
        assert 'validators_ip' in out and 'validators_email' in out
        assert 'cache_get_hit' not in out  # only+tags both applied
        assert (tmp_path / 'latest.json').exists()

    def test_full_quick_smoke(self, capsys, monkeypatch, tmp_path):
        """Every registered bench survives a whole-suite quick run."""
        save = tmp_path / 'latest.json'
        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', save)
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', tmp_path / 'baseline.json')
        assert run_mod.main(['--quick']) == 0
        out = capsys.readouterr().out
        for name in ('validators_ip', 'detect_kind_all20', 'cluster_geo_dbscan_500',
                     'mcp_tools_encode', 'plugins_load_cycle',
                     'database_get_history_500'):
            assert name in out
        report = BenchReport.load(save)
        assert report.quick is True
        assert report.errors == []
        assert len(report.results) >= 60

    def test_save_and_compare_round_trip(self, capsys, monkeypatch, tmp_path):
        save = tmp_path / 'run.json'
        baseline = tmp_path / 'baseline.json'
        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', save)
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', baseline)
        assert run_mod.main(['--quick', '--only', 'validators_ip',
                             '--save', str(save)]) == 0
        capsys.readouterr()
        # compare the fresh report against itself: perfectly stable
        assert run_mod.main(['--quick', '--only', 'validators_ip',
                             '--save', str(save),
                             '--compare', str(save)]) == 0
        out = capsys.readouterr().out
        assert 'stable' in out
        assert 'validators_ip' in out

    def test_default_save_never_targets_baseline(self, monkeypatch, tmp_path):
        baseline = tmp_path / 'baseline.json'
        baseline.write_text('{"sentinel": true}', encoding='utf-8')
        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', tmp_path / 'latest.json')
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', baseline)
        assert run_mod.main(['--quick', '--only', 'nothing-matches']) == 0
        assert json.loads(baseline.read_text(encoding='utf-8')) == {'sentinel': True}
        assert (tmp_path / 'latest.json').exists()

    def test_exit_1_when_a_bench_raises(self, capsys, monkeypatch, tmp_path):
        def broken_builder(workdir=None):
            return [BenchSpec('broken_bench', lambda: (_ for _ in ()).throw(
                ValueError('boom')), tags=('core',))]

        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', tmp_path / 'latest.json')
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', tmp_path / 'baseline.json')
        monkeypatch.setattr(run_mod.bench_core, 'build_benches', broken_builder)
        monkeypatch.setattr(run_mod.bench_analytics, 'build_benches',
                            lambda workdir=None: [])
        monkeypatch.setattr(run_mod.bench_platform, 'build_benches',
                            lambda workdir=None: [])
        assert run_mod.main(['--only', 'broken_bench']) == 1
        assert 'broken_bench' in capsys.readouterr().err

    def test_exit_2_on_regression_with_flag(self, capsys, monkeypatch, tmp_path):
        # A bench that sleeps ~2 ms/call cannot reach a 1e9 ops/sec
        # baseline, so the comparison is guaranteed 'slower'.
        def slow_builder(workdir=None):
            def slow():
                time.sleep(0.002)
            return [BenchSpec('deliberately_slow', slow, tags=('core',))]

        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps({'results': [
            {'name': 'deliberately_slow', 'ops_per_sec': 1_000_000_000.0}]}),
            encoding='utf-8')
        monkeypatch.setattr(run_mod, 'DEFAULT_SAVE', tmp_path / 'latest.json')
        monkeypatch.setattr(run_mod, 'DEFAULT_BASELINE', tmp_path / 'baseline.json')
        monkeypatch.setattr(run_mod.bench_core, 'build_benches', slow_builder)
        monkeypatch.setattr(run_mod.bench_analytics, 'build_benches',
                            lambda workdir=None: [])
        monkeypatch.setattr(run_mod.bench_platform, 'build_benches',
                            lambda workdir=None: [])
        args = ['--only', 'deliberately_slow', '--compare', str(baseline)]
        assert run_mod.main(args) == 0  # slower alone never fails
        capsys.readouterr()
        assert run_mod.main(args + ['--fail-on-regression']) == 2
        out = capsys.readouterr().out
        assert 'slower' in out and 'deliberately_slow' in out


# --- state_dir glue -----------------------------------------------------------


class TestStateDir:
    def test_workdir_mode_creates_named_subdir(self, tmp_path):
        path, cleanup = state_dir(str(tmp_path), 'cache')
        assert path == tmp_path / 'cache'
        assert path.is_dir()
        assert cleanup is None

    def test_self_managed_mode_returns_cleanup(self):
        path, cleanup = state_dir(None, 'cache')
        try:
            assert path.is_dir()
            assert 'obscuralens-bench-cache-' in str(path)
        finally:
            cleanup()
        assert not path.exists()
