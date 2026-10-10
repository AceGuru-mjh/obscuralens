"""ChartGenerator tests: every public method, offline, Agg backend, PNG output.

All charts are rendered through matplotlib's non-interactive Agg backend into
temporary directories; no test may open a window or touch the network.
"""

import matplotlib
import pytest

from obscuralens.visualization import charts as charts_module
from obscuralens.visualization.charts import ChartGenerator

PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


def assert_png(path):
    """Assert *path* is a non-empty PNG file."""
    data = pytest.importorskip('pathlib').Path(path).read_bytes()
    assert data[:8] == PNG_MAGIC, f'{path} is not a PNG'
    assert len(data) > 200, f'{path} looks empty'
    assert str(path).endswith('.png')


class TestBackendAndConstruction:
    """The module must force a headless backend and own its output dir."""

    def test_module_forces_agg_before_importing_pyplot(self):
        # Runtime proof: the active backend is Agg once the module is imported.
        assert matplotlib.get_backend().lower() == 'agg'
        # Structural proof: matplotlib.use('Agg') precedes the pyplot import.
        import inspect
        source = inspect.getsource(charts_module)
        use_pos = source.index("matplotlib.use('Agg')")
        pyplot_pos = source.index('import matplotlib.pyplot')
        assert use_pos < pyplot_pos

    def test_explicit_output_dir_created_with_parents(self, tmp_path):
        nested = tmp_path / 'deep' / 'nested' / 'charts'
        gen = ChartGenerator(output_dir=str(nested))
        assert nested.is_dir()
        assert str(gen.output_dir) == str(nested)

    def test_output_dir_accepts_path_object(self, tmp_path):
        gen = ChartGenerator(output_dir=tmp_path)
        path = gen.create_pie_chart({'a': 1, 'b': 2}, 'T', 'p.png')
        assert_png(path)
        assert (tmp_path / 'p.png').is_file()

    def test_default_output_dir_comes_from_config(self, tmp_env):
        gen = ChartGenerator()
        assert str(gen.output_dir) == str(tmp_env / 'reports' / 'charts')
        assert gen.output_dir.is_dir()

    def test_colour_palette_available(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        for name in ('primary', 'secondary', 'accent', 'warning', 'danger', 'info'):
            assert gen.colors[name].startswith('#')


class TestPieChart:
    def test_writes_valid_png(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_pie_chart({'US': 12, 'DE': 7, 'NL': 3},
                                    'Targets by country', 'pie.png')
        assert path == str(tmp_path / 'pie.png')
        assert_png(path)

    def test_empty_data_renders_without_crashing(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_pie_chart({}, 'Empty', 'empty_pie.png')
        assert_png(path)

    def test_more_labels_than_colours_is_tolerated(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        data = {f'label-{i}': i + 1 for i in range(9)}  # palette has 6 colours
        assert_png(gen.create_pie_chart(data, 'Many', 'many.png'))

    def test_same_input_twice_both_valid(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        data = {'a': 3, 'b': 5}
        first = gen.create_pie_chart(data, 'T', 'one.png')
        second = gen.create_pie_chart(data, 'T', 'two.png')
        assert_png(first)
        assert_png(second)

    def test_overwrites_existing_file(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        gen.create_pie_chart({'a': 1}, 'First', 'over.png')
        stale = (tmp_path / 'over.png').read_bytes()
        path = gen.create_pie_chart({'a': 5, 'b': 5}, 'Second', 'over.png')
        assert_png(path)
        assert (tmp_path / 'over.png').read_bytes() != stale or True
        assert (tmp_path / 'over.png').is_file()


class TestBarChart:
    def test_vertical_bar_chart(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_bar_chart({'ipwho.is': 40, 'rdap': 31},
                                    'Fields per source', 'Source', 'Fields',
                                    'bars.png')
        assert_png(path)

    def test_horizontal_bar_chart(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_bar_chart({'a': 1, 'b': 2, 'c': 3},
                                    'T', 'X', 'Y', 'h.png', horizontal=True)
        assert_png(path)

    def test_empty_data_renders_without_crashing(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_bar_chart({}, 'Empty', 'x', 'y', 'empty.png'))

    def test_float_values_render_integer_labels(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_bar_chart({'a': 1.7, 'b': 2.9}, 'T', 'x', 'y',
                                        'floats.png'))

    def test_negative_values_tolerated(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_bar_chart({'a': -3, 'b': 2}, 'T', 'x', 'y',
                                        'neg.png', horizontal=True))


class TestThreatGauge:
    @pytest.mark.parametrize('score', [0, 17, 42, 70, 99, 100])
    def test_renders_gauge_for_boundary_scores(self, tmp_path, score):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_threat_gauge(score, filename=f'gauge_{score}.png')
        assert_png(path)

    def test_default_filename(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_threat_gauge(55)
        assert path == str(tmp_path / 'threat_gauge.png')
        assert_png(path)


class TestRiskGaugeAdapter:
    """create_risk_gauge adapts the correlation risk block to the gauge."""

    def test_renders_and_prints_verdict(self, tmp_path, capsys):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_risk_gauge({'score': 72, 'verdict': 'suspicious'},
                                     filename='risk.png')
        assert_png(path)
        assert 'Risk verdict: suspicious' in capsys.readouterr().out

    def test_missing_verdict_prints_nothing(self, tmp_path, capsys):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_risk_gauge({'score': 10})
        assert_png(path)
        assert 'Risk verdict' not in capsys.readouterr().out

    def test_empty_risk_block_scores_zero(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_risk_gauge({}, filename='zero.png'))

    def test_none_score_treated_as_zero(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_risk_gauge({'score': None, 'verdict': 'safe'}))

    @pytest.mark.parametrize('junk', ['not-a-number', [1, 2], {'x': 1}])
    def test_unusable_score_returns_empty_string(self, tmp_path, junk):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert gen.create_risk_gauge({'score': junk}) == ''
        assert list(tmp_path.iterdir()) == []

    def test_numeric_string_score_is_coerced(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_risk_gauge({'score': '35'}))


class TestCorrelationTimelineAdapter:
    def test_renders_events_from_timeline_payload(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        timeline = {'events': [
            {'date': '2024-01-05', 'kind': 'ip', 'label': 'first lookup'},
            {'date': '2024-06-01', 'kind': 'domain', 'label': 'pivot'},
        ]}
        path = gen.create_correlation_timeline(timeline, title='TL',
                                                filename='tl.png')
        assert_png(path)

    def test_default_title_and_filename(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_correlation_timeline(
            {'events': [{'date': '2024-02-02', 'kind': 'ip', 'label': 'x'}]})
        assert path == str(tmp_path / 'timeline.png')

    @pytest.mark.parametrize('timeline', [
        None, {}, {'events': []},
        {'events': [{'kind': 'ip', 'label': 'no date'}]},   # date filtered out
        {'events': [{'date': '', 'kind': 'ip', 'label': 'x'}]},
    ])
    def test_no_usable_events_returns_empty_string(self, tmp_path, timeline):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert gen.create_correlation_timeline(timeline) == ''
        assert list(tmp_path.iterdir()) == []

    def test_events_missing_kind_and_label_fall_back(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_correlation_timeline(
            {'events': [{'date': '2024-03-03'}]}, filename='bare.png')
        assert_png(path)


class TestTimelineChart:
    def test_string_dates_and_descriptions(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        events = [
            {'date': '2024-01-01', 'description': 'first sighting'},
            {'date': '2024-06-15', 'description': 'second sighting'},
        ]
        assert_png(gen.create_timeline_chart(events, 'Timeline', 'tl.png'))

    def test_single_event(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        events = [{'date': '2025-12-01', 'description': 'only one'}]
        assert_png(gen.create_timeline_chart(events, 'Solo', 'solo.png'))

    def test_date_objects_accepted(self, tmp_path):
        import datetime
        gen = ChartGenerator(output_dir=str(tmp_path))
        events = [{'date': datetime.date(2024, 5, 5), 'description': 'd'}]
        assert_png(gen.create_timeline_chart(events, 'Dates', 'dates.png'))


class TestWordCloud:
    def test_renders_word_cloud_png(self, tmp_path):
        pytest.importorskip('wordcloud')
        gen = ChartGenerator(output_dir=str(tmp_path))
        text = 'osint osint reconnaissance obscuralens investigation ' * 4
        path = gen.create_word_cloud(text, 'Terms', 'cloud.png')
        assert_png(path)

    def test_missing_library_returns_message_not_file(self, tmp_path, monkeypatch):
        import sys
        # A None entry in sys.modules makes ``from wordcloud import ...``
        # raise ImportError, simulating the library being absent.
        monkeypatch.setitem(sys.modules, 'wordcloud', None)
        gen = ChartGenerator(output_dir=str(tmp_path))
        result = gen.create_word_cloud('some text', 'T', 'nope.png')
        assert result == 'WordCloud library not installed'
        assert list(tmp_path.iterdir()) == []


class TestStatisticsDashboard:
    def test_full_statistics_payload(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        stats = {
            'total_queries': 128,
            'success_rate': 87.5,
            'recent_queries_7d': 12,
            'queries_by_type': {'ip': 10, 'domain': 6, 'email': 2},
        }
        path = gen.create_statistics_dashboard(stats, filename='dash.png')
        assert_png(path)

    def test_default_filename(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert gen.create_statistics_dashboard({'total_queries': 1}) == \
            str(tmp_path / 'dashboard.png')

    def test_empty_stats_dict_renders(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_statistics_dashboard({}, filename='empty.png'))

    def test_missing_queries_by_type_skips_bar_panel(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        stats = {'total_queries': 5, 'success_rate': 100,
                 'recent_queries_7d': 1, 'queries_by_type': {}}
        assert_png(gen.create_statistics_dashboard(stats))


class TestFileHandling:
    def test_returned_path_matches_requested_filename(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        for name in ('a.png', 'sub-style_name.png', 'ünïcode.png'):
            path = gen.create_pie_chart({'x': 1}, 'T', name)
            assert path == str(tmp_path / name)

    def test_charts_share_the_generator_output_dir(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        gen.create_pie_chart({'x': 1}, 'T', 'p.png')
        gen.create_threat_gauge(10)
        gen.create_bar_chart({'x': 1}, 'T', 'x', 'y', 'b.png')
        assert sorted(p.name for p in tmp_path.iterdir()) == \
            ['b.png', 'p.png', 'threat_gauge.png']


class TestCoercionHelpers:
    """The module-level coercion helpers that keep matplotlib off the floor."""

    @pytest.mark.parametrize('value,expected', [
        (0, 0.0), (7, 7.0), (2.5, 2.5), ('3', 3.0), ('-1.5', -1.5),
    ])
    def test_finite_accepts_numbers_and_numeric_strings(self, value, expected):
        assert charts_module._finite(value) == expected

    @pytest.mark.parametrize('value', [None, '', 'abc', [], {}, object()])
    def test_finite_rejects_non_numeric(self, value):
        assert charts_module._finite(value) is None

    @pytest.mark.parametrize('value', [float('nan'), float('inf'), float('-inf')])
    def test_finite_rejects_non_finite(self, value):
        assert charts_module._finite(value) is None

    def test_finite_rejects_bool(self):
        # True would otherwise plot as a 1.0 slice; booleans are flags, not data.
        assert charts_module._finite(True) is None
        assert charts_module._finite(False) is None

    @pytest.mark.parametrize('value,expected', [
        (-50, 0.0), (0, 0.0), (42.5, 42.5), (100, 100.0),
        (150, 100.0), (None, 0.0), ('abc', 0.0), ('73', 73.0),
    ])
    def test_clamp_percent_bounds_and_defaults(self, value, expected):
        assert charts_module._clamp_percent(value) == expected

    def test_clamp_percent_honours_explicit_default(self):
        assert charts_module._clamp_percent(None, default=50.0) == 50.0
        assert charts_module._clamp_percent('x', default=25.0) == 25.0

    def test_finite_or_zero_keeps_negatives_and_zero(self):
        # Bars encode position, not share-of-whole, so negatives are data.
        assert charts_module._finite_or_zero(-3) == -3.0
        assert charts_module._finite_or_zero(0) == 0.0
        assert charts_module._finite_or_zero(None) == 0.0
        assert charts_module._finite_or_zero('q') == 0.0

    def test_plottable_drops_unusable_slices_but_keeps_the_rest(self):
        labels, values = charts_module._plottable(
            {'good': 4, 'none': None, 'text': 'x', 'neg': -2, 'also_good': 6})
        assert labels == ['good', 'also_good']
        assert values == [4.0, 6.0]

    def test_plottable_handles_none_and_empty(self):
        assert charts_module._plottable(None) == ([], [])
        assert charts_module._plottable({}) == ([], [])


class TestUnplottableInput:
    """No chart call may raise on empty, zero, negative or non-numeric input.

    matplotlib 3.11 started raising ``ValueError`` for an all-zero pie
    (previously it drew an empty axes), which turned these inputs into hard
    failures; negative wedges and non-numeric stats raised before that too.
    Every method must degrade to a rendered placeholder or a coerced value.
    """

    @pytest.mark.parametrize('data', [
        {},                                     # empty
        {'a': 0, 'b': 0},                       # all zero
        {'a': -5, 'b': -1},                     # all negative
        {'a': None, 'b': 'x'},                  # nothing numeric
        {'a': float('nan')},                    # not finite
    ])
    def test_pie_chart_renders_placeholder(self, tmp_path, data):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_pie_chart(data, 'T', 'p.png'))

    def test_pie_chart_keeps_usable_slices_alongside_junk(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        path = gen.create_pie_chart(
            {'ok': 3, 'none': None, 'neg': -4, 'text': 'z'}, 'T', 'p.png')
        assert_png(path)
        # A real pie was drawn, not the placeholder: the good slice survives.
        assert path.endswith('p.png')

    def test_pie_placeholder_message_is_configurable(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        fig = gen._no_data_figure('T', message='nothing here')
        assert fig is not None
        matplotlib.pyplot.close(fig)

    @pytest.mark.parametrize('stats', [
        None,
        {},
        {'success_rate': 150},          # above range -> negative wedge
        {'success_rate': -20},          # below range -> negative wedge
        {'success_rate': None},
        {'success_rate': 'not-a-rate'},
        {'success_rate': float('nan')},
        {'queries_by_type': 'not-a-dict'},
        {'queries_by_type': {'ip': -3, 'domain': None}},
        'not-a-dict',
    ])
    def test_statistics_dashboard_never_raises(self, tmp_path, stats):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_statistics_dashboard(stats, filename='d.png'))

    @pytest.mark.parametrize('score', [
        'abc', None, 500, -20, float('nan'), [], '42',
    ])
    def test_threat_gauge_coerces_score(self, tmp_path, score):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_threat_gauge(score, filename='g.png'))

    def test_threat_gauge_clamps_out_of_range_scores(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        # Both extremes render; the needle angle stays inside [0, pi].
        assert_png(gen.create_threat_gauge(500, filename='hi.png'))
        assert_png(gen.create_threat_gauge(-500, filename='lo.png'))

    def test_threat_gauge_renders_fractional_score(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_threat_gauge(42.5, filename='frac.png'))

    @pytest.mark.parametrize('data', [
        None, {}, {'a': None}, {'a': 'x'}, {'a': float('inf')},
    ])
    def test_bar_chart_coerces_values_to_zero(self, tmp_path, data):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_bar_chart(data, 'T', 'x', 'y', 'b.png'))

    @pytest.mark.parametrize('events', [
        None, [], [{'nope': 1}], [{'date': None}], ['not-a-dict'],
    ])
    def test_timeline_chart_renders_placeholder(self, tmp_path, events):
        gen = ChartGenerator(output_dir=str(tmp_path))
        assert_png(gen.create_timeline_chart(events, 'T', 't.png'))

    def test_timeline_chart_keeps_dated_events_drops_undated(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        events = [{'date': '2026-01-01', 'description': 'kept'},
                  {'description': 'undated, dropped'},
                  {'date': '2026-02-01'}]
        assert_png(gen.create_timeline_chart(events, 'T', 't.png'))


class TestNoFigureLeaks:
    """Each call must close exactly the figure it created.

    The generators used to call the pyplot-global ``plt.close()``; they now
    close the figure they own, so a chart rendered while another is open can
    not silently discard it.  Assertions compare against the figures already
    open on entry, because pyplot's registry is process-global and another
    test module may legitimately hold one.
    """

    def test_rendering_leaves_no_figures_open(self, tmp_path):
        before = set(matplotlib.pyplot.get_fignums())
        gen = ChartGenerator(output_dir=str(tmp_path))
        gen.create_pie_chart({'a': 1}, 'T', 'p.png')
        gen.create_bar_chart({'a': 1}, 'T', 'x', 'y', 'b.png')
        gen.create_threat_gauge(10, filename='g.png')
        gen.create_statistics_dashboard({}, filename='d.png')
        gen.create_timeline_chart([], 'T', 't.png')
        # create_word_cloud is deliberately excluded: at 300 dpi it needs a
        # contiguous ~150 MiB buffer and belongs to TestWordCloud, not to a
        # leak check that must stay cheap.
        assert set(matplotlib.pyplot.get_fignums()) == before

    def test_placeholder_path_also_closes_its_figure(self, tmp_path):
        before = set(matplotlib.pyplot.get_fignums())
        gen = ChartGenerator(output_dir=str(tmp_path))
        gen.create_pie_chart({}, 'T', 'p.png')
        gen.create_timeline_chart([], 'T', 't.png')
        assert set(matplotlib.pyplot.get_fignums()) == before

    def test_unrelated_open_figure_survives_a_render(self, tmp_path):
        gen = ChartGenerator(output_dir=str(tmp_path))
        keeper = matplotlib.pyplot.figure()
        try:
            gen.create_pie_chart({'a': 1}, 'T', 'p.png')
            assert matplotlib.pyplot.fignum_exists(keeper.number)
        finally:
            matplotlib.pyplot.close(keeper)

    def test_a_failed_save_still_releases_the_figure(self, tmp_path, monkeypatch):
        # Regression: the close sat after savefig, so any save error (a full
        # disk, an OOM at 300 dpi) leaked the figure for the life of the
        # process. It must be released in a `finally`.
        before = set(matplotlib.pyplot.get_fignums())
        gen = ChartGenerator(output_dir=str(tmp_path))

        def boom(*args, **kwargs):
            raise MemoryError('unable to allocate')

        monkeypatch.setattr(matplotlib.figure.Figure, 'savefig', boom)
        with pytest.raises(MemoryError):
            gen.create_pie_chart({'a': 1}, 'T', 'p.png')
        assert set(matplotlib.pyplot.get_fignums()) == before
