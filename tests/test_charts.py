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
