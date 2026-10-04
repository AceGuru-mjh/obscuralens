"""
Offline tests for obscuralens.advanced.report_builder (self-contained HTML reports).

Every public builder accepts pre-built payloads, which keeps the suite pure and
offline: tracker execution is exercised through the module's own lazy seams
(``import_module`` for the tracker fleet, ``correlation.attach_risk`` for the
best-effort enrichment, ``investigate.investigate`` for pivot runs and
``patterns._load_records`` for the stored journal), so no test ever touches the
network or the shared test database. Assertions target the exact markup the
builders emit (chips, panels, inline SVG) plus the escaping rules that render
hostile data inert.
"""

import re
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from obscuralens import __version__
from obscuralens.advanced import report_builder as rb

# --------------------------------------------------------------- test helpers

def tracker_result(target='8.8.8.8', **overrides):
    """A well-formed successful tracker result in the repo envelope shape."""
    result = {
        'success': True,
        'info': {
            'ip': target,
            'reverse_dns': 'dns.google',
            'country': 'United States',
            'ports': [53, 443],
        },
        'field_sources': {'ip': ['rdap', 'ipwho.is'], 'reverse_dns': 'dns'},
        'sources_ok': ['rdap', 'ipwho.is'],
        'sources_failed': {'ip-api.com': 'timeout after 5s'},
        'field_count': 3,
        'errors': [],
    }
    result.update(overrides)
    return result


def invest_payload():
    """An investigate() payload: two pivoted kinds, entities, links, errors."""
    return {
        'target': 'example.com',
        'kind': 'domain',
        'order': ['domain', 'ip', 'nope'],
        'results': {
            'domain': {
                'domain': 'example.com', 'success': True,
                'info': {'domain': 'example.com', 'registrar': 'Example Inc'},
                'field_sources': {'domain': ['rdap']},
                'sources_ok': ['rdap'], 'sources_failed': {'dns': 'timeout'},
                'field_count': 2, 'errors': [],
            },
            'ip': {
                'ip': '93.184.216.34', 'success': False, 'info': {},
                'field_sources': {}, 'sources_ok': ['dns'],
                'sources_failed': {'ipwho.is': 'http 500'},
                'field_count': 0, 'errors': ['ipwho.is failed'],
            },
        },
        'entities': [
            {'id': 'e1', 'type': 'domain', 'value': 'example.com',
             'role': 'target', 'label': 'example.com'},
            {'id': 'e2', 'type': 'ip', 'value': '93.184.216.34'},
            {'id': 'e3', 'type': 'hostname', 'value': 'www.example.com'},
        ],
        'links': [
            {'from': 'e1', 'to': 'e2', 'label': 'resolves to'},
            {'from': 'e9', 'to': 'e1', 'label': 'dangling'},
            {'to': 'e2', 'label': 'no from'},
        ],
        'errors': [],
    }


HISTORY_RECORDS = [
    {'kind': 'ip', 'value': '8.8.8.8', 'timestamp': '2024-06-01T10:00:00Z'},
    {'kind': 'ip', 'value': '8.8.8.8', 'timestamp': '2024-06-02T11:00:00Z'},
    {'kind': 'domain', 'value': 'example.com', 'timestamp': '2024-06-03T12:00:00Z'},
    {'kind': 'domain', 'value': 'example.com', 'timestamp': 'not-a-timestamp'},
    {'kind': 'ip', 'value': '1.1.1.1', 'timestamp': 1717245600},
]


# ------------------------------------------------------- display / escaping

class TestDisplayAndEscaping:
    """_display flattens every value shape; _esc HTML-escapes the result."""

    @pytest.mark.parametrize('value, expected', [
        (None, ''),
        (True, 'true'),
        (False, 'false'),
        (5, '5'),
        (2.5, '2.5'),
        ('plain', 'plain'),
        ([], ''),
        ([None, 'a', None], 'a'),
        ((1, 2), '1, 2'),
        ({'a': 1}, '{"a": 1}'),
    ])
    def test_display_basics(self, value, expected):
        assert rb._display(value) == expected

    def test_display_long_list_summarises_remainder(self):
        text = rb._display(list(range(12)))
        assert text.startswith('0, 1, 2, 3, 4, 5, 6, 7, 8, 9')
        assert text.endswith('(+2 more)')

    def test_display_all_none_overflow_list(self):
        # first ten items are all None -> the "(+N more)" tail is all that survives
        assert rb._display([None] * 10 + ['x']) == '(+1 more)'

    def test_display_caps_long_strings(self):
        assert rb._display('x' * 400) == 'x' * 400
        assert rb._display('x' * 401) == 'x' * 400 + '…'

    def test_display_dict_falls_back_to_str_when_unserialisable(self):
        value = {(1, 2): 'x'}  # tuple keys are not JSON
        assert rb._display(value) == str(value)

    def test_esc_escapes_markup_characters(self):
        assert rb._esc('<b>&"\'') == '&lt;b&gt;&amp;&quot;&#x27;'

    def test_esc_flattens_then_escapes(self):
        assert rb._esc(['<i>', None]) == '&lt;i&gt;'


class TestSmallHelpers:
    """Colours, stamps, chips, the page skeleton, header/footer/panel."""

    @pytest.mark.parametrize('kind, color', [
        ('ip', '#60a5fa'), ('domain', '#2dd4a7'), ('hostname', '#7dd3fc'),
        (' IP ', '#60a5fa'), ('Domain', '#2dd4a7'),
        ('zzz', rb._FALLBACK_COLOR), ('', rb._FALLBACK_COLOR),
        (None, rb._FALLBACK_COLOR), (123, rb._FALLBACK_COLOR),
    ])
    def test_kind_color(self, kind, color):
        assert rb._kind_color(kind) == color

    def test_kind_color_map_has_the_documented_kinds(self):
        assert set(rb._KIND_COLORS) >= {'ip', 'phone', 'username', 'email', 'domain',
                                        'url', 'crypto', 'hash', 'cve', 'asn', 'mac',
                                        'iban', 'imei', 'coords'}
        assert set(rb._KIND_COLORS) >= {'hostname', 'registrar', 'breach',
                                        'organisation', 'subdomain', 'nameserver',
                                        'mx', 'prefix', 'wallet', 'profile'}

    def test_generated_text_format(self):
        assert re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC',
                            rb._generated_text())

    def test_css_returns_the_embedded_stylesheet(self):
        assert rb._css() is rb._STYLESHEET
        assert ':root' in rb._css() and '@media print' in rb._css()

    def test_stat_chip_markup(self):
        assert rb._stat_chip('Fields', 3) == (
            '<span class="chip "><span class="chip-label">Fields</span>'
            '<span class="chip-value">3</span></span>')
        chip = rb._stat_chip('<L>', '<v>', 'bad')
        assert chip.startswith('<span class="chip bad">')
        assert '&lt;L&gt;' in chip and '&lt;v&gt;' in chip

    def test_page_skeleton(self):
        page = rb._page('T<i>tle', '<p>body</p>')
        assert page.startswith('<!DOCTYPE html>\n<html lang="en">')
        assert '<meta charset="utf-8">' in page
        assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in page
        assert '<title>T&lt;i&gt;tle</title>' in page
        assert f'<style>{rb._STYLESHEET}</style>' in page
        assert '<body>\n<div class="wrap">\n<p>body</p>\n</div>\n</body>\n</html>' in page

    def test_header_markup(self):
        header = rb._header('ip', '8.8.8.8', 'meta line')
        assert 'Obscura<span class="accent">Lens</span>' in header
        assert '<span class="badge kind">ip</span>' in header
        assert '<span class="target mono">8.8.8.8</span>' in header
        assert '<div class="head-sub">meta line</div>' in header

    def test_footer_markup(self):
        footer = rb._footer()
        assert 'Generated by ObscuraLens' in footer
        assert f'v{__version__}' in footer
        assert 'all data stays on this machine' in footer
        assert '<span class="muted">' in footer

    def test_panel_markup(self):
        assert rb._panel('<h>Hi</h>', 'inner') == \
            '<section class="panel"><h2><h>Hi</h></h2>inner</section>'

    def test_info_of_tolerates_junk(self):
        assert rb._info_of('junk') == {}
        assert rb._info_of({'info': 'junk'}) == {}
        assert rb._info_of({'info': {'a': 1}}) == {'a': 1}
        assert rb._info_of({}) == {}

    @pytest.mark.parametrize('score, color', [
        (0, '#2dd4a7'), (14, '#2dd4a7'), (15, '#60a5fa'), (39, '#60a5fa'),
        (40, '#f5a524'), (69, '#f5a524'), (70, '#fb923c'), (89, '#fb923c'),
        (90, '#f87171'), (100, '#f87171'), ('x', rb._FALLBACK_COLOR),
        (None, rb._FALLBACK_COLOR),
    ])
    def test_risk_color_bands(self, score, color):
        assert rb._risk_color(score) == color


# ------------------------------------------------------ lazy execution seams

class TestRunTracker:
    """_run_tracker degrades every failure into the standard failure shape."""

    def test_unsupported_kind(self):
        result = rb._run_tracker('nope', 'x')
        assert result['success'] is False
        assert result['info'] == {} and result['field_sources'] == {}
        assert result['sources_ok'] == [] and result['sources_failed'] == {}
        assert result['field_count'] == 0
        assert result['errors'] == ["unsupported kind 'nope'"]

    def test_missing_tracker_class_is_captured(self, monkeypatch):
        monkeypatch.setattr(rb, 'import_module',
                            lambda name, package=None: SimpleNamespace())
        result = rb._run_tracker('ip', 'x')
        assert result['success'] is False
        assert result['errors'][0].startswith('AttributeError')

    def test_tracker_explosion_is_captured(self, monkeypatch):
        class Boom:
            def track(self, target):
                raise RuntimeError('boom')

        monkeypatch.setattr(rb, 'import_module',
                            lambda name, package=None: SimpleNamespace(IPTracker=Boom))
        result = rb._run_tracker('ip', 'x')
        assert result['success'] is False
        assert result['errors'] == ['RuntimeError: boom']

    def test_tracker_resolution_uses_the_tracker_package(self, monkeypatch):
        holder = {}

        class Fake:
            def track(self, target):
                return {'success': True, 'info': {}, 'field_count': 0}

        def fake_import(name, package=None):
            holder['name'] = name
            holder['package'] = package
            return SimpleNamespace(IPTracker=Fake)

        monkeypatch.setattr(rb, 'import_module', fake_import)
        result = rb._run_tracker('ip', 'x')
        assert result['success'] is True
        assert holder['name'] == '..trackers.ip_tracker'
        assert holder['package'] == 'obscuralens.advanced'


class TestRunInvestigate:
    """_run_investigate passes the payload through or degrades to a shape."""

    def test_success_passthrough(self, monkeypatch):
        import obscuralens.investigate as investigate_module
        payload = invest_payload()
        monkeypatch.setattr(investigate_module, 'investigate', lambda target: payload)
        assert rb._run_investigate('example.com') is payload

    def test_exception_failure_shape(self, monkeypatch):
        import obscuralens.investigate as investigate_module

        def boom(target):
            raise ValueError('undetectable')

        monkeypatch.setattr(investigate_module, 'investigate', boom)
        out = rb._run_investigate('x')
        assert out['target'] == 'x' and out['kind'] == 'unknown'
        assert out['order'] == [] and out['results'] == {}
        assert out['entities'] == [] and out['links'] == []
        assert out['errors'][0].startswith('ValueError')


# ---------------------------------------------------- reusable renderers

class TestFieldTable:
    """The Field | Value | Sources table with provenance chips."""

    def test_empty_or_junk_info_renders_a_note(self):
        note = 'No fields were returned for this target.'
        assert note in rb._field_table({}, {})
        assert note in rb._field_table('junk', None)

    def test_rows_sorted_by_name_with_values(self):
        info = {'ports': [53, 443], 'country': 'US', 'ip': '1.2.3.4'}
        html = rb._field_table(info, None)
        assert html.index('<td class="mono">country</td>') < \
            html.index('<td class="mono">ip</td>') < \
            html.index('<td class="mono">ports</td>')
        assert '<td class="value">53, 443</td>' in html
        assert '<span class="muted">&mdash;</span>' in html  # no provenance

    def test_provenance_shapes(self):
        info = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
        provenance = {
            'a': ['s1', 's2'],        # list -> one chip per source
            'b': 'whois',             # bare string -> single chip
            'c': 7,                   # junk -> em dash
            'd': [f's{i}' for i in range(8)],  # capped at six chips
        }
        html = rb._field_table(info, provenance)
        assert '<span class="src">s1</span><span class="src">s2</span>' in html
        assert '<span class="src">whois</span>' in html
        assert 's6' not in html and 's5' in html
        assert '<span class="muted">&mdash;</span>' in html

    def test_values_are_escaped(self):
        html = rb._field_table({'x': '<script>'}, None)
        assert '<script>' not in html and '&lt;script&gt;' in html


class TestSourcesChips:
    """Source health chips: green ok, red failed (reason on hover)."""

    def test_ok_and_failed_chips(self):
        html = rb._sources_chips(['rdap', 'ipwho.is'], {'ip-api.com': 'timeout'})
        assert '<div><span class="src">rdap</span><span class="src">ipwho.is</span></div>' in html
        assert '<span class="src bad" title="timeout">ip-api.com</span>' in html

    def test_blank_and_junk_entries_filtered(self):
        html = rb._sources_chips(['', '   ', None, 5], 'junk')
        assert '<span class="src">5</span>' in html
        assert '<span class="src"></span>' not in html

    def test_no_health_note(self):
        note = 'No source health recorded for this lookup.'
        assert note in rb._sources_chips([], {})
        assert note in rb._sources_chips(None, None)
        assert note in rb._sources_chips([], 'junk')
        # a lone ok list still renders its chips rather than the note
        assert rb._sources_chips(['ok'], []) == '<div><span class="src">ok</span></div>'

    def test_failed_chips_capped_at_twenty(self):
        failed = {f's{i}': 'x' for i in range(25)}
        html = rb._sources_chips([], failed)
        assert 's19' in html and 's20' not in html


class TestRiskPanel:
    """The risk panel: score, verdict, SVG bar and the signal table."""

    def test_missing_risk_renders_explanatory_note(self):
        assert 'No heuristic risk score is attached' in rb._risk_panel(None)
        assert 'No heuristic risk score is attached' in rb._risk_panel('junk')

    def test_full_panel(self):
        risk = {'score': 42, 'verdict': 'elevated', 'summary': 'weighted signals',
                'signals': [{'id': 'open_ports', 'weight': 2, 'detail': '3 open ports'},
                            'junk', {'id': 'proxy', 'weight': 1, 'detail': 'none'}]}
        html = rb._risk_panel(risk)
        assert '<span class="risk-score" style="color:#f5a524">42</span>' in html
        assert '<span class="risk-verdict" style="color:#f5a524">elevated</span>' in html
        assert 'weighted signals' in html
        assert '<rect x="0" y="0" width="42" height="12" rx="3" fill="#f5a524"/>' in html
        assert '<th>Signal</th><th>Weight</th><th>Detail</th>' in html
        assert html.count('<tr><td class="mono">') == 2  # junk entry dropped
        assert 'Heuristic score' in html

    def test_junk_score_renders_zero_bar_and_unknown_verdict(self):
        html = rb._risk_panel({'score': 'abc', 'verdict': None, 'signals': 'nope'})
        assert '<rect x="0" y="0" width="0" height="12"' in html
        assert '<span class="risk-verdict" style="color:#8b98a9">unknown</span>' in html
        assert '<th>Signal</th>' not in html

    def test_none_score_displays_a_dash(self):
        html = rb._risk_panel({'score': None})
        assert '<span class="risk-score" style="color:#8b98a9">-</span>' in html


# ---------------------------------------------------------- inline SVG

class TestSvgCharts:
    """_svg_bars / _svg_sparkline / _svg_donut / _svg_graph markup."""

    def test_num_text(self):
        assert rb._num_text(5.0) == '5'
        assert rb._num_text(5.25) == '5.25'

    def test_bars_empty_or_non_numeric(self):
        assert rb._svg_bars([]) == ''
        assert rb._svg_bars(None) == ''
        assert rb._svg_bars(['a', None, True]) == ''

    def test_bars_render_one_rect_per_value(self):
        html = rb._svg_bars([2, 0, 1.5])
        assert 'aria-label="bar chart of 3 values"' in html
        assert html.count('<rect') == 3
        assert '<title>2</title>' in html      # integer-ish tooltip
        assert '<title>1.50</title>' in html   # two-decimal tooltip
        assert '<rect x="0" y="0" width="860"' not in html  # scaled, not full width

    def test_sparkline_empty_single_and_multi(self):
        assert rb._svg_sparkline([]) == ''
        assert rb._svg_sparkline([True]) == ''
        dot = rb._svg_sparkline([5])
        assert '<svg class="spark"' in dot and '<circle' in dot
        line = rb._svg_sparkline([1, 2, 3])
        assert '<polyline points="' in line and 'sparkline of 3 values' in line

    def test_donut_skips_non_positive_and_junk_slices(self):
        assert rb._svg_donut([]) == ''
        assert rb._svg_donut([{'label': 'x', 'value': 0, 'color': '#fff'}]) == ''
        assert rb._svg_donut([{'label': 'x', 'value': True, 'color': '#fff'}]) == ''
        assert rb._svg_donut(['junk', {'label': 'x'}]) == ''

    def test_donut_arcs_and_total(self):
        slices = [{'label': 'ip', 'value': 3, 'color': '#60a5fa'},
                  {'label': 'domain', 'value': 1, 'color': '#2dd4a7'},
                  {'label': 'plain', 'value': 2}]
        html = rb._svg_donut(slices)
        assert 'aria-label="distribution donut chart"' in html
        assert html.count('<circle') == 3
        assert 'class="donut-total">6</text>' in html
        assert '<title>ip: 3 (50.0%)</title>' in html
        assert 'stroke="#8b98a9"' in html  # colourless slice falls back

    def test_graph_empty_when_no_usable_entities(self):
        assert rb._svg_graph([], []) == ''
        assert rb._svg_graph([{'type': 'ip'}], []) == ''  # no id
        assert rb._svg_graph(None, None) == ''

    def test_graph_renders_nodes_edges_and_target_ring(self):
        entities = [{'id': 'e1', 'type': 'domain', 'value': 'example.com',
                     'role': 'target', 'label': 'example.com'},
                    {'id': 'e2', 'type': 'ip', 'value': '93.184.216.34'},
                    {'id': 'e3', 'type': 'ip', 'value': '0.0.0.0'}]
        links = [{'from': 'e1', 'to': 'e2', 'label': 'resolves to'},
                 {'from': 'e9', 'to': 'e1', 'label': 'dangling'},
                 {'to': 'e2', 'label': 'no from'}]
        html = rb._svg_graph(entities, links)
        assert '<svg class="graph"' in html
        assert 'aria-label="entity relationship graph, 3 nodes, 1 links"' in html
        assert html.count('<circle') == 3       # dangling / linkless edges dropped
        assert html.count('<line') == 1
        assert 'stroke="#f5a524" stroke-width="3.0"' in html   # investigated target
        assert 'stroke="#0a0e14" stroke-width="1.5"' in html   # plain node
        assert '<title>resolves to</title>' in html
        assert '<title>domain: example.com</title>' in html
        # degree grows the radius: linked node 9.9, isolated node 9.0
        assert 'r="9.9"' in html and 'r="9.0"' in html

    def test_graph_label_truncated_at_eighteen_chars(self):
        entities = [{'id': 'e1', 'type': 'domain', 'value': 'x',
                     'label': 'y' * 25}]
        html = rb._svg_graph(entities, [])
        assert 'y' * 17 + '…' in html
        assert 'y' * 18 not in html

    def test_graph_hides_labels_beyond_forty_nodes(self):
        entities = [{'id': f'e{i}', 'type': 'ip', 'value': f'v{i}'}
                    for i in range(45)]
        html = rb._svg_graph(entities, [])
        assert '<text' not in html
        assert 'entity relationship graph, 45 nodes, 0 links' in html

    def test_graph_layout_is_deterministic(self):
        entities = [{'id': f'e{i}', 'type': 'ip', 'value': f'v{i}'} for i in range(12)]
        links = [{'from': 'e0', 'to': f'e{i}', 'label': 'l'} for i in range(1, 12)]
        assert rb._svg_graph(entities, links) == rb._svg_graph(entities, links)


# ------------------------------------------------------- build_report

class TestBuildReport:
    """The single-target dossier over a synthetic tracker result."""

    def test_full_document_structure(self):
        html = rb.build_report('ip', '8.8.8.8', tracker_result())
        assert html.startswith('<!DOCTYPE html>\n<html lang="en">')
        assert '<meta charset="utf-8">' in html
        assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html
        assert '<title>ObscuraLens · ip · 8.8.8.8</title>' in html
        assert '<style>' in html and '--bg: #0a0e14' in html and '@media print' in html
        assert 'Obscura<span class="accent">Lens</span>' in html
        assert '<span class="badge kind">ip</span>' in html
        assert '<span class="target mono">8.8.8.8</span>' in html
        assert 'Investigation report · generated' in html
        assert f'ObscuraLens v{__version__}' in html
        assert html.rstrip().endswith('</html>')

    def test_summary_stat_chips(self):
        html = rb.build_report('ip', '8.8.8.8', tracker_result())
        assert ('<span class="chip ok"><span class="chip-label">Success</span>'
                '<span class="chip-value">yes</span></span>') in html
        assert ('<span class="chip "><span class="chip-label">Fields</span>'
                '<span class="chip-value">3</span></span>') in html
        assert ('<span class="chip ok"><span class="chip-label">Sources ok</span>'
                '<span class="chip-value">2</span></span>') in html
        assert ('<span class="chip bad"><span class="chip-label">Sources failed</span>'
                '<span class="chip-value">1</span></span>') in html
        assert ('<span class="chip "><span class="chip-label">Risk</span>'
                '<span class="chip-value">—</span></span>') in html

    def test_panels_field_table_and_sources(self):
        html = rb.build_report('ip', '8.8.8.8', tracker_result())
        assert '<h2>Risk Assessment</h2>' in html
        assert '<h2>Collected Fields</h2>' in html
        assert '<h2>Data Sources</h2>' in html
        assert 'No heuristic risk score is attached' in html
        assert html.index('<td class="mono">country</td>') < \
            html.index('<td class="mono">ip</td>') < \
            html.index('<td class="mono">ports</td>')
        assert '<td class="value">53, 443</td>' in html
        assert '<span class="src">rdap</span><span class="src">ipwho.is</span>' in html
        assert '<span class="src">dns</span>' in html
        assert '<span class="src bad" title="timeout after 5s">ip-api.com</span>' in html

    def test_errors_panel_when_tracker_failed(self):
        result = tracker_result(success=False, info={}, sources_ok=[],
                                field_count=0, errors=['lookup failed'])
        html = rb.build_report('ip', '1.2.3.4', result)
        assert ('<span class="chip bad"><span class="chip-label">Success</span>'
                '<span class="chip-value">no</span></span>') in html
        assert '<h2>Errors</h2>' in html
        assert '<li>lookup failed</li>' in html
        assert 'No fields were returned for this target.' in html

    def test_result_risk_block_used_when_no_payload(self):
        result = tracker_result()
        result['risk'] = {'score': 90, 'verdict': 'critical', 'signals': [],
                          'summary': 'many signals'}
        html = rb.build_report('ip', 'x', result)
        assert ('<span class="chip warn"><span class="chip-label">Risk</span>'
                '<span class="chip-value">90</span></span>') in html
        assert '<rect x="0" y="0" width="90" height="12" rx="3" fill="#f87171"/>' in html

    def test_payload_risk_wins_over_result_risk(self):
        result = tracker_result()
        result['risk'] = {'score': 90, 'verdict': 'critical', 'signals': []}
        payload = {'risk': {'score': 10, 'verdict': 'low', 'signals': []}}
        html = rb.build_report('ip', 'x', result, payload)
        assert '<span class="chip-value">10</span>' in html
        assert '<rect x="0" y="0" width="10" height="12"' in html
        assert 'width="90"' not in html

    def test_hostile_values_are_escaped_everywhere(self):
        result = tracker_result()
        result['info'] = {'note': '<script>alert("x")</script>', "o'brien": '<b>&</b>'}
        html = rb.build_report('<k>', '<t>&"x"</t>', result)
        assert '<script>' not in html
        assert '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;' in html
        assert '<t>' not in html
        assert '&lt;t&gt;&amp;&quot;x&quot;&lt;/t&gt;' in html
        assert '&#x27;' in html and '&lt;b&gt;&amp;&lt;/b&gt;' in html

    def test_field_count_junk_falls_back_to_info_length(self):
        result = tracker_result()
        result['field_count'] = 'not-a-number'
        html = rb.build_report('ip', 'x', result)
        assert ('<span class="chip "><span class="chip-label">Fields</span>'
                '<span class="chip-value">4</span></span>') in html

    def test_kind_and_target_normalised_and_defaulted(self):
        html = rb.build_report(' IP ', ' 8.8.4.4 ', tracker_result('8.8.4.4'))
        assert '<span class="badge kind">ip</span>' in html
        assert '<span class="target mono">8.8.4.4</span>' in html
        html = rb.build_report('', '', tracker_result())
        assert '<span class="badge kind">target</span>' in html
        assert '<span class="target mono">(no target)</span>' in html
        assert '<title>ObscuraLens · report · target</title>' in html

    def test_deterministic_when_generated_stamp_fixed(self, monkeypatch):
        monkeypatch.setattr(rb, '_generated_text', lambda: '2024-01-01 00:00 UTC')
        first = rb.build_report('ip', '8.8.8.8', tracker_result())
        second = rb.build_report('ip', '8.8.8.8', tracker_result())
        assert first == second
        assert '2024-01-01 00:00 UTC' in first

    def test_result_none_runs_tracker_and_attaches_risk(self, monkeypatch):
        holder = {}

        class FakeTracker:
            def track(self, target):
                holder['target'] = target
                return tracker_result(target)

        monkeypatch.setattr(rb, 'import_module',
                            lambda name, package=None: SimpleNamespace(
                                IPTracker=FakeTracker))

        def fake_attach(kind, payload):
            holder['attach'] = (kind, payload['info']['ip'])
            payload['risk'] = {'score': 12, 'verdict': 'low', 'signals': [],
                               'summary': 'quiet'}

        monkeypatch.setattr('obscuralens.correlation.attach_risk', fake_attach)
        html = rb.build_report('ip', '8.8.8.8')
        assert holder['target'] == '8.8.8.8'
        assert holder['attach'] == ('ip', '8.8.8.8')
        assert '<span class="chip-value">12</span>' in html
        assert '<rect x="0" y="0" width="12" height="12"' in html

    def test_attach_risk_failure_is_suppressed(self, monkeypatch):
        class FakeTracker:
            def track(self, target):
                return tracker_result(target)

        monkeypatch.setattr(rb, 'import_module',
                            lambda name, package=None: SimpleNamespace(
                                IPTracker=FakeTracker))

        def boom(kind, payload):
            raise RuntimeError('scoring unavailable')

        monkeypatch.setattr('obscuralens.correlation.attach_risk', boom)
        html = rb.build_report('ip', '8.8.8.8')
        assert html.startswith('<!DOCTYPE html>')
        assert ('<span class="chip "><span class="chip-label">Risk</span>'
                '<span class="chip-value">—</span></span>') in html

    def test_non_dict_result_degrades_to_tracker_run(self, monkeypatch):
        monkeypatch.setattr(rb, '_run_tracker',
                            lambda kind, target: tracker_result(target))
        html = rb.build_report('ip', '8.8.8.8', result='junk')
        assert '<span class="chip-value">yes</span>' in html


class TestTargetOf:
    """_target_of picks the best identity key from a result section."""

    def test_kind_key_first(self):
        assert rb._target_of({'ip': '1.2.3.4'}, 'ip') == '1.2.3.4'

    @pytest.mark.parametrize('result, expected', [
        ({'value': 'x'}, 'x'),
        ({'target': 't'}, 't'),
        ({'address': 'a'}, 'a'),
        ({'email': 'e@x'}, 'e@x'),
        ({'domain': 'd'}, 'd'),
        ({'username': 'u'}, 'u'),
        ({'phone_number': 'p'}, 'p'),
        ({'cve': 'CVE-1'}, 'CVE-1'),
        ({'hash': 'abc'}, 'abc'),
        ({'url': 'https://x'}, 'https://x'),
    ])
    def test_generic_identity_keys(self, result, expected):
        assert rb._target_of(result, 'crypto') == expected

    def test_blank_and_non_string_values_skipped(self):
        assert rb._target_of({'ip': '   ', 'value': 'x'}, 'ip') == 'x'
        assert rb._target_of({'ip': 5, 'value': 'x'}, 'ip') == 'x'

    def test_non_dict_or_empty_falls_back_to_kind(self):
        assert rb._target_of('junk', 'ip') == 'ip'
        assert rb._target_of({}, 'ip') == 'ip'
        assert rb._target_of(None, 'crypto') == 'crypto'


# ------------------------------------------- build_investigation_report

class TestBuildInvestigationReport:
    """The pivot-graph dossier over a synthetic investigate() payload."""

    def test_full_document(self):
        html = rb.build_investigation_report('example.com', invest_payload())
        assert html.startswith('<!DOCTYPE html>')
        assert '<title>ObscuraLens · investigation · example.com</title>' in html
        assert '<span class="badge kind">domain</span>' in html
        assert '<span class="target mono">example.com</span>' in html
        assert 'Investigation with pivots · generated' in html
        assert html.rstrip().endswith('</html>')

    def test_summary_chips(self):
        html = rb.build_investigation_report('example.com', invest_payload())
        assert ('<span class="chip info"><span class="chip-label">Lookups</span>'
                '<span class="chip-value">2</span></span>') in html
        assert ('<span class="chip "><span class="chip-label">Entities</span>'
                '<span class="chip-value">3</span></span>') in html
        # every dict-shaped link counts for the chip (edge filtering happens
        # later, inside the graph renderer: 3 links -> 1 drawn edge)
        assert ('<span class="chip "><span class="chip-label">Relationships</span>'
                '<span class="chip-value">3</span></span>') in html
        assert ('<span class="chip "><span class="chip-label">Kinds</span>'
                '<span class="chip-value">3</span></span>') in html
        # one "ran" chip per kind in order; kinds missing from results dropped
        assert ('<span class="chip ok"><span class="chip-label">domain</span>'
                '<span class="chip-value">ran</span></span>') in html
        assert ('<span class="chip ok"><span class="chip-label">ip</span>'
                '<span class="chip-value">ran</span></span>') in html
        assert '<span class="chip-label">nope</span>' not in html

    def test_pivot_graph_panel(self):
        html = rb.build_investigation_report('example.com', invest_payload())
        assert '<h2>Pivot Graph</h2>' in html
        assert 'entity relationship graph, 3 nodes, 1 links' in html
        assert 'Deterministic layout' in html
        assert 'stroke="#f5a524" stroke-width="3.0"' in html

    def test_per_kind_sections_and_sources_appendix(self):
        html = rb.build_investigation_report('example.com', invest_payload())
        assert 'domain result' in html and 'ip result' in html
        assert '<small>example.com</small>' in html
        assert '<small>93.184.216.34</small>' in html
        assert ('<span class="chip bad"><span class="chip-label">Success</span>'
                '<span class="chip-value">no</span></span>') in html
        assert '<h2>Sources Appendix</h2>' in html
        assert 'Aggregated across every kind' in html
        assert '<span class="src">rdap</span>' in html
        assert '<span class="src">dns</span>' in html
        assert '<span class="src bad" title="http 500">ipwho.is</span>' in html

    def test_errors_panel(self):
        payload = dict(invest_payload(), errors=['pivot failed'])
        html = rb.build_investigation_report('example.com', payload)
        assert '<h2>Errors</h2>' in html
        assert '<li>pivot failed</li>' in html

    def test_empty_entities_render_the_note(self):
        payload = dict(invest_payload(), entities=[], links=[])
        html = rb.build_investigation_report('example.com', payload)
        assert 'No entities were derived from this investigation.' in html
        assert '<span class="chip-label">Kinds</span>' in html

    def test_payload_none_runs_the_investigation(self, monkeypatch):
        import obscuralens.investigate as investigate_module
        payload = invest_payload()
        monkeypatch.setattr(investigate_module, 'investigate', lambda target: payload)
        html = rb.build_investigation_report('example.com')
        assert '<span class="badge kind">domain</span>' in html
        assert 'domain result' in html

    def test_bad_payload_falls_back_to_running(self, monkeypatch):
        payload = invest_payload()
        monkeypatch.setattr(rb, '_run_investigate', lambda target: payload)
        html = rb.build_investigation_report('example.com', {'results': 'junk'})
        assert 'domain result' in html
        html = rb.build_investigation_report('example.com', 'junk')
        assert 'domain result' in html

    def test_order_defaults_to_result_kinds(self):
        payload = invest_payload()
        del payload['order']
        html = rb.build_investigation_report('example.com', payload)
        assert '<span class="chip-label">domain</span>' in html
        assert '<span class="chip-label">ip</span>' in html

    def test_junk_result_entries_are_skipped(self):
        payload = {'target': 'x', 'kind': 'domain', 'order': ['domain'],
                   'results': {'domain': 'junk'}, 'entities': [], 'links': [],
                   'errors': []}
        html = rb.build_investigation_report('x', payload)
        assert 'domain result <small>domain</small>' in html  # section renders
        assert 'No fields were returned for this target.' in html
        assert 'No source health recorded' in html  # skipped in the appendix too


# --------------------------------------------- build_history_report

class TestBuildHistoryReport:
    """The workspace analytics report over synthetic journal records."""

    def test_full_document(self):
        html = rb.build_history_report(HISTORY_RECORDS)
        assert html.startswith('<!DOCTYPE html>')
        assert '<title>ObscuraLens · history report</title>' in html
        assert '<span class="badge kind">history</span>' in html
        assert 'Stored lookup analytics' in html
        assert 'History report · generated' in html
        assert 'data never left this machine' in html
        assert '<h2>Lookups Over Time</h2>' in html
        assert '<h2>Kind Distribution</h2>' in html
        assert '<h2>Top Targets</h2>' in html

    def test_summary_chips(self):
        html = rb.build_history_report(HISTORY_RECORDS)
        assert ('<span class="chip info"><span class="chip-label">Lookups</span>'
                '<span class="chip-value">5</span></span>') in html
        assert ('<span class="chip "><span class="chip-label">Distinct targets</span>'
                '<span class="chip-value">3</span></span>') in html
        assert ('<span class="chip "><span class="chip-label">Kinds</span>'
                '<span class="chip-value">2</span></span>') in html
        assert '<span class="chip-value">2024-06-01</span>' in html  # first seen
        assert '<span class="chip-value">2024-06-03</span>' in html  # last seen

    def test_charts_and_legend(self):
        html = rb.build_history_report(HISTORY_RECORDS)
        assert '<svg class="spark"' in html    # sparkline over the day series
        assert '<svg class="chart"' in html    # per-day bar chart
        assert '<td>60.0%</td>' in html        # ip: 3 of 5 lookups
        assert 'class="donut-total">5</text>' in html
        assert 'peak ' in html and 'lookups on one day' in html

    def test_top_targets_table(self):
        html = rb.build_history_report(HISTORY_RECORDS)
        assert '<td class="mono">8.8.8.8</td>' in html
        assert '<td class="mono">example.com</td>' in html

    def test_pattern_of_life_highlights_with_night_ratio(self):
        records = [
            {'kind': 'ip', 'value': '9.9.9.9', 'timestamp': '2024-06-01T23:30:00Z'},
            {'kind': 'ip', 'value': '9.9.9.9', 'timestamp': '2024-06-02T02:00:00Z'},
            {'kind': 'ip', 'value': '9.9.9.9', 'timestamp': '2024-06-03T10:00:00Z'},
        ]
        html = rb.build_history_report(records)
        assert '<h2>Pattern-of-Life Highlights</h2>' in html
        assert '<td class="mono">9.9.9.9</td>' in html
        assert '0.667' in html  # 2 of 3 lookups in the 22:00-06:00 window

    def test_highlight_without_parseable_timestamps(self):
        # one parseable record keeps the day series alive; the highlighted
        # target's three unparseable timestamps yield no peak hour
        records = [{'kind': 'ip', 'value': 'x', 'timestamp': 'not-a-date'}] * 3
        records.append({'kind': 'domain', 'value': 'y',
                        'timestamp': '2024-06-01T10:00:00Z'})
        html = rb.build_history_report(records)
        assert 'Pattern-of-Life Highlights' in html
        assert '<td>&mdash;</td>' in html  # no peak hour without timestamps
        assert '<td>0.0</td>' in html      # night ratio degenerates to zero

    def test_history_with_only_unparseable_timestamps(self):
        # Fixed alongside part 6: records without a parseable timestamp
        # used to crash the report (empty shown_days -> IndexError).
        html = rb.build_history_report([{'kind': 'ip', 'value': 'x',
                                         'timestamp': 'not-a-date'}])
        assert 'No parseable timestamps' in html
        assert 'Kind Distribution' in html  # the rest of the report still renders

    def test_more_than_ninety_active_days_note(self):
        start = datetime(2023, 1, 1)
        records = [{'kind': 'ip', 'value': '8.8.8.8',
                    'timestamp': (start + timedelta(days=i)).isoformat()}
                   for i in range(95)]
        html = rb.build_history_report(records)
        assert 'Showing the most recent 90 of 95 active days.' in html
        assert 'bar chart of 90 values' in html

    def test_empty_history_renders_honest_note(self):
        html = rb.build_history_report([])
        assert 'Nothing has been recorded yet' in html
        assert '<h2>Lookups Over Time</h2>' in html
        assert 'Kind Distribution' not in html
        assert 'Top Targets' not in html
        assert '<span class="chip-value">—</span>' in html  # no first/last seen

    def test_records_none_loads_the_stored_journal(self, monkeypatch):
        from obscuralens.advanced import patterns
        monkeypatch.setattr(patterns, '_load_records', lambda: HISTORY_RECORDS)
        html = rb.build_history_report()
        assert '<td class="mono">8.8.8.8</td>' in html
        assert '<span class="chip-value">5</span>' in html

    def test_junk_records_tolerated(self):
        # non-dict entries are dropped by normalisation -> honest empty report
        html = rb.build_history_report(['junk', None, 42])
        assert html.startswith('<!DOCTYPE html>')
        assert 'Nothing has been recorded yet' in html
        # a dict without a timestamp still counts as a lookup
        html = rb.build_history_report([
            {'kind': 'ip'},
            {'kind': 'ip', 'value': 'v', 'timestamp': '2024-06-01T10:00:00Z'},
        ])
        assert '<span class="chip-value">2</span>' in html

    def test_deterministic_when_generated_stamp_fixed(self, monkeypatch):
        monkeypatch.setattr(rb, '_generated_text', lambda: '2024-01-01 00:00 UTC')
        first = rb.build_history_report(HISTORY_RECORDS)
        second = rb.build_history_report(HISTORY_RECORDS)
        assert first == second


# ------------------------------------------------------- output helpers

class TestSaveReport:
    """save_report writes UTF-8 and creates parent directories."""

    def test_creates_parent_directories(self, tmp_path):
        target = tmp_path / 'a' / 'b' / 'report.html'
        out = rb.save_report(str(target), '<html></html>')
        assert out == str(target)
        assert target.read_text(encoding='utf-8') == '<html></html>'

    def test_non_string_html_coerced(self, tmp_path):
        target = tmp_path / 'n.html'
        out = rb.save_report(str(target), 12345)
        assert out == str(target)
        assert target.read_text(encoding='utf-8') == '12345'

    def test_bare_filename_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert rb.save_report('plain.html', 'x') == 'plain.html'
        assert (tmp_path / 'plain.html').read_text(encoding='utf-8') == 'x'


class TestReportPath:
    """report_path sanitises kind/target into a timestamped filename."""

    def test_sanitises_kind_and_target(self, tmp_path):
        path = rb.report_path(' IP! ', '8.8.8.8/../../etc', base_dir=str(tmp_path))
        assert path.startswith(str(tmp_path) + '/')
        name = Path(path).name
        assert name.startswith('report_ip_')
        assert '/' not in name and '..' not in name and '!' not in name
        assert re.search(r'_\d{8}_\d{6}\.html$', name)
        assert tmp_path.is_dir()  # base directory created

    def test_long_target_capped_and_defaults(self, tmp_path):
        name = Path(rb.report_path('ip', 'a' * 80, base_dir=str(tmp_path))).name
        assert 'a' * 60 in name and 'a' * 61 not in name
        name = Path(rb.report_path('', '', base_dir=str(tmp_path))).name
        assert name.startswith('report_target_target_')

    def test_default_base_dir_from_config(self, tmp_path, monkeypatch):
        from obscuralens.config import config
        base = tmp_path / 'configured'
        monkeypatch.setattr(config.app_config, 'report_dir', str(base))
        path = rb.report_path('ip', '1.1.1.1')
        assert path.startswith(str(base) + '/')
        assert base.is_dir()

    def test_report_dir_none_falls_back_to_reports(self, tmp_path, monkeypatch):
        from obscuralens.config import config
        monkeypatch.setattr(config.app_config, 'report_dir', None)
        monkeypatch.chdir(tmp_path)
        path = rb.report_path('ip', '1.1.1.1')
        assert path.startswith('reports/report_ip_1.1.1.1_')
        assert (tmp_path / 'reports').is_dir()
