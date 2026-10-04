"""
Offline tests for the Jinja2 report templates (reporting.template_render).

Covers template discovery and the shared environment, rendering of the three
shipped templates (standalone HTML, Markdown, executive summary) with a
realistic sections/meta context, the esc / nl2br / fmt_date / fmt_pct
filters, the friendly ``TemplateNotFound`` error, and the defensive
normalisation performed by the ``render_standalone_html_report`` /
``render_markdown_report`` convenience wrappers.

Everything runs offline; no files are written outside ``tmp_path``-free
in-memory rendering.
"""

from datetime import date, datetime

import pytest
from jinja2 import TemplateNotFound

from obscuralens import __version__ as PACKAGE_VERSION
from obscuralens.reporting import template_render as tr

TEMPLATE_NAMES = ('report.md.j2', 'standalone_report.html.j2', 'summary.html.j2')

SECTIONS = [
    {
        'title': 'Domain Posture',
        'rows': [
            ['Field', 'Value'],
            ['Registrar', 'Example Inc'],
            ['Registrar URL', 'https://registrar.example'],
            ['Note', 'has a | pipe'],
        ],
        'notes': 'Two\nlines of notes',
    },
    {
        'title': 'Risk Signals',
        'rows': [
            ['Signal', 'Weight'],
            ['Very young domain', '20'],
            ['No DMARC policy', '10'],
        ],
        'notes': '',
    },
    {
        'title': 'Empty Section',
        'rows': [],
        'notes': 'only notes here',
    },
]

META = {
    'title': 'ObscuraLens Report',
    'target': 'example.com',
    'kind': 'domain',
    'version': '5.1.0',
    'generated': '2026-01-01T12:00:00Z',
    'channel': 'beta',
    'band': 'high',
    'score': 72,
    'top_signals': ['very young domain', 'no DMARC policy'],
}

SUMMARY_META = dict(META, source_health=[
    ['Source', 'Status', 'Detail'],
    ['rdap', 'ok', '3 fields'],
    ['dns', 'failed', 'timeout'],
])


@pytest.fixture()
def rendered_html():
    return tr.render_standalone_html_report(SECTIONS, META)


@pytest.fixture()
def rendered_md():
    return tr.render_markdown_report(SECTIONS, META)


@pytest.fixture()
def rendered_summary():
    return tr.render_template('summary.html.j2', sections=SECTIONS, meta=SUMMARY_META)


# --------------------------------------------------------------------------- #
# discovery + environment
# --------------------------------------------------------------------------- #

class TestTemplateDiscovery:

    def test_available_templates_contains_the_three_names(self):
        names = tr.available_templates()
        assert set(names) == set(TEMPLATE_NAMES)
        assert len(names) == 3

    def test_available_templates_is_sorted(self):
        assert tr.available_templates() == sorted(tr.available_templates())

    def test_templates_dir_holds_the_files(self):
        assert tr.TEMPLATES_DIR.is_dir()
        for name in TEMPLATE_NAMES:
            assert (tr.TEMPLATES_DIR / name).is_file()

    def test_template_env_is_cached(self):
        assert tr.template_env() is tr.template_env()

    def test_filters_are_installed(self):
        env = tr.template_env()
        assert env.filters['esc'] is tr.esc
        assert env.filters['nl2br'] is tr.nl2br
        assert env.filters['fmt_date'] is tr.fmt_date
        assert env.filters['fmt_pct'] is tr.fmt_pct

    def test_environment_flags(self):
        env = tr.template_env()
        assert env.autoescape is False      # trusted templates + explicit |esc
        assert env.trim_blocks is True
        assert env.lstrip_blocks is True

    @pytest.mark.parametrize('name', TEMPLATE_NAMES)
    def test_each_template_renders_non_empty_string(self, name):
        rendered = tr.render_template(name, sections=SECTIONS, meta=META)
        assert isinstance(rendered, str)
        assert rendered.strip()


# --------------------------------------------------------------------------- #
# standalone HTML report
# --------------------------------------------------------------------------- #

class TestStandaloneHtmlReport:

    def test_starts_with_doctype_and_html_tag(self, rendered_html):
        assert rendered_html.lstrip().startswith('<!DOCTYPE html>')
        assert '<html lang="en">' in rendered_html

    def test_contains_target_and_section_titles(self, rendered_html):
        assert 'example.com' in rendered_html
        for title in ('Domain Posture', 'Risk Signals', 'Empty Section'):
            assert title in rendered_html

    def test_contains_inline_css_and_version(self, rendered_html):
        assert '<style>' in rendered_html
        assert 'v5.1.0' in rendered_html
        assert 'ObscuraLens v5.1.0' in rendered_html

    def test_contains_table_headers_and_cells(self, rendered_html):
        assert '<th scope="col">Field</th>' in rendered_html
        assert '<td>Example Inc</td>' in rendered_html
        assert '4 row(s)' in rendered_html

    def test_section_indexes_are_sequential(self, rendered_html):
        assert 'S1' in rendered_html
        assert 'S2' in rendered_html

    def test_notes_use_nl2br(self, rendered_html):
        assert 'Two<br>' in rendered_html
        assert 'lines of notes' in rendered_html

    def test_values_are_html_escaped(self):
        sections = [{'title': 'XSS', 'rows': [['F', 'V'], ['a', '<script>alert(1)</script>']],
                     'notes': ''}]
        html = tr.render_standalone_html_report(sections, META)
        assert '&lt;script&gt;' in html
        assert '<script>' not in html

    def test_section_without_rows_renders_empty_state(self, rendered_html):
        assert 'No rows were collected for this section.' in rendered_html

    def test_band_and_score_are_rendered(self, rendered_html):
        assert 'is-active active-high' in rendered_html
        assert 'aria-label="Risk band high (score 72)"' in rendered_html
        assert 'Rule score:' in rendered_html
        assert '<strong>72</strong>' in rendered_html

    def test_top_signals_are_listed(self, rendered_html):
        assert 'Top Signals' in rendered_html
        assert '<li>very young domain</li>' in rendered_html
        assert '<li>no DMARC policy</li>' in rendered_html

    def test_channel_appears_in_footer(self, rendered_html):
        assert '(beta channel)' in rendered_html
        assert 'Generated by' in rendered_html

    def test_table_of_contents_lists_sections(self, rendered_html):
        assert 'Contents' in rendered_html
        assert '<a href="#sec-1">Domain Posture</a>' in rendered_html

    def test_empty_sections_list_still_renders_document(self):
        html = tr.render_standalone_html_report([], META)
        assert html.lstrip().startswith('<!DOCTYPE html>')
        assert 'No sections' in html
        assert '<style>' in html

    def test_meta_without_band_hides_band_strip(self):
        meta = dict(META)
        del meta['band']
        html = tr.render_standalone_html_report(SECTIONS, meta)
        # The CSS block mentions the classes; the rendered elements must go.
        assert 'aria-label="Risk band' not in html
        assert 'Rule score:' not in html
        assert 'is-active active-' not in html


# --------------------------------------------------------------------------- #
# Markdown report
# --------------------------------------------------------------------------- #

class TestMarkdownReport:

    def test_starts_with_title_heading(self, rendered_md):
        assert rendered_md.startswith('# ObscuraLens Report')

    def test_contains_meta_values(self, rendered_md):
        assert '**ObscuraLens OSINT report**' in rendered_md
        assert 'kind: `domain`' in rendered_md
        assert 'channel: `beta`' in rendered_md
        assert '- **Target:** `example.com`' in rendered_md
        assert '- **Engine:** ObscuraLens v5.1.0' in rendered_md
        assert '- **Generated:** 2026-01-01 12:00 UTC' in rendered_md

    def test_contains_risk_band_with_score(self, rendered_md):
        assert '- **Risk band:** **high** (rule score 72/100)' in rendered_md

    def test_contains_top_signal_bullets(self, rendered_md):
        assert '- **Top signals:**' in rendered_md
        assert '  - very young domain' in rendered_md
        assert '  - no DMARC policy' in rendered_md

    def test_contains_contents_list_and_section_headings(self, rendered_md):
        assert '## Contents' in rendered_md
        assert '1. [Domain Posture]' in rendered_md
        assert '## Domain Posture' in rendered_md
        assert '## Risk Signals' in rendered_md

    def test_contains_pipe_table_rows(self, rendered_md):
        assert '| Field | Value |' in rendered_md
        assert '| --- | --- |' in rendered_md
        assert '| Registrar | Example Inc |' in rendered_md

    def test_pipe_characters_in_cells_are_escaped(self, rendered_md):
        assert 'has a \\| pipe' in rendered_md
        assert 'has a | pipe' not in rendered_md

    def test_newlines_in_cells_collapse_to_spaces(self):
        sections = [{'title': 'Multi', 'rows': [['F', 'V'], ['cell', 'multi\nline']],
                     'notes': ''}]
        md = tr.render_markdown_report(sections, META)
        assert '| cell | multi line |' in md

    def test_html_is_not_escaped_in_markdown_cells(self):
        sections = [{'title': 'Raw', 'rows': [['F', 'V'], ['a', '<b>bold</b>']],
                     'notes': ''}]
        md = tr.render_markdown_report(sections, META)
        assert '<b>bold</b>' in md

    def test_notes_render_as_blockquote(self, rendered_md):
        assert '> Two' in rendered_md
        assert '> lines of notes' in rendered_md

    def test_section_without_rows_uses_placeholder(self, rendered_md):
        assert '_(no rows collected)_' in rendered_md

    def test_empty_sections_list_renders_placeholder(self):
        md = tr.render_markdown_report([], META)
        assert '## No sections' in md
        assert 'This report contains no data sections.' in md

    def test_footer_mentions_engine_version(self, rendered_md):
        assert f'Generated by ObscuraLens v{META["version"]}' in rendered_md


# --------------------------------------------------------------------------- #
# executive summary card
# --------------------------------------------------------------------------- #

class TestSummaryCard:

    def test_renders_self_contained_html_document(self, rendered_summary):
        assert rendered_summary.lstrip().startswith('<!DOCTYPE html>')
        assert '<style>' in rendered_summary
        assert '</html>' in rendered_summary

    def test_contains_target_kind_and_band(self, rendered_summary):
        assert 'example.com' in rendered_summary
        assert 'domain' in rendered_summary
        assert 'band-chip high' in rendered_summary
        assert '72/100' in rendered_summary

    def test_contains_top_signals(self, rendered_summary):
        assert '<li>very young domain</li>' in rendered_summary
        assert '<li>no DMARC policy</li>' in rendered_summary

    def test_contains_source_health_table(self, rendered_summary):
        assert 'Source health' in rendered_summary
        assert 'rdap' in rendered_summary
        assert 'timeout' in rendered_summary

    def test_contains_version_and_disclaimer(self, rendered_summary):
        assert 'v5.1.0' in rendered_summary
        assert 'heuristics, not verdicts' in rendered_summary

    def test_band_is_required_for_the_chip(self):
        meta = dict(META)
        del meta['band']
        summary = tr.render_template('summary.html.j2', sections=SECTIONS, meta=meta)
        # The CSS block always mentions .band-chip; the element itself must go.
        assert '<span class="band-chip' not in summary
        assert 'band-chip high' not in summary

    def test_score_is_optional(self):
        meta = {'title': 'T', 'target': 'example.com', 'version': '5.1.0',
                'generated': '2026-01-01T12:00:00Z', 'band': 'watch'}
        summary = tr.render_template('summary.html.j2', sections=[], meta=meta)
        assert 'band-chip watch' in summary
        # The progress bar is guarded with "is defined" and stays hidden.
        assert 'role="progressbar"' not in summary

    def test_renders_with_empty_sections(self):
        summary = tr.render_template('summary.html.j2', sections=[], meta=SUMMARY_META)
        assert 'example.com' in summary


# --------------------------------------------------------------------------- #
# filters
# --------------------------------------------------------------------------- #

class TestFilters:

    def test_esc_escapes_html(self):
        assert tr.esc('<b>&"x"') == '&lt;b&gt;&amp;&quot;x&quot;'
        assert tr.esc("a'b") == 'a&#x27;b'

    def test_esc_none_and_non_strings(self):
        assert tr.esc(None) == ''
        assert tr.esc(42) == '42'
        assert tr.esc(1.5) == '1.5'

    def test_nl2br_converts_newlines(self):
        assert tr.nl2br('a\nb') == 'a<br>\nb'
        assert tr.nl2br('a\r\nb') == 'a<br>\nb'
        assert tr.nl2br('a\rb') == 'a<br>\nb'

    def test_nl2br_escapes_before_converting(self):
        assert tr.nl2br('<x>\ny') == '&lt;x&gt;<br>\ny'

    def test_fmt_pct_converts_fractions_and_percentages(self):
        assert tr.fmt_pct(0.123) == '12.3%'
        assert tr.fmt_pct(12.3) == '12.3%'
        assert tr.fmt_pct(1.0) == '100.0%'
        assert tr.fmt_pct(0) == '0.0%'
        assert tr.fmt_pct(-0.5) == '-50.0%'
        assert tr.fmt_pct(0.5, 0) == '50%'
        assert tr.fmt_pct('0.25') == '25.0%'

    def test_fmt_pct_rejects_junk(self):
        assert tr.fmt_pct('junk') == ''
        assert tr.fmt_pct(None) == ''
        assert tr.fmt_pct(True) == ''

    def test_fmt_date_parses_iso_strings(self):
        assert tr.fmt_date('2026-01-01T12:00:00Z') == '2026-01-01 12:00 UTC'
        assert tr.fmt_date('2026-01-01 12:00:00') == '2026-01-01 12:00 UTC'
        assert tr.fmt_date('2026-01-01') == '2026-01-01 00:00 UTC'

    def test_fmt_date_accepts_datetime_and_date_objects(self):
        assert tr.fmt_date(datetime(2026, 1, 1, 12, 0)) == '2026-01-01 12:00 UTC'
        assert tr.fmt_date(date(2026, 1, 1)) == '2026-01-01 00:00 UTC'

    def test_fmt_date_returns_unparseable_values_verbatim(self):
        assert tr.fmt_date('junk') == 'junk'
        assert tr.fmt_date('half-formed 42') == 'half-formed 42'
        assert tr.fmt_date(None) == ''

    def test_fmt_date_honours_custom_format(self):
        assert tr.fmt_date('2026-01-01T12:00:00Z', fmt='%Y') == '2026'


# --------------------------------------------------------------------------- #
# render_template error handling
# --------------------------------------------------------------------------- #

class TestRenderTemplateErrors:

    def test_unknown_template_raises_with_available_list(self):
        with pytest.raises(TemplateNotFound) as excinfo:
            tr.render_template('nope.j2')
        message = str(excinfo.value)
        for name in TEMPLATE_NAMES:
            assert name in message
        assert 'nope.j2' in message

    def test_unknown_template_without_extension_also_raises(self):
        with pytest.raises(TemplateNotFound):
            tr.render_template('nope')

    def test_name_without_extension_is_retried(self):
        direct = tr.render_template('report.md.j2', sections=SECTIONS, meta=META)
        without_ext = tr.render_template('report.md', sections=SECTIONS, meta=META)
        assert without_ext == direct

    def test_summary_renders_without_extension(self):
        summary = tr.render_template('summary.html', sections=[], meta=SUMMARY_META)
        assert 'example.com' in summary


# --------------------------------------------------------------------------- #
# convenience wrappers + context normalisation
# --------------------------------------------------------------------------- #

class TestConvenienceWrappers:

    def test_render_standalone_html_report_returns_string(self):
        html = tr.render_standalone_html_report(SECTIONS, META)
        assert isinstance(html, str)
        assert 'Domain Posture' in html
        assert 'example.com' in html

    def test_render_markdown_report_returns_string(self):
        md = tr.render_markdown_report(SECTIONS, META)
        assert isinstance(md, str)
        assert '# ObscuraLens Report' in md

    def test_meta_none_uses_documented_defaults(self):
        html = tr.render_standalone_html_report(SECTIONS, None)
        assert 'ObscuraLens Report' in html
        assert f'v{PACKAGE_VERSION}' in html
        assert 'Generated by' in html

    def test_partial_meta_gets_defaults(self):
        html = tr.render_standalone_html_report(SECTIONS, {'target': 'example.com'})
        assert 'ObscuraLens Report' in html
        assert 'example.com' in html
        assert f'v{PACKAGE_VERSION}' in html

    def test_sections_none_renders_placeholders(self):
        html = tr.render_standalone_html_report(None, META)
        md = tr.render_markdown_report(None, META)
        assert 'No sections' in html
        assert '## No sections' in md

    def test_non_dict_section_entries_are_skipped(self):
        sections = [None, 'just a string', 42,
                    {'title': 'Only Good', 'rows': [['H'], ['a']]}]
        html = tr.render_standalone_html_report(sections, META)
        assert 'Only Good' in html
        md = tr.render_markdown_report(sections, META)
        assert '## Only Good' in md
        assert 'just a string' not in md

    def test_section_without_title_is_untitled(self):
        html = tr.render_standalone_html_report([{'rows': [['H']]}], META)
        assert '(untitled)' in html

    def test_scalar_rows_become_single_cell_rows(self):
        sections = [{'title': 'S', 'rows': [['Header'], 'plain-value']}]
        html = tr.render_standalone_html_report(sections, META)
        assert '<td>plain-value</td>' in html
        md = tr.render_markdown_report(sections, META)
        assert '| plain-value |' in md

    def test_none_cells_become_empty_strings(self):
        sections = [{'title': 'S', 'rows': [['F', 'V'], ['a', None]]}]
        html = tr.render_standalone_html_report(sections, META)
        assert '<td></td>' in html
        md = tr.render_markdown_report(sections, META)
        assert '| a |  |' in md

    def test_section_without_notes_has_no_notes_paragraph(self):
        html = tr.render_standalone_html_report(
            [{'title': 'S', 'rows': [['F'], ['v']]}], META)
        assert 'class="notes"' not in html

    def test_extra_meta_keys_are_passed_through(self):
        meta = dict(META, custom_key='custom-value')
        html = tr.render_standalone_html_report(SECTIONS, meta)
        assert 'Domain Posture' in html  # still renders fine with extras
        summary = tr.render_template('summary.html.j2', sections=[], meta=meta)
        assert 'example.com' in summary

class TestResolveTemplateName:
    """Name resolution: exact, +.j2, and unique-prefix matching."""

    def test_exact_name_resolves(self):
        for name in TEMPLATE_NAMES:
            assert tr.resolve_template_name(name) == name

    def test_suffixless_name_gets_j2_appended(self):
        assert tr.resolve_template_name('report.md') == 'report.md.j2'

    def test_unique_prefix_resolves_to_full_filename(self):
        # The CLI user types `standalone_report`, not the full file name.
        assert tr.resolve_template_name('standalone_report') == \
            'standalone_report.html.j2'
        assert tr.resolve_template_name('summary') == 'summary.html.j2'

    def test_unknown_name_resolves_to_none(self):
        assert tr.resolve_template_name('nope') is None
        assert tr.resolve_template_name('') is None

    def test_ambiguous_prefix_resolves_to_none(self):
        # `report` is a prefix of exactly one shipped template, but a
        # hypothetical second one must not silently pick a winner.
        monkey = tr.available_templates
        try:
            tr.available_templates = lambda: ['report.md.j2', 'report.html.j2']
            assert tr.resolve_template_name('report') is None
        finally:
            tr.available_templates = monkey


class TestSectionRowAdaptation:
    """The templates want a header row first; our builders do not emit one."""

    def test_columns_become_the_header_row(self):
        sections = tr._normalize_sections([
            {'title': 'Sources Queried', 'type': 'table',
             'columns': ['Source', 'Status'],
             'rows': [['ipinfo.io', 'ok'], ['rdap.arin.net', 'ok']]},
        ])
        assert sections[0]['rows'][0] == ['Source', 'Status']
        assert len(sections[0]['rows']) == 3  # header + 2 body rows

    def test_already_headered_rows_do_not_gain_a_duplicate(self):
        sections = tr._normalize_sections([
            {'title': 'T', 'type': 'table', 'columns': ['A', 'B'],
             'rows': [['A', 'B'], ['1', '2']]},
        ])
        assert sections[0]['rows'] == [['A', 'B'], ['1', '2']]

    def test_grid_data_becomes_a_field_value_table(self):
        sections = tr._normalize_sections([
            {'title': 'Summary', 'type': 'grid',
             'data': {'Registrar': 'Example Inc', 'Created': '1995-08-14'}},
        ])
        rows = sections[0]['rows']
        assert rows[0] == ['Field', 'Value']
        assert ['Registrar', 'Example Inc'] in rows

    def test_section_with_neither_shape_yields_no_rows(self):
        sections = tr._normalize_sections([
            {'title': 'Empty', 'type': 'grid', 'data': 'not-a-dict'},
        ])
        assert sections[0]['rows'] == []

    def test_rendered_html_contains_the_column_headers(self):
        html = tr.render_standalone_html_report([
            {'title': 'Sources Queried', 'type': 'table',
             'columns': ['Source', 'Status'], 'rows': [['ipinfo.io', 'ok']]},
        ], META)
        assert 'Source' in html and 'Status' in html and 'ipinfo.io' in html


class TestRenderReport:
    """render_report(): the CLI --template entry point."""

    SECTIONS = [{'title': 'T', 'type': 'table', 'columns': ['A'],
                 'rows': [['1']]}]

    def test_builds_meta_from_lookup_arguments(self):
        html = tr.render_report('standalone_report', sections=self.SECTIONS,
                                title='IP Report - 8.8.8.8', kind='ip',
                                target='8.8.8.8')
        assert '8.8.8.8' in html
        assert PACKAGE_VERSION in html

    def test_risk_band_is_mapped_from_the_verdict(self):
        for verdict, band in (('clean', 'clean'), ('low', 'watch'),
                              ('medium', 'elevated'), ('high', 'high'),
                              ('critical', 'critical')):
            html = tr.render_report(
                'standalone_report', sections=self.SECTIONS,
                risk={'score': 42, 'verdict': verdict,
                      'signals': [{'label': 's'}]})
            assert f'active-{band}' in html, verdict

    def test_unknown_verdict_claims_no_band(self):
        html = tr.render_report('standalone_report', sections=self.SECTIONS,
                                risk={'score': 0, 'verdict': 'unknown',
                                      'signals': []})
        assert 'band-seg is-active' not in html

    def test_explicit_meta_band_wins_over_the_risk_verdict(self):
        html = tr.render_report('standalone_report', sections=self.SECTIONS,
                                meta={'band': 'critical'},
                                risk={'score': 1, 'verdict': 'clean',
                                      'signals': []})
        assert 'active-critical' in html

    def test_top_signals_reach_the_summary_card(self):
        html = tr.render_report(
            'summary', sections=self.SECTIONS,
            risk={'score': 70, 'verdict': 'high',
                  'signals': [{'label': 'Tor exit node'},
                              {'label': 'Known scanner'}]})
        assert 'Tor exit node' in html and 'Known scanner' in html

    def test_rendered_documents_are_not_empty(self):
        for name in TEMPLATE_NAMES:
            out = tr.render_report(name, sections=self.SECTIONS,
                                   title='T', kind='ip', target='1.1.1.1')
            assert out.strip(), name

    def test_bad_name_still_raises_with_the_catalogue(self):
        with pytest.raises(TemplateNotFound) as excinfo:
            tr.render_report('does-not-exist', sections=self.SECTIONS)
        assert 'available templates' in str(excinfo.value)
