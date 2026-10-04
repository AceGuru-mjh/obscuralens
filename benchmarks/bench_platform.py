"""
Platform-surface benchmarks: the MCP tool registry and its offline tools,
the Python SDK's URL building / model parsing / session recording, report
section builders and Jinja template rendering, STIX/MISP export packing,
the plugin load cycle, shell completion generation, i18n translation
lookups and the SQLite history database.

Hermetic state, bench by bench:

* ``sdk`` benches talk to a :class:`~obscuralens.sdk.transport.StaticTransport`
  (an in-memory fake server) - zero network;
* ``plugins`` benches patch ``obscuralens.plugins.plugin_paths`` to the
  repository's ``plugins-examples/`` directory for the duration of the
  measurement (this is a benchmark, not a test, so the patch is applied by
  the setup function and documented here); teardown restores the original
  path resolver and rescans so global plugin registries return to their
  pre-bench state;
* ``i18n`` benches switch the active language and reset it in teardown;
* ``database`` benches construct a private
  :class:`~obscuralens.database.DatabaseManager` pointed at
  ``<workdir>/database/history.db`` (config paths are patched around the
  constructor and restored immediately, so nothing is ever written outside
  the workdir) and seed 500 synthetic rows in setup.

Register everything with :func:`build_benches` (consumed by
:mod:`benchmarks.run`).
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import obscuralens.plugins as plugins_pkg
from obscuralens.completion import (
    bash_completion,
    command_tree,
    fish_completion,
    zsh_completion,
)
from obscuralens.export.misp import build_misp_event
from obscuralens.export.stix import build_bundle
from obscuralens.i18n import reset as i18n_reset
from obscuralens.i18n import set_language, t
from obscuralens.mcp_server import TOOLS as MCP_TOOLS
from obscuralens.mcp_server import call_tool
from obscuralens.reporting.sections import (
    domain_sections,
    email_sections,
    ip_sections,
    phone_sections,
    username_sections,
)
from obscuralens.reporting.template_render import (
    render_markdown_report,
    render_standalone_html_report,
)
from obscuralens.sdk import (
    InvestigationReport,
    InvestigationSession,
    LookupResult,
    ObscuraLensClient,
    Response,
    StaticTransport,
)

from .harness import BenchSpec, state_dir

# --- fixed inputs ------------------------------------------------------------

#: Repository-relative examples directory used by the plugin load cycle.
PLUGIN_EXAMPLES = Path(__file__).resolve().parent.parent / 'plugins-examples'

#: Offline MCP data-pack lookups rotating across packs, keys and misses.
DATA_PACK_CALLS = (
    {'pack': 'country', 'key': 'US'},
    {'pack': 'country', 'key': 'DE'},
    {'pack': 'country', 'key': 'XX'},
    {'pack': 'port', 'key': 22},
    {'pack': 'port', 'key': 443},
    {'pack': 'cwe', 'key': 'CWE-79'},
    {'pack': 'http_status', 'key': 404},
    {'pack': 'http_status', 'key': 500},
)

#: Small numeric list for the analytics_stats MCP tool.
MCP_STAT_VALUES = [12, 4, 7, 19, 3, 11, 8, 15, 6, 9, 14, 5]

#: Synthetic tracker envelope: ~50 populated fields, 5 sources.
SECTION_INFO: Dict[str, Any] = {f'field_{i}': f'value-{i}' for i in range(48)}
SECTION_INFO.update({
    'ip': '8.8.8.8', 'domain': 'example.com', 'email': 'user@example.com',
    'country': 'United States', 'country_code': 'US', 'city': 'Mountain View',
    'asn': 'AS15169', 'org': 'Google LLC', 'ports': [53, 443, 8443],
    'latitude': 37.4056, 'longitude': -122.0775,
})
SECTION_ENV = {
    'ip': '8.8.8.8', 'domain': 'example.com', 'email': 'user@example.com',
    'username': 'some_user', 'phone': '+14155552671',
    'info': SECTION_INFO,
    'sources_ok': ['source_a', 'source_b', 'source_c', 'source_d', 'source_e'],
    'sources_failed': {'source_f': 'timeout after 30s'},
    'field_count': len(SECTION_INFO), 'success': True, 'elapsed': 0.31,
}

#: SDK lookup envelope (the shape GET /api/lookup/{kind}/{target} returns).
SDK_PAYLOAD: Dict[str, Any] = {
    'ip': '8.8.8.8', 'kind': 'ip', 'info': SECTION_INFO,
    'field_sources': {f'field_{i}': ['source_a', 'source_b'] for i in range(48)},
    'sources_ok': ['source_a', 'source_b', 'source_c', 'source_d', 'source_e'],
    'sources_failed': {}, 'field_count': 48, 'success': True, 'elapsed': 0.25,
}

#: SDK investigate payload: five per-kind results plus a small graph.
SDK_REPORT_PAYLOAD: Dict[str, Any] = {
    'target': '8.8.8.8', 'kind': 'ip', 'order': ['ip', 'domain', 'cve', 'hash', 'asn'],
    'results': {kind: dict(SDK_PAYLOAD, kind=kind)
                for kind in ('ip', 'domain', 'cve', 'hash', 'asn')},
    'entities': [{'type': 'ip', 'value': f'10.0.0.{i}', 'role': 'related'}
                 for i in range(20)],
    'links': [{'from': f'entity-{i}', 'to': f'entity-{(i + 1) % 20}',
               'label': 'related'} for i in range(20)],
    'errors': [],
}

#: Locales and keys exercised by the i18n bench (all shipped locales).
I18N_LOCALES = ('en', 'de', 'fr', 'es', 'ru', 'ja', 'zh')
I18N_KEYS = ('app.title', 'app.tagline', 'common.ok', 'common.cancel',
             'common.target', 'common.results')


# --- builder -----------------------------------------------------------------

def build_benches(workdir: Optional[str] = None) -> List[BenchSpec]:
    """
    Build every platform benchmark.

    Args:
        workdir: optional caller-owned directory for on-disk state (the
            database group); when None the group self-manages a tempdir
            that its teardown removes.

    Returns:
        :class:`~benchmarks.harness.BenchSpec` list, registration order.
    """
    specs: List[BenchSpec] = []
    specs.extend(_mcp_benches())
    specs.extend(_sdk_benches())
    specs.extend(_reporting_benches())
    specs.extend(_export_benches())
    specs.extend(_plugin_benches())
    specs.extend(_completion_benches())
    specs.extend(_i18n_benches())
    specs.extend(_database_benches(workdir))
    return specs


# --- MCP ---------------------------------------------------------------------

def _mcp_benches() -> List[BenchSpec]:
    """Tool-registry serialisation and the purely offline MCP tools."""

    def tools_json() -> None:
        payload = json.dumps(MCP_TOOLS)
        assert payload  # keep the result alive

    def encode() -> None:
        call_tool('tools_encode', {'text': 'benchmark payload text 0123456789'})

    def hash_id() -> None:
        call_tool('tools_hash_id',
                  {'hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'})

    def analytics_stats() -> None:
        call_tool('analytics_stats', {'values': MCP_STAT_VALUES})

    def data_packs() -> None:
        for arguments in DATA_PACK_CALLS:
            call_tool('data_pack_lookup', arguments)

    return [
        BenchSpec('mcp_tools_list_json', tools_json, repeat=5, number=100,
                  tags=('platform', 'mcp')),
        BenchSpec('mcp_tools_encode', encode, repeat=5, number=10,
                  tags=('platform', 'mcp')),
        BenchSpec('mcp_tools_hash_id', hash_id, repeat=5, number=50,
                  tags=('platform', 'mcp')),
        BenchSpec('mcp_analytics_stats', analytics_stats, repeat=5, number=100,
                  tags=('platform', 'mcp')),
        BenchSpec('mcp_data_pack_lookup', data_packs, repeat=5, number=10,
                  tags=('platform', 'mcp')),
    ]


# --- SDK ---------------------------------------------------------------------

def _sdk_benches() -> List[BenchSpec]:
    """
    URL building, model parsing and session step recording.

    The client is constructed over an empty :class:`StaticTransport`, so
    nothing leaves memory; the session bench scripts one canned 200
    response with ``repeat_last`` so 200 recorded steps replay offline.
    """
    client = ObscuraLensClient(transport=StaticTransport([]))

    def build_urls() -> None:
        for i in range(500):
            path = client._path('/api/lookup/{}/{}', 'ip', f'8.8.4.{i % 256}')
            client._build_url(path, {'verbose': 'true', 'missing': None})

    def parse_lookup() -> None:
        for _ in range(100):
            LookupResult.from_dict(SDK_PAYLOAD, kind='ip')

    def parse_report() -> None:
        for _ in range(20):
            InvestigationReport.from_dict(SDK_REPORT_PAYLOAD)

    def make_session() -> InvestigationSession:
        response = Response.from_json(200, dict(SDK_PAYLOAD))
        transport = StaticTransport([response], repeat_last=True)
        return InvestigationSession(ObscuraLensClient(transport=transport), 'bench')

    def session_steps() -> None:
        session = make_session()
        for i in range(200):
            session.lookup('ip', f'8.8.8.{i % 256}')

    return [
        BenchSpec('sdk_build_url', build_urls, repeat=5, number=10,
                  tags=('platform', 'sdk')),
        BenchSpec('sdk_lookup_result_from_dict', parse_lookup, repeat=5, number=10,
                  tags=('platform', 'sdk')),
        BenchSpec('sdk_investigation_report_from_dict', parse_report, repeat=5,
                  number=10, tags=('platform', 'sdk')),
        BenchSpec('sdk_session_200_steps', session_steps, repeat=3, number=1,
                  tags=('platform', 'sdk')),
    ]


# --- reporting ---------------------------------------------------------------

def _reporting_benches() -> List[BenchSpec]:
    """Section builders over a synthetic envelope plus Jinja rendering."""

    def sections() -> None:
        ip_sections(SECTION_ENV)
        domain_sections(SECTION_ENV)
        email_sections(SECTION_ENV)
        phone_sections(SECTION_ENV)
        username_sections(SECTION_ENV)

    def render_md() -> None:
        render_markdown_report(ip_sections(SECTION_ENV), {'title': 'bench'})

    def render_html() -> None:
        render_standalone_html_report(ip_sections(SECTION_ENV), {'title': 'bench'})

    return [
        BenchSpec('reporting_sections_all_kinds', sections, repeat=5, number=50,
                  tags=('platform', 'reporting')),
        BenchSpec('reporting_render_markdown', render_md, repeat=5, number=10,
                  tags=('platform', 'reporting')),
        BenchSpec('reporting_render_standalone_html', render_html, repeat=5,
                  number=10, tags=('platform', 'reporting')),
    ]


# --- export ------------------------------------------------------------------

def _export_benches() -> List[BenchSpec]:
    """STIX bundle and MISP core-format event packing."""

    def stix() -> None:
        build_bundle('ip', '8.8.8.8', SECTION_ENV)

    def misp() -> None:
        build_misp_event('ip', '8.8.8.8', SECTION_ENV)

    return [
        BenchSpec('export_stix_bundle', stix, repeat=5, number=50,
                  tags=('platform', 'export')),
        BenchSpec('export_misp_event', misp, repeat=5, number=50,
                  tags=('platform', 'export')),
    ]


# --- plugins -----------------------------------------------------------------

def _plugin_benches() -> List[BenchSpec]:
    """
    Full load cycle of the three plugins-examples plugins.

    The setup function patches ``obscuralens.plugins.plugin_paths`` to
    return ``plugins-examples/`` (a benchmark-side reroute, not a test
    monkeypatch); the measured function force-reloads the plugins and
    extracts the merged v2 surface (commands, report sections, tools,
    analytics, manifests); teardown restores the original resolver and
    rescans so no plugin state leaks out of the benchmark.
    """
    state: Dict[str, Any] = {}

    def setup() -> None:
        state['original'] = plugins_pkg.plugin_paths
        plugins_pkg.plugin_paths = lambda: [PLUGIN_EXAMPLES]  # type: ignore[assignment]

    def teardown() -> None:
        original = state.pop('original', None)
        if original is not None:
            plugins_pkg.plugin_paths = original  # type: ignore[assignment]
        plugins_pkg.load_plugins(force=True)

    def load_cycle() -> None:
        infos = plugins_pkg.load_plugins(force=True)
        assert len(infos) == 3
        plugins_pkg.plugin_commands()
        plugins_pkg.plugin_report_sections()
        plugins_pkg.plugin_tools()
        plugins_pkg.plugin_analytics()
        plugins_pkg.plugin_meta_list()

    return [BenchSpec('plugins_load_cycle', load_cycle, repeat=3, number=1,
                      tags=('platform', 'plugins'), setup=setup,
                      teardown=teardown)]


# --- completion --------------------------------------------------------------

def _completion_benches() -> List[BenchSpec]:
    """CLI command-tree walk and the three shell script generators."""

    def tree() -> None:
        command_tree()

    def bash() -> None:
        bash_completion()

    def zsh() -> None:
        zsh_completion()

    def fish() -> None:
        fish_completion()

    return [
        BenchSpec('completion_command_tree', tree, repeat=3, number=1,
                  tags=('platform', 'completion')),
        BenchSpec('completion_bash', bash, repeat=3, number=1,
                  tags=('platform', 'completion')),
        BenchSpec('completion_zsh', zsh, repeat=3, number=1,
                  tags=('platform', 'completion')),
        BenchSpec('completion_fish', fish, repeat=3, number=1,
                  tags=('platform', 'completion')),
    ]


# --- i18n --------------------------------------------------------------------

def _i18n_benches() -> List[BenchSpec]:
    """
    Translation lookups across locales.

    The measured function activates every locale in :data:`I18N_LOCALES`
    and resolves :data:`I18N_KEYS` (plus one interpolated key) in each;
    teardown calls :func:`obscuralens.i18n.reset` so the active language
    returns to the import-time default.
    """

    def translate() -> None:
        for locale in I18N_LOCALES:
            set_language(locale)
            for key in I18N_KEYS:
                t(key, default=key)
            t('app.version', version='6.2.0')

    return [BenchSpec('i18n_translations_7locales', translate, repeat=5,
                      number=20, teardown=i18n_reset, tags=('platform', 'i18n'))]


# --- database ----------------------------------------------------------------

def _database_benches(workdir: Optional[str]) -> List[BenchSpec]:
    """
    History reads against a private, seeded temp database.

    Setup reroutes ``config.db_config.sqlite_path`` (and the two
    save-history flags) to a workdir-local file for the duration of the
    constructor call and seeding, then restores every value; the bench
    itself only ever reads.  500 synthetic rows are inserted once, so the
    measured ``get_history`` calls hit a realistic result-set size.
    """
    from obscuralens.config import config
    from obscuralens.database import DatabaseManager

    state: Dict[str, Any] = {}

    def setup() -> None:
        path, cleanup = state_dir(workdir, 'database')
        state['cleanup'] = cleanup
        state['old_sqlite'] = config.db_config.sqlite_path
        state['old_save'] = config.app_config.save_history
        state['old_cap'] = config.app_config.max_history_entries
        config.db_config.sqlite_path = str(path / 'history.db')
        config.app_config.save_history = True
        config.app_config.max_history_entries = 10000
        try:
            manager = DatabaseManager()
            payload = {'info': {f'field_{i}': i for i in range(20)},
                       'sources_ok': ['source_a', 'source_b']}
            for i in range(500):
                manager.save_query('bench', f'93.184.216.{i % 256}', payload,
                                   success=i % 25 != 0,
                                   error_message='' if i % 25 != 0 else 'source timeout')
            state['manager'] = manager
        finally:
            config.db_config.sqlite_path = state['old_sqlite']
            config.app_config.save_history = state['old_save']
            config.app_config.max_history_entries = state['old_cap']

    def teardown() -> None:
        state.pop('manager', None)
        cleanup = state.pop('cleanup', None)
        if cleanup is not None:
            cleanup()

    def read_history() -> None:
        manager = state['manager']
        rows = manager.get_history(limit=500)
        assert len(rows) == 500

    return [BenchSpec('database_get_history_500', read_history, repeat=5,
                      number=20, tags=('platform', 'database'), setup=setup,
                      teardown=teardown)]


__all__ = ['build_benches']
