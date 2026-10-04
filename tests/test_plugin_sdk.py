"""Plugin SDK v2 tests: contracts, loader evolution, examples, CLI wiring.

All tests are fully offline: plugin files are written into ``tmp_path``
directories and the loader is pointed at them with the same monkeypatch
pattern the v1 suite uses. The three shipped example plugins in
``plugins-examples/`` are loaded through the real loader.
"""

import sys
import textwrap
from pathlib import Path

import pytest

from obscuralens import commands, plugins
from obscuralens.config import config
from obscuralens.plugins import (
    SUPPORTED_PLUGIN_API,
    PluginContext,
    PluginMeta,
    build_plugin_argument_parser,
    validate_plugin_file,
)
from obscuralens.plugins.contracts import extract_plugin_surface

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / 'plugins-examples'


def _write(directory: Path, filename: str, body: str) -> Path:
    """Create a plugin file with dedented source text."""
    path = directory / filename
    path.write_text(textwrap.dedent(body), encoding='utf-8')
    return path


@pytest.fixture()
def plugin_dirs(tmp_path, monkeypatch):
    """Two fake plugin directories, pointed at by the real loader."""
    project = tmp_path / 'project' / 'plugins'
    user = tmp_path / 'user' / 'plugins'
    project.mkdir(parents=True)
    user.mkdir(parents=True)

    monkeypatch.setattr(plugins, 'plugin_paths', lambda: [project, user])
    monkeypatch.setattr(config.app_config, 'enable_plugins', True, raising=False)
    plugins.load_plugins(force=True)
    return project, user


@pytest.fixture()
def examples_dir(monkeypatch):
    """Point the loader at the shipped plugins-examples/ directory."""
    assert EXAMPLES_DIR.is_dir(), 'plugins-examples/ must ship with the repo'
    monkeypatch.setattr(plugins, 'plugin_paths', lambda: [EXAMPLES_DIR])
    monkeypatch.setattr(config.app_config, 'enable_plugins', True, raising=False)
    plugins.load_plugins(force=True)
    return EXAMPLES_DIR


V1_PLUGIN = '''
    def lookup(target):
        return {'note': target}

    SOURCES = {'ip': {'Legacy': lookup}}
'''

V2_PLUGIN = '''
    PLUGIN_META = {
        'name': 'demo-v2',
        'version': '3.1.4',
        'author': 'Test Author',
        'description': 'A v2 plugin exercising every piece.',
        'license': 'MIT',
        'url': 'https://example.com/plugin',
        'requires_api': 2,
    }

    def lookup(target):
        return {'demo': True}

    def cmd_handler(args, ctx):
        return 7

    def render(envelope):
        return ['section line']

    def tool_handler(arguments):
        return {'ok': True}

    def analytics_run(payload):
        return {'n': 1}

    SOURCES = {'domain': {'demo': lookup}}
    COMMANDS = {'demo-cmd': {'description': 'demo command',
                             'handler': cmd_handler,
                             'arguments': [{'name': 'target', 'help': 'a target',
                                            'required': True}]}}
    REPORT_SECTIONS = {'demo-sec': {'title': 'Demo Section', 'kinds': 'all',
                                    'render': render}}
    TOOLS = {'demo-tool': {'description': 'demo tool', 'handler': tool_handler}}
    ANALYTICS = {'demo-an': {'description': 'demo analytics', 'run': analytics_run}}
'''


class TestV1Compatibility:
    """v1 plugins keep loading exactly as before, with a synthesized surface."""

    def test_v1_plugin_loads_with_synthesized_meta(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'legacy.py', V1_PLUGIN)

        infos = plugins.load_plugins(force=True)
        info = infos[0]

        assert info.error == ''
        assert info.kinds == ['ip']
        assert info.sources == {'ip': ['Legacy']}
        assert plugins.plugin_sources('ip')['Legacy']('8.8.8.8') == {'note': '8.8.8.8'}

        surface = info.surface
        assert surface is not None
        assert surface.meta.name == 'legacy'          # file stem
        assert surface.meta.version == '1.0.0'
        assert surface.meta.requires_api == 1
        assert surface.meta.author == ''
        assert surface.commands == {}
        assert surface.report_sections == {}
        assert surface.tools == {}
        assert surface.analytics == {}
        assert surface.errors == []
        assert not surface.has_v2_features()

    def test_v1_broken_plugin_keeps_surface_none(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'broken.py', 'def broken(:\n')

        info = plugins.load_plugins(force=True)[0]

        assert info.error != ''
        assert info.surface is None
        assert plugins.plugin_commands() == {}

    def test_v1_no_sources_still_an_error(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'empty.py', 'X = 1\n')

        info = plugins.load_plugins(force=True)[0]

        assert info.error == 'SOURCES is missing or not a dict'
        assert info.kinds == []


class TestV2Meta:
    """PLUGIN_META parsing, synthesis and degradation."""

    def test_meta_parsed_from_dict(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'meta.py', V2_PLUGIN)

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.meta == PluginMeta(
            name='demo-v2', version='3.1.4', author='Test Author',
            description='A v2 plugin exercising every piece.',
            license='MIT', url='https://example.com/plugin', requires_api=2)
        assert surface.errors == []

    def test_meta_not_a_dict_is_synthesized_with_error(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badmeta.py', '''
            PLUGIN_META = ['not', 'a', 'dict']
            SOURCES = {}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.meta.name == 'badmeta'
        assert surface.meta.requires_api == 1
        assert ('meta', "PLUGIN_META is list, not a dict") in surface.errors

    def test_partial_meta_gets_defaults(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'partial.py', '''
            PLUGIN_META = {'name': 'tiny', 'requires_api': 2}
            SOURCES = {}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.meta.name == 'tiny'
        assert surface.meta.version == '1.0.0'
        assert surface.meta.author == ''
        assert surface.meta.requires_api == 2
        assert surface.errors == []

    def test_junk_requires_api_falls_back_to_api_1(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'junkapi.py', '''
            PLUGIN_META = {'name': 'junk', 'requires_api': 'banana'}
            SOURCES = {}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.meta.requires_api == 1
        assert any(piece == 'meta' for piece, _ in surface.errors)

    def test_meta_to_dict_round_trip(self):
        meta = PluginMeta.from_dict(
            {'name': 'x', 'version': '2.0', 'requires_api': 2}, 'fallback')
        assert meta.to_dict() == {
            'name': 'x', 'version': '2.0', 'author': '', 'description': '',
            'license': '', 'url': '', 'requires_api': 2}
        assert meta.summary() == 'x 2.0 (api 2)'


class TestCommands:
    """COMMANDS extraction, argument normalization and malformed pieces."""

    def test_commands_extracted_and_merged(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'cmds.py', V2_PLUGIN)

        plugins.load_plugins(force=True)
        merged = plugins.plugin_commands()

        assert set(merged) == {'demo-cmd'}
        spec = merged['demo-cmd']
        assert spec['description'] == 'demo command'
        assert spec['plugin'] == 'cmds'
        assert callable(spec['handler'])
        assert spec['arguments'] == [
            {'name': 'target', 'help': 'a target', 'required': True,
             'default': None, 'choices': None}]

    def test_commands_not_a_dict(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badcmds.py', '''
            SOURCES = {}
            COMMANDS = ['nope']
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.commands == {}
        assert ('commands', 'COMMANDS is list, not a dict') in surface.errors

    def test_command_entry_not_a_dict_dropped(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badentry.py', '''
            SOURCES = {}
            COMMANDS = {'good': {'handler': lambda a, c: 0},
                        'bad': 'not a dict'}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert set(surface.commands) == {'good'}
        assert any("command 'bad': spec is str" in reason
                   for piece, reason in surface.errors)

    def test_command_handler_not_callable_dropped(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badhandler.py', '''
            SOURCES = {}
            COMMANDS = {'bad': {'description': 'x', 'handler': 42}}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.commands == {}
        assert any("command 'bad': handler is missing or not callable" in reason
                   for piece, reason in surface.errors)

    def test_command_arguments_not_a_list_drops_arguments(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badargs.py', '''
            SOURCES = {}
            COMMANDS = {'bad': {'handler': lambda a, c: 0, 'arguments': {'a': 1}}}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert set(surface.commands) == {'bad'}          # command survives ...
        assert surface.commands['bad']['arguments'] == []  # ... without args
        assert any("command 'bad': arguments is dict" in reason
                   for piece, reason in surface.errors)

    def test_bad_argument_name_dropped(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badargname.py', '''
            SOURCES = {}
            COMMANDS = {'ok': {'handler': lambda a, c: 0, 'arguments': [
                {'name': 'good', 'required': True},
                {'name': '--also-good', 'default': 'x'},
                {'name': 'not a name!'},
                'not a dict',
            ]}}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface
        arguments = surface.commands['ok']['arguments']

        assert [arg['name'] for arg in arguments] == ['good', '--also-good']
        assert arguments[0]['required'] is True
        assert arguments[1]['required'] is False
        assert arguments[1]['default'] == 'x'
        assert len([e for e in surface.errors if e[0] == 'commands']) == 2

    def test_argument_choices_normalized(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'choices.py', '''
            SOURCES = {}
            COMMANDS = {'pick': {'handler': lambda a, c: 0, 'arguments': [
                {'name': '--mode', 'choices': ['fast', 'slow'], 'default': 'fast'},
            ]}}
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.commands['pick']['arguments'][0]['choices'] == ['fast', 'slow']

    def test_command_collision_first_wins(self, plugin_dirs):
        project, user = plugin_dirs
        _write(project, 'first.py', '''
            SOURCES = {}
            COMMANDS = {'shared': {'description': 'first one',
                                   'handler': lambda a, c: 11}}
        ''')
        _write(user, 'second.py', '''
            SOURCES = {}
            COMMANDS = {'shared': {'description': 'second one',
                                   'handler': lambda a, c: 22}}
        ''')

        infos = {info.name: info for info in plugins.load_plugins(force=True)}
        merged = plugins.plugin_commands()

        assert merged['shared']['description'] == 'first one'
        assert merged['shared']['plugin'] == 'first'
        assert merged['shared']['handler'](None, None) == 11
        assert any("command 'shared' skipped: already provided by plugin 'first'"
                   in reason for piece, reason in infos['second'].surface.errors)
        assert infos['first'].surface.errors == []


class TestReportSections:
    """REPORT_SECTIONS extraction and the never-raising safe wrapper."""

    def test_sections_extracted_with_kinds(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'sections.py', V2_PLUGIN)

        plugins.load_plugins(force=True)
        sections = plugins.plugin_report_sections()

        assert len(sections) == 1
        entry = sections[0]
        assert entry['name'] == 'demo-sec'
        assert entry['title'] == 'Demo Section'
        assert entry['kinds'] == 'all'
        assert entry['plugin'] == 'sections'
        assert callable(entry['render'])
        assert callable(entry['safe_render'])
        assert entry['safe_render']({}) == ['section line']

    def test_kinds_normalized_from_tuple(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'kinds.py', '''
            SOURCES = {}
            REPORT_SECTIONS = {
                'both': {'title': 'Both', 'kinds': ('ip', 'domain'),
                         'render': lambda env: ['x']},
                'single': {'title': 'S', 'kinds': 'cve',
                           'render': lambda env: ['y']},
            }
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.report_sections['both']['kinds'] == ('domain', 'ip')
        assert surface.report_sections['single']['kinds'] == ('cve',)

    def test_bad_section_dropped(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badsec.py', '''
            SOURCES = {}
            REPORT_SECTIONS = {
                'ok': {'title': 'OK', 'render': lambda env: []},
                'no-render': {'title': 'Missing'},
                'bad-kinds': {'title': 'K', 'kinds': 42, 'render': lambda e: []},
            }
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert set(surface.report_sections) == {'ok'}
        assert any("section 'no-render': render is missing" in reason
                   for piece, reason in surface.errors)
        assert any("section 'bad-kinds': kinds is not a kind list" in reason
                   for piece, reason in surface.errors)

    def test_safe_render_never_raises(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'raising.py', '''
            SOURCES = {}
            def boom(env):
                raise RuntimeError('kaboom')
            REPORT_SECTIONS = {
                'boom': {'title': 'Boom', 'render': boom},
            }
        ''')

        plugins.load_plugins(force=True)
        entry = plugins.plugin_report_sections()[0]

        lines = entry['safe_render']({'kind': 'ip'})
        assert len(lines) == 1
        assert "plugin section 'boom' failed" in lines[0]
        assert 'RuntimeError' in lines[0]
        assert 'kaboom' in lines[0]

    def test_safe_render_tolerates_str_and_junk(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'shapes.py', '''
            SOURCES = {}
            REPORT_SECTIONS = {
                'text': {'title': 'T', 'render': lambda env: 'one\\ntwo'},
                'junk': {'title': 'J', 'render': lambda env: 42},
                'tuple': {'title': 'X', 'render': lambda env: ('a', 'b')},
            }
        ''')

        plugins.load_plugins(force=True)
        sections = {entry['name']: entry for entry in plugins.plugin_report_sections()}

        assert sections['text']['safe_render']({}) == ['one', 'two']
        assert sections['tuple']['safe_render']({}) == ['a', 'b']
        junk = sections['junk']['safe_render']({})
        assert len(junk) == 1
        assert 'returned int, expected a list' in junk[0]

    def test_render_report_section_kind_gating(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'gated.py', '''
            SOURCES = {}
            REPORT_SECTIONS = {
                'ip-only': {'title': 'IP', 'kinds': ('ip',),
                            'render': lambda env: ['ip line']},
            }
        ''')

        plugins.load_plugins(force=True)

        assert plugins.render_report_section('ip-only', {'kind': 'ip'}) == ['ip line']
        assert plugins.render_report_section('ip-only', {'kind': 'domain'}) == []
        assert plugins.render_report_section(
            'gated:ip-only', {'kind': 'ip'}) == ['ip line']  # qualified name
        assert plugins.render_report_section('nope', {'kind': 'ip'}) == []

    def test_render_report_section_survives_raising_renderer(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'boomsec.py', '''
            SOURCES = {}
            def boom(env):
                raise ValueError('nope')
            REPORT_SECTIONS = {'boom': {'title': 'B', 'render': boom}}
        ''')

        plugins.load_plugins(force=True)

        lines = plugins.render_report_section('boom', {'kind': 'ip'})
        assert len(lines) == 1
        assert 'failed' in lines[0]


class TestToolsAndAnalytics:
    """TOOLS and ANALYTICS extraction, merging and collisions."""

    def test_tools_and_analytics_extracted(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'pieces.py', V2_PLUGIN)

        plugins.load_plugins(force=True)

        tools = plugins.plugin_tools()
        assert set(tools) == {'demo-tool'}
        assert tools['demo-tool']['description'] == 'demo tool'
        assert tools['demo-tool']['plugin'] == 'pieces'
        assert tools['demo-tool']['handler']({'x': 1}) == {'ok': True}

        analytics = plugins.plugin_analytics()
        assert set(analytics) == {'demo-an'}
        assert analytics['demo-an']['run']({'a': 2}) == {'n': 1}

    def test_malformed_tools_dropped(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badtools.py', '''
            SOURCES = {}
            TOOLS = {
                'ok': {'description': 'fine', 'handler': lambda a: {}},
                'no-handler': {'description': 'x'},
                'not-a-spec': 'nope',
            }
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert set(surface.tools) == {'ok'}
        reason = ('tools', "tool 'no-handler': handler is missing or not callable")
        assert reason in surface.errors
        assert any("tool 'not-a-spec': spec is str" in reason
                   for piece, reason in surface.errors)

    def test_malformed_analytics_dropped(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'badan.py', '''
            SOURCES = {}
            ANALYTICS = {
                'ok': {'run': lambda p: {}},
                'no-run': {'description': 'x'},
            }
        ''')

        surface = plugins.load_plugins(force=True)[0].surface

        assert set(surface.analytics) == {'ok'}
        assert any("analytics 'no-run': run is missing" in reason
                   for piece, reason in surface.errors)

    def test_tool_collision_first_wins(self, plugin_dirs):
        project, user = plugin_dirs
        _write(project, 'ta.py', '''
            SOURCES = {}
            TOOLS = {'dup': {'handler': lambda a: {'who': 'first'}}}
            ANALYTICS = {'dup': {'run': lambda p: {'who': 'first'}}}
        ''')
        _write(user, 'tb.py', '''
            SOURCES = {}
            TOOLS = {'dup': {'handler': lambda a: {'who': 'second'}}}
            ANALYTICS = {'dup': {'run': lambda p: {'who': 'second'}}}
        ''')

        infos = {info.name: info for info in plugins.load_plugins(force=True)}

        assert plugins.plugin_tools()['dup']['handler']({}) == {'who': 'first'}
        assert plugins.plugin_analytics()['dup']['run']({}) == {'who': 'first'}
        assert any("tool 'dup' skipped" in reason
                   for piece, reason in infos['tb'].surface.errors)
        assert any("analytics 'dup' skipped" in reason
                   for piece, reason in infos['tb'].surface.errors)


class TestApiGating:
    """requires_api gating: sources always load, v2 features degrade."""

    def test_future_api_plugin_degrades(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'future.py', '''
            PLUGIN_META = {'name': 'future', 'version': '9.0', 'requires_api': 3}
            SOURCES = {'ip': {'legacy': lambda t: {'legacy': True}}}
            COMMANDS = {'future-cmd': {'handler': lambda a, c: 0}}
            TOOLS = {'future-tool': {'handler': lambda a: {}}}
            ANALYTICS = {'future-an': {'run': lambda p: {}}}
            REPORT_SECTIONS = {'future-sec': {'render': lambda e: []}}
        ''')

        infos = plugins.load_plugins(force=True)
        info = infos[0]
        surface = info.surface

        assert info.error == ''                       # v1 contract still loads
        assert info.kinds == ['ip']
        assert plugins.plugin_sources('ip')['legacy']('t') == {'legacy': True}
        assert surface.meta.requires_api == 3
        assert surface.commands == {}                 # v2 features skipped
        assert surface.tools == {}
        assert surface.analytics == {}
        assert surface.report_sections == {}
        assert ('api', 'requires_api 3 > 2') in surface.errors
        assert plugins.plugin_commands() == {}

    def test_supported_api_constant(self):
        assert SUPPORTED_PLUGIN_API == 2


class TestPluginMetaList:
    """plugin_meta_list() reports manifests in scan order."""

    def test_meta_list_scan_order(self, plugin_dirs):
        project, user = plugin_dirs
        _write(project, 'a_first.py', V1_PLUGIN)
        _write(user, 'z_second.py', V2_PLUGIN)

        plugins.load_plugins(force=True)  # the fixture pre-dated the files
        metas = plugins.plugin_meta_list()

        assert [meta.name for meta in metas] == ['a_first', 'demo-v2']
        assert metas[0].requires_api == 1
        assert metas[1].requires_api == 2


class TestValidatePluginFile:
    """The plugin developer's linter."""

    def test_good_v2_file(self, plugin_dirs, tmp_path):
        target = _write(tmp_path, 'good_v2.py', V2_PLUGIN)

        report = validate_plugin_file(target)

        assert report['ok'] is True
        assert report['errors'] == []
        assert report['meta']['name'] == 'demo-v2'
        assert report['meta']['requires_api'] == 2
        assert report['sources'] == {'domain': ['demo']}
        assert set(report['commands']) == {'demo-cmd'}
        assert report['commands']['demo-cmd']['description'] == 'demo command'
        assert report['commands']['demo-cmd']['arguments'][0]['name'] == 'target'
        assert report['report_sections'] == [
            {'name': 'demo-sec', 'title': 'Demo Section', 'kinds': 'all'}]
        assert report['tools'] == {'demo-tool': 'demo tool'}
        assert report['analytics'] == {'demo-an': 'demo analytics'}

    def test_good_v1_file(self, plugin_dirs, tmp_path):
        target = _write(tmp_path, 'good_v1.py', V1_PLUGIN)

        report = validate_plugin_file(target)

        assert report['ok'] is True
        assert report['meta']['name'] == 'good_v1'
        assert report['meta']['requires_api'] == 1
        assert report['sources'] == {'ip': ['Legacy']}

    def test_syntax_error_file(self, tmp_path):
        target = _write(tmp_path, 'broken.py', 'def broken(:\n')

        report = validate_plugin_file(target)

        assert report['ok'] is False
        assert report['errors']
        assert report['errors'][0][0] == 'import'
        assert 'SyntaxError' in report['errors'][0][1]

    def test_file_with_errors_is_not_ok(self, tmp_path):
        target = _write(tmp_path, 'flawed.py', '''
            SOURCES = {}
            COMMANDS = {'broken': {'handler': 'not callable'}}
        ''')

        report = validate_plugin_file(target)

        assert report['ok'] is False
        assert any(piece == 'commands' for piece, _ in report['errors'])

    def test_missing_file(self, tmp_path):
        report = validate_plugin_file(tmp_path / 'nope.py')

        assert report['ok'] is False
        assert report['errors'][0][0] == 'file'

    def test_empty_plugin_is_not_ok(self, tmp_path):
        target = _write(tmp_path, 'nothing.py', 'X = 1\n')

        report = validate_plugin_file(target)

        assert report['ok'] is False

    def test_check_does_not_pollute_sys_modules(self, tmp_path):
        target = _write(tmp_path, 'isolated.py', V2_PLUGIN)

        validate_plugin_file(target)

        leftovers = [name for name in sys.modules
                     if name.startswith('_obscuralens_plugin_check')]
        assert leftovers == []

    def test_check_does_not_affect_loaded_cache(self, plugin_dirs, tmp_path):
        project, _ = plugin_dirs
        _write(project, 'loaded.py', V1_PLUGIN)
        plugins.load_plugins(force=True)

        target = _write(tmp_path, 'other.py', V2_PLUGIN)
        validate_plugin_file(target)

        assert [info.name for info in plugins.loaded_plugins()] == ['loaded']
        assert plugins.plugin_commands() == {}


class TestPluginContext:
    """Lazy resolution of the platform handles."""

    class Sentinel:
        """Counts attribute accesses so laziness is observable."""

        def __init__(self, label, log):
            self._label = label
            self._log = log

        def __getattr__(self, item):
            self._log.append(self._label)
            return 'value'

    def test_handles_resolve_lazily(self, monkeypatch):
        import importlib

        config_module = importlib.import_module('obscuralens.config')
        database_module = importlib.import_module('obscuralens.database')
        cache_module = importlib.import_module('obscuralens.core.cache')
        metrics_module = importlib.import_module('obscuralens.core.metrics')

        log = []
        monkeypatch.setattr(config_module, 'config',
                            self.Sentinel('config', log))
        monkeypatch.setattr(database_module, 'db',
                            self.Sentinel('db', log))
        monkeypatch.setattr(cache_module, 'cache',
                            self.Sentinel('cache', log))
        monkeypatch.setattr(metrics_module, 'metrics',
                            self.Sentinel('metrics', log))

        context = PluginContext()

        assert log == []                      # nothing touched at construction
        assert context.config.anything == 'value'
        assert log == ['config']              # only config was resolved
        assert context.db.rows == 'value'
        assert log == ['config', 'db']
        assert context.cache.get == 'value'
        assert context.metrics.snapshot == 'value'
        assert log == ['config', 'db', 'cache', 'metrics']

        # repeated access reuses the cached handle: the same object comes
        # back without the module being consulted again
        first_handle = context.config
        assert context.config is first_handle
        assert log == ['config', 'db', 'cache', 'metrics']

    def test_http_get_uses_platform_client(self, monkeypatch):
        from obscuralens.utils import http_client

        calls = []

        def fake_get_json(url, **kwargs):
            calls.append((url, kwargs))
            return True, {'answer': 42}, ''

        monkeypatch.setattr(http_client, 'get_json', fake_get_json)

        context = PluginContext()
        data = context.http.get('https://example.com/api',
                                params={'q': 'osint'})

        assert data == {'answer': 42}
        assert calls == [('https://example.com/api', {'params': {'q': 'osint'},
                                                      'use_cache': True})]

    def test_http_get_returns_none_on_failure(self, monkeypatch):
        from obscuralens.utils import http_client

        monkeypatch.setattr(http_client, 'get_json',
                            lambda url, **kw: (False, None, 'timeout'))
        context = PluginContext()
        assert context.http.get('https://down.example') is None

        def boom(url, **kw):
            raise RuntimeError('offline')

        monkeypatch.setattr(http_client, 'get_json', boom)
        assert context.http.get('https://down.example') is None

    def test_http_get_text(self, monkeypatch):
        from obscuralens.utils import http_client

        monkeypatch.setattr(http_client.http, 'get_text',
                            lambda url, **kw: (True, '<html/>', ''))
        context = PluginContext()
        assert context.http.get_text('https://example.com') == '<html/>'

    def test_temp_dir_created_once(self, tmp_path, monkeypatch):
        import tempfile

        monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(tmp_path))
        context = PluginContext()

        first = context.temp_dir
        assert first.is_dir()
        assert first.name == 'obscuralens-plugins'
        assert context.temp_dir == first      # cached, not recreated


class TestArgumentParser:
    """build_plugin_argument_parser turns specs into parsers."""

    def _spec(self):
        return {
            'description': 'demo',
            'arguments': [
                {'name': 'target', 'help': 'the target', 'required': True},
                {'name': '--name', 'help': 'a name', 'required': False,
                 'default': 'world'},
                {'name': '--mode', 'choices': ['fast', 'slow'],
                 'default': 'fast'},
            ],
        }

    def test_parser_builds_positional_and_options(self):
        parser = build_plugin_argument_parser('demo', self._spec(), 'plug')
        args = parser.parse_args(['8.8.8.8', '--name', 'Ada', '--mode', 'slow'])

        assert args.target == '8.8.8.8'
        assert args.name == 'Ada'
        assert args.mode == 'slow'
        assert parser.prog == 'obscuralens plugins run demo'

    def test_defaults_applied(self):
        parser = build_plugin_argument_parser('demo', self._spec())
        args = parser.parse_args(['target-value'])

        assert args.name == 'world'
        assert args.mode == 'fast'

    def test_optional_positional_with_default(self):
        spec = {'arguments': [{'name': 'thing', 'required': False,
                               'default': 'fallback'}]}
        parser = build_plugin_argument_parser('opt', spec)
        assert parser.parse_args([]).thing == 'fallback'
        assert parser.parse_args(['given']).thing == 'given'

    def test_parse_known_args_ignores_extras(self):
        parser = build_plugin_argument_parser('demo', self._spec())
        args, extra = parser.parse_known_args(['t', '--unknown', 'x'])

        assert args.target == 't'
        assert extra == ['--unknown', 'x']


class TestShippedExamples:
    """The three example plugins in plugins-examples/ load through the loader."""

    def test_all_three_examples_load_cleanly(self, examples_dir):
        infos = {info.name: info for info in plugins.loaded_plugins()}

        assert set(infos) == {'example_commands', 'example_full',
                              'example_source_pack'}
        for info in infos.values():
            assert info.error == ''
            assert info.surface.errors == []

    def test_example_source_pack_sources(self, examples_dir):
        ip = plugins.plugin_sources('ip')
        domain = plugins.plugin_sources('domain')

        assert ip['demo_ip_info']('8.8.8.8') == {
            'demo_ip_version': 4, 'demo_ip_is_global': True,
            'demo_ip_is_private': False, 'demo_ip_is_multicast': False,
            'demo_ip_first_octet': 8}
        assert ip['demo_ip_info']('not-an-ip') == {}
        assert domain['demo_domain_tags']('www.example.org') == {
            'demo_domain_label_count': 3,
            'demo_domain_tags': ['non-commercial registry',
                                 'multi-label host name']}
        assert domain['demo_domain_tags']('') == {}

    def test_example_commands_discoverable_and_runnable(self, examples_dir):
        merged = plugins.plugin_commands()

        assert {'hello', 'db-peek'} <= set(merged)
        assert merged['hello']['plugin'] == 'example_commands'

        parser = build_plugin_argument_parser('hello', merged['hello'])
        args = parser.parse_args(['--name', 'Ada'])
        assert merged['hello']['handler'](args, PluginContext()) == 0

    def test_example_full_showcase(self, examples_dir):
        commands_ = plugins.plugin_commands()
        assert 'note' in commands_

        tools = plugins.plugin_tools()
        assert tools['demo_echo']['handler']({'text': 'hi'}) == {
            'tool': 'demo_echo', 'echo': {'text': 'hi'}}

        analytics = plugins.plugin_analytics()
        assert analytics['demo_wordcount']['run'](
            {'text': 'one two three four'}) == {'words': 4, 'characters': 18}

        sections = {entry['name']: entry for entry
                    in plugins.plugin_report_sections()}
        assert sections['notes']['title'] == 'Plugin Notes'
        assert sections['notes']['kinds'] == ('ip',)
        rendered = plugins.render_report_section(
            'notes', {'kind': 'ip', 'target': '8.8.8.8',
                      'fields': {'full_ip_note': 'globally routable address'}})
        assert any('PLUGIN NOTES' in line for line in rendered)
        assert any('globally routable' in line for line in rendered)

    def test_example_metas_reported(self, examples_dir):
        metas = {meta.name: meta for meta in plugins.plugin_meta_list()}

        assert set(metas) == {'obscuralens-example-commands',
                              'obscuralens-example-full',
                              'obscuralens-example-source-pack'}
        assert metas['obscuralens-example-full'].version == '2.0.0'
        assert metas['obscuralens-example-source-pack'].version == '1.2.0'
        assert all(meta.requires_api == 2 for meta in metas.values())

    def test_validate_example_files_ok(self, examples_dir):
        for name in ('example_source_pack.py', 'example_commands.py',
                     'example_full.py'):
            report = validate_plugin_file(examples_dir / name)
            assert report['ok'] is True, (name, report['errors'])


class TestCliWiring:
    """plugins list/check/run and completion through commands.run()."""

    def test_plugins_list_reports_v2_surface(self, examples_dir, capsys):
        code = commands.run(['plugins', 'list'])

        out = capsys.readouterr().out
        assert code == 0
        assert 'example_full' in out
        assert '1 cmd, 1 sec, 1 tools, 1 analytics' in out
        assert 'obscuralens-example-full 2.0.0' in out or '2.0.0' in out

    def test_plugins_list_json_includes_meta_and_surface(self, examples_dir,
                                                          capsys):
        import json

        code = commands.run(['plugins', 'list', '-f', 'json'])
        payload = json.loads(capsys.readouterr().out)

        assert code == 0
        by_name = {row['name']: row for row in payload}
        row = by_name['example_full']
        assert row['kinds'] == 'ip'                      # v1 columns kept
        assert row['sources'] == 'ip: demo_full_ip_note'
        assert row['meta']['name'] == 'obscuralens-example-full'
        assert row['surface']['commands'] == ['note']
        assert row['surface']['tools'] == ['demo_echo']
        assert row['surface']['errors'] == []

    def test_plugins_check_good_file(self, examples_dir, capsys):
        code = commands.run(['plugins', 'check',
                             str(examples_dir / 'example_full.py')])
        out = capsys.readouterr().out

        assert code == 0
        assert 'ok: yes' in out
        assert 'obscuralens-example-full 2.0.0 (api 2)' in out
        assert 'demo_echo' in out
        assert 'demo_wordcount' in out
        assert 'Plugin Notes' in out

    def test_plugins_check_broken_file(self, tmp_path, capsys):
        broken = _write(tmp_path, 'broken.py', 'def broken(:\n')

        code = commands.run(['plugins', 'check', str(broken)])

        assert code == 1
        captured = capsys.readouterr()
        assert 'ok: no' in captured.out
        assert 'SyntaxError' in captured.err

    def test_plugins_check_json_output(self, examples_dir, capsys):
        import json

        code = commands.run(['plugins', 'check',
                             str(examples_dir / 'example_commands.py'),
                             '-f', 'json'])
        report = json.loads(capsys.readouterr().out)

        assert code == 0
        assert report['ok'] is True
        assert set(report['commands']) == {'hello', 'db-peek'}

    def test_plugins_run_hello(self, examples_dir, capsys):
        code = commands.run(['plugins', 'run', 'hello', '--name', 'Ridwan'])
        out = capsys.readouterr().out

        assert code == 0
        assert 'Hello, Ridwan!' in out

    def test_plugins_run_forwards_positionals(self, examples_dir, capsys):
        code = commands.run(['plugins', 'run', 'note', '10.0.0.5'])
        out = capsys.readouterr().out

        assert code == 0
        assert 'RFC 1918 private range' in out

    def test_plugins_run_unknown_command(self, examples_dir, capsys):
        code = commands.run(['plugins', 'run', 'does-not-exist'])
        captured = capsys.readouterr()

        assert code == 2
        assert 'unknown plugin command' in captured.err
        assert 'hello' in captured.err          # known commands are listed

    def test_plugins_run_handler_exit_code_wins(self, plugin_dirs, capsys):
        project, _ = plugin_dirs
        _write(project, 'failing.py', '''
            SOURCES = {}
            def handler(args, ctx):
                print('about to fail')
                return 5
            COMMANDS = {'fail': {'description': 'returns 5', 'handler': handler}}
        ''')
        plugins.load_plugins(force=True)

        code = commands.run(['plugins', 'run', 'fail'])

        assert code == 5
        assert 'about to fail' in capsys.readouterr().out

    def test_plugins_reload_still_works(self, examples_dir, capsys):
        code = commands.run(['plugins', 'reload'])

        assert code == 0
        assert 'example_full' in capsys.readouterr().out

    def test_extract_plugin_surface_on_module_object(self):
        import types

        module = types.ModuleType('synthetic')
        module.PLUGIN_META = {'name': 'synthetic', 'requires_api': 2}
        module.COMMANDS = {'ping': {'handler': lambda a, c: 0}}

        surface = extract_plugin_surface(module)

        assert surface.meta.name == 'synthetic'
        assert set(surface.commands) == {'ping'}
        assert surface.errors == []


class TestSurfaceHelpers:
    """PluginSurface convenience methods."""

    def test_summary_and_to_dict(self, plugin_dirs):
        project, _ = plugin_dirs
        _write(project, 'rich.py', V2_PLUGIN)

        surface = plugins.load_plugins(force=True)[0].surface

        assert surface.summary() == '1 cmd, 1 sec, 1 tools, 1 analytics'
        assert surface.has_v2_features() is True
        data = surface.to_dict()
        assert data['meta']['name'] == 'demo-v2'
        assert data['sources'] == {'domain': ['demo']}
        assert data['commands']['demo-cmd']['arguments'][0]['name'] == 'target'
        assert data['report_sections'][0]['kinds'] == 'all'
        assert data['tools'] == {'demo-tool': 'demo tool'}
        assert data['errors'] == []
