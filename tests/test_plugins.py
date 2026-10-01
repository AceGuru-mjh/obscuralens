"""Plugin loader tests (fully offline; never touches the real plugin dirs)."""

import textwrap
from pathlib import Path

import pytest

from obscuralens import plugins
from obscuralens.config import config


def _write(directory: Path, filename: str, body: str) -> Path:
    """Create a plugin file with dedented source text."""
    path = directory / filename
    path.write_text(textwrap.dedent(body), encoding='utf-8')
    return path


@pytest.fixture()
def plugin_dirs(tmp_path, monkeypatch):
    """Create two fake plugin directories and point the loader at them."""
    project = tmp_path / 'project' / 'plugins'
    user = tmp_path / 'user' / 'plugins'
    project.mkdir(parents=True)
    user.mkdir(parents=True)

    monkeypatch.setattr(plugins, 'plugin_paths', lambda: [project, user])
    monkeypatch.setattr(config.app_config, 'enable_plugins', True, raising=False)
    plugins.load_plugins(force=True)  # start each test from a clean cache
    return project, user


def test_valid_plugin_loads_and_registers_sources(plugin_dirs):
    project, _user = plugin_dirs
    _write(project, 'good_ip.py', '''
        def lookup(target):
            return {'network_note': target}

        SOURCES = {'ip': {'Good': lookup}}
    ''')

    infos = plugins.load_plugins(force=True)

    assert [info.name for info in infos] == ['good_ip']
    info = infos[0]
    assert info.path == str(project / 'good_ip.py')
    assert info.error == ''
    assert info.kinds == ['ip']
    assert info.sources == {'ip': ['Good']}

    sources = plugins.plugin_sources('ip')
    assert sources['Good']('1.2.3.4') == {'network_note': '1.2.3.4'}
    assert plugins.loaded_plugins() == infos


def test_broken_plugins_are_isolated(plugin_dirs):
    project, _user = plugin_dirs
    _write(project, 'good.py',
           "SOURCES = {'ip': {'Good': lambda target: {'ok': target}}}\n")
    _write(project, 'broken_syntax.py', 'def broken(:\n    pass\n')
    _write(project, 'broken_import.py',
           'import module_that_does_not_exist_obscuralens\n\nSOURCES = {}\n')
    _write(project, 'no_sources.py', "SOURCES = ['not', 'a', 'dict']\n")

    infos = {info.name: info for info in plugins.load_plugins(force=True)}

    assert infos['good'].error == ''
    for name in ('broken_syntax', 'broken_import', 'no_sources'):
        assert infos[name].error != ''
        assert infos[name].kinds == []
        assert infos[name].sources == {}

    # The healthy plugin still loaded and is usable.
    assert plugins.plugin_sources('ip')['Good']('x') == {'ok': 'x'}


def test_unknown_kinds_are_filtered(plugin_dirs):
    project, _user = plugin_dirs
    _write(project, 'kinds.py', '''
        SOURCES = {
            'ip': {'IpSource': lambda target: {'ip': target}},
            'domain': {'DomainSource': lambda target: {'domain': target}},
            'phone': {'Bad': 'not callable'},
            'carrier_pigeon': {'Nope': lambda target: {'x': target}},
            'dns': 'not a mapping',
        }
    ''')

    info = plugins.load_plugins(force=True)[0]

    assert info.kinds == ['domain', 'ip']
    assert info.sources == {'domain': ['DomainSource'], 'ip': ['IpSource']}
    assert set(plugins.plugin_sources('ip')) == {'IpSource'}
    assert plugins.plugin_sources('carrier_pigeon') == {}
    assert plugins.plugin_sources('phone') == {}


def test_duplicate_source_names_later_path_wins(plugin_dirs):
    project, user = plugin_dirs
    _write(project, 'first.py',
           "SOURCES = {'ip': {'Shared': lambda target: {'origin': 'project'}}}\n")
    _write(user, 'second.py',
           "SOURCES = {'ip': {'Shared': lambda target: {'origin': 'user'}}}\n")

    plugins.load_plugins(force=True)

    assert plugins.plugin_sources('ip')['Shared']('target') == {'origin': 'user'}


def test_enable_plugins_false_returns_empty(plugin_dirs, monkeypatch):
    project, _user = plugin_dirs
    _write(project, 'good.py',
           "SOURCES = {'ip': {'Good': lambda target: {'ok': True}}}\n")
    monkeypatch.setattr(config.app_config, 'enable_plugins', False, raising=False)

    assert plugins.load_plugins(force=True) == []
    assert plugins.loaded_plugins() == []
    assert plugins.plugin_sources('ip') == {}


def test_reload_plugins_picks_up_new_files(plugin_dirs):
    project, _user = plugin_dirs
    _write(project, 'one.py',
           "SOURCES = {'ip': {'One': lambda target: {}}}\n")
    assert [info.name for info in plugins.load_plugins(force=True)] == ['one']

    _write(project, 'two.py',
           "SOURCES = {'domain': {'Two': lambda target: {}}}\n")

    # Without force the cached scan is returned; reload rescans the disk.
    assert [info.name for info in plugins.load_plugins()] == ['one']
    assert [info.name for info in plugins.reload_plugins()] == ['one', 'two']
    assert set(plugins.plugin_sources('domain')) == {'Two'}


def test_underscore_files_are_ignored(plugin_dirs):
    project, _user = plugin_dirs
    _write(project, 'visible.py',
           "SOURCES = {'ip': {'Visible': lambda target: {}}}\n")
    _write(project, '_helper.py',
           "SOURCES = {'ip': {'Hidden': lambda target: {}}}\n")
    _write(project, '_broken.py', 'this is not valid python!\n')

    infos = plugins.load_plugins(force=True)

    assert [info.name for info in infos] == ['visible']
    assert set(plugins.plugin_sources('ip')) == {'Visible'}


def test_plugin_paths_returns_existing_directories_only(tmp_path, monkeypatch):
    config_plugins = tmp_path / 'cfg' / 'plugins'
    config_plugins.mkdir(parents=True)
    monkeypatch.setattr(config, 'config_dir', tmp_path / 'cfg')

    paths = plugins.plugin_paths()

    project_plugins = Path(plugins.__file__).resolve().parent.parent.parent / 'plugins'
    expected = [path for path in (project_plugins, config_plugins) if path.is_dir()]
    assert paths == expected
    assert config_plugins in paths
    assert all(path.is_dir() for path in paths)

    # A config directory without a plugins/ subdirectory is dropped.
    monkeypatch.setattr(config, 'config_dir', tmp_path / 'missing')
    assert config_plugins not in plugins.plugin_paths()


def test_named_sources_include_plugin_file_stem(plugin_dirs):
    project, user = plugin_dirs
    _write(project, 'first.py',
           "SOURCES = {'ip': {'Shared': lambda target: {'origin': 'project'}}}\n")
    _write(user, 'second.py',
           "SOURCES = {'ip': {'Shared': lambda target: {'origin': 'user'}}}\n")

    plugins.reload_plugins()

    named = plugins.plugin_sources_named('ip')
    assert set(named) == {'first:Shared', 'second:Shared'}
    assert named['first:Shared']('t') == {'origin': 'project'}
    assert named['second:Shared']('t') == {'origin': 'user'}


def test_ip_tracker_runs_plugin_sources(plugin_dirs, monkeypatch):
    from obscuralens.trackers import ip_sources

    project, _user = plugin_dirs
    _write(project, 'demo.py', '''
        def lookup(target):
            return {'network_note': f'seen {target}'}

        SOURCES = {'ip': {'Demo': lookup}}
    ''')
    plugins.reload_plugins()

    monkeypatch.setattr(ip_sources, 'FREE_SOURCES', {})
    out = ip_sources.gather_all('1.2.3.4')

    assert out['sources']['plugin:demo:Demo']['ok'] is True
    assert out['fields']['network_note'] == 'seen 1.2.3.4'
    assert out['provenance']['network_note'] == ['plugin:demo:Demo']
