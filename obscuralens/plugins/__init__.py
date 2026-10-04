"""
Plugin loader for user-supplied OSINT data sources and SDK v2 plugins.

A plugin is a ``*.py`` file dropped into one of the directories returned by
:func:`plugin_paths` (plain modules are scanned, not packages). Files whose
names start with ``_`` are ignored, so helper modules may live next to
plugins. Every plugin module may define a module-level ``SOURCES`` dict::

    SOURCES = {
        'ip': {'example': lookup_ip},
        'domain': {'example': lookup_domain},
    }

Supported kinds are the platform KINDS registry (``ip``, ``phone``,
``username``, ``email``, ``domain`` and the v4/v5/v6 additions); unknown
kinds are ignored. Each source is a callable that takes the target as a
single string and returns a ``dict`` of fields, using the same contract as
the built-in readers: return ``{}`` on failure and never raise for ordinary
errors (unexpected exceptions are still caught and isolated per source by
the trackers).

Plugin SDK v2 (see :mod:`.contracts`) adds four optional pieces on top of
``SOURCES`` — ``COMMANDS`` (CLI subcommands, run with
``obscuralens plugins run``), ``REPORT_SECTIONS`` (extra report blocks),
``TOOLS`` (MCP-exposed handlers) and ``ANALYTICS`` (pure functions) — plus a
``PLUGIN_META`` manifest declaring the required plugin API version. All v2
pieces are optional and validated independently; a plugin with only
``SOURCES`` behaves exactly as it did under the v1 loader.

Loading is lazy, cached and error-isolated: a module that raises while
importing, or that defines a missing or malformed ``SOURCES`` mapping (and
no v2 features), is skipped and reported through :attr:`PluginInfo.error`
without affecting the other plugins. ``app.enable_plugins`` (default
``True``) switches the whole mechanism off.

Source names are returned unprefixed by :func:`plugin_sources`; the tracker
integration exposes them in results as ``plugin:<file>:<name>``. Plugin
commands are merged first-wins (the earliest plugin in scan order owns a
name; collisions are recorded on the later plugin's surface) — the opposite
of the sources rule, so an existing command alias can never be silently
replaced by a newly dropped-in file.
"""

import hashlib
import importlib.util
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ..config import config
from .contracts import (
    KNOWN_KINDS,
    SUPPORTED_PLUGIN_API,
    PluginContext,
    PluginMeta,
    PluginSurface,
    build_plugin_argument_parser,
    extract_plugin_surface,
)

__all__ = [
    'KNOWN_KINDS',
    'PluginContext',
    'PluginInfo',
    'PluginMeta',
    'PluginSurface',
    'SUPPORTED_PLUGIN_API',
    'build_plugin_argument_parser',
    'extract_plugin_surface',
    'load_plugins',
    'loaded_plugins',
    'plugin_analytics',
    'plugin_commands',
    'plugin_meta_list',
    'plugin_paths',
    'plugin_report_sections',
    'plugin_sources',
    'plugin_sources_named',
    'plugin_tools',
    'reload_plugins',
    'render_report_section',
    'validate_plugin_file',
]


@dataclass
class PluginInfo:
    """Metadata for a single plugin file discovered on disk.

    ``surface`` carries the validated SDK v2 surface (manifest, commands,
    report sections, tools, analytics and per-piece errors) once the module
    imported successfully; it stays ``None`` for plugins that failed to
    import. Old code that only reads ``kinds``/``sources``/``error`` is
    unaffected.
    """

    name: str
    path: str
    kinds: List[str] = field(default_factory=list)
    sources: Dict[str, List[str]] = field(default_factory=dict)
    error: str = ''
    surface: Optional[PluginSurface] = None


# Cache of the last scan, plus the callables behind PluginInfo.sources.
_cache: Optional[List[PluginInfo]] = None
_source_index: Dict[str, Dict[str, Callable]] = {}
_named_index: Dict[str, Dict[str, Callable]] = {}
_module_names: List[str] = []

# Merged SDK v2 registries, rebuilt on every scan. Commands, tools and
# analytics are name-keyed and merged FIRST-WINS (a collision is recorded on
# the later plugin's surface); report sections keep every plugin's entry,
# disambiguated by the '<plugin>:<section>' key.
_command_index: Dict[str, Dict] = {}
_section_index: Dict[str, Dict] = {}
_tool_index: Dict[str, Dict] = {}
_analytics_index: Dict[str, Dict] = {}


def plugin_paths() -> List[Path]:
    """
    Return the plugin directories scanned, in priority order.

    The project-level ``<project_root>/plugins`` directory comes first, then
    the per-user ``<config_dir>/plugins`` directory. Only directories that
    currently exist are returned; later directories override earlier ones
    when two plugins register the same source name.
    """
    candidates = [
        Path(__file__).resolve().parent.parent.parent / 'plugins',
        Path(config.config_dir) / 'plugins',
    ]
    return [path for path in candidates if path.is_dir()]


def load_plugins(force: bool = False) -> List[PluginInfo]:
    """
    Scan the plugin directories and load every plugin found.

    Args:
        force: rescan even when a cached result exists; previously imported
            plugin modules are removed from ``sys.modules`` first.

    Returns:
        One :class:`PluginInfo` per plugin file, including files that failed
        to load (their ``error`` is non-empty). Returns an empty list when
        ``config.app_config.enable_plugins`` is false. Broken plugins never
        raise out of this function.
    """
    global _cache

    if not getattr(config.app_config, 'enable_plugins', True):
        _release_modules()
        _source_index.clear()
        _named_index.clear()
        _clear_v2_indexes()
        _cache = []
        return []

    if _cache is not None and not force:
        return list(_cache)

    _release_modules()
    _source_index.clear()
    _named_index.clear()
    _clear_v2_indexes()
    infos: List[PluginInfo] = []

    for directory in plugin_paths():
        for path in sorted(directory.glob('*.py')):
            if path.name.startswith('_'):
                continue  # helper module, not a plugin
            info, sources = _load_file(path)
            infos.append(info)
            for kind, entries in sources.items():
                # Later files (and later directories) win on name clashes.
                _source_index.setdefault(kind, {}).update(entries)
                _named_index.setdefault(kind, {}).update({
                    f"{path.stem}:{name}": reader
                    for name, reader in entries.items()
                })
            _merge_surface(info)

    _cache = infos
    return list(infos)


def plugin_sources(kind: str) -> Dict[str, Callable]:
    """
    Return ``{name: callable}`` for one target kind across all loaded plugins.

    Names are the plugin's own unprefixed source names. When two plugins
    register the same name, the plugin found later during the scan wins (the
    per-user directory is scanned after the project directory, and files are
    scanned in alphabetical order). An unknown ``kind`` yields an empty dict.
    """
    loaded_plugins()
    return dict(_source_index.get(kind, {}))


def plugin_sources_named(kind: str) -> Dict[str, Callable]:
    """
    Like :func:`plugin_sources`, but keys are ``'<file>:<name>'``.

    Trackers use this form and expose the sources as
    ``plugin:<file>:<name>`` in results, so two plugins defining the same
    source name stay distinguishable.
    """
    loaded_plugins()
    return dict(_named_index.get(kind, {}))


def loaded_plugins() -> List[PluginInfo]:
    """Return the cached plugin list, loading it on first use."""
    if _cache is None:
        return load_plugins()
    return list(_cache)


def reload_plugins() -> List[PluginInfo]:
    """Rescan the plugin directories from scratch and return the new list."""
    return load_plugins(force=True)


# --- SDK v2 registries ------------------------------------------------------

def plugin_commands() -> Dict[str, Dict]:
    """
    Return ``{name: spec}`` for every plugin command across loaded plugins.

    Each spec carries ``name``, ``description``, ``handler`` (called as
    ``handler(args, ctx) -> int``), the normalised ``arguments`` list and the
    owning ``plugin`` file stem. Commands are merged FIRST-WINS: when two
    plugins declare the same command name, the plugin found earlier in the
    scan (project directory before per-user directory, alphabetical file
    order) keeps it and the later plugin's surface records a collision error.
    This is deliberately the opposite of the source-name rule so dropping a
    new file next to an existing one can never swap an installed command.
    """
    loaded_plugins()
    return dict(_command_index)


def plugin_report_sections() -> List[Dict]:
    """
    Return every report section contributed by loaded plugins, in scan order.

    Entries are the section specs (``name``, ``title``, ``kinds``,
    ``render``, ``safe_render``) plus the owning ``plugin`` stem. Sections
    from different plugins never collide — render one through
    :func:`render_report_section` by bare name (first plugin wins) or by the
    qualified ``'<plugin>:<name>'`` form.
    """
    loaded_plugins()
    return list(_section_index.values())


def plugin_tools() -> Dict[str, Dict]:
    """
    Return ``{name: spec}`` for every MCP-exposed plugin tool.

    Specs carry ``description`` and ``handler(arguments: dict) -> dict``.
    Merged first-wins like :func:`plugin_commands`, with collisions recorded
    on the later plugin's surface.
    """
    loaded_plugins()
    return dict(_tool_index)


def plugin_analytics() -> Dict[str, Dict]:
    """
    Return ``{name: spec}`` for every plugin analytics hook.

    Specs carry ``description`` and ``run(payload: dict) -> dict`` — pure
    functions, no platform state required. Merged first-wins like
    :func:`plugin_commands`.
    """
    loaded_plugins()
    return dict(_analytics_index)


def plugin_meta_list() -> List[PluginMeta]:
    """
    Return the manifest of every loaded plugin, in scan order.

    Plugins without ``PLUGIN_META`` report the synthesised v1 manifest
    (name = file stem, version ``'1.0.0'``, ``requires_api`` 1).
    """
    loaded_plugins()
    return [info.surface.meta for info in (_cache or [])
            if info.surface is not None]


def render_report_section(name: str, envelope: Dict) -> List[str]:
    """
    Render one registered report section for a result envelope.

    Args:
        name: section name — either the bare ``<name>`` (first plugin that
            registered it wins) or the qualified ``<plugin>:<name>`` form.
        envelope: the result envelope the section renders. The reporting
            pipeline hands every section the tracker result dict augmented
            with ``kind``; sections can read ``envelope['kind']``,
            ``envelope['target']`` and any result fields they declared
            interest in via ``kinds``.

    Returns:
        The section's lines. Sections whose declared ``kinds`` do not cover
        the envelope's kind decline politely (``[]``), and a renderer that
        raises is caught by the loader-installed safe wrapper and turned
        into a visible one-line error instead — this function never raises.
        Unknown section names also return ``[]``.
    """
    loaded_plugins()
    kind = envelope.get('kind') if isinstance(envelope, dict) else None
    for key, entry in _section_index.items():
        if key == name or entry.get('name') == name:
            kinds = entry.get('kinds', 'all')
            if kinds != 'all' and kind not in kinds:
                return []
            return entry['safe_render'](envelope)
    return []


def validate_plugin_file(path) -> Dict:
    """
    Load one plugin file in isolation and report what the loader would find.

    This is the plugin developer's linter behind
    ``obscuralens plugins check <file>``: the file is imported under a
    throw-away module name (removed from ``sys.modules`` again afterwards,
    so a check never pollutes the real plugin cache), its surface is
    extracted with the exact production rules, and everything is returned
    as a JSON-safe dict::

        {
            'ok': bool,
            'meta': {...},            # PluginMeta.to_dict()
            'sources': {kind: [names]},
            'commands': {name: {'description', 'arguments'}},
            'report_sections': [{'name', 'title', 'kinds'}],
            'tools': {name: 'description'},
            'analytics': {name: 'description'},
            'errors': [[piece, reason], ...],
        }

    ``ok`` is true only when the file imports cleanly, declares at least one
    usable piece and records no validation errors (a ``requires_api`` newer
    than the platform therefore reports not-ok). Never raises.
    """
    report: Dict = {
        'ok': False,
        'meta': {},
        'sources': {},
        'commands': {},
        'report_sections': [],
        'tools': {},
        'analytics': {},
        'errors': [],
    }
    file_path = Path(path)
    if not file_path.is_file():
        report['errors'] = [('file', f'no such file: {file_path}')]
        return report

    digest = hashlib.sha1(str(file_path).encode('utf-8')).hexdigest()[:12]
    module_name = f'_obscuralens_plugin_check_{file_path.stem}_{digest}'
    try:
        spec = importlib.util.spec_from_file_location(module_name, str(file_path))
        if spec is None or spec.loader is None:
            raise ImportError(f'cannot create an import spec for {file_path}')
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(module_name, None)
    except Exception as exc:  # syntax error, missing dependency, ...
        report['errors'] = [('import', f'{type(exc).__name__}: {exc}')]
        return report

    surface = extract_plugin_surface(module)
    data = surface.to_dict()
    report['meta'] = data['meta']
    report['sources'] = data['sources']
    report['commands'] = data['commands']
    report['report_sections'] = data['report_sections']
    report['tools'] = data['tools']
    report['analytics'] = data['analytics']
    report['errors'] = data['errors']
    report['ok'] = (not surface.errors
                    and bool(surface.sources or surface.commands
                             or surface.report_sections or surface.tools
                             or surface.analytics))
    return report


def _merge_surface(info: PluginInfo) -> None:
    """Merge one plugin's validated surface into the global v2 registries."""
    surface = info.surface
    if surface is None:
        return

    for name in sorted(surface.commands):
        if name in _command_index:
            earlier = _command_index[name].get('plugin', '?')
            surface.errors.append(
                ('commands', f"command '{name}' skipped: already provided "
                             f"by plugin '{earlier}'"))
            continue
        _command_index[name] = dict(surface.commands[name], plugin=info.name)

    for name in sorted(surface.tools):
        if name in _tool_index:
            earlier = _tool_index[name].get('plugin', '?')
            surface.errors.append(
                ('tools', f"tool '{name}' skipped: already provided "
                          f"by plugin '{earlier}'"))
            continue
        _tool_index[name] = dict(surface.tools[name], plugin=info.name)

    for name in sorted(surface.analytics):
        if name in _analytics_index:
            earlier = _analytics_index[name].get('plugin', '?')
            surface.errors.append(
                ('analytics', f"analytics '{name}' skipped: already provided "
                              f"by plugin '{earlier}'"))
            continue
        _analytics_index[name] = dict(surface.analytics[name], plugin=info.name)

    for name in sorted(surface.report_sections):
        entry = dict(surface.report_sections[name], plugin=info.name)
        _section_index[f'{info.name}:{name}'] = entry


def _clear_v2_indexes() -> None:
    """Reset the merged v2 registries (called on every full rescan)."""
    _command_index.clear()
    _section_index.clear()
    _tool_index.clear()
    _analytics_index.clear()


def _load_file(path: Path) -> Tuple[PluginInfo, Dict[str, Dict[str, Callable]]]:
    """Import one plugin file and collect its valid sources; never raises.

    The v1 rules are kept: a module without a usable ``SOURCES`` dict is an
    error — unless it declares v2 features (commands, report sections, tools
    or analytics), in which case it is a legitimate v2 plugin that simply
    contributes no data sources. Either way the validated v2 surface is
    stored on :attr:`PluginInfo.surface` when the import succeeded.
    """
    info = PluginInfo(name=path.stem, path=str(path))
    try:
        module = _import_module(path)
    except Exception as exc:  # a broken plugin must not stop the scan
        info.error = f'{type(exc).__name__}: {exc}'
        return info, {}

    surface = extract_plugin_surface(module)  # validated, never raises
    info.surface = surface

    raw = getattr(module, 'SOURCES', None)
    if isinstance(raw, dict):
        sources = _extract_sources(raw)
    elif surface.has_v2_features():
        sources = {}  # a v2 plugin does not need SOURCES at all
    else:
        info.error = 'SOURCES is missing or not a dict'
        return info, {}

    info.kinds = sorted(sources)
    info.sources = {kind: sorted(sources[kind]) for kind in sorted(sources)}
    return info, sources


def _extract_sources(raw: Dict[object, object]) -> Dict[str, Dict[str, Callable]]:
    """Drop unknown kinds, non-dict kind mappings and non-callable entries."""
    found: Dict[str, Dict[str, Callable]] = {}
    for kind, entries in raw.items():
        if kind not in KNOWN_KINDS or not isinstance(entries, dict):
            continue
        valid = {
            name: reader
            for name, reader in entries.items()
            if isinstance(name, str) and callable(reader)
        }
        if valid:
            found[kind] = valid
    return found


def _import_module(path: Path) -> types.ModuleType:
    """Import a file under a unique, filesystem-independent module name."""
    module_name = _module_name(path)
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot create an import spec for {path}')

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    _module_names.append(module_name)
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


def _module_name(path: Path) -> str:
    """Build a unique module name so equal stems in different dirs coexist."""
    digest = hashlib.sha1(str(path).encode('utf-8')).hexdigest()[:12]
    return f'_obscuralens_plugin_{path.stem}_{digest}'


def _release_modules() -> None:
    """Remove every module imported by this loader from ``sys.modules``."""
    for module_name in _module_names:
        sys.modules.pop(module_name, None)
    _module_names.clear()
