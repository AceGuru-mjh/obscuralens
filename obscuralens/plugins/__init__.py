"""
Plugin loader for user-supplied OSINT data sources.

A plugin is a ``*.py`` file dropped into one of the directories returned by
:func:`plugin_paths` (plain modules are scanned, not packages). Files whose
names start with ``_`` are ignored, so helper modules may live next to
plugins. Every plugin module must define a module-level ``SOURCES`` dict::

    SOURCES = {
        'ip': {'example': lookup_ip},
        'domain': {'example': lookup_domain},
    }

Supported kinds are ``ip``, ``phone``, ``username``, ``email`` and
``domain``; unknown kinds are ignored. Each source is a callable that takes
the target as a single string and returns a ``dict`` of fields, using the same
contract as the built-in readers: return ``{}`` on failure and never raise for
ordinary errors (unexpected exceptions are still caught and isolated per
source by the trackers).

Loading is lazy, cached and error-isolated: a module that raises while
importing, or that defines a missing or malformed ``SOURCES`` mapping, is
skipped and reported through :attr:`PluginInfo.error` without affecting the
other plugins. ``app.enable_plugins`` (default ``True``) switches the whole
mechanism off.

Source names are returned unprefixed by :func:`plugin_sources`; the tracker
integration exposes them in results as ``plugin:<file>:<name>``.
"""

import hashlib
import importlib.util
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ..config import config

__all__ = [
    'PluginInfo',
    'load_plugins',
    'loaded_plugins',
    'plugin_paths',
    'plugin_sources',
    'plugin_sources_named',
    'reload_plugins',
]

# Target kinds a tracker can feed to plugin sources. Other kinds are ignored.
KNOWN_KINDS = ('ip', 'phone', 'username', 'email', 'domain')


@dataclass
class PluginInfo:
    """Metadata for a single plugin file discovered on disk."""

    name: str
    path: str
    kinds: List[str] = field(default_factory=list)
    sources: Dict[str, List[str]] = field(default_factory=dict)
    error: str = ''


# Cache of the last scan, plus the callables behind PluginInfo.sources.
_cache: Optional[List[PluginInfo]] = None
_source_index: Dict[str, Dict[str, Callable]] = {}
_named_index: Dict[str, Dict[str, Callable]] = {}
_module_names: List[str] = []


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
        _cache = []
        return []

    if _cache is not None and not force:
        return list(_cache)

    _release_modules()
    _source_index.clear()
    _named_index.clear()
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


def _load_file(path: Path) -> Tuple[PluginInfo, Dict[str, Dict[str, Callable]]]:
    """Import one plugin file and collect its valid sources; never raises."""
    info = PluginInfo(name=path.stem, path=str(path))
    try:
        module = _import_module(path)
    except Exception as exc:  # a broken plugin must not stop the scan
        info.error = f'{type(exc).__name__}: {exc}'
        return info, {}

    raw = getattr(module, 'SOURCES', None)
    if not isinstance(raw, dict):
        info.error = 'SOURCES is missing or not a dict'
        return info, {}

    sources = _extract_sources(raw)
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
