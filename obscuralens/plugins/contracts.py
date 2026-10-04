"""
Plugin SDK v2 contracts: the rich plugin surface ObscuraLens understands.

A v1 plugin is a ``*.py`` file with a module-level ``SOURCES`` dict (see the
package :mod:`obscuralens.plugins` loader). Plugin SDK v2 keeps that contract
untouched and adds four optional, independently usable pieces plus a manifest:

=================  ==================================  ============================
Piece              Module-level attribute              Purpose
=================  ==================================  ============================
manifest           ``PLUGIN_META`` (dict)               name/version/author/api
data sources       ``SOURCES`` (dict)                   v1 contract, unchanged
commands           ``COMMANDS`` (dict)                  CLI subcommands
report sections    ``REPORT_SECTIONS`` (dict)           extra report blocks
MCP tools          ``TOOLS`` (dict)                     tool handlers
analytics hooks    ``ANALYTICS`` (dict)                 pure functions
=================  ==================================  ============================

Every piece is optional and validated independently: a plugin that gets one
piece wrong still loads, the malformed piece is dropped and the reason is
recorded in :attr:`PluginSurface.errors`. Nothing in this module ever raises
for a badly shaped plugin — plugin authors get their feedback from
:func:`obscuralens.plugins.validate_plugin_file` (the ``obscuralens plugins
check <file>`` subcommand) instead of a crashed scan.

API version gating: the loader speaks plugin API 2 (:data:`SUPPORTED_PLUGIN_API`).
A plugin whose ``PLUGIN_META['requires_api']`` is greater than 2 keeps its
``SOURCES`` (v1 always loads) but has its v2 features skipped with an error
entry, so future API revisions degrade gracefully on old installations.

See ``docs/plugins.md`` for the full authoring guide and
``plugins-examples/`` for shipped, documented example plugins.
"""

import argparse
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

__all__ = [
    'KNOWN_KINDS',
    'PluginAnalytics',
    'PluginCommand',
    'PluginContext',
    'PluginHTTP',
    'PluginMeta',
    'PluginReportSection',
    'PluginSurface',
    'PluginTool',
    'SUPPORTED_PLUGIN_API',
    'build_plugin_argument_parser',
    'extract_plugin_surface',
]

#: Plugin API version implemented by this module. Plugins declaring a higher
#: ``requires_api`` keep their v1 ``SOURCES`` but have v2 features skipped.
SUPPORTED_PLUGIN_API = 2

#: Target kinds a tracker can feed to plugin sources (mirrors the platform
#: KINDS registries: the original five, the v4.0/v5.0 additions and the six
#: v6.0 sensor kinds). Unknown kinds are ignored during extraction.
KNOWN_KINDS = ('ip', 'phone', 'username', 'email', 'domain', 'url', 'crypto',
               'hash', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords',
               'vin', 'flight', 'mmsi', 'app', 'bssid', 'plate')


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

@dataclass
class PluginMeta:
    """
    Plugin manifest, parsed from the module-level ``PLUGIN_META`` dict.

    Attributes:
        name: display name of the plugin. Defaults to the file name stem
            (without ``.py``) when the manifest omits it.
        version: plugin version string (no format enforced; semver
            recommended). Defaults to ``'1.0.0'``.
        author: free-form author or team name.
        description: one-line human description shown by
            ``obscuralens plugins list``.
        license: SPDX identifier or license name (e.g. ``'MIT'``).
        url: project/homepage URL for the plugin.
        requires_api: plugin API version the plugin was written for. The
            platform supports :data:`SUPPORTED_PLUGIN_API`; a plugin asking
            for more keeps v1 ``SOURCES`` support but has its v2 features
            skipped. Defaults to 2 (an explicit ``PLUGIN_META`` is a v2
            plugin); a plugin without any ``PLUGIN_META`` is synthesised
            with ``requires_api = 1``.

    A plugin without ``PLUGIN_META`` gets a synthesised manifest: name =
    module file stem, version ``'1.0.0'``, ``requires_api`` 1. All scalar
    fields are string-coerced; a non-int ``requires_api`` falls back to 1 and
    is reported as a validation error.
    """

    name: str = ''
    version: str = '1.0.0'
    author: str = ''
    description: str = ''
    license: str = ''
    url: str = ''
    requires_api: int = 2

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], fallback_name: str = '') -> 'PluginMeta':
        """
        Build a manifest from a ``PLUGIN_META`` dict, coercing scalar types.

        Unknown keys are ignored; missing keys keep their defaults. This
        never raises: junk values degrade to the defaults documented on the
        dataclass.
        """
        meta = cls()
        if not isinstance(raw, dict):
            meta.name = str(fallback_name or '')
            meta.requires_api = 1
            return meta
        meta.name = _text(raw.get('name'), fallback_name)
        meta.version = _text(raw.get('version'), '1.0.0')
        meta.author = _text(raw.get('author'), '')
        meta.description = _text(raw.get('description'), '')
        meta.license = _text(raw.get('license'), '')
        meta.url = _text(raw.get('url'), '')
        meta.requires_api = _as_int(raw.get('requires_api'), 2)
        return meta

    @classmethod
    def synthesized(cls, module: Any) -> 'PluginMeta':
        """Return the v1 manifest for a module without ``PLUGIN_META``."""
        meta = cls()
        meta.name = _module_stem(module)
        meta.version = '1.0.0'
        meta.requires_api = 1
        return meta

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe dict of the manifest."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'license': self.license,
            'url': self.url,
            'requires_api': self.requires_api,
        }

    def summary(self) -> str:
        """One-line ``name version (api N)`` summary for tables and logs."""
        return f'{self.name} {self.version} (api {self.requires_api})'


def _text(value: Any, default: str = '') -> str:
    """Coerce a scalar to ``str``; anything unpresentable becomes default."""
    if value is None:
        return default
    try:
        text = str(value)
    except Exception:  # pragma: no cover - str() basically never fails
        return default
    return text if text else default


def _as_int(value: Any, default: int) -> int:
    """Coerce to ``int`` (bools rejected); return ``default`` when impossible."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _module_stem(module: Any) -> str:
    """Best-effort file stem of a module ('' when it has no ``__file__``)."""
    file_name = getattr(module, '__file__', None)
    if not file_name:
        name = getattr(module, '__name__', '') or ''
        return name.rsplit('.', 1)[-1].replace('_obscuralens_plugin_', '')
    try:
        return Path(str(file_name)).stem
    except Exception:  # pragma: no cover - Path() on weird __file__ values
        return ''


# ---------------------------------------------------------------------------
# Runtime context
# ---------------------------------------------------------------------------

class PluginHTTP:
    """
    Minimal HTTP helper handed to plugins through ``ctx.http``.

    It wraps the platform HTTP client (:mod:`obscuralens.utils.http_client`),
    so plugins automatically share its timeouts, retries, proxy settings,
    rate limiting, response cache and metrics — there is no way for a plugin
    to smuggle in a raw ``requests`` call with different behaviour.

    Both methods never raise and return ``None`` on any failure (offline,
    timeout, non-2xx, unparseable body), matching the plugin philosophy that
    ordinary errors are values, not exceptions.
    """

    def get(self, url: str, params: Optional[Dict[str, Any]] = None,
            use_cache: bool = True) -> Optional[Any]:
        """
        GET ``url`` (optionally with query ``params``) and parse JSON.

        Returns:
            The parsed JSON value on success, otherwise ``None``.
        """
        from ..utils import http_client

        try:
            ok, data, _error = http_client.get_json(
                url, params=params, use_cache=use_cache)
        except Exception:
            return None
        return data if ok else None

    def get_text(self, url: str, params: Optional[Dict[str, Any]] = None,
                 use_cache: bool = True) -> Optional[str]:
        """
        GET ``url`` and return the response body as text (``None`` on failure).

        Text bodies larger than the platform cache cap are not cached.
        """
        from ..utils import http_client

        try:
            client = getattr(http_client, 'http', None)
            if client is None:  # pragma: no cover - singleton always exists
                return None
            ok, text, _error = client.get_text(
                url, params=params, use_cache=use_cache)
        except Exception:
            return None
        return text if ok else None


@dataclass
class PluginContext:
    """
    The runtime handle bundle every plugin command handler receives.

    Handlers are called as ``handler(args, ctx)`` where ``args`` is the
    :class:`argparse.Namespace` built from the command's declared arguments
    and ``ctx`` is a fresh :class:`PluginContext`. All platform handles are
    resolved lazily on first property access, so a plugin that only prints a
    greeting never touches the database, the cache or the metrics registry.

    Properties:
        config: the live :class:`~obscuralens.config.Config` singleton
            (``config.app_config``, service keys, ...).
        db: the shared :class:`~obscuralens.database.DatabaseManager`
            singleton (history queries, stored results).
        cache: the HTTP response :class:`~obscuralens.core.cache.HttpCache`
            singleton (``get``/``set``/``clear`` by namespace and key).
        metrics: the :class:`~obscuralens.core.metrics.NetworkMetrics`
            singleton (``snapshot()`` for request/cache/failure counters).
        http: a :class:`PluginHTTP` helper (``get``/``get_text``, never
            raises, uses the platform HTTP client underneath).
        temp_dir: a per-user scratch directory (created on first access,
            then cached) suitable for plugin output files.

    Example:
        ::

            def handle_db_peek(args, ctx):
                rows = ctx.db.get_history(limit=500)
                print(f'{len(rows)} history rows')
                return 0
    """

    _handles: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def config(self) -> Any:
        """The platform configuration singleton (imported lazily)."""
        if 'config' not in self._handles:
            from ..config import config
            self._handles['config'] = config
        return self._handles['config']

    @property
    def db(self) -> Any:
        """The platform database singleton (imported lazily)."""
        if 'db' not in self._handles:
            from ..database import db
            self._handles['db'] = db
        return self._handles['db']

    @property
    def cache(self) -> Any:
        """The HTTP response cache singleton (imported lazily)."""
        if 'cache' not in self._handles:
            from ..core.cache import cache
            self._handles['cache'] = cache
        return self._handles['cache']

    @property
    def metrics(self) -> Any:
        """The network metrics singleton (imported lazily)."""
        if 'metrics' not in self._handles:
            from ..core.metrics import metrics
            self._handles['metrics'] = metrics
        return self._handles['metrics']

    @property
    def http(self) -> PluginHTTP:
        """A never-raising HTTP helper backed by the platform client."""
        if 'http' not in self._handles:
            self._handles['http'] = PluginHTTP()
        return self._handles['http']

    @property
    def temp_dir(self) -> Path:
        """A scratch directory for plugin files (created on first access)."""
        if 'temp_dir' not in self._handles:
            path = Path(tempfile.gettempdir()) / 'obscuralens-plugins'
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError:  # pragma: no cover - unwritable temp dir
                path = Path(tempfile.gettempdir())
            self._handles['temp_dir'] = path
        return self._handles['temp_dir']


# ---------------------------------------------------------------------------
# Surface extraction
# ---------------------------------------------------------------------------

@dataclass
class PluginSurface:
    """
    Everything the loader found on one plugin module, validated per piece.

    Attributes:
        meta: the parsed (or synthesised) :class:`PluginMeta`.
        sources: ``{kind: {name: callable}}`` — the v1 contract, extracted
            with the same rules the v1 loader applies.
        commands: ``{name: spec}`` where spec has ``description``,
            ``handler``, ``arguments`` (normalised dicts) and, once merged
            by the loader, ``plugin``.
        report_sections: ``{name: spec}`` with ``title``, ``kinds``
            (``'all'`` or a tuple of kinds), ``render`` (the raw callable)
            and ``safe_render`` (a wrapped callable that never raises).
        tools: ``{name: {'description', 'handler'}}`` for MCP exposure.
        analytics: ``{name: {'description', 'run'}}`` pure-function hooks.
        errors: list of ``(piece, reason)`` tuples describing every dropped
            or skipped piece. Always plain strings; safe to print and to
            serialise.
    """

    meta: PluginMeta = field(default_factory=PluginMeta)
    sources: Dict[str, Dict[str, Callable]] = field(default_factory=dict)
    commands: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    report_sections: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    analytics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    errors: List[Tuple[str, str]] = field(default_factory=list)

    def has_v2_features(self) -> bool:
        """True when the plugin declares any v2 piece at all."""
        return bool(self.commands or self.report_sections or self.tools
                    or self.analytics)

    def summary(self) -> str:
        """Compact counts string like ``2 cmd, 1 sec, 3 tools, 0 analytics``."""
        return (f'{len(self.commands)} cmd, {len(self.report_sections)} sec, '
                f'{len(self.tools)} tools, {len(self.analytics)} analytics')

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe projection (callables are stripped) for reports/CLI."""
        return {
            'meta': self.meta.to_dict(),
            'sources': {kind: sorted(names)
                        for kind, names in self.sources.items()},
            'commands': {
                name: {'description': spec.get('description', ''),
                       'arguments': [dict(arg) for arg in spec.get('arguments', [])]}
                for name, spec in self.commands.items()},
            'report_sections': [
                {'name': name, 'title': spec.get('title', ''),
                 'kinds': list(spec['kinds']) if spec.get('kinds') != 'all' else 'all'}
                for name, spec in self.report_sections.items()],
            'tools': {name: spec.get('description', '')
                      for name, spec in self.tools.items()},
            'analytics': {name: spec.get('description', '')
                          for name, spec in self.analytics.items()},
            'errors': [[piece, reason] for piece, reason in self.errors],
        }


def extract_plugin_surface(module: Any) -> PluginSurface:
    """
    Inspect one imported plugin module and collect its validated v2 surface.

    The module is only read through :func:`getattr`; this function never
    raises and never imports the plugin's own dependencies. Piece by piece:

    * ``PLUGIN_META`` non-dict → error ``('meta', ...)`` + synthesised meta.
    * ``SOURCES`` non-dict → error ``('sources', ...)``; dict entries are
      filtered with the v1 rules (unknown kinds dropped silently, exactly
      like the v1 loader).
    * ``COMMANDS`` / ``REPORT_SECTIONS`` / ``TOOLS`` / ``ANALYTICS`` are
      validated entry by entry; malformed entries are dropped with a
      ``('commands'|'report_sections'|'tools'|'analytics', reason)`` error.

    API gating: when ``meta.requires_api`` exceeds
    :data:`SUPPORTED_PLUGIN_API`, the four v2 pieces are skipped entirely and
    an ``('api', 'requires_api N > 2')`` error is recorded; ``SOURCES`` is
    still extracted because the v1 contract is forever backward compatible.
    """
    surface = PluginSurface()

    raw_meta = getattr(module, 'PLUGIN_META', None)
    if raw_meta is None:
        surface.meta = PluginMeta.synthesized(module)
    elif isinstance(raw_meta, dict):
        surface.meta = PluginMeta.from_dict(raw_meta, _module_stem(module))
        if not isinstance(raw_meta.get('requires_api'), int) \
                or isinstance(raw_meta.get('requires_api'), bool):
            surface.errors.append(
                ('meta', 'requires_api is not an int; assuming 1'))
            surface.meta.requires_api = 1
    else:
        surface.meta = PluginMeta.synthesized(module)
        surface.errors.append(
            ('meta', f'PLUGIN_META is {type(raw_meta).__name__}, not a dict'))

    surface.sources = _extract_sources(getattr(module, 'SOURCES', None),
                                       surface.errors)

    if surface.meta.requires_api > SUPPORTED_PLUGIN_API:
        surface.errors.append(
            ('api', f'requires_api {surface.meta.requires_api} > '
                    f'{SUPPORTED_PLUGIN_API}'))
        return surface

    surface.commands = _extract_commands(
        getattr(module, 'COMMANDS', None), surface.errors)
    surface.report_sections = _extract_report_sections(
        getattr(module, 'REPORT_SECTIONS', None), surface.errors)
    surface.tools = _extract_tools(
        getattr(module, 'TOOLS', None), surface.errors)
    surface.analytics = _extract_analytics(
        getattr(module, 'ANALYTICS', None), surface.errors)
    return surface


# --- typed spec aliases (documentation helpers) ----------------------------

@dataclass
class PluginCommand:
    """
    Normalised ``COMMANDS`` entry (documentation view of the spec dict).

    The loader stores plain dicts (see :class:`PluginSurface`); this dataclass
    documents the exact shape and is used by tests as the reference contract.
    """

    name: str
    description: str = ''
    handler: Optional[Callable[[argparse.Namespace, PluginContext], int]] = None
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    plugin: str = ''

    def to_spec(self) -> Dict[str, Any]:
        """Convert back to the loader's dict form."""
        return {'name': self.name, 'description': self.description,
                'handler': self.handler, 'arguments': self.arguments,
                'plugin': self.plugin}


@dataclass
class PluginReportSection:
    """Normalised ``REPORT_SECTIONS`` entry (documentation view)."""

    name: str
    title: str = ''
    kinds: Union[str, Tuple[str, ...]] = 'all'
    render: Optional[Callable[[Dict[str, Any]], List[str]]] = None
    plugin: str = ''


@dataclass
class PluginTool:
    """Normalised ``TOOLS`` entry (documentation view)."""

    name: str
    description: str = ''
    handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
    plugin: str = ''


@dataclass
class PluginAnalytics:
    """Normalised ``ANALYTICS`` entry (documentation view)."""

    name: str
    description: str = ''
    run: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
    plugin: str = ''


# --- per-piece extractors ---------------------------------------------------

def _extract_sources(raw: Any, errors: List[Tuple[str, str]]
                     ) -> Dict[str, Dict[str, Callable]]:
    """Apply the v1 source rules; record one error when SOURCES is malformed."""
    if raw is None:
        return {}  # a v2 plugin may legitimately declare no sources at all
    if not isinstance(raw, dict):
        errors.append(('sources', f'SOURCES is {type(raw).__name__}, not a dict'))
        return {}

    found: Dict[str, Dict[str, Callable]] = {}
    for kind, entries in raw.items():
        if kind not in KNOWN_KINDS or not isinstance(entries, dict):
            continue  # unknown kinds are silently ignored, as in v1
        valid = {
            name: reader
            for name, reader in entries.items()
            if isinstance(name, str) and callable(reader)
        }
        if valid:
            found[kind] = valid
    return found


def _is_usable_name(name: Any) -> bool:
    """
    True when an argument name builds a valid argparse dest.

    Positional names must be plain identifiers; option names may carry any
    number of leading dashes and hyphens inside (``--db-peek`` -> dest
    ``db_peek``).
    """
    if not isinstance(name, str) or not name:
        return False
    probe = (name.lstrip('-').replace('-', '_') if name.startswith('-')
             else name.replace('-', '_'))
    return bool(probe) and probe.isidentifier()


def _extract_commands(raw: Any, errors: List[Tuple[str, str]]
                      ) -> Dict[str, Dict[str, Any]]:
    """Validate the ``COMMANDS`` mapping; drop bad entries with reasons."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        errors.append(('commands', f'COMMANDS is {type(raw).__name__}, not a dict'))
        return {}

    commands: Dict[str, Dict[str, Any]] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not name:
            errors.append(('commands', f'command key {name!r} is not a name'))
            continue
        if not isinstance(spec, dict):
            errors.append(('commands', f"command '{name}': spec is "
                                       f'{type(spec).__name__}, not a dict'))
            continue
        handler = spec.get('handler')
        if not callable(handler):
            errors.append(('commands', f"command '{name}': handler is "
                                       'missing or not callable'))
            continue
        arguments, arg_errors = _normalize_arguments(
            spec.get('arguments'), name)
        errors.extend(arg_errors)
        commands[name] = {
            'name': name,
            'description': _text(spec.get('description'), ''),
            'handler': handler,
            'arguments': arguments,
        }
    return commands


def _normalize_arguments(raw: Any, command: str
                         ) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]]]:
    """
    Normalise the ``arguments`` list of one command.

    Each argument dict may declare ``name`` (required — a positional name or
    an option spelling like ``--name``), ``help``, ``required`` (bool),
    ``default`` and optionally ``choices`` (list of allowed values). Malformed
    entries are dropped with a recorded reason instead of poisoning the
    command.
    """
    errors: List[Tuple[str, str]] = []
    if raw is None:
        return [], errors
    if not isinstance(raw, (list, tuple)):
        errors.append(('commands', f"command '{command}': arguments is "
                                   f'{type(raw).__name__}, not a list'))
        return [], errors

    normalized: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            errors.append(('commands', f"command '{command}': argument "
                                       f'{item!r} is not a dict'))
            continue
        name = item.get('name')
        if not _is_usable_name(name):
            errors.append(('commands', f"command '{command}': argument name "
                                       f'{name!r} is not usable'))
            continue
        choices = item.get('choices')
        if not isinstance(choices, (list, tuple)) or not choices:
            choices = None
        normalized.append({
            'name': name,
            'help': _text(item.get('help'), ''),
            'required': bool(item.get('required', False)),
            'default': item.get('default'),
            'choices': list(choices) if choices else None,
        })
    return normalized, errors


def _extract_report_sections(raw: Any, errors: List[Tuple[str, str]]
                             ) -> Dict[str, Dict[str, Any]]:
    """Validate ``REPORT_SECTIONS``; wrap renderers so they can never raise."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        errors.append(('report_sections',
                       f'REPORT_SECTIONS is {type(raw).__name__}, not a dict'))
        return {}

    sections: Dict[str, Dict[str, Any]] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not name:
            errors.append(('report_sections',
                           f'section key {name!r} is not a name'))
            continue
        if not isinstance(spec, dict):
            errors.append(('report_sections', f"section '{name}': spec is "
                                              f'{type(spec).__name__}, not a dict'))
            continue
        render = spec.get('render')
        if not callable(render):
            errors.append(('report_sections', f"section '{name}': render is "
                                              'missing or not callable'))
            continue
        kinds = _normalize_kinds(spec.get('kinds'))
        if kinds is None:
            errors.append(('report_sections', f"section '{name}': kinds is "
                                              'not a kind list'))
            continue
        sections[name] = {
            'name': name,
            'title': _text(spec.get('title'), name),
            'kinds': kinds,
            'render': render,
            'safe_render': _wrap_render(name, render),
        }
    return sections


def _normalize_kinds(raw: Any) -> Union[None, str, Tuple[str, ...]]:
    """
    Accept ``'all'``, a single kind string or an iterable of kind strings.

    Returns ``None`` (invalid) for anything else so the caller can record a
    precise error.
    """
    if raw is None:
        return 'all'
    if isinstance(raw, str):
        return 'all' if raw == 'all' else (raw,)
    if isinstance(raw, (list, tuple, set, frozenset)):
        kinds = tuple(sorted({str(kind) for kind in raw}))
        return kinds or 'all'
    return None


def _wrap_render(section: str, render: Callable
                 ) -> Callable[[Dict[str, Any]], List[str]]:
    """
    Wrap a section renderer so it can never raise and always returns lines.

    The wrapped callable also tolerates plugins that return a bare string or
    a non-list value, converting everything into a list of plain strings and
    substituting a visible error line on failure.
    """
    def safe_render(envelope: Dict[str, Any]) -> List[str]:
        try:
            produced = render(envelope)
        except Exception as exc:  # a broken plugin section must not kill a report
            return [f"<plugin section '{section}' failed: "
                    f'{type(exc).__name__}: {exc}>']
        if isinstance(produced, str):
            return produced.splitlines()
        if isinstance(produced, (list, tuple)):
            return [str(line) for line in produced]
        return [f"<plugin section '{section}' returned "
                f'{type(produced).__name__}, expected a list of lines>']

    return safe_render


def _extract_tools(raw: Any, errors: List[Tuple[str, str]]
                   ) -> Dict[str, Dict[str, Any]]:
    """Validate the ``TOOLS`` mapping for MCP exposure."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        errors.append(('tools', f'TOOLS is {type(raw).__name__}, not a dict'))
        return {}

    tools: Dict[str, Dict[str, Any]] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not name:
            errors.append(('tools', f'tool key {name!r} is not a name'))
            continue
        if not isinstance(spec, dict):
            errors.append(('tools', f"tool '{name}': spec is "
                                    f'{type(spec).__name__}, not a dict'))
            continue
        handler = spec.get('handler')
        if not callable(handler):
            errors.append(('tools', f"tool '{name}': handler is missing "
                                    'or not callable'))
            continue
        tools[name] = {
            'name': name,
            'description': _text(spec.get('description'), ''),
            'handler': handler,
        }
    return tools


def _extract_analytics(raw: Any, errors: List[Tuple[str, str]]
                       ) -> Dict[str, Dict[str, Any]]:
    """Validate the ``ANALYTICS`` mapping of pure-function hooks."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        errors.append(('analytics',
                       f'ANALYTICS is {type(raw).__name__}, not a dict'))
        return {}

    analytics: Dict[str, Dict[str, Any]] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not name:
            errors.append(('analytics', f'analytics key {name!r} is not a name'))
            continue
        if not isinstance(spec, dict):
            errors.append(('analytics', f"analytics '{name}': spec is "
                                        f'{type(spec).__name__}, not a dict'))
            continue
        run = spec.get('run')
        if not callable(run):
            errors.append(('analytics', f"analytics '{name}': run is missing "
                                        'or not callable'))
            continue
        analytics[name] = {
            'name': name,
            'description': _text(spec.get('description'), ''),
            'run': run,
        }
    return analytics


# ---------------------------------------------------------------------------
# Command dispatch helper
# ---------------------------------------------------------------------------

def build_plugin_argument_parser(command: str, spec: Dict[str, Any],
                                 plugin: str = '') -> argparse.ArgumentParser:
    """
    Build the argument parser for one plugin command.

    Used by ``obscuralens plugins run <command>`` and safe to reuse in tests.
    The parser's ``prog`` looks like
    ``obscuralens plugins run <command>`` so usage errors read naturally.

    Arguments whose ``name`` starts with ``-`` become options (honouring
    ``required``/``default``/``choices``); plain names become positionals
    (optional ones use ``nargs='?'`` with the declared default).
    """
    plugin_label = f' [{plugin}]' if plugin else ''
    parser = argparse.ArgumentParser(
        prog=f'obscuralens plugins run {command}',
        description=(_text(spec.get('description'), '')
                     or f'Plugin command {command!r}{plugin_label}'))

    for arg in spec.get('arguments', []) or []:
        name = arg.get('name', '')
        help_text = arg.get('help', '')
        choices = arg.get('choices') or None
        if name.startswith('-'):
            parser.add_argument(
                name, required=bool(arg.get('required', False)),
                default=arg.get('default'), choices=choices,
                help=help_text or None)
        else:
            if arg.get('required', False):
                parser.add_argument(name, choices=choices, help=help_text or None)
            else:
                parser.add_argument(name, nargs='?', default=arg.get('default'),
                                    choices=choices, help=help_text or None)
    return parser
