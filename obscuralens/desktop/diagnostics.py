"""
Diagnostics for the ObscuraLens desktop edition.

``obscuralens-desktop --diagnostics`` (and ``collect_diagnostics`` /
``render_diagnostics`` / ``diagnostics_report`` from the package root)
assemble a full environment report: Python, platform, frozen-build status,
config paths, optional-dependency availability, offline data-pack stats
and -- on request -- a network reachability probe.

Rules:

* **Offline by default.**  The optional network probe only runs when
  ``check_network=True`` and never raises, even offline.
* **Import-light.**  Module-level imports are standard library only.  The
  ``obscuralens.config`` manager (which imports PyYAML and touches disk)
  and the data-pack loader are imported *inside* the collection function
  behind guards, so importing this module is free.
* **Pure ASCII output**, consistent with the desktop banner, so the report
  renders on a stock Windows ``cmd.exe``.
"""

import contextlib
import json
import os
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .. import __desktop_channel__, __version__

#: Product name used in report headers.
DESKTOP_NAME = "ObscuraLens Desktop"

#: Optional dependencies worth reporting, as ``(import_name, purpose)``.
TRACKED_DEPENDENCIES: Tuple[Tuple[str, str], ...] = (
    ("requests", "core: HTTP client for the data sources"),
    ("yaml", "core: PyYAML, config/rule-pack parsing"),
    ("jinja2", "core: report templates"),
    ("fastapi", "web extra: local web UI and REST API"),
    ("uvicorn", "web extra: ASGI server for the desktop launcher"),
    ("textual", "tui extra: terminal user interface"),
    ("matplotlib", "core: charts inside reports"),
    ("numpy", "core: numerical helpers for charts"),
    ("reportlab", "core: PDF report generation"),
    ("phonenumbers", "core: phone number parsing"),
    ("PyInstaller", "exe extra: builds the frozen desktop binary"),
)

#: Import-name -> distribution name (for importlib.metadata.version).
_DISTRIBUTION_NAMES: Dict[str, str] = {
    "yaml": "PyYAML",
    "PyInstaller": "pyinstaller",
}

#: Value reported for modules without a discoverable version.
UNKNOWN_VERSION = "unknown"


# ---------------------------------------------------------------------------
# Dependency probing
# ---------------------------------------------------------------------------

@dataclass
class DependencyStatus:
    """Availability + version of one optional dependency."""

    #: Import name that was probed (``yaml``, ``fastapi``, ...).
    module: str
    #: Whether the module can be imported in this interpreter.
    importable: bool
    #: Installed distribution version, or ``"unknown"``.
    version: str
    #: Why this dependency matters (shown in the rendered table).
    note: str


def _module_version(module: str) -> str:
    """Best-effort distribution version for an import name."""
    try:
        from importlib import metadata
    except ImportError:  # pragma: no cover - Python < 3.8
        return UNKNOWN_VERSION
    candidates = [module]
    mapped = _DISTRIBUTION_NAMES.get(module)
    if mapped:
        candidates.append(mapped)
    for candidate in candidates:
        try:
            return str(metadata.version(candidate))
        except Exception:
            continue
    return UNKNOWN_VERSION


def check_dependency(module: str, note: str = "") -> DependencyStatus:
    """
    Probe one module with ``importlib.util.find_spec`` (never raises).

    ``find_spec`` answers without importing the module, so probing
    ``matplotlib`` or ``PyInstaller`` does not pay their import cost or
    trigger their side effects.
    """
    importable = False
    try:
        import importlib.util

        importable = importlib.util.find_spec(module) is not None
    except Exception:
        importable = False
    return DependencyStatus(
        module=module,
        importable=importable,
        version=_module_version(module) if importable else UNKNOWN_VERSION,
        note=note,
    )


def collect_dependencies() -> List[DependencyStatus]:
    """Probe every tracked dependency (order matches the registry above)."""
    return [
        check_dependency(module, note)
        for module, note in TRACKED_DEPENDENCIES
    ]


# ---------------------------------------------------------------------------
# Section collectors
# ---------------------------------------------------------------------------

def _python_section() -> Dict[str, Any]:
    return {
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": sys.platform,
        "machine": platform.machine(),
        "processor": platform.processor() or "",
        "executable": sys.executable,
        "argv0": sys.argv[0] if sys.argv else "",
    }


def _app_section() -> Dict[str, Any]:
    return {
        "name": DESKTOP_NAME,
        "version": __version__,
        "channel": __desktop_channel__,
        "frozen": bool(getattr(sys, "frozen", False)),
        "exe_path": sys.executable,
    }


def _paths_section() -> Dict[str, Any]:
    """
    Config paths from the shared config manager.

    ``obscuralens.config`` is imported lazily (it pulls PyYAML and reads
    YAML from disk at import time); relative database/cache paths are
    resolved against the current directory so the report shows where the
    files really land.
    """
    try:
        from ..config import config

        db_path = Path(str(config.db_config.sqlite_path or ""))
        cache_path = Path(str(config.app_config.cache_path or ""))
        return {
            "config_dir": str(config.config_dir),
            "database": str(db_path if db_path.is_absolute() else Path.cwd() / db_path),
            "cache": str(cache_path if cache_path.is_absolute() else Path.cwd() / cache_path),
            "report_dir": str(config.app_config.report_dir or ""),
        }
    except Exception as exc:
        return {"error": "config unavailable: {0}".format(exc)}


def _data_pack_stats(module: Any) -> List[Dict[str, Any]]:
    """Per-pack stats (name, entries, size) for the offline data packs."""
    stats: List[Dict[str, Any]] = []
    data_dir = Path(module.DATA_DIR)
    try:
        files = sorted(data_dir.glob("*.txt"))
    except OSError:
        return stats
    for path in files:
        entry = {
            "name": path.stem,
            "file": path.name,
            "entries": 0,
            "bytes": 0,
        }
        try:
            entry["bytes"] = path.stat().st_size
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                entry["entries"] = sum(1 for line in handle if line.strip())
        except OSError:
            continue
        stats.append(entry)
    return stats


def _data_packs_section() -> Dict[str, Any]:
    try:
        from ..utils import data_packs

        packs = _data_pack_stats(data_packs)
        return {
            "available": True,
            "directory": str(getattr(data_packs, "DATA_DIR", "")),
            "packs": packs,
            "pack_count": len(packs),
            "entries_total": sum(int(pack["entries"]) for pack in packs),
        }
    except Exception as exc:
        return {"available": False, "error": "data packs unavailable: {0}".format(exc)}


def _locale_name() -> str:
    for variable in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        value = os.environ.get(variable)
        if value:
            return value
    try:
        import locale

        with contextlib.suppress(Exception):
            current = locale.getlocale()
            if current and current[0]:
                return str(current[0])
    except Exception:  # pragma: no cover - exotic locale failures
        return "unknown"
    return "unknown"


def _preferred_encoding() -> str:
    try:
        import locale

        return locale.getpreferredencoding(False) or "unknown"
    except Exception:  # pragma: no cover
        return "unknown"


def _environment_section() -> Dict[str, Any]:
    return {
        "cwd": os.getcwd(),
        "argv": list(sys.argv),
        "locale": _locale_name(),
        "encoding": _preferred_encoding(),
        "config_dir_env": os.environ.get("OBSCURALENS_CONFIG_DIR", ""),
        "pythonpath_set": bool(os.environ.get("PYTHONPATH")),
        "no_color": bool(os.environ.get("NO_COLOR") or os.environ.get("OBSCURALENS_NO_COLOR")),
    }


def _network_reachable(timeout: float = 5.0) -> bool:
    """
    HEAD ``https://github.com`` with urllib; ``False`` on any failure.

    Used by ``collect_diagnostics(check_network=True)`` only.  Never
    raises; a timeout, a DNS failure or a proxy refusal all count as
    "unreachable".
    """
    try:
        import urllib.error
        import urllib.request

        request = urllib.request.Request(
            "https://github.com",
            method="HEAD",
            headers={"User-Agent": "ObscuraLens-Desktop/{0}".format(__version__)},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200) or 200)
            return status < 500
    except urllib.error.HTTPError:
        return True  # any HTTP answer proves reachability
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def collect_diagnostics(check_network: bool = False) -> Dict[str, Any]:
    """
    Collect every diagnostics section into one plain dictionary.

    Sections: ``python``, ``app``, ``paths``, ``dependencies``,
    ``data_packs``, ``environment`` and (only when ``check_network`` is
    true) ``network``.  All values are JSON-safe primitives.  Never raises
    and never touches the network unless asked to.
    """
    report: Dict[str, Any] = {
        "python": _python_section(),
        "app": _app_section(),
        "paths": _paths_section(),
        "dependencies": [asdict(status) for status in collect_dependencies()],
        "data_packs": _data_packs_section(),
        "environment": _environment_section(),
    }
    if check_network:
        report["network"] = {
            "checked": True,
            "target": "https://github.com",
            "reachable": _network_reachable(5.0),
        }
    return report


def render_dependency_table(dependencies: List[Dict[str, Any]]) -> str:
    """
    ASCII table of dependency statuses (``module / status / version``).

    Accepts the dictionaries produced by ``collect_diagnostics`` (or
    ``[asdict(d) for d in collect_dependencies()]``).
    """
    name_width = max([len(str(entry.get("module", ""))) for entry in dependencies] + [10])
    status_width = 9
    version_width = 12
    header = "  {0}  {1}  {2}".format(
        "module".ljust(name_width), "status".ljust(status_width), "version".ljust(version_width)
    )
    lines = [header, "  " + "-" * len(header)]
    for entry in dependencies:
        name = str(entry.get("module", ""))
        status = "ok" if entry.get("importable") else "missing"
        version = str(entry.get("version") or "-")
        if version == UNKNOWN_VERSION:
            version = "-"
        lines.append(
            "  {0}  {1}  {2}".format(
                name.ljust(name_width), status.ljust(status_width), version.ljust(version_width)
            )
        )
    return "\n".join(lines)


def _section(title: str) -> str:
    return "-- {0} ".format(title).ljust(60, "-")


def _render_rows(rows: List[Tuple[str, Any]]) -> List[str]:
    if not rows:
        return ["  (nothing to report)"]
    key_width = max(len(str(key)) for key, _ in rows)
    lines = []
    for key, value in rows:
        rendered = str(value)
        if not rendered:
            rendered = "-"
        lines.append("  {0} : {1}".format(str(key).ljust(key_width), rendered))
    return lines


def render_diagnostics(report: Dict[str, Any]) -> str:
    """
    Render a collected report as a sectioned, pure-ASCII text block.

    Complements :func:`collect_diagnostics`: pass its output here (or use
    :func:`diagnostics_report` which chains both).
    """
    title = "{0} diagnostics".format(report.get("app", {}).get("name", DESKTOP_NAME))
    lines = ["", "=" * 70, title.center(70), "=" * 70, ""]

    python_section = report.get("python", {}) or {}
    lines.append(_section("Python"))
    lines.extend(
        _render_rows(
            [
                ("version", python_section.get("version")),
                ("implementation", python_section.get("implementation")),
                ("platform", python_section.get("platform")),
                ("machine", python_section.get("machine")),
                ("processor", python_section.get("processor")),
                ("executable", python_section.get("executable")),
            ]
        )
    )
    lines.append("")

    app_section = report.get("app", {}) or {}
    lines.append(_section("Application"))
    lines.extend(
        _render_rows(
            [
                ("version", app_section.get("version")),
                ("channel", app_section.get("channel")),
                ("frozen", "yes" if app_section.get("frozen") else "no"),
                ("exe path", app_section.get("exe_path")),
            ]
        )
    )
    lines.append("")

    lines.append(_section("Paths"))
    paths = report.get("paths", {}) or {}
    if "error" in paths:
        lines.append("  {0}".format(paths["error"]))
    else:
        lines.extend(
            _render_rows(
                [
                    ("config dir", paths.get("config_dir")),
                    ("database", paths.get("database")),
                    ("cache", paths.get("cache")),
                    ("report dir", paths.get("report_dir")),
                ]
            )
        )
    lines.append("")

    lines.append(_section("Dependencies"))
    dependencies = report.get("dependencies", []) or []
    if dependencies:
        lines.append(render_dependency_table(dependencies))
    else:
        lines.append("  (no dependency information)")
    lines.append("")

    lines.append(_section("Data packs"))
    packs = report.get("data_packs", {}) or {}
    if packs.get("available"):
        lines.append("  directory : {0}".format(packs.get("directory")))
        lines.append(
            "  packs     : {0} ({1} entries total)".format(
                packs.get("pack_count"), packs.get("entries_total")
            )
        )
        for pack in packs.get("packs", []) or []:
            lines.append(
                "  - {0} ({1} entries, {2} bytes)".format(
                    pack.get("name"), pack.get("entries"), pack.get("bytes")
                )
            )
    else:
        lines.append("  {0}".format(packs.get("error", "unavailable")))
    lines.append("")

    lines.append(_section("Environment"))
    environment = report.get("environment", {}) or {}
    lines.extend(
        _render_rows(
            [
                ("cwd", environment.get("cwd")),
                ("locale", environment.get("locale")),
                ("encoding", environment.get("encoding")),
                ("argv", " ".join(environment.get("argv", []) or []) or "-"),
                ("config dir env", environment.get("config_dir_env") or "(unset)"),
                ("no color", "yes" if environment.get("no_color") else "no"),
            ]
        )
    )
    lines.append("")

    network = report.get("network")
    if network is not None:
        lines.append(_section("Network"))
        reachable = network.get("reachable")
        lines.append(
            "  {0}: {1}".format(
                network.get("target", "https://github.com"),
                "reachable" if reachable else "unreachable",
            )
        )
        lines.append("")

    lines.append("(generated by obscuralens-desktop --diagnostics)")
    return "\n".join(lines)


def diagnostics_report(check_network: bool = False, as_json: bool = False) -> str:
    """
    Collect and render the diagnostics report in one call.

    ``as_json=True`` returns ``json.dumps(collect_diagnostics(...), indent=2)``
    instead of the ASCII rendering (handy for bug reports pasted into
    tools).  Never raises and stays offline unless ``check_network``.
    """
    report = collect_diagnostics(check_network=check_network)
    if as_json:
        try:
            return json.dumps(report, indent=2, default=str)
        except (TypeError, ValueError):  # pragma: no cover - report is JSON-safe
            return json.dumps({"error": "report serialization failed"})
    return render_diagnostics(report)


__all__ = [
    "DependencyStatus",
    "DESKTOP_NAME",
    "TRACKED_DEPENDENCIES",
    "UNKNOWN_VERSION",
    "check_dependency",
    "collect_dependencies",
    "collect_diagnostics",
    "diagnostics_report",
    "render_dependency_table",
    "render_diagnostics",
]
