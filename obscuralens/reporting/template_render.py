"""
Jinja2 template rendering for ObscuraLens reports (v5.1).

This module fronts the report templates shipped in
``obscuralens/reporting/templates`` with a small, dependency-light
facade:

* :func:`template_env` -- a cached :class:`jinja2.Environment` backed by
  a ``FileSystemLoader`` on the templates directory.  Autoescaping is
  OFF because the templates are trusted first-party files; every value
  that lands in HTML is passed through the provided ``esc`` filter
  (``html.escape``) instead, and Markdown escaping is handled by the
  templates' own ``cell`` macros.
* :func:`render_template` -- render a named template with a friendly
  :class:`jinja2.TemplateNotFound` error that lists the available names.
* :func:`render_report` -- the entry point the CLI's ``--template`` flag
  uses: adapts this project's own section dicts (including the ``grid``
  shape) and folds a ``correlation.risk`` block into the template context.
* :func:`render_standalone_html_report` / :func:`render_markdown_report`
  -- convenience wrappers with a documented context contract.

Context contract shared by the report templates
-----------------------------------------------

``sections`` is a list of mappings shaped like::

    {
        'title': 'Domain Posture',          # required
        'rows': [['Field', 'Value'], ...],  # required; first row IS the header
        'notes': 'optional free text',      # optional, rendered as a paragraph
        'columns': [...],                   # optional; when present it is used
    }                                       # as the header and 'rows' are all data

``meta`` is a mapping shaped like::

    {
        'title': 'ObscuraLens Report',   # report headline
        'target': 'example.com',         # the investigated indicator
        'kind': 'domain',                # target kind
        'version': '5.1.0',              # ObscuraLens version
        'generated': '2026-01-01T12:00:00Z',
        'channel': 'beta',               # desktop/release channel (optional)
    }

Unknown/missing meta keys are filled with defaults, so callers can pass a
partial dict (or ``None``).  Extra keys are passed through verbatim -- the
summary template additionally understands ``band`` (risk band),
``score`` (0-100), ``top_signals`` (list of strings) and
``source_health`` (rows in the same first-row-is-header shape).
"""

import html
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

__all__ = [
    'RISK_BANDS',
    'TEMPLATES_DIR',
    'available_templates',
    'fmt_date',
    'fmt_pct',
    'nl2br',
    'render_markdown_report',
    'render_report',
    'render_standalone_html_report',
    'render_template',
    'resolve_template_name',
    'template_env',
]

#: Directory with the shipped ``*.j2`` report templates.
TEMPLATES_DIR = Path(__file__).resolve().parent / 'templates'

#: Module-level environment cache (one loader per process is plenty).
_ENV: Optional[Environment] = None


# --------------------------------------------------------------------------- #
# filters
# --------------------------------------------------------------------------- #

def esc(value: Any) -> str:
    """HTML-escape a value (trusted templates + explicit escaping)."""
    if value is None:
        return ''
    return html.escape(str(value), quote=True)


def nl2br(value: Any) -> str:
    """Escape a value, then turn line breaks into ``<br>`` elements."""
    escaped = esc(value)
    return escaped.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '<br>\n')


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Datetime form of a datetime/date/ISO-ish string; None otherwise."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith(('Z', 'z')):
        candidate = candidate[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in ('%Y-%m-%d', '%Y/%m/%d %H:%M:%S', '%Y-%m-%d %H:%M:%S'):
            try:
                parsed = datetime.strptime(candidate, fmt)
                break
            except ValueError:
                continue
    return parsed


def fmt_date(value: Any, fmt: str = '%Y-%m-%d %H:%M UTC') -> str:
    """
    Format a date-ish value; values that cannot be parse are returned
    verbatim (so half-formed stamps stay visible instead of vanishing).
    """
    parsed = _parse_datetime(value)
    if parsed is None:
        return '' if value is None else str(value)
    return parsed.strftime(fmt)


def fmt_pct(value: Any, decimals: int = 1) -> str:
    """
    Percentage formatting: ``0.123`` -> ``"12.3%"``.

    Values with an absolute magnitude of at most 1.0 are treated as
    fractions and multiplied by 100 (EPSS-style scores); larger values are
    assumed to already be percentages (``12.3`` -> ``"12.3%"``).
    Non-numeric input renders as an empty string.
    """
    if isinstance(value, bool) or value is None:
        return ''
    try:
        number = float(value)
    except (TypeError, ValueError):
        return ''
    fraction = number * 100.0 if abs(number) <= 1.0 else number
    return f'{fraction:.{decimals}f}%'


# --------------------------------------------------------------------------- #
# environment
# --------------------------------------------------------------------------- #

def template_env() -> Environment:
    """
    The shared Jinja2 environment for the shipped report templates.

    ``trim_blocks`` / ``lstrip_blocks`` keep template control lines out of
    the rendered output, and ``keep_trailing_newline`` preserves the final
    newline of Markdown templates.  The filters :func:`esc`, :func:`nl2br`,
    :func:`fmt_date` and :func:`fmt_pct` are installed as ``esc``,
    ``nl2br``, ``fmt_date`` and ``fmt_pct`` respectively.
    """
    global _ENV
    if _ENV is not None:
        return _ENV
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=False,           # templates are trusted; values use |esc
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters['esc'] = esc
    env.filters['nl2br'] = nl2br
    env.filters['fmt_date'] = fmt_date
    env.filters['fmt_pct'] = fmt_pct
    _ENV = env
    return env


def available_templates() -> List[str]:
    """
    Sorted names of every ``*.j2`` template in the templates directory.

    Missing directories yield an empty list rather than raising so the
    friendly :func:`render_template` error still works in broken installs.
    """
    try:
        names = [path.name for path in TEMPLATES_DIR.glob('*.j2') if path.is_file()]
    except OSError:
        return []
    return sorted(names)


def resolve_template_name(name: str) -> Optional[str]:
    """
    Map a user-supplied template name onto a shipped template file.

    Three increasingly forgiving passes, so ``--template report``,
    ``--template report.md`` and ``--template report.md.j2`` all work:

    1. the name as given;
    2. the name with ``.j2`` appended;
    3. the unique shipped template whose file name starts with the name
       (which is what lets ``standalone_report`` find
       ``standalone_report.html.j2``).

    Returns:
        The matching file name, or ``None`` when nothing matches or the
        prefix is ambiguous.
    """
    env = template_env()
    candidates = [name] if name.endswith('.j2') else [name, name + '.j2']
    for candidate in candidates:
        try:
            env.get_template(candidate)
        except TemplateNotFound:
            continue
        return candidate

    prefix_matches = [n for n in available_templates() if n.startswith(name)]
    return prefix_matches[0] if len(prefix_matches) == 1 else None


def render_template(name: str, **context: Any) -> str:
    """
    Render a named template from the templates directory.

    Raises:
        jinja2.TemplateNotFound: the name is unknown or ambiguous; the
            message lists every available template so the fix is obvious.
    """
    resolved = resolve_template_name(name)
    if resolved is None:
        available = ', '.join(available_templates()) or '(none found)'
        raise TemplateNotFound(
            f"template {name!r} was not found in {TEMPLATES_DIR}; "
            f'available templates: {available}')
    return template_env().get_template(resolved).render(**context)


# --------------------------------------------------------------------------- #
# context normalisation + convenience renderers
# --------------------------------------------------------------------------- #

def _default_version() -> str:
    """ObscuraLens version, looked up lazily ('unknown' when unavailable)."""
    try:
        from .. import __version__
        return str(__version__)
    except ImportError:
        return 'unknown'


def _normalize_meta(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Fill meta defaults and keep any extra keys (band, score, ...)."""
    normalized: Dict[str, Any] = dict(meta or {})
    defaults = {
        'title': 'ObscuraLens Report',
        'target': '',
        'kind': '',
        'version': _default_version(),
        'generated': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'channel': '',
    }
    for key, value in defaults.items():
        if not normalized.get(key):
            normalized[key] = value
    return normalized


def _as_rows(raw: Any) -> List[List[str]]:
    """Coerce an arbitrary row collection into a list of string lists."""
    rows: List[List[str]] = []
    if not isinstance(raw, (list, tuple)):
        return rows
    for row in raw:
        if isinstance(row, (list, tuple)):
            rows.append(['' if cell is None else str(cell) for cell in row])
        elif row is not None:
            rows.append([str(row)])
    return rows


def _section_rows(entry: Dict[str, Any]) -> List[List[str]]:
    """
    Rows for one section builder, with the header row first.

    ``reporting.sections`` emits two shapes and both are accepted here so
    the templates never have to care which builder produced a section:

    * ``{'type': 'table', 'columns': [...], 'rows': [...]}`` -- ``columns``
      is the header and ``rows`` holds only body rows, so the header is
      prepended.
    * ``{'type': 'grid', 'data': {...}}`` -- a flat mapping rendered as a
      two-column Field/Value table.
    """
    kind = str(entry.get('type') or 'table').lower()
    if kind == 'grid':
        data = entry.get('data')
        if not isinstance(data, dict):
            return []
        body = [[key, '' if value is None else value] for key, value in data.items()]
        return [['Field', 'Value'], *body]

    rows = _as_rows(entry.get('rows'))
    columns = entry.get('columns')
    if isinstance(columns, (list, tuple)) and columns:
        header = ['' if cell is None else str(cell) for cell in columns]
        # Already-headered input (a caller that inlined the header in
        # ``rows``) must not gain a duplicate header row.
        if not rows or rows[0] != header:
            rows = [header, *rows]
    return rows


def _normalize_sections(sections: Optional[List[Any]]) -> List[Dict[str, Any]]:
    """
    Coerce section entries into the documented shape.

    Each entry becomes ``{'title', 'rows', 'notes'}`` where ``rows`` is a
    list of lists of strings whose first row is the header; sections
    without rows keep an empty list so templates can still render a
    heading plus notes.  Both the ``table`` (``columns`` + ``rows``) and
    ``grid`` (``data``) shapes emitted by ``reporting.sections`` are
    accepted -- see :func:`_section_rows`.
    """
    clean: List[Dict[str, Any]] = []
    for entry in sections or []:
        if not isinstance(entry, dict):
            continue
        title = str(entry.get('title') or '(untitled)')
        notes = entry.get('notes')
        clean.append({
            'title': title,
            'rows': _section_rows(entry),
            'notes': '' if notes is None else str(notes),
        })
    return clean


def render_standalone_html_report(
        sections: Optional[List[Any]],
        meta: Optional[Dict[str, Any]] = None) -> str:
    """
    Render the full standalone HTML report (``standalone_report.html.j2``).

    ``sections`` and ``meta`` follow the context contract documented in
    the module docstring; both are normalised defensively so partial or
    slightly malformed input still produces a valid document.
    """
    return render_template(
        'standalone_report.html.j2',
        sections=_normalize_sections(sections),
        meta=_normalize_meta(meta),
    )


def render_markdown_report(
        sections: Optional[List[Any]],
        meta: Optional[Dict[str, Any]] = None) -> str:
    """
    Render the Markdown report (``report.md.j2``).

    Pipe characters inside cell values are escaped by the template's
    ``cell`` macro so tables never break, and the same sections/meta
    contract as the HTML report applies.
    """
    return render_template(
        'report.md.j2',
        sections=_normalize_sections(sections),
        meta=_normalize_meta(meta),
    )


# --------------------------------------------------------------------------- #
# adapter for the project's own section builders
# --------------------------------------------------------------------------- #

#: Maps ``correlation.risk`` verdicts onto the five-step band vocabulary the
#: report templates' band strip is drawn for.  ``unknown`` and anything
#: unrecognised deliberately have no entry: no band is claimed rather than
#: an invented one.
RISK_BANDS: Dict[str, str] = {
    'clean': 'clean',
    'low': 'watch',
    'medium': 'elevated',
    'high': 'high',
    'critical': 'critical',
}


def render_report(name: str, *, sections: Optional[List[Any]] = None,
                  meta: Optional[Dict[str, Any]] = None,
                  risk: Optional[Dict[str, Any]] = None,
                  title: str = '', target: str = '', kind: str = '',
                  **extra: Any) -> str:
    """
    Render any shipped report template from a tracker payload.

    This is the entry point the CLI uses for ``--template``: it adapts the
    section dicts produced by ``reporting.sections`` (see
    :func:`_section_rows`), builds the ``meta`` block from the lookup, and
    folds an optional ``correlation.risk`` block into the ``band`` /
    ``score`` / ``top_signals`` keys the summary template understands.

    Args:
        name: template name, with or without the ``.j2`` suffix.
        sections: section dicts from ``sections_for`` / ``generic_sections``.
        meta: explicit meta overrides; computed values fill the blanks.
        risk: the payload's ``risk`` block, if risk scoring was attached.
        title: report headline (defaults to ``"<kind> report"``).
        target: the investigated indicator.
        kind: target kind (``ip``, ``domain``, ...).
        **extra: additional template context, passed through untouched.

    Returns:
        The rendered document.

    Raises:
        jinja2.TemplateNotFound: *name* matches no shipped template; the
            message lists the available names.
    """
    built: Dict[str, Any] = {
        'title': title or (f'{kind.capitalize()} report' if kind else ''),
        'target': target,
        'kind': kind,
    }
    built.update(meta or {})
    if risk:
        built.setdefault('score', risk.get('score'))
        built.setdefault('top_signals', [
            str(signal.get('label') or signal.get('name') or signal)
            for signal in (risk.get('signals') or []) if signal
        ])
        if not built.get('band'):
            built['band'] = RISK_BANDS.get(str(risk.get('verdict') or ''), '')
    return render_template(
        name,
        sections=_normalize_sections(sections),
        meta=_normalize_meta(built),
        **extra,
    )
