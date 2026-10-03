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
    'TEMPLATES_DIR',
    'available_templates',
    'fmt_date',
    'fmt_pct',
    'nl2br',
    'render_markdown_report',
    'render_standalone_html_report',
    'render_template',
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


def render_template(name: str, **context: Any) -> str:
    """
    Render a named template from the templates directory.

    Raises:
        jinja2.TemplateNotFound: the name is unknown; the message lists
            every available template so the fix is obvious.  A name given
            without the ``.j2`` extension is retried with it appended
            first.
    """
    env = template_env()
    candidates = [name]
    if not name.endswith('.j2'):
        candidates.append(name + '.j2')
    for candidate in candidates:
        try:
            template = env.get_template(candidate)
        except TemplateNotFound:
            continue
        return template.render(**context)
    available = ', '.join(available_templates()) or '(none found)'
    message = (f"template {name!r} was not found in {TEMPLATES_DIR}; "
               f'available templates: {available}')
    raise TemplateNotFound(message)


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


def _normalize_sections(sections: Optional[List[Any]]) -> List[Dict[str, Any]]:
    """
    Coerce section entries into the documented shape.

    Each entry becomes ``{'title', 'rows', 'notes'}`` where ``rows`` is a
    list of lists of strings; sections without rows keep an empty list so
    templates can still render a heading plus notes.
    """
    clean: List[Dict[str, Any]] = []
    for entry in sections or []:
        if not isinstance(entry, dict):
            continue
        title = str(entry.get('title') or '(untitled)')
        raw_rows = entry.get('rows')
        rows: List[List[str]] = []
        if isinstance(raw_rows, (list, tuple)):
            for row in raw_rows:
                if isinstance(row, (list, tuple)):
                    rows.append(['' if cell is None else str(cell) for cell in row])
                elif row is not None:
                    rows.append([str(row)])
        notes = entry.get('notes')
        clean.append({
            'title': title,
            'rows': rows,
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
