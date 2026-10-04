"""
Self-contained HTML investigation reports (v5.0) - the showcase feature.

An OSINT finding that cannot leave the analyst's machine is a finding
that goes unwritten. This module turns any lookup result into a single
HTML file that is **print-ready, email-able and zero-dependency**: one
document, inline CSS, inline SVG charts, no external assets, no CDN, no
JavaScript - open it in any browser from an air-gapped laptop, attach it
to an email, or hand the printed page to a case review.

Three report shapes:

* :func:`build_report` - the single-target dossier: styled header with
  the ObscuraLens wordmark, kind badge and target, summary stat chips,
  a heuristic risk panel (score bar + explainable signal table), the
  merged field table with per-field source chips, the source health
  panel (answered vs failed, failures carry their reason) and a footer
  that states what this tool always states: data stays local.
* :func:`build_investigation_report` - the pivot graph dossier for an
  ``investigate()`` payload: entity summary chips, the relationship
  graph rendered as inline SVG (deterministic golden-angle spiral
  layout, nodes coloured by kind, the investigated target ringed in
  amber), one result section per pivoted kind and a sources appendix.
* :func:`build_history_report` - the workspace analytics report:
  lookups-per-day sparkline + bar chart, kind distribution donut, top
  targets table and pattern-of-life highlights lifted from the
  ``patterns`` module.

Every dynamic value - targets, field values, source names, error
strings - passes through :func:`_esc` (``html.escape``) before it
touches the document, so hostile data cannot inject markup into a
report. Trackers are imported lazily so a report render never pays for
the tracker fleet until it actually needs a fresh lookup; the only
network a report can cause is the tracker lookup it was asked to run.
"""

import contextlib
import json
import math
import re
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import __version__
from ..config import config

__all__ = [
    'build_history_report',
    'build_investigation_report',
    'build_report',
    'report_path',
    'save_report',
]

#: Lazy tracker resolution table: kind -> (tracker module, class name).
_TRACKER_CLASSES: Dict[str, Tuple[str, str]] = {
    'ip': ('ip_tracker', 'IPTracker'),
    'phone': ('phone_tracker', 'PhoneTracker'),
    'username': ('username_tracker', 'UsernameTracker'),
    'email': ('email_tracker', 'EmailTracker'),
    'domain': ('domain_tracker', 'DomainTracker'),
    'url': ('url_tracker', 'URLTracker'),
    'crypto': ('crypto_tracker', 'CryptoTracker'),
    'hash': ('hash_tracker', 'HashTracker'),
    'cve': ('cve_tracker', 'CVETracker'),
    'asn': ('asn_tracker', 'ASNTracker'),
    'mac': ('mac_tracker', 'MACTracker'),
    'iban': ('iban_tracker', 'IBANTracker'),
    'imei': ('imei_tracker', 'IMEITracker'),
    'coords': ('coords_tracker', 'CoordsTracker'),
}

#: Kind (and graph entity type) -> node/chip colour, drawn from the app
#: palette family so reports match the web UI's mental model.
_KIND_COLORS: Dict[str, str] = {
    'ip': '#60a5fa', 'phone': '#f472b6', 'username': '#a78bfa', 'email': '#f5a524',
    'domain': '#2dd4a7', 'url': '#34d399', 'crypto': '#fbbf24', 'hash': '#f87171',
    'cve': '#fb923c', 'asn': '#38bdf8', 'mac': '#c084fc', 'iban': '#4ade80',
    'imei': '#facc15', 'coords': '#22d3ee',
    # entity types the investigate engine derives from payloads
    'hostname': '#7dd3fc', 'registrar': '#fca5a5', 'breach': '#ef4444',
    'organisation': '#e879f9', 'subdomain': '#5eead4', 'nameserver': '#93c5fd',
    'mx': '#fde047', 'prefix': '#94a3b8', 'wallet': '#fbbf24', 'profile': '#a78bfa',
}

#: Fallback colour for unknown kinds.
_FALLBACK_COLOR = '#8b98a9'

#: How many list items / characters a field value contributes to a report.
_MAX_LIST_ITEMS = 10
_MAX_TEXT_CHARS = 400

#: The embedded stylesheet - a compact port of the app's design tokens
#: (dark #0a0e14 base, teal #2dd4a7 accent, amber #f5a524 highlight,
#: system + mono fonts). The ``@media print`` block flips to a light
#: paper theme so the same file prints cleanly.
_STYLESHEET = """
:root {
  --bg: #0a0e14; --panel: #10161f; --panel-2: #0d1420; --line: #1e2836;
  --text: #d5dee8; --muted: #8b98a9; --accent: #2dd4a7; --amber: #f5a524;
  --red: #f87171; --blue: #60a5fa; --green: #4ade80;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--text); line-height: 1.55;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
               Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1060px; margin: 0 auto; padding: 28px 22px 40px; }
.mono { font-family: var(--mono); }
.muted { color: var(--muted); }
.rep-head { border-bottom: 1px solid var(--line); padding-bottom: 16px; margin-bottom: 20px; }
.wordmark { font-size: 26px; font-weight: 800; letter-spacing: 0.5px; }
.wordmark .accent { color: var(--accent); }
.head-meta { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.badge {
  display: inline-block; padding: 2px 10px; border-radius: 999px;
  background: rgba(45, 212, 167, 0.12); color: var(--accent);
  border: 1px solid rgba(45, 212, 167, 0.35); font-size: 12px;
  font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
}
.target { font-size: 17px; font-weight: 600; word-break: break-all; }
.head-sub { margin-top: 8px; color: var(--muted); font-size: 12.5px; }
.chips { display: flex; flex-wrap: wrap; gap: 10px; margin: 18px 0 22px; }
.chip {
  display: inline-flex; flex-direction: column; gap: 2px; min-width: 108px;
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 8px 14px;
}
.chip-label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
.chip-value { font-size: 18px; font-weight: 700; font-family: var(--mono); }
.chip.ok .chip-value { color: var(--accent); }
.chip.bad .chip-value { color: var(--red); }
.chip.warn .chip-value { color: var(--amber); }
.chip.info .chip-value { color: var(--blue); }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
         padding: 18px 18px 14px; margin-bottom: 20px; }
.panel h2 { margin: 0 0 12px; font-size: 15px; text-transform: uppercase;
            letter-spacing: 1.2px; color: var(--text); }
.panel h2 .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
                 margin-right: 8px; }
h2 small { color: var(--muted); text-transform: none; letter-spacing: 0; font-weight: 400; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th { text-align: left; color: var(--muted); font-size: 11.5px; text-transform: uppercase;
     letter-spacing: 1px; border-bottom: 1px solid var(--line); padding: 6px 10px; }
td { border-bottom: 1px solid rgba(30, 40, 54, 0.6); padding: 7px 10px; vertical-align: top; }
tr:last-child td { border-bottom: none; }
td.mono { font-family: var(--mono); color: var(--accent); white-space: nowrap; }
td.value { word-break: break-word; }
.src-cell { min-width: 130px; }
.src { display: inline-block; margin: 1px 3px 1px 0; padding: 1px 8px; border-radius: 999px;
       background: rgba(45, 212, 167, 0.10); border: 1px solid rgba(45, 212, 167, 0.3);
       color: var(--accent); font-size: 11px; font-family: var(--mono); }
.src.bad { background: rgba(248, 113, 113, 0.10); border-color: rgba(248, 113, 113, 0.35);
           color: var(--red); }
.risk-head { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 10px; }
.risk-score { font-family: var(--mono); font-size: 40px; font-weight: 800; line-height: 1; }
.risk-verdict { text-transform: uppercase; letter-spacing: 2px; font-weight: 700; font-size: 13px; }
.risk-summary { color: var(--muted); font-size: 13px; }
svg.risk-bar { display: block; width: 100%; height: 12px; margin: 4px 0 14px; }
svg.chart, svg.spark { display: block; width: 100%; height: auto; margin: 6px 0; }
.donut-row { display: flex; flex-wrap: wrap; gap: 26px; align-items: center; }
.donut-total { fill: var(--text); font-size: 26px; font-weight: 800; font-family: var(--mono); }
.legend { display: flex; flex-direction: column; gap: 6px; font-size: 13px; }
.legend .key { display: inline-block; width: 11px; height: 11px; border-radius: 3px;
               margin-right: 8px; }
.edge { stroke: #2a3648; stroke-width: 1.4; }
.node { }
.node-label { font-size: 10px; font-family: var(--mono); }
svg.graph { display: block; width: 100%; height: auto; background: var(--panel-2);
            border: 1px solid var(--line); border-radius: 10px; }
.errors li { color: var(--red); font-size: 13px; margin-bottom: 4px; }
.rep-foot { margin-top: 26px; border-top: 1px solid var(--line); padding-top: 14px;
            color: var(--muted); font-size: 12px; }
.note { color: var(--muted); font-size: 12.5px; margin: 8px 0 0; }
.grid-2 { display: grid; grid-template-columns: minmax(0, 1fr); gap: 20px; }
@media (min-width: 780px) { .grid-2 { grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); } }
@media print {
  body { background: #ffffff; color: #111827; }
  .wrap { max-width: none; padding: 0; }
  .panel, .chip { background: #f7f8fa; border-color: #d6dbe3; }
  .chip-label, th, .head-sub, .muted, .note, .rep-foot { color: #4b5563; }
  .wordmark, .chip-value, .risk-score, .donut-total { color: #0f172a; }
  .wordmark .accent, .badge, .src { color: #0d9488; }
  .badge { background: #ccfbf1; border-color: #99f6e4; }
  .src { background: #f0fdfa; }
  .src.bad { color: #b91c1c; background: #fef2f2; border-color: #fecaca; }
  td, th { border-color: #d6dbe3; }
  .panel { break-inside: avoid; }
  svg.graph { background: #ffffff; }
}
"""


# ---------------------------------------------------------------------------
# Small helpers: escaping, colours, chips, timestamps
# ---------------------------------------------------------------------------

def _display(value: Any) -> str:
    """
    Flatten one field value into report display text.

    Lists contribute up to :data:`_MAX_LIST_ITEMS` items (the remainder
    is summarised as ``(+N more)``), dicts become compact JSON, booleans
    become ``true``/``false`` and over-long strings are capped at
    :data:`_MAX_TEXT_CHARS` with an ellipsis - a report stays readable
    even when a source returned a 4 000-character blob.
    """
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (list, tuple)):
        items = [_display(item) for item in list(value)[:_MAX_LIST_ITEMS]
                 if item is not None]
        text = ', '.join(part for part in items if part)
        if len(value) > _MAX_LIST_ITEMS:
            text = f"{text} (+{len(value) - _MAX_LIST_ITEMS} more)".strip(', ')
        return text
    if isinstance(value, dict):
        with contextlib.suppress(TypeError, ValueError):
            return json.dumps(value, ensure_ascii=False, default=str)
        return str(value)
    text = str(value)
    if len(text) > _MAX_TEXT_CHARS:
        return text[:_MAX_TEXT_CHARS] + '…'
    return text


def _esc(value: Any) -> str:
    """
    HTML-escape the display form of any dynamic value.

    Every target, field value, source name and error string in a report
    passes through here, so a malicious hostname or a crafted error
    message renders as inert text - never as markup.
    """
    from html import escape
    return escape(_display(value))


def _kind_color(kind: Any) -> str:
    """The palette colour for a kind / entity type (muted fallback)."""
    return _KIND_COLORS.get(str(kind or '').strip().lower(), _FALLBACK_COLOR)


def _generated_text() -> str:
    """The 'generated at' stamp shown in headers and footers."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _css() -> str:
    """
    The embedded stylesheet (module constant :data:`_STYLESHEET`).

    Returned by a function so the CSS lives beside the other design
    helpers and callers never concatenate the raw constant by accident.
    """
    return _STYLESHEET


def _stat_chip(label: str, value: Any, cls: str = '') -> str:
    """
    One summary stat chip (``label`` over a big mono ``value``).

    Args:
        label: short uppercase caption, e.g. ``'Fields'``
        value: the number/verdict to display (escaped)
        cls: optional colour class - ``ok``, ``bad``, ``warn`` or ``info``
    """
    return (f'<span class="chip {cls}"><span class="chip-label">{_esc(label)}</span>'
            f'<span class="chip-value">{_esc(value)}</span></span>')


def _page(title: str, body: str) -> str:
    """
    Wrap a report body in the standalone HTML document skeleton.

    The output starts with ``<!DOCTYPE html>`` and carries the charset,
    viewport, title and the full inline stylesheet - one file, no
    external requests, works from ``file://``.
    """
    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<title>{_esc(title)}</title>\n<style>{_css()}</style>\n'
        '</head>\n<body>\n<div class="wrap">\n'
        f'{body}\n'
        '</div>\n</body>\n</html>\n'
    )


def _header(badge: str, target: str, meta: str) -> str:
    """
    The styled report header: wordmark, kind badge, target, meta line.

    Args:
        badge: the kind label rendered in the teal badge
        target: the investigated indicator (escaped, mono)
        meta: the small line under the target (generated time, version)
    """
    return (
        '<header class="rep-head">'
        '<div class="wordmark">Obscura<span class="accent">Lens</span></div>'
        '<div class="head-meta">'
        f'<span class="badge kind">{_esc(badge)}</span>'
        f'<span class="target mono">{_esc(target)}</span>'
        '</div>'
        f'<div class="head-sub">{_esc(meta)}</div>'
        '</header>'
    )


def _footer() -> str:
    """The report footer: generator, version and the locality promise."""
    return ('<footer class="rep-foot">Generated by ObscuraLens '
            f'v{_esc(__version__)} &mdash; all data stays on this machine; '
            'nothing in this report was sent anywhere. '
            f'<span class="muted">{_esc(_generated_text())}</span></footer>')


def _panel(title_html: str, inner: str) -> str:
    """One bordered panel section with a heading."""
    return (f'<section class="panel"><h2>{title_html}</h2>{inner}</section>')


def _info_of(result: Any) -> Dict[str, Any]:
    """The merged ``info`` mapping of a tracker result (``{}`` for junk)."""
    if not isinstance(result, dict):
        return {}
    info = result.get('info')
    return info if isinstance(info, dict) else {}


# ---------------------------------------------------------------------------
# Tracker / investigation execution (lazy)
# ---------------------------------------------------------------------------

def _run_tracker(kind: str, target: str) -> Dict[str, Any]:
    """
    Run one tracker lookup lazily; every failure yields a failure-shaped dict.

    The tracker module is imported on first use (and cached by Python
    afterwards). An unsupported kind or an exploding tracker degrades to
    the standard failure shape so the report builder can always render.
    """
    spec = _TRACKER_CLASSES.get(kind)
    if spec is None:
        return {'success': False, 'info': {}, 'field_sources': {}, 'sources_ok': [],
                'sources_failed': {}, 'field_count': 0,
                'errors': [f"unsupported kind {kind!r}"]}
    try:
        module = import_module(f"..trackers.{spec[0]}", package=__package__)
        tracker_cls = getattr(module, spec[1])
        return tracker_cls().track(target)
    except Exception as exc:  # a report must render even when a tracker breaks
        return {'success': False, 'info': {}, 'field_sources': {}, 'sources_ok': [],
                'sources_failed': {}, 'field_count': 0,
                'errors': [f"{type(exc).__name__}: {exc}"]}


def _run_investigate(target: str) -> Dict[str, Any]:
    """
    Run a full pivot investigation lazily (failure-shaped dict on error).

    ``investigate()`` itself fans out to the trackers, so this is the one
    call that can issue real lookups; an undetectable or failing target
    still produces a renderable payload with the error recorded.
    """
    try:
        from ..investigate import investigate  # lazy: pulls pivot machinery
        return investigate(target)
    except Exception as exc:
        return {'target': target, 'kind': 'unknown', 'order': [], 'results': {},
                'entities': [], 'links': [],
                'errors': [f"{type(exc).__name__}: {exc}"]}


# ---------------------------------------------------------------------------
# Reusable renderers: field table, sources, risk panel
# ---------------------------------------------------------------------------

def _field_table(info: Any, field_sources: Any = None) -> str:
    """
    The Field | Value | Sources table at the heart of every report.

    Rows are sorted by field name; each value is flattened by
    :func:`_display` and escaped; the Sources column renders one chip per
    contributing source (from the tracker's ``field_sources`` provenance
    map). An empty info dict renders an explanatory note instead of a
    bare table skeleton.

    Args:
        info: the merged ``info`` mapping of a tracker result
        field_sources: optional ``{field: [source, ...]}`` provenance map
    """
    if not isinstance(info, dict) or not info:
        return '<p class="muted">No fields were returned for this target.</p>'
    provenance = field_sources if isinstance(field_sources, dict) else {}
    rows: List[str] = []
    for name in sorted(info, key=str):
        raw_sources = provenance.get(name)
        if isinstance(raw_sources, (list, tuple)) and raw_sources:
            chips = ''.join(f'<span class="src">{_esc(item)}</span>'
                            for item in list(raw_sources)[:6])
        elif isinstance(raw_sources, str) and raw_sources:
            chips = f'<span class="src">{_esc(raw_sources)}</span>'
        else:
            chips = '<span class="muted">&mdash;</span>'
        rows.append(f'<tr><td class="mono">{_esc(name)}</td>'
                    f'<td class="value">{_esc(info[name])}</td>'
                    f'<td class="src-cell">{chips}</td></tr>')
    return ('<table><thead><tr><th>Field</th><th>Value</th><th>Sources</th></tr>'
            f'</thead><tbody>{"".join(rows)}</tbody></table>')


def _sources_chips(sources_ok: Any, sources_failed: Any) -> str:
    """
    Source health chips: green for answered, red for failed (reason on hover).

    Failed chips carry the tracker's error text in a ``title`` attribute
    so the reason is one hover away without cluttering the layout.
    """
    ok = [str(item) for item in (sources_ok or []) if str(item or '').strip()]
    failed = sources_failed if isinstance(sources_failed, dict) else {}
    parts: List[str] = []
    if ok:
        parts.append('<div>' + ''.join(f'<span class="src">{_esc(name)}</span>'
                                       for name in ok) + '</div>')
    if failed:
        parts.append('<div>' + ''.join(
            f'<span class="src bad" title="{_esc(reason)}">{_esc(name)}</span>'
            for name, reason in list(failed.items())[:20]) + '</div>')
    if not parts:
        return '<p class="muted">No source health recorded for this lookup.</p>'
    return ''.join(parts)


def _risk_color(score: Any) -> str:
    """Palette colour for a risk score band (teal -> red)."""
    try:
        value = int(score)
    except (TypeError, ValueError):
        return _FALLBACK_COLOR
    if value < 15:
        return '#2dd4a7'
    if value < 40:
        return '#60a5fa'
    if value < 70:
        return '#f5a524'
    if value < 90:
        return '#fb923c'
    return '#f87171'


def _risk_panel(risk: Any) -> str:
    """
    The risk panel: big score, verdict, inline-SVG score bar, signal table.

    Args:
        risk: a ``correlation.risk.score`` result (``{'score', 'verdict',
            'signals': [{'id', 'weight', 'detail'}], 'summary'}``); a
            missing or malformed block renders an explanatory note.

    The score bar is an inline SVG whose filled rect width equals the
    score percent - no JavaScript, prints correctly.
    """
    if not isinstance(risk, dict):
        return _panel('Risk Assessment',
                      '<p class="muted">No heuristic risk score is attached to '
                      'this result (scoring disabled or not requested).</p>')
    score = risk.get('score')
    try:
        pct = max(0, min(100, int(score)))
    except (TypeError, ValueError):
        pct = 0
    color = _risk_color(score)
    verdict = str(risk.get('verdict') or 'unknown')
    summary = _display(risk.get('summary'))
    bar = (f'<svg class="risk-bar" viewBox="0 0 100 12" preserveAspectRatio="none" '
           f'role="img" aria-label="risk score {pct} of 100">'
           f'<rect x="0" y="0" width="100" height="12" rx="3" fill="#1e2836"/>'
           f'<rect x="0" y="0" width="{pct}" height="12" rx="3" fill="{color}"/>'
           '</svg>')
    signals = risk.get('signals')
    rows = ''
    if isinstance(signals, (list, tuple)) and signals:
        rows = ('<table><thead><tr><th>Signal</th><th>Weight</th><th>Detail</th>'
                '</tr></thead><tbody>'
                + ''.join(
                    f'<tr><td class="mono">{_esc(signal.get("id"))}</td>'
                    f'<td>{_esc(signal.get("weight"))}</td>'
                    f'<td class="value">{_esc(signal.get("detail"))}</td></tr>'
                    for signal in signals if isinstance(signal, dict))
                + '</tbody></table>')
    inner = (f'<div class="risk-head"><span class="risk-score" style="color:{color}">'
             f'{_esc(score if score is not None else "-")}</span>'
             f'<span class="risk-verdict" style="color:{color}">{_esc(verdict)}</span>'
             f'<span class="risk-summary">{_esc(summary)}</span></div>'
             f'{bar}{rows}'
             '<p class="note">Heuristic score - explainable weighted signals over '
             'technical indicators, not a verdict about people.</p>')
    return _panel('Risk Assessment', inner)


# ---------------------------------------------------------------------------
# Inline SVG charts
# ---------------------------------------------------------------------------

def _svg_bars(values: Sequence[Any], width: int = 860, height: int = 150,
              color: str = '#2dd4a7') -> str:
    """
    A responsive inline-SVG bar chart for a numeric series.

    Bars scale to the series maximum; zero values collapse to the
    baseline and each bar carries its value in a hover ``<title>``. An
    empty or non-numeric series renders an empty string so callers can
    drop the chart without a guard.
    """
    numbers = [float(v) for v in values or []
               if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if not numbers:
        return ''
    peak = max(numbers) or 1.0
    count = len(numbers)
    slot = float(width) / count
    bar_width = max(1.0, slot * 0.72)
    rects: List[str] = []
    for index, value in enumerate(numbers):
        bar_height = (value / peak) * (height - 10)
        bar_height = max(2.0, bar_height) if value > 0 else 0.0
        x = index * slot + (slot - bar_width) / 2.0
        y = height - bar_height
        rects.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" '
                     f'height="{bar_height:.1f}" rx="2" fill="{color}">'
                     f'<title>{_num_text(value)}</title></rect>')
    return (f'<svg class="chart" viewBox="0 0 {width} {height}" width="100%" '
            f'height="{height}" role="img" aria-label="bar chart of {count} values">'
            f'<line x1="0" y1="{height - 0.5}" x2="{width}" y2="{height - 0.5}" '
            'stroke="#1e2836"/>'
            f'{"".join(rects)}</svg>')


def _num_text(value: float) -> str:
    """Compact integer-ish text for chart tooltips."""
    if float(value).is_integer():
        return str(int(value))
    return f'{value:.2f}'


def _svg_sparkline(values: Sequence[Any], width: int = 860, height: int = 44,
                   color: str = '#f5a524') -> str:
    """
    A thin inline-SVG sparkline (trend at a glance, no axes).

    Sits above the per-day bar chart in the history report; a
    single-point series renders as a lone dot, an empty series as ``''``.
    """
    numbers = [float(v) for v in values or []
               if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if not numbers:
        return ''
    peak = max(numbers) or 1.0
    count = len(numbers)
    if count == 1:
        x, y = width / 2.0, height / 2.0
        return (f'<svg class="spark" viewBox="0 0 {width} {height}" width="100%" '
                f'height="{height}" role="img" aria-label="sparkline">'
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}"/></svg>')
    points: List[str] = []
    for index, value in enumerate(numbers):
        x = index * (width / (count - 1.0))
        y = height - 3.0 - (value / peak) * (height - 8.0)
        points.append(f'{x:.1f},{y:.1f}')
    return (f'<svg class="spark" viewBox="0 0 {width} {height}" width="100%" '
            f'height="{height}" role="img" aria-label="sparkline of {count} values">'
            f'<polyline points="{" ".join(points)}" fill="none" stroke="{color}" '
            'stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/></svg>')


def _svg_donut(slices: Sequence[Dict[str, Any]], size: int = 190,
               stroke: int = 26) -> str:
    """
    A kind-distribution donut as inline SVG (``stroke-dasharray`` arcs).

    Args:
        slices: ``[{'label', 'value', 'color'}]`` dicts; non-positive
            values are skipped
        size: SVG canvas size in pixels
        stroke: arc thickness in pixels

    The arcs start at 12 o'clock and run clockwise; each carries a hover
    ``<title>`` with label, count and share. The total sits in the hole.
    An all-zero series renders ``''``.
    """
    clean = [item for item in (slices or [])
             if isinstance(item, dict)
             and isinstance(item.get('value'), (int, float))
             and not isinstance(item.get('value'), bool)
             and item['value'] > 0]
    total = sum(item['value'] for item in clean)
    if not clean or total <= 0:
        return ''
    radius = (size - stroke) / 2.0
    circumference = 2.0 * math.pi * radius
    center = size / 2.0
    arcs: List[str] = []
    offset = 0.0
    for item in clean:
        share = item['value'] / total
        dash = share * circumference
        label = _display(item.get('label'))
        color = _esc(item.get('color') or _FALLBACK_COLOR)
        title = f"{label}: {_num_text(item['value'])} ({share * 100:.1f}%)"
        arcs.append(f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" '
                    f'stroke="{color}" stroke-width="{stroke}" '
                    f'stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" '
                    f'stroke-dashoffset="{-offset:.2f}">'
                    f'<title>{_esc(title)}</title></circle>')
        offset += dash
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
            'role="img" aria-label="distribution donut chart">'
            f'<g transform="rotate(-90 {center} {center})">{"".join(arcs)}</g>'
            f'<text x="{center}" y="{center}" text-anchor="middle" '
            f'dominant-baseline="middle" class="donut-total">'
            f'{_esc(_num_text(total))}</text></svg>')


def _svg_graph(entities: Sequence[Dict[str, Any]],
               links: Sequence[Dict[str, Any]], width: int = 880,
               height: int = 520) -> str:
    """
    The pivot relationship graph as inline SVG.

    Layout is fully deterministic: nodes are placed on a golden-angle
    spiral (``i * 137.5°``, radius ``sqrt(i)``) in entity order, then
    scaled to fit the canvas - the same input always draws the same
    graph, which matters when two analysts compare printouts. Node fill
    comes from :func:`_kind_color`; the investigated target keeps an
    amber ring; node radius grows with relationship degree; edges carry
    their relationship label as a hover ``<title>``. Labels are drawn
    when the graph has 40 nodes or fewer.

    Args:
        entities: ``{'id', 'type', 'value', 'role', 'label'}`` dicts
            (the investigate engine's entity list)
        links: ``{'from', 'to', 'label'}`` dicts referencing entity ids
        width, height: the SVG viewBox dimensions
    """
    ents = [ent for ent in (entities or [])
            if isinstance(ent, dict) and ent.get('id')]
    if not ents:
        return ''
    ids = {str(ent['id']) for ent in ents}
    edges = [link for link in (links or [])
             if isinstance(link, dict)
             and str(link.get('from') or '') in ids
             and str(link.get('to') or '') in ids]

    # golden-angle spiral placement (deterministic in entity order)
    golden = 2.399963229728653
    raw: List[Tuple[float, float]] = []
    for index in range(len(ents)):
        radius = 30.0 * math.sqrt(index)
        angle = index * golden
        raw.append((radius * math.cos(angle), radius * math.sin(angle)))
    xs = [point[0] for point in raw]
    ys = [point[1] for point in raw]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    span_x = (max_x - min_x) or 1.0
    span_y = (max_y - min_y) or 1.0
    margin = 46.0
    usable_w = width - 2 * margin
    usable_h = height - 2 * margin
    scale = min(usable_w / span_x, usable_h / span_y)
    pad_x = (usable_w - span_x * scale) / 2.0
    pad_y = (usable_h - span_y * scale) / 2.0
    positions: Dict[str, Tuple[float, float]] = {}
    for ent, (x, y) in zip(ents, raw):
        positions[str(ent['id'])] = (margin + pad_x + (x - min_x) * scale,
                                     margin + pad_y + (y - min_y) * scale)

    degree: Dict[str, int] = {}
    for link in edges:
        degree[str(link['from'])] = degree.get(str(link['from']), 0) + 1
        degree[str(link['to'])] = degree.get(str(link['to']), 0) + 1

    edge_parts: List[str] = []
    for link in edges:
        x1, y1 = positions[str(link['from'])]
        x2, y2 = positions[str(link['to'])]
        edge_parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" '
                          f'y2="{y2:.1f}" class="edge">'
                          f'<title>{_esc(link.get("label"))}</title></line>')

    show_labels = len(ents) <= 40
    node_parts: List[str] = []
    for ent in ents:
        x, y = positions[str(ent['id'])]
        radius = 9.0 + min(degree.get(str(ent['id']), 0), 14) * 0.9
        color = _kind_color(ent.get('type'))
        is_target = ent.get('role') == 'target'
        stroke = '#f5a524' if is_target else '#0a0e14'
        stroke_width = 3.0 if is_target else 1.5
        title = _esc(f"{ent.get('type')}: {ent.get('value')}")
        node_parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius:.1f}" fill="{color}" '
            f'stroke="{stroke}" stroke-width="{stroke_width}">'
            f'<title>{title}</title></circle>')
        if show_labels:
            label = str(ent.get('label') or ent.get('value') or '')
            if len(label) > 18:
                label = label[:17] + '…'
            fill = '#f5a524' if is_target else '#8b98a9'
            weight = '700' if is_target else '400'
            node_parts.append(
                f'<text x="{x:.1f}" y="{y + radius + 13:.1f}" text-anchor="middle" '
                f'class="node-label" font-weight="{weight}" fill="{fill}">'
                f'{_esc(label)}</text>')

    return (f'<svg class="graph" viewBox="0 0 {width} {height}" width="100%" '
            f'role="img" aria-label="entity relationship graph, '
            f'{len(ents)} nodes, {len(edges)} links">'
            f'<g>{"".join(edge_parts)}</g><g>{"".join(node_parts)}</g></svg>')


# ---------------------------------------------------------------------------
# Public builders
# ---------------------------------------------------------------------------

def build_report(kind: str, target: str, result: Optional[Dict[str, Any]] = None,
                 payload: Optional[Dict[str, Any]] = None) -> str:
    """
    Build the single-target investigation report as standalone HTML.

    Args:
        kind: tracker kind (one of the 14 v5.0 kinds)
        target: the indicator that was looked up
        result: a tracker result dict; when ``None`` the tracker runs now
            (lazily imported) and heuristic risk scoring is attached to
            the fresh result
        payload: optional pre-risked payload whose ``'risk'`` block wins
            over any risk section already inside ``result``

    Returns:
        A complete HTML document (``<!DOCTYPE html>`` ... ``</html>``):
        styled header with wordmark / kind badge / target / generated
        stamp / version, summary stat chips, risk panel with inline-SVG
        score bar, the merged field table with per-field source chips,
        the source health panel and the locality footer. Failures render
        as failed - with the tracker's error list visible - never as an
        exception.
    """
    kind = str(kind or '').strip().lower()
    target = str(target or '').strip()
    ran_here = False
    if not isinstance(result, dict):
        result = _run_tracker(kind, target)
        ran_here = True
    if ran_here:
        with contextlib.suppress(Exception):  # risk enrichment is best-effort
            from ..correlation import attach_risk  # lazy: correlation engine
            attach_risk(kind, result)

    risk: Optional[Dict[str, Any]] = None
    if isinstance(payload, dict) and isinstance(payload.get('risk'), dict):
        risk = payload['risk']
    elif isinstance(result, dict) and isinstance(result.get('risk'), dict):
        risk = result['risk']

    info = _info_of(result)
    try:
        field_count = int(result.get('field_count') or 0)
    except (AttributeError, TypeError, ValueError):
        field_count = len(info)
    sources_ok = result.get('sources_ok') if isinstance(result, dict) else []
    sources_failed = result.get('sources_failed') if isinstance(result, dict) else {}
    success = bool(result.get('success')) if isinstance(result, dict) else False
    risk_score = risk.get('score') if isinstance(risk, dict) else None

    body: List[str] = []
    body.append(_header(
        kind or 'target', target or '(no target)',
        f'Investigation report · generated {_generated_text()} · '
        f'ObscuraLens v{__version__} · local analysis only'))

    chips = ''.join([
        _stat_chip('Success', 'yes' if success else 'no', 'ok' if success else 'bad'),
        _stat_chip('Fields', field_count),
        _stat_chip('Sources ok', len(sources_ok or []), 'ok' if sources_ok else ''),
        _stat_chip('Sources failed', len(sources_failed or {}), 'bad' if sources_failed else ''),
        _stat_chip('Risk', risk_score if risk_score is not None else '—',
                   'warn' if risk_score is not None else ''),
    ])
    body.append(f'<div class="chips">{chips}</div>')

    body.append(_risk_panel(risk))
    body.append(_panel('Collected Fields',
                       _field_table(info, result.get('field_sources')
                                    if isinstance(result, dict) else None)))
    body.append(_panel('Data Sources', _sources_chips(sources_ok, sources_failed)))

    errors = result.get('errors') if isinstance(result, dict) else None
    if isinstance(errors, (list, tuple)) and errors:
        items = ''.join(f'<li>{_esc(item)}</li>' for item in errors)
        body.append(_panel('Errors', f'<ul class="errors">{items}</ul>'))

    body.append(_footer())
    title = f'ObscuraLens · {kind or "report"} · {target or "target"}'
    return _page(title, '\n'.join(body))


def _result_section(kind_name: str, result: Any) -> str:
    """
    One per-kind section of the investigation report.

    A kind dot in the heading, the same stat chips / field table /
    source chips as the single-target report - the investigation report
    is the single-target report repeated per pivoted kind, so analysts
    only have to learn one layout.
    """
    info = _info_of(result)
    try:
        field_count = int(result.get('field_count') or 0)
    except (AttributeError, TypeError, ValueError):
        field_count = len(info)
    sources_ok = result.get('sources_ok') if isinstance(result, dict) else []
    sources_failed = result.get('sources_failed') if isinstance(result, dict) else {}
    success = bool(result.get('success')) if isinstance(result, dict) else False
    color = _kind_color(kind_name)
    heading = (f'<span class="dot" style="background:{color}"></span>'
               f'{_esc(kind_name)} result '
               f'<small>{_esc(_target_of(result, kind_name))}</small>')
    chips = ''.join([
        _stat_chip('Success', 'yes' if success else 'no', 'ok' if success else 'bad'),
        _stat_chip('Fields', field_count),
        _stat_chip('Sources ok', len(sources_ok or [])),
    ])
    inner = (f'<div class="chips">{chips}</div>'
             + _field_table(info, result.get('field_sources')
                            if isinstance(result, dict) else None)
             + '<h2 style="margin-top:14px">Sources</h2>'
             + _sources_chips(sources_ok, sources_failed))
    return _panel(heading, inner)


def _target_of(result: Any, kind_name: str) -> str:
    """
    Best-effort display target for one tracker result section heading.

    Tracker results name their target key after the kind (``ip``,
    ``domain``, ``iban``...) - this picks whichever identity key the
    payload actually carries, falling back to the kind name itself.
    """
    if not isinstance(result, dict):
        return kind_name
    for key in (kind_name, 'value', 'target', 'address', 'email', 'domain',
                'username', 'phone_number', 'cve', 'hash', 'url'):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return kind_name


def build_investigation_report(target: str,
                               payload: Optional[Dict[str, Any]] = None) -> str:
    """
    Build the pivot-graph investigation report for an ``investigate()`` run.

    Args:
        target: the indicator that was investigated
        payload: an investigate payload (``{'target', 'kind', 'order',
            'results': {kind: result}, 'entities', 'links', 'errors'}``);
            when ``None`` a full pivot investigation runs now

    Returns:
        A standalone HTML document: header with the detected-kind badge,
        entity summary chips (lookups / entities / relationships / one
        chip per pivoted kind), the relationship graph as deterministic
        inline SVG (target ringed in amber, nodes coloured by kind),
        one field-table section per pivoted kind, a sources appendix
        aggregating every source that answered anywhere in the run, the
        error list (if any) and the locality footer.
    """
    target = str(target or '').strip()
    if not isinstance(payload, dict) or not isinstance(payload.get('results'), dict):
        payload = _run_investigate(target)
    results = payload.get('results') if isinstance(payload.get('results'), dict) else {}
    order = [name for name in (payload.get('order') or list(results))
             if name in results]
    entities = [ent for ent in (payload.get('entities') or [])
                if isinstance(ent, dict)]
    links = [link for link in (payload.get('links') or [])
             if isinstance(link, dict)]
    detected = str(payload.get('kind') or 'unknown')

    body: List[str] = []
    body.append(_header(
        detected, target or str(payload.get('target') or ''),
        f'Investigation with pivots · generated {_generated_text()} · '
        f'ObscuraLens v{__version__} · local analysis only'))

    chips = [_stat_chip('Lookups', len(order), 'info'),
             _stat_chip('Entities', len(entities)),
             _stat_chip('Relationships', len(links)),
             _stat_chip('Kinds', len({ent.get('type') for ent in entities} or {detected}))]
    for kind_name in order:
        chips.append(_stat_chip(kind_name, 'ran', 'ok'))
    body.append(f'<div class="chips">{"".join(chips)}</div>')

    graph = _svg_graph(entities, links)
    if graph:
        body.append(_panel(
            'Pivot Graph',
            graph + '<p class="note">Deterministic layout (golden-angle spiral); '
                    'node colour = entity kind, amber ring = investigated target, '
                    'hover a node or edge for details.</p>'))
    else:
        body.append(_panel('Pivot Graph',
                           '<p class="muted">No entities were derived from this '
                           'investigation.</p>'))

    for kind_name in order:
        body.append(_result_section(str(kind_name), results.get(kind_name)))

    ok_all: List[str] = []
    failed_all: Dict[str, str] = {}
    for kind_name in order:
        result = results.get(kind_name)
        if not isinstance(result, dict):
            continue
        for name in result.get('sources_ok') or []:
            if str(name) not in ok_all:
                ok_all.append(str(name))
        failed = result.get('sources_failed')
        if isinstance(failed, dict):
            for name, reason in failed.items():
                failed_all.setdefault(str(name), str(reason))
    body.append(_panel('Sources Appendix',
                       _sources_chips(ok_all, failed_all)
                       + '<p class="note">Aggregated across every kind looked up in '
                         'this investigation.</p>'))

    errors = payload.get('errors')
    if isinstance(errors, (list, tuple)) and errors:
        items = ''.join(f'<li>{_esc(item)}</li>' for item in errors)
        body.append(_panel('Errors', f'<ul class="errors">{items}</ul>'))

    body.append(_footer())
    title = f'ObscuraLens · investigation · {target or "target"}'
    return _page(title, '\n'.join(body))


def build_history_report(records: Optional[List[Dict[str, Any]]] = None) -> str:
    """
    Build the history analytics report over the stored lookup journal.

    Args:
        records: optional pre-loaded records; ``None`` loads the stored
            history through the patterns module (which supplements the
            kinds the correlation engine skips)

    Returns:
        A standalone HTML document with: summary chips (total lookups,
        distinct targets, kinds, date span), a lookups-per-day sparkline
        plus bar chart (last 90 days), the kind-distribution donut with a
        colour legend and share table, the top-targets table and the
        pattern-of-life highlights (top 10 targets by stored activity,
        with peak hour and night ratio). Empty history renders an honest
        "nothing recorded yet" report instead of blank charts.
    """
    from .patterns import (  # lazy: reuse the analytics + record plumbing
        _load_records,
        _normalise_records,
        _parse_timestamp,
        all_targets_pattern,
    )
    # None loads the stored history (all 14 kinds); anything else is normalised.
    recs = _load_records() if records is None else _normalise_records(records)

    moments: List[datetime] = []
    day_counts: Dict[str, int] = {}
    kind_counts: Dict[str, int] = {}
    target_counts: Dict[Tuple[str, str], int] = {}
    for record in recs:
        kind = str(record.get('kind') or 'unknown')
        value = str(record.get('value') or '')
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        if value:
            key = (kind, value)
            target_counts[key] = target_counts.get(key, 0) + 1
        moment = _parse_timestamp(record.get('timestamp'))
        if moment is None:
            continue
        moments.append(moment)
        day = moment.strftime('%Y-%m-%d')
        day_counts[day] = day_counts.get(day, 0) + 1
    moments.sort()

    body: List[str] = []
    body.append(_header(
        'history', 'Stored lookup analytics',
        f'History report · generated {_generated_text()} · '
        f'ObscuraLens v{__version__} · data never left this machine'))
    body.append('<div class="chips">' + ''.join([
        _stat_chip('Lookups', len(recs), 'info'),
        _stat_chip('Distinct targets', len(target_counts)),
        _stat_chip('Kinds', len(kind_counts)),
        _stat_chip('First seen', moments[0].strftime('%Y-%m-%d') if moments else '—'),
        _stat_chip('Last seen', moments[-1].strftime('%Y-%m-%d') if moments else '—'),
    ]) + '</div>')

    if not recs:
        body.append(_panel('Lookups Over Time',
                           '<p class="muted">Nothing has been recorded yet - run a '
                           'lookup and the journal starts filling in.</p>'))
        body.append(_footer())
        return _page('ObscuraLens · history report', '\n'.join(body))

    days = sorted(day_counts)
    shown_days = days[-90:]
    if shown_days:
        series = [day_counts[day] for day in shown_days]
        note = ('' if len(days) <= 90
                else f'<p class="note">Showing the most recent {len(shown_days)} of '
                     f'{len(days)} active days.</p>')
        chart = (_svg_sparkline(series)
                 + _svg_bars(series)
                 + f'<p class="muted">{_esc(shown_days[0])} &rarr; '
                   f'{_esc(shown_days[-1])} · peak {max(series)} lookups on one day</p>'
                 + note)
        body.append(_panel('Lookups Over Time', chart))
    else:
        # Records exist but none carried a parseable timestamp: the day
        # buckets are empty, so charting them would index into nothing.
        body.append(_panel('Lookups Over Time',
                           '<p class="muted">No parseable timestamps in the '
                           'recorded history - the day-by-day chart needs '
                           'dated records.</p>'))

    ranked_kinds = sorted(kind_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    slices = [{'label': kind, 'value': count, 'color': _kind_color(kind)}
              for kind, count in ranked_kinds]
    donut = _svg_donut(slices)
    legend_rows = ''.join(
        f'<tr><td><span class="key" style="background:{_kind_color(kind)}"></span>'
        f'{_esc(kind)}</td><td>{count}</td>'
        f'<td>{count * 100.0 / len(recs):.1f}%</td></tr>'
        for kind, count in ranked_kinds)
    legend = ('<table><thead><tr><th>Kind</th><th>Lookups</th><th>Share</th></tr>'
              f'</thead><tbody>{legend_rows}</tbody></table>')
    body.append(_panel('Kind Distribution',
                       f'<div class="donut-row">{donut or ""}<div class="legend">'
                       f'{legend}</div></div>' if donut else legend))

    top_targets = sorted(target_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:15]
    target_rows = ''.join(
        f'<tr><td><span class="key" style="background:{_kind_color(kind)}"></span>'
        f'{_esc(kind)}</td><td class="mono">{_esc(value)}</td>'
        f'<td>{count}</td></tr>'
        for (kind, value), count in top_targets)
    body.append(_panel('Top Targets',
                       '<table><thead><tr><th>Kind</th><th>Target</th>'
                       f'<th>Lookups</th></tr></thead><tbody>{target_rows}</tbody>'
                       '</table>'))

    highlights = all_targets_pattern(recs)[:10]
    if highlights:
        hl_rows = ''.join(
            f'<tr><td><span class="key" style="background:{_kind_color(entry["kind"])}">'
            f'</span>{_esc(entry["kind"])}</td>'
            f'<td class="mono">{_esc(entry["value"])}</td>'
            f'<td>{_esc(entry["count"])}</td>'
            f'<td>{_esc(entry["peak_hour"]) if entry["peak_hour"] is not None else "&mdash;"}</td>'
            f'<td>{_esc(entry["night_ratio"])}</td></tr>'
            for entry in highlights)
        body.append(_panel('Pattern-of-Life Highlights',
                           '<table><thead><tr><th>Kind</th><th>Target</th>'
                           '<th>Lookups</th><th>Peak hour</th><th>Night ratio</th>'
                           f'</tr></thead><tbody>{hl_rows}</tbody></table>'
                           '<p class="note">Targets with 3+ stored lookups; night '
                           'ratio is the fraction of lookups between 22:00 and '
                           '06:00 of the stored timestamp.</p>'))

    body.append(_footer())
    return _page('ObscuraLens · history report', '\n'.join(body))


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def save_report(path: str, html: str) -> str:
    """
    Write a report to ``path`` as UTF-8 (parent directories created).

    Args:
        path: destination file path
        html: the document produced by one of the ``build_*`` functions

    Returns:
        The path written, as a string.
    """
    destination = Path(path)
    parent = destination.parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html if isinstance(html, str) else str(html),
                           encoding='utf-8')
    return str(destination)


def report_path(kind: str, target: str, base_dir: Optional[str] = None) -> str:
    """
    A safe, timestamped report filename under the configured report directory.

    The shape is ``reports/report_<kind>_<safe-target>_<YYYYmmdd_HHMMSS>.html``
    (e.g. ``reports/report_ip_8.8.8.8_20250101_120000.html``): the target
    is reduced to ``[0-9A-Za-z._-]`` (everything else becomes ``_``,
    capped at 60 characters) so no path traversal or filesystem-unfriendly
    character survives.

    Args:
        kind: tracker kind (sanitised into the filename)
        target: the looked-up indicator (sanitised into the filename)
        base_dir: override directory; defaults to
            ``config.app_config.report_dir``

    Returns:
        The absolute-or-relative path (string); the directory is created
        with ``mkdir -p`` semantics before returning.
    """
    base = Path(base_dir) if base_dir else Path(
        str(config.app_config.report_dir or 'reports'))
    kind_slug = re.sub(r'[^0-9A-Za-z_-]+', '', str(kind or 'target')).strip('_-').lower()
    kind_slug = kind_slug or 'target'
    target_slug = re.sub(r'[^0-9A-Za-z._-]+', '_', str(target or ''))
    target_slug = target_slug.replace('..', '_').strip('_.')[:60] or 'target'
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base.mkdir(parents=True, exist_ok=True)
    return str(base / f'report_{kind_slug}_{target_slug}_{stamp}.html')
