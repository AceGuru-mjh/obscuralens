"""
Parallel batch lookups across many targets of one kind (v5.0).

Real OSINT work is rarely one indicator at a time: an analyst pastes a
column of IPs out of a firewall log, exports a thousand IOCs from a SIEM,
or wants every username variant of a subject checked before the morning
brief. Doing that by hand, one workbench lookup at a time, is where
afternoons go to die - and where typos sneak in.

This module turns a list of targets into a fan-out engine:

* :func:`run_batch` - run every target of one kind through its tracker
  concurrently (bounded :class:`~concurrent.futures.ThreadPoolExecutor`,
  default 6 workers). One bad row never kills the run: every failure is
  captured per-target and the summary keeps counting. Optional heuristic
  risk scoring is attached to each result (``risk=True``), a progress
  callback reports ``(done, total, target)`` after every completion for
  progress bars, and a ``stop_flag`` callable lets a UI cancel mid-batch.
  Input is capped at 200 targets per run so a stray paste cannot turn into
  an accidental crawl; the excess is counted in ``skipped``.
* :func:`run_mixed` - the same engine for ``[{'kind', 'target'}, ...]``
  pairs, so a triage list mixing IPs, domains and hashes can be enriched
  in one call, each row dispatched to its own tracker.
* :func:`to_csv` / :func:`to_json` / :func:`to_markdown` - render a run
  into the three shapes analysts actually hand around: a spreadsheet
  (target, verdict, field count, error plus the top-8 merged fields as
  extra columns), a lossless JSON dump, and a markdown table with the
  summary block. :func:`save` writes any of them to disk.
* :func:`main` - a CLI wrapper so the module doubles as a tool::

      python -m obscuralens.advanced.batch ip targets.txt --format csv > out.csv
      python -m obscuralens.advanced.batch email targets.txt --risk --workers 8

Trackers are imported lazily, one per kind, so importing this module never
pulls the whole tracker fleet (or its optional dependencies) into memory
until a batch actually runs. All HTTP happens through the trackers'
own shared client - this module adds no requests of its own.
"""

import argparse
import contextlib
import csv
import io
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

__all__ = [
    'DEFAULT_WORKERS',
    'MAX_TARGETS',
    'SUPPORTED_KINDS',
    'main',
    'run_batch',
    'run_mixed',
    'save',
    'to_csv',
    'to_json',
    'to_markdown',
]

#: Every kind the batch engine can fan out to (the full v5.0 set of 14).
SUPPORTED_KINDS: Tuple[str, ...] = (
    'ip', 'phone', 'username', 'email', 'domain', 'url', 'crypto', 'hash',
    'cve', 'asn', 'mac', 'iban', 'imei', 'coords',
)

#: Upper bound on targets processed per run; the remainder is ignored and
#: reported in the result's ``skipped`` counter.
MAX_TARGETS = 200

#: Worker threads used when the caller does not say otherwise.
DEFAULT_WORKERS = 6

#: Lazy tracker resolution table: kind -> (tracker module, class name).
#: Modules are imported inside :func:`_tracker_for` so importing this
#: module stays cheap and import-cycle free.
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


# ---------------------------------------------------------------------------
# Tracker resolution and single-target execution
# ---------------------------------------------------------------------------

def _tracker_for(kind: str) -> Type[Any]:
    """
    Resolve the tracker class for a kind, importing it lazily.

    The tracker modules are imported on first use (and cached by Python's
    import machinery afterwards) so this module's import cost stays flat
    and no import cycle can form between the trackers and the advanced
    analysis package.

    Args:
        kind: one of :data:`SUPPORTED_KINDS`

    Returns:
        The tracker class (instantiate it and call ``track(value)``).

    Raises:
        ValueError: when ``kind`` is not in :data:`SUPPORTED_KINDS`.
    """
    spec = _TRACKER_CLASSES.get(kind)
    if spec is None:
        raise ValueError(
            f"unsupported kind {kind!r}; choose one of: {', '.join(SUPPORTED_KINDS)}")
    module_name, class_name = spec
    module = import_module(f"..trackers.{module_name}", package=__package__)
    return getattr(module, class_name)


def _info_of(result: Any) -> Dict[str, Any]:
    """
    The merged ``info`` field mapping of a tracker result (``{}`` for junk).

    Every v5.0 tracker result carries its fields under ``info``; payloads
    that keep fields at the top level (older shapes) are returned as-is so
    CSV flattening still finds them.
    """
    if not isinstance(result, dict):
        return {}
    info = result.get('info')
    if isinstance(info, dict):
        return info
    return result


def _run_one(kind: str, target: str, risk: bool) -> Dict[str, Any]:
    """
    Run a single tracker lookup and package it as a batch entry.

    This is the unit of work submitted to the thread pool. It never
    raises: a tracker that explodes, an unknown kind or a failing risk
    enrichment all degrade into a well-formed failure entry so the rest
    of the batch keeps running.

    Args:
        kind: tracker kind (validated by :func:`_tracker_for`)
        target: the indicator value to look up
        risk: attach the heuristic risk block to the result

    Returns:
        ``{'target', 'success', 'field_count', 'error', 'result'}``.
    """
    try:
        tracker_cls = _tracker_for(kind)
        result = tracker_cls().track(target)
    except Exception as exc:  # one broken target must never kill the batch
        return {'target': target, 'success': False, 'field_count': 0,
                'error': f"{type(exc).__name__}: {exc}", 'result': None}

    if risk and isinstance(result, dict):
        with contextlib.suppress(Exception):  # risk scoring is best-effort
            from ..correlation import attach_risk  # lazy: correlation engine
            attach_risk(kind, result)

    error_text = ''
    if isinstance(result, dict):
        errors = result.get('errors')
        if isinstance(errors, (list, tuple)):
            error_text = '; '.join(str(item) for item in errors if item)
        elif result.get('error'):
            error_text = str(result['error'])
    try:
        field_count = int(result.get('field_count') or 0)
    except (AttributeError, TypeError, ValueError):
        field_count = 0
    success = bool(result.get('success')) if isinstance(result, dict) else False
    return {'target': target, 'success': success, 'field_count': field_count,
            'error': error_text, 'result': result}


# ---------------------------------------------------------------------------
# Batch engine
# ---------------------------------------------------------------------------

def _clean_targets(targets: Any) -> List[str]:
    """
    Coerce the ``targets`` argument into a list of stripped non-empty strings.

    A single string is treated as one target; an iterable is stringified
    item by item; anything unusable yields ``[]``. Duplicates are kept
    verbatim (a re-run of the same target is a legitimate request).
    """
    if targets is None:
        return []
    if isinstance(targets, str):
        candidates: List[Any] = [targets]
    else:
        try:
            candidates = list(targets)
        except TypeError:
            return []
    cleaned: List[str] = []
    for item in candidates:
        text = str(item or '').strip()
        if text:
            cleaned.append(text)
    return cleaned


def _stop_requested(stop_flag: Any) -> bool:
    """Whether the caller asked the batch to stop (a raising flag counts as no)."""
    if stop_flag is None:
        return False
    with contextlib.suppress(Exception):
        return bool(stop_flag())
    return False


def _report_progress(progress: Any, done: int, total: int, target: str) -> None:
    """Invoke the progress callback; a broken callback never fails the batch."""
    if progress is None:
        return
    with contextlib.suppress(Exception):
        progress(done, total, target)


def _drive(work_items: List[Tuple[str, str]], risk: bool, max_workers: int,
           progress: Any, stop_flag: Any) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Shared fan-out loop behind :func:`run_batch` and :func:`run_mixed`.

    Args:
        work_items: ``(kind, target)`` pairs already capped and cleaned
        risk: attach risk blocks to each result
        max_workers: thread pool size (clamped to the workload)
        progress: optional ``progress(done, total, target)`` callback
        stop_flag: optional callable returning truthy to stop between items

    Returns:
        ``(entries, stopped)`` - the per-target result entries (in
        completion order) and whether the run was interrupted.
    """
    total = len(work_items)
    entries: List[Dict[str, Any]] = []
    if not total:
        return entries, False
    try:
        workers = max(1, min(int(max_workers or DEFAULT_WORKERS), total))
    except (TypeError, ValueError):
        workers = min(DEFAULT_WORKERS, total)
    stopped = False
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(_run_one, kind, target, risk): (kind, target)
            for kind, target in work_items
        }
        for done, future in enumerate(as_completed(future_map), start=1):
            if _stop_requested(stop_flag):  # checked between items
                stopped = True
                for pending in future_map:
                    pending.cancel()
                break
            kind, target = future_map[future]
            try:
                entry = future.result()
            except Exception as exc:  # defensive: _run_one already catches
                entry = {'target': target, 'success': False, 'field_count': 0,
                         'error': f"{type(exc).__name__}: {exc}", 'result': None}
            entries.append(entry)
            _report_progress(progress, done, total, target)
    return entries, stopped


def _summarise(kind: str, entries: List[Dict[str, Any]], started: float,
               total: int) -> Dict[str, Any]:
    """Summary statistics block shared by both runners."""
    ok = sum(1 for entry in entries if entry.get('success'))
    fields_total = 0
    for entry in entries:
        try:
            fields_total += int(entry.get('field_count') or 0)
        except (TypeError, ValueError):
            continue
    return {
        'total': total,
        'ok': ok,
        'failed': len(entries) - ok,
        'elapsed': round(time.monotonic() - started, 3),
        'fields_total': fields_total,
    }


def run_batch(kind: str, targets: Any = None, risk: bool = False,
              max_workers: int = DEFAULT_WORKERS, progress: Any = None,
              stop_flag: Any = None) -> Dict[str, Any]:
    """
    Look up many targets of one kind concurrently.

    The classic batch shape: paste a list of IPs (or hashes, IBANs,
    usernames...) and get one entry per target plus a summary. Targets are
    capped at :data:`MAX_TARGETS`; the surplus is ignored and counted in
    ``skipped``. Individual failures - invalid values, unreachable
    sources, tracker exceptions - are captured per entry and never raise.

    Args:
        kind: tracker kind, one of :data:`SUPPORTED_KINDS`
        targets: iterable of target strings (a bare string counts as one)
        risk: attach the heuristic risk block to every result
        max_workers: thread pool size (default :data:`DEFAULT_WORKERS`)
        progress: optional ``progress(done, total, target)`` callback fired
            after each completed lookup
        stop_flag: optional callable returning truthy to stop the run
            between items (pending lookups are cancelled)

    Returns:
        ``{'kind', 'risk', 'skipped', 'stopped', 'results', 'summary'}``;
        ``results`` entries are ``{'target', 'success', 'field_count',
        'error', 'result'}`` and ``summary`` is ``{'total', 'ok',
        'failed', 'elapsed', 'fields_total'}``. An unsupported kind yields
        the same shape with an ``error`` message and empty results instead
        of an exception, so API callers can surface it cleanly.
    """
    started = time.monotonic()
    kind = str(kind or '').strip().lower()
    if kind not in SUPPORTED_KINDS:
        return {
            'kind': kind, 'risk': bool(risk), 'skipped': 0, 'stopped': False,
            'results': [],
            'summary': {'total': 0, 'ok': 0, 'failed': 0, 'elapsed': 0.0,
                        'fields_total': 0},
            'error': f"unsupported kind {kind!r}; choose one of: "
                     f"{', '.join(SUPPORTED_KINDS)}",
        }

    cleaned = _clean_targets(targets)
    skipped = max(0, len(cleaned) - MAX_TARGETS)
    work_items = [(kind, target) for target in cleaned[:MAX_TARGETS]]
    entries, stopped = _drive(work_items, risk, max_workers, progress, stop_flag)
    return {
        'kind': kind,
        'risk': bool(risk),
        'skipped': skipped,
        'stopped': stopped,
        'results': entries,
        'summary': _summarise(kind, entries, started, len(work_items)),
    }


def run_mixed(pairs: Any = None, risk: bool = False,
              max_workers: int = DEFAULT_WORKERS, progress: Any = None,
              stop_flag: Any = None) -> Dict[str, Any]:
    """
    Look up a mixed list of ``{'kind', 'target'}`` pairs concurrently.

    Triage lists rarely respect kind boundaries: a pasted incident block
    is two IPs, a domain and a hash. Each pair is dispatched to its own
    tracker inside one shared thread pool, so the whole list enriches in
    a single call. Pairs that are not dicts, miss a target or name an
    unknown kind become per-item failure entries (counted in
    ``malformed`` for the first two) - the run itself never raises.

    Args:
        pairs: iterable of ``{'kind': str, 'target': str}`` dicts
        risk: attach the heuristic risk block to every result
        max_workers: thread pool size (default :data:`DEFAULT_WORKERS`)
        progress: optional ``progress(done, total, target)`` callback
        stop_flag: optional callable returning truthy to stop between items

    Returns:
        Same shape as :func:`run_batch` with ``kind='mixed'`` plus a
        ``malformed`` counter for unusable pairs.
    """
    started = time.monotonic()
    cleaned: List[Tuple[str, str]] = []
    malformed = 0
    try:
        candidates = list(pairs or [])
    except TypeError:
        candidates = []
    for pair in candidates:
        if not isinstance(pair, dict):
            malformed += 1
            continue
        target = str(pair.get('target') or '').strip()
        kind = str(pair.get('kind') or '').strip().lower()
        if not target:
            malformed += 1
            continue
        cleaned.append((kind, target))

    skipped = max(0, len(cleaned) - MAX_TARGETS)
    work_items = cleaned[:MAX_TARGETS]
    entries, stopped = _drive(work_items, risk, max_workers, progress, stop_flag)
    result = {
        'kind': 'mixed',
        'risk': bool(risk),
        'skipped': skipped,
        'malformed': malformed,
        'stopped': stopped,
        'results': entries,
        'summary': _summarise('mixed', entries, started, len(work_items)),
    }
    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _result_rows(results: Any) -> List[Dict[str, Any]]:
    """
    The per-target entry list out of a run result or a raw entry list.

    Both ``run_batch(...)`` dicts (take ``results``) and pre-extracted
    entry lists are accepted so the renderers work on either.
    """
    if isinstance(results, dict) and isinstance(results.get('results'), list):
        return [row for row in results['results'] if isinstance(row, dict)]
    if isinstance(results, list):
        return [row for row in results if isinstance(row, dict)]
    return []


def _stringify(value: Any) -> str:
    """
    Flatten one field value into CSV/markdown-safe display text.

    Lists become ``'; '``-joined items, dicts compact JSON, booleans
    ``true``/``false``, and ``None`` an empty string - the shapes that
    survive a round-trip through a spreadsheet cell.
    """
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (list, tuple)):
        return '; '.join(_stringify(item) for item in value if item is not None)
    if isinstance(value, dict):
        with contextlib.suppress(TypeError, ValueError):
            return json.dumps(value, default=str, ensure_ascii=False)
        return str(value)
    return str(value)


def _top_fields(rows: List[Dict[str, Any]], limit: int = 8) -> List[str]:
    """
    The ``limit`` field names most often present across a batch's results.

    Ranking by frequency (name ascending as tie-break) picks the fields
    that actually describe this dataset - ``country_name`` for a geo-rich
    IP batch, ``valid`` for an IBAN triage - instead of an arbitrary
    prefix of the first result.
    """
    counts: Dict[str, int] = {}
    for row in rows:
        info = _info_of(row.get('result'))
        for name in info:
            if isinstance(name, str) and name:
                counts[name] = counts.get(name, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [name for name, _count in ranked[:limit]]


def to_csv(results: Any) -> str:
    """
    Render a batch run as CSV text.

    Columns are ``target, success, field_count, error`` followed by the
    top-8 merged fields (ranked by how many rows carry them); each extra
    cell holds the field's value flattened from ``result.info`` via
    :func:`_stringify`. Rows with no result contribute empty cells, so a
    failed row still lines up with its siblings in the spreadsheet.
    """
    rows = _result_rows(results)
    field_names = _top_fields(rows, 8)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerow(['target', 'success', 'field_count', 'error'] + field_names)
    for row in rows:
        info = _info_of(row.get('result'))
        writer.writerow(
            [row.get('target') or '',
             'true' if row.get('success') else 'false',
             row.get('field_count') or 0,
             row.get('error') or ''] +
            [_stringify(info.get(name)) for name in field_names])
    return buffer.getvalue()


def to_json(results: Any) -> str:
    """
    Render a batch run as pretty JSON (the full result, nothing dropped).

    Non-serialisable values fall back to ``str()`` so a stray datetime in
    a tracker payload cannot break the export.
    """
    try:
        return json.dumps(results, indent=2, default=str, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return json.dumps({'error': 'results could not be serialised'})


def _md_cell(value: Any, cap: int = 80) -> str:
    """Markdown-table-safe, length-capped text for one cell."""
    text = _stringify(value).replace('|', '\\|').replace('\n', ' ').strip()
    return text[:cap] + '…' if len(text) > cap else text


def to_markdown(results: Any) -> str:
    """
    Render a batch run as a markdown table plus summary block.

    The table keeps one row per target (Target / Status / Fields / Error)
    and the summary block carries the run statistics - the shape that
    pastes straight into an incident channel or a case note.
    """
    rows = _result_rows(results)
    kind = results.get('kind') if isinstance(results, dict) else None
    summary = results.get('summary') if isinstance(results, dict) else None
    lines: List[str] = ['# ObscuraLens batch results']
    if kind:
        lines.append('')
        lines.append(f'**Kind:** `{kind}`')
    lines.append('')
    lines.append('| Target | Status | Fields | Error |')
    lines.append('|---|---|---:|---|')
    for row in rows:
        status = 'ok' if row.get('success') else 'failed'
        lines.append(
            f"| {_md_cell(row.get('target'))} | {status} "
            f"| {row.get('field_count') or 0} | {_md_cell(row.get('error'), 60)} |")
    if not rows:
        lines.append('| _no targets processed_ |  |  | |')
    lines.append('')
    if isinstance(summary, dict):
        lines.append('## Summary')
        lines.append('')
        lines.append(f"- **Targets processed:** {summary.get('total', 0)}")
        lines.append(f"- **Succeeded:** {summary.get('ok', 0)}")
        lines.append(f"- **Failed:** {summary.get('failed', 0)}")
        lines.append(f"- **Fields collected:** {summary.get('fields_total', 0)}")
        elapsed = summary.get('elapsed')
        if elapsed is not None:
            lines.append(f"- **Elapsed:** {elapsed}s")
    if isinstance(results, dict) and results.get('skipped'):
        lines.append(f"- **Skipped (over cap):** {results['skipped']}")
    if isinstance(results, dict) and results.get('stopped'):
        lines.append('- **Stopped early:** stop flag requested cancellation')
    return '\n'.join(lines) + '\n'


def save(path: str, results: Any, fmt: str = 'markdown') -> str:
    """
    Write a batch run to ``path`` in the requested format.

    Parent directories are created as needed so ``--output out/batch.csv``
    works without a prior ``mkdir``.

    Args:
        path: destination file path
        results: a run result (dict) or entry list
        fmt: ``'csv'``, ``'json'`` or ``'markdown'`` (``'md'`` accepted)

    Returns:
        The path written, as a string.

    Raises:
        ValueError: when ``fmt`` is not one of the supported formats.
    """
    fmt = str(fmt or 'markdown').strip().lower()
    if fmt == 'md':
        fmt = 'markdown'
    renderers = {'csv': to_csv, 'json': to_json, 'markdown': to_markdown}
    renderer = renderers.get(fmt)
    if renderer is None:
        raise ValueError(f"unsupported format {fmt!r}; choose csv, json or markdown")
    destination = Path(path)
    if destination.parent and str(destination.parent):
        destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(renderer(results), encoding='utf-8')
    return str(destination)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read_targets(source: Optional[str]) -> List[str]:
    """
    Read the target list for the CLI: a file path, ``-`` or stdin.

    One target per line; blank lines and ``#`` comments are dropped. When
    the source is omitted and stdin is a terminal the caller gets ``[]``
    (a usage error) instead of blocking forever.
    """
    if source and source != '-':
        with open(source, 'r', encoding='utf-8', errors='replace') as handle:
            lines = handle.readlines()
    else:
        if sys.stdin.isatty():
            return []
        lines = sys.stdin.readlines()
    targets: List[str] = []
    for line in lines:
        text = line.strip()
        if not text or text.startswith('#'):
            continue
        targets.append(text)
    return targets


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI entry point: ``python -m obscuralens.advanced.batch``.

    Reads targets (file or stdin), runs the batch and prints the chosen
    format to stdout, or writes it to ``--output``. Exit codes: ``0`` on a
    completed run (individual target failures are part of the result, not
    an error), ``2`` on bad usage, an unreadable targets file or an
    unsupported kind.
    """
    parser = argparse.ArgumentParser(
        prog='python -m obscuralens.advanced.batch',
        description='Parallel batch lookups: enrich a list of targets of one kind '
                    'and render csv, json or markdown output.')
    parser.add_argument('kind', help=f"target kind; one of: {', '.join(SUPPORTED_KINDS)}")
    parser.add_argument('targets', nargs='?', default=None,
                        help="file with one target per line ('#' comments allowed); "
                             "'-' or omitted reads stdin")
    parser.add_argument('--risk', action='store_true',
                        help='attach heuristic risk scores to every result')
    parser.add_argument('--format', '-f', choices=('csv', 'json', 'markdown'),
                        default='markdown', help='output format (default: markdown)')
    parser.add_argument('--output', '-o', default=None,
                        help='write to this file instead of stdout')
    parser.add_argument('--workers', '-w', type=int, default=DEFAULT_WORKERS,
                        help=f'parallel workers (default: {DEFAULT_WORKERS})')
    args = parser.parse_args(argv)

    try:
        targets = _read_targets(args.targets)
    except OSError as exc:
        print(f"error: cannot read targets: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print('error: no targets to process '
              '(expected a file of one target per line, or piped stdin)',
              file=sys.stderr)
        return 2

    result = run_batch(args.kind, targets, risk=args.risk, max_workers=args.workers)
    if result.get('error'):
        print(f"error: {result['error']}", file=sys.stderr)
        return 2

    if args.output:
        path = save(args.output, result, fmt=args.format)
        summary = result['summary']
        print(f"wrote {path} ({summary['ok']} ok, {summary['failed']} failed)",
              file=sys.stderr)
        return 0

    if args.format == 'csv':
        text = to_csv(result)
    elif args.format == 'json':
        text = to_json(result)
    else:
        text = to_markdown(result)
    sys.stdout.write(text if text.endswith('\n') else text + '\n')
    return 0


if __name__ == '__main__':  # pragma: no cover - CLI guard
    sys.exit(main())
