"""
Non-interactive command-line interface.

Examples:
    obscuralens ip 8.8.8.8 --format json
    obscuralens username github --fast
    obscuralens batch ip targets.txt --format csv --output results.csv
    obscuralens history --search 8.8.8.8
    obscuralens stats
    obscuralens sources
    obscuralens keys
    obscuralens cache clear

Running `obscuralens` with no arguments opens the interactive console.
Result data goes to stdout; progress and diagnostics go to stderr, so output
can be piped safely.
"""

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .config import SERVICES, config
from .core.cache import cache
from .core.metrics import metrics
from .database import db
from .investigate import (
    detect_kind,
    investigate,
    investigate_sections,
    to_mermaid,
)
from .plugins import loaded_plugins, reload_plugins
from .reporting import ReportGenerator, batch_sections, sections_for
from .trackers import (
    DomainTracker,
    EmailTracker,
    IPTracker,
    PhoneTracker,
    UsernameTracker,
)
from .utils import render_table, set_colors
from .utils.formatting import fmt_value, rows_from_fields
from .utils.validators import (
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_username,
)
from .watchlist import watchlist

KINDS = ('ip', 'phone', 'username', 'email', 'domain')
FORMATS = ('table', 'json', 'markdown', 'html', 'csv', 'mermaid')

_TRACKERS: Dict[str, Any] = {}


def _tracker(kind: str):
    if kind not in _TRACKERS:
        _TRACKERS[kind] = {
            'ip': IPTracker,
            'phone': PhoneTracker,
            'username': UsernameTracker,
            'email': EmailTracker,
            'domain': DomainTracker,
        }[kind]()
    return _TRACKERS[kind]


def _err(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def _info(message: str) -> None:
    print(message, file=sys.stderr)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='obscuralens',
        description='Multi-source OSINT console for IPs, phones, usernames, '
                    'emails and domains.',
        epilog='Run without arguments to open the interactive console.')
    parser.add_argument('--version', action='version',
                        version=f'ObscuraLens {__version__}')

    sub = parser.add_subparsers(dest='command', metavar='<command>')

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument('-f', '--format', choices=FORMATS, default=None,
                       help='output format (default: table)')
        p.add_argument('-o', '--output', metavar='FILE',
                       help='write output to FILE instead of stdout')
        p.add_argument('--timeout', type=int, metavar='SECONDS',
                       help='HTTP timeout for this run')
        p.add_argument('--no-cache', action='store_true',
                       help='bypass the response cache')
        p.add_argument('--no-color', action='store_true',
                       help='disable ANSI colours')

    p_ip = sub.add_parser('ip', help='look up an IP address')
    p_ip.add_argument('target', help='IPv4 or IPv6 address')
    add_common(p_ip)

    p_phone = sub.add_parser('phone', help='look up a phone number')
    p_phone.add_argument('target', help='phone number')
    p_phone.add_argument('--region', default='ID',
                         help='default region code (default: ID)')
    add_common(p_phone)

    p_user = sub.add_parser('username', help='scan platforms for a username')
    p_user.add_argument('target', help='username')
    p_user.add_argument('--fast', action='store_true',
                        help='skip profile extraction on hits')
    p_user.add_argument('--platforms', metavar='LIST',
                        help='comma-separated platform names to scan')
    add_common(p_user)

    p_email = sub.add_parser('email', help='look up an email address')
    p_email.add_argument('target', help='email address')
    add_common(p_email)

    p_domain = sub.add_parser('domain', help='look up a domain')
    p_domain.add_argument('target', help='domain name')
    add_common(p_domain)

    p_inv = sub.add_parser(
        'investigate',
        help='auto-detect a target and follow related pivots')
    p_inv.add_argument('target', help='IP / domain / email / phone / username')
    p_inv.add_argument('--no-pivot', action='store_false', dest='pivot',
                       help='do not follow related targets')
    p_inv.add_argument('--max-pivots', type=int, default=3,
                       help='maximum related lookups per kind (default: 3)')
    p_inv.add_argument('--graph', metavar='FILE',
                       help='also write a Mermaid graph to FILE')
    add_common(p_inv)

    p_watch = sub.add_parser('watch', help='watch targets and detect changes')
    watch_sub = p_watch.add_subparsers(dest='action', metavar='<action>')
    p_watch_add = watch_sub.add_parser('add', help='start watching a target')
    p_watch_add.add_argument('target')
    p_watch_add.add_argument('--kind', choices=KINDS)
    p_watch_add.add_argument('--label', default='')
    add_common(p_watch_add)
    p_watch_list = watch_sub.add_parser('list', help='list watched targets')
    add_common(p_watch_list)
    p_watch_rm = watch_sub.add_parser('remove', help='stop watching')
    p_watch_rm.add_argument('identifier', help='watch id or target')
    add_common(p_watch_rm)
    p_watch_check = watch_sub.add_parser('check', help='run and diff watched targets')
    p_watch_check.add_argument('identifier', nargs='?',
                               help='watch id or target (default: all)')
    add_common(p_watch_check)

    p_plugins = sub.add_parser('plugins', help='list or reload data-source plugins')
    plugins_sub = p_plugins.add_subparsers(dest='action', metavar='<action>')
    add_common(plugins_sub.add_parser('list', help='show loaded plugins'))
    add_common(plugins_sub.add_parser('reload', help='rescan plugin directories'))

    p_serve = sub.add_parser('serve', help='web UI + REST API (needs [web] extra)')
    p_serve.add_argument('--host', default='127.0.0.1')
    p_serve.add_argument('--port', type=int, default=8000)
    p_serve.add_argument('--reload', action='store_true',
                         help='auto-reload on code changes (development)')
    add_common(p_serve)

    p_tui = sub.add_parser('tui', help='terminal UI (needs [tui] extra)')
    add_common(p_tui)

    p_mcp = sub.add_parser('mcp', help='MCP stdio server for AI assistants')
    add_common(p_mcp)
    add_common(p_plugins)

    p_batch = sub.add_parser('batch', help='look up many targets from a file')
    p_batch.add_argument('kind', choices=KINDS, help='target type')
    p_batch.add_argument('file', help='text file with one target per line')
    p_batch.add_argument('--region', default='ID',
                         help='default region for phone numbers')
    p_batch.add_argument('--workers', type=int, default=4)
    add_common(p_batch)

    p_hist = sub.add_parser('history', help='browse stored query history')
    p_hist.add_argument('--search', metavar='TERM')
    p_hist.add_argument('--id', type=int, metavar='N')
    p_hist.add_argument('--type', choices=KINDS, dest='kind')
    p_hist.add_argument('--limit', type=int, default=25)
    add_common(p_hist)

    p_stats = sub.add_parser('stats', help='database, cache and network stats')
    add_common(p_stats)

    p_sources = sub.add_parser('sources', help='list data sources')
    p_sources.add_argument('kind', nargs='?', choices=KINDS)
    add_common(p_sources)

    p_keys = sub.add_parser('keys', help='show API key configuration')
    add_common(p_keys)

    p_cache = sub.add_parser('cache', help='manage the response cache')
    p_cache.add_argument('action', choices=('stats', 'clear'))
    add_common(p_cache)

    p_config = sub.add_parser('config', help='show resolved configuration')
    add_common(p_config)

    return parser


def _apply_globals(args: argparse.Namespace) -> None:
    if getattr(args, 'timeout', None):
        config.app_config.request_timeout = int(args.timeout)
    if getattr(args, 'no_cache', False):
        config.app_config.cache_enabled = False
    if getattr(args, 'no_color', False):
        set_colors(False)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _emit(text: str, output: Optional[str]) -> None:
    if output:
        path = Path(output)
        if path.parent and str(path.parent) not in ('', '.'):
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        _info(f"Saved: {path}")
    else:
        print(text)


def _render_sections_text(sections: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for section in sections:
        parts.append(section.get('title', '').upper())
        if section['type'] == 'grid':
            parts.append(render_table([[k, v] for k, v in section['data'].items()],
                                      headers=['Field', 'Value']))
        elif section['type'] == 'table':
            parts.append(render_table(section['rows'],
                                      headers=section.get('columns')))
        elif section['type'] == 'text':
            parts.append(str(section.get('content', '')))
    return '\n\n'.join(part for part in parts if part)


def _csv_from_result(kind: str, result: Dict[str, Any]) -> str:
    if kind == 'username':
        rows = [{'platform': r.get('platform', ''), 'status': r.get('status', ''),
                 'confidence': r.get('confidence', ''), 'url': r.get('url', ''),
                 'reason': r.get('reason', '')}
                for r in result.get('results', [])]
    else:
        rows = [{'field': key, 'value': fmt_value(key, value)}
                for key, value in rows_from_fields(result.get('info', {}))]
    buffer = io.StringIO()
    if rows:
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return buffer.getvalue().rstrip('\n')


def _csv_from_batch(kind: str, results: List[Dict[str, Any]]) -> str:
    rows = []
    for r in results:
        info = r.get('info', {})
        rows.append({
            'target': r.get(kind, ''),
            'sources_ok': len(r.get('sources_ok', [])),
            'field_count': r.get('field_count', 0),
            'success': r.get('success', False),
            'country': info.get('country', ''),
            'city': info.get('city', ''),
            'org': info.get('org', ''),
            'registrar': info.get('registrar', ''),
        })
    buffer = io.StringIO()
    if rows:
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return buffer.getvalue().rstrip('\n')


def _emit_result(args: argparse.Namespace, kind: str, result: Dict[str, Any],
                 title: str) -> None:
    fmt = args.format or 'table'
    if fmt == 'json':
        _emit(json.dumps(result, indent=2, ensure_ascii=False, default=str),
              args.output)
    elif fmt == 'csv':
        _emit(_csv_from_result(kind, result), args.output)
    elif fmt in ('markdown', 'html'):
        sections = sections_for(kind, result)
        generator = ReportGenerator()
        data = {'sections': sections}
        text = (generator.render_markdown(data, title) if fmt == 'markdown'
                else generator.render_html(data, title))
        _emit(text, args.output)
    else:
        _emit(_render_sections_text(sections_for(kind, result)), args.output)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _run_lookup(args: argparse.Namespace, kind: str, target: str,
                title: str, **tracker_kwargs: Any) -> int:
    result = _tracker(kind).track(target, **tracker_kwargs)
    _emit_result(args, kind, result, title)
    if result.get('success'):
        if result.get('sources_failed'):
            _info(f"Warning: {len(result['sources_failed'])} source(s) "
                  f"unavailable: {', '.join(result['sources_failed'])}")
        return 0
    _err('all data sources failed')
    return 1


def _cmd_ip(args: argparse.Namespace) -> int:
    ok, error = validate_ip(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'ip', args.target, f"IP Report - {args.target}")


def _cmd_phone(args: argparse.Namespace) -> int:
    ok, error = validate_phone(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'phone', args.target,
                       f"Phone Report - {args.target}", default_region=args.region)


def _cmd_username(args: argparse.Namespace) -> int:
    ok, error = validate_username(args.target)
    if not ok:
        _err(error)
        return 2
    platforms = None
    if args.platforms:
        platforms = [p for p in args.platforms.split(',') if p.strip()]
        known = [p['name'] for p in UsernameTracker().platforms]
        unknown = [p for p in platforms
                   if not any(p.lower() in name.lower() for name in known)]
        if unknown:
            _err(f"unknown platform(s): {', '.join(unknown)}; "
                 f"see `obscuralens sources username`")
            return 2
    return _run_lookup(args, 'username', args.target,
                       f"Username Report - {args.target}",
                       deep=not args.fast, platforms=platforms)


def _cmd_email(args: argparse.Namespace) -> int:
    ok, error = validate_email(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'email', args.target, f"Email Report - {args.target}")


def _cmd_domain(args: argparse.Namespace) -> int:
    ok, error = validate_domain(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'domain', args.target,
                       f"Domain Report - {args.target}")


def _cmd_batch(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        _err(f"file not found: {path}")
        return 2
    targets = [line.strip() for line in
               path.read_text(encoding='utf-8').splitlines() if line.strip()]
    if not targets:
        _err('no targets in file')
        return 2

    validator = {
        'ip': validate_ip, 'phone': validate_phone, 'username': validate_username,
        'email': validate_email, 'domain': validate_domain,
    }[args.kind]
    invalid = [t for t in targets if not validator(t)[0]]
    if invalid:
        _err(f"{len(invalid)} invalid target(s), e.g. {invalid[0]!r}")
        return 2

    _info(f"Looking up {len(targets)} {args.kind} target(s)...")
    tracker = _tracker(args.kind)
    if args.kind == 'phone':
        results = tracker.batch_track(targets, args.region, args.workers)
    elif args.kind == 'username':
        results = tracker.batch_track(targets)
    else:
        results = tracker.batch_track(targets, args.workers)

    fmt = args.format or 'table'
    if fmt == 'json':
        _emit(json.dumps(results, indent=2, ensure_ascii=False, default=str),
              args.output)
    elif fmt == 'csv':
        _emit(_csv_from_batch(args.kind, results), args.output)
    elif fmt in ('markdown', 'html'):
        generator = ReportGenerator()
        data = {'sections': batch_sections(args.kind, results)}
        text = (generator.render_markdown(data, f"Batch {args.kind} report")
                if fmt == 'markdown' else
                generator.render_html(data, f"Batch {args.kind} report"))
        _emit(text, args.output)
    else:
        _emit(_render_sections_text(batch_sections(args.kind, results)),
              args.output)

    successes = sum(1 for r in results if r.get('success'))
    _info(f"{successes}/{len(results)} succeeded")
    return 0 if successes else 1


def _record_to_dict(record: Any) -> Dict[str, Any]:
    return {
        'id': record.id,
        'type': record.query_type,
        'value': record.query_value,
        'success': record.success,
        'created_at': record.created_at,
        'error': record.error_message or '',
    }


def _cmd_history(args: argparse.Namespace) -> int:
    if args.id is not None:
        record = db.get_query_by_id(args.id)
        if record is None:
            _err(f"record #{args.id} not found")
            return 1
        data = _record_to_dict(record)
        try:
            data['result'] = json.loads(record.result_data or '{}')
        except ValueError:
            data['result'] = {}
        if (args.format or 'table') == 'json':
            _emit(json.dumps(data, indent=2, ensure_ascii=False, default=str),
                  args.output)
        else:
            _emit(_render_sections_text([
                {'title': f"Record #{record.id}", 'type': 'grid',
                 'data': {k: v for k, v in data.items() if k not in ('result',)}},
            ]), args.output)
        return 0

    if args.search:
        records = db.search_history(args.search, limit=args.limit)
    else:
        records = db.get_history(query_type=args.kind, limit=args.limit)

    rows = [_record_to_dict(r) for r in records]
    if (args.format or 'table') == 'json':
        _emit(json.dumps(rows, indent=2, ensure_ascii=False, default=str),
              args.output)
    else:
        _emit(render_table(rows, headers=['id', 'type', 'value', 'success',
                                          'created_at', 'error']), args.output)
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    stats = db.get_statistics()
    payload = {
        'database': stats,
        'cache': cache.stats(),
        'network': metrics.snapshot(),
    }
    if (args.format or 'table') == 'json':
        _emit(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
              args.output)
        return 0

    parts = [
        'DATABASE',
        render_table([[k, v] for k, v in stats.items()
                      if k != 'queries_by_type'], headers=['Metric', 'Value']),
        'QUERIES BY TYPE',
        render_table(stats['queries_by_type'] or {'(none)': 0},
                     headers=['Type', 'Count']),
        'RESPONSE CACHE',
        render_table(cache.stats(), headers=['Metric', 'Value']),
        'NETWORK (THIS SESSION)',
        render_table(metrics.snapshot(), headers=['Metric', 'Value']),
    ]
    _emit('\n\n'.join(parts), args.output)
    return 0


def _cmd_sources(args: argparse.Namespace) -> int:
    from .trackers.domain_sources import SOURCE_CATALOG as DOMAIN_CATALOG
    from .trackers.email_sources import SOURCE_CATALOG as EMAIL_CATALOG
    from .trackers.ip_sources import SOURCE_CATALOG as IP_CATALOG

    catalogs: Dict[str, Dict[str, str]] = {
        'ip': IP_CATALOG,
        'email': EMAIL_CATALOG,
        'domain': DOMAIN_CATALOG,
    }
    if args.kind:
        catalogs = {args.kind: catalogs.get(args.kind, {})}

    if (args.format or 'table') == 'json':
        _emit(json.dumps(catalogs, indent=2, ensure_ascii=False), args.output)
        return 0

    parts = []
    for kind, catalog in catalogs.items():
        rows = [[name, desc] for name, desc in catalog.items()]
        if not rows and kind == 'username':
            tracker = UsernameTracker()
            rows = [[p['name'], 'JSON API' if p.get('api') else 'HTML scrape']
                    for p in tracker.platforms]
        if not rows and kind == 'phone':
            rows = [['libphonenumber', 'Local metadata and heuristics']]
        parts.append(f"{kind.upper()} SOURCES")
        parts.append(render_table(rows, headers=['Source', 'Coverage'])
                     if rows else '(none)')
    _emit('\n\n'.join(parts), args.output)
    return 0


def _cmd_keys(args: argparse.Namespace) -> int:
    rows = []
    for service in SERVICES:
        rows.append({
            'service': service,
            'configured': config.is_configured(service),
            'env_var': f"OBSCURALENS_{service.upper()}_API_KEY",
        })
    if (args.format or 'table') == 'json':
        _emit(json.dumps(rows, indent=2), args.output)
    else:
        _emit(render_table(rows), args.output)
    return 0


def _cmd_cache(args: argparse.Namespace) -> int:
    if args.action == 'clear':
        removed = cache.clear()
        _emit(f"Removed {removed} cached responses", args.output)
    else:
        stats = cache.stats()
        if (args.format or 'table') == 'json':
            _emit(json.dumps(stats, indent=2), args.output)
        else:
            _emit(render_table(stats), args.output)
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    payload = {
        'app': asdict(config.app_config),
        'database': asdict(config.db_config),
        'api_keys_configured': config.configured_services(),
        'config_dir': str(config.config_dir),
    }
    if (args.format or 'table') == 'json':
        _emit(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
              args.output)
    else:
        _emit(_render_sections_text([
            {'title': 'Application', 'type': 'grid', 'data': payload['app']},
            {'title': 'Database', 'type': 'grid', 'data': payload['database']},
            {'title': 'API Keys', 'type': 'grid',
             'data': payload['api_keys_configured']},
        ]), args.output)
    return 0


def _watch_sections(diffs: List[Any]) -> List[Dict[str, Any]]:
    summary_rows = []
    detail_rows = []
    for diff in diffs:
        summary_rows.append([
            diff.watch_id, diff.target, diff.kind,
            'yes' if diff.is_first else 'no',
            len(diff.added), len(diff.removed), len(diff.changed),
            'ok' if diff.success else f"error: {diff.error}",
        ])
        for field, value in diff.added.items():
            detail_rows.append([diff.target, 'added', field, '', value])
        for field, value in diff.removed.items():
            detail_rows.append([diff.target, 'removed', field, value, ''])
        for field, change in diff.changed.items():
            detail_rows.append([diff.target, 'changed', field,
                                change.get('from'), change.get('to')])

    sections: List[Dict[str, Any]] = [{
        'title': 'Watch Check', 'type': 'table',
        'columns': ['ID', 'Target', 'Kind', 'First check', 'Added',
                    'Removed', 'Changed', 'Status'],
        'rows': summary_rows,
    }]
    if detail_rows:
        sections.append({
            'title': 'Changes', 'type': 'table',
            'columns': ['Target', 'Change', 'Field', 'From', 'To'],
            'rows': detail_rows,
        })
    return sections


def _identifier(value: Optional[str]) -> Any:
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def _cmd_investigate(args: argparse.Namespace) -> int:
    if detect_kind(args.target) is None:
        _err(f"cannot determine target type: {args.target!r}")
        return 2

    _info(f"Investigating {args.target} (pivot={args.pivot})...")
    payload = investigate(args.target, pivot=args.pivot,
                          max_pivots=args.max_pivots)
    fmt = args.format or 'table'
    title = f"Investigation - {payload['target']}"

    if fmt == 'json':
        _emit(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
              args.output)
    elif fmt == 'mermaid':
        _emit(to_mermaid(payload), args.output)
    elif fmt == 'csv':
        rows = [{'type': e['type'], 'value': e['value'], 'role': e['role']}
                for e in payload.get('entities', [])]
        buffer = io.StringIO()
        if rows:
            writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        _emit(buffer.getvalue().rstrip('\n'), args.output)
    elif fmt in ('markdown', 'html'):
        generator = ReportGenerator()
        data = {'sections': investigate_sections(payload)}
        text = (generator.render_markdown(data, title) if fmt == 'markdown'
                else generator.render_html(data, title))
        _emit(text, args.output)
    else:
        _emit(_render_sections_text(investigate_sections(payload)), args.output)

    if args.graph:
        Path(args.graph).write_text(to_mermaid(payload), encoding='utf-8')
        _info(f"Graph saved: {args.graph}")
    if payload.get('errors'):
        _info(f"{len(payload['errors'])} pivot(s) failed")
    return 0 if payload.get('results') else 1


def _cmd_watch(args: argparse.Namespace) -> int:
    action = getattr(args, 'action', None)
    if action is None:
        _err('usage: obscuralens watch add|list|remove|check')
        return 2
    try:
        if action == 'add':
            watch_id = watchlist.add(args.target, kind=args.kind,
                                     label=args.label)
            suffix = f" ({args.label})" if args.label else ''
            _emit(f"Watching #{watch_id}: {args.target}{suffix}", args.output)
            return 0
        if action == 'list':
            entries = watchlist.list()
            rows = [{'id': e.id, 'target': e.target, 'kind': e.kind,
                     'label': e.label, 'snapshots': e.snapshots,
                     'last_checked': e.last_checked or ''}
                    for e in entries]
            if (args.format or 'table') == 'json':
                _emit(json.dumps(rows, indent=2, ensure_ascii=False,
                                 default=str), args.output)
            else:
                _emit(render_table(rows) if rows else 'No watched targets.',
                      args.output)
            return 0
        if action == 'remove':
            removed = watchlist.remove(_identifier(args.identifier))
            if not removed:
                _err(f"not watching {args.identifier!r}")
                return 1
            _emit(f"Removed {removed} watch entry", args.output)
            return 0
        if action == 'check':
            diffs = watchlist.check(_identifier(args.identifier))
            if not diffs:
                _err('no matching watch entries')
                return 1
            if (args.format or 'table') == 'json':
                from dataclasses import asdict
                _emit(json.dumps([asdict(d) for d in diffs], indent=2,
                                 ensure_ascii=False, default=str),
                      args.output)
            else:
                _emit(_render_sections_text(_watch_sections(diffs)),
                      args.output)
            return 0 if all(d.success for d in diffs) else 1
    except ValueError as e:
        _err(str(e))
        return 2
    return 2


def _cmd_plugins(args: argparse.Namespace) -> int:
    action = getattr(args, 'action', None)
    if action == 'reload':
        infos = reload_plugins()
    elif action in (None, 'list'):
        infos = loaded_plugins()
    else:
        _err('usage: obscuralens plugins list|reload')
        return 2

    rows = [{
        'name': info.name,
        'kinds': ', '.join(info.kinds),
        'sources': '; '.join(
            f"{kind}: {', '.join(names)}"
            for kind, names in info.sources.items()),
        'error': info.error or '',
        'path': info.path,
    } for info in infos]

    if (args.format or 'table') == 'json':
        _emit(json.dumps(rows, indent=2, ensure_ascii=False), args.output)
    elif rows:
        _emit(render_table(rows), args.output)
    else:
        _emit('No plugins loaded.', args.output)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        from .web import serve
    except ImportError as e:
        _err(str(e))
        return 2
    serve(host=args.host, port=args.port, reload=args.reload)
    return 0


def _cmd_tui(args: argparse.Namespace) -> int:
    try:
        from .tui import run_tui
    except ImportError as e:
        _err(str(e))
        return 2
    run_tui()
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import main as mcp_main
    return mcp_main([])


_HANDLERS = {
    'ip': _cmd_ip,
    'phone': _cmd_phone,
    'username': _cmd_username,
    'email': _cmd_email,
    'domain': _cmd_domain,
    'batch': _cmd_batch,
    'history': _cmd_history,
    'stats': _cmd_stats,
    'sources': _cmd_sources,
    'keys': _cmd_keys,
    'cache': _cmd_cache,
    'config': _cmd_config,
    'investigate': _cmd_investigate,
    'watch': _cmd_watch,
    'plugins': _cmd_plugins,
    'serve': _cmd_serve,
    'tui': _cmd_tui,
    'mcp': _cmd_mcp,
}


def run(argv: Optional[List[str]] = None) -> int:
    """Parse arguments and execute one command. Returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, 'command', None):
        parser.print_help()
        return 1

    _apply_globals(args)
    handler = _HANDLERS.get(args.command)
    if handler is None:  # pragma: no cover - argparse enforces the choices
        parser.print_help()
        return 1
    try:
        return handler(args)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        _info('Interrupted.')
        return 130
    except Exception as e:  # never dump a traceback at the user
        if config.app_config.debug:
            raise
        _err(f"{type(e).__name__}: {e}")
        return 1
