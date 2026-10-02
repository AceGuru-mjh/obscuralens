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
from .utils import render_table, set_colors
from .utils.formatting import fmt_value, rows_from_fields
from .utils.validators import (
    validate_asn,
    validate_crypto_address,
    validate_cve,
    validate_domain,
    validate_email,
    validate_hash,
    validate_ip,
    validate_phone,
    validate_url,
    validate_username,
)
from .watchlist import watchlist

KINDS = ('ip', 'phone', 'username', 'email', 'domain', 'url', 'crypto',
         'hash', 'cve', 'asn')
FORMATS = ('table', 'json', 'markdown', 'html', 'csv', 'mermaid')

_TRACKERS: Dict[str, Any] = {}


def _tracker(kind: str):
    if kind not in _TRACKERS:
        from .trackers import (
            ASNTracker,
            CryptoTracker,
            CVETracker,
            DomainTracker,
            EmailTracker,
            HashTracker,
            IPTracker,
            PhoneTracker,
            URLTracker,
            UsernameTracker,
        )
        _TRACKERS[kind] = {
            'ip': IPTracker,
            'phone': PhoneTracker,
            'username': UsernameTracker,
            'email': EmailTracker,
            'domain': DomainTracker,
            'url': URLTracker,
            'crypto': CryptoTracker,
            'hash': HashTracker,
            'cve': CVETracker,
            'asn': ASNTracker,
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
        p.add_argument('--risk', action='store_true',
                       help='attach heuristic risk scoring (v4.0)')

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

    # -- v4.0 target kinds --------------------------------------------------
    p_url = sub.add_parser('url', help='analyze a URL (redirects, verdicts, history)')
    p_url.add_argument('target', help='http(s) or ftp URL')
    add_common(p_url)

    p_crypto = sub.add_parser('crypto', help='analyze a cryptocurrency address')
    p_crypto.add_argument('target', help='btc / eth / xmr / doge / ltc / xrp / ada address')
    add_common(p_crypto)

    p_hash = sub.add_parser('hash', help='look up a file hash')
    p_hash.add_argument('target', help='md5 / sha1 / sha256 file hash')
    add_common(p_hash)

    p_cve = sub.add_parser('cve', help='look up a CVE vulnerability')
    p_cve.add_argument('target', help='CVE identifier, e.g. CVE-2021-44228')
    add_common(p_cve)

    p_asn = sub.add_parser('asn', help='look up an autonomous system')
    p_asn.add_argument('target', help='AS number, e.g. AS15169 or 15169')
    add_common(p_asn)

    p_inv = sub.add_parser(
        'investigate',
        help='auto-detect a target and follow related pivots')
    p_inv.add_argument('target', help='IP / domain / email / phone / username / URL / CVE / hash / ASN / crypto')
    p_inv.add_argument('--no-pivot', action='store_false', dest='pivot',
                       help='do not follow related targets')
    p_inv.add_argument('--max-pivots', type=int, default=3,
                       help='maximum related lookups per kind (default: 3)')
    p_inv.add_argument('--graph', metavar='FILE',
                       help='also write a Mermaid graph to FILE')
    p_inv.add_argument('--export', metavar='FMT',
                       choices=('graphml', 'gexf', 'dot', 'jsonl', 'csv'),
                       help='export the entity graph (Gephi/Graphviz formats)')
    p_inv.add_argument('--timeline', action='store_true',
                       help='append a chronological event timeline')
    p_inv.add_argument('--llm', action='store_true',
                       help='append an experimental LLM narrative summary')
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
    p_sources.add_argument('kind', nargs='?',
                           choices=KINDS + ('health',))
    p_sources.add_argument('--reset', metavar='SOURCE',
                           help='reset health data for one source (with health)')
    add_common(p_sources)

    p_keys = sub.add_parser('keys', help='show API key configuration')
    add_common(p_keys)

    p_cache = sub.add_parser('cache', help='manage the response cache')
    p_cache.add_argument('action', choices=('stats', 'clear'))
    add_common(p_cache)

    p_config = sub.add_parser('config', help='show resolved configuration')
    add_common(p_config)

    # -- v4.0 analysis commands ---------------------------------------------

    p_risk = sub.add_parser('risk', help='heuristic risk scoring for a target')
    p_risk.add_argument('kind', choices=KINDS)
    p_risk.add_argument('target')
    add_common(p_risk)

    p_timeline = sub.add_parser(
        'timeline', help='chronological event timeline from stored history')
    p_timeline.add_argument('target', nargs='?',
                            help='restrict to one target (default: all)')
    p_timeline.add_argument('--limit', type=int, default=100,
                            help='maximum events (default: 100)')
    add_common(p_timeline)

    p_corr = sub.add_parser(
        'correlate', help='find shared infrastructure between targets')
    p_corr.add_argument('targets', nargs='*',
                        help='two targets to compare, or none for --all')
    p_corr.add_argument('--all', action='store_true',
                        help='correlate the whole stored history')
    p_corr.add_argument('--limit', type=int, default=None,
                        help='history rows to consider')
    p_corr.add_argument('--export', metavar='FMT',
                        choices=('graphml', 'gexf', 'dot', 'jsonl', 'csv'),
                        help='export the correlation graph')
    add_common(p_corr)

    p_diff = sub.add_parser(
        'diff', help='compare two stored results field by field')
    p_diff.add_argument('left', help='history id or target value')
    p_diff.add_argument('right', help='history id or target value')
    add_common(p_diff)

    p_export = sub.add_parser(
        'export', help='export an investigation graph to a file format')
    p_export.add_argument('fmt', choices=('graphml', 'gexf', 'dot', 'jsonl',
                                          'csv', 'mermaid'))
    p_export.add_argument('target', help='any supported target')
    p_export.add_argument('--no-pivot', action='store_false', dest='pivot')
    p_export.add_argument('--max-pivots', type=int, default=3)
    p_export.add_argument('--from-json', metavar='FILE',
                          help='export a saved investigate payload instead')
    p_export.add_argument('-o', '--output', metavar='FILE',
                          help='output file (default: report dir)')
    p_export.add_argument('--no-color', action='store_true')

    # -- v4.0 case management -------------------------------------------------

    p_case = sub.add_parser('case', help='manage investigation cases')
    case_sub = p_case.add_subparsers(dest='action', metavar='<action>')
    p_case_new = case_sub.add_parser('new', help='create a case')
    p_case_new.add_argument('name')
    p_case_new.add_argument('--description', default='')
    add_common(p_case_new)
    p_case_list = case_sub.add_parser('list', help='list cases')
    p_case_list.add_argument('--all', action='store_true',
                             help='include archived cases')
    add_common(p_case_list)
    p_case_show = case_sub.add_parser('show', help='show one case')
    p_case_show.add_argument('id', type=int)
    add_common(p_case_show)
    p_case_add = case_sub.add_parser('add', help='add a target to a case')
    p_case_add.add_argument('id', type=int)
    p_case_add.add_argument('target')
    p_case_add.add_argument('--kind', default='auto',
                            help='auto / ip / domain / email / username / ...')
    p_case_add.add_argument('--note', default='')
    add_common(p_case_add)
    p_case_rmi = case_sub.add_parser('remove-item', help='remove an item')
    p_case_rmi.add_argument('id', type=int)
    p_case_rmi.add_argument('item', type=int)
    add_common(p_case_rmi)
    p_case_note = case_sub.add_parser('note', help='append a note')
    p_case_note.add_argument('id', type=int)
    p_case_note.add_argument('body')
    add_common(p_case_note)
    p_case_tag = case_sub.add_parser('tag', help='add a tag')
    p_case_tag.add_argument('id', type=int)
    p_case_tag.add_argument('tag')
    add_common(p_case_tag)
    p_case_untag = case_sub.add_parser('untag', help='remove a tag')
    p_case_untag.add_argument('id', type=int)
    p_case_untag.add_argument('tag')
    add_common(p_case_untag)
    p_case_close = case_sub.add_parser('close', help='close a case')
    p_case_close.add_argument('id', type=int)
    add_common(p_case_close)
    p_case_reopen = case_sub.add_parser('reopen', help='reopen a case')
    p_case_reopen.add_argument('id', type=int)
    add_common(p_case_reopen)
    p_case_archive = case_sub.add_parser('archive', help='archive a case')
    p_case_archive.add_argument('id', type=int)
    add_common(p_case_archive)
    p_case_delete = case_sub.add_parser('delete', help='delete a case')
    p_case_delete.add_argument('id', type=int)
    add_common(p_case_delete)
    p_case_find = case_sub.add_parser('find', help='find cases containing a value')
    p_case_find.add_argument('value')
    add_common(p_case_find)
    p_case_export = case_sub.add_parser('export', help='export a case')
    p_case_export.add_argument('id', type=int)
    p_case_export.add_argument('-f', '--format', choices=('markdown', 'json'),
                               default='markdown')
    p_case_export.add_argument('--path', metavar='FILE')
    p_case_stats = case_sub.add_parser('stats', help='case statistics')
    add_common(p_case_stats)

    # -- v4.0 pipelines --------------------------------------------------------

    p_pipe = sub.add_parser('pipeline', help='run YAML investigation pipelines')
    pipe_sub = p_pipe.add_subparsers(dest='action', metavar='<action>')
    p_pipe_list = pipe_sub.add_parser('list', help='discover pipelines')
    add_common(p_pipe_list)
    p_pipe_run = pipe_sub.add_parser('run', help='run a pipeline file')
    p_pipe_run.add_argument('file', help='pipeline YAML path or name')
    p_pipe_run.add_argument('--set', metavar='KEY=VALUE', action='append',
                            default=[], dest='variables',
                            help='override a pipeline variable')
    add_common(p_pipe_run)
    p_pipe_init = pipe_sub.add_parser('init', help='write a starter pipeline')
    p_pipe_init.add_argument('name')
    p_pipe_init.add_argument('--path', metavar='FILE',
                            help='output file (default: pipelines/<name>.yaml)')
    p_pipe_init.add_argument('--no-color', action='store_true')

    # -- v4.0 threat intel -----------------------------------------------------

    p_intel = sub.add_parser('intel',
                             help='threat-intel checks (Tor, blocklist feeds)')
    intel_sub = p_intel.add_subparsers(dest='action', metavar='<action>')
    p_intel_ip = intel_sub.add_parser('ip', help='check an IP against feeds')
    p_intel_ip.add_argument('target')
    add_common(p_intel_ip)
    p_intel_tor = intel_sub.add_parser('tor', help='Tor exit / relay check')
    p_intel_tor.add_argument('target')
    add_common(p_intel_tor)
    p_intel_feeds = intel_sub.add_parser('feeds', help='blocklist feed status')
    p_intel_feeds.add_argument('--refresh', action='store_true',
                               help='force feed download')
    add_common(p_intel_feeds)

    # -- v4.0 experimental -----------------------------------------------------

    p_expt = sub.add_parser('experimental', help='experimental features')
    expt_sub = p_expt.add_subparsers(dest='action', metavar='<action>')
    p_llm = expt_sub.add_parser('llm', help='LLM narrative summary (opt-in)')
    p_llm.add_argument('kind', choices=KINDS + ('auto',))
    p_llm.add_argument('target')
    add_common(p_llm)
    p_permute = expt_sub.add_parser(
        'permute', help='generate username permutations')
    p_permute.add_argument('username')
    p_permute.add_argument('--max', type=int, default=None)
    p_permute.add_argument('--scan', action='store_true',
                           help='check permutations on a few platforms')
    p_permute.add_argument('--platforms', type=int, default=None)
    add_common(p_permute)
    p_crawl = expt_sub.add_parser(
        'crawl', help='bounded same-domain web crawler')
    p_crawl.add_argument('url')
    p_crawl.add_argument('--depth', type=int, default=None)
    p_crawl.add_argument('--max-pages', type=int, default=None)
    p_crawl.add_argument('--delay', type=float, default=None)
    p_crawl.add_argument('--ignore-robots', action='store_true')
    add_common(p_crawl)
    p_phish = expt_sub.add_parser(
        'phish', help='heuristic phishing score for a URL or domain')
    p_phish.add_argument('target')
    add_common(p_phish)

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
        sections.extend(_extra_sections(result))
        generator = ReportGenerator()
        data = {'sections': sections}
        text = (generator.render_markdown(data, title) if fmt == 'markdown'
                else generator.render_html(data, title))
        _emit(text, args.output)
    else:
        sections = sections_for(kind, result)
        sections.extend(_extra_sections(result))
        _emit(_render_sections_text(sections), args.output)


def _extra_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Optional v4.0 sections attached to a result payload (risk, ...)."""
    extra: List[Dict[str, Any]] = []
    risk = result.get('risk')
    if isinstance(risk, dict):
        try:
            from .correlation import risk_sections
            extra.extend(risk_sections(risk))
        except ImportError:
            pass
    return extra


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _run_lookup(args: argparse.Namespace, kind: str, target: str,
                title: str, **tracker_kwargs: Any) -> int:
    result = _tracker(kind).track(target, **tracker_kwargs)
    if getattr(args, 'risk', False):
        try:
            from .correlation import attach_risk
            attach_risk(kind, result)
        except ImportError:
            _info('risk scoring unavailable (correlation package missing)')
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
        from .trackers import UsernameTracker
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


def _cmd_url(args: argparse.Namespace) -> int:
    ok, error = validate_url(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'url', args.target, f"URL Report - {args.target}")


def _cmd_crypto(args: argparse.Namespace) -> int:
    ok, error = validate_crypto_address(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'crypto', args.target,
                       f"Crypto Report - {args.target[:20]}...")


def _cmd_hash(args: argparse.Namespace) -> int:
    ok, error = validate_hash(args.target)
    if not ok:
        _err(error)
        return 2
    target = args.target.strip().lower()
    return _run_lookup(args, 'hash', target, f"Hash Report - {target}")


def _cmd_cve(args: argparse.Namespace) -> int:
    ok, error = validate_cve(args.target)
    if not ok:
        _err(error)
        return 2
    target = args.target.strip().upper()
    return _run_lookup(args, 'cve', target, f"CVE Report - {target}")


def _cmd_asn(args: argparse.Namespace) -> int:
    ok, error = validate_asn(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'asn', args.target, f"ASN Report - {args.target}")


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
    # v4.0: `sources health` shows persisted reliability + circuit state.
    if getattr(args, 'kind', None) == 'health' or \
            getattr(args, 'health', False):
        return _cmd_sources_health(args)

    from .trackers.asn_sources import SOURCE_CATALOG as ASN_CATALOG
    from .trackers.crypto_sources import SOURCE_CATALOG as CRYPTO_CATALOG
    from .trackers.cve_sources import SOURCE_CATALOG as CVE_CATALOG
    from .trackers.domain_sources import SOURCE_CATALOG as DOMAIN_CATALOG
    from .trackers.email_sources import SOURCE_CATALOG as EMAIL_CATALOG
    from .trackers.hash_sources import SOURCE_CATALOG as HASH_CATALOG
    from .trackers.ip_sources import SOURCE_CATALOG as IP_CATALOG
    from .trackers.url_sources import SOURCE_CATALOG as URL_CATALOG

    catalogs: Dict[str, Dict[str, str]] = {
        'ip': IP_CATALOG,
        'email': EMAIL_CATALOG,
        'domain': DOMAIN_CATALOG,
        'url': URL_CATALOG,
        'crypto': CRYPTO_CATALOG,
        'hash': HASH_CATALOG,
        'cve': CVE_CATALOG,
        'asn': ASN_CATALOG,
    }
    if args.kind and args.kind in catalogs:
        catalogs = {args.kind: catalogs[args.kind]}

    if (args.format or 'table') == 'json':
        _emit(json.dumps(catalogs, indent=2, ensure_ascii=False), args.output)
        return 0

    from .trackers import UsernameTracker

    parts = []
    for kind, catalog in catalogs.items():
        rows = [[name, desc] for name, desc in catalog.items()]
        if not rows and kind == 'username':
            tracker = UsernameTracker()
            rows = [[p['name'], 'JSON API' if p.get('api') else 'HTML scrape']
                    for p in tracker.platforms]
        if not rows and kind == 'phone':
            rows = [['libphonenumber', 'Local metadata and heuristics + geo pack']]
        parts.append(f"{kind.upper()} SOURCES")
        parts.append(render_table(rows, headers=['Source', 'Coverage'])
                     if rows else '(none)')
    _emit('\n\n'.join(parts), args.output)
    return 0


def _cmd_sources_health(args: argparse.Namespace) -> int:
    """Persisted per-source reliability and circuit-breaker state."""
    from .health import health

    reset = getattr(args, 'reset', None)
    if reset:
        removed = health.reset(source=reset)
        _emit(f"Reset health for {reset!r} ({removed} row(s))",
              getattr(args, 'output', None))
        return 0

    rows = health.get_health()
    if (getattr(args, 'format', None) or 'table') == 'json':
        _emit(json.dumps(rows, indent=2, ensure_ascii=False),
              getattr(args, 'output', None))
        return 0
    if not rows:
        _emit('No source health recorded yet (run some lookups first).',
              getattr(args, 'output', None))
        return 0
    _emit(render_table([{
        'source': r.get('source'), 'kind': r.get('kind'),
        'ok': r.get('ok_count'), 'fail': r.get('fail_count'),
        'reliability': f"{r.get('reliability', 0)}%",
        'state': r.get('state'), 'last error': (r.get('last_error') or '')[:40],
    } for r in rows[:100]]), getattr(args, 'output', None))
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

    # v4.0 optional enrichments on every gathered result.
    if getattr(args, 'risk', False):
        from .correlation import attach_risk
        for kind_name, result in payload.get('results', {}).items():
            attach_risk(kind_name, result)

    if getattr(args, 'timeline', False):
        from .correlation import build_timeline, timeline_sections
        entries = [{'kind': kind, 'value': _result_target(kind, result),
                    'payload': result}
                   for kind, result in payload.get('results', {}).items()]
        if entries:
            payload['timeline'] = build_timeline(entries)

    if getattr(args, 'llm', False):
        from .experimental.llm_summary import summarize
        summary = summarize(payload.get('kind'), payload)
        if summary.get('error'):
            _info(f"llm summary unavailable: {summary['error']}")
        else:
            payload['llm_summary'] = summary

    fmt = args.format or 'table'
    title = f"Investigation - {payload['target']}"

    sections = investigate_sections(payload)
    if payload.get('timeline'):
        from .correlation import timeline_sections
        sections.extend(timeline_sections(payload['timeline']))
    if payload.get('llm_summary'):
        from .experimental.llm_summary import llm_sections
        sections.extend(llm_sections(payload['llm_summary']))

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
        data = {'sections': sections}
        text = (generator.render_markdown(data, title) if fmt == 'markdown'
                else generator.render_html(data, title))
        _emit(text, args.output)
    else:
        _emit(_render_sections_text(sections), args.output)

    if args.graph:
        Path(args.graph).write_text(to_mermaid(payload), encoding='utf-8')
        _info(f"Graph saved: {args.graph}")
    if getattr(args, 'export', None):
        _write_graph_export(payload, args.export,
                            args.output or f"{_slug(payload['target'])}")
    if payload.get('errors'):
        _info(f"{len(payload['errors'])} pivot(s) failed")
    return 0 if payload.get('results') else 1


def _result_target(kind: str, result: Dict[str, Any]) -> str:
    for key in (kind, 'target', 'username', 'email', 'domain', 'ip', 'url',
                'address', 'hash', 'cve', 'asn', 'phone_number'):
        value = result.get(key)
        if value:
            return str(value)
    return ''


def _slug(value: str) -> str:
    import re as _re
    return _re.sub(r'[^0-9A-Za-z_.-]+', '_', str(value))[:60].strip('_') or 'graph'


def _write_graph_export(payload: Dict[str, Any], fmt: str, base: str) -> None:
    """Write an entity-graph export (GraphML/GEXF/DOT/JSONL/CSV)."""
    from .export import export_graph
    path = f"{base}.{fmt}" if '.' not in Path(base).name else base
    text = export_graph(payload, fmt=fmt, path=path)
    if text is None:
        _err(f"graph export failed: {path}")
    else:
        _info(f"Graph exported: {path}")


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


# ---------------------------------------------------------------------------
# v4.0 handlers: risk / timeline / correlate / diff / export
# ---------------------------------------------------------------------------

def _cmd_risk(args: argparse.Namespace) -> int:
    from .correlation import risk_sections, score

    validator = {
        'ip': validate_ip, 'phone': validate_phone,
        'username': validate_username, 'email': validate_email,
        'domain': validate_domain, 'url': validate_url,
        'crypto': validate_crypto_address, 'hash': validate_hash,
        'cve': validate_cve, 'asn': validate_asn,
    }.get(args.kind)
    if validator:
        ok, error = validator(args.target)
        if not ok:
            _err(error)
            return 2

    _info(f"Scoring {args.target} ...")
    result = _tracker(args.kind).track(args.target)
    if not result.get('info'):
        _err('no data collected - cannot score')
        return 1
    risk = score(args.kind, result)
    result['risk'] = risk

    if (args.format or 'table') == 'json':
        _emit(json.dumps(result, indent=2, ensure_ascii=False, default=str),
              args.output)
    else:
        _emit(_render_sections_text(risk_sections(risk)), args.output)
    return 0


def _cmd_timeline(args: argparse.Namespace) -> int:
    from .correlation import build_timeline, history_records, timeline_sections

    limit = int(getattr(args, 'limit', 100) or 100)
    records = history_records(limit=max(limit * 3, 200))
    if args.target:
        needle = args.target.strip().lower()
        records = [r for r in records
                   if needle in str(r.get('value', '')).lower()]
    if not records:
        _err('no stored lookups match - run a lookup first')
        return 1

    timeline = build_timeline(records, cap=limit)
    if (args.format or 'table') == 'json':
        _emit(json.dumps(timeline, indent=2, ensure_ascii=False, default=str),
              args.output)
    else:
        _emit(_render_sections_text(timeline_sections(timeline)), args.output)
    return 0


def _cmd_correlate(args: argparse.Namespace) -> int:
    from .correlation import (
        build_graph,
        correlation_sections,
        history_records,
    )
    from .correlation import correlate as correlate_pair

    if args.all or not args.targets:
        limit = args.limit or config.app_config.correlation_max_history
        records = history_records(limit=limit)
        if not records:
            _err('no stored lookups to correlate - run some lookups first')
            return 1
        graph = build_graph(records)
        if (args.format or 'table') == 'json':
            _emit(json.dumps(graph, indent=2, ensure_ascii=False, default=str),
                  args.output)
        else:
            _emit(_render_sections_text(correlation_sections(graph)),
                  args.output)
        if args.export:
            _export_correlation_graph(graph, args.export, args.output)
        return 0

    if len(args.targets) != 2:
        _err('correlate takes two targets (or --all)')
        return 2

    records = history_records(limit=args.limit
                              or config.app_config.correlation_max_history)
    verdict = correlate_pair(args.targets[0], args.targets[1],
                             records=records or None)
    if (args.format or 'table') == 'json':
        _emit(json.dumps(verdict, indent=2, ensure_ascii=False, default=str),
              args.output)
    else:
        rows = [[item.get('type', ''), item.get('entity', ''),
                 item.get('via_a', ''), item.get('via_b', '')]
                for item in verdict.get('shared', [])]
        sections = [
            {'title': 'Correlation', 'type': 'grid', 'data': {
                'Target A': verdict.get('targets', ['?'])[0],
                'Target B': (verdict.get('targets') or ['?', '?'])[1],
                'Related': 'yes' if verdict.get('related') else 'no',
                'Shared entities': verdict.get('connections', 0),
            }},
        ]
        if rows:
            sections.append({'title': 'Shared Infrastructure', 'type': 'table',
                             'columns': ['Type', 'Entity', 'Via A', 'Via B'],
                             'rows': rows})
        _emit(_render_sections_text(sections), args.output)
    return 0


def _export_correlation_graph(graph: Dict[str, Any], fmt: str,
                              output: Optional[str]) -> None:
    from .export import export_graph
    path = output or f"correlation.{fmt}"
    text = export_graph(graph, fmt=fmt, path=path)
    if text is None:
        _err(f"graph export failed: {path}")
    else:
        _info(f"Graph exported: {path}")


def _history_record(identifier: str) -> Optional[Dict[str, Any]]:
    """Resolve a history id (int) or target value (str) to a stored result."""
    if str(identifier).isdigit():
        record = db.get_query_by_id(int(identifier))
        if record is None:
            return None
        return {'kind': record.query_type, 'value': record.query_value,
                'payload': _safe_json(record.result_data),
                'created_at': record.created_at}
    for record in db.search_history(str(identifier), limit=20):
        if record.success:
            return {'kind': record.query_type, 'value': record.query_value,
                    'payload': _safe_json(record.result_data),
                    'created_at': record.created_at}
    return None


def _safe_json(text: Optional[str]) -> Dict[str, Any]:
    try:
        return json.loads(text) if text else {}
    except (ValueError, TypeError):
        return {}


def _cmd_diff(args: argparse.Namespace) -> int:
    left = _history_record(args.left)
    right = _history_record(args.right)
    if not left or not right:
        _err('target not found in history (use ids or stored target values)')
        return 1

    def flat(record: Dict[str, Any]) -> Dict[str, Any]:
        payload = record.get('payload') or {}
        info = payload.get('info')
        if isinstance(info, dict):
            return {k: fmt_value(k, v) for k, v in info.items()}
        if isinstance(payload.get('results'), list):
            return {r.get('platform', ''): r.get('status', '')
                    for r in payload['results']}
        return {}

    left_fields, right_fields = flat(left), flat(right)
    added = {k: v for k, v in right_fields.items() if k not in left_fields}
    removed = {k: v for k, v in left_fields.items() if k not in right_fields}
    changed = {k: (left_fields[k], right_fields[k]) for k in left_fields
               if k in right_fields and left_fields[k] != right_fields[k]}

    report = {
        'left': {'kind': left['kind'], 'value': left['value'],
                 'created_at': left.get('created_at')},
        'right': {'kind': right['kind'], 'value': right['value'],
                  'created_at': right.get('created_at')},
        'added': added,
        'removed': removed,
        'changed': {k: {'left': v[0], 'right': v[1]} for k, v in changed.items()},
    }

    if (args.format or 'table') == 'json':
        _emit(json.dumps(report, indent=2, ensure_ascii=False, default=str),
              args.output)
    else:
        sections = [{
            'title': 'Comparison', 'type': 'grid', 'data': {
                'Left': f"{left['kind']}: {left['value']} ({left.get('created_at')})",
                'Right': f"{right['kind']}: {right['value']} ({right.get('created_at')})",
                'Added': len(added), 'Removed': len(removed),
                'Changed': len(changed),
            },
        }]
        if added:
            sections.append({'title': 'Added Fields', 'type': 'table',
                             'columns': ['Field', 'Value'],
                             'rows': [[k, v] for k, v in added.items()]})
        if removed:
            sections.append({'title': 'Removed Fields', 'type': 'table',
                             'columns': ['Field', 'Value'],
                             'rows': [[k, v] for k, v in removed.items()]})
        if changed:
            sections.append({'title': 'Changed Fields', 'type': 'table',
                             'columns': ['Field', 'Left', 'Right'],
                             'rows': [[k, v[0], v[1]] for k, v in changed.items()]})
        _emit(_render_sections_text(sections), args.output)
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    from .export import export_graph

    if args.from_json:
        try:
            payload = json.loads(Path(args.from_json).read_text(encoding='utf-8'))
        except (OSError, ValueError) as e:
            _err(f"cannot read {args.from_json}: {e}")
            return 2
        if not isinstance(payload, dict) or 'entities' not in payload:
            _err('not an investigate payload (entities missing)')
            return 2
    else:
        if detect_kind(args.target) is None:
            _err(f"cannot determine target type: {args.target!r}")
            return 2
        _info(f"Investigating {args.target} ...")
        payload = investigate(args.target, pivot=args.pivot,
                              max_pivots=args.max_pivots)

    base = args.output or f"{_slug(payload.get('target', 'graph'))}"
    path = base if '.' in Path(base).name else f"{base}.{args.fmt}"
    if args.fmt == 'mermaid':
        text = to_mermaid(payload)
        Path(path).write_text(text, encoding='utf-8')
        _info(f"Graph exported: {path}")
        return 0
    text = export_graph(payload, fmt=args.fmt, path=path)
    if text is None:
        _err(f"graph export failed: {path}")
        return 1
    _info(f"Graph exported: {path}")
    _emit(f"{path}: {len(payload.get('entities', []))} entities, "
          f"{len(payload.get('links', []))} relationships", None)
    return 0


# ---------------------------------------------------------------------------
# v4.0 handlers: cases
# ---------------------------------------------------------------------------

def _cmd_case(args: argparse.Namespace) -> int:
    from .cases import cases

    action = getattr(args, 'action', None)
    if action is None:
        _err('usage: obscuralens case new|list|show|add|remove-item|note|'
             'tag|untag|close|reopen|archive|delete|find|export|stats')
        return 2

    fmt = args.format or 'table'

    if action == 'new':
        result = cases.create_case(args.name, description=args.description)
        if result.get('error'):
            _err(f"{result['error']} (existing id: {result.get('id')})")
            return 1
        _emit(f"Created case #{result['id']}: {result['name']}", args.output)
        return 0

    if action == 'list':
        listing = cases.list_cases(include_archived=args.all)
        if fmt == 'json':
            _emit(json.dumps(listing, indent=2, ensure_ascii=False), args.output)
        elif listing:
            _emit(render_table([{
                'id': c.get('id'), 'name': c.get('name'),
                'status': c.get('status'), 'items': c.get('item_count'),
                'notes': c.get('note_count'), 'tags': c.get('tag_count'),
            } for c in listing]), args.output)
        else:
            _emit('No cases yet (create one with `case new`).', args.output)
        return 0

    if action == 'show':
        case = cases.get_case(args.id)
        if not case:
            _err(f"no case #{args.id}")
            return 1
        if fmt == 'json':
            _emit(json.dumps(case, indent=2, ensure_ascii=False), args.output)
            return 0
        sections = [
            {'title': f"Case #{case['id']}: {case['name']}", 'type': 'grid',
             'data': {'Status': case.get('status'),
                      'Description': case.get('description', ''),
                      'Created': case.get('created_at'),
                      'Updated': case.get('updated_at'),
                      'Tags': ', '.join(case.get('tags', []))}},
        ]
        if case.get('items'):
            sections.append({'title': 'Items', 'type': 'table',
                             'columns': ['#', 'Kind', 'Value', 'Note', 'Added'],
                             'rows': [[i.get('id'), i.get('kind'), i.get('value'),
                                       i.get('note', ''), i.get('added_at')]
                                      for i in case['items']]})
        if case.get('notes'):
            sections.append({'title': 'Notes', 'type': 'table',
                             'columns': ['Created', 'Note'],
                             'rows': [[n.get('created_at'), n.get('body')]
                                      for n in case['notes']]})
        _emit(_render_sections_text(sections), args.output)
        return 0

    if action == 'add':
        result = cases.add_item(args.id, args.kind, args.target, note=args.note)
        if result.get('error'):
            _err(str(result['error']))
            return 1
        _emit(f"Added item #{result.get('id')} ({result.get('kind')}) "
              f"to case #{args.id}", args.output)
        return 0

    if action == 'remove-item':
        removed = cases.remove_item(args.id, args.item)
        if not removed:
            _err(f"no item #{args.item} in case #{args.id}")
            return 1
        _emit(f"Removed item #{args.item} from case #{args.id}", args.output)
        return 0

    if action == 'note':
        result = cases.add_note(args.id, args.body)
        if result.get('error'):
            _err(str(result['error']))
            return 1
        _emit(f"Note #{result.get('id')} added to case #{args.id}", args.output)
        return 0

    if action == 'tag':
        result = cases.add_tag(args.id, args.tag)
        if result.get('error'):
            _err(str(result['error']))
            return 1
        _emit(f"Tagged case #{args.id}: {args.tag}", args.output)
        return 0

    if action == 'untag':
        removed = cases.remove_tag(args.id, args.tag)
        if not removed:
            _err(f"case #{args.id} has no tag {args.tag!r}")
            return 1
        _emit(f"Removed tag {args.tag} from case #{args.id}", args.output)
        return 0

    def status_mutator(method_name: str, verb: str) -> int:
        method = getattr(cases, method_name)
        result = method(args.id)
        if result is None:
            _err(f"no case #{args.id}")
            return 1
        _emit(f"{verb} case #{args.id}", args.output)
        return 0

    if action == 'close':
        return status_mutator('close_case', 'Closed')
    if action == 'reopen':
        return status_mutator('reopen_case', 'Reopened')
    if action == 'archive':
        return status_mutator('archive_case', 'Archived')
    if action == 'delete':
        if not cases.delete_case(args.id):
            _err(f"no case #{args.id}")
            return 1
        _emit(f"Deleted case #{args.id}", args.output)
        return 0

    if action == 'find':
        found = cases.find_cases(args.value)
        if fmt == 'json':
            _emit(json.dumps(found, indent=2, ensure_ascii=False), args.output)
        elif found:
            _emit(render_table([{'id': c.get('id'), 'name': c.get('name'),
                                 'status': c.get('status')}
                                for c in found]), args.output)
        else:
            _emit(f"No case contains {args.value!r}", args.output)
        return 0

    if action == 'export':
        try:
            text = cases.export_case(args.id, fmt=args.format or 'markdown')
        except ValueError as e:
            _err(str(e))
            return 2
        except TypeError:
            _err(f"no case #{args.id}")
            return 1
        _emit(text, getattr(args, 'path', None))
        return 0

    if action == 'stats':
        stats = cases.case_stats()
        if fmt == 'json':
            _emit(json.dumps(stats, indent=2, ensure_ascii=False), args.output)
        else:
            _emit(render_table([{'metric': k, 'value': v}
                                for k, v in stats.items()]), args.output)
        return 0

    return 2


# ---------------------------------------------------------------------------
# v4.0 handlers: pipelines
# ---------------------------------------------------------------------------

def _cmd_pipeline(args: argparse.Namespace) -> int:
    try:
        from .pipelines import (
            PipelineError,
            list_pipelines,
            load_pipeline,
            pipeline_sections,
            run_pipeline,
            save_pipeline,
        )
    except ImportError as e:
        _err(f'pipeline engine unavailable: {e}')
        return 2

    action = getattr(args, 'action', None)
    fmt = args.format or 'table'

    if action is None:
        _err('usage: obscuralens pipeline list|run|init')
        return 2

    if action == 'list':
        listing = list_pipelines()
        if fmt == 'json':
            _emit(json.dumps(listing, indent=2, ensure_ascii=False), args.output)
        elif listing:
            _emit(render_table([{
                'name': p['name'], 'steps': p.get('steps'),
                'description': p.get('description', ''),
                'path': p.get('path', ''),
            } for p in listing]), args.output)
        else:
            _emit('No pipelines found (see pipelines/examples/).', args.output)
        return 0

    if action == 'run':
        variables: Dict[str, str] = {}
        for pair in args.variables:
            key, sep, value = pair.partition('=')
            if not sep:
                _err(f"bad --set value (expected KEY=VALUE): {pair}")
                return 2
            variables[key] = value
        try:
            spec = load_pipeline(args.file)
            report = run_pipeline(spec, variables=variables)
        except PipelineError as e:
            _err(f'pipeline error: {e}')
            return 2
        if fmt == 'json':
            _emit(json.dumps(report, indent=2, ensure_ascii=False, default=str),
                  args.output)
        else:
            _emit(_render_sections_text(pipeline_sections(report)), args.output)
        return 0 if not report.get('errors') else 1

    if action == 'init':
        spec = {
            'name': args.name,
            'description': 'Starter pipeline generated by `pipeline init`.',
            'variables': {'target': 'example.com'},
            'steps': [
                {'lookup': '$target'},
                {'risk': True},
                {'timeline': True},
                {'output': {'format': 'table', 'path': ''}},
            ],
        }
        path = save_pipeline(args.name, spec, folder=getattr(args, 'path', None))
        if path is None:
            _err('could not write pipeline file')
            return 1
        _emit(f"Pipeline written: {path}", None)
        return 0

    return 2


# ---------------------------------------------------------------------------
# v4.0 handlers: intel
# ---------------------------------------------------------------------------

def _cmd_intel(args: argparse.Namespace) -> int:
    action = getattr(args, 'action', None)
    if action is None:
        _err('usage: obscuralens intel ip|tor|feeds')
        return 2

    from .intel import feeds as intel_feeds
    from .intel import tor as intel_tor

    fmt = args.format or 'table'

    if action == 'ip':
        ok, error = validate_ip(args.target)
        if not ok:
            _err(error)
            return 2
        verdict = intel_feeds.check_ip(args.target)
        if fmt == 'json':
            _emit(json.dumps(verdict, indent=2, ensure_ascii=False, default=str),
                  args.output)
        else:
            rows = [['Tor exit node', 'yes' if verdict.get('tor') else 'no'],
                    ['Spamhaus DROP', 'yes' if verdict.get('spamhaus_drop') else 'no'],
                    ['Feodo tracker', 'yes' if verdict.get('feodo') else 'no'],
                    ['FireHOL level-1', 'yes' if verdict.get('firehol_level1') else 'no'],
                    ['Listed on', verdict.get('listed_count', 0)]]
            relay = verdict.get('relay') or {}
            if relay.get('is_relay'):
                rows.append(['Tor relay', relay.get('nickname', 'yes')])
            sections = [{'title': f'Threat Intel - {args.target}',
                         'type': 'table', 'columns': ['Check', 'Result'],
                         'rows': rows}]
            _emit(_render_sections_text(sections), args.output)
        return 0

    if action == 'tor':
        ok, error = validate_ip(args.target)
        if not ok:
            _err(error)
            return 2
        data = {
            'ip': args.target,
            'is_tor_exit': intel_tor.is_tor_exit(args.target),
            'relay': intel_tor.relay_details(args.target),
        }
        if fmt == 'json':
            _emit(json.dumps(data, indent=2, ensure_ascii=False, default=str),
                  args.output)
        else:
            relay = data.get('relay') or {}
            rows = [
                ['Exit node', 'yes' if data['is_tor_exit'] else 'no'],
                ['Relay', relay.get('nickname', 'no') if relay.get('is_relay') else 'no'],
            ]
            _emit(_render_sections_text(
                [{'title': f'Tor - {args.target}', 'type': 'table',
                  'columns': ['Check', 'Result'], 'rows': rows}]),
                args.output)
        return 0

    if action == 'feeds':
        if args.refresh:
            intel_feeds.load_exit_nodes(force=True)
        status = intel_feeds.feeds_status()
        if fmt == 'json':
            _emit(json.dumps(status, indent=2, ensure_ascii=False), args.output)
        else:
            sections = [{'title': 'Blocklist Feeds', 'type': 'table',
                         'columns': ['Feed', 'Entries', 'Status'],
                         'rows': intel_feeds.feeds_sections()}]
            _emit(_render_sections_text(sections), args.output)
        return 0

    return 2


# ---------------------------------------------------------------------------
# v4.0 handlers: experimental
# ---------------------------------------------------------------------------

def _cmd_experimental(args: argparse.Namespace) -> int:
    action = getattr(args, 'action', None)
    if action is None:
        _err('usage: obscuralens experimental llm|permute|crawl|phish')
        return 2
    if not config.app_config.experimental_features:
        _err('experimental features are disabled (app.experimental_features)')
        return 2

    fmt = args.format or 'table'

    if action == 'llm':
        kind = args.kind
        target = args.target
        if kind == 'auto':
            kind = detect_kind(target)
            if kind is None:
                _err(f"cannot determine target type: {target!r}")
                return 2
        validator = {
            'ip': validate_ip, 'phone': validate_phone,
            'username': validate_username, 'email': validate_email,
            'domain': validate_domain, 'url': validate_url,
            'crypto': validate_crypto_address, 'hash': validate_hash,
            'cve': validate_cve, 'asn': validate_asn,
        }.get(kind)
        if validator:
            ok, error = validator(target)
            if not ok:
                _err(error)
                return 2

        from .experimental.llm_summary import llm_configured, summarize
        if not llm_configured():
            _err('llm not configured - set app.llm_base_url and the llm api key')
            return 2
        _info(f"Collecting data for {target} ...")
        result = _tracker(kind).track(target)
        summary = summarize(kind, result)
        if summary.get('error'):
            _err(f"llm summary failed: {summary['error']}")
            return 1
        if fmt == 'json':
            _emit(json.dumps({'target': target, 'kind': kind, 'llm': summary},
                             indent=2, ensure_ascii=False, default=str), args.output)
        else:
            from .experimental.llm_summary import llm_sections
            _emit(_render_sections_text(llm_sections(summary)), args.output)
        return 0

    if action == 'permute':
        from .experimental.username_permutations import (
            generate_variants,
            permutation_summary,
            scan_variants,
        )
        variants = generate_variants(args.username, max_variants=args.max)
        if not args.scan:
            if fmt == 'json':
                _emit(json.dumps({'username': args.username,
                                  'variants': variants}, indent=2), args.output)
            else:
                _emit('\n'.join(variants), args.output)
            return 0
        _info(f"Scanning {len(variants)} variants on {args.platforms or ''}platforms...")
        scanned = scan_variants(variants, max_platforms=args.platforms)
        summary = permutation_summary(scanned)
        if fmt == 'json':
            _emit(json.dumps({'summary': summary, 'results': scanned},
                             indent=2, ensure_ascii=False), args.output)
        else:
            rows = [[r.get('variant', ''), r.get('platform', ''),
                     r.get('status', ''), r.get('url', '')]
                    for r in scanned]
            sections = [{'title': 'Permutation Scan', 'type': 'grid', 'data': {
                'Username': args.username,
                'Scanned': summary.get('scanned', 0),
                'Found': summary.get('found', 0),
                'Variants with hits': summary.get('variants_with_hits', 0),
            }}]
            if rows:
                sections.append({'title': 'Results', 'type': 'table',
                                 'columns': ['Variant', 'Platform', 'Status', 'URL'],
                                 'rows': rows})
            _emit(_render_sections_text(sections), args.output)
        return 0

    if action == 'crawl':
        ok, error = validate_url(args.url)
        if not ok:
            _err(error)
            return 2
        from .experimental.web_crawler import crawl, crawl_sections
        _info(f"Crawling {args.url} (bounded)...")
        report = crawl(args.url, max_depth=args.depth,
                       max_pages=args.max_pages, delay=args.delay,
                       respect_robots=not args.ignore_robots)
        if report.get('error'):
            _err(str(report['error']))
            return 1
        if fmt == 'json':
            _emit(json.dumps(report, indent=2, ensure_ascii=False, default=str),
                  args.output)
        else:
            _emit(_render_sections_text(crawl_sections(report)), args.output)
        return 0

    if action == 'phish':
        from .experimental.phishing_score import phishing_sections, score
        verdict = score(args.target)
        if fmt == 'json':
            _emit(json.dumps(verdict, indent=2, ensure_ascii=False), args.output)
        else:
            _emit(_render_sections_text(phishing_sections(verdict)), args.output)
        return 0

    return 2


_HANDLERS = {
    'ip': _cmd_ip,
    'phone': _cmd_phone,
    'username': _cmd_username,
    'email': _cmd_email,
    'domain': _cmd_domain,
    'url': _cmd_url,
    'crypto': _cmd_crypto,
    'hash': _cmd_hash,
    'cve': _cmd_cve,
    'asn': _cmd_asn,
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
    # v4.0 commands
    'risk': _cmd_risk,
    'timeline': _cmd_timeline,
    'correlate': _cmd_correlate,
    'diff': _cmd_diff,
    'export': _cmd_export,
    'case': _cmd_case,
    'pipeline': _cmd_pipeline,
    'intel': _cmd_intel,
    'experimental': _cmd_experimental,
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
