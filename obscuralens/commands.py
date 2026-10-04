"""
Non-interactive command-line interface.

Examples:
    obscuralens ip 8.8.8.8 --format json
    obscuralens username github --fast
    obscuralens mac b8:27:eb:11:22:33
    obscuralens tools jwt <token>
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
from .utils.formatting import label as _label
from .utils.validators import (
    validate_asn,
    validate_coords,
    validate_crypto_address,
    validate_cve,
    validate_domain,
    validate_email,
    validate_hash,
    validate_iban,
    validate_imei,
    validate_ip,
    validate_mac,
    validate_phone,
    validate_url,
    validate_username,
)
from .watchlist import watchlist

KINDS = ('ip', 'phone', 'username', 'email', 'domain', 'url', 'crypto',
         'hash', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords')
FORMATS = ('table', 'json', 'markdown', 'html', 'csv', 'mermaid')

_TRACKERS: Dict[str, Any] = {}

#: Input validators for every supported target kind (v5.0 added the last four).
_VALIDATORS: Dict[str, Any] = {
    'ip': validate_ip, 'phone': validate_phone,
    'username': validate_username, 'email': validate_email,
    'domain': validate_domain, 'url': validate_url,
    'crypto': validate_crypto_address, 'hash': validate_hash,
    'cve': validate_cve, 'asn': validate_asn,
    'mac': validate_mac, 'iban': validate_iban,
    'imei': validate_imei, 'coords': validate_coords,
}


def _validator(kind: str) -> Optional[Any]:
    """Return the input validator for a target kind (None when unknown)."""
    return _VALIDATORS.get(kind)


def _tracker(kind: str):
    if kind not in _TRACKERS:
        from .trackers import (
            ASNTracker,
            CoordsTracker,
            CryptoTracker,
            CVETracker,
            DomainTracker,
            EmailTracker,
            HashTracker,
            IBANTracker,
            IMEITracker,
            IPTracker,
            MACTracker,
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
            'mac': MACTracker,
            'iban': IBANTracker,
            'imei': IMEITracker,
            'coords': CoordsTracker,
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
        p.add_argument('--template', nargs='?', const='list', metavar='NAME',
                       help='render through a shipped Jinja report template '
                            'instead of the built-in formatter; a bare '
                            '--template lists the available names')

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

    # -- v5.0 target kinds ----------------------------------------------------

    p_mac = sub.add_parser('mac', help='look up a MAC address (vendor, flags)')
    p_mac.add_argument('target', help='MAC address, e.g. b8:27:eb:11:22:33')
    add_common(p_mac)

    p_iban = sub.add_parser('iban', help='validate and dissect an IBAN')
    p_iban.add_argument('target', help='IBAN, e.g. DE89370400440532013000')
    add_common(p_iban)

    p_imei = sub.add_parser('imei', help='decode an IMEI (TAC, manufacturer)')
    p_imei.add_argument('target', help='IMEI (15/16 digits), e.g. 356938035643809')
    add_common(p_imei)

    p_coords = sub.add_parser('coords', help='reverse-geocode coordinates')
    p_coords.add_argument('target',
                          help='DD/DMS/UTM/MGRS coordinates, e.g. "48.8584, 2.2945"')
    add_common(p_coords)

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
    p_serve.add_argument('--open', dest='open_browser', action='store_true',
                         default=None,
                         help='open the web UI in a browser after startup '
                              '(default: auto when run interactively)')
    p_serve.add_argument('--no-open', dest='open_browser', action='store_false',
                         help='never open a browser automatically')
    add_common(p_serve)

    p_tui = sub.add_parser('tui', help='terminal UI (needs [tui] extra)')
    add_common(p_tui)

    p_mcp = sub.add_parser('mcp', help='MCP stdio server for AI assistants')
    add_common(p_mcp)
    add_common(p_plugins)

    # -- v5.1 desktop beta commands ------------------------------------
    p_desktop = sub.add_parser(
        'desktop', help='launch the desktop beta (local web UI in a browser)')
    p_desktop.add_argument('--host', default='127.0.0.1',
                           help='interface to bind (default: loopback only)')
    p_desktop.add_argument('--port', type=int, default=8000,
                           help='preferred port; free ports are probed upward')
    p_desktop.add_argument('--no-browser', action='store_true',
                           help='start the server without opening a browser')
    p_desktop.add_argument('--channel', default=None,
                           help='release channel to report/check (beta default)')
    p_desktop.add_argument('--diagnostics', action='store_true',
                           help='print a desktop diagnostics report and exit')
    p_desktop.add_argument('--check-update', action='store_true',
                           help='check GitHub Releases for a newer beta and exit')

    p_update = sub.add_parser('update',
                              help='desktop beta update checks (no auto-download)')
    update_sub = p_update.add_subparsers(dest='update_command', metavar='<action>')
    p_update_check = update_sub.add_parser(
        'check', help='check GitHub Releases for a newer desktop beta')
    p_update_check.add_argument('--channel', default=None,
                                help='channel to check (beta default)')
    add_common(p_update)

    p_i18n = sub.add_parser('i18n', help='language catalogues (14 languages)')
    i18n_sub = p_i18n.add_subparsers(dest='i18n_command', metavar='<action>')
    i18n_list = i18n_sub.add_parser('list', help='list supported languages')
    i18n_list.add_argument('--completion', action='store_true',
                           help='include key coverage per locale')
    i18n_show = i18n_sub.add_parser('show', help='show one translated key')
    i18n_show.add_argument('key', help='dot-separated catalogue key')
    i18n_show.add_argument('--lang', default=None, help='locale code (default: en)')
    i18n_show.add_argument('--all', action='store_true', dest='all_langs',
                           help='print the key in every locale')
    i18n_match = i18n_sub.add_parser('match', help='resolve an Accept-Language header')
    i18n_match.add_argument('header', help='e.g. "zh-CN,zh;q=0.9,en;q=0.8"')
    add_common(p_i18n)

    p_data = sub.add_parser('data', help='query the offline data catalog')
    data_sub = p_data.add_subparsers(dest='data_command', metavar='<query>')
    data_country = data_sub.add_parser('country', help='ISO 3166 country lookup')
    data_country.add_argument('code', help='alpha-2 or alpha-3 code, or search term')
    data_port = data_sub.add_parser('port', help='IANA port/service lookup')
    data_port.add_argument('number', type=int, help='port number')
    data_port.add_argument('--protocol', default='tcp', choices=['tcp', 'udp'])
    data_tld = data_sub.add_parser('tld', help='check a TLD against the IANA list')
    data_tld.add_argument('tld', help='TLD with or without the leading dot')
    data_cwe = data_sub.add_parser('cwe', help='CWE weakness lookup')
    data_cwe.add_argument('id', help='e.g. CWE-79 or 79')
    data_status = data_sub.add_parser('status', help='HTTP status phrase lookup')
    data_status.add_argument('code', type=int, help='status code')
    data_ua = data_sub.add_parser('ua', help='draw a random user-agent string')
    data_ua.add_argument('--family', default=None, help='Chrome, Firefox, curl ...')
    data_ua.add_argument('--platform', default=None, help='Windows 11, macOS ...')
    data_ua.add_argument('--seed', type=int, default=None,
                         help='deterministic draw')
    data_mime = data_sub.add_parser('mime', help='MIME type lookup by extension')
    data_mime.add_argument('ext', help='extension with or without the dot')
    data_sub.add_parser('stats', help='catalog pack statistics')
    add_common(p_data)

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

    # -- v5.0 analyst toolbox ----------------------------------------------------

    p_tools = sub.add_parser(
        'tools', help='offline analyst toolbox (encoders, JWT, hashes, ...)')
    tools_sub = p_tools.add_subparsers(dest='action', metavar='<action>')

    def add_tools_common(p: argparse.ArgumentParser) -> None:
        p.add_argument('-f', '--format', choices=('table', 'json'), default=None,
                       help='output format (default: table)')
        p.add_argument('-o', '--output', metavar='FILE',
                       help='write output to FILE instead of stdout')
        p.add_argument('--no-color', action='store_true',
                       help='disable ANSI colours')

    p_enc = tools_sub.add_parser(
        'encode', help='encode text through every scheme')
    p_enc.add_argument('text', help='text to encode')
    p_enc.add_argument('--scheme', metavar='NAME',
                       help='one scheme (hex/base32/base64/base85/url_percent/'
                            'html_entity/rot13/caesar/binary/decimal/reversed/'
                            'morse/gzip); default: all schemes + digests')
    add_tools_common(p_enc)

    p_dec = tools_sub.add_parser('decode', help='decode an encoded value')
    p_dec.add_argument('value', help='the encoded value')
    p_dec.add_argument('--scheme', metavar='NAME',
                       help='decode with one named scheme')
    p_dec.add_argument('--all', action='store_true',
                       help='rank decode candidates from every scheme')
    add_tools_common(p_dec)

    p_jwt = tools_sub.add_parser('jwt', help='inspect a JSON Web Token')
    p_jwt.add_argument('token', help='JWT in compact serialization')
    add_tools_common(p_jwt)

    p_hid = tools_sub.add_parser('hash-id', help='identify a hash format')
    p_hid.add_argument('hash', help='the hash string to identify')
    add_tools_common(p_hid)

    p_tcoords = tools_sub.add_parser(
        'coords', help='convert coordinates between formats')
    p_tcoords.add_argument('value', help='DD / DMS / UTM / MGRS coordinates')
    add_tools_common(p_tcoords)

    p_extr = tools_sub.add_parser(
        'extract', help='extract OSINT entities from text')
    p_extr.add_argument('text', nargs='?', default='',
                        help='text to scan (or use --file / --stdin)')
    p_extr.add_argument('--file', metavar='PATH', help='read text from a file')
    p_extr.add_argument('--stdin', action='store_true',
                        help='read text from standard input')
    add_tools_common(p_extr)

    p_squat = tools_sub.add_parser(
        'squat', help='typosquat / homoglyph variant analysis')
    p_squat.add_argument('domain', help='domain to defend, e.g. google.com')
    p_squat.add_argument('--min-risk', type=int, default=None, metavar='N',
                         help='only show variants scoring N or higher')
    p_squat.add_argument('--category', metavar='CAT',
                         help='restrict to one family (e.g. homoglyph)')
    add_tools_common(p_squat)

    p_exif = tools_sub.add_parser('exif', help='image metadata triage')
    p_exif.add_argument('path', help='path to an image file')
    add_tools_common(p_exif)

    p_stego = tools_sub.add_parser('stego', help='steganography analysis')
    p_stego.add_argument('path', help='path to an image file')
    add_tools_common(p_stego)

    # -- v5.0 analysis commands ----------------------------------------------------

    p_report = sub.add_parser(
        'report', help='self-contained HTML investigation report')
    p_report.add_argument('kind', choices=KINDS, help='target type')
    p_report.add_argument('target', help='target value')
    p_report.add_argument('--format', choices=('html',), default='html',
                          help='report format (html)')
    p_report.add_argument('--output', metavar='FILE',
                          help='write the report to FILE (default: report dir)')
    p_report.add_argument('--no-color', action='store_true')

    p_patterns = sub.add_parser(
        'patterns', help='pattern-of-life analysis from stored history')
    p_patterns.add_argument('kind', choices=KINDS, help='target type')
    p_patterns.add_argument('target', help='target value')
    add_common(p_patterns)

    p_geo = sub.add_parser('geo', help='geographic profiling of stored history')
    geo_sub = p_geo.add_subparsers(dest='action', metavar='<action>')
    add_common(geo_sub.add_parser(
        'profile', help='country breakdown + analyst summary'))
    add_common(geo_sub.add_parser(
        'clusters', help='geohash clusters of coordinate lookups'))
    add_common(geo_sub.add_parser(
        'regions', help='most frequently looked-up regions'))

    p_alerts = sub.add_parser('alerts', help='webhook alert configuration')
    alerts_sub = p_alerts.add_subparsers(dest='action', metavar='<action>')
    add_common(alerts_sub.add_parser('show', help='config + recent events'))
    p_alerts_set = alerts_sub.add_parser('set', help='configure the webhook')
    p_alerts_set.add_argument('--url', metavar='URL', help='webhook URL')
    p_alerts_set.add_argument('--events', metavar='LIST',
                              help='comma-separated event list')
    add_common(p_alerts_set)
    add_common(alerts_sub.add_parser('test', help='send a test notification'))

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


def _render_via_template(name: str, kind: str, result: Dict[str, Any],
                         title: str) -> str:
    """
    Render a lookup through a shipped Jinja report template.

    ``--template`` with no value short-circuits to the catalogue listing so
    the available names are discoverable from the CLI itself.  A bad name is
    reported as a normal error, never as a traceback.
    """
    from jinja2 import TemplateNotFound

    from .reporting.template_render import available_templates, render_report

    if name == 'list':
        names = available_templates()
        return ('Available report templates:\n  '
                + ('\n  '.join(names) if names else '(none installed)'))

    sections = _sections_for_kind(kind, result)
    sections.extend(_extra_sections(result))
    try:
        return render_report(
            name, sections=sections, title=title, kind=kind,
            target=_result_target(kind, result), risk=result.get('risk'),
        )
    except TemplateNotFound as exc:
        return f'Error: {exc}'


def _emit_result(args: argparse.Namespace, kind: str, result: Dict[str, Any],
                 title: str) -> None:
    template = getattr(args, 'template', None)
    fmt = args.format or 'table'
    if template:
        _emit(_render_via_template(template, kind, result, title), args.output)
        return
    if fmt == 'json':
        _emit(json.dumps(result, indent=2, ensure_ascii=False, default=str),
              args.output)
    elif fmt == 'csv':
        _emit(_csv_from_result(kind, result), args.output)
    elif fmt in ('markdown', 'html'):
        sections = _sections_for_kind(kind, result)
        sections.extend(_extra_sections(result))
        generator = ReportGenerator()
        data = {'sections': sections}
        text = (generator.render_markdown(data, title) if fmt == 'markdown'
                else generator.render_html(data, title))
        _emit(text, args.output)
    else:
        sections = _sections_for_kind(kind, result)
        sections.extend(_extra_sections(result))
        _emit(_render_sections_text(sections), args.output)


def _sections_for_kind(kind: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reporting sections for a result, with a generic v5.0 fallback.

    Kinds that have no dedicated builder in ``reporting.sections`` (the
    v5.0 mac/iban/imei/coords kinds until they land there) are rendered
    through a provenance-aware generic layout instead.
    """
    sections = sections_for(kind, result)
    return sections if sections else _generic_sections(kind, result)


def _generic_sections(kind: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Provenance-aware fallback sections for kinds without a builder."""
    sections: List[Dict[str, Any]] = []
    info = result.get('info') or {}
    rows = rows_from_fields(info)
    if rows:
        sections.append({'title': f'{kind.upper()} FIELDS', 'type': 'table',
                         'columns': ['Field', 'Value'], 'rows': rows})

    provenance = result.get('field_sources') or {}
    if provenance:
        prov_rows = [[_label(field), ', '.join(str(s) for s in sources)]
                     for field, sources in sorted(provenance.items())]
        sections.append({'title': 'FIELD SOURCES', 'type': 'table',
                         'columns': ['Field', 'Source(s)'], 'rows': prov_rows})

    ok_sources = list(result.get('sources_ok') or [])
    failed = result.get('sources_failed') or {}
    if isinstance(failed, dict):
        failed_rows = [[name, str(err) or 'failed']
                       for name, err in failed.items()]
    else:
        failed_rows = [[name, 'failed'] for name in failed]
    source_rows = [[name, 'OK'] for name in ok_sources] + failed_rows
    if source_rows:
        sections.append({'title': 'SOURCES QUERIED', 'type': 'table',
                         'columns': ['Source', 'Status'], 'rows': source_rows})
    return sections


def _emit_tools(args: argparse.Namespace, payload: Dict[str, Any],
                sections: List[Dict[str, Any]]) -> None:
    """Emit a toolbox result: JSON to stdout/file or rendered sections."""
    fmt = getattr(args, 'format', None) or 'table'
    if fmt == 'json':
        _emit(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
              getattr(args, 'output', None))
    else:
        _emit(_render_sections_text(sections), getattr(args, 'output', None))


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


# ---------------------------------------------------------------------------
# v5.0 kind handlers: mac / iban / imei / coords
# ---------------------------------------------------------------------------

def _cmd_mac(args: argparse.Namespace) -> int:
    ok, error = validate_mac(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'mac', args.target, f"MAC Report - {args.target}")


def _cmd_iban(args: argparse.Namespace) -> int:
    ok, error = validate_iban(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'iban', args.target, f"IBAN Report - {args.target}")


def _cmd_imei(args: argparse.Namespace) -> int:
    ok, error = validate_imei(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'imei', args.target, f"IMEI Report - {args.target}")


def _cmd_coords(args: argparse.Namespace) -> int:
    ok, error = validate_coords(args.target)
    if not ok:
        _err(error)
        return 2
    return _run_lookup(args, 'coords', args.target,
                       f"Coordinates Report - {args.target}")


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

    validator = _validator(args.kind)
    invalid = [t for t in targets if validator and not validator(t)[0]]
    if invalid:
        _err(f"{len(invalid)} invalid target(s), e.g. {invalid[0]!r}")
        return 2

    risk = getattr(args, 'risk', False)
    advanced_batch = None
    if risk:
        # v5.0: the advanced engine adds per-result risk sections and a
        # run summary. It is optional: the legacy tracker path below still
        # covers plain batch runs unchanged.
        try:
            from .advanced import batch as advanced_batch
        except ImportError as e:
            advanced_batch = None
            _info(f"advanced batch module unavailable ({e}); "
                  f"using the legacy engine")

    results = None
    if advanced_batch is not None:
        try:
            payload = advanced_batch.run_batch(args.kind, targets, risk=True,
                                               max_workers=args.workers)
            results = payload.get('results', [])
            summary = payload.get('summary') or {}
            if summary:
                _info("Batch summary: "
                      + ', '.join(f"{k}={v}" for k, v in summary.items()))
        except Exception as e:  # contract drift should never kill a batch run
            results = None
            _info(f"advanced batch engine failed ({type(e).__name__}: {e}); "
                  f"using the legacy engine")

    if results is None:
        _info(f"Looking up {len(targets)} {args.kind} target(s)...")
        tracker = _tracker(args.kind)
        if args.kind == 'phone':
            results = tracker.batch_track(targets, args.region, args.workers)
        elif args.kind == 'username':
            results = tracker.batch_track(targets)
        else:
            results = tracker.batch_track(targets, args.workers)
        if risk:
            try:
                from .correlation import attach_risk
                for result in results:
                    attach_risk(args.kind, result)
            except ImportError:
                _info('risk scoring unavailable (correlation package missing)')

    fmt = args.format or 'table'
    emitted = False
    if advanced_batch is not None and fmt in ('csv', 'json', 'markdown'):
        try:
            text = {
                'csv': advanced_batch.to_csv,
                'json': advanced_batch.to_json,
                'markdown': advanced_batch.to_markdown,
            }[fmt](results)
            _emit(text, args.output)
            emitted = True
        except Exception as e:
            _info(f"advanced batch formatter failed ({type(e).__name__}: {e}); "
                  f"using the legacy renderer")

    if not emitted:
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
    from .trackers.coords_sources import SOURCE_CATALOG as COORDS_CATALOG
    from .trackers.crypto_sources import SOURCE_CATALOG as CRYPTO_CATALOG
    from .trackers.cve_sources import SOURCE_CATALOG as CVE_CATALOG
    from .trackers.domain_sources import SOURCE_CATALOG as DOMAIN_CATALOG
    from .trackers.email_sources import SOURCE_CATALOG as EMAIL_CATALOG
    from .trackers.hash_sources import SOURCE_CATALOG as HASH_CATALOG
    from .trackers.iban_sources import SOURCE_CATALOG as IBAN_CATALOG
    from .trackers.imei_sources import SOURCE_CATALOG as IMEI_CATALOG
    from .trackers.ip_sources import SOURCE_CATALOG as IP_CATALOG
    from .trackers.mac_sources import SOURCE_CATALOG as MAC_CATALOG
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
        # v5.0 kinds
        'mac': MAC_CATALOG,
        'iban': IBAN_CATALOG,
        'imei': IMEI_CATALOG,
        'coords': COORDS_CATALOG,
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
    open_browser = getattr(args, 'open_browser', None)
    if open_browser is None:
        open_browser = sys.stdin.isatty() and sys.stdout.isatty()
    if open_browser:
        _schedule_browser_open(args.host, args.port)
    serve(host=args.host, port=args.port, reload=args.reload)
    return 0
    return 0


def _schedule_browser_open(host: str, port: int, delay: float = 1.2) -> None:
    """Open the web UI in the default browser shortly after startup.

    The server prints its startup banner and binds its socket inside
    ``serve()``; a short daemon timer lands the browser right after that
    message without blocking or crashing on headless machines.
    """
    import threading

    url_host = '127.0.0.1' if host in ('0.0.0.0', '::', '') else host

    def _open() -> None:
        try:
            import webbrowser
            webbrowser.open(f'http://{url_host}:{port}')
        except Exception:  # browser launch is best-effort, never fatal
            _info('could not open a browser automatically')

    try:
        timer = threading.Timer(delay, _open)
        timer.daemon = True
        timer.start()
    except Exception:
        pass  # never let a timer failure block the server


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

    validator = _validator(args.kind)
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
        validator = _validator(kind)
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


# ---------------------------------------------------------------------------
# v5.0 handlers: analyst toolbox (`tools`)
# ---------------------------------------------------------------------------

def _cmd_tools(args: argparse.Namespace) -> int:
    action = getattr(args, 'action', None)
    handlers: Dict[str, Any] = {
        'encode': _cmd_tools_encode,
        'decode': _cmd_tools_decode,
        'jwt': _cmd_tools_jwt,
        'hash-id': _cmd_tools_hash_id,
        'coords': _cmd_tools_coords,
        'extract': _cmd_tools_extract,
        'squat': _cmd_tools_squat,
        'exif': _cmd_tools_exif,
        'stego': _cmd_tools_stego,
    }
    handler = handlers.get(action)
    if handler is None:
        _err('usage: obscuralens tools encode|decode|jwt|hash-id|coords|'
             'extract|squat|exif|stego')
        return 2
    return handler(args)


def _cmd_tools_encode(args: argparse.Namespace) -> int:
    """Encode text through one or every scheme, plus known digests."""
    from .experimental.encoders import SCHEMES, encode_all, hash_all

    scheme_name = (args.scheme or '').strip().lower()
    if scheme_name:
        scheme = SCHEMES.get(scheme_name)
        if scheme is None:
            _err(f"unknown scheme {args.scheme!r}; "
                 f"available: {', '.join(SCHEMES)}")
            return 2
        try:
            value = scheme['encode'](args.text)
        except (ValueError, UnicodeError) as e:
            _err(f"cannot encode with {scheme_name}: {e}")
            return 1
        payload: Dict[str, Any] = {
            'text': args.text, 'scheme': scheme_name,
            'label': scheme['label'], 'value': value,
        }
        sections = [{
            'title': f"Encoded - {scheme['label']}", 'type': 'grid',
            'data': {'input': args.text, 'scheme': scheme_name, 'value': value},
        }]
        _emit_tools(args, payload, sections)
        return 0

    encoded = encode_all(args.text)
    digests = hash_all(args.text)
    payload = {'text': args.text, 'encodings': encoded, 'digests': digests}
    sections = [
        {'title': 'Encodings', 'type': 'table',
         'columns': ['Scheme', 'Value'],
         'rows': [[name, value] for name, value in encoded.items()]},
        {'title': 'Digests', 'type': 'table',
         'columns': ['Hash', 'Value'],
         'rows': [[name, value] for name, value in digests.items()]},
    ]
    _emit_tools(args, payload, sections)
    return 0


def _cmd_tools_decode(args: argparse.Namespace) -> int:
    """Decode a value with one scheme, or rank every scheme (--all)."""
    from .experimental.encoders import SCHEMES, decode_auto

    if args.all or not args.scheme:
        candidates = decode_auto(args.value)
        payload: Dict[str, Any] = {'value': args.value, 'candidates': candidates}
        sections = [{
            'title': 'Decode Candidates (best first)', 'type': 'table',
            'columns': ['Scheme', 'Score', 'Result', 'Note'],
            'rows': [[c.get('scheme', ''), c.get('score', ''),
                      c.get('result', ''), c.get('note', '')]
                     for c in candidates],
        }]
        if not candidates:
            sections.append({
                'title': 'No Readable Decode', 'type': 'text',
                'content': 'No scheme produced printable output for this value.'})
        _emit_tools(args, payload, sections)
        return 0

    scheme_name = args.scheme.strip().lower()
    scheme = SCHEMES.get(scheme_name)
    if scheme is None:
        _err(f"unknown scheme {args.scheme!r}; "
             f"available: {', '.join(SCHEMES)}")
        return 2
    try:
        decoded = scheme['decode'](args.value)
    except (ValueError, UnicodeError) as e:
        _err(f"cannot decode with {scheme_name}: {e}")
        return 1
    payload = {'value': args.value, 'scheme': scheme_name, 'decoded': decoded}
    sections = [{
        'title': f"Decoded - {scheme['label']}", 'type': 'grid',
        'data': {'input': args.value, 'scheme': scheme_name, 'decoded': decoded},
    }]
    _emit_tools(args, payload, sections)
    return 0


def _cmd_tools_jwt(args: argparse.Namespace) -> int:
    """Inspect a JWT: header, payload, claims, key hints and warnings."""
    from .experimental.jwt_tools import inspect_jwt

    inspected = inspect_jwt(args.token)
    if inspected.get('error'):
        _err(f"invalid JWT: {inspected['error']}")
        return 1

    header = inspected.get('header') or {}
    payload_claims = inspected.get('payload') or {}
    claims = inspected.get('claims') or {}
    identifiers = inspected.get('identifiers') or {}
    key_info = inspected.get('key_info') or {}
    token_stats = inspected.get('token_stats') or {}
    alg = inspected.get('alg') or {}

    sections: List[Dict[str, Any]] = [
        {'title': 'Header', 'type': 'table', 'columns': ['Claim', 'Value'],
         'rows': [[key, value] for key, value in header.items()]},
        {'title': 'Payload', 'type': 'table', 'columns': ['Claim', 'Value'],
         'rows': [[key, value] for key, value in payload_claims.items()]},
    ]

    claim_rows = []
    for name in ('iat', 'nbf', 'exp'):
        summary = claims.get(name) or {}
        expired = summary.get('expired')
        state = ''
        if expired is True:
            state = 'expired'
        elif expired is False:
            state = 'valid'
        claim_rows.append([name.upper(), summary.get('raw', ''),
                           summary.get('datetime') or '', state])
    sections.append({'title': 'Time Claims', 'type': 'table',
                     'columns': ['Claim', 'Raw', 'Datetime (UTC)', 'Status'],
                     'rows': claim_rows})

    summary_grid: Dict[str, Any] = {}
    for key in ('iss', 'sub', 'aud', 'jti'):
        if identifiers.get(key):
            summary_grid[key] = identifiers[key]
    if alg:
        summary_grid['alg'] = alg.get('value')
        summary_grid['alg family'] = alg.get('family')
    for key in ('kid', 'jku', 'x5u'):
        if key_info.get(key):
            summary_grid[f'header {key}'] = key_info[key]
    if key_info.get('x5c_present'):
        summary_grid['x5c chain'] = f"{key_info.get('x5c_count', 0)} certificate(s)"
    for key in ('total_length', 'header_length', 'payload_length',
                'signature_length'):
        if token_stats.get(key) is not None:
            summary_grid[key.replace('_', ' ')] = token_stats[key]
    if summary_grid:
        sections.append({'title': 'Token Summary', 'type': 'grid',
                         'data': summary_grid})

    notes = inspected.get('notes') or []
    if notes:
        sections.append({'title': 'Notes & Warnings', 'type': 'text',
                         'content': '\n'.join(f'- {note}' for note in notes)})
    _emit_tools(args, inspected, sections)
    return 0


def _cmd_tools_hash_id(args: argparse.Namespace) -> int:
    """Identify the likely format(s) of a hash-like string."""
    from .experimental.hash_identify import identify_hash

    if not (args.hash or '').strip():
        _err('hash value cannot be empty')
        return 2
    candidates = identify_hash(args.hash)
    payload = {'hash': args.hash, 'candidates': candidates}
    sections = [{
        'title': 'Hash Candidates', 'type': 'table',
        'columns': ['Name', 'Confidence', 'Bytes', 'Note'],
        'rows': [[c.get('name', ''), c.get('confidence', ''),
                  c.get('length', ''), c.get('note', '')]
                 for c in candidates],
    }]
    if not candidates:
        sections.append({'title': 'No Candidates', 'type': 'text',
                         'content': 'No candidate matched this value.'})
    _emit_tools(args, payload, sections)
    return 0


def _cmd_tools_coords(args: argparse.Namespace) -> int:
    """Parse coordinates and convert them to every supported format."""
    from .utils.coordinate_math import (
        latlon_to_ddm,
        latlon_to_dms,
        latlon_to_geohash,
        latlon_to_maidenhead,
        latlon_to_mgrs,
        latlon_to_utm,
    )
    from .utils.validators import parse_coords

    parsed = parse_coords(args.value)
    if parsed is None:
        _err(f"unrecognised coordinate format: {args.value!r}")
        return 2
    lat, lon = parsed

    def safe(label: str, func: Any, *func_args: Any) -> List[str]:
        try:
            return [label, str(func(*func_args))]
        except (ValueError, TypeError, OverflowError):
            return [label, 'out of range']

    utm = latlon_to_utm(lat, lon)
    rows = [
        ['Input', args.value],
        ['Decimal degrees', f"{lat:.6f}, {lon:.6f}"],
        safe('DMS latitude', latlon_to_dms, lat, 'lat'),
        safe('DMS longitude', latlon_to_dms, lon, 'lon'),
        safe('Degrees decimal minutes', latlon_to_ddm, lat, lon),
        ['UTM', f"{utm[0]}{utm[1]} {utm[2]:.0f} {utm[3]:.0f}"],
        safe('MGRS', latlon_to_mgrs, lat, lon),
        safe('Geohash', latlon_to_geohash, lat, lon),
        safe('Maidenhead', latlon_to_maidenhead, lat, lon),
    ]
    payload = {'input': args.value, 'latitude': lat, 'longitude': lon,
               'formats': {row[0]: row[1] for row in rows}}
    sections = [{'title': 'Coordinate Formats', 'type': 'table',
                 'columns': ['Format', 'Value'], 'rows': rows}]
    _emit_tools(args, payload, sections)
    return 0


def _cmd_tools_extract(args: argparse.Namespace) -> int:
    """Extract OSINT pivot entities from text, a file or stdin."""
    from .experimental.entity_extract import extract_entities, summarize_entities

    if args.stdin:
        text = sys.stdin.read()
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            _err(f"file not found: {path}")
            return 2
        text = path.read_text(encoding='utf-8', errors='replace')
    else:
        text = args.text or ''
    if not text.strip():
        _err('no text to scan (pass TEXT, --file PATH or --stdin)')
        return 2

    found = extract_entities(text)
    summary = summarize_entities(found)
    payload = {'summary': summary, 'entities': found}
    sections = [{
        'title': 'Entity Counts', 'type': 'table',
        'columns': ['Kind', 'Count'],
        'rows': [[kind, count] for kind, count in summary.items()],
    }]
    for kind, values in found.items():
        if values:
            sections.append({
                'title': f"{kind} ({len(values)})", 'type': 'table',
                'columns': ['Value'], 'rows': [[value] for value in values]})
    _emit_tools(args, payload, sections)
    return 0


def _cmd_tools_squat(args: argparse.Namespace) -> int:
    """Generate and risk-score typosquat variants of a domain."""
    from .experimental.squatting import generate_variants, score_variants

    variants = generate_variants(args.domain)
    if not variants:
        _err(f"cannot parse domain: {args.domain!r}")
        return 2
    scored = score_variants(variants, args.domain)

    min_risk = args.min_risk if args.min_risk is not None else 0
    category = (args.category or '').strip().lower()
    shown = [v for v in scored
             if int(v.get('risk', 0)) >= min_risk
             and (not category or str(v.get('category', '')).lower() == category)]

    payload = {'domain': args.domain, 'total_variants': len(scored),
               'shown': len(shown), 'min_risk': min_risk,
               'category': category or None, 'variants': shown}
    sections = [
        {'title': f"Squatting Variants - {args.domain}", 'type': 'grid',
         'data': {'domain': args.domain,
                  'variants generated': len(scored),
                  'shown': len(shown)}},
        {'title': 'Variants (risk descending)', 'type': 'table',
         'columns': ['Domain', 'Category', 'Risk', 'Description'],
         'rows': [[v.get('domain', ''), v.get('category', ''),
                   v.get('risk', ''), v.get('description', '')] for v in shown]},
    ]
    if not shown:
        sections.append({'title': 'No Variants', 'type': 'text',
                         'content': 'No variant matched the given filters.'})
    _emit_tools(args, payload, sections)
    return 0


def _cmd_tools_exif(args: argparse.Namespace) -> int:
    """Local-only EXIF / metadata triage for an image file."""
    from .experimental.exif_reader import analyze

    path = Path(args.path)
    if not path.exists():
        _err(f"file not found: {path}")
        return 2
    _info(f"Analyzing {path} ...")
    report = analyze(str(path))
    if report.get('error') and not report.get('file'):
        _err(f"cannot read file: {report['error']}")
        return 1

    sections: List[Dict[str, Any]] = []
    file_facts = report.get('file') or {}
    if file_facts:
        sections.append({'title': 'File', 'type': 'table',
                         'columns': ['Field', 'Value'],
                         'rows': rows_from_fields(file_facts)})
    exif = report.get('exif') or {}
    if exif:
        sections.append({'title': 'EXIF Metadata', 'type': 'table',
                         'columns': ['Field', 'Value'],
                         'rows': rows_from_fields(exif)})
    gps = report.get('gps') or {}
    if gps:
        sections.append({'title': 'GPS', 'type': 'table',
                         'columns': ['Field', 'Value'],
                         'rows': rows_from_fields(gps)})
    timeline = report.get('timeline') or []
    if timeline:
        sections.append({'title': 'Timeline Hints', 'type': 'table',
                         'columns': ['When (ISO 8601)'],
                         'rows': [[stamp] for stamp in timeline]})
    notes = report.get('osint_notes') or []
    if notes:
        sections.append({'title': 'OSINT Notes', 'type': 'text',
                         'content': '\n'.join(f'- {note}' for note in notes)})
    strings = report.get('strings') or []
    if strings:
        sections.append({
            'title': f"Interesting Strings (first {min(30, len(strings))})",
            'type': 'table', 'columns': ['Offset', 'Encoding', 'Value'],
            'rows': [[s.get('offset', ''), s.get('encoding', ''),
                      s.get('value', '')] for s in strings[:30]]})
    if report.get('error'):
        sections.append({'title': 'Parser Notes', 'type': 'text',
                         'content': str(report['error'])})
    if len(sections) <= 1:
        sections.append({'title': 'No Metadata', 'type': 'text',
                         'content': 'No EXIF/GPS metadata found in this image.'})
    _emit_tools(args, report, sections)
    return 0


def _cmd_tools_stego(args: argparse.Namespace) -> int:
    """Local-only steganography triage for an image file."""
    from .experimental.steganography import analyze as stego_analyze

    path = Path(args.path)
    if not path.exists():
        _err(f"file not found: {path}")
        return 2
    _info(f"Analyzing {path} ...")
    report = stego_analyze(str(path))
    if report.get('error') and 'lsb' not in report:
        _err(f"cannot read file: {report['error']}")
        return 1

    summary = report.get('summary') or {}
    sections: List[Dict[str, Any]] = [{
        'title': 'Steganography Verdict', 'type': 'grid',
        'data': {'format': report.get('format', ''),
                 'verdict': summary.get('verdict', ''),
                 'suspicion': summary.get('suspicion', 0)},
    }]
    findings = summary.get('findings') or []
    if findings:
        sections.append({'title': f"Findings ({len(findings)})", 'type': 'text',
                         'content': '\n'.join(f'- {item}' for item in findings)})
    entropy = report.get('entropy') or {}
    if entropy:
        sections.append({'title': 'Entropy', 'type': 'grid',
                         'data': {'overall (bits/byte)':
                                  entropy.get('overall_entropy_bits', ''),
                                  'sampled bytes':
                                  entropy.get('sampled_bytes', '')}})
        regions = entropy.get('high_entropy_regions') or []
        if regions:
            sections.append({
                'title': 'High-Entropy Regions', 'type': 'table',
                'columns': ['From', 'To', 'Mean entropy'],
                'rows': [[r.get('offset_from', ''), r.get('offset_to', ''),
                          r.get('mean_entropy', '')] for r in regions]})
    embedded = report.get('embedded_files') or {}
    carved = embedded.get('findings') or []
    if carved:
        sections.append({
            'title': f"Embedded Files ({len(carved)})", 'type': 'table',
            'columns': ['Type', 'Offset', 'Details'],
            'rows': [[c.get('type', ''), c.get('offset', ''),
                      c.get('details', '')] for c in carved]})
    strings = report.get('strings') or []
    if strings:
        sections.append({'title': 'Strings (lite)', 'type': 'text',
                         'content': '\n'.join(str(s) for s in strings[:10])})
    _emit_tools(args, report, sections)
    return 0


# ---------------------------------------------------------------------------
# v5.0 handlers: report / patterns / geo / alerts
# ---------------------------------------------------------------------------

def _cmd_report(args: argparse.Namespace) -> int:
    """Build and save a self-contained HTML investigation report."""
    try:
        from .advanced import report_builder
    except ImportError as e:
        _err(f"report builder unavailable: {e}")
        return 1

    _info(f"Building {args.kind} report for {args.target} ...")
    try:
        html = report_builder.build_report(args.kind, args.target)
        path = args.output or report_builder.report_path(args.kind, args.target)
        report_builder.save_report(path, html)
    except Exception as e:
        _err(f"report build failed: {type(e).__name__}: {e}")
        return 1
    _emit(str(path), None)
    return 0


_WEEKDAYS = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')


def _as_int(value: Any) -> int:
    """Best-effort int conversion (0 when not numeric)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _ascii_bar(count: int, max_count: int, width: int = 40) -> str:
    """ASCII bar in the repo's style (filled blocks + light shade)."""
    if max_count <= 0:
        return ''
    filled = int(round(width * float(count) / float(max_count)))
    filled = max(0, min(width, filled))
    return '█' * filled + '░' * (width - filled)


def _hour_counts(histogram: Any) -> List[List[Any]]:
    """Normalise an hour histogram (dict or 24-slot list) into rows."""
    pairs: List[List[Any]] = []
    if isinstance(histogram, dict):
        by_hour: Dict[int, int] = {}
        for key, value in histogram.items():
            try:
                by_hour[int(str(key).strip())] = _as_int(value)
            except (TypeError, ValueError):
                continue
        pairs = [[f'{hour:02d}', by_hour.get(hour, 0)] for hour in range(24)]
    elif isinstance(histogram, (list, tuple)):
        for hour in range(min(24, len(histogram))):
            pairs.append([f'{hour:02d}', _as_int(histogram[hour])])
    return pairs


def _weekday_counts(histogram: Any) -> List[List[Any]]:
    """Normalise a weekday histogram (dict or 7-slot list) into rows."""
    names = ('monday', 'tuesday', 'wednesday', 'thursday', 'friday',
             'saturday', 'sunday')
    pairs: List[List[Any]] = []
    if isinstance(histogram, dict):
        lowered = {str(key).strip().lower(): _as_int(value)
                   for key, value in histogram.items()}
        for index in range(7):
            value = None
            for candidate in (names[index], _WEEKDAYS[index].lower(),
                              str(index), str(index + 1)):
                if candidate in lowered:
                    value = lowered[candidate]
                    break
            pairs.append([_WEEKDAYS[index], _as_int(value)])
    elif isinstance(histogram, (list, tuple)):
        for index in range(min(7, len(histogram))):
            pairs.append([_WEEKDAYS[index], _as_int(histogram[index])])
    return pairs


def _pattern_sections(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Render a pattern-of-life report as sections (v5.0)."""
    sections: List[Dict[str, Any]] = []

    cadence = report.get('cadence')
    if isinstance(cadence, dict) and cadence:
        sections.append({'title': 'Cadence', 'type': 'grid', 'data': cadence})

    hours = _hour_counts(report.get('hour_histogram'))
    if hours:
        peak = max((count for _, count in hours), default=0)
        sections.append({'title': 'Hour Of Day', 'type': 'table',
                         'columns': ['Hour', 'Lookups', 'Distribution'],
                         'rows': [[name, count, _ascii_bar(count, peak)]
                                  for name, count in hours]})

    weekdays = _weekday_counts(report.get('weekday_histogram'))
    if weekdays:
        peak = max((count for _, count in weekdays), default=0)
        sections.append({'title': 'Day Of Week', 'type': 'table',
                         'columns': ['Day', 'Lookups', 'Distribution'],
                         'rows': [[name, count, _ascii_bar(count, peak)]
                                  for name, count in weekdays]})

    matrix = report.get('activity_matrix')
    if isinstance(matrix, dict) and matrix:
        rows = []
        for day, counts in matrix.items():
            if isinstance(counts, dict):
                by_hour = {}
                for key, value in counts.items():
                    try:
                        by_hour[int(str(key).strip())] = _as_int(value)
                    except (TypeError, ValueError):
                        continue
                text = ' '.join(f"{by_hour.get(hour, 0):2d}"
                                for hour in range(24))
            elif isinstance(counts, (list, tuple)):
                text = ' '.join(f"{_as_int(value):2d}" for value in counts[:24])
            else:
                continue
            rows.append([str(day), text])
        if rows:
            sections.append({'title': 'Activity Matrix (lookups per hour)',
                             'type': 'table', 'columns': ['Day', 'Hours 00-23'],
                             'rows': rows})

    bursts = report.get('bursts')
    if isinstance(bursts, (list, tuple)) and bursts \
            and isinstance(bursts[0], dict):
        columns = [str(key) for key in bursts[0]]
        sections.append({'title': f"Bursts ({len(bursts)})", 'type': 'table',
                         'columns': columns,
                         'rows': [[item.get(column, '') for column in columns]
                                  for item in bursts
                                  if isinstance(item, dict)]})

    peak_window = report.get('peak_window')
    if isinstance(peak_window, dict) and peak_window:
        sections.append({'title': 'Peak Window', 'type': 'grid',
                         'data': peak_window})

    verdict = report.get('verdict')
    if verdict:
        lines = verdict if isinstance(verdict, (list, tuple)) else [verdict]
        sections.append({'title': 'Verdict', 'type': 'text',
                         'content': '\n'.join(f'- {line}' for line in lines
                                              if line)})
    return sections


def _cmd_patterns(args: argparse.Namespace) -> int:
    """Pattern-of-life analysis for one target from stored history."""
    try:
        from .advanced import patterns
    except ImportError as e:
        _err(f"pattern analysis unavailable: {e}")
        return 1

    _info(f"Analysing stored activity for {args.target} ...")
    try:
        report = patterns.pattern_report(args.kind, args.target)
    except Exception as e:
        _err(f"pattern analysis failed: {type(e).__name__}: {e}")
        return 1
    if not report:
        _err('no stored lookups for this target - run a lookup first')
        return 1

    if (args.format or 'table') == 'json':
        _emit(json.dumps(report, indent=2, ensure_ascii=False, default=str),
              args.output)
        return 0
    sections = _pattern_sections(report)
    if not sections:
        sections = [{'title': 'Pattern Report', 'type': 'grid',
                     'data': {'kind': args.kind, 'target': args.target}}]
    _emit(_render_sections_text(sections), args.output)
    return 0


def _cmd_geo(args: argparse.Namespace) -> int:
    """Geographic profiling of the stored lookup history."""
    action = getattr(args, 'action', None)
    if action is None:
        _err('usage: obscuralens geo profile|clusters|regions')
        return 2
    try:
        from .advanced import geospatial
    except ImportError as e:
        _err(f"geospatial module unavailable: {e}")
        return 1

    fmt = args.format or 'table'

    if action == 'profile':
        breakdown = geospatial.country_breakdown()
        summary = geospatial.geo_profile_summary()
        payload = {'summary': summary, 'countries': breakdown}
        if fmt == 'json':
            _emit(json.dumps(payload, indent=2, ensure_ascii=False,
                             default=str), args.output)
            return 0
        top_country = summary.get('top_country') or {}
        top_region = summary.get('top_region') or {}
        sections = [
            {'title': 'Geo Profile Summary', 'type': 'grid', 'data': {
                'distinct countries': summary.get('distinct_countries', 0),
                'top country': top_country.get('country', '(none)'),
                'top region': top_region.get('region', '(none)'),
                'coords lookups': summary.get('coords_lookups', 0),
                'geohash clusters': summary.get('geohash_clusters', 0),
                'history span (days)': summary.get('span_days') or 0,
                'records scanned': breakdown.get('total_records', 0),
                'geo-tagged records': breakdown.get('total_geo_tagged', 0),
            }},
        ]
        countries = breakdown.get('countries') or []
        rows = [[c.get('country', ''), c.get('code') or '-', c.get('count', 0),
                 ', '.join(c.get('targets') or [])] for c in countries]
        sections.append({'title': 'Countries', 'type': 'table',
                         'columns': ['Country', 'Code', 'Lookups', 'Targets'],
                         'rows': rows or [['(none)', '-', 0, '']]})
        _emit(_render_sections_text(sections), args.output)
        return 0

    if action == 'clusters':
        clusters = geospatial.geohash_clusters()
        payload = {'clusters': clusters}
        if fmt == 'json':
            _emit(json.dumps(payload, indent=2, ensure_ascii=False,
                             default=str), args.output)
            return 0
        rows = [[c.get('geohash', ''), c.get('count', 0),
                 ', '.join(str(v) for v in c.get('center') or []),
                 ', '.join(c.get('targets') or [])] for c in clusters]
        sections = [{'title': 'Geohash Clusters', 'type': 'table',
                     'columns': ['Geohash', 'Lookups', 'Center (lat, lon)',
                                 'Targets'],
                     'rows': rows or [['(none)', 0, '', '']]}]
        _emit(_render_sections_text(sections), args.output)
        return 0

    if action == 'regions':
        regions = geospatial.most_looked_up_regions()
        payload = {'regions': regions}
        if fmt == 'json':
            _emit(json.dumps(payload, indent=2, ensure_ascii=False,
                             default=str), args.output)
            return 0
        rows = [[r.get('region', ''), r.get('country') or '-', r.get('count', 0),
                 ', '.join(r.get('targets') or [])] for r in regions]
        sections = [{'title': 'Most Looked-Up Regions', 'type': 'table',
                     'columns': ['Region', 'Country', 'Lookups', 'Targets'],
                     'rows': rows or [['(none)', '-', 0, '']]}]
        _emit(_render_sections_text(sections), args.output)
        return 0

    return 2


def _cmd_alerts(args: argparse.Namespace) -> int:
    """Webhook alert configuration (show / set / test)."""
    action = getattr(args, 'action', None)
    if action is None:
        _err('usage: obscuralens alerts show|set|test')
        return 2
    try:
        from .advanced import alerts
    except ImportError as e:
        _err(f"alerts module unavailable: {e}")
        return 1

    fmt = args.format or 'table'

    if action == 'show':
        cfg = alerts.get_config()
        recent = alerts.recent()
        payload = {'config': cfg, 'recent': recent}
        if fmt == 'json':
            _emit(json.dumps(payload, indent=2, ensure_ascii=False,
                             default=str), args.output)
            return 0
        sections = [{'title': 'Alert Configuration', 'type': 'grid',
                     'data': cfg if isinstance(cfg, dict)
                     else {'config': str(cfg)}}]
        if isinstance(recent, (list, tuple)) and recent:
            rows = [[item] for item in recent]
            sections.append({'title': f"Recent Events ({len(recent)})",
                             'type': 'table', 'columns': ['Event'], 'rows': rows})
        elif isinstance(recent, dict) and recent:
            sections.append({'title': 'Recent Events', 'type': 'grid',
                             'data': recent})
        else:
            sections.append({'title': 'Recent Events', 'type': 'text',
                             'content': 'No notifications recorded yet.'})
        _emit(_render_sections_text(sections), args.output)
        return 0

    if action == 'set':
        if not args.url:
            _err('--url is required (obscuralens alerts set --url URL)')
            return 2
        events = [e.strip() for e in (args.events or '').split(',')
                  if e.strip()]
        try:
            try:
                result = alerts.configure(args.url, events=events or None)
            except TypeError:
                result = alerts.configure(args.url, events or None)
        except Exception as e:
            _err(f"alert configuration failed: {type(e).__name__}: {e}")
            return 1
        _emit(str(result), args.output)
        return 0

    if action == 'test':
        try:
            result = alerts.test()
        except Exception as e:
            _err(f"test notification failed: {type(e).__name__}: {e}")
            return 1
        if isinstance(result, dict) and result.get('error'):
            _err(f"test notification failed: {result['error']}")
            return 1
        _emit(str(result), args.output)
        return 0

    return 2


# ---------------------------------------------------------------------------
# v5.1 desktop beta commands
# ---------------------------------------------------------------------------

def _cmd_desktop(args: argparse.Namespace) -> int:
    """Launch the desktop beta experience (single-instance web UI)."""
    from .desktop import diagnostics_report
    from .desktop.launcher import LaunchOptions, launch

    if getattr(args, 'diagnostics', False):
        print(diagnostics_report(check_network=False))
        return 0
    if getattr(args, 'check_update', False):
        return _run_update_check(getattr(args, 'channel', None))

    options = LaunchOptions(
        host=getattr(args, 'host', '127.0.0.1'),
        port=getattr(args, 'port', 8000),
        no_browser=getattr(args, 'no_browser', False),
        channel=getattr(args, 'channel', None),
    )
    return launch(options)


def _run_update_check(channel: Optional[str]) -> int:
    """Check GitHub Releases for a newer desktop beta; never auto-downloads."""
    from .desktop.updater import check_for_updates

    info = check_for_updates(channel=channel)
    if info is None:
        _info('Update check failed or offline — the desktop beta never '
              'raises here; try again later or visit the Releases page.')
        return 1
    print(str(info))
    if info.is_newer:
        print()
        _info('Download: ' + (info.download_url or 'see the Releases page'))
    return 0


def _cmd_update(args: argparse.Namespace) -> int:
    """`obscuralens update check` entry point."""
    action = getattr(args, 'update_command', None) or 'check'
    if action != 'check':  # argparse enforces choices; defensive fallback
        _err(f"unknown update action: {action}")
        return 2
    return _run_update_check(getattr(args, 'channel', None))


def _cmd_i18n(args: argparse.Namespace) -> int:
    """Inspect the shipped language catalogues (14 locales)."""
    from .i18n import available_locales, best_match, language_name, list_languages, set_language, t

    action = getattr(args, 'i18n_command', None) or 'list'

    if action == 'list':
        show_completion = getattr(args, 'completion', False)
        rows = []
        for info in list_languages():
            row = [info.code, info.english_name, info.native_name,
                   info.direction]
            if show_completion:
                row.append(f"{info.completion * 100:.0f}%")
            rows.append(row)
        header = ['code', 'english', 'native', 'dir']
        if show_completion:
            header.append('coverage')
        print(render_table(rows, headers=header))
        _info(f"{len(available_locales())} languages; "
              "set one with `obscuralens i18n show <key> --lang <code>`")
        return 0

    if action == 'show':
        key = args.key
        lang = getattr(args, 'lang', None)
        if getattr(args, 'all_langs', False):
            rows = []
            for code in available_locales():
                set_language(code)
                rows.append([code, t(key)])
            set_language('en')
            print(render_table(rows, headers=['locale', 'value']))
            return 0
        code = lang or 'en'
        try:
            set_language(code)
        except Exception as e:  # unknown locale code
            _err(str(e))
            return 2
        value = t(key)
        print(f"{key} [{code}] = {value}")
        _info(f"native name: {language_name(code)}")
        return 0

    if action == 'match':
        header = args.header
        print(f"accept-language: {header}")
        print(f"best supported: {best_match(header)}")
        return 0

    _err(f"unknown i18n action: {action}")
    return 2


def _cmd_data(args: argparse.Namespace) -> int:
    """Query the offline data catalog (ISO registries, ports, TLDs, ...)."""
    from .utils import data_catalog

    action = getattr(args, 'data_command', None) or 'stats'

    if action == 'country':
        code = args.code
        entry = data_catalog.country(code)
        if entry is not None:
            print(render_table(
                [['alpha-2', entry.code], ['alpha-3', entry.code3],
                 ['numeric', entry.numeric], ['name', entry.name],
                 ['capital', entry.capital]],
                headers=['field', 'value']))
            return 0
        results = data_catalog.search_countries(code)
        if results:
            print(render_table(
                [[c.code, c.code3, c.numeric, c.name, c.capital]
                 for c in results[:25]],
                headers=['alpha-2', 'alpha-3', 'numeric', 'name', 'capital']))
            _info(f"{len(results)} matches")
            return 0
        _err(f"no country matches {code!r}")
        return 1

    if action == 'port':
        entry = data_catalog.port_service(args.number, args.protocol)
        if entry is None:
            cat = data_catalog.port_category(args.number)
            _info(f"port {args.number}/{args.protocol} is unassigned "
                  f"({cat} range)")
            return 1
        print(render_table(
            [['port', str(entry.port)], ['protocol', entry.protocol],
             ['service', entry.service], ['description', entry.description],
             ['category', data_catalog.port_category(entry.port)]],
            headers=['field', 'value']))
        return 0

    if action == 'tld':
        tld = args.tld
        if data_catalog.is_iana_tld(tld):
            clean = tld.lstrip('.').lower()
            print(f".{clean} is a delegated IANA root-zone TLD "
                  f"(of {data_catalog.tld_count()} tracked)")
            return 0
        _info(f"{tld!r} is NOT in the IANA root-zone list "
              f"(possible abuse signal in lookups)")
        return 1

    if action == 'cwe':
        entry = data_catalog.cwe(args.id)
        if entry is None:
            _err(f"unknown CWE id: {args.id}")
            return 1
        print(render_table([['id', entry.cwe_id], ['name', entry.name]],
                           headers=['field', 'value']))
        return 0

    if action == 'status':
        entry = data_catalog.http_status(args.code)
        if entry is None:
            _err(f"no HTTP status phrase for {args.code}")
            return 1
        print(render_table(
            [['code', str(entry.code)], ['phrase', entry.phrase],
             ['category', entry.category]],
            headers=['field', 'value']))
        return 0

    if action == 'ua':
        agent = data_catalog.random_user_agent(
            family=getattr(args, 'family', None),
            platform=getattr(args, 'platform', None),
            seed=getattr(args, 'seed', None))
        print(agent)
        return 0

    if action == 'mime':
        entry = data_catalog.mime_for_extension(args.ext)
        if entry is None:
            _err(f"no MIME mapping for .{args.ext.lstrip('.')}")
            return 1
        print(render_table(
            [['extension', entry.extension], ['mime', entry.mime],
             ['description', entry.description]],
            headers=['field', 'value']))
        return 0

    if action == 'stats':
        print(data_catalog.catalog_summary())
        return 0

    _err(f"unknown data query: {action}")
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
    # v5.0 kinds
    'mac': _cmd_mac,
    'iban': _cmd_iban,
    'imei': _cmd_imei,
    'coords': _cmd_coords,
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
    # v5.0 commands
    'tools': _cmd_tools,
    'report': _cmd_report,
    'patterns': _cmd_patterns,
    'geo': _cmd_geo,
    'alerts': _cmd_alerts,
    # v5.1 desktop beta commands
    'desktop': _cmd_desktop,
    'update': _cmd_update,
    'i18n': _cmd_i18n,
    'data': _cmd_data,
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
