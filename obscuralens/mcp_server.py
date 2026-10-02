"""
Model Context Protocol (MCP) server for ObscuraLens.

Exposes the ObscuraLens lookup and watchlist tools to AI assistants over
stdio using newline-delimited JSON-RPC 2.0 (one JSON object per line), which
is the transport MCP defines. This is deliberately *not* LSP Content-Length
framing.

Run it with::

    python -m obscuralens.mcp_server

Only JSON-RPC responses are written to stdout; diagnostics go to stderr, so
the stream stays machine-parsable.
"""

import json
import sys
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from . import __version__

_PROTOCOL_VERSION = '2024-11-05'

TOOLS: List[Dict[str, Any]] = [
    {
        'name': 'ip_lookup',
        'description': 'Look up geolocation, network and reputation data for '
                       'an IP address.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'IPv4 or IPv6 address.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'phone_lookup',
        'description': 'Parse a phone number and report its carrier, region '
                       'and type.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Phone number to look up.'},
                'region': {'type': 'string',
                           'description': 'Default region code used when the '
                                          'number has no country prefix '
                                          '(default: ID).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'username_lookup',
        'description': 'Scan public platforms for a username.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Username to scan for.'},
                'fast': {'type': 'boolean',
                         'description': 'Skip profile extraction on hits '
                                        '(default: false).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'email_lookup',
        'description': 'Look up an email address for domain, MX, breach and '
                       'reputation data.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Email address to look up.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'domain_lookup',
        'description': 'Look up registration, DNS, certificate transparency '
                       'and HTTP data for a domain.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Domain name to look up.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'investigate',
        'description': 'Auto-detect a target kind and optionally follow '
                       'bounded related pivots.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'IP / domain / email / phone / '
                                          'username to investigate.'},
                'pivot': {'type': 'boolean',
                          'description': 'Follow related targets '
                                         '(default: true).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'watch_list',
        'description': 'List every target currently on the watchlist.',
        'inputSchema': {
            'type': 'object',
            'properties': {},
            'additionalProperties': False,
        },
    },
    {
        'name': 'watch_check',
        'description': 'Run and diff watched targets, returning changes since '
                       'the previous check.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'identifier': {
                    'type': ['string', 'integer'],
                    'description': 'Watch id or target to check '
                                   '(default: all watched targets).',
                },
            },
            'additionalProperties': False,
        },
    },
    # -- v4.0 tools ------------------------------------------------------------
    {
        'name': 'url_lookup',
        'description': 'Analyze a URL: redirect chain, HTTP response, safety '
                       'verdicts and archive history.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string', 'description': 'http(s) URL.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'crypto_lookup',
        'description': 'Analyze a cryptocurrency address (btc/eth/xmr/doge/'
                       'ltc/xrp/ada): balances, totals and activity dates.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Cryptocurrency address.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'hash_lookup',
        'description': 'Look up a file hash across malware repositories '
                       'and reputation services.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'md5/sha1/sha256 file hash.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'cve_lookup',
        'description': 'Look up a CVE: description, CVSS, EPSS, references '
                       'and affected products.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'CVE identifier (CVE-YYYY-NNNN).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'asn_lookup',
        'description': 'Look up an autonomous system: holder, country, '
                       'announced prefixes and peers.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': ['string', 'integer'],
                           'description': 'AS number (AS15169 or 15169).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'risk_report',
        'description': 'Run a lookup and attach explainable heuristic risk '
                       'scoring (score, verdict, signals).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'kind': {'type': 'string',
                         'enum': ['ip', 'phone', 'username', 'email', 'domain',
                                  'url', 'crypto', 'hash', 'cve', 'asn'],
                         'description': 'Target kind.'},
                'target': {'type': 'string', 'description': 'Target value.'},
            },
            'required': ['kind', 'target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'correlate',
        'description': 'Correlate two targets against stored history and '
                       'report shared infrastructure, or scan the whole '
                       'history for clusters.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'a': {'type': 'string', 'description': 'First target value.'},
                'b': {'type': 'string', 'description': 'Second target value.'},
                'all': {'type': 'boolean',
                        'description': 'Scan the whole history for clusters '
                                       'instead of comparing two targets.'},
            },
            'additionalProperties': False,
        },
    },
    {
        'name': 'timeline',
        'description': 'Build a chronological event timeline across stored '
                       'lookup history.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Restrict to one target (optional).'},
                'limit': {'type': 'integer',
                          'description': 'Maximum events (default: 100).'},
            },
            'additionalProperties': False,
        },
    },
    {
        'name': 'threat_intel',
        'description': 'Check an IP against Tor exit lists and blocklist '
                       'feeds (Spamhaus DROP, Feodo, FireHOL level-1).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string', 'description': 'IPv4 address.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'source_health',
        'description': 'Per-source reliability statistics and circuit-breaker '
                       'state across all lookups.',
        'inputSchema': {
            'type': 'object',
            'properties': {},
            'additionalProperties': False,
        },
    },
]


def _target(arguments: Dict[str, Any]) -> str:
    """Return the required ``target`` argument or raise ValueError."""
    target = arguments.get('target')
    if not isinstance(target, str) or not target.strip():
        raise ValueError('target is required')
    return target


def _identifier(value: Any) -> Any:
    """Coerce a numeric watch identifier string to int (CLI convention)."""
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatch one MCP tool call to the matching ObscuraLens function.

    Trackers are imported lazily so this module can be imported cheaply and
    tests can monkeypatch the tracker classes. Raises ValueError for an
    unknown tool; callers translate that into an ``isError`` result.
    """
    arguments = arguments or {}
    if name == 'ip_lookup':
        from .trackers import IPTracker
        return IPTracker().track(_target(arguments))
    if name == 'phone_lookup':
        from .trackers import PhoneTracker
        region = arguments.get('region') or 'ID'
        return PhoneTracker().track(_target(arguments), default_region=region)
    if name == 'username_lookup':
        from .trackers import UsernameTracker
        deep = not bool(arguments.get('fast'))
        return UsernameTracker().track(_target(arguments), deep=deep)
    if name == 'email_lookup':
        from .trackers import EmailTracker
        return EmailTracker().track(_target(arguments))
    if name == 'domain_lookup':
        from .trackers import DomainTracker
        return DomainTracker().track(_target(arguments))
    if name == 'investigate':
        from .investigate import investigate
        pivot = bool(arguments.get('pivot', True))
        return investigate(_target(arguments), pivot=pivot)
    if name == 'url_lookup':
        from .trackers import URLTracker
        return URLTracker().track(_target(arguments))
    if name == 'crypto_lookup':
        from .trackers import CryptoTracker
        return CryptoTracker().track(_target(arguments))
    if name == 'hash_lookup':
        from .trackers import HashTracker
        return HashTracker().track(_target(arguments))
    if name == 'cve_lookup':
        from .trackers import CVETracker
        return CVETracker().track(_target(arguments))
    if name == 'asn_lookup':
        from .trackers import ASNTracker
        return ASNTracker().track(str(arguments.get('target', '')))
    if name == 'risk_report':
        from .correlation import attach_risk
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
        kind = arguments.get('kind')
        tracker_classes = {
            'ip': IPTracker, 'phone': PhoneTracker,
            'username': UsernameTracker, 'email': EmailTracker,
            'domain': DomainTracker, 'url': URLTracker,
            'crypto': CryptoTracker, 'hash': HashTracker,
            'cve': CVETracker, 'asn': ASNTracker,
        }
        if kind not in tracker_classes:
            raise ValueError(f'unknown kind: {kind}')
        result = tracker_classes[kind]().track(_target(arguments))
        attach_risk(str(kind), result)
        return result
    if name == 'correlate':
        from .correlation import build_graph, correlate, history_records
        if arguments.get('all'):
            records = history_records(
                limit=arguments.get('limit') or None)
            return build_graph(records)
        a = arguments.get('a')
        b = arguments.get('b')
        if not a or not b:
            raise ValueError('correlate needs both a and b, or all=true')
        return correlate(str(a), str(b))
    if name == 'timeline':
        from .correlation import build_timeline, history_records
        limit = arguments.get('limit') or 100
        records = history_records(limit=max(int(limit) * 3, 200))
        target = arguments.get('target')
        if target:
            needle = str(target).lower()
            records = [r for r in records
                       if needle in str(r.get('value', '')).lower()]
        return build_timeline(records, cap=int(limit))
    if name == 'threat_intel':
        from .intel import feeds as intel_feeds
        from .intel import tor as intel_tor
        target = _target(arguments)
        return {
            'ip': target,
            'feeds': intel_feeds.check_ip(target),
            'tor_exit': intel_tor.is_tor_exit(target),
            'relay': intel_tor.relay_details(target),
        }
    if name == 'source_health':
        from .health import health
        return {'sources': health.get_health()}
    if name == 'watch_list':
        from .watchlist import watchlist
        return {'entries': [asdict(entry) for entry in watchlist.list()]}
    if name == 'watch_check':
        from .watchlist import watchlist
        identifier = _identifier(arguments.get('identifier'))
        return {'diffs': [asdict(diff) for diff in watchlist.check(identifier)]}
    raise ValueError(f'unknown tool: {name}')


def _success(msg_id: Any, result: Any) -> Dict[str, Any]:
    return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}


def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {'jsonrpc': '2.0', 'id': msg_id,
            'error': {'code': code, 'message': message}}


def handle_request(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Handle a single JSON-RPC message.

    Returns the response dict, or None when the message is a notification
    (which must not be answered).
    """
    if not isinstance(message, dict):
        return _error(None, -32600, 'invalid request')

    msg_id = message.get('id')
    method = message.get('method')
    if not isinstance(method, str):
        return _error(msg_id, -32600, 'invalid request')

    if method.startswith('notifications/'):
        return None

    if method == 'initialize':
        params = message.get('params')
        params = params if isinstance(params, dict) else {}
        requested = params.get('protocolVersion')
        version = requested if isinstance(requested, str) else _PROTOCOL_VERSION
        return _success(msg_id, {
            'protocolVersion': version,
            'capabilities': {'tools': {}},
            'serverInfo': {'name': 'obscuralens', 'version': __version__},
        })

    if method == 'ping':
        return _success(msg_id, {})

    if method == 'tools/list':
        return _success(msg_id, {'tools': TOOLS})

    if method == 'tools/call':
        params = message.get('params')
        if not isinstance(params, dict) or not isinstance(params.get('name'),
                                                           str):
            return _error(msg_id, -32602, 'invalid params')
        arguments = params.get('arguments', {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return _error(msg_id, -32602, 'invalid params')
        try:
            result = call_tool(params['name'], arguments)
            is_error = False
        except Exception as exc:  # never let a tool crash the server loop
            result = {'error': f'{type(exc).__name__}: {exc}'}
            is_error = True
        return _success(msg_id, {
            'content': [{
                'type': 'text',
                'text': json.dumps(result, ensure_ascii=False, default=str),
            }],
            'isError': is_error,
        })

    return _error(msg_id, -32601, 'method not found')


def main(argv: Optional[List[str]] = None) -> int:
    """
    Run the MCP stdio loop.

    Reads one JSON object per line from stdin and writes one JSON response
    per line to stdout (blank lines are ignored). Parse errors are answered
    with a JSON-RPC error whose id is null. EOF ends the loop cleanly.
    """
    stdin = sys.stdin
    stdout = sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = _error(None, -32700, 'parse error')
            print('obscuralens-mcp: parse error on input line', file=sys.stderr)
        else:
            response = handle_request(message)
        if response is None:
            continue
        stdout.write(json.dumps(response, ensure_ascii=False, default=str))
        stdout.write('\n')
        stdout.flush()
    return 0


if __name__ == '__main__':  # pragma: no cover - module entry point
    raise SystemExit(main())
