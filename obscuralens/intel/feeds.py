"""
Threat-intel blocklist feeds: download, parse, cache and IP membership.

Eight keyless feeds are supported (three joined in v5.2):

* **spamhaus_drop** — Spamhaus DROP (hijacked / rogue ranges), lines like
  ``1.2.3.0/24 ; SBL12345 ; description`` with ``;``/``#`` comments.
* **feodo** — abuse.ch Feodo-Tracker botnet C2 IP blocklist, one bare IP
  per line (treated as a /32 network), ``#`` comments.
* **firehol_level1** — FireHOL level 1 aggregate netset, one CIDR per
  line, ``#`` comments.
* **urlhaus** — abuse.ch URLhaus malware URL dump
  (``https://urlhaus.abuse.ch/downloads/text/``), one URL per line; the
  host of every URL is extracted and kept when it is a literal IP.
* **threatfox** — abuse.ch ThreatFox IOC dump, CSV lines of
  ``"first_seen", "id", "ioc_value", "ioc_type", ...``; rows whose
  ``ioc_type`` starts with ``ip`` contribute the host part of
  ``ioc_value`` (``1.2.3.4:8080`` → ``1.2.3.4``). The authenticated JSON
  API (``POST /api/v1/`` with ``{"query": "get_iocs"}``) now demands an
  abuse.ch Auth-Key, so the keyless recent CSV export is used instead -
  same data, no account, and plain GET transport.
* **cins_army** (v5.2) — CINS Army blocklist (cinsscore.com), one bare IP
  per line; a curated score-based feed of currently active attackers.
* **blocklist_de** (v5.2) — blocklist.de aggregated abuse list
  (``lists/all.txt``): IPs that attacked mail/HTTP/SSH honeypots in the
  last 48 hours, one bare IP per line.
* **openphish** (v5.2) — OpenPhish community phishing feed, one URL per
  line; the host is extracted exactly like urlhaus and kept when it is a
  literal IP (the free feed is small but refreshed hourly).

Every feed body is parsed into ``ipaddress`` network objects, so
membership is an exact subnet match instead of a string comparison, and
cached in-process with its fetch timestamp, refreshed after
``app.feed_cache_ttl`` seconds. Parsing is capped at
``_MAX_FEED_ENTRIES`` networks so monster dumps (URLhaus ships ~56k lines)
never blow memory - the cap keeps the newest entries because the dumps are
ordered most-recent-first. Transport failures keep the last known
networks and surface through ``feeds_status``. Nothing in this module
ever raises.
"""

import csv
import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..config import config
from ..utils.http_client import http
from .tor import _relay_rows, is_tor_exit, relay_details

logger = logging.getLogger(__name__)

# name -> download URL (insertion order is the report/display order).
FEED_URLS: Dict[str, str] = {
    'spamhaus_drop': 'https://www.spamhaus.org/drop/drop.txt',
    'feodo': 'https://raw.githubusercontent.com/abusech/Feodo-Tracker/'
             'main/feodoc.ipblocklist.txt',
    'firehol_level1': 'https://raw.githubusercontent.com/firehol/'
                      'blocklist-ipsets/master/firehol_level1.netset',
    'urlhaus': 'https://urlhaus.abuse.ch/downloads/text/',
    'threatfox': 'https://threatfox.abuse.ch/export/csv/recent/',
    # v5.2 additions -----------------------------------------------------
    'cins_army': 'https://cinsscore.com/list/ci-badguys.txt',
    'blocklist_de': 'https://lists.blocklist.de/lists/all.txt',
    'openphish': 'https://openphish.com/feed.txt',
}

# Human labels used by the report rows.
FEED_LABELS: Dict[str, str] = {
    'spamhaus_drop': 'Spamhaus DROP',
    'feodo': 'Feodo Tracker',
    'firehol_level1': 'FireHOL Level 1',
    'urlhaus': 'abuse.ch URLhaus',
    'threatfox': 'abuse.ch ThreatFox',
    'cins_army': 'CINS Army',
    'blocklist_de': 'blocklist.de',
    'openphish': 'OpenPhish',
}

# Comment prefixes shared by every feed format.
_COMMENT_PREFIXES = ('#', ';')

# What separates an entry from its trailing annotation. Spamhaus annotates
# after ';', the GitHub lists after '#'.
_FEED_SEPARATOR: Dict[str, str] = {
    'spamhaus_drop': ';',
    'feodo': '#',
    'firehol_level1': '#',
}

# Hard cap on parsed networks per feed: URLhaus alone ships ~56k URLs, so
# only the first 20k (newest, the dumps are most-recent-first) are kept.
_MAX_FEED_ENTRIES = 20_000


# ---------------------------------------------------------------------------
# Per-line tokenizers for feeds whose lines are not bare networks (v5.0).
# A tokenizer turns one non-comment line into a candidate network token
# ('' means skip); _parse_feed still validates it with ipaddress and
# de-duplicates, so junk simply never reaches the network list.
# ---------------------------------------------------------------------------

def _urlhaus_host(line: str) -> str:
    """
    Extract the host from one URLhaus malware-URL line.

    Lines look like ``http://61.52.219.186:56983/i``. ``urlparse`` yields
    the host (IP or domain, port stripped); domains are rejected later by
    ``_network_from_token`` because they are not IP literals.
    """
    try:
        return urlparse(line).hostname or ''
    except ValueError:
        return ''


def _threatfox_field(value: str) -> str:
    """Strip the padding the ThreatFox export puts around CSV fields."""
    return value.strip().strip('"').strip()


def _threatfox_host(line: str) -> str:
    """
    Extract the IP host from one ThreatFox CSV export line.

    Columns: ``"first_seen", "id", "ioc_value", "ioc_type", ...``. Only
    rows whose ``ioc_type`` starts with ``ip`` (``ip:port`` etc.) are kept;
    the host part of ``ioc_value`` is returned without the port
    (``1.2.3.4:8000`` → ``1.2.3.4``, ``[2001:db8::1]:443`` → the bare
    IPv6). Hashes, domains and URLs score an empty token.
    """
    try:
        row = next(csv.reader([line]))
    except (csv.Error, StopIteration):
        return ''
    if len(row) < 4:
        return ''
    ioc_value = _threatfox_field(row[2])
    ioc_type = _threatfox_field(row[3]).lower()
    if not ioc_value or not ioc_type.startswith('ip'):
        return ''
    if ioc_value.startswith('['):  # [ipv6]:port
        end = ioc_value.find(']')
        return ioc_value[1:end] if end > 0 else ''
    host = ioc_value.split('/')[0]
    return host.rsplit(':', 1)[0] if host.count(':') == 1 else host


def _openphish_host(line: str) -> str:
    """
    Extract the host from one OpenPhish feed URL line (v5.2).

    Lines look like ``https://phish.example/login``; ``urlparse`` yields the
    host (IP or domain, port stripped) and ``_network_from_token`` keeps
    only literal IPs - domains are dropped exactly like urlhaus does.
    """
    try:
        return urlparse(line).hostname or ''
    except ValueError:
        return ''


#: name -> tokenizer for non-bare-network feed lines (absent = plain split).
_FEED_TOKENIZERS: Dict[str, Any] = {
    'urlhaus': _urlhaus_host,
    'threatfox': _threatfox_host,
    'openphish': _openphish_host,
}

# In-module cache: name -> (fetch timestamp, [ip_network, ...]).
_feed_cache: Dict[str, Tuple[float, List[Any]]] = {}
_feed_errors: Dict[str, str] = {}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _network_from_token(token: str) -> Optional[Any]:
    """
    Parse one feed token into an ``ipaddress`` network.

    Bare addresses become /32 (IPv4) or /128 (IPv6) networks; anything the
    ``ipaddress`` module rejects returns None. Host bits inside a CIDR are
    masked off (``strict=False``) so slightly sloppy feeds still parse.
    """
    token = (token or '').strip()
    if not token:
        return None
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def _parse_feed(text: str, name: str) -> List[Any]:
    """Parse a feed body into a de-duplicated list of networks."""
    separator = _FEED_SEPARATOR.get(name, '#')
    tokenize = _FEED_TOKENIZERS.get(name)
    networks: List[Any] = []
    seen: Set = set()
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue
        # Tokenized feeds (urlhaus/threatfox) carry URLs or CSV rows; the
        # plain feeds are "network [separator] annotation".
        token = tokenize(line) if tokenize is not None \
            else line.split(separator)[0].strip()
        network = _network_from_token(token)
        if network is not None and network not in seen:
            seen.add(network)
            networks.append(network)
            if len(networks) >= _MAX_FEED_ENTRIES:
                break  # newest-first dumps: keep the freshest entries
    return networks


# ---------------------------------------------------------------------------
# Download + cache
# ---------------------------------------------------------------------------

def _load_feed(name: str, force: bool = False) -> List[Any]:
    """
    Return the networks of one feed, downloading it when needed.

    Fresh in-memory data is served without any HTTP activity; ``force``
    re-downloads. A transport failure keeps the last known networks and is
    recorded for ``feeds_status``. Never raises.
    """
    url = FEED_URLS.get(name)
    if url is None:
        return []
    cached = _feed_cache.get(name)
    if not force and cached is not None:
        fetched_at, networks = cached
        if (time.time() - fetched_at) < config.app_config.feed_cache_ttl:
            return list(networks)
    try:
        ok, text, error = http.get_text(
            url, use_cache=True, cache_ttl=config.app_config.feed_cache_ttl)
    except Exception as exc:  # http client is defensive; belt and braces
        ok, text, error = False, '', str(exc)
    if ok:
        networks = _parse_feed(text, name)
        _feed_cache[name] = (time.time(), networks)
        _feed_errors.pop(name, None)
    else:
        _feed_errors[name] = error or 'fetch failed'
        networks = cached[1] if cached is not None else []
    return list(networks)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_ip(ip: str) -> Dict[str, Any]:
    """
    Check one address against the Tor exit list and every blocklist feed.

    Returns ``{'tor', <one key per feed>, 'listed_count', 'relay'}`` where
    ``listed_count`` counts how many lists contain the address (the eight
    blocklist feeds plus the Tor exit list). Invalid input gives all-False
    verdicts, and ``app.feeds_enabled`` switched off gives exactly
    ``{'disabled': True}``. Never raises.
    """
    if not config.app_config.feeds_enabled:
        return {'disabled': True}
    empty = dict.fromkeys(FEED_URLS, False)
    empty.update({
        'tor': False,
        'listed_count': 0,
        'relay': {'is_relay': False, 'error': 'invalid ip address'},
    })
    try:
        ip_obj = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return dict(empty)
    try:
        verdict: Dict[str, Any] = {
            'tor': is_tor_exit(ip_obj.compressed),
        }
        for name in FEED_URLS:
            networks = _load_feed(name)
            verdict[name] = any(ip_obj in net for net in networks)
        verdict['listed_count'] = sum(
            1 for value in verdict.values() if value is True)
        verdict['relay'] = relay_details(ip_obj.compressed)
        return verdict
    except Exception as exc:  # pragma: no cover - helpers never raise
        logger.warning('intel check failed for %s: %s', ip, exc)
        empty['relay'] = {'is_relay': False, 'error': str(exc) or 'check failed'}
        return empty


def feeds_status() -> List[Dict[str, Any]]:
    """
    Snapshot of every feed cache: ``[{'name', 'url', 'entries', 'cached',
    'error'}]`` — purely a read of the current cache state, no fetching.
    """
    status: List[Dict[str, Any]] = []
    for name, url in FEED_URLS.items():
        cached = _feed_cache.get(name)
        status.append({
            'name': name,
            'url': url,
            'entries': len(cached[1]) if cached is not None else 0,
            'cached': cached is not None,
            'error': _feed_errors.get(name, ''),
        })
    return status


def feeds_sections() -> List[List[str]]:
    """
    Report table rows ``[Feed | Entries | Status]`` for every feed,
    reflecting the current cache state without fetching anything.
    """
    rows: List[List[str]] = []
    for item in feeds_status():
        if item['error']:
            state = f"error: {item['error']}"
        elif item['cached']:
            state = 'cached'
        else:
            state = 'not loaded'
        rows.append([FEED_LABELS.get(item['name'], item['name']),
                     str(item['entries']), state])
    return rows


def intel_sections(ip: str) -> List[List[str]]:
    """
    Combined Tor + blocklist rows ``[label, value]`` for embedding into IP
    reports: exit/relay verdicts followed by per-feed membership and the
    total number of lists the address appears on. Never raises.
    """
    try:
        verdict = check_ip(ip)
        if verdict.get('disabled'):
            return [['Threat intel', 'disabled']]
        rows: List[List[str]] = [
            ['Tor exit node', 'Yes' if verdict.get('tor') else 'No'],
        ]
        rows.extend(_relay_rows(verdict.get('relay') or {}))
        for name in FEED_URLS:
            listed = bool(verdict.get(name))
            rows.append([FEED_LABELS.get(name, name),
                         'listed' if listed else 'clear'])
        rows.append(['Feeds listed', str(verdict.get('listed_count', 0))])
        return rows
    except Exception as exc:  # pragma: no cover - check_ip never raises
        logger.warning('intel sections failed for %s: %s', ip, exc)
        return [['Threat intel', 'unavailable']]


# ---------------------------------------------------------------------------
# Test hook
# ---------------------------------------------------------------------------

def _reset_cache() -> None:
    """Drop all feed caches and error states (used by the test suite)."""
    _feed_cache.clear()
    _feed_errors.clear()
