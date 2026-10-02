"""
Tor network intelligence: exit-node membership and relay details.

Two keyless Tor Project services are used:

* ``torbulkexitlist`` — a plain-text list of the addresses of every Tor
  exit node right now. It is downloaded through the shared HTTP client and
  cached in-process with its fetch timestamp, refreshed after
  ``app.feed_cache_ttl`` seconds (6h by default).
* Onionoo — the Tor network document API, queried per address for relay
  metadata (nickname, fingerprint, flags, first/last seen, bandwidth).

Everything here is defensive: a failed download keeps the last known
exit-node set, malformed payloads collapse to ``{'is_relay': False}``,
and no public function ever raises.
"""

import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional, Set

from ..config import config
from ..utils.http_client import http

logger = logging.getLogger(__name__)

EXIT_LIST_URL = 'https://check.torproject.org/torbulkexitlist'
ONIONOO_URL = 'https://onionoo.torproject.org/details'

# In-module cache: parsed exit addresses + when they were last fetched.
_exit_nodes: Set[str] = set()
_exit_fetched_at: Optional[float] = None


# ---------------------------------------------------------------------------
# Exit list download + parsing
# ---------------------------------------------------------------------------

def _parse_exit_nodes(text: str) -> Set[str]:
    """
    Extract validated IP addresses from bulk exit-list text.

    Blank lines, ``#``/``;`` comment banners and anything that is not a
    literal IPv4/IPv6 address are dropped; addresses are normalised to
    their compressed form so later membership checks are exact.
    """
    nodes: Set[str] = set()
    for raw_line in (text or '').splitlines():
        token = raw_line.strip()
        if not token or token.startswith('#') or token.startswith(';'):
            continue
        try:
            nodes.add(ipaddress.ip_address(token).compressed)
        except ValueError:
            continue  # banner / garbage line
    return nodes


def _cache_is_fresh(fetched_at: Optional[float]) -> bool:
    """True when a cached fetch is younger than the configured feed TTL."""
    if fetched_at is None:
        return False
    return (time.time() - fetched_at) < config.app_config.feed_cache_ttl


def load_exit_nodes(force: bool = False) -> Set[str]:
    """
    Return the current set of Tor exit node addresses.

    The parsed list is cached in memory together with its fetch timestamp;
    a call within ``app.feed_cache_ttl`` seconds is served without any HTTP
    activity. ``force=True`` bypasses the cache and re-downloads. On
    failure the last known set (possibly empty) is returned — never an
    exception.
    """
    global _exit_fetched_at
    if not force and _cache_is_fresh(_exit_fetched_at):
        return set(_exit_nodes)
    try:
        ok, text, _ = http.get_text(
            EXIT_LIST_URL, use_cache=True,
            cache_ttl=config.app_config.feed_cache_ttl)
        if ok:
            _exit_nodes.clear()
            _exit_nodes.update(_parse_exit_nodes(text))
            _exit_fetched_at = time.time()
    except Exception as exc:  # http client is defensive; belt and braces
        logger.warning('Tor exit list fetch failed: %s', exc)
    return set(_exit_nodes)


def is_tor_exit(ip: str) -> bool:
    """
    Whether ``ip`` is currently listed as a Tor exit node.

    The address is normalised through ``ipaddress`` first, so compressed
    and expanded IPv6 forms both match; invalid input is simply ``False``
    and never raises.
    """
    try:
        normalized = ipaddress.ip_address(str(ip).strip()).compressed
    except (ValueError, TypeError):
        return False
    try:
        return normalized in load_exit_nodes()
    except Exception:  # pragma: no cover - load_exit_nodes never raises
        return False


# ---------------------------------------------------------------------------
# Onionoo relay details
# ---------------------------------------------------------------------------

def relay_details(ip: str) -> Dict[str, Any]:
    """
    Look up relay metadata for one address via Onionoo.

    Returns ``{'is_relay': True, 'nickname', 'fingerprint', 'flags',
    'first_seen', 'last_seen', 'bandwidth', 'or_addresses' (max 5)}`` when
    the address belongs to a relay, ``{'is_relay': False}`` when it does
    not, and ``{'is_relay': False, 'error': ...}`` when the lookup failed
    or the address is invalid. Never raises.
    """
    try:
        ip_obj = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return {'is_relay': False, 'error': 'invalid ip address'}
    try:
        ok, data, error = http.get_json(
            f'{ONIONOO_URL}?lookup={ip_obj.compressed}',
            use_cache=True, cache_ttl=config.app_config.feed_cache_ttl)
        if not ok or not isinstance(data, dict):
            return {'is_relay': False,
                    'error': error or 'unexpected response format'}
        relays = data.get('relays')
        if not isinstance(relays, list) or not relays:
            return {'is_relay': False}
        relay = relays[0]
        if not isinstance(relay, dict):
            return {'is_relay': False}
        flags = relay.get('flags')
        flags = [str(flag) for flag in flags if flag] if isinstance(
            flags, list) else []
        or_addresses = relay.get('or_addresses')
        or_addresses = [str(addr) for addr in or_addresses[:5]] if isinstance(
            or_addresses, list) else []
        return {
            'is_relay': True,
            'nickname': relay.get('nickname') or '',
            'fingerprint': relay.get('fingerprint') or '',
            'flags': flags,
            'first_seen': relay.get('first_seen') or '',
            'last_seen': relay.get('last_seen') or '',
            'bandwidth': relay.get('advertised_bandwidth'),
            'or_addresses': or_addresses,
        }
    except Exception as exc:  # pragma: no cover - onionoo is defensive too
        logger.warning('Onionoo relay lookup failed for %s: %s', ip, exc)
        return {'is_relay': False, 'error': str(exc) or 'lookup failed'}


# ---------------------------------------------------------------------------
# Report rows
# ---------------------------------------------------------------------------

def _fmt_bandwidth(value: Any) -> str:
    """Human-readable B/s figure for ``advertised_bandwidth``."""
    try:
        bits = int(value)
    except (TypeError, ValueError):
        return 'unknown'
    if bits >= 1_000_000:
        return f'{bits / 1_000_000:.1f} MB/s'
    if bits >= 1_000:
        return f'{bits / 1_000:.1f} KB/s'
    return f'{bits} B/s'


def _relay_rows(relay: Dict[str, Any]) -> List[List[str]]:
    """Report rows [label, value] describing one relay_details() result."""
    if not isinstance(relay, dict):
        return []
    if not relay.get('is_relay'):
        error = relay.get('error')
        if error:
            return [['Relay lookup', f'failed: {error}']]
        return []
    rows = [
        ['Tor relay nickname', str(relay.get('nickname') or 'unknown')],
        ['Relay fingerprint', str(relay.get('fingerprint') or 'unknown')],
        ['Relay flags', ', '.join(str(f) for f in relay.get('flags') or [])
         or 'none'],
        ['Relay first seen', str(relay.get('first_seen') or 'unknown')],
        ['Relay last seen', str(relay.get('last_seen') or 'unknown')],
        ['Relay bandwidth', _fmt_bandwidth(relay.get('bandwidth'))],
    ]
    or_addresses = relay.get('or_addresses') or []
    rows.append(['Relay OR addresses',
                 ', '.join(str(a) for a in or_addresses) or 'none'])
    return rows


def tor_sections(ip: str) -> List[List[str]]:
    """
    Report rows [label, value] combining exit-node membership with Onionoo
    relay details — ready for embedding into IP reports / CLI output.
    """
    try:
        rows = [['Tor exit node', 'Yes' if is_tor_exit(ip) else 'No']]
        rows.extend(_relay_rows(relay_details(ip)))
        return rows
    except Exception as exc:  # pragma: no cover - helpers never raise
        logger.warning('tor sections failed for %s: %s', ip, exc)
        return [['Tor exit node', 'unavailable']]


# ---------------------------------------------------------------------------
# Test hook
# ---------------------------------------------------------------------------

def _reset_cache() -> None:
    """Drop the in-module exit-list cache (used by the test suite)."""
    global _exit_fetched_at
    _exit_nodes.clear()
    _exit_fetched_at = None
