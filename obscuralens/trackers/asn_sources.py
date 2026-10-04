"""
AS number (BGP / routing) intelligence sources.

Autonomous Systems are the building blocks of inter-domain routing, and two
keyless APIs describe them from complementary angles:

* ``ripestat`` - RIPEstat's ``as-overview`` (holder name, description) and
                 ``announced-prefixes`` (what the AS announces to the world,
                 split v4/v6).
* ``bgpview``  - BGPView's ASN record (name, country, website, contacts) plus
                 its per-ASN prefixes and upstream/downstream peers.

Every provider is queried independently; results are merged field-by-field
so a single flaky source cannot blank out the whole report. Field provenance
is tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import contextlib
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.helpers import fanout_workers
from ..utils.http_client import http
from ..utils.validators import normalize_asn

# Caps keep merged payloads small: large transit ASes announce tens of
# thousands of prefixes and peer with hundreds of neighbours.
_MAX_PREFIXES = 50
_MAX_V4_PREFIXES = 30
_MAX_V6_PREFIXES = 15
_MAX_PEERS = 20
_MAX_DESCRIPTION_CHARS = 300


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _as_number(asn: Any) -> int:
    """
    Coerce 'AS15169', '15169' or 15169 into an int; 0 when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_asn(str(asn))


def _unique(items: List[str]) -> List[str]:
    """Order-preserving de-duplication of a list of strings."""
    return list(dict.fromkeys(items))


def _prefixes_of(entries: Any) -> List[str]:
    """Extract non-empty ``prefix`` values from a prefix entry list."""
    prefixes: List[str] = []
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get('prefix'):
            prefixes.append(entry['prefix'])
    return prefixes


def _peer_labels(entries: Any) -> List[str]:
    """
    Render peer entries as ``'AS<num>'`` plus the peer name when known.

    Example: ``{'asn': 174, 'name': 'Cogent Communications'}`` becomes
    ``'AS174 Cogent Communications'``.
    """
    labels: List[str] = []
    for entry in entries or []:
        if not isinstance(entry, dict) or entry.get('asn') is None:
            continue
        label = f"AS{entry['asn']}"
        if entry.get('name'):
            label = f"{label} {entry['name']}"
        labels.append(label)
    return labels


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _ripestat_overview(num: int) -> Dict[str, Any]:
    """
    RIPEstat ``as-overview`` half: who runs the AS.

    Endpoint: ``GET /data/as-overview/data.json?resource=AS<num>``. The
    holder is the authoritative registry name (e.g. ``'GOOGLE - Google LLC'``);
    ``desc`` is a longer free-text description, capped for report sanity.
    """
    out: Dict[str, Any] = {}

    ok, d, _ = http.get_json(
        f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{num}")
    if not ok or not d:
        return {}

    data = d.get('data') or {}
    if data.get('holder'):
        out['asn_name'] = data['holder']
    if data.get('desc'):
        out['asn_description'] = str(data['desc'])[:_MAX_DESCRIPTION_CHARS]
    if data.get('website'):
        out['asn_website'] = data['website']
    return out


def _ripestat_prefixes(num: int) -> Dict[str, Any]:
    """
    RIPEstat ``announced-prefixes`` half: the AS routing footprint.

    Endpoint: ``GET /data/announced-prefixes/data.json?resource=AS<num>``.
    Prefixes containing ``':'`` are IPv6, everything else IPv4; counts are
    totals (not capped) while the stored list is truncated for size.
    """
    out: Dict[str, Any] = {}

    ok, d, _ = http.get_json(
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{num}")
    if not ok or not d:
        return {}

    data = d.get('data') or {}
    prefixes = _prefixes_of(data.get('prefixes'))
    if not prefixes:
        return {}

    out['announced_prefixes'] = prefixes[:_MAX_PREFIXES]
    out['announced_prefix_count'] = len(prefixes)
    out['announced_v4_count'] = sum(1 for p in prefixes if ':' not in p)
    out['announced_v6_count'] = sum(1 for p in prefixes if ':' in p)
    return out


def _ripestat(asn: Any) -> Dict[str, Any]:
    """
    RIPEstat (keyless): AS overview merged with announced prefixes.

    Two GETs are combined so one reader failure means one source failure,
    not two: ``as-overview`` contributes the holder and description,
    ``announced-prefixes`` contributes the routing table footprint. Each
    half degrades independently - a failed prefixes call still returns the
    holder name.
    """
    num = _as_number(asn)
    if not num:
        return {}

    out = _ripestat_overview(num)
    out.update(_ripestat_prefixes(num))
    return out


def _bgpview_record(num: int) -> Dict[str, Any]:
    """
    BGPView ASN record third: identity fields.

    Endpoint: ``GET /asn/<num>``. Contributes name, description, country
    code, website and the contact e-mail when published.
    """
    out: Dict[str, Any] = {}

    ok, d, _ = http.get_json(f"https://api.bgpview.io/asn/{num}")
    if not ok or not d:
        return {}

    data = d.get('data') or {}
    if data.get('name'):
        out['bgpview_name'] = data['name']
    description = data.get('description_short') or data.get('description_long')
    if description:
        out['bgpview_description'] = str(description)[:_MAX_DESCRIPTION_CHARS]
    if data.get('country_code'):
        out['asn_country'] = data['country_code']
    if data.get('website'):
        out['asn_website'] = data['website']
    if data.get('email_address'):
        out['asn_email'] = data['email_address']
    return out


def _bgpview_prefixes(num: int) -> Dict[str, Any]:
    """
    BGPView prefixes third: the v4/v6 separated routing footprint.

    Endpoint: ``GET /asn/<num>/prefixes``. Each family gets its own list
    (30 v4 / 15 v6 entries kept) plus an uncapped total count.
    """
    out: Dict[str, Any] = {}

    ok, d, _ = http.get_json(f"https://api.bgpview.io/asn/{num}/prefixes")
    if not ok or not d:
        return {}

    data = d.get('data') or {}
    v4 = _prefixes_of(data.get('ipv4_prefixes'))
    v6 = _prefixes_of(data.get('ipv6_prefixes'))
    if v4:
        out['bgpview_ipv4_prefixes'] = v4[:_MAX_V4_PREFIXES]
        out['ipv4_prefix_count'] = len(v4)
    if v6:
        out['bgpview_ipv6_prefixes'] = v6[:_MAX_V6_PREFIXES]
        out['ipv6_prefix_count'] = len(v6)
    return out


def _bgpview_peers(num: int) -> Dict[str, Any]:
    """
    BGPView peers third: the neighbour graph.

    Endpoint: ``GET /asn/<num>/peers``. v4 and v6 peers are combined and
    de-duplicated (a neighbour present on both families is one peer), then
    rendered as ``'AS<num> <name>'`` labels, capped at 20.
    """
    out: Dict[str, Any] = {}

    ok, d, _ = http.get_json(f"https://api.bgpview.io/asn/{num}/peers")
    if not ok or not d:
        return {}

    data = d.get('data') or {}
    peers = _unique(_peer_labels(data.get('ipv4_peers'))
                    + _peer_labels(data.get('ipv6_peers')))
    if not peers:
        return {}

    out['peers'] = peers[:_MAX_PEERS]
    out['peer_count'] = len(peers)
    return out


def _bgpview(asn: Any) -> Dict[str, Any]:
    """
    BGPView (keyless): ASN record, prefixes and peers merged into one dict.

    Three GETs are combined: the ASN record contributes identity fields
    (name, country, website, email), the prefixes call contributes the
    separated v4/v6 routing footprint, and the peers call contributes the
    neighbour graph. Each third degrades independently.
    """
    num = _as_number(asn)
    if not num:
        return {}

    out = _bgpview_record(num)
    out.update(_bgpview_prefixes(num))
    out.update(_bgpview_peers(num))
    return out


# ---------------------------------------------------------------------------
# v6.1 additions: CAIDA AS-Rank (global ranking and customer cone) and
# PeeringDB (the peering ecosystem's self-published record). Both were
# probed live before shipping - AS15169 answers rich records, unknown ASNs
# answer clean negatives.
# ---------------------------------------------------------------------------

def _asrank(asn: Any) -> Dict[str, Any]:
    """
    CAIDA AS-Rank (keyless, v6.1): global connectivity ranking.

    Endpoint: ``https://api.asrank.caida.org/v2/restful/asns/{asn}``.
    AS-Rank scores every AS on the planet by its position in the inferred
    customer-cone hierarchy - the closest thing routing research has to an
    importance score. ``rank`` 1 is the most transit-heavy AS; ``source``
    says which RIR registered it; ``cone`` counts the ASes reachable
    through customers. Unknown ASNs answer ``{"data": {"asn": null}}``,
    which maps to ``{}``.

    Fields: ``asrank_rank``, ``asrank_source`` (RIR), ``asrank_cone``,
    ``asrank_ixp`` (bool), ``asrank_seen`` (bool).
    """
    num = _as_number(asn)
    if not num:
        return {}

    ok, d, _ = http.get_json(
        f"https://api.asrank.caida.org/v2/restful/asns/{num}", cache_ttl=86400)
    record = (d.get('data') or {}).get('asn') if ok and isinstance(d, dict) else None
    if not isinstance(record, dict):
        return {}

    out: Dict[str, Any] = {}
    if record.get('rank') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['asrank_rank'] = int(record.get('rank'))
    if record.get('source'):
        out['asrank_source'] = record.get('source')
    if record.get('asnName'):
        out['asrank_name'] = record.get('asnName')
    cone = record.get('cone')
    if isinstance(cone, dict) and cone.get('number') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['asrank_cone'] = int(cone.get('number'))
    if record.get('ixp') is not None:
        out['asrank_ixp'] = bool(record.get('ixp'))
    if record.get('seen') is not None:
        out['asrank_seen'] = bool(record.get('seen'))
    return out


def _peeringdb(asn: Any) -> Dict[str, Any]:
    """
    PeeringDB (keyless, v6.1): the network's self-published peering record.

    Endpoint: ``https://www.peeringdb.com/api/net?asn={asn}``. Operators
    maintain their own entries - network name, traffic volume, service
    level, IX and facility presence, policy notes - so this is the one
    source that reports what the AS *says about itself*. Unknown ASNs
    answer HTTP 404 with an error body, which maps to ``{}``.

    Fields: ``pdb_name``, ``pdb_name_long``, ``pdb_website``,
    ``pdb_traffic_volume``, ``pdb_scope``, ``pdb_ix_count``,
    ``pdb_policy_general``, ``pdb_info_type``.
    """
    num = _as_number(asn)
    if not num:
        return {}

    ok, d, _ = http.get_json(
        f"https://www.peeringdb.com/api/net?asn={num}", cache_ttl=86400)
    if not ok or not isinstance(d, dict):
        return {}
    entries = d.get('data')
    if not isinstance(entries, list) or not entries:
        return {}
    record = entries[0]
    if not isinstance(record, dict):
        return {}

    out: Dict[str, Any] = {}
    if record.get('name'):
        out['pdb_name'] = record.get('name')
    if record.get('name_long'):
        out['pdb_name_long'] = record.get('name_long')
    if record.get('website'):
        out['pdb_website'] = record.get('website')
    if record.get('info_traffic'):
        out['pdb_traffic_volume'] = record.get('info_traffic')
    if record.get('info_type'):
        out['pdb_info_type'] = record.get('info_type')
    if record.get('policy_general'):
        out['pdb_policy_general'] = record.get('policy_general')
    if record.get('ix_count') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['pdb_ix_count'] = int(record.get('ix_count'))
    if record.get('netixlan_updated'):
        out['pdb_last_updated'] = record.get('netixlan_updated')
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'ripestat': _ripestat,
    'bgpview': _bgpview,
    'asrank': _asrank,
    'peeringdb': _peeringdb,
}

# AS number intelligence is fully keyless today; the registry stays here so
# future keyed sources (e.g. paid BGP feeds) slot in without touching the
# tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'ripestat': 'RIPEstat AS overview and announced prefixes (keyless)',
    'bgpview': 'BGPView AS record, prefixes and peers (keyless)',
    'asrank': 'CAIDA AS-Rank global ranking, RIR source and customer-cone '
              'size (keyless; v6.1)',
    'peeringdb': 'Operator-maintained peering record: name, traffic volume, '
                 'IX presence, policy (keyless; v6.1)',
}


def _keep(value: Any) -> bool:
    # An AS announcing zero v6 prefixes (announced_v6_count == 0) is a real
    # answer, so only None / '' / [] / {} count as "no data".
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(asn_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable AS number source in parallel and merge the results.

    Args:
        asn_value: AS number as ``'AS15169'``, ``'15169'`` or ``15169``
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'asn' and
                    'asn_display'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as an AS number.
    """
    keys = keys or {}
    num = _as_number(asn_value)
    if not num:
        raise ValueError(f"invalid AS number: {asn_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(num))

    for name, fn in _plugin_sources('asn').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(num))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=fanout_workers(len(tasks))) as ex:
            future_map = {ex.submit(fn): name for name, fn in tasks.items()}
            for future in futures.as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result() or {}
                    results[name] = data
                    status[name] = {'ok': bool(data), 'error': '' if data else 'no data'}
                except Exception as e:  # a broken source must not kill the scan
                    results[name] = {}
                    status[name] = {'ok': False, 'error': type(e).__name__}

    health.record_batch('asn', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the registry's RIPE NCC numbers beat third-party mirrors on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # both the bare number and the conventional display form.
    merged['asn'] = num
    merged['asn_display'] = f"AS{num}"

    return {'fields': merged, 'sources': status, 'provenance': provenance}
