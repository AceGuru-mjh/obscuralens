"""
Cross-target entity correlation engine (v4.0).

Builds one entity graph across every stored lookup so shared infrastructure
between otherwise unrelated targets becomes visible: the same IP resolved by
two domains, the same registrar, the same breach name, the same hosting AS.

Three layers:

* :func:`extract_entities` derives (type, value) pairs from any tracker
  payload shape. Every field access is defensive -- payloads may be any
  shape (or garbage) and extraction never raises.
* :class:`EntityGraph` accumulates entities/links with de-duplication,
  reusing the ``investigate._Graph`` pattern across payloads.
* :func:`build_graph` turns history records into a graph plus connected
  components ("clusters") and degree statistics, and :func:`correlate`
  answers "are these two targets connected?" with the entities they share.

Entity/link format matches :mod:`obscuralens.investigate` exactly:
entities ``[{id, type, value, role, label}]``, links ``[{from, to, label}]``.
"""

import ipaddress
import json
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from ..config import config
from ..database import db

__all__ = [
    'KINDS', 'EntityGraph', 'build_graph', 'correlate',
    'correlation_sections', 'extract_entities', 'history_records',
]

#: Lookup kinds the engine can extract entities from.
KINDS = ('ip', 'domain', 'email', 'username', 'crypto', 'hash', 'url', 'cve', 'asn')

#: Entity types whose values keep their case (URLs and profile links).
_CASE_SENSITIVE_TYPES = frozenset({'url', 'profile'})

#: Caps for noisy extraction lists (mirrors investigate/report caps).
_BREACH_CAP = 10
_CPE_CAP = 10
_PREFIX_CAP = 20

_AS_NUMBER = re.compile(r'^\s*(?:as)?(\d+)\s*$', re.IGNORECASE)
_PEER_ASN = re.compile(r'\bas\d+\b', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Payload helpers (payloads may be any shape; nothing here may raise)
# ---------------------------------------------------------------------------

def _info_of(payload: Any) -> Dict[str, Any]:
    """The field mapping of a tracker payload (``info`` when present)."""
    if not isinstance(payload, dict):
        return {}
    info = payload.get('info')
    if isinstance(info, dict):
        return info
    return payload


def _text(value: Any) -> str:
    """String form of a scalar value ('' for containers/None/bools)."""
    if value is None or isinstance(value, (bool, dict, list, tuple, set)):
        return ''
    return str(value).strip()


def _list(value: Any) -> List[Any]:
    """List form of a value (only real sequences qualify)."""
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item is not None]
    return []


def _dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """First-occurrence-wins de-duplication on (type, lowercased value)."""
    seen: Set[Tuple[str, str]] = set()
    unique: List[Dict[str, Any]] = []
    for item in items:
        key = (item['type'], str(item['value']).strip().lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _entity(entity_type: str, value: Any, relation: str,
            label: str = '') -> Dict[str, Any]:
    """One extracted sub-entity: {'type', 'value', 'label', 'relation'}."""
    return {'type': entity_type, 'value': value,
            'label': label or str(value), 'relation': relation}


def _url_host(url: Any) -> str:
    """Hostname of a URL string ('' when missing or unparseable)."""
    try:
        host = urlsplit(str(url or '')).hostname
    except (ValueError, TypeError):
        return ''
    return (host or '').strip().lower()


def _looks_like_ip(host: str) -> bool:
    """Whether a hostname string is an IP literal."""
    try:
        ipaddress.ip_address(host)
    except (ValueError, TypeError):
        return False
    return True


def _asn_value(raw: Any) -> str:
    """Canonical ``AS<n>`` from 15169 / '15169' / 'AS15169' / {'asn': 15169}."""
    if isinstance(raw, dict):
        raw = raw.get('asn')
    if isinstance(raw, bool) or raw is None:
        return ''
    match = _AS_NUMBER.match(str(raw))
    if not match:
        return ''
    return f"AS{match.group(1)}"


def _peer_asn(peer: Any) -> str:
    """``AS<n>`` from a peer entry ('AS15169 Google LLC' or {'asn': 15169})."""
    if isinstance(peer, dict):
        return _asn_value(peer.get('asn'))
    match = _PEER_ASN.search(_text(peer))
    if match:
        return match.group(0).upper()
    return ''


# ---------------------------------------------------------------------------
# Per-kind extractors
# ---------------------------------------------------------------------------

def _ip_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    ptr = _text(info.get('reverse_dns'))
    if ptr:
        items.append(_entity('hostname', ptr, 'ptr'))
    for host in _list(info.get('hostnames')):
        items.append(_entity('hostname', host, 'hostname'))

    asn = _asn_value(info.get('asn'))
    if asn:
        items.append(_entity('asn', asn, 'announced_by'))

    for field in ('org', 'rdap_org'):
        org = _text(info.get(field))
        if org:
            items.append(_entity('organisation', org, 'operated_by'))

    prefix = _text(info.get('prefix'))
    if prefix:
        items.append(_entity('prefix', prefix, 'in_prefix'))

    domain = _text(info.get('domain'))
    if domain:
        items.append(_entity('domain', domain, 'network_domain'))

    # Ports are deliberately NOT extracted: they are per-service noise, not
    # shared infrastructure, and would flood every graph.
    return _dedupe(items)


def _domain_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    for field, relation in (('a_records', 'a_record'), ('aaaa_records', 'aaaa_record')):
        for value in _list(info.get(field)):
            items.append(_entity('ip', value, relation))
    for value in _list(info.get('urlscan_ips')):
        items.append(_entity('ip', value, 'observed_ip'))
    for value in _list(info.get('ns_records')):
        items.append(_entity('nameserver', value, 'nameserver'))
    for value in _list(info.get('mx_records')):
        items.append(_entity('mx', value, 'mx'))
    for value in _list(info.get('ct_subdomains')):
        items.append(_entity('subdomain', value, 'subdomain'))

    registrar = _text(info.get('registrar'))
    if registrar:
        items.append(_entity('registrar', registrar, 'registrar'))

    return _dedupe(items)


def _email_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    domain = _text(info.get('domain'))
    if domain:
        items.append(_entity('domain', domain, 'email_domain'))

    for breach in _list(info.get('hibp_breaches'))[:_BREACH_CAP]:
        if isinstance(breach, dict):
            name = _text(breach.get('name'))
            if name:
                items.append(_entity('breach', name, 'exposed_in'))

    github = _text(info.get('github_username'))
    if github:
        items.append(_entity('username', github, 'github_account'))

    # gravatar is a per-address avatar fact, not shared infrastructure.
    return _dedupe(items)


def _username_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    for record in _list(info.get('results')):
        if not isinstance(record, dict) or record.get('status') != 'found':
            continue
        url = _text(record.get('url'))
        if not url:
            continue
        platform = _text(record.get('platform'))
        items.append(_entity('profile', url, 'profile_on',
                             label=platform or url))
        host = _url_host(url)
        if host:
            items.append(_entity('domain', host, 'hosted_on'))

    return _dedupe(items)


def _crypto_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # On-chain addresses have no sub-entities worth cross-linking.
    return []


def _hash_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    family = _text(info.get('malware_family'))
    if family:
        items.append(_entity('malware_family', family, 'family'))

    # file_name / imphash are per-sample detail, not shared infrastructure.
    return _dedupe(items)


def _url_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    domain = _text(info.get('domain')) or _text(payload.get('domain'))
    if domain:
        items.append(_entity('domain', domain, 'url_domain'))

    host = _text(info.get('host')) or _url_host(payload.get('url'))
    if host and _looks_like_ip(host):
        items.append(_entity('ip', host, 'host_ip'))

    return _dedupe(items)


def _cve_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    # references[] are too noisy for graph building; CPEs anchor the affected
    # software instead.
    for cpe in _list(info.get('affected_cpes'))[:_CPE_CAP]:
        cpe = _text(cpe)
        if cpe:
            items.append(_entity('cpe', cpe, 'affects_cpe'))

    return _dedupe(items)


def _asn_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _info_of(payload)
    items: List[Dict[str, Any]] = []

    for prefix in _list(info.get('announced_prefixes'))[:_PREFIX_CAP]:
        prefix = _text(prefix)
        if prefix:
            items.append(_entity('prefix', prefix, 'announces'))

    for peer in _list(info.get('peers')):
        peer_asn = _peer_asn(peer)
        if peer_asn:
            items.append(_entity('asn', peer_asn, 'peers_with'))

    country = _text(info.get('asn_country'))
    if country:
        items.append(_entity('country', country, 'registered_in'))

    return _dedupe(items)


_EXTRACTORS = {
    'ip': _ip_entities,
    'domain': _domain_entities,
    'email': _email_entities,
    'username': _username_entities,
    'crypto': _crypto_entities,
    'hash': _hash_entities,
    'url': _url_entities,
    'cve': _cve_entities,
    'asn': _asn_entities,
}


def extract_entities(kind: str, payload: Any) -> List[Dict[str, Any]]:
    """
    Derive sub-entities from any tracker payload.

    Args:
        kind: tracker kind ('ip', 'domain', 'email', 'username', 'crypto',
            'hash', 'url', 'cve', 'asn'); unknown kinds yield []
        payload: tracker result payload in any shape (dict with 'info',
            username-style flat dict, or garbage)

    Returns:
        List of ``{'type', 'value', 'label', 'relation'}`` dicts,
        de-duplicated on (type, value). Never raises.
    """
    try:
        handler = _EXTRACTORS.get(str(kind or '').strip().lower())
        if handler is None:
            return []
        source = payload if isinstance(payload, dict) else {}
        return handler(source)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Entity graph
# ---------------------------------------------------------------------------

class EntityGraph:
    """Accumulates entities and relationships across payloads, deduplicated."""

    def __init__(self) -> None:
        self.entities: List[Dict[str, Any]] = []
        self.links: List[Dict[str, str]] = []
        self._seen: Set[str] = set()
        self._link_seen: Set[Tuple[str, str, str]] = set()
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._by_value: Dict[Tuple[str, str], str] = {}

    def add_entity(self, entity_type: str, value: Any, label: str = '',
                   role: str = 'related') -> Optional[str]:
        """
        Add an entity; returns its id (``'type:value'``), None for junk values.

        Values are lowercased for every type except URLs/profile links, so
        'Example.com' and 'example.com' resolve to one entity. ASN values
        are canonicalised to ``AS<n>``.
        """
        if value is None or isinstance(value, (bool, dict, list, tuple, set)):
            return None
        text = str(value).strip()
        if not text:
            return None
        if entity_type not in _CASE_SENSITIVE_TYPES:
            text = text.lower()
        if entity_type == 'asn':
            match = _AS_NUMBER.match(text)
            if match:
                text = f"AS{match.group(1)}"
        entity_id = f"{entity_type}:{text}"
        if entity_id in self._seen:
            if role == 'target':
                existing = self._by_id.get(entity_id)
                if existing and existing.get('role') != 'target':
                    existing['role'] = 'target'
            return entity_id
        self._seen.add(entity_id)
        entity = {'id': entity_id, 'type': entity_type, 'value': text,
                  'role': role, 'label': label or text}
        self.entities.append(entity)
        self._by_id[entity_id] = entity
        self._by_value[(entity_type, text.lower())] = entity_id
        return entity_id

    def link(self, source_id: Optional[str], target_id: Optional[str],
             label: str) -> None:
        """Add a relationship, ignoring duplicates and self-loops."""
        if not source_id or not target_id or source_id == target_id:
            return
        key = (source_id, target_id, label)
        if key in self._link_seen:
            return
        self._link_seen.add(key)
        self.links.append({'from': source_id, 'to': target_id, 'label': label})

    def entity_id(self, entity_type: str, value: Any) -> Optional[str]:
        """Id of the entity with this type/value (case-insensitive)."""
        key = (str(entity_type), str(value or '').strip().lower())
        return self._by_value.get(key)

    def degree_map(self) -> Dict[str, int]:
        """Undirected degree of every entity (number of incident links)."""
        degrees: Dict[str, int] = {}
        for link in self.links:
            degrees[link['from']] = degrees.get(link['from'], 0) + 1
            degrees[link['to']] = degrees.get(link['to'], 0) + 1
        return degrees

    def neighbors(self, entity_id: str) -> Set[str]:
        """Undirected neighbour ids of one entity."""
        result: Set[str] = set()
        for link in self.links:
            if link['from'] == entity_id:
                result.add(link['to'])
            elif link['to'] == entity_id:
                result.add(link['from'])
        return result


def _adjacency(links: List[Dict[str, str]]) -> Dict[str, Set[str]]:
    """Undirected adjacency map built from a link list."""
    adjacency: Dict[str, Set[str]] = defaultdict(set)
    for link in links:
        adjacency[link['from']].add(link['to'])
        adjacency[link['to']].add(link['from'])
    return adjacency


def _connected_components(entities: List[Dict[str, Any]],
                          links: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Connected components (BFS) over the undirected link graph."""
    adjacency = _adjacency(links)
    clusters: List[List[str]] = []
    seen: Set[str] = set()
    for entity in entities:
        start = entity['id']
        if start in seen:
            continue
        seen.add(start)
        component = [start]
        queue = [start]
        while queue:
            current = queue.pop()
            for neighbour in adjacency.get(current, ()):
                if neighbour not in seen:
                    seen.add(neighbour)
                    component.append(neighbour)
                    queue.append(neighbour)
        clusters.append(component)
    clusters.sort(key=lambda ids: (-len(ids), ids))
    return [{'id': f'cluster-{index + 1}', 'size': len(ids),
             'entities': sorted(ids)} for index, ids in enumerate(clusters)]


# ---------------------------------------------------------------------------
# Graph construction over stored lookups
# ---------------------------------------------------------------------------

def build_graph(records: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Build the cross-target entity graph from correlation records.

    Args:
        records: list of ``{'kind', 'value', 'payload', 'created_at'}`` dicts
            (as produced by :func:`history_records`; ``created_at`` is not
            used for graph construction)

    Returns:
        ``{'entities', 'links', 'clusters', 'stats', 'degree'}`` where
        clusters are connected components sorted by size (desc) and stats
        carries ``targets/entities/links/clusters/largest_cluster/bridges``.
        Bridges are the highest-degree entities (degree >= 3, capped at 20).
    """
    graph = EntityGraph()
    targets = 0
    for record in records or []:
        if not isinstance(record, dict):
            continue
        kind = str(record.get('kind') or '').strip().lower()
        if not kind or _text(record.get('value')) == '':
            continue
        target_id = graph.add_entity(kind, record.get('value'), role='target')
        if not target_id:
            continue
        targets += 1
        for item in extract_entities(kind, record.get('payload')):
            sub_id = graph.add_entity(item['type'], item['value'],
                                      label=item.get('label', ''))
            graph.link(target_id, sub_id, item.get('relation', 'related'))

    degree = graph.degree_map()
    clusters = _connected_components(graph.entities, graph.links)
    bridges = [
        {'id': entity['id'], 'type': entity['type'], 'value': entity['value'],
         'degree': degree.get(entity['id'], 0)}
        for entity in graph.entities if degree.get(entity['id'], 0) >= 3
    ]
    bridges.sort(key=lambda bridge: (-bridge['degree'], bridge['id']))
    stats = {
        'targets': targets,
        'entities': len(graph.entities),
        'links': len(graph.links),
        'clusters': len(clusters),
        'largest_cluster': clusters[0]['size'] if clusters else 0,
        'bridges': bridges[:20],
    }
    return {
        'entities': graph.entities,
        'links': graph.links,
        'clusters': clusters,
        'stats': stats,
        'degree': degree,
    }


def _json_payload(raw: Any) -> Dict[str, Any]:
    """Decode a stored ``result_data`` JSON string into a dict."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def history_records(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Read stored lookups as correlation records.

    Rows come from ``db.get_history`` (newest first, capped at
    ``config.app_config.correlation_max_history`` unless ``limit`` is given),
    with ``result_data`` JSON-decoded into ``payload``. Kinds the engine
    cannot extract from (e.g. 'batch' or 'phone' rows) are skipped.

    Returns:
        List of ``{'kind', 'value', 'payload', 'created_at'}`` dicts.
    """
    if limit is None:
        limit = int(config.app_config.correlation_max_history or 500)
    records: List[Dict[str, Any]] = []
    try:
        rows = db.get_history(limit=limit)
    except Exception:
        return records
    for row in rows:
        kind = str(getattr(row, 'query_type', '') or '').strip().lower()
        if kind not in _EXTRACTORS:
            continue
        records.append({
            'kind': kind,
            'value': str(getattr(row, 'query_value', '') or ''),
            'payload': _json_payload(getattr(row, 'result_data', None)),
            'created_at': getattr(row, 'created_at', None),
        })
    return records


# ---------------------------------------------------------------------------
# Pairwise correlation
# ---------------------------------------------------------------------------

def _edge_labels(links: List[Dict[str, str]]) -> Dict[frozenset, str]:
    """Undirected edge -> relationship label (first occurrence wins)."""
    labels: Dict[frozenset, str] = {}
    for link in links:
        labels.setdefault(frozenset((link['from'], link['to'])), link['label'])
    return labels


def _via_label(nodes: List[str], entity_id: str,
               labels: Dict[frozenset, str]) -> str:
    """Relationship label between any of ``nodes`` and ``entity_id``."""
    for node in nodes:
        label = labels.get(frozenset((node, entity_id)))
        if label:
            return label
    return 'related'


def _reachable(adjacency: Dict[str, Set[str]], sources: List[str],
               goals: List[str], max_hops: int) -> bool:
    """Whether any goal node is reachable from a source within max_hops."""
    if not sources or not goals:
        return False
    goal_set = set(goals)
    frontier = set(sources)
    seen = set(sources)
    if frontier & goal_set:
        return True
    for _ in range(max_hops):
        next_frontier: Set[str] = set()
        for node in frontier:
            for neighbour in adjacency.get(node, ()):
                if neighbour not in seen:
                    seen.add(neighbour)
                    next_frontier.add(neighbour)
        if not next_frontier:
            return False
        if next_frontier & goal_set:
            return True
        frontier = next_frontier
    return False


def correlate(a: str, b: str,
              records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Correlate two target values over the stored (or given) lookups.

    Values are matched case-insensitively. An entity adjacent to one target
    whose value *is* the other target counts as a direct hit (``'direct'``
    via). Relatedness requires a path of at most 3 hops (BFS) between the
    two targets' entity nodes.

    Args:
        a: first target value (e.g. a domain)
        b: second target value
        records: correlation records; ``None`` reads query history via
            :func:`history_records`

    Returns:
        ``{'targets': [a, b], 'shared': [{'entity', 'type', 'via_a',
        'via_b'}], 'connections': n, 'related': bool}``.
    """
    a = str(a or '').strip()
    b = str(b or '').strip()
    if not a or not b:
        return {'targets': [a, b], 'shared': [], 'connections': 0, 'related': False}
    if records is None:
        records = history_records()

    graph = build_graph(records)
    entities_by_id = {entity['id']: entity for entity in graph['entities']}
    adjacency = _adjacency(graph['links'])
    labels = _edge_labels(graph['links'])

    nodes_a = [e['id'] for e in graph['entities']
               if str(e['value']).lower() == a.lower()]
    nodes_b = [e['id'] for e in graph['entities']
               if str(e['value']).lower() == b.lower()]

    neighbours_a: Set[str] = set()
    for node in nodes_a:
        neighbours_a |= adjacency.get(node, set())
    neighbours_a -= set(nodes_a)
    neighbours_b: Set[str] = set()
    for node in nodes_b:
        neighbours_b |= adjacency.get(node, set())
    neighbours_b -= set(nodes_b)

    shared: Dict[str, Dict[str, Any]] = {}

    def entry_for(entity_id: str) -> Dict[str, Any]:
        entity = entities_by_id.get(entity_id) or {}
        return shared.setdefault(entity_id, {
            'entity': entity_id,
            'type': entity.get('type', ''),
            'via_a': _via_label(nodes_a, entity_id, labels),
            'via_b': _via_label(nodes_b, entity_id, labels),
        })

    # 1-hop shared neighbours of both targets.
    for entity_id in sorted(neighbours_a & neighbours_b):
        entry_for(entity_id)

    # Direct hits: an entity adjacent to one target whose value IS the other.
    for entity_id in sorted(neighbours_a):
        entity = entities_by_id.get(entity_id)
        if entity and str(entity['value']).lower() == b.lower():
            entry_for(entity_id)['via_b'] = 'direct'
    for entity_id in sorted(neighbours_b):
        entity = entities_by_id.get(entity_id)
        if entity and str(entity['value']).lower() == a.lower():
            entry_for(entity_id)['via_a'] = 'direct'

    related = (
        bool(shared)
        or bool(set(nodes_a) & set(nodes_b))
        or _reachable(adjacency, nodes_a, nodes_b, 3)
    )
    return {
        'targets': [a, b],
        'shared': [shared[key] for key in sorted(shared)],
        'connections': len(shared),
        'related': bool(related),
    }


# ---------------------------------------------------------------------------
# Report sections (investigate_sections shape)
# ---------------------------------------------------------------------------

def correlation_sections(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Report sections for a :func:`build_graph` result.

    Shapes follow ``investigate.investigate_sections``: summary as a grid,
    bridges/clusters/entities/relationships as tables.
    """
    graph = graph if isinstance(graph, dict) else {}
    stats = graph.get('stats') or {}
    sections: List[Dict[str, Any]] = [{
        'title': 'Correlation Summary', 'type': 'grid', 'data': {
            'Targets': stats.get('targets', 0),
            'Entities': stats.get('entities', 0),
            'Links': stats.get('links', 0),
            'Clusters': stats.get('clusters', 0),
            'Largest cluster': stats.get('largest_cluster', 0),
        }}]

    bridges = stats.get('bridges') or []
    if bridges:
        sections.append({
            'title': 'Bridges (highest-degree entities)', 'type': 'table',
            'columns': ['Entity', 'Type', 'Degree'],
            'rows': [[b.get('id'), b.get('type'), b.get('degree')]
                     for b in bridges],
        })

    clusters = graph.get('clusters') or []
    if clusters:
        sections.append({
            'title': 'Clusters (shared infrastructure)', 'type': 'table',
            'columns': ['Cluster', 'Size', 'Entities'],
            'rows': [[c.get('id'), c.get('size'),
                      ', '.join((c.get('entities') or [])[:8])]
                     for c in clusters],
        })

    entities = graph.get('entities') or []
    if entities:
        sections.append({
            'title': 'Entities', 'type': 'table',
            'columns': ['Type', 'Value', 'Role'],
            'rows': [[e.get('type'), e.get('value'), e.get('role')]
                     for e in entities],
        })

    links = graph.get('links') or []
    if links:
        sections.append({
            'title': 'Relationships', 'type': 'table',
            'columns': ['From', 'Relationship', 'To'],
            'rows': [[link.get('from'), link.get('label'), link.get('to')]
                     for link in links],
        })
    return sections
