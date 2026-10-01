"""
Universal investigation: detect a target's kind, run the matching tracker and
follow a bounded set of pivots to related entities.

Pivots (depth 1):
  * email   -> its domain is looked up as a domain
  * domain  -> up to ``max_pivots`` A records are looked up as IPs
  * ip      -> its PTR hostname is looked up as a domain

The result is a self-contained payload with per-kind tracker results plus an
entity list and a relationship list, renderable as a table, JSON or a Mermaid
graph.
"""

import re
from typing import Any, Callable, Dict, List, Optional

from .reporting.sections import sections_for
from .utils.validators import (
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_username,
)

KINDS = ('ip', 'phone', 'username', 'email', 'domain')


def detect_kind(target: str) -> Optional[str]:
    """Best-effort target type detection; None when nothing matches."""
    value = (target or '').strip()
    if not value:
        return None
    if validate_ip(value)[0]:
        return 'ip'
    if validate_email(value)[0]:
        return 'email'
    if '.' in value and validate_domain(value)[0]:
        return 'domain'
    if validate_phone(value)[0]:
        return 'phone'
    if validate_username(value)[0]:
        return 'username'
    return None


def _default_checker(kind: str, target: str) -> Dict[str, Any]:
    """Run the real tracker for a kind (imported lazily to avoid cycles)."""
    from .trackers import (
        DomainTracker,
        EmailTracker,
        IPTracker,
        PhoneTracker,
        UsernameTracker,
    )
    trackers = {
        'ip': IPTracker, 'phone': PhoneTracker, 'username': UsernameTracker,
        'email': EmailTracker, 'domain': DomainTracker,
    }
    return trackers[kind]().track(target)


def _entity_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


class _Graph:
    """Accumulates entities and relationships without duplicates."""

    def __init__(self, target: str, kind: str):
        self.entities: List[Dict[str, Any]] = []
        self.links: List[Dict[str, str]] = []
        self._seen = set()
        self._link_seen = set()
        self.add_entity(kind, target, role='target')

    def add_entity(self, kind: str, value: Any, role: str = 'related',
                   label: str = '') -> Optional[str]:
        if value in (None, '', [], {}):
            return None
        value = str(value)
        eid = _entity_id(kind, value)
        if eid not in self._seen:
            self._seen.add(eid)
            self.entities.append({
                'id': eid, 'type': kind, 'value': value,
                'role': role, 'label': label or value,
            })
        return eid

    def link(self, source: Optional[str], target: Optional[str],
             label: str) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, label)
        if key in self._link_seen:
            return
        self._link_seen.add(key)
        self.links.append({'from': source, 'to': target, 'label': label})


def _add_domain_facts(graph: _Graph, result: Dict[str, Any],
                      subdomain_cap: int = 15) -> None:
    info = result.get('info', {})
    host = graph.add_entity('domain', info.get('domain') or result.get('domain'))
    if not host:
        return

    entries = (
        ('a_records', 'ip', 'a_record', 10),
        ('urlscan_ips', 'ip', 'observed_ip', 5),
        ('ns_records', 'nameserver', 'nameserver', 5),
        ('mx_records', 'mx', 'mx', 5),
        ('ct_subdomains', 'subdomain', 'subdomain', subdomain_cap),
    )
    for key, entity_type, link_label, cap in entries:
        for value in (info.get(key) or [])[:cap]:
            graph.link(host, graph.add_entity(entity_type, value),
                       link_label)

    registrar = graph.add_entity('registrar', info.get('registrar'))
    graph.link(host, registrar, 'registrar')


def _add_ip_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('ip', info.get('ip') or result.get('ip'))
    if not node:
        return
    graph.link(node, graph.add_entity('hostname', info.get('reverse_dns')), 'ptr')
    graph.link(node, graph.add_entity('asn', f"AS{info.get('asn')}"
                                      if info.get('asn') else None),
               'announced_by')
    graph.link(node, graph.add_entity('organisation', info.get('org')),
               'operated_by')
    graph.link(node, graph.add_entity('prefix', info.get('prefix')),
               'prefix')
    for hostname in (info.get('hostnames') or [])[:5]:
        graph.link(node, graph.add_entity('hostname', hostname), 'hostname')


def _add_email_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('email', info.get('email') or result.get('email'))
    if not node:
        return
    graph.link(node, graph.add_entity('domain', info.get('domain')),
               'email_domain')
    for breach in (info.get('hibp_breaches') or [])[:10]:
        graph.link(node, graph.add_entity('breach', breach.get('name')),
                   'exposed_in')


def _add_phone_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('phone', result.get('phone_number'))
    if not node:
        return
    graph.link(node, graph.add_entity('carrier', info.get('carrier')),
               'carrier')
    graph.link(node, graph.add_entity('region', info.get('region_code')),
               'region')


def _add_username_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    node = graph.add_entity('username', result.get('username'))
    if not node:
        return
    found = [r for r in result.get('results', [])
             if r.get('status') == 'found']
    for record in found[:25]:
        graph.link(node, graph.add_entity('profile', record.get('url'),
                                          label=f"{record.get('platform')}: "
                                                f"{record.get('url', '')}"),
                   'profile_on')


_GRAPH_BUILDERS = {
    'domain': _add_domain_facts,
    'ip': _add_ip_facts,
    'email': _add_email_facts,
    'phone': _add_phone_facts,
    'username': _add_username_facts,
}


def investigate(target: str, pivot: bool = True, max_pivots: int = 3,
                checker: Optional[Callable[[str, str], Dict[str, Any]]] = None
                ) -> Dict[str, Any]:
    """
    Investigate any supported target and follow bounded pivots.

    Args:
        target: IP / domain / email / phone / username
        pivot: follow related targets (email->domain, domain->A, ip->PTR)
        max_pivots: maximum related lookups of each kind
        checker: injectable ``callable(kind, value) -> result`` for tests

    Returns:
        Payload with per-kind results, entities, links and errors.
    """
    kind = detect_kind(target)
    if kind is None:
        raise ValueError(f"cannot determine target type: {target!r}")

    checker = checker or _default_checker
    value = target.strip()
    payload: Dict[str, Any] = {
        'target': value,
        'kind': kind,
        'order': [kind],
        'results': {},
        'entities': [],
        'links': [],
        'errors': [],
    }

    def run(kind_name: str, target_value: str) -> Optional[Dict[str, Any]]:
        try:
            result = checker(kind_name, target_value)
        except Exception as e:
            payload['errors'].append(
                f"{kind_name} {target_value}: {type(e).__name__}")
            return None
        return result

    primary = run(kind, value)
    if primary is None:
        return payload
    payload['results'][kind] = primary

    if pivot:
        seen = {(kind, value.lower())}

        def pivot_to(kind_name: str, pivot_value: str) -> None:
            key = (kind_name, pivot_value.lower())
            if key in seen or len(payload['results']) >= max_pivots + 1:
                return
            seen.add(key)
            result = run(kind_name, pivot_value)
            if result is not None:
                payload['results'][kind_name] = result

        if kind == 'email':
            domain = (primary.get('info') or {}).get('domain')
            if domain:
                pivot_to('domain', domain)
        elif kind == 'domain':
            info = primary.get('info') or {}
            for record in (info.get('a_records') or [])[:max_pivots]:
                pivot_to('ip', str(record))
        elif kind == 'ip':
            info = primary.get('info') or {}
            ptr = info.get('reverse_dns')
            if ptr and validate_domain(str(ptr))[0]:
                pivot_to('domain', str(ptr))

    graph = _Graph(value, kind)
    for kind_name, result in payload['results'].items():
        builder = _GRAPH_BUILDERS.get(kind_name)
        if builder:
            builder(graph, result)
    payload['entities'] = graph.entities
    payload['links'] = graph.links
    payload['order'] = list(payload['results'].keys())
    return payload


def to_mermaid(payload: Dict[str, Any]) -> str:
    """Render the entity graph as a Mermaid flowchart."""
    node_ids: Dict[str, str] = {}

    def node_id(entity_id: str) -> str:
        if entity_id not in node_ids:
            slug = re.sub(r'[^0-9A-Za-z]', '_', entity_id)[:48].strip('_')
            node_ids[entity_id] = f"n{len(node_ids)}_{slug}" if slug else \
                f"n{len(node_ids)}"
        return node_ids[entity_id]

    def esc(text: Any) -> str:
        return str(text).replace('"', "'").replace('\n', ' ')[:80]

    lines = ['graph LR']
    for entity in payload.get('entities', []):
        label = esc(f"{entity['type']}: {entity.get('label') or entity['value']}")
        lines.append(f'    {node_id(entity["id"])}["{label}"]')
    for link in payload.get('links', []):
        lines.append(f'    {node_id(link["from"])} -->|{esc(link["label"])}| '
                     f'{node_id(link["to"])}')
    return '\n'.join(lines)


def investigate_sections(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Report sections for an investigation payload."""
    summary = {
        'Target': payload.get('target'),
        'Detected kind': payload.get('kind'),
        'Lookups': ', '.join(payload.get('order', [])),
        'Entities': len(payload.get('entities', [])),
        'Relationships': len(payload.get('links', [])),
    }
    sections: List[Dict[str, Any]] = [
        {'title': 'Investigation Summary', 'type': 'grid', 'data': summary},
    ]

    for kind in payload.get('order', []):
        result = payload.get('results', {}).get(kind)
        if not result:
            continue
        for section in sections_for(kind, result):
            section = dict(section)
            section['title'] = f"{kind.upper()}: {section['title']}"
            sections.append(section)

    entities = payload.get('entities', [])
    if entities:
        sections.append({
            'title': 'Entities', 'type': 'table',
            'columns': ['Type', 'Value', 'Role'],
            'rows': [[e['type'], e['value'], e['role']] for e in entities],
        })
    links = payload.get('links', [])
    if links:
        sections.append({
            'title': 'Relationships', 'type': 'table',
            'columns': ['From', 'Relationship', 'To'],
            'rows': [[link['from'], link['label'], link['to']]
                     for link in links],
        })
    if payload.get('errors'):
        sections.append({
            'title': 'Errors', 'type': 'table', 'columns': ['Error'],
            'rows': [[error] for error in payload['errors']],
        })
    return sections
