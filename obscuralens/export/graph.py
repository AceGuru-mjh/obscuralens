"""
Entity/relationship graph serializers for external visualisation tooling.

Input is the investigate payload graph shape:

    entities: [{'id', 'type', 'value', 'role', 'label'}, ...]
    links:    [{'from', 'to', 'label'}, ...]

Available formats:

  * ``to_graphml``   -- GraphML XML             (Gephi, yEd, Cytoscape)
  * ``to_gexf``      -- GEXF 1.3                (Gephi, Sigma.js)
  * ``to_dot``       -- Graphviz digraph source  (Graphviz, OmniGraffle)
  * ``to_jsonl``     -- one JSON record per line (nodes first, then edges)
  * ``to_csv_edges`` -- edge list (source, relationship, target)

Every serializer returns a string and never raises on malformed input: rows
that are not mappings, entities without an ``id`` and links without both a
``from`` and a ``to`` are skipped silently.  Edges that point at entity ids
missing from the node list are dropped from the graph documents (GraphML,
GEXF and DOT must stay valid) but are kept in the line-oriented JSONL and
CSV exports, where they are plain records.

``render`` dispatches on a format name; ``export_graph`` accepts either a
full investigate payload or an entities list plus links and optionally
writes the result under ``report_dir``.
"""

import csv
import io
import json
import logging
import re
import zlib
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from xml.sax.saxutils import escape, quoteattr

from ..config import config

logger = logging.getLogger(__name__)

#: Supported export format names (also the ``render`` dispatch keys).
EXPORT_FORMATS = ('graphml', 'gexf', 'dot', 'jsonl', 'csv')

GRAPHML_NS = 'http://graphml.graphdrawing.org/xmlns'
GEXF_NS = 'http://gexf.net/1.3draft'

#: Stable per-entity-type node colours used by the DOT export.
PALETTE = {
    'ip': '#e74c3c',
    'domain': '#3498db',
    'email': '#9b59b6',
    'username': '#16a085',
    'phone': '#f39c12',
    'profile': '#2980b9',
    'breach': '#c0392b',
    'hostname': '#1abc9c',
    'asn': '#27ae60',
    'organisation': '#8e44ad',
    'carrier': '#d35400',
    'registrar': '#2c3e50',
    'nameserver': '#34495e',
    'mx': '#e67e22',
    'subdomain': '#95a5a6',
    'prefix': '#f1c40f',
}

#: Fallback colours for entity types missing from ``PALETTE``.  Picked via a
#: CRC32 hash of the type name, so a colour never changes between runs.
FALLBACK_COLORS = (
    '#e91e63', '#00bcd4', '#ffc107', '#795548', '#4caf50', '#3f51b5',
)

#: Format catalogue shown by ``export_sections``.
FORMAT_INFO = (
    ('graphml', 'GraphML XML with node/edge attributes', 'Gephi, yEd, Cytoscape'),
    ('gexf', 'GEXF 1.3 graph exchange format', 'Gephi, Sigma.js'),
    ('dot', 'Graphviz digraph source', 'Graphviz, OmniGraffle'),
    ('jsonl', 'One JSON record per line (nodes then edges)', 'jq, custom scripts'),
    ('csv', 'Edge list (source, relationship, target)', 'spreadsheets, pandas'),
)

_XML_CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


# -- input normalisation -------------------------------------------------


def _text(value: Any) -> str:
    """Stringify a graph field, dropping characters that are invalid in XML."""
    return _XML_CTRL.sub('', str(value if value is not None else ''))


def _clean_entities(entities: Any) -> Iterator[Dict[str, str]]:
    """Yield well-formed entity dicts; malformed rows are skipped."""
    if not entities:
        return
    seen = set()
    for row in entities:
        if not isinstance(row, dict):
            continue
        raw_id = row.get('id')
        if raw_id is None or raw_id == '':
            continue
        entity_id = _text(raw_id)
        if not entity_id or entity_id in seen:
            continue
        seen.add(entity_id)
        value = _text(row.get('value'))
        label = _text(row.get('label')) or value or entity_id
        yield {
            'id': entity_id,
            'type': _text(row.get('type')),
            'value': value,
            'role': _text(row.get('role')),
            'label': label,
        }


def _clean_links(links: Any,
                 known_ids: Optional[set] = None) -> Iterator[Dict[str, str]]:
    """Yield well-formed link dicts; malformed rows are skipped.

    When ``known_ids`` is given, links whose endpoints are not part of the
    node list are dropped as well — used by the graph documents that must
    stay valid (GraphML/GEXF/DOT).  Line-oriented exports call this without
    ``known_ids`` so raw relationship records survive.
    """
    if not links:
        return
    seen = set()
    for row in links:
        if not isinstance(row, dict):
            continue
        source = row.get('from')
        target = row.get('to')
        if source is None or source == '' or target is None or target == '':
            continue
        source, target = _text(source), _text(target)
        label = _text(row.get('label'))
        key = (source, target, label)
        if key in seen:
            continue
        if known_ids is not None and (source not in known_ids
                                      or target not in known_ids):
            continue
        seen.add(key)
        yield {'source': source, 'target': target, 'label': label}


def _unpack(payload_or_entities: Any,
            links: Any = None) -> Tuple[Any, Any]:
    """Accept an investigate payload dict OR an entities list (+ links)."""
    if isinstance(payload_or_entities, dict):
        entities = payload_or_entities.get('entities') or []
        if links is None:
            links = payload_or_entities.get('links') or []
        return entities, links
    return payload_or_entities or [], links or []


def _resolve_path(path: Any) -> Path:
    """Resolve an output path; relative paths land under ``report_dir``."""
    target = Path(path)
    if not target.is_absolute():
        target = Path(config.app_config.report_dir or '.') / target
    return target


# -- serializers ---------------------------------------------------------


def to_graphml(entities: Any, links: Any) -> str:
    """Serialize the graph as GraphML XML (Gephi / yEd / Cytoscape).

    Node attributes ``type`` / ``role`` / ``label`` and the edge attribute
    ``label`` are declared as ``<key>`` entries; ids and values are XML
    escaped, so hostile characters survive a parse round-trip.
    """
    nodes = list(_clean_entities(entities))
    edges = list(_clean_links(links, {node['id'] for node in nodes}))
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<graphml xmlns="{GRAPHML_NS}"',
        '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
        f'         xsi:schemaLocation="{GRAPHML_NS}'
        f' {GRAPHML_NS}/1.0/graphml.xsd">',
        '  <key id="d0" for="node" attr.name="type" attr.type="string"/>',
        '  <key id="d1" for="node" attr.name="role" attr.type="string"/>',
        '  <key id="d2" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="e0" for="edge" attr.name="label" attr.type="string"/>',
        '  <graph edgedefault="undirected">',
    ]
    for node in nodes:
        lines.append(f'    <node id={quoteattr(node["id"])}>')
        lines.append(f'      <data key="d0">{escape(node["type"])}</data>')
        lines.append(f'      <data key="d1">{escape(node["role"])}</data>')
        lines.append(f'      <data key="d2">{escape(node["label"])}</data>')
        lines.append('    </node>')
    for edge in edges:
        lines.append(f'    <edge source={quoteattr(edge["source"])} '
                     f'target={quoteattr(edge["target"])}>')
        lines.append(f'      <data key="e0">{escape(edge["label"])}</data>')
        lines.append('    </edge>')
    lines += ['  </graph>', '</graphml>']
    return '\n'.join(lines) + '\n'


def to_gexf(entities: Any, links: Any) -> str:
    """Serialize the graph as GEXF 1.3 (Gephi / Sigma.js).

    Node attributes ``type`` / ``role`` / ``label`` are declared for the
    ``node`` attribute class and mirrored in ``<attvalues>``; edges carry a
    ``label`` attribute plus weight 1.0.
    """
    nodes = list(_clean_entities(entities))
    edges = list(_clean_links(links, {node['id'] for node in nodes}))
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<gexf xmlns="{GEXF_NS}" version="1.3">',
        '  <graph defaultedgetype="undirected">',
        '    <attributes class="node">',
        '      <attribute id="type" title="Type" type="string"/>',
        '      <attribute id="role" title="Role" type="string"/>',
        '      <attribute id="label" title="Label" type="string"/>',
        '    </attributes>',
        '    <attributes class="edge">',
        '      <attribute id="label" title="Label" type="string"/>',
        '    </attributes>',
        '    <nodes>',
    ]
    for node in nodes:
        lines.append(f'      <node id={quoteattr(node["id"])} '
                     f'label={quoteattr(node["label"])}>')
        lines.append('        <attvalues>')
        lines.append(f'          <attvalue for="type" '
                     f'value={quoteattr(node["type"])}/>')
        lines.append(f'          <attvalue for="role" '
                     f'value={quoteattr(node["role"])}/>')
        lines.append(f'          <attvalue for="label" '
                     f'value={quoteattr(node["label"])}/>')
        lines.append('        </attvalues>')
        lines.append('      </node>')
    lines.append('    </nodes>')
    lines.append('    <edges>')
    for index, edge in enumerate(edges):
        lines.append(f'      <edge id="e{index}" source={quoteattr(edge["source"])} '
                     f'target={quoteattr(edge["target"])} weight="1.0" '
                     f'label={quoteattr(edge["label"])}>')
        lines.append('        <attvalues>')
        lines.append(f'          <attvalue for="label" '
                     f'value={quoteattr(edge["label"])}/>')
        lines.append('        </attvalues>')
        lines.append('      </edge>')
    lines.append('    </edges>')
    lines += ['  </graph>', '</gexf>']
    return '\n'.join(lines) + '\n'


def _dot_escape(text: Any) -> str:
    """Escape a value for use inside a quoted DOT string."""
    value = _text(text).replace('\\', '\\\\').replace('"', '\\"')
    return value.replace('\n', ' ').replace('\r', ' ')


def _color_for(entity_type: str) -> str:
    """Stable colour for an entity type (hash-based for unknown types)."""
    if entity_type in PALETTE:
        return PALETTE[entity_type]
    index = zlib.crc32(entity_type.encode('utf-8')) % len(FALLBACK_COLORS)
    return FALLBACK_COLORS[index]


def _dot_names(nodes: List[Dict[str, str]]) -> Dict[str, str]:
    """Map entity ids to unique DOT names (digit-leading ids get an ``n``)."""
    names: Dict[str, str] = {}
    taken = set()
    for node in nodes:
        base = node['id']
        if base[:1].isdigit():
            base = f'n{base}'
        name, counter = base, 2
        while name in taken:
            name = f'{base}_{counter}'
            counter += 1
        taken.add(name)
        names[node['id']] = name
    return names


def to_dot(entities: Any, links: Any) -> str:
    """Serialize the graph as a Graphviz digraph with per-type colours.

    Node names are quoted and escaped, digit-leading ids get an ``n``
    prefix; node labels read ``"type: label"``.
    """
    nodes = list(_clean_entities(entities))
    names = _dot_names(nodes)
    edges = list(_clean_links(links, set(names)))
    lines = [
        'digraph obscuralens {',
        '    rankdir=LR;',
        '    node [style=filled];',
    ]
    for node in nodes:
        label = f"{node['type']}: {node['label']}" if node['type'] else node['label']
        color = _color_for(node['type'])
        lines.append(f'    "{_dot_escape(names[node["id"]])}" '
                     f'[label="{_dot_escape(label)}", color="{color}", '
                     f'fillcolor="{color}"];')
    for edge in edges:
        lines.append(f'    "{_dot_escape(names[edge["source"]])}" -> '
                     f'"{_dot_escape(names[edge["target"]])}" '
                     f'[label="{_dot_escape(edge["label"])}"];')
    lines.append('}')
    return '\n'.join(lines) + '\n'


def to_jsonl(entities: Any, links: Any) -> str:
    """One JSON object per line: node records first, then edge records."""
    nodes = list(_clean_entities(entities))
    edges = list(_clean_links(links))
    lines = []
    for node in nodes:
        lines.append(json.dumps({
            'record': 'node', 'id': node['id'], 'type': node['type'],
            'value': node['value'], 'role': node['role'], 'label': node['label'],
        }))
    for edge in edges:
        lines.append(json.dumps({
            'record': 'edge', 'source': edge['source'],
            'target': edge['target'], 'label': edge['label'],
        }))
    return '\n'.join(lines) + ('\n' if lines else '')


def to_csv_edges(links: Any) -> str:
    """Edge list CSV with the header ``source,relationship,target``."""
    edges = list(_clean_links(links))
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator='\n')
    writer.writerow(['source', 'relationship', 'target'])
    for edge in edges:
        writer.writerow([edge['source'], edge['label'], edge['target']])
    return buf.getvalue()


# -- dispatch + persistence ----------------------------------------------


def render(entities: Any, links: Any, fmt: str) -> str:
    """Render the graph in ``fmt`` (one of ``EXPORT_FORMATS``).

    Raises:
        ValueError: when ``fmt`` is not a known export format.
    """
    fmt = str(fmt or '').strip().lower()
    if fmt == 'graphml':
        return to_graphml(entities, links)
    if fmt == 'gexf':
        return to_gexf(entities, links)
    if fmt == 'dot':
        return to_dot(entities, links)
    if fmt == 'jsonl':
        return to_jsonl(entities, links)
    if fmt == 'csv':
        return to_csv_edges(links)
    raise ValueError(
        f'unsupported export format {fmt!r} '
        f"(expected one of: {', '.join(EXPORT_FORMATS)})")


def export_graph(payload_or_entities: Any, links: Any = None,
                 fmt: str = 'graphml', path: Any = None) -> Optional[str]:
    """Render (and optionally persist) the graph in ``fmt``.

    Accepts either an investigate payload dict (with ``entities``/``links``)
    or an entities list plus a links list.  When ``path`` is given the
    document is written there — relative paths land under
    ``config.app_config.report_dir`` — and the text is still returned.

    Returns:
        The rendered document, or ``None`` when writing failed (logged as a
        warning, never raised).  Unknown formats raise ``ValueError``.
    """
    entities, graph_links = _unpack(payload_or_entities, links)
    text = render(entities, graph_links, fmt)
    if path:
        target = _resolve_path(path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding='utf-8')
        except OSError as exc:
            logger.warning('graph export: cannot write %s: %s', target, exc)
            return None
    return text


def export_sections(payload: Any) -> List[Dict[str, Any]]:
    """Informational report sections describing the available exports."""
    entities, links = _unpack(payload)
    nodes = list(_clean_entities(entities))
    edges = list(_clean_links(links, {node['id'] for node in nodes}))
    return [
        {
            'title': 'Graph Export', 'type': 'grid',
            'data': {
                'Entities': len(nodes),
                'Relationships': len(edges),
                'Formats': ', '.join(EXPORT_FORMATS),
                'Output directory': config.app_config.report_dir,
            },
        },
        {
            'title': 'Export Formats', 'type': 'table',
            'columns': ['Format', 'Description', 'Opens with'],
            'rows': [list(row) for row in FORMAT_INFO],
        },
    ]
