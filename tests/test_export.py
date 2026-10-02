"""Graph export tests: XML round-trips, DOT/JSONL/CSV output, dispatcher."""

import csv
import io
import json
import logging
import xml.etree.ElementTree as ET

import pytest

from obscuralens.export import (
    EXPORT_FORMATS,
    export_graph,
    export_sections,
    render,
    to_csv_edges,
    to_dot,
    to_gexf,
    to_graphml,
    to_jsonl,
)
from obscuralens.export.graph import FALLBACK_COLORS, _color_for

NS = '{http://graphml.graphdrawing.org/xmlns}'
GNS = '{http://gexf.net/1.3draft}'

ENTITIES = [
    {'id': 'ip:8.8.8.8', 'type': 'ip', 'value': '8.8.8.8',
     'role': 'target', 'label': '8.8.8.8'},
    {'id': 'domain:dns.google', 'type': 'domain', 'value': 'dns.google',
     'role': 'related', 'label': 'dns.google'},
    {'id': 'hostname:dns.google', 'type': 'hostname', 'value': 'dns.google',
     'role': 'related', 'label': 'dns.google'},
]
LINKS = [
    {'from': 'ip:8.8.8.8', 'to': 'domain:dns.google', 'label': 'ptr'},
    {'from': 'ip:8.8.8.8', 'to': 'hostname:dns.google', 'label': 'hostname'},
]
HOSTILE = [
    {'id': 'q:"x&y<z>"', 'type': 'ip', 'value': 'v',
     'role': 'target', 'label': 'a"b<c>&d'},
    {'id': 'other:node', 'type': 'domain', 'value': 'w',
     'role': 'related', 'label': 'plain'},
]


def _parse_graphml(text):
    root = ET.fromstring(text)
    return (
        root,
        root.findall(f'{NS}graph/{NS}node'),
        root.findall(f'{NS}graph/{NS}edge'),
    )


def test_export_formats_registry():
    assert EXPORT_FORMATS == ('graphml', 'gexf', 'dot', 'jsonl', 'csv')


def test_graphml_roundtrip_counts_ids_and_edges():
    root, nodes, edges = _parse_graphml(to_graphml(ENTITIES, LINKS))
    assert root.tag == f'{NS}graphml'
    assert [node.get('id') for node in nodes] == [
        'ip:8.8.8.8', 'domain:dns.google', 'hostname:dns.google']
    assert len(edges) == 2
    assert edges[0].get('source') == 'ip:8.8.8.8'
    assert edges[0].get('target') == 'domain:dns.google'
    data = {item.get('key'): item.text for item in edges[0].findall(f'{NS}data')}
    assert data['e0'] == 'ptr'


def test_graphml_key_declarations():
    root = _parse_graphml(to_graphml(ENTITIES, LINKS))[0]
    attrs = {(key.get('for'), key.get('attr.name'))
             for key in root.findall(f'{NS}key')}
    assert ('node', 'type') in attrs
    assert ('node', 'role') in attrs
    assert ('node', 'label') in attrs
    assert ('edge', 'label') in attrs


def test_graphml_escapes_hostile_values():
    root, nodes, edges = _parse_graphml(to_graphml(HOSTILE, [
        {'from': 'q:"x&y<z>"', 'to': 'other:node', 'label': '<e>&"'}]))
    assert nodes[0].get('id') == 'q:"x&y<z>"'
    data = {item.get('key'): item.text for item in nodes[0].findall(f'{NS}data')}
    assert data['d2'] == 'a"b<c>&d'
    edge_data = {item.get('key'): item.text
                 for item in edges[0].findall(f'{NS}data')}
    assert edge_data['e0'] == '<e>&"'


def test_gexf_parses_with_namespace():
    root = ET.fromstring(to_gexf(ENTITIES, LINKS))
    assert root.tag == f'{GNS}gexf'
    assert root.get('version') == '1.3'
    graph = root.find(f'{GNS}graph')
    assert graph.get('defaultedgetype') == 'undirected'
    assert len(graph.find(f'{GNS}nodes')) == 3
    assert len(graph.find(f'{GNS}edges')) == 2


def test_gexf_attribute_values_roundtrip():
    root = ET.fromstring(to_gexf(HOSTILE, [
        {'from': 'q:"x&y<z>"', 'to': 'other:node', 'label': '<e>&"'}]))
    node = root.find(f'{GNS}graph/{GNS}nodes/{GNS}node')
    assert node.get('id') == 'q:"x&y<z>"'
    values = {item.get('for'): item.get('value')
              for item in node.find(f'{GNS}attvalues')}
    assert values['label'] == 'a"b<c>&d'
    assert values['type'] == 'ip'
    edge = root.find(f'{GNS}graph/{GNS}edges/{GNS}edge')
    assert edge.get('source') == 'q:"x&y<z>"'
    assert edge.get('weight') == '1.0'
    assert edge.get('label') == '<e>&"'


def test_dot_structure_and_edges():
    dot = to_dot(ENTITIES, LINKS)
    assert dot.lstrip().startswith('digraph')
    assert '"ip:8.8.8.8" [label="ip: 8.8.8.8"' in dot
    assert '"ip:8.8.8.8" -> "domain:dns.google" [label="ptr"];' in dot
    assert '"ip:8.8.8.8" -> "hostname:dns.google" [label="hostname"];' in dot
    assert dot.rstrip().endswith('}')


def test_dot_escapes_labels_and_prefixes_digit_ids():
    entities = [
        {'id': '12345', 'type': 'ip', 'value': '1.2.3.4',
         'role': 'target', 'label': 'a"b\\c'},
        {'id': 'x:1', 'type': 'domain', 'value': 'e.com',
         'role': 'r', 'label': 'e'},
    ]
    dot = to_dot(entities, [{'from': '12345', 'to': 'x:1', 'label': 'rel"ate'}])
    assert '"n12345"' in dot
    assert '"n12345" -> "x:1"' in dot
    assert 'label="ip: a\\"b\\\\c"' in dot
    assert 'label="rel\\"ate"' in dot


def test_dot_palette_colors_and_unknown_types():
    dot = to_dot(ENTITIES, LINKS)
    assert 'color="#e74c3c"' in dot        # ip
    assert 'color="#3498db"' in dot        # domain
    color = _color_for('martian')
    assert color in FALLBACK_COLORS
    assert _color_for('martian') == color  # deterministic across calls
    alien = [
        {'id': 'm:1', 'type': 'martian', 'value': 'v', 'role': 'r', 'label': 'v'},
        {'id': 'm:2', 'type': 'martian', 'value': 'v', 'role': 'r', 'label': 'v'},
    ]
    dot2 = to_dot(alien, [])
    assert dot2.count(f'fillcolor="{color}"') == 2


def test_jsonl_node_and_edge_records():
    lines = to_jsonl(ENTITIES, LINKS).splitlines()
    records = [json.loads(line) for line in lines]
    assert [record['record'] for record in records] == ['node'] * 3 + ['edge'] * 2
    node = records[0]
    assert node == {'record': 'node', 'id': 'ip:8.8.8.8', 'type': 'ip',
                    'value': '8.8.8.8', 'role': 'target', 'label': '8.8.8.8'}
    assert records[3] == {'record': 'edge', 'source': 'ip:8.8.8.8',
                          'target': 'domain:dns.google', 'label': 'ptr'}
    hostile = [json.loads(line) for line in to_jsonl(HOSTILE, []).splitlines()]
    assert hostile[0]['label'] == 'a"b<c>&d'


def test_csv_edges_roundtrip_and_quoting():
    text = to_csv_edges(LINKS + [
        {'from': 'a,x', 'to': 'b"c', 'label': 'quoted'}])
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ['source', 'relationship', 'target']
    assert rows[1] == ['ip:8.8.8.8', 'ptr', 'domain:dns.google']
    assert rows[-1] == ['a,x', 'quoted', 'b"c']


def test_render_dispatches_all_formats_deterministically():
    expected = {
        'graphml': to_graphml(ENTITIES, LINKS),
        'gexf': to_gexf(ENTITIES, LINKS),
        'dot': to_dot(ENTITIES, LINKS),
        'jsonl': to_jsonl(ENTITIES, LINKS),
        'csv': to_csv_edges(LINKS),
    }
    for fmt, text in expected.items():
        assert render(ENTITIES, LINKS, fmt) == text
        assert render(ENTITIES, LINKS, fmt) == text  # stable across calls
    assert render(ENTITIES, LINKS, 'GraphML') == expected['graphml']


def test_render_unknown_format_raises():
    with pytest.raises(ValueError) as excinfo:
        render(ENTITIES, LINKS, 'svg')
    assert 'svg' in str(excinfo.value)


def test_export_graph_from_payload():
    payload = {'target': '8.8.8.8', 'kind': 'ip', 'entities': ENTITIES,
               'links': LINKS}
    assert export_graph(payload, fmt='jsonl') == to_jsonl(ENTITIES, LINKS)
    assert export_graph(payload, fmt='csv').startswith('source,relationship')
    assert export_graph(payload, fmt='graphml') == to_graphml(ENTITIES, LINKS)


def test_export_graph_from_entities_and_links():
    text = export_graph(ENTITIES, LINKS, fmt='gexf')
    assert text == to_gexf(ENTITIES, LINKS)
    default = export_graph(ENTITIES, LINKS)
    assert default == to_graphml(ENTITIES, LINKS)


def test_export_graph_writes_under_report_dir(tmp_env):
    text = export_graph(ENTITIES, LINKS, fmt='dot', path='case1.dot')
    assert text is not None
    target = tmp_env / 'reports' / 'case1.dot'
    assert target.exists()
    assert target.read_text(encoding='utf-8') == text


def test_export_graph_absolute_path_creates_parents(tmp_path):
    target = tmp_path / 'deep' / 'nested' / 'case.graphml'
    text = export_graph(ENTITIES, LINKS, fmt='graphml', path=str(target))
    assert text is not None
    assert target.exists()
    assert target.read_text(encoding='utf-8') == to_graphml(ENTITIES, LINKS)


def test_export_graph_io_error_returns_none(tmp_path, caplog):
    blocker = tmp_path / 'blocker'
    blocker.write_text('not a directory')
    with caplog.at_level(logging.WARNING):
        result = export_graph(ENTITIES, LINKS, fmt='dot',
                              path=str(blocker / 'sub' / 'g.dot'))
    assert result is None
    assert 'cannot write' in caplog.text


def test_malformed_rows_are_skipped():
    entities = ENTITIES + [
        {'type': 'ip', 'value': '1.2.3.4'},   # no id
        'junk',
        None,
        {'id': None, 'type': 'ip'},
    ]
    links = LINKS + [
        {'to': 'domain:dns.google', 'label': 'no from'},
        {'from': 'ip:8.8.8.8'},               # no to
        'junk',
        None,
    ]
    root, nodes, edges = _parse_graphml(to_graphml(entities, links))
    assert len(nodes) == 3
    assert len(edges) == 2


def test_dangling_edges_dropped_only_in_graph_documents():
    links = LINKS + [{'from': 'ip:9.9.9.9', 'to': 'domain:dns.google',
                      'label': 'ghost'}]
    _, _, edges = _parse_graphml(to_graphml(ENTITIES, links))
    assert len(edges) == 2
    assert len(ET.fromstring(to_gexf(ENTITIES, links))
               .find(f'{GNS}graph/{GNS}edges')) == 2
    assert 'ghost' not in to_dot(ENTITIES, links)
    # line-oriented exports keep the raw relationship record
    records = [json.loads(line) for line in to_jsonl(ENTITIES, links).splitlines()]
    assert any(record['record'] == 'edge' and record['label'] == 'ghost'
               for record in records)
    assert to_csv_edges(links).count('ghost') == 1


def test_duplicate_entity_ids_collapse():
    entities = ENTITIES + [dict(ENTITIES[0])]
    root, nodes, _ = _parse_graphml(to_graphml(entities, []))
    assert len(nodes) == 3


def test_entity_label_falls_back_to_value():
    entities = [{'id': 'ip:1.1.1.1', 'type': 'ip', 'value': '1.1.1.1',
                 'role': 'target'}]
    records = [json.loads(line)
               for line in to_jsonl(entities, []).splitlines()]
    assert records[0]['label'] == '1.1.1.1'
    root, nodes, _ = _parse_graphml(to_graphml(entities, []))
    data = {item.get('key'): item.text for item in nodes[0].findall(f'{NS}data')}
    assert data['d2'] == '1.1.1.1'


def test_empty_inputs_render_without_raising():
    for fmt in EXPORT_FORMATS:
        assert isinstance(render([], [], fmt), str)
        assert isinstance(render(None, None, fmt), str)
    assert to_jsonl([], []) == ''
    assert to_csv_edges([]) == 'source,relationship,target\n'
    root, nodes, edges = _parse_graphml(to_graphml(None, None))
    assert root.tag == f'{NS}graphml'
    assert nodes == [] and edges == []


def test_export_sections_shape():
    payload = {'target': '8.8.8.8', 'kind': 'ip', 'entities': ENTITIES,
               'links': LINKS}
    sections = export_sections(payload)
    assert isinstance(sections, list) and len(sections) == 2
    grid, table = sections
    assert grid['type'] == 'grid'
    assert grid['data']['Entities'] == 3
    assert grid['data']['Relationships'] == 2
    assert grid['data']['Formats'] == ', '.join(EXPORT_FORMATS)
    assert table['type'] == 'table'
    assert table['columns'] == ['Format', 'Description', 'Opens with']
    assert [row[0] for row in table['rows']] == list(EXPORT_FORMATS)
    # entity lists work too (payload-free invocation)
    sections2 = export_sections({'entities': ENTITIES, 'links': LINKS})
    assert sections2[0]['data']['Entities'] == 3
