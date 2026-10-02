"""
Correlation package tests: entity extraction, graph building, pairwise
correlation, timelines and heuristic risk scoring.

Pure functions throughout -- no network. The only stateful tests use the
shared sqlite history database through the repo's ``tmp_env`` fixture.
"""

from datetime import datetime, timedelta, timezone

import pytest

from obscuralens.config import config
from obscuralens.correlation import (
    DATE_FIELD_REGISTRY,
    EntityGraph,
    build_graph,
    correlate,
    correlation_sections,
    extract_entities,
    history_records,
)
from obscuralens.correlation.risk import attach_risk, risk_sections, score
from obscuralens.correlation.timeline import (
    _parse_date,
    build_timeline,
    extract_events,
    timeline_sections,
)
from obscuralens.database import db

ALL_KINDS = ('ip', 'domain', 'email', 'username', 'crypto', 'hash', 'url',
             'cve', 'asn')

VERDICTS = ('clean', 'low', 'medium', 'high', 'critical', 'unknown')


def days_ago(days: int) -> str:
    """ISO date string for N days in the past."""
    moment = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    return moment.strftime('%Y-%m-%d')


def signal_ids(risk: dict) -> list:
    return [entry['id'] for entry in risk['signals']]


def signal_weight(risk: dict, sid: str) -> int:
    matches = [entry['weight'] for entry in risk['signals'] if entry['id'] == sid]
    assert matches, f"signal {sid!r} missing from {signal_ids(risk)}"
    return matches[0]


# ---------------------------------------------------------------------------
# extract_entities -- realistic tracker payload shapes
# ---------------------------------------------------------------------------

IP_PAYLOAD = {
    'ip': '45.33.32.156',
    'info': {
        'ip': '45.33.32.156',
        'reverse_dns': 'scanme.nmap.org',
        'hostnames': ['scanme.nmap.org', 'nmap.org'],
        'asn': 63949,
        'org': 'Akamai Connected Cloud',
        'prefix': '45.33.32.0/24',
        'domain': 'linode.com',
        'rdap_org': 'Linode LLC',
        'ports': [22, 80, 443],
        'vulns': ['CVE-2021-1'],
        'tags': ['self-signed'],
    },
}


def test_extract_entities_ip():
    entities = extract_entities('ip', IP_PAYLOAD)
    pairs = {(e['type'], e['value']) for e in entities}
    assert ('hostname', 'scanme.nmap.org') in pairs          # reverse_dns (deduped)
    assert ('hostname', 'nmap.org') in pairs                  # hostnames[]
    assert ('asn', 'AS63949') in pairs                        # asn -> 'AS<n>'
    assert ('organisation', 'Akamai Connected Cloud') in pairs
    assert ('organisation', 'Linode LLC') in pairs            # rdap_org
    assert ('prefix', '45.33.32.0/24') in pairs
    assert ('domain', 'linode.com') in pairs
    assert not any(e['type'] == 'port' for e in entities)     # ports excluded
    assert len(pairs) == 7                                    # hostname deduped
    relations = {e['relation'] for e in entities}
    assert 'ptr' in relations and 'announced_by' in relations


def test_extract_entities_domain():
    payload = {
        'domain': 'example.test',
        'info': {
            'domain': 'example.test',
            'a_records': ['93.184.216.34'],
            'aaaa_records': ['2606:2800:220:1:248:1893:25c8:1946'],
            'urlscan_ips': ['93.184.216.34'],
            'ns_records': ['ns1.example.test'],
            'mx_records': ['mail.example.test'],
            'ct_subdomains': ['www.example.test'],
            'registrar': 'Example Registrar',
            'http_final_url': 'https://example.test/',
        },
    }
    entities = extract_entities('domain', payload)
    pairs = {(e['type'], e['value']) for e in entities}
    assert ('ip', '93.184.216.34') in pairs        # a_records + urlscan_ips deduped
    assert ('ip', '2606:2800:220:1:248:1893:25c8:1946') in pairs
    assert ('nameserver', 'ns1.example.test') in pairs
    assert ('mx', 'mail.example.test') in pairs
    assert ('subdomain', 'www.example.test') in pairs
    assert ('registrar', 'Example Registrar') in pairs
    assert len(entities) == 6                       # shared IP counted once
    relation = {e['relation'] for e in entities}
    assert 'a_record' in relation


def test_extract_entities_email():
    payload = {
        'email': 'user@example.test',
        'info': {
            'email': 'user@example.test',
            'domain': 'example.test',
            'hibp_breaches': [{'name': 'Collection1'},
                              {'name': 'MyFitnessPal'},
                              {'added': '2020-01-01'}],   # nameless breach skipped
            'github_username': 'octocat',
            'gravatar': True,
        },
    }
    entities = extract_entities('email', payload)
    pairs = {(e['type'], e['value']) for e in entities}
    assert ('domain', 'example.test') in pairs
    assert ('breach', 'Collection1') in pairs
    assert ('breach', 'MyFitnessPal') in pairs
    assert ('username', 'octocat') in pairs
    assert not any(e['type'] == 'gravatar' for e in entities)
    assert len(entities) == 4


def test_extract_entities_username():
    payload = {
        'username': 'octocat',
        'results': [
            {'platform': 'GitHub', 'url': 'https://github.com/octocat',
             'status': 'found'},
            {'platform': 'Twitter', 'url': 'https://twitter.com/octocat',
             'status': 'found'},
            {'platform': 'Reddit', 'url': 'https://www.reddit.com/user/octocat',
             'status': 'not_found'},
        ],
        'found_count': 2,
    }
    entities = extract_entities('username', payload)
    profiles = [e for e in entities if e['type'] == 'profile']
    assert {p['value'] for p in profiles} == {'https://github.com/octocat',
                                              'https://twitter.com/octocat'}
    assert {p['label'] for p in profiles} == {'GitHub', 'Twitter'}  # platform label
    domains = {e['value'] for e in entities if e['type'] == 'domain'}
    assert domains == {'github.com', 'twitter.com'}                 # url hosts


def test_extract_entities_url():
    ip_host = {
        'url': 'http://185.199.110.153/login',
        'info': {'host': '185.199.110.153', 'host_is_ip': True, 'port': 80},
    }
    entities = extract_entities('url', ip_host)
    assert {(e['type'], e['value']) for e in entities} == {('ip', '185.199.110.153')}

    named = {
        'url': 'https://evil.test/phish',
        'domain': 'evil.test',
        'info': {'domain': 'evil.test', 'host': 'evil.test'},
    }
    entities = extract_entities('url', named)
    assert {(e['type'], e['value']) for e in entities} == {('domain', 'evil.test')}


def test_extract_entities_asn():
    payload = {
        'asn': 15169,
        'info': {
            'asn': 15169,
            'asn_display': 'AS15169',
            'asn_country': 'US',
            'announced_prefixes': [f'192.0.2.{i}.0/24' for i in range(30)],
            'peers': ['AS3356 Lumen', 'AS1299 Arelion', {'asn': 174}],
        },
    }
    entities = extract_entities('asn', payload)
    prefixes = [e for e in entities if e['type'] == 'prefix']
    assert len(prefixes) == 20                                   # capped at 20
    peer_asns = {e['value'] for e in entities if e['type'] == 'asn'}
    assert peer_asns == {'AS3356', 'AS1299', 'AS174'}             # string + dict peers
    assert ('country', 'US') in {(e['type'], e['value']) for e in entities}


def test_extract_entities_hash_crypto_cve():
    hash_entities = extract_entities('hash', {
        'hash': 'e3b0c442', 'info': {'malware_family': 'RedLine',
                                     'file_name': 'invoice.pdf'}})
    assert {(e['type'], e['value']) for e in hash_entities} == {
        ('malware_family', 'RedLine')}                           # file_name skipped

    assert extract_entities('crypto', {'address': '1A1zP1eP',
                                       'info': {'chain': 'btc'}}) == []

    cve_entities = extract_entities('cve', {
        'cve': 'CVE-2021-44228',
        'info': {'affected_cpes': [f'cpe:2.3:a:x:y:{i}:*:*:*:*:*:*:*'
                                   for i in range(12)],
                 'references': ['https://example.test/ref']}})
    cpes = [e for e in cve_entities if e['type'] == 'cpe']
    assert len(cpes) == 10                                       # capped at 10
    assert not any(e['type'] == 'reference' for e in cve_entities)


@pytest.mark.parametrize('kind', ALL_KINDS + ('phone', 'mystery', ''))
def test_extract_entities_never_raises_on_garbage(kind):
    for payload in (None, {}, [], 'string', 42, {'info': None},
                    {'info': 'junk'}, {'info': []}, {'results': 'nope'},
                    {'results': [{'status': 'found'}]}):
        assert extract_entities(kind, payload) == []


# ---------------------------------------------------------------------------
# EntityGraph, build_graph, clusters, bridges
# ---------------------------------------------------------------------------

def shared_ip_records():
    return [
        {'kind': 'domain', 'value': 'a.test',
         'payload': {'info': {'a_records': ['9.9.9.9']}}},
        {'kind': 'domain', 'value': 'b.test',
         'payload': {'info': {'a_records': ['9.9.9.9']}}},
    ]


def test_graph_dedupe_same_entity_two_records():
    graph = build_graph(shared_ip_records())
    ids = [entity['id'] for entity in graph['entities']]
    assert ids.count('ip:9.9.9.9') == 1                # single entity
    assert graph['degree']['ip:9.9.9.9'] == 2          # linked from both targets


def test_graph_dedupe_case_insensitive():
    records = shared_ip_records() + [
        {'kind': 'domain', 'value': 'A.TEST',
         'payload': {'info': {'urlscan_ips': ['9.9.9.9']}}}]
    graph = build_graph(records)
    domains = [e['id'] for e in graph['entities'] if e['type'] == 'domain']
    assert domains == ['domain:a.test', 'domain:b.test']   # 'A.TEST' merged
    assert graph['degree']['ip:9.9.9.9'] == 3               # new relation = new link


def test_entity_graph_role_upgrade_and_lookup():
    graph = EntityGraph()
    first = graph.add_entity('domain', 'evil.test')            # related
    later = graph.add_entity('domain', 'evil.test', role='target')
    assert first == later == 'domain:evil.test'
    assert graph.entities[0]['role'] == 'target'               # upgraded in place
    assert graph.entity_id('domain', 'EVIL.TEST') == 'domain:evil.test'
    assert graph.add_entity('ip', None) is None
    assert graph.add_entity('ip', '') is None
    assert graph.add_entity('ip', []) is None


def test_entity_graph_asn_canonicalisation():
    graph = EntityGraph()
    graph.add_entity('asn', '15169')
    graph.add_entity('asn', 'AS15169')
    assert len(graph.entities) == 1
    assert graph.entities[0]['value'] == 'AS15169'


def test_cluster_detection_shared_ip():
    records = shared_ip_records() + [
        {'kind': 'domain', 'value': 'solo.test',
         'payload': {'info': {'a_records': ['1.1.1.1']}}}]
    graph = build_graph(records)
    clusters = graph['clusters']
    assert len(clusters) == 2
    assert clusters[0]['size'] == 3                        # a.test + b.test + shared IP
    assert set(clusters[0]['entities']) == {'domain:a.test', 'domain:b.test',
                                            'ip:9.9.9.9'}
    assert clusters[1]['size'] == 2                        # solo.test + its own IP


def test_build_graph_stats_and_bridges():
    records = [
        {'kind': 'domain', 'value': f'd{i}.test',
         'payload': {'info': {'a_records': ['7.7.7.7']}}}
        for i in range(3)
    ]
    graph = build_graph(records)
    stats = graph['stats']
    assert stats['targets'] == 3
    assert stats['entities'] == 4                          # 3 domains + 1 shared IP
    assert stats['links'] == 3
    assert stats['clusters'] == 1
    assert stats['largest_cluster'] == 4
    bridges = stats['bridges']
    assert bridges and bridges[0] == {'id': 'ip:7.7.7.7', 'type': 'ip',
                                      'value': '7.7.7.7', 'degree': 3}
    assert graph['degree']['ip:7.7.7.7'] == 3


def test_build_graph_empty_and_garbage_records():
    for records in (None, [], ['nope', 7, {'kind': '', 'value': 'x'},
                               {'kind': 'domain'}, {'kind': 'domain', 'value': ''}]):
        graph = build_graph(records)
        assert graph['entities'] == []
        assert graph['stats']['targets'] == 0
        assert graph['stats']['largest_cluster'] == 0
        assert graph['clusters'] == []


def test_build_graph_target_value_normalisation():
    graph = build_graph([{'kind': 'email', 'value': 'User@Evil.TEST',
                          'payload': {'info': {'domain': 'evil.test'}}}])
    target = graph['entities'][0]
    assert target['id'] == 'email:user@evil.test'          # lowercased
    assert target['role'] == 'target'
    assert target['label'] == 'user@evil.test'


# ---------------------------------------------------------------------------
# correlate()
# ---------------------------------------------------------------------------

def test_correlate_shared_ip():
    result = correlate('a.test', 'b.test', shared_ip_records())
    assert result['targets'] == ['a.test', 'b.test']
    assert result['related'] is True
    assert result['connections'] == 1
    shared = result['shared'][0]
    assert shared == {'entity': 'ip:9.9.9.9', 'type': 'ip',
                      'via_a': 'a_record', 'via_b': 'a_record'}


def test_correlate_direct_hit():
    records = [
        {'kind': 'email', 'value': 'user@evil.test',
         'payload': {'info': {'domain': 'evil.test'}}},
        {'kind': 'domain', 'value': 'evil.test',
         'payload': {'info': {'a_records': ['6.6.6.6']}}},
    ]
    result = correlate('user@evil.test', 'evil.test', records)
    assert result['related'] is True
    by_entity = {entry['entity']: entry for entry in result['shared']}
    assert by_entity['domain:evil.test']['via_a'] == 'email_domain'
    assert by_entity['domain:evil.test']['via_b'] == 'direct'   # entity IS target b
    assert by_entity['email:user@evil.test']['via_a'] == 'direct'
    assert result['connections'] == 2


def test_correlate_case_insensitive():
    records = [
        {'kind': 'domain', 'value': 'Mixed.Case.TEST',
         'payload': {'info': {'a_records': ['9.9.9.9']}}},
        {'kind': 'domain', 'value': 'other.test',
         'payload': {'info': {'urlscan_ips': ['9.9.9.9']}}},
    ]
    result = correlate('mixed.case.test', 'OTHER.TEST', records)
    assert result['related'] is True
    assert result['shared'][0]['entity'] == 'ip:9.9.9.9'


def test_correlate_unrelated():
    records = [
        {'kind': 'domain', 'value': 'one.test',
         'payload': {'info': {'a_records': ['1.1.1.1']}}},
        {'kind': 'domain', 'value': 'two.test',
         'payload': {'info': {'a_records': ['2.2.2.2']}}},
    ]
    result = correlate('one.test', 'two.test', records)
    assert result['related'] is False
    assert result['shared'] == []
    assert result['connections'] == 0


def test_correlate_three_hop_path_without_shared_neighbour():
    records = [
        {'kind': 'domain', 'value': 'a.test',
         'payload': {'info': {'a_records': ['1.1.1.1']}}},
        {'kind': 'domain', 'value': 'y.test',
         'payload': {'info': {'a_records': ['1.1.1.1']}}},
        {'kind': 'email', 'value': 'b@y.test',
         'payload': {'info': {'domain': 'y.test'}}},
    ]
    result = correlate('a.test', 'b@y.test', records)
    assert result['related'] is True            # a - ip - y - b (3 hops, BFS)
    assert result['connections'] == 0           # no 1-hop shared neighbour


def test_correlate_empty_or_missing_values():
    result = correlate('', 'b.test', records=[])
    assert result == {'targets': ['', 'b.test'], 'shared': [], 'connections': 0,
                      'related': False}
    result = correlate('nope.test', 'nada.test', records=[])
    assert result['related'] is False
    assert result['targets'] == ['nope.test', 'nada.test']


# ---------------------------------------------------------------------------
# history_records() + graph over the database
# ---------------------------------------------------------------------------

def test_history_records_membership_and_graph(tmp_env):
    db.save_query('ip', '198.51.100.7',
                  {'ip': '198.51.100.7',
                   'info': {'ip': '198.51.100.7', 'asn': 64500}}, success=True)
    db.save_query('domain', 'correlation-demo.test',
                  {'domain': 'correlation-demo.test',
                   'info': {'a_records': ['198.51.100.7']}}, success=True)
    records = history_records()
    ip_record = [r for r in records if r['value'] == '198.51.100.7']
    assert ip_record and ip_record[0]['payload']['info']['asn'] == 64500
    assert {'kind', 'value', 'payload', 'created_at'} <= set(ip_record[0])

    graph = build_graph(records)
    assert graph['stats']['targets'] >= 2
    assert any(e['id'] == 'ip:198.51.100.7' for e in graph['entities'])
    assert any(e['id'] == 'asn:AS64500' for e in graph['entities'])
    assert any(link['from'] == 'domain:correlation-demo.test'
               and link['to'] == 'ip:198.51.100.7' for link in graph['links'])


def test_history_records_skips_unknown_kinds_and_honours_limit(tmp_env):
    db.save_query('unittest', 'ignored-value', {'info': {'x': 1}})
    assert all(record['kind'] != 'unittest' for record in history_records())

    db.save_query('domain', 'limit-one.test', {'info': {'a_records': ['1.2.3.4']}})
    db.save_query('domain', 'limit-two.test', {'info': {'a_records': ['1.2.3.4']}})
    assert len(history_records(limit=1)) == 1


def test_history_records_limit_defaults_to_config(tmp_env, monkeypatch):
    monkeypatch.setattr(config.app_config, 'correlation_max_history', 1)
    db.save_query('domain', 'cfg-a.test', {'info': {}})
    db.save_query('domain', 'cfg-b.test', {'info': {}})
    assert len(history_records()) == 1


def test_history_records_tolerates_bad_json(tmp_env):
    with db._get_connection() as conn:
        conn.execute(
            "INSERT INTO query_history (query_type, query_value, result_data, success)"
            " VALUES ('ip', '203.0.113.99', 'not-json', 1)")
        conn.commit()
    records = history_records()
    matches = [record for record in records if record['value'] == '203.0.113.99']
    assert matches and matches[0]['payload'] == {}


def test_correlate_reads_history_when_records_none(tmp_env):
    db.save_query('domain', 'hist-a.test',
                  {'info': {'a_records': ['198.51.100.9']}}, success=True)
    db.save_query('domain', 'hist-b.test',
                  {'info': {'a_records': ['198.51.100.9']}}, success=True)
    result = correlate('hist-a.test', 'hist-b.test')
    assert result['related'] is True
    assert any(entry['entity'] == 'ip:198.51.100.9' for entry in result['shared'])


# ---------------------------------------------------------------------------
# correlation_sections()
# ---------------------------------------------------------------------------

def test_correlation_sections_shape():
    graph = build_graph([
        {'kind': 'domain', 'value': 'a.test',
         'payload': {'info': {'a_records': ['9.9.9.9']}}},
        {'kind': 'domain', 'value': 'b.test',
         'payload': {'info': {'a_records': ['9.9.9.9'],
                              'urlscan_ips': ['9.9.9.9']}}},
        {'kind': 'domain', 'value': 'c.test',
         'payload': {'info': {'a_records': ['9.9.9.9']}}},
    ])
    sections = correlation_sections(graph)
    assert sections[0]['title'] == 'Correlation Summary'
    assert sections[0]['type'] == 'grid'
    assert sections[0]['data']['Targets'] == 3
    assert sections[0]['data']['Entities'] == 4
    tables = {s['title']: s for s in sections if s['type'] == 'table'}
    assert 'Bridges (highest-degree entities)' in tables
    assert tables['Bridges (highest-degree entities)']['columns'] == \
        ['Entity', 'Type', 'Degree']
    assert tables['Bridges (highest-degree entities)']['rows'][0] == \
        ['ip:9.9.9.9', 'ip', 3]
    assert 'Clusters (shared infrastructure)' in tables
    assert tables['Clusters (shared infrastructure)']['rows'][0][1] == 4
    assert tables['Entities']['columns'] == ['Type', 'Value', 'Role']
    assert tables['Relationships']['columns'] == ['From', 'Relationship', 'To']


def test_correlation_sections_empty_graph():
    sections = correlation_sections(build_graph([]))
    assert len(sections) == 1                     # summary grid only
    assert sections[0]['data']['Targets'] == 0
    assert correlation_sections(None) == sections


# ---------------------------------------------------------------------------
# timeline: parsing and event extraction
# ---------------------------------------------------------------------------

def test_parse_date_epochs():
    assert _parse_date(1580515200) == '2020-02-01T00:00:00'        # seconds
    assert _parse_date(1580515200000) == '2020-02-01T00:00:00'     # milliseconds
    assert _parse_date('1580515200') == '2020-02-01T00:00:00'      # numeric string
    assert _parse_date(1580515200.0) == '2020-02-01T00:00:00'
    assert _parse_date(1580519999) == '2020-02-01T01:19:59'


def test_parse_date_iso_and_garbage():
    assert _parse_date('2020-02-01') == '2020-02-01'
    assert _parse_date('2020-02-01T10:30:00') == '2020-02-01T10:30:00'
    assert _parse_date('2020-02-01T10:30:00Z') == '2020-02-01T10:30:00'
    assert _parse_date('2020-02-01 10:30') == '2020-02-01T10:30:00'
    assert _parse_date('2020-02-01T10:30:00.123+00:00') == '2020-02-01T10:30:00'
    for junk in (None, True, False, '', 'not a date', '13/01/2020', 123,
                 1e6, -5, [], {}, '2020', 'NaN'):
        assert _parse_date(junk) is None


def test_extract_events_domain():
    payload = {'domain': 'example.test', 'info': {
        'domain': 'example.test',
        'domain_created': '2020-01-15',
        'domain_expires': '2030-01-15',
        'domain_updated': '2024-06-01T08:00:00',
        'ct_last_seen': '2023-04-01T10:00:00',
        'wayback_first': '2019-08-20 04:15',
        'not_a_date': 'whenever',
    }}
    events = extract_events('domain', payload)
    by_field = {event['field']: event for event in events}
    assert set(by_field) == {'domain_created', 'domain_expires',
                              'domain_updated', 'ct_last_seen', 'wayback_first'}
    assert by_field['domain_created']['date'] == '2020-01-15'
    assert by_field['domain_created']['label'] == 'Created'
    assert by_field['ct_last_seen']['date'] == '2023-04-01T10:00:00'
    assert by_field['wayback_first']['date'] == '2019-08-20T04:15:00'
    assert all(event['target'] == 'example.test' for event in events)
    assert all(event['kind'] == 'domain' for event in events)
    assert all(event['sort_key'] == event['date'] for event in events)


def test_extract_events_email_hibp():
    payload = {'email': 'user@example.test', 'info': {
        'email': 'user@example.test',
        'domain_created': '2015-05-05',
        'hibp_breaches': [
            {'name': 'Collection1', 'added': '2019-07-01T00:00:00Z'},
            {'name': 'MyFitnessPal', 'breach_date': '2018-02-01'},
            {'name': 'NoDates'},
        ],
    }}
    events = extract_events('email', payload)
    labels = {event['label']: event for event in events}
    assert labels['Domain created']['field'] == 'domain_created'
    breach = labels['Breached: Collection1']
    assert breach['field'] == 'hibp_breaches.added'
    assert breach['date'] == '2019-07-01T00:00:00'
    assert labels['Breached: MyFitnessPal']['field'] == 'hibp_breaches.breach_date'
    assert len(events) == 3                                     # NoDates skipped


def test_extract_events_username_profiles():
    payload = {'username': 'octocat', 'results': [
        {'platform': 'GitHub', 'status': 'found',
         'profile': {'joined': '2011-01-25', 'followers': 300}},
        {'platform': 'Reddit', 'status': 'not_found',
         'profile': {'created': '2010-01-01'}},
    ]}
    events = extract_events('username', payload)
    assert len(events) == 1                                     # only found profiles
    assert events[0]['label'] == 'Joined GitHub'
    assert events[0]['field'] == 'profile.joined'
    assert events[0]['date'] == '2011-01-25'
    assert events[0]['target'] == 'octocat'


def test_extract_events_crypto_blockchair_and_registry():
    payload = {'address': '1A1zP1eP', 'info': {
        'address': '1A1zP1eP',
        'chain': 'btc',
        'first_seen': '2009-01-03',
        'blockchair_first_seen_receiving': 1231748993,
        'blockchair_last_seen_spending': '2021-06-01T00:00:00',
        'blockchair_balance': 12.5,                              # not a date field
    }}
    events = extract_events('crypto', payload)
    fields = {event['field'] for event in events}
    assert fields == {'first_seen', 'blockchair_first_seen_receiving',
                      'blockchair_last_seen_spending'}
    labels = {event['label'] for event in events}
    assert 'First Seen Receiving' in labels                     # humanised label
    receiving = [e for e in events
                 if e['field'] == 'blockchair_first_seen_receiving'][0]
    assert receiving['date'] == '2009-01-12T08:29:53'
    assert 'first_seen' in DATE_FIELD_REGISTRY['crypto']


def test_extract_events_url_hash_and_cve_registry_dates():
    url_events = extract_events('url', {'url': 'https://x.test/a', 'info': {
        'url': 'https://x.test/a', 'wayback_first_capture': '2020-01-01',
        'urlscan_last_scan': '2022-10-05T12:00:00', 'vt_last_analysis': 1664952000}})
    assert {event['field'] for event in url_events} == {
        'wayback_first_capture', 'urlscan_last_scan', 'vt_last_analysis'}

    hash_events = extract_events('hash', {'info': {
        'hash': 'aa', 'first_seen': '2021-03-01', 'vt_created': '2020-02-01'}})
    assert {event['field'] for event in hash_events} == {'first_seen', 'vt_created'}

    cve_events = extract_events('cve', {'info': {
        'cve': 'CVE-2020-1', 'published': '2020-09-01',
        'epss_date': '2025-01-01T00:00:00.000Z'}})
    assert {event['field'] for event in cve_events} == {'published', 'epss_date'}


@pytest.mark.parametrize('kind', ALL_KINDS + ('phone', 'mystery', ''))
def test_extract_events_never_raises_on_garbage(kind):
    for payload in (None, {}, [], 'string', 42, {'info': None},
                    {'info': 'junk'}, {'info': []},
                    {'info': {'created': 'whenever'}}, {'results': 'x'}):
        assert extract_events(kind, payload) == []


# ---------------------------------------------------------------------------
# build_timeline() + timeline_sections()
# ---------------------------------------------------------------------------

def timeline_payloads():
    return [
        {'kind': 'domain', 'value': 'late.test',
         'payload': {'info': {'domain': 'late.test',
                              'domain_created': '2022-02-02'}}},
        {'kind': 'domain', 'value': 'early.test',
         'payload': {'info': {'domain': 'early.test',
                              'domain_created': '2018-01-01',
                              'domain_expires': '2019-12-31'}}},
        {'kind': 'email', 'value': 'user@no-target.test',
         'payload': {'info': {'hibp_breaches': [
             {'name': 'OldBreach', 'added': '2020-06-15'}]}}},
    ]


def test_build_timeline_sorts_oldest_first():
    timeline = build_timeline(timeline_payloads(), cap=None)
    dates = [event['date'] for event in timeline['events']]
    assert dates == sorted(dates)                               # ascending
    assert dates == ['2018-01-01', '2019-12-31', '2020-06-15', '2022-02-02']
    assert timeline['count'] == 4
    assert timeline['first'] == '2018-01-01'
    assert timeline['last'] == '2022-02-02'


def test_build_timeline_target_fallback():
    timeline = build_timeline(timeline_payloads(), cap=None)
    breach = [event for event in timeline['events']
              if event['field'] == 'hibp_breaches.added'][0]
    assert breach['target'] == 'user@no-target.test'            # payload has no identity


def test_build_timeline_cap_keeps_most_recent():
    timeline = build_timeline(timeline_payloads(), cap=2)
    assert timeline['count'] == 2
    assert [event['date'] for event in timeline['events']] == \
        ['2020-06-15', '2022-02-02']
    assert timeline['first'] == '2020-06-15'
    assert timeline['last'] == '2022-02-02'


def test_build_timeline_cap_from_config(monkeypatch):
    monkeypatch.setattr(config.app_config, 'timeline_max_events', 3)
    timeline = build_timeline(timeline_payloads())              # cap=None -> config
    assert timeline['count'] == 3
    assert timeline['events'][0]['date'] == '2019-12-31'


def test_build_timeline_empty():
    timeline = build_timeline([])
    assert timeline == {'events': [], 'count': 0, 'first': None, 'last': None}
    assert build_timeline(None) == timeline
    assert build_timeline(['junk', 7, {'kind': 'domain'}])['count'] == 0


def test_timeline_sections_shape():
    timeline = build_timeline(timeline_payloads(), cap=None)
    sections = timeline_sections(timeline)
    assert sections[0]['title'] == 'Timeline Summary'
    assert sections[0]['type'] == 'grid'
    assert sections[0]['data']['Events'] == 4
    assert sections[0]['data']['Earliest'] == '2018-01-01'
    table = sections[1]
    assert table['type'] == 'table'
    assert table['columns'] == ['Date', 'Target', 'Event', 'Source']
    assert table['rows'][0] == ['2018-01-01', 'early.test', 'Created',
                                'domain_created']
    assert len(table['rows']) == 4


def test_timeline_sections_empty():
    sections = timeline_sections(build_timeline([]))
    assert len(sections) == 1
    assert sections[0]['data']['Earliest'] == '-'
    empty = timeline_sections(None)                     # never raises
    assert len(empty) == 1
    assert empty[0]['data']['Events'] == 0
    assert empty[0]['data']['Earliest'] == '-'


# ---------------------------------------------------------------------------
# risk: score() per kind
# ---------------------------------------------------------------------------

def test_risk_ip_high():
    risk = score('ip', {'info': {
        'abuse_confidence': 80, 'malicious': 5, 'suspicious': 3,
        'tor_exit': True, 'vulns': ['CVE-1', 'CVE-2', 'CVE-3', 'CVE-4', 'CVE-5',
                                    'CVE-6'],
        'ports': list(range(12)), 'tags': ['self-signed', 'nginx'],
    }})
    assert risk['score'] == 100                                 # capped
    assert risk['verdict'] in ('high', 'critical')
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights['abuse_confidence_high'] == 45
    assert weights['vt_malicious_engines'] == 20
    assert weights['vt_suspicious_engines'] == 10
    assert weights['tor_exit'] == 15
    assert weights['many_open_vulns'] == 25
    assert weights['many_open_ports'] == 5
    assert weights['risky_service_tags'] == 5
    assert '80' in [e for e in risk['signals']
                    if e['id'] == 'abuse_confidence_high'][0]['detail']


def test_risk_ip_clean_and_informational():
    risk = score('ip', {'info': {'ip': '1.2.3.4', 'reverse_dns': 'ptr.example.net',
                                 'hostnames': ['ptr.example.net']}})
    assert risk['score'] == 0
    assert risk['verdict'] == 'clean'
    assert risk['signals'] == []

    quiet = score('ip', {'info': {'ip': '5.6.7.8'}})            # no DNS at all
    assert quiet['score'] == 0
    assert signal_ids(quiet) == ['no_dns_presence']
    assert signal_weight(quiet, 'no_dns_presence') == 0


def test_risk_ip_abuse_tiers_and_blocklists():
    moderate = score('ip', {'info': {'ip': '1.2.3.4', 'abuse_confidence': 30,
                                     'reverse_dns': 'ptr.example.net'}})
    assert signal_ids(moderate) == ['abuse_confidence_moderate']
    assert signal_weight(moderate, 'abuse_confidence_moderate') == 15

    elevated = score('ip', {'info': {'ip': '1.2.3.4', 'abuse_confidence': 60,
                                     'reverse_dns': 'ptr.example.net'}})
    assert signal_weight(elevated, 'abuse_confidence_elevated') == 30
    assert elevated['verdict'] == 'low'

    for flag in ('spamhaus_drop', 'feodo', 'firehol'):
        listed = score('ip', {'info': {'ip': '9.9.9.9', flag: True}})
        assert signal_weight(listed, f"{flag}_listed") == 25
        assert flag in [e for e in listed['signals']
                        if e['id'] == f"{flag}_listed"][0]['detail']


def test_risk_domain_young_and_mail_posture():
    payload = {'info': {
        'domain': 'fresh.test', 'domain_created': days_ago(3),
        'mx_records': ['mail.fresh.test'], 'mx_exists': True,
        'spf_record': 'v=spf1 -all', 'dmarc_record': 'v=DMARC1; p=none',
        'dmarc_policy': 'none', 'dnssec': False}}
    risk = score('domain', payload)
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'very_new_domain': 25, 'dmarc_monitor_only': 5,
                       'no_dnssec': 5}
    assert risk['score'] == 35 and risk['verdict'] == 'low'

    young = {'info': {'domain': 'young.test', 'domain_age_days': 20,
                      'txt_records': ['v=spf1 -all'], 'dnssec': True}}
    risk = score('domain', young)
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'new_domain': 15, 'no_mx': 5, 'no_spf': 10,
                       'no_dmarc': 10}
    assert risk['verdict'] == 'medium'


def test_risk_domain_parking_typosquat_expired():
    parked = score('domain', {'info': {'domain': 'idle.test',
                                       'http_title': 'This domain is for sale!'}})
    assert signal_weight(parked, 'parked_domain') == 15

    typo = score('domain', {'info': {'domain': 'g00gle.test',
                                     'typosquat_of_popular': 'google.com'}})
    assert signal_weight(typo, 'typosquat_of_popular') == 20

    expired = score('domain', {'info': {'domain': 'gone.test',
                                        'domain_status': 'clientExpired',
                                        'a_records': []}})
    weights = {entry['id']: entry['weight'] for entry in expired['signals']}
    assert weights == {'domain_expired': 5, 'no_a_records': 5}

    scanned = score('domain', {'info': {'domain': 'x.test',
                                        'urlscan_malicious_verdicts': 2}})
    assert signal_weight(scanned, 'urlscan_malicious') == 25


def test_risk_email_high():
    risk = score('email', {'info': {
        'email': 'a@b.test', 'disposable': True, 'mx_exists': False,
        'hibp_breaches': [{'name': f'B{i}'} for i in range(6)],
        'hibp_classes': ['Email addresses', 'Passwords'],
    }})
    assert risk['score'] == 80
    assert risk['verdict'] == 'high'
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'disposable_mailbox': 15, 'no_mx': 20,
                       'multiple_breaches': 25, 'credentials_leaked': 20}


def test_risk_email_recent_breach_and_reputation():
    risk = score('email', {'info': {
        'email': 'a@b.test',
        'hibp_breaches': [{'name': 'Fresh', 'added': days_ago(5)}],
        'emailrep_reputation': 8}})
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'breached': 10, 'emailrep_bad_reputation': 20,
                       'recent_breach': 10}
    assert risk['score'] == 40 and risk['verdict'] == 'medium'

    low = score('email', {'info': {'email': 'a@b.test',
                                   'emailrep_reputation': 20}})
    assert signal_weight(low, 'emailrep_low_reputation') == 15


def test_risk_email_clean():
    risk = score('email', {'info': {
        'email': 'a@b.test', 'disposable': False, 'mx_exists': True,
        'mx_records': ['mail.b.test'], 'spf_record': 'v=spf1 -all',
        'dmarc_record': 'v=DMARC1; p=reject', 'dmarc_policy': 'reject'}})
    assert risk['score'] == 0
    assert risk['verdict'] == 'clean'
    assert risk['signals'] == []


def test_risk_hash_malicious():
    risk = score('hash', {'info': {
        'hash': 'aa', 'malicious': 8, 'suspicious': 2,
        'malware_family': 'AgentTesla', 'otx_pulses': 5,
        'vt_threat_label': 'trojan.agent'}})
    assert risk['score'] == 100                                 # 50+10+30+10+10 capped
    assert risk['verdict'] == 'critical'
    detail = [e for e in risk['signals']
              if e['id'] == 'malware_family'][0]['detail']
    assert 'AgentTesla' in detail


def test_risk_hash_benign_known_floors_at_zero():
    risk = score('hash', {'info': {'hash': 'bb', 'known_file': True}})
    assert risk['score'] == 0
    assert risk['verdict'] == 'clean'
    benign = risk['signals'][0]
    assert benign['id'] == 'benign_known_file'
    assert benign['weight'] == -20


def test_risk_url_gsb():
    risk = score('url', {'url': 'http://185.199.110.153:8081/login/verify',
                         'info': {
                             'gsb_malicious': True,
                             'gsb_threat_types': ['MALWARE'],
                             'vt_malicious': 3, 'redirect_count': 6,
                             'host_is_ip': True, 'port': 8081}})
    assert risk['score'] == 100
    assert risk['verdict'] == 'critical'
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'gsb_malicious': 50, 'vt_malicious': 25,
                       'redirect_chain': 10, 'ip_hosted_url': 15,
                       'credential_keywords': 5, 'nonstandard_port': 5}


def test_risk_url_punycode_and_single_vt_detection():
    risk = score('url', {'url': 'http://xn--80ak6aa92e.com/',
                         'info': {'vt_malicious': 1}})
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'vt_malicious': 15, 'punycode_host': 20}
    assert risk['verdict'] == 'low'

    scanned = score('url', {'url': 'https://x.test/',
                            'info': {'urlscan_malicious_verdicts': 1}})
    assert signal_weight(scanned, 'urlscan_malicious') == 25


def test_risk_cve_critical():
    risk = score('cve', {'info': {
        'cve': 'CVE-2021-44228', 'cvss_score': 9.8,
        'cvss_severity': 'CRITICAL', 'epss_score': 97,
        'references': ['https://example.test/exploit-db',
                       'https://nvd.nist.gov/vuln/detail']}})
    assert risk['score'] == 90
    assert risk['verdict'] == 'critical'
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'cvss_critical': 60, 'epss_very_likely': 15,
                       'exploit_reference': 15, 'cvss_severity_label': 0}


def test_risk_cve_lower_bands():
    medium = score('cve', {'info': {'cve': 'CVE-2020-1', 'cvss_score': 5.3}})
    assert signal_weight(medium, 'cvss_medium') == 20
    assert medium['verdict'] == 'low'

    epss = score('cve', {'info': {'cve': 'CVE-2020-2', 'cvss_score': 8.1,
                                  'epss_score': 60}})
    weights = {entry['id']: entry['weight'] for entry in epss['signals']}
    assert weights == {'cvss_high': 40, 'epss_likely': 5}


def test_risk_crypto_activity_profile():
    risk = score('crypto', {'info': {
        'address': '1A1zP1eP', 'chain': 'btc', 'first_seen': days_ago(10),
        'btc_tx_count': 0, 'btc_balance': 0}})
    weights = {entry['id']: entry['weight'] for entry in risk['signals']}
    assert weights == {'new_address': 10, 'unused_address': 0}
    assert risk['score'] == 10
    assert risk['verdict'] == 'clean'
    assert 'activity profile' in risk['summary']              # no risk language

    funded = score('crypto', {'info': {'address': 'x', 'chain': 'eth',
                                       'eth_balance': 1.25}})
    assert signal_ids(funded) == ['funded_address']
    assert signal_weight(funded, 'funded_address') == 0


def test_risk_username_exposure_profile():
    risk = score('username', {'username': 'octocat', 'found_count': 12,
                              'results': []})
    assert signal_weight(risk, 'broad_footprint') == 5
    assert 'exposure profile' in risk['summary']

    derived = score('username', {
        'username': 'octocat',
        'results': [{'status': 'found'}] * 11})
    assert signal_ids(derived) == ['broad_footprint']         # falls back to results

    narrow = score('username', {'username': 'x', 'found_count': 3})
    assert narrow['signals'] == []


def test_risk_asn_informational():
    risk = score('asn', {'info': {'asn': 15169, 'announced_prefix_count': 2000,
                                  'peer_count': 800}})
    assert risk['score'] == 0
    assert risk['verdict'] == 'clean'
    assert {entry['id'] for entry in risk['signals']} == \
        {'large_transit', 'large_peering'}
    assert all(entry['weight'] == 0 for entry in risk['signals'])

    small = score('asn', {'info': {'asn': 64500, 'announced_prefix_count': 12,
                                   'peer_count': 3}})
    assert small['score'] == 0
    assert small['verdict'] == 'clean'
    assert small['signals'] == []                     # small network: no signals


# ---------------------------------------------------------------------------
# risk: unknown payloads, attach_risk, sections, robustness
# ---------------------------------------------------------------------------

EMPTY_PAYLOADS = ({}, {'info': None}, {'info': []}, {'info': 'junk'},
                  {'info': {}}, None, 'string', 42, [])


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_risk_unknown_on_empty_payloads(kind):
    for payload in EMPTY_PAYLOADS:
        risk = score(kind, payload)
        assert risk == {'score': 0, 'verdict': 'unknown', 'signals': [],
                        'summary': 'no collected fields to score'}, \
            f"{kind} / {payload!r}"


def test_risk_never_raises_on_garbage():
    garbage = ({}, {'info': None}, {'info': 'junk'}, {'info': []},
               {'info': {'deep': {'x': 1}}}, None, 'oops', 7, [1])
    for kind in ALL_KINDS + ('phone', 'mystery'):
        for payload in garbage:
            risk = score(kind, payload)
            assert 0 <= risk['score'] <= 100
            assert risk['verdict'] in VERDICTS
            assert isinstance(risk['signals'], list)
            assert isinstance(risk['summary'], str) and risk['summary']


def test_risk_unknown_kind_scores_clean():
    risk = score('mystery', {'info': {'x': 1}})
    assert risk['score'] == 0
    assert risk['verdict'] == 'clean'
    assert risk['signals'] == []


def test_attach_risk_adds_block(tmp_env, monkeypatch):
    monkeypatch.setattr(config.app_config, 'risk_enabled', True)
    payload = {'ip': '1.2.3.4', 'info': {'ip': '1.2.3.4',
                                         'abuse_confidence': 90}}
    result = attach_risk('ip', payload)
    assert result is payload
    assert result['risk']['score'] == 45
    assert result['risk']['verdict'] == 'medium'
    assert 'abuse_confidence_high' in signal_ids(result['risk'])

    empty = attach_risk('ip', {'info': {}})
    assert empty['risk']['verdict'] == 'unknown'


def test_attach_risk_respects_config_switch(tmp_env, monkeypatch):
    monkeypatch.setattr(config.app_config, 'risk_enabled', False)
    payload = {'info': {'abuse_confidence': 90}}
    assert attach_risk('ip', payload) is payload
    assert 'risk' not in payload

    monkeypatch.setattr(config.app_config, 'risk_enabled', True)
    assert attach_risk('not-a-dict', None) is None           # never raises


def test_risk_sections_shape():
    risk = score('ip', {'info': {'ip': '1.2.3.4', 'abuse_confidence': 60}})
    sections = risk_sections(risk)
    assert sections[0]['title'] == 'Risk Assessment'
    assert sections[0]['type'] == 'grid'
    assert sections[0]['data']['Score'] == '30/100'
    assert sections[0]['data']['Verdict'] == 'low'
    assert 'heuristic score' in sections[0]['data']['Summary']
    table = sections[1]
    assert table['type'] == 'table'
    assert table['columns'] == ['Signal', 'Weight', 'Detail']
    assert table['rows'][0][0] == 'abuse_confidence_elevated'
    assert table['rows'][0][1] == 30


def test_risk_sections_empty():
    sections = risk_sections(score('ip', {}))
    assert len(sections) == 1                                 # grid only, no signals
    assert sections[0]['data']['Verdict'] == 'unknown'
    assert risk_sections(None)[0]['data']['Score'] == '0/100'  # never raises
