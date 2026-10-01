"""Universal investigation engine tests (pivots, graph, sections)."""

import pytest

from obscuralens.investigate import (
    detect_kind,
    investigate,
    investigate_sections,
    to_mermaid,
)

IP_RESULT = {
    'ip': '8.8.8.8',
    'info': {'ip': '8.8.8.8', 'reverse_dns': 'dns.google', 'asn': 15169,
             'org': 'Google LLC', 'prefix': '8.8.8.0/24',
             'hostnames': ['dns.google']},
    'sources_ok': ['rdap'], 'sources_failed': {}, 'field_count': 5,
    'success': True, 'errors': [],
}

DOMAIN_RESULT = {
    'domain': 'example.com',
    'info': {'domain': 'example.com',
             'a_records': ['93.184.216.34', '93.184.216.35'],
             'mx_records': ['mail.example.com'],
             'ns_records': ['ns1.example.com'],
             'ct_subdomains': ['www.example.com'],
             'urlscan_ips': ['172.66.147.243'],
             'registrar': 'Example Registrar'},
    'sources_ok': ['dns'], 'sources_failed': {}, 'field_count': 7,
    'success': True, 'errors': [],
}

EMAIL_RESULT = {
    'email': 'alice@example.com',
    'info': {'email': 'alice@example.com', 'domain': 'example.com',
             'mx_records': ['mail.example.com'],
             'hibp_breaches': [{'name': 'ExampleBreach'}]},
    'sources_ok': ['dns'], 'sources_failed': {}, 'field_count': 4,
    'success': True, 'errors': [],
}


def _checker(results):
    def check(kind, value):
        if (kind, value) not in results:
            raise KeyError(f"no fixture for {kind} {value}")
        return results[(kind, value)]
    return check


def test_detect_kind():
    assert detect_kind('8.8.8.8') == 'ip'
    assert detect_kind('2001:4860:4860::8888') == 'ip'
    assert detect_kind('user@example.com') == 'email'
    assert detect_kind('example.com') == 'domain'
    assert detect_kind('+14155552671') == 'phone'
    assert detect_kind('some_user') == 'username'
    assert detect_kind('not a target!') is None
    assert detect_kind('') is None


def test_email_pivots_to_domain():
    checker = _checker({('email', 'alice@example.com'): EMAIL_RESULT,
                        ('domain', 'example.com'): DOMAIN_RESULT})
    payload = investigate('alice@example.com', checker=checker)
    assert payload['kind'] == 'email'
    assert payload['order'] == ['email', 'domain']
    assert payload['results']['domain']['info']['registrar'] == 'Example Registrar'
    assert {'from': 'email:alice@example.com',
            'to': 'domain:example.com', 'label': 'email_domain'} in payload['links']
    assert any(e['value'] == 'ExampleBreach' for e in payload['entities'])


def test_domain_pivots_to_limited_ips():
    checker = _checker({
        ('domain', 'example.com'): DOMAIN_RESULT,
        ('ip', '93.184.216.34'): IP_RESULT,
        ('ip', '93.184.216.35'): IP_RESULT,
    })
    payload = investigate('example.com', max_pivots=1, checker=checker)
    assert payload['order'] == ['domain', 'ip']
    assert payload['results']['ip']['ip'] == '8.8.8.8'
    links = {(link['from'], link['label'], link['to'])
             for link in payload['links']}
    assert ('domain:example.com', 'a_record', 'ip:93.184.216.34') in links
    # Only one A record was followed because of max_pivots=1.
    assert ('domain:example.com', 'a_record', 'ip:93.184.216.35') in links


def test_ip_pivots_to_ptr_domain():
    checker = _checker({
        ('ip', '8.8.8.8'): IP_RESULT,
        ('domain', 'dns.google'): DOMAIN_RESULT,
    })
    payload = investigate('8.8.8.8', checker=checker)
    assert payload['order'] == ['ip', 'domain']
    assert ('ip:8.8.8.8', 'ptr', 'hostname:dns.google') in {
        (link['from'], link['label'], link['to']) for link in payload['links']}


def test_pivot_can_be_disabled():
    checker = _checker({('email', 'alice@example.com'): EMAIL_RESULT})
    payload = investigate('alice@example.com', pivot=False, checker=checker)
    assert payload['order'] == ['email']
    assert 'domain' not in payload['results']


def test_max_pivots_counts_all_related_lookups():
    checker = _checker({('domain', 'example.com'): DOMAIN_RESULT,
                        ('ip', '93.184.216.34'): IP_RESULT,
                        ('ip', '93.184.216.35'): IP_RESULT})
    payload = investigate('example.com', max_pivots=1, checker=checker)
    assert payload['order'] == ['domain', 'ip']
    assert len(payload['results']) == 2


def test_failing_pivot_is_reported_not_raised():
    def checker(kind, value):
        if kind == 'email':
            return EMAIL_RESULT
        raise TimeoutError('boom')

    payload = investigate('alice@example.com', checker=checker)
    assert payload['results']['email'] == EMAIL_RESULT
    assert payload['errors'] == ['domain example.com: TimeoutError']


def test_unknown_target_raises():
    with pytest.raises(ValueError):
        investigate('not a target!')


def test_mermaid_graph():
    checker = _checker({('email', 'alice@example.com'): EMAIL_RESULT,
                        ('domain', 'example.com'): DOMAIN_RESULT})
    payload = investigate('alice@example.com', checker=checker)
    mermaid = to_mermaid(payload)
    assert mermaid.startswith('graph LR')
    assert 'email_domain' in mermaid
    assert 'domain: example.com' in mermaid


def test_investigate_sections():
    checker = _checker({('domain', 'example.com'): DOMAIN_RESULT,
                        ('ip', '93.184.216.34'): IP_RESULT})
    payload = investigate('example.com', max_pivots=1, checker=checker)
    titles = [section['title'] for section in investigate_sections(payload)]
    assert 'Investigation Summary' in titles
    assert any(title.startswith('DOMAIN:') for title in titles)
    assert any(title.startswith('IP:') for title in titles)
    assert 'Entities' in titles
    assert 'Relationships' in titles
