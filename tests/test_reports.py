"""Report sections and multi-format rendering tests."""

import json
from pathlib import Path

from obscuralens.reporting import ReportGenerator, sections_for

IP_RESULT = {
    'ip': '8.8.8.8',
    'info': {
        'reverse_dns': 'dns.google', 'country': 'United States',
        'city': 'Mountain View', 'latitude': 37.4, 'longitude': -122.0,
        'asn': 'AS15169', 'org': 'Google LLC', 'is_proxy': False,
        'ports': [53, 443], 'vulns': [], 'rdap_name': 'GOOGLE',
        'coordinates_by_source': [{'source': 'ipwho.is', 'lat': 37.4, 'lon': -122.0}],
    },
    'sources_ok': ['ipwho.is', 'rdap'],
    'sources_failed': {'ip-api.com': 'timeout'},
    'field_count': 9,
    'success': True,
    'errors': [],
}

DOMAIN_RESULT = {
    'domain': 'example.com',
    'info': {
        'domain': 'example.com', 'registrar': 'Example Inc',
        'domain_age_days': 100, 'dnssec': True,
        'missing_security_headers': ['permissions-policy'],
        'ct_subdomains': ['www.example.com'],
    },
    'sources_ok': ['rdap', 'dns'],
    'sources_failed': {},
    'field_count': 5,
    'success': True,
    'errors': [],
}

USERNAME_RESULT = {
    'username': 'alice',
    'found_count': 1, 'not_found_count': 1, 'unknown_count': 1,
    'total_checked': 3, 'total_fields': 2,
    'results': [
        {'platform': 'Keybase', 'url': 'https://keybase.io/alice',
         'status': 'found', 'confidence': 'high', 'reason': 'api',
         'status_code': 200, 'exists': True, 'profile': {'name': 'Alice'}},
        {'platform': 'HackerNews', 'url': 'u', 'status': 'not_found',
         'confidence': 'high', 'reason': '404', 'status_code': 404,
         'exists': False, 'profile': {}},
        {'platform': 'Reddit', 'url': 'u', 'status': 'unknown',
         'confidence': 'low', 'reason': 'shell', 'status_code': 200,
         'exists': False, 'profile': {}},
    ],
    'success': True, 'errors': [],
}


def test_ip_sections_have_expected_titles():
    titles = [s['title'] for s in sections_for('ip', IP_RESULT)]
    assert 'Location' in titles
    assert 'Network' in titles
    assert 'Exposure (InternetDB)' in titles
    assert 'Sources Queried' in titles


def test_domain_sections_include_subdomains_and_missing_headers():
    titles = [s['title'] for s in sections_for('domain', DOMAIN_RESULT)]
    assert 'Registration' in titles
    assert 'Subdomains (Certificate Transparency)' in titles
    assert 'Missing Security Headers' in titles


def test_username_sections_buckets():
    titles = [s['title'] for s in sections_for('username', USERNAME_RESULT)]
    assert any(t.startswith('Confirmed') for t in titles)
    assert any(t.startswith('Ruled Out') for t in titles)
    assert any(t.startswith('Inconclusive') for t in titles)
    assert 'Profile Details' in titles


def test_render_markdown_and_html_include_values(tmp_path):
    gen = ReportGenerator(output_dir=str(tmp_path))
    sections = sections_for('ip', IP_RESULT)
    data = {'sections': sections}
    markdown = gen.render_markdown(data, 'Test Report')
    assert '# Test Report' in markdown
    assert 'dns.google' in markdown

    html = gen.render_html(data, 'Test Report')
    assert '<title>Test Report</title>' in html
    assert 'dns.google' in html


def test_generate_files(tmp_path):
    gen = ReportGenerator(output_dir=str(tmp_path))
    data = {'sections': sections_for('ip', IP_RESULT)}

    json_path = gen.generate_json_report(data, 'Test')
    payload = json.loads(Path(json_path).read_text(encoding='utf-8'))
    assert payload['title'] == 'Test'

    assert Path(gen.generate_markdown_report(data, 'Test')).read_text(
        encoding='utf-8').startswith('# Test')
    assert '<html' in Path(gen.generate_html_report(data, 'Test')).read_text(
        encoding='utf-8')
    csv_path = gen.generate_csv_report(
        [{'a': 1, 'b': 'x,y'}], 'test.csv')
    assert 'a,b' in Path(csv_path).read_text(encoding='utf-8')

    pdf_path = gen.generate_pdf_report(data, 'Test')
    assert pdf_path.endswith('.pdf')
