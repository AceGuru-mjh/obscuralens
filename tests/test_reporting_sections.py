"""Report section builder tests for every target kind (v1 through v6).

Each ``*_sections`` builder turns a tracker envelope (``info`` plus
``sources_ok`` / ``sources_failed`` / counters) into ReportGenerator
sections (``grid`` / ``table``). These tests build synthetic envelopes per
kind and assert structure, key fields, bucket routing and junk tolerance.
"""

import pytest

from obscuralens.reporting.sections import (
    app_sections,
    asn_sections,
    batch_sections,
    bssid_sections,
    coords_sections,
    crypto_sections,
    cve_sections,
    domain_sections,
    email_sections,
    flight_sections,
    hash_sections,
    iban_sections,
    imei_sections,
    ip_sections,
    mac_sections,
    mmsi_sections,
    phone_sections,
    plate_sections,
    sections_for,
    sources_table,
    url_sections,
    username_sections,
    vin_sections,
)

SECTION_TYPES = {'grid', 'table', 'text'}


# ---------------------------------------------------------------------------
# Shared assertions
# ---------------------------------------------------------------------------

def assert_well_formed(sections):
    """Every section must be a dict ReportGenerator can render."""
    assert isinstance(sections, list)
    for section in sections:
        assert isinstance(section, dict)
        assert isinstance(section.get('title'), str) and section['title']
        assert section['type'] in SECTION_TYPES
        if section['type'] == 'grid':
            assert isinstance(section['data'], dict)
        elif section['type'] == 'table':
            assert isinstance(section['columns'], list)
            assert isinstance(section['rows'], list)
            assert all(len(row) == len(section['columns'])
                       for row in section['rows'])
    return sections


def by_title(sections, title):
    for section in sections:
        if section['title'] == title:
            return section
    raise AssertionError(f'no section titled {title!r}; got '
                         f'{[s["title"] for s in sections]}')


def grid_value(sections, title, label):
    return by_title(sections, title)['data'][label]


# ---------------------------------------------------------------------------
# Synthetic envelopes (field names mirror the real trackers)
# ---------------------------------------------------------------------------

def ip_result(**extra):
    result = {
        'ip': '8.8.8.8',
        'info': {
            'reverse_dns': 'dns.google', 'country': 'United States',
            'country_code': 'US', 'region': 'California',
            'city': 'Mountain View', 'postal': '94043',
            'latitude': 37.4, 'longitude': -122.0,
            'timezone': 'America/Los_Angeles', 'is_eu': False,
            'asn': 'AS15169', 'org': 'Google LLC', 'is_proxy': False,
            'rdap_name': 'GOOGLE', 'rdap_cidr': '8.8.8.0/24',
            'rdap_abuse_email': 'network-abuse@google.com',
            'ports': [53, 443], 'vulns': ['CVE-2020-0001'],
            'cpes': ['cpe:2.3:a:google:dns:8.8.8.8'],
            'malicious': 3, 'suspicious': 1, 'malicious_score': 12,
            'is_tor': False, 'is_datacenter': True,
            'analyst_note': 'manual triage note',
        },
        'field_sources': {'country': ['ipwho.is']},
        'sources_ok': ['ipwho.is', 'rdap'],
        'sources_failed': {'ip-api.com': 'timeout'},
        'field_count': 20,
        'success': True,
    }
    result.update(extra)
    return result


def phone_result(**extra):
    result = {
        'phone_number': '+15551234567',
        'info': {
            'original_number': '+1 555 123 4567',
            'e164': '+15551234567', 'international': '+1 555-123-4567',
            'national_format': '(555) 123-4567',
            'rfc3966': 'tel:+1-555-123-4567', 'country_code': '1',
            'region_code': 'US', 'type': 'MOBILE', 'valid_format': True,
            'possible': True, 'is_mobile': True, 'is_voip': False,
            'carrier': 'Verizon', 'location': 'New Jersey',
            'primary_timezone': 'America/New_York',
            'hints': ['carrier lookup used local numbering plan'],
        },
        'sources_ok': ['libphonenumber'],
        'sources_failed': {},
        'field_count': 12,
        'success': True,
    }
    result.update(extra)
    return result


def username_result(**extra):
    result = {
        'username': 'alice',
        'found_count': 2, 'not_found_count': 1, 'unknown_count': 1,
        'total_checked': 4, 'total_fields': 3,
        'results': [
            {'platform': 'Keybase', 'url': 'https://keybase.io/alice',
             'status': 'found', 'confidence': 'high', 'reason': 'api 200',
             'status_code': 200, 'exists': True,
             'profile': {'name': 'Alice', 'location': 'Wonderland'}},
            {'platform': 'GitHub', 'url': 'https://github.com/alice',
             'status': 'found', 'confidence': 'medium', 'reason': '200',
             'status_code': 200, 'exists': True,
             'profile': {'name': 'Alice Dev', 'public_repos': 12}},
            {'platform': 'HackerNews', 'url': 'u', 'status': 'not_found',
             'confidence': 'high', 'reason': '404', 'status_code': 404,
             'exists': False, 'profile': {}},
            {'platform': 'Reddit', 'url': 'u', 'status': 'unknown',
             'confidence': 'low', 'reason': 'bot wall', 'status_code': 200,
             'error': 'blocked', 'exists': False, 'profile': {}},
        ],
        'success': True,
    }
    result.update(extra)
    return result


def email_result(**extra):
    result = {
        'email': 'user@example.com',
        'info': {
            'email': 'user@example.com', 'domain': 'example.com',
            'valid_format': True, 'mx_exists': True, 'mx_count': 2,
            'is_webmail': False, 'disposable': False, 'openpgp': True,
            'gravatar': True, 'dnssec': True, 'dmarc_policy': 'reject',
            'domain_created': '1995-08-14', 'domain_expires': '2027-08-14',
            'domain_age_days': 11000, 'registrar': 'Example Registrar',
            'hibp_breaches': [
                {'name': 'ExampleBreach', 'date': '2021-02-03',
                 'pwn_count': 12345, 'data_classes': ['Emails', 'Passwords']},
                {'name': 'OtherBreach', 'date': '2019-01-01',
                 'pwn_count': 0, 'data_classes': None},
            ],
            'pastes': [{'date': '2020-05-05', 'entries': 42}],
        },
        'sources_ok': ['dns', 'hibp'],
        'sources_failed': {'hunter': 'no api key'},
        'field_count': 15,
        'success': True,
    }
    result.update(extra)
    return result


def domain_result(**extra):
    result = {
        'domain': 'example.com',
        'info': {
            'domain': 'example.com', 'registrar': 'Example Registrar',
            'domain_created': '1995-08-14', 'domain_age_days': 11000,
            'domain_expires': '2027-08-14', 'expires_in_days': 400,
            'domain_status': ['clientTransferProhibited'],
            'nameservers': ['a.iana-servers.net', 'b.iana-servers.net'],
            'dnssec': True, 'mx_records': ['mail.example.com'],
            'spf_record': 'v=spf1 -all', 'dmarc_policy': 'reject',
            'dkim_selectors': ['sel1'], 'caa_records': ['0 issue "letsencrypt.org"'],
            'soa_record': 'ns1.example.com hostmaster 42',
            'http_status': 200, 'http_title': 'Example Domain',
            'http_final_url': 'https://example.com/', 'server': 'nginx',
            'powered_by': 'Example', 'robots_txt': 'User-agent: *',
            'security_headers': ['strict-transport-security'],
            'missing_security_headers': ['content-security-policy'],
            'ct_certificates': 3, 'ct_last_seen': '2026-01-01',
            'ct_subdomains': ['www.example.com', 'api.example.com'],
            'custom_field': 'extra intelligence',
        },
        'sources_ok': ['rdap', 'dns'],
        'sources_failed': {},
        'field_count': 24,
        'success': True,
    }
    result.update(extra)
    return result


def envelope(kind, info, **extra):
    result = {
        kind: 'target-' + kind,
        'info': info,
        'field_sources': {k: ['demo-source'] for k in info},
        'sources_ok': ['demo-source', 'demo-source-2'],
        'sources_failed': {'flaky-source': 'timeout'},
        'field_count': len(info),
        'success': True,
    }
    result.update(extra)
    return result


V4_RESULTS = {
    'url': envelope('url', {
        'url': 'http://example.com/', 'final_url': 'https://example.com/',
        'domain': 'example.com', 'scheme': 'http', 'host': 'example.com',
        'port': 80, 'redirect_count': 1, 'host_is_ip': False,
        'http_status': 200, 'http_title': 'Example', 'http_server': 'nginx',
        'content_type': 'text/html', 'gsb_malicious': False,
        'vt_malicious': 2, 'vt_suspicious': 1, 'malicious_score': 5,
        'urlscan_total': 12, 'urlscan_last_scan': '2026-01-02',
        'wayback_captures': 340, 'wayback_first_capture': '2015-01-01',
        'redirect_chain': [{'url': 'http://example.com/', 'status': 301},
                           {'url': 'https://example.com/', 'status': 200}],
    }),
    'crypto': envelope('crypto', {
        'address': '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
        'chain': 'bitcoin', 'blockchair_type': 'address',
        'btc_balance': 3.2, 'btc_total_received': 10.0,
        'btc_total_sent': 6.8, 'btc_tx_count': 42,
        'first_seen': '2017-03-04', 'last_seen': '2026-01-01',
        'blockstream_tx_count': 42, 'blockstream_mempool_txs': 0,
        'blockchair_balance': 3.2, 'blockchair_tx_count': 42,
        'eth_balance': 1.5, 'eth_tx_sample_count': 3,
        'eth_tx_first_seen': '2020-01-01', 'eth_tx_last_seen': '2026-01-01',
    }),
    'hash': envelope('hash', {
        'hash': '44d88612fea8a8f36de82e1278abb02f', 'algorithm': 'md5',
        'file_name': 'sample.exe', 'file_size': 512000,
        'file_type_mime': 'application/x-dos',
        'malware_family': 'Emotet', 'vt_threat_label': 'trojan.emotet',
        'malware_tags': ['emotet', 'loader'], 'imphash': 'abc123',
        'malicious': 45, 'suspicious': 2, 'undetected': 8,
        'malicious_score': 80, 'reputation': -4.2,
        'first_seen': '2019-06-01', 'last_seen': '2026-02-02',
        'otx_pulses': 7, 'known_file': False,
    }),
    'cve': envelope('cve', {
        'cve': 'CVE-2021-44228', 'vuln_status': 'Analyzed',
        'cna_state': 'Finalized', 'description': 'Log4Shell RCE',
        'cvss_score': 10.0, 'cvss_severity': 'CRITICAL',
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L', 'cvss_version': '3.1',
        'epss_score': 0.97, 'epss_percentile': 0.99,
        'published': '2021-12-10', 'last_modified': '2023-01-01',
        'cwe': 'CWE-502', 'osv_severity_vector': 'CVSS',
        'references': ['https://nvd.example/1', 'https://nvd.example/2'],
        'affected_cpes': ['cpe:2.3:a:apache:log4j:2.14.1'],
        'cpe_count': 1, 'osv_packages': ['Maven:org.apache.logging.log4j'],
    }),
    'asn': envelope('asn', {
        'asn_display': 'AS15169', 'asn_name': 'GOOGLE',
        'asn_description': 'Google LLC', 'asn_country': 'US',
        'asn_website': 'https://google.com', 'asn_email': 'noc@google.com',
        'announced_prefix_count': 2, 'announced_v4_count': 2,
        'announced_v6_count': 0, 'peer_count': 2,
        'announced_prefixes': ['8.8.8.0/24', '8.8.4.0/24'],
        'peers': ['AS3356', 'AS1299'],
    }),
}

V5_RESULTS = {
    'mac': envelope('mac', {
        'vendor': 'Raspberry Pi Trading Ltd', 'oui': 'B8:27:EB',
        'vendor_country': 'GB', 'assignment_type': 'OUI',
        'is_multicast': False, 'is_locally_administered': False,
        'transmission': 'unicast', 'assignment': 'OUI',
        'randomization_hint': 'stable', 'eui64_expansion':
        'b827:ebff:fe11:2233',
    }),
    'iban': envelope('iban', {
        'country_name': 'Germany', 'country_code': 'DE',
        'bank_code': '37040044', 'bank_name': 'Commerzbank',
        'bic': 'COBADEFFXXX', 'structure_ok': True, 'checksum_valid': True,
        'expected_length': 22, 'length': 22, 'check_digits': '89',
        'formatted': 'DE89 3704 0044 0532 0130 00',
        'masked_iban': 'DE89 **** *** 0130 00', 'bban': '370400440532013000',
    }),
    'imei': envelope('imei', {
        'imei_type': 'IMEI', 'tac': '35693803',
        'reporting_body_identifier': '35', 'reporting_body': 'BABT',
        'serial_number': '564380', 'check_digit': '9',
        'expected_check_digit': '9', 'luhn_valid': True,
        'formatted': '35-693803-564380-9', 'manufacturer': 'Apple',
        'model': 'iPhone 14',
    }),
    'coords': envelope('coords', {
        'latitude': 48.8584, 'longitude': 2.2945,
        'coords_display': '48.8584, 2.2945', 'latitude_dms': "48°51'30\"N",
        'longitude_dms': "2°17'40\"E", 'geohash': 'u09twn',
        'formatted_address': 'Tour Eiffel, Paris', 'city': 'Paris',
        'country': 'France', 'country_code': 'FR', 'elevation_m': 33,
        'nearest_country': 'France', 'nearest_country_distance_km': 0.1,
        'solar_altitude_deg': 42.5, 'is_daylight': True,
    }),
}

V6_RESULTS = {
    'vin': envelope('vin', {
        'wmi': '1G1', 'manufacturer': 'Chevrolet', 'country': 'USA',
        'region_hint': 'North America', 'vds': 'PE2268', 'vis': 'X5100010',
        'year_code': '5', 'model_year': 2005, 'plant_code': 'X',
        'serial_number': '5100010', 'check_digit': '8',
        'check_digit_valid': True, 'vpic_make': 'CHEVROLET',
        'vpic_model': 'Corvette', 'vpic_body_class': 'Convertible',
        'vpic_manufacturer': 'GENERAL MOTORS', 'vpic_plant_city': 'Bowling Green',
    }),
    'flight': envelope('flight', {
        'airline_name': 'Lufthansa', 'airline_iata': 'LH',
        'airline_icao': 'DLH', 'country': 'Germany', 'callsign': 'LUFTHANSA',
        'carrier_code': 'LH', 'carrier_code_type': 'IATA',
        'flight_number_digits': 400, 'digit_count': 3,
        'suffix_letter': '', 'direction_hint': 'even = eastbound',
        'avstack_status': 'scheduled', 'avstack_airline': 'Lufthansa',
        'avstack_departure_airport': 'Frankfurt',
        'avstack_departure_iata': 'FRA', 'avstack_arrival_iata': 'JFK',
    }),
    'mmsi': envelope('mmsi', {
        'station_type': 'Ship', 'station_type_code': '2', 'itu_series': 'MID',
        'mid': '211', 'country': 'Germany', 'serial_digits': '000001',
    }),
    'app': envelope('app', {
        'ecosystem': 'pypi', 'ecosystem_label': 'Python (PyPI)',
        'registry_url': 'https://pypi.org/pypi/requests/',
        'namespace': '', 'package_name': 'requests', 'name': 'requests',
        'version': '2.31.0', 'latest_version': '2.32.0',
        'summary': 'HTTP library', 'author': 'Kenneth Reitz',
        'requires_python': '>=3.7', 'license': 'Apache-2.0',
        'vulnerabilities_count': 1, 'stars': 51000, 'downloads': 1000000,
        'vulnerability_ids': [
            {'id': 'GHSA-9wx4-h78v-9563', 'severity': 'high',
             'summary': 'Proxy bypass'},
        ],
    }),
    'bssid': envelope('bssid', {
        'vendor': 'Raspberry Pi Trading Ltd', 'oui_prefix': 'B8:27:EB',
        'transmission': 'unicast', 'assignment': 'OUI',
        'is_multicast': False, 'is_locally_administered': False,
        'eui64_expansion': 'b827:ebff:fe11:2233',
        'ipv6_link_local_hint': 'fe80::ba27:ebff:fe11:2233',
        'lat': 52.2, 'lon': 0.1, 'accuracy_range': 40, 'time': '2026-01-01',
        'ssid': 'home-net', 'encryption': 'WPA2', 'last_seen': '2026-01-02',
    }),
    'plate': envelope('plate', {
        'normalized': 'MAB1234', 'country_prefix': 'D',
        'country_known': True, 'matched_count': 2,
        'match_note': 'two plausible formats', 'length': 7,
        'letters_count': 3, 'digits_count': 4, 'separators': 0,
        'composition_note': '3 letters + 4 digits',
        'german_city_code': 'MA', 'german_city': 'Mannheim',
        'style_hint': 'EU long format',
        'matched_countries': [
            {'country': 'Germany', 'region': 'Baden-Württemberg',
             'example': 'M-AB 1234', 'confidence': 0.9},
            {'country': 'Austria', 'region': '', 'example': 'A-123',
             'confidence': 0.4},
        ],
    }),
}


# ---------------------------------------------------------------------------
# Core kinds (already partially covered by test_reports.py — here we go deep)
# ---------------------------------------------------------------------------

class TestIpSections:
    def test_full_envelope_renders_all_grid_blocks(self):
        sections = assert_well_formed(ip_sections(ip_result()))
        for title in ('Location', 'Network', 'Registry (RDAP)',
                      'Exposure (InternetDB)', 'Threat Intelligence',
                      'Other Fields', 'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Location', 'Country') == 'United States'
        assert grid_value(sections, 'Location', 'City') == 'Mountain View'
        assert grid_value(sections, 'Network', 'ASN') == 'AS15169'
        assert grid_value(sections, 'Registry (RDAP)', 'CIDR Range') == \
            '8.8.8.0/24'
        assert grid_value(sections, 'Threat Intelligence', 'Datacenter IP') \
            == 'yes'

    def test_grid_falsy_values_are_dropped(self):
        sections = ip_sections(ip_result())
        location = by_title(sections, 'Location')['data']
        assert 'Is EU' not in location          # False is skipped
        assert 'Reverse DNS (PTR)' in location  # truthy string kept

    def test_other_fields_collects_unmapped_keys_only(self):
        sections = ip_sections(ip_result())
        other = by_title(sections, 'Other Fields')['data']
        assert other['Analyst Note'] == 'manual triage note'
        assert 'Country' not in other  # already used by the Location grid

    def test_plumbing_fields_never_rendered(self):
        sections = ip_sections(ip_result())
        labels = {k for s in sections if s['type'] == 'grid'
                  for k in s['data']}
        assert 'Field Sources' not in labels
        assert 'Provenance' not in labels

    def test_sources_table_rows_ok_then_failed(self):
        rows = by_title(ip_sections(ip_result()), 'Sources Queried')['rows']
        assert ['ipwho.is', 'OK'] in rows
        assert ['rdap', 'OK'] in rows
        assert ['ip-api.com', 'timeout'] in rows
        assert rows.index(['ipwho.is', 'OK']) < rows.index(['ip-api.com',
                                                            'timeout'])

    def test_sources_table_omitted_without_source_data(self):
        result = ip_result(sources_ok=[], sources_failed={})
        sections = ip_sections(result)
        assert all(s['title'] != 'Sources Queried' for s in sections)

    @pytest.mark.parametrize('result', [{}, {'info': {}},
                                        {'info': {}, 'sources_ok': []}])
    def test_empty_envelope_returns_no_sections(self, result):
        assert ip_sections(result) == []


class TestPhoneSections:
    def test_full_envelope(self):
        sections = assert_well_formed(phone_sections(phone_result()))
        details = by_title(sections, 'Phone Details')['data']
        assert details['E.164 Format'] == '+15551234567'
        assert details['Carrier'] == 'Verizon'
        assert details['Is Mobile'] == 'yes'
        assert details['Type'] == 'MOBILE'

    def test_hints_render_analyst_notes_table(self):
        rows = by_title(phone_sections(phone_result()),
                        'Analyst Notes')['rows']
        assert rows == [['carrier lookup used local numbering plan']]

    def test_all_collected_fields_grid_present(self):
        grid = by_title(phone_sections(phone_result()),
                       'All Collected Fields')['data']
        assert grid['Primary Timezone'] == 'America/New_York'
        # hints get their own table *and* appear in the catch-all grid
        assert grid['Analyst Notes'] == 'carrier lookup used local numbering plan'

    def test_falsy_phone_fields_dropped_from_grids(self):
        facts = by_title(phone_sections(phone_result()),
                         'Phone Details')['data']
        assert 'Is VoIP' not in facts   # False is skipped by _grid
        assert 'Is Mobile' in facts

    def test_empty_envelope_returns_no_sections(self):
        assert phone_sections({'info': {}}) == []

    def test_minimal_info_still_well_formed(self):
        sections = assert_well_formed(phone_sections(
            {'info': {'e164': '+15551234567'}, 'sources_ok': ['libphonenumber']}))
        assert grid_value(sections, 'Phone Details', 'E.164 Format') == \
            '+15551234567'


class TestUsernameSections:
    def test_summary_grid_counts(self):
        sections = assert_well_formed(username_sections(username_result()))
        summary = by_title(sections, 'Summary')['data']
        assert summary['Username'] == 'alice'
        assert summary['Confirmed'] == 2
        assert summary['Ruled out'] == 1
        assert summary['Inconclusive'] == 1
        assert summary['Platforms checked'] == 4
        assert summary['Profile fields'] == 3

    def test_confirmed_table_with_confidence(self):
        rows = by_title(username_sections(username_result()),
                        'Confirmed (2)')['rows']
        assert ['Keybase', 'https://keybase.io/alice', 'high',
                'api 200'] in rows
        assert ['GitHub', 'https://github.com/alice', 'medium', '200'] in rows

    def test_profile_details_label_fields(self):
        rows = by_title(username_sections(username_result()),
                        'Profile Details')['rows']
        assert ['Keybase', 'Location', 'Wonderland'] in rows
        assert ['GitHub', 'Public Repos', 12] in rows  # ints stay ints

    def test_not_found_and_unknown_buckets(self):
        sections = username_sections(username_result())
        assert by_title(sections, 'Ruled Out (1)')['rows'] == \
            [['HackerNews', '404']]
        assert by_title(sections, 'Inconclusive (1) - not hits')['rows'] == \
            [['Reddit', 'bot wall', 200]]  # status_code wins over error

    def test_unknown_without_status_code_uses_error(self):
        result = username_result()
        result['results'][3] = {'platform': 'Reddit', 'status': 'unknown',
                                'reason': 'shell', 'error': 'timeout'}
        rows = by_title(username_sections(result),
                        'Inconclusive (1) - not hits')['rows']
        assert rows[0][2] == 'timeout'

    def test_empty_results_still_renders_summary(self):
        sections = assert_well_formed(username_sections(
            {'username': 'nobody', 'results': []}))
        assert len(sections) == 1
        assert by_title(sections, 'Summary')['data']['Confirmed'] == 0


class TestEmailSections:
    def test_key_facts_grid(self):
        sections = assert_well_formed(email_sections(email_result()))
        facts = by_title(sections, 'Key Facts')['data']
        assert facts['Email'] == 'user@example.com'
        assert facts['DMARC Policy'] == 'reject'
        assert facts['MX Exists'] == 'yes'
        assert 'Disposable Email' not in facts  # False is dropped by _grid

    def test_breach_table_formats_counts(self):
        rows = by_title(email_sections(email_result()),
                        'Data Breaches (2)')['rows']
        assert rows[0] == ['ExampleBreach', '2021-02-03', '12,345',
                           'Emails, Passwords']
        assert rows[1] == ['OtherBreach', '2019-01-01', '?', '']  # falsy
        # pwn_count dropped from the falsy check, '?' placeholder kept

    def test_pastes_table(self):
        rows = by_title(email_sections(email_result()), 'Pastes (1)')['rows']
        assert rows == [['2020-05-05', 42]]

    def test_all_collected_fields_and_sources(self):
        sections = email_sections(email_result())
        assert 'All Collected Fields' in [s['title'] for s in sections]
        rows = by_title(sections, 'Sources Queried')['rows']
        assert ['hunter', 'no api key'] in rows

    def test_empty_envelope_returns_no_sections(self):
        assert email_sections({'info': {}}) == []


class TestDomainSections:
    def test_full_envelope(self):
        sections = assert_well_formed(domain_sections(domain_result()))
        for title in ('Registration', 'DNS & Mail Security', 'Web Presence',
                      'Certificate Transparency',
                      'Subdomains (Certificate Transparency)',
                      'Missing Security Headers', 'Other Fields',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Registration', 'Registrar') == \
            'Example Registrar'
        assert grid_value(sections, 'DNS & Mail Security', 'DNSSEC Signed') \
            == 'yes'
        assert grid_value(sections, 'Web Presence', 'HTTP Status') == '200'

    def test_subdomain_table_rows(self):
        rows = by_title(domain_sections(domain_result()),
                        'Subdomains (Certificate Transparency)')['rows']
        assert ['www.example.com'] in rows
        assert ['api.example.com'] in rows

    def test_missing_security_headers_table(self):
        rows = by_title(domain_sections(domain_result()),
                        'Missing Security Headers')['rows']
        assert rows == [['content-security-policy']]

    def test_other_fields_excludes_used_and_list_fields(self):
        other = by_title(domain_sections(domain_result()),
                         'Other Fields')['data']
        assert other['Custom Field'] == 'extra intelligence'
        assert 'Registrar' not in other
        assert 'Security Headers' not in other  # subdomain/headers bucketed

    def test_empty_envelope_returns_no_sections(self):
        assert domain_sections({'info': {}}) == []


class TestBatchSections:
    def test_rows_summarise_each_result(self):
        results = [ip_result(), ip_result(ip='1.1.1.1')]
        sections = assert_well_formed(batch_sections('ip', results))
        table = sections[0]
        assert table['title'] == 'Batch ip results (2)'
        assert table['columns'] == ['Target', 'Sources', 'Fields',
                                    'Country/Registrar', 'City/Org']
        assert table['rows'][0] == ['8.8.8.8', 2, 20, 'United States',
                                    'Mountain View']
        assert table['rows'][1][0] == '1.1.1.1'

    def test_target_falls_back_to_target_key(self):
        results = [{'target': 'example.com', 'sources_ok': ['rdap'],
                    'field_count': 1,
                    'info': {'registrar': 'Example Inc'}}]
        rows = batch_sections('domain', results)[0]['rows']
        assert rows[0] == ['example.com', 1, 1, 'Example Inc', '']

    def test_empty_results_list(self):
        sections = batch_sections('ip', [])
        assert sections[0]['title'] == 'Batch ip results (0)'
        assert sections[0]['rows'] == []


# ---------------------------------------------------------------------------
# v4.0 kinds
# ---------------------------------------------------------------------------

class TestUrlSections:
    def test_full_envelope(self):
        sections = assert_well_formed(url_sections(V4_RESULTS['url']))
        for title in ('URL', 'HTTP Response', 'Verdicts', 'History',
                      'Redirect Chain (2 hops)', 'Other Fields',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'URL', 'Final URL') == \
            'https://example.com/'
        assert grid_value(sections, 'Verdicts', 'Threat Score %') == '5'

    def test_redirect_chain_rows(self):
        rows = by_title(url_sections(V4_RESULTS['url']),
                        'Redirect Chain (2 hops)')['rows']
        assert rows == [['http://example.com/', 301],
                        ['https://example.com/', 200]]

    def test_empty_envelope(self):
        assert url_sections({'info': {}}) == []


class TestCryptoSections:
    def test_full_envelope(self):
        sections = assert_well_formed(crypto_sections(V4_RESULTS['crypto']))
        for title in ('Address', 'Activity (blockchain.info)',
                      'Activity (blockstream.info)', 'Activity (blockchair)',
                      'Activity (etherscan)', 'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Address', 'Chain') == 'bitcoin'
        assert grid_value(sections, 'Activity (blockchain.info)',
                          'BTC Transactions') == '42'

    def test_empty_envelope(self):
        assert crypto_sections({'info': {}}) == []


class TestHashSections:
    def test_full_envelope(self):
        sections = assert_well_formed(hash_sections(V4_RESULTS['hash']))
        for title in ('Hash', 'Malware Classification', 'Detections',
                      'Sightings', 'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Hash', 'Hash Algorithm') == 'md5'
        assert grid_value(sections, 'Malware Classification',
                          'Malware Family') == 'Emotet'

    def test_empty_envelope(self):
        assert hash_sections({'info': {}}) == []


class TestCveSections:
    def test_full_envelope(self):
        sections = assert_well_formed(cve_sections(V4_RESULTS['cve']))
        for title in ('Identifier', 'Description', 'Scoring', 'Timeline',
                      'Weakness & Reach', 'References (2)',
                      'Affected Products (1)', 'Affected Packages (1)',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Identifier', 'CVE ID') == \
            'CVE-2021-44228'
        assert grid_value(sections, 'Scoring', 'CVSS Severity') == 'CRITICAL'

    def test_reference_and_cpe_rows(self):
        sections = cve_sections(V4_RESULTS['cve'])
        assert by_title(sections, 'References (2)')['rows'] == \
            [['https://nvd.example/1'], ['https://nvd.example/2']]
        assert by_title(sections, 'Affected Products (1)')['rows'] == \
            [['cpe:2.3:a:apache:log4j:2.14.1']]

    def test_cpe_count_drives_title(self):
        result = envelope('cve', {'cve': 'CVE-2020-1', 'affected_cpes': ['a', 'b'],
                                  'cpe_count': 9})
        assert 'Affected Products (9)' in [s['title'] for s in
                                            cve_sections(result)]

    def test_empty_envelope(self):
        assert cve_sections({'info': {}}) == []


class TestAsnSections:
    def test_full_envelope(self):
        sections = assert_well_formed(asn_sections(V4_RESULTS['asn']))
        for title in ('Identity', 'Footprint', 'Announced Prefixes (2)',
                      'Peers (2)', 'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Identity', 'AS Name') == 'GOOGLE'
        assert grid_value(sections, 'Footprint', 'BGP Peer Count') == '2'

    def test_prefix_and_peer_rows(self):
        sections = asn_sections(V4_RESULTS['asn'])
        assert by_title(sections, 'Announced Prefixes (2)')['rows'] == \
            [['8.8.8.0/24'], ['8.8.4.0/24']]
        assert by_title(sections, 'Peers (2)')['rows'] == \
            [['AS3356'], ['AS1299']]

    def test_empty_envelope(self):
        assert asn_sections({'info': {}}) == []


# ---------------------------------------------------------------------------
# v5.0 kinds
# ---------------------------------------------------------------------------

class TestMacSections:
    def test_full_envelope(self):
        sections = assert_well_formed(mac_sections(V5_RESULTS['mac']))
        for title in ('Identity', 'Network Hints', 'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Identity', 'Vendor') == \
            'Raspberry Pi Trading Ltd'
        assert grid_value(sections, 'Network Hints', 'Transmission') == \
            'unicast'
        assert 'Is Multicast' not in by_title(sections, 'Network Hints')['data']

    def test_empty_envelope(self):
        assert mac_sections({'info': {}}) == []


class TestIbanSections:
    def test_full_envelope(self):
        sections = assert_well_formed(iban_sections(V5_RESULTS['iban']))
        for title in ('Issuing Bank', 'Structure & Format',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Issuing Bank', 'Bank Name') == \
            'Commerzbank'
        assert grid_value(sections, 'Structure & Format',
                          'Checksum Valid') == 'yes'

    def test_empty_envelope(self):
        assert iban_sections({'info': {}}) == []


class TestImeiSections:
    def test_full_envelope(self):
        sections = assert_well_formed(imei_sections(V5_RESULTS['imei']))
        for title in ('Decomposition (3GPP TS 23.003)', 'Device',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Decomposition (3GPP TS 23.003)',
                          'Luhn Valid') == 'yes'
        assert grid_value(sections, 'Device', 'Model') == 'iPhone 14'

    def test_empty_envelope(self):
        assert imei_sections({'info': {}}) == []


class TestCoordsSections:
    def test_full_envelope(self):
        sections = assert_well_formed(coords_sections(V5_RESULTS['coords']))
        for title in ('Position', 'Place & Terrain',
                      'Solar Position (photo cross-check)',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Position', 'Latitude') == '48.8584'
        assert grid_value(sections, 'Place & Terrain', 'City') == 'Paris'

    def test_empty_envelope(self):
        assert coords_sections({'info': {}}) == []


# ---------------------------------------------------------------------------
# v6.0 kinds
# ---------------------------------------------------------------------------

class TestVinSections:
    def test_full_envelope(self):
        sections = assert_well_formed(vin_sections(V6_RESULTS['vin']))
        for title in ('Identity', 'ISO 3779 Decomposition', 'Vehicle (NHTSA vPIC)',
                      'Assembly Plant', 'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Identity', 'Manufacturer') == 'Chevrolet'
        assert grid_value(sections, 'Vehicle (NHTSA vPIC)',
                          'Vpic Model') == 'Corvette'

    def test_empty_envelope(self):
        assert vin_sections({'info': {}}) == []


class TestFlightSections:
    def test_full_envelope(self):
        sections = assert_well_formed(flight_sections(V6_RESULTS['flight']))
        for title in ('Airline', 'Designator Anatomy', 'Live Status (aviationstack)',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Airline', 'Airline Name') == 'Lufthansa'
        assert grid_value(sections, 'Designator Anatomy',
                          'Direction Hint') == 'even = eastbound'

    def test_empty_envelope(self):
        assert flight_sections({'info': {}}) == []


class TestMmsiSections:
    def test_full_envelope(self):
        sections = assert_well_formed(mmsi_sections(V6_RESULTS['mmsi']))
        for title in ('Station Identity (ITU-R M.1085)',
                      'Flag State & Serial', 'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Station Identity (ITU-R M.1085)',
                          'Station Type') == 'Ship'
        assert grid_value(sections, 'Flag State & Serial', 'Country') == \
            'Germany'

    def test_empty_envelope(self):
        assert mmsi_sections({'info': {}}) == []


class TestAppSections:
    def test_full_envelope(self):
        sections = assert_well_formed(app_sections(V6_RESULTS['app']))
        for title in ('Identity', 'Registry Record', 'Security (OSV.dev)',
                      'Community & Maintenance', 'Known Vulnerabilities (1)',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Registry Record', 'Latest Version') == \
            '2.32.0'
        assert grid_value(sections, 'Community & Maintenance', 'Stars') == \
            '51000'

    def test_vulnerability_rows(self):
        rows = by_title(app_sections(V6_RESULTS['app']),
                        'Known Vulnerabilities (1)')['rows']
        assert rows == [['GHSA-9wx4-h78v-9563', 'high', 'Proxy bypass']]

    def test_vulnerability_ids_with_non_dict_entries(self):
        result = envelope('app', {'vulnerability_ids': ['GHSA-x', 42],
                                  'vulnerabilities_count': 0})
        sections = app_sections(result)
        assert all('Known Vulnerabilities' not in s['title'] for s in sections)

    def test_empty_envelope(self):
        assert app_sections({'info': {}}) == []


class TestBssidSections:
    def test_full_envelope(self):
        sections = assert_well_formed(bssid_sections(V6_RESULTS['bssid']))
        for title in ('Identity', 'Address Anatomy (EUI-48)',
                      'Location (crowd-sourced)', 'Network (WiGLE)',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'Network (WiGLE)', 'Ssid') == 'home-net'
        assert grid_value(sections, 'Location (crowd-sourced)', 'Lat') == \
            '52.2'

    def test_empty_envelope(self):
        assert bssid_sections({'info': {}}) == []


class TestPlateSections:
    def test_full_envelope(self):
        sections = assert_well_formed(plate_sections(V6_RESULTS['plate']))
        for title in ('Format Analysis', 'Composition', 'German City Code',
                      'Style Heuristic', 'Matched Jurisdictions (2)',
                      'Sources Queried'):
            by_title(sections, title)
        assert grid_value(sections, 'German City Code', 'German City') == \
            'Mannheim'

    def test_matched_jurisdictions_confidence_formatting(self):
        rows = by_title(plate_sections(V6_RESULTS['plate']),
                        'Matched Jurisdictions (2)')['rows']
        assert rows[0] == ['Germany', 'Baden-Württemberg', 'M-AB 1234', '0.9']
        assert rows[1][3] == '0.4'

    def test_empty_envelope(self):
        assert plate_sections({'info': {}}) == []


# ---------------------------------------------------------------------------
# sources_table + sections_for dispatch
# ---------------------------------------------------------------------------

class TestSourcesTable:
    def test_direct_call(self):
        table = sources_table({'sources_ok': ['a', 'b'],
                               'sources_failed': {'c': 'down'}})
        assert table['title'] == 'Sources Queried'
        assert table['columns'] == ['Source', 'Status']
        assert table['rows'] == [['a', 'OK'], ['b', 'OK'], ['c', 'down']]

    def test_missing_keys_default_to_empty(self):
        assert sources_table({})['rows'] == []
        assert sources_table({'sources_ok': ['a']})['rows'] == [['a', 'OK']]


POPULATED = dict(V4_RESULTS, **V5_RESULTS, **V6_RESULTS, **{
    'ip': ip_result(), 'phone': phone_result(),
    'username': username_result(), 'email': email_result(),
    'domain': domain_result(),
})

BUILDERS = {
    'ip': ip_sections, 'phone': phone_sections,
    'username': username_sections, 'email': email_sections,
    'domain': domain_sections, 'url': url_sections,
    'crypto': crypto_sections, 'hash': hash_sections,
    'cve': cve_sections, 'asn': asn_sections, 'mac': mac_sections,
    'iban': iban_sections, 'imei': imei_sections, 'coords': coords_sections,
    'vin': vin_sections, 'flight': flight_sections, 'mmsi': mmsi_sections,
    'app': app_sections, 'bssid': bssid_sections, 'plate': plate_sections,
}


class TestSectionsForDispatch:
    @pytest.mark.parametrize('kind', sorted(BUILDERS))
    def test_dispatches_to_the_kind_builder(self, kind):
        result = POPULATED[kind]
        assert sections_for(kind, result) == BUILDERS[kind](result)

    @pytest.mark.parametrize('kind', sorted(BUILDERS))
    def test_populated_envelope_yields_well_formed_sections(self, kind):
        sections = assert_well_formed(sections_for(kind, POPULATED[kind]))
        assert sections, f'{kind} produced no sections'

    @pytest.mark.parametrize('kind', sorted(BUILDERS))
    def test_empty_info_yields_well_formed_output(self, kind):
        sections = assert_well_formed(sections_for(kind, {'info': {}}))
        assert isinstance(sections, list)

    @pytest.mark.parametrize('kind', ['nope', '', 'IP', 'ipv4', 'usernames'])
    def test_unknown_kind_returns_empty_list(self, kind):
        assert sections_for(kind, POPULATED['ip']) == []


class TestValueFormattingEdgeCases:
    """fmt_value / label routing through the grid builders."""

    def test_junk_values_tolerated_in_info(self):
        info = {
            'flag_bool': True, 'flag_false': False, 'zero': 0, 'minus': -1,
            'empty_str': '', 'none': None, 'empty_list': [],
            'a_list': ['x', 'y'], 'a_dict': {'k': 'v'},
            'long': 'z' * 300, 'plain': 'text',
        }
        sections = assert_well_formed(ip_sections({'info': info}))
        other = by_title(sections, 'Other Fields')['data']
        assert other['Flag Bool'] == 'yes'
        assert other['Minus'] == '-1'
        assert other['A List'] == 'x, y'
        assert other['A Dict'] == '{"k": "v"}'
        assert other['Long'] == 'z' * 300
        # falsy values dropped entirely
        for absent in ('Flag False', 'Zero', 'Empty Str', 'None',
                       'Empty List'):
            assert absent not in other

    def test_unknown_keys_fall_back_to_title_case(self):
        sections = ip_sections({'info': {'weird_custom_key': 'v'}})
        other = by_title(sections, 'Other Fields')['data']
        assert other['Weird Custom Key'] == 'v'

    def test_nested_list_of_dicts_uses_str_joining(self):
        sections = ip_sections({'info': {'coordinates': [
            {'source': 'a', 'lat': 1.0, 'lon': 2.0}]}})
        other = by_title(sections, 'Other Fields')['data']
        # lists are comma-joined via str(); dicts only become JSON at top level
        assert other['Coordinates'].startswith("{'source'")
