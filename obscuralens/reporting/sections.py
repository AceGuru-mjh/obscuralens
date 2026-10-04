"""
Report section builders shared by the interactive console and the CLI.

Each tracker result is turned into a list of sections understood by
ReportGenerator (grid / table / text / status) so HTML, Markdown and PDF
exports show the same structure everywhere.
"""

from typing import Any, Dict, List

from ..utils.formatting import fmt_value, label, rows_from_fields


def _grid(title: str, keys: Any, info: Dict[str, Any]) -> Dict[str, Any]:
    clean: Dict[str, Any] = {}
    for key in keys:
        value = info.get(key)
        if value not in (None, '', [], {}, False):
            clean[label(key)] = fmt_value(key, value)
    return {'title': title, 'type': 'grid', 'data': clean}


def _fields_grid(title: str, info: Dict[str, Any]) -> Dict[str, Any]:
    """Grid of every populated field, using human labels."""
    clean = {row[0]: row[1] for row in rows_from_fields(info)}
    return {'title': title, 'type': 'grid', 'data': clean}


def sources_table(result: Dict[str, Any]) -> Dict[str, Any]:
    rows = [[s, 'OK'] for s in result.get('sources_ok', [])]
    rows += [[s, err] for s, err in result.get('sources_failed', {}).items()]
    return {'title': 'Sources Queried', 'type': 'table',
            'columns': ['Source', 'Status'], 'rows': rows}


def ip_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Location', ('reverse_dns', 'country', 'country_code', 'region',
                      'city', 'postal', 'latitude', 'longitude', 'timezone',
                      'is_eu', 'current_time')),
        ('Network', ('asn', 'asn_full', 'org', 'isp', 'domain', 'is_proxy')),
        ('Registry (RDAP)', ('rdap_name', 'rdap_org', 'rdap_cidr', 'rdap_range',
                             'rdap_registered', 'rdap_abuse_name',
                             'rdap_abuse_email', 'rdap_abuse_phone',
                             'rdap_address', 'rdap_country', 'rdap_status')),
        ('Exposure (InternetDB)', ('ports', 'vulns', 'cpes', 'hostnames', 'tags')),
        ('Threat Intelligence', ('reputation', 'malicious', 'suspicious',
                                 'harmless', 'undetected', 'malicious_score',
                                 'abuse_confidence', 'abuse_total_reports',
                                 'usage_type', 'is_tor', 'is_vpn', 'is_abuser',
                                 'is_datacenter')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _grid('Other Fields', (), info)
    rest['data'] = {row[0]: row[1] for row in rows_from_fields(info)
                    if row[0] not in _used_labels(sections)}
    if rest['data']:
        sections.append(rest)

    if result.get('sources_ok') or result.get('sources_failed'):
        sections.append(sources_table(result))
    return sections


def _used_labels(sections: List[Dict[str, Any]]) -> set:
    used = set()
    for section in sections:
        if section['type'] == 'grid':
            used.update(section['data'].keys())
    return used


def phone_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections = [_grid('Phone Details', (
        'original_number', 'e164', 'international', 'national_format',
        'rfc3966', 'country_code', 'region_code', 'type', 'valid_format',
        'possible', 'is_mobile', 'is_voip', 'is_toll_free', 'carrier',
        'location', 'primary_timezone', 'timezone_count', 'number_length'),
        info)]
    if info.get('hints'):
        sections.append({'title': 'Analyst Notes', 'type': 'table',
                         'columns': ['Hint'],
                         'rows': [[hint] for hint in info['hints']]})
    sections.append(_fields_grid('All Collected Fields', info))
    return [s for s in sections if s.get('data') or s.get('rows')]


def username_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = [{
        'title': 'Summary', 'type': 'grid',
        'data': {
            'Username': result.get('username'),
            'Confirmed': result.get('found_count', 0),
            'Ruled out': result.get('not_found_count', 0),
            'Inconclusive': result.get('unknown_count', 0),
            'Platforms checked': result.get('total_checked', 0),
            'Profile fields': result.get('total_fields', 0),
        },
    }]

    found = [r for r in result.get('results', []) if r.get('status') == 'found']
    if found:
        sections.append({
            'title': f'Confirmed ({len(found)})', 'type': 'table',
            'columns': ['Platform', 'URL', 'Confidence', 'Reason'],
            'rows': [[r['platform'], r.get('url', ''), r.get('confidence', ''),
                      r.get('reason', '')] for r in found],
        })
        profiles = [(r['platform'], r.get('profile') or {}) for r in found]
        profiles = [(name, prof) for name, prof in profiles if prof]
        if profiles:
            sections.append({
                'title': 'Profile Details', 'type': 'table',
                'columns': ['Platform', 'Field', 'Value'],
                'rows': [[name, label(k), v]
                         for name, prof in profiles
                         for k, v in prof.items()],
            })

    missing = [r for r in result.get('results', [])
               if r.get('status') == 'not_found']
    if missing:
        sections.append({
            'title': f'Ruled Out ({len(missing)})', 'type': 'table',
            'columns': ['Platform', 'Reason'],
            'rows': [[r['platform'], r.get('reason', '')] for r in missing],
        })

    unknown = [r for r in result.get('results', [])
               if r.get('status') not in ('found', 'not_found')]
    if unknown:
        sections.append({
            'title': f'Inconclusive ({len(unknown)}) - not hits', 'type': 'table',
            'columns': ['Platform', 'Reason', 'HTTP'],
            'rows': [[r['platform'], r.get('reason', ''),
                      r.get('status_code') or r.get('error', '')]
                     for r in unknown],
        })
    return sections


def email_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = [
        _grid('Key Facts', (
            'email', 'domain', 'valid_format', 'mx_exists', 'mx_count',
            'is_webmail', 'disposable', 'openpgp', 'gravatar', 'dnssec',
            'dmarc_policy', 'domain_created', 'domain_expires',
            'domain_age_days', 'registrar'), info),
    ]

    breaches = info.get('hibp_breaches')
    if breaches:
        sections.append({
            'title': f'Data Breaches ({len(breaches)})', 'type': 'table',
            'columns': ['Breach', 'Date', 'Accounts', 'Data Exposed'],
            'rows': [[b.get('name', '?'), b.get('date', '?'),
                      f"{b.get('pwn_count', 0):,}" if b.get('pwn_count') else '?',
                      ', '.join(b.get('data_classes') or [])]
                     for b in breaches],
        })
    pastes = info.get('pastes')
    if pastes:
        sections.append({
            'title': f'Pastes ({len(pastes)})', 'type': 'table',
            'columns': ['Date', 'Entries'],
            'rows': [[p.get('date', '?'), p.get('entries', '?')] for p in pastes],
        })

    sections.append(_fields_grid('All Collected Fields', info))
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def domain_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Registration', ('domain', 'registrar', 'domain_created',
                          'domain_age_days', 'domain_expires', 'expires_in_days',
                          'domain_status')),
        ('DNS & Mail Security', ('nameservers', 'dnssec', 'mx_records',
                                 'spf_record', 'spf_third_party', 'dmarc_policy',
                                 'dkim_selectors', 'caa_records', 'soa_record')),
        ('Web Presence', ('http_status', 'http_final_url', 'http_title',
                          'server', 'powered_by', 'robots_txt',
                          'security_headers', 'missing_security_headers')),
        ('Certificate Transparency', ('ct_certificates', 'ct_last_seen',
                                      'ct_revoked')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    if info.get('ct_subdomains'):
        sections.append({
            'title': 'Subdomains (Certificate Transparency)', 'type': 'table',
            'columns': ['Subdomain'],
            'rows': [[name] for name in info['ct_subdomains']],
        })
    if info.get('missing_security_headers'):
        sections.append({
            'title': 'Missing Security Headers', 'type': 'table',
            'columns': ['Header'],
            'rows': [[name] for name in info['missing_security_headers']],
        })

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def batch_sections(kind: str, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for r in results:
        info = r.get('info', {})
        rows.append([
            r.get(kind) or r.get('target') or '',
            len(r.get('sources_ok', [])),
            r.get('field_count', 0),
            info.get('country') or info.get('registrar') or info.get('carrier') or '',
            info.get('city') or info.get('org') or info.get('region_code') or '',
        ])
    return [{
        'title': f'Batch {kind} results ({len(results)})', 'type': 'table',
        'columns': ['Target', 'Sources', 'Fields', 'Country/Registrar', 'City/Org'],
        'rows': rows,
    }]


# ---------------------------------------------------------------------------
# v4.0 kinds
# ---------------------------------------------------------------------------

def url_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('URL', ('url', 'final_url', 'domain', 'scheme', 'host', 'port',
                 'redirect_count', 'host_is_ip')),
        ('HTTP Response', ('http_status', 'http_title', 'http_server',
                           'content_type')),
        ('Verdicts', ('gsb_malicious', 'gsb_threat_types', 'vt_malicious',
                      'vt_suspicious', 'vt_reputation', 'malicious_score',
                      'urlscan_malicious_verdicts')),
        ('History', ('urlscan_total', 'urlscan_last_scan',
                     'wayback_captures', 'wayback_first_capture',
                     'wayback_last_capture', 'vt_last_analysis')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    chain = info.get('redirect_chain') or []
    if chain:
        sections.append({
            'title': f'Redirect Chain ({len(chain)} hops)', 'type': 'table',
            'columns': ['URL', 'Status'],
            'rows': [[hop.get('url', ''), hop.get('status', '')] for hop in chain],
        })

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def crypto_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Address', ('address', 'chain', 'blockchair_type')),
        ('Activity (blockchain.info)', ('btc_balance', 'btc_total_received',
                                        'btc_total_sent', 'btc_tx_count',
                                        'first_seen', 'last_seen')),
        ('Activity (blockstream.info)', ('blockstream_funded_btc',
                                         'blockstream_spent_btc',
                                         'blockstream_tx_count',
                                         'blockstream_mempool_txs',
                                         'blockstream_last_activity')),
        ('Activity (blockchair)', ('blockchair_balance', 'blockchair_tx_count',
                                   'blockchair_first_seen_receiving',
                                   'blockchair_first_seen_spending',
                                   'blockchair_last_seen_receiving',
                                   'blockchair_last_seen_spending')),
        ('Activity (etherscan)', ('eth_balance', 'eth_tx_sample_count',
                                  'eth_tx_first_seen', 'eth_tx_last_seen')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def hash_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Hash', ('hash', 'algorithm', 'file_name', 'file_size',
                  'file_type_mime')),
        ('Malware Classification', ('malware_family', 'vt_threat_label',
                                    'malware_tags', 'imphash')),
        ('Detections', ('malicious', 'suspicious', 'undetected', 'harmless',
                        'malicious_score', 'reputation')),
        ('Sightings', ('first_seen', 'last_seen', 'vt_created', 'otx_pulses',
                       'known_file', 'otx_whitelisted')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def cve_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Identifier', ('cve', 'vuln_status', 'cna_state')),
        ('Description', ('description', 'cna_description', 'cna_title')),
        ('Scoring', ('cvss_score', 'cvss_severity', 'cvss_vector',
                     'cvss_version', 'epss_score', 'epss_percentile',
                     'epss_date')),
        ('Timeline', ('published', 'last_modified', 'cna_published',
                      'cna_updated')),
        ('Weakness & Reach', ('cwe', 'osv_severity_vector')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    references = info.get('references') or []
    if references:
        sections.append({
            'title': f'References ({len(references)})', 'type': 'table',
            'columns': ['URL'],
            'rows': [[url] for url in references],
        })
    cpes = info.get('affected_cpes') or []
    if cpes:
        sections.append({
            'title': f'Affected Products ({info.get("cpe_count", len(cpes))})',
            'type': 'table', 'columns': ['CPE'],
            'rows': [[cpe] for cpe in cpes],
        })
    packages = info.get('osv_packages') or []
    if packages:
        sections.append({
            'title': f'Affected Packages ({len(packages)})', 'type': 'table',
            'columns': ['Ecosystem / Package'],
            'rows': [[package] for package in packages],
        })

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def asn_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Identity', ('asn_display', 'asn_name', 'asn_description',
                      'asn_country', 'asn_website', 'asn_email')),
        ('Footprint', ('announced_prefix_count', 'announced_v4_count',
                       'announced_v6_count', 'ipv4_prefix_count',
                       'ipv6_prefix_count', 'peer_count')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    prefixes = info.get('announced_prefixes') or []
    if prefixes:
        count = info.get('announced_prefix_count', len(prefixes))
        sections.append({
            'title': f'Announced Prefixes ({count})',
            'type': 'table', 'columns': ['Prefix'],
            'rows': [[prefix] for prefix in prefixes],
        })
    peers = info.get('peers') or []
    if peers:
        peer_count = info.get('peer_count', len(peers))
        sections.append({
            'title': f'Peers ({peer_count})',
            'type': 'table', 'columns': ['Peer'],
            'rows': [[peer] for peer in peers],
        })

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


# ---------------------------------------------------------------------------
# v5.0 kinds
# ---------------------------------------------------------------------------

def mac_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Identity', ('vendor', 'oui', 'vendor_country', 'vendor_address',
                      'assignment_type', 'eui64_expansion')),
        ('Network Hints', ('is_multicast', 'is_locally_administered',
                           'transmission', 'assignment', 'randomization_hint',
                           'reserved_block', 'virtualization_hint',
                           'embedded_ipv4', 'ipv6_interface_id',
                           'ipv6_link_local_hint')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def iban_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Issuing Bank', ('country_name', 'country_code', 'bank_code',
                          'bank_name', 'bic')),
        ('Structure & Format', ('structure_ok', 'checksum_valid',
                                'expected_length', 'length', 'check_digits',
                                'formatted', 'masked_iban', 'bban',
                                'account_number')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def imei_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Decomposition (3GPP TS 23.003)',
         ('imei_type', 'tac', 'reporting_body_identifier', 'reporting_body',
          'serial_number', 'check_digit', 'expected_check_digit',
          'software_version', 'luhn_valid', 'formatted')),
        ('Device', ('manufacturer', 'model')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def coords_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Position', ('latitude', 'longitude', 'coords_display',
                      'latitude_dms', 'longitude_dms', 'coords_ddm', 'utm',
                      'mgrs', 'geohash', 'maidenhead', 'hemisphere')),
        ('Place & Terrain', ('formatted_address', 'place_name', 'city',
                             'locality', 'county', 'region', 'postcode',
                             'road', 'house_number', 'country', 'country_code',
                             'elevation_m', 'nearest_country',
                             'nearest_country_code',
                             'nearest_country_distance_km',
                             'timezone_offset_hint')),
        ('Solar Position (photo cross-check)',
         ('solar_altitude_deg', 'solar_azimuth_deg', 'is_daylight',
          'solar_sunrise_utc', 'solar_sunset_utc', 'solar_note')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


# ---------------------------------------------------------------------------
# v6.0 additions: vin / flight / mmsi / app / bssid / plate sections
# ---------------------------------------------------------------------------

def vin_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Identity', ('wmi', 'manufacturer', 'country', 'region_hint')),
        ('ISO 3779 Decomposition',
         ('vds', 'vis', 'year_code', 'model_year_candidates', 'model_year',
          'model_year_cycle', 'plant_code', 'serial_number', 'check_digit',
          'check_digit_valid', 'expected_check_digit')),
        ('Vehicle (NHTSA vPIC)',
         ('vpic_make', 'vpic_model', 'vpic_vehicle_type', 'vpic_body_class',
          'vpic_drive_type', 'vpic_fuel_type', 'vpic_transmission_style',
          'vpic_engine_cylinders', 'vpic_engine_hp', 'vpic_displacement_l',
          'vpic_doors', 'vpic_series', 'vpic_trim', 'vpic_gvwr',
          'vpic_electrification')),
        ('Assembly Plant', ('vpic_manufacturer', 'vpic_plant_city',
                            'vpic_plant_state', 'vpic_plant_country')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def flight_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Airline', ('airline_name', 'airline_iata', 'airline_icao',
                     'country', 'callsign')),
        ('Designator Anatomy',
         ('carrier_code', 'carrier_code_type', 'flight_number_digits',
          'digit_count', 'suffix_letter', 'flight_iata_code',
          'flight_icao_code', 'radio_callsign', 'direction_hint',
          'number_band_hint')),
        ('Live Status (aviationstack)',
         ('avstack_status', 'avstack_airline',
          'avstack_departure_airport', 'avstack_departure_iata',
          'avstack_departure_scheduled', 'avstack_arrival_airport',
          'avstack_arrival_iata', 'avstack_arrival_scheduled',
          'avstack_aircraft_registration')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def mmsi_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Station Identity (ITU-R M.1085)',
         ('station_type', 'station_type_code', 'itu_series')),
        ('Flag State & Serial',
         ('mid', 'country', 'serial_digits', 'trailing_zero_notes')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def app_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Identity', ('ecosystem', 'ecosystem_label', 'registry_url',
                      'namespace', 'package_name')),
        ('Registry Record',
         ('name', 'version', 'latest_version', 'summary', 'description',
          'author', 'author_email', 'maintainer', 'requires_python',
          'license', 'homepage', 'repository', 'documentation', 'created',
          'updated', 'pushed', 'archived')),
        ('Security (OSV.dev)', ('vulnerabilities_count',)),
        ('Community & Maintenance',
         ('downloads', 'recent_downloads', 'stars', 'pulls', 'forks',
          'open_issues', 'topics_count', 'maintainers_count',
          'versions_count', 'categories', 'keywords')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    vulns = info.get('vulnerability_ids')
    if isinstance(vulns, list) and vulns:
        rows = [[v.get('id', ''), v.get('severity', ''), v.get('summary', '')]
                for v in vulns if isinstance(v, dict)]
        if rows:
            sections.append({
                'title': f'Known Vulnerabilities ({len(rows)})',
                'type': 'table',
                'columns': ['Advisory', 'Severity', 'Summary'],
                'rows': rows,
            })

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def bssid_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Identity', ('vendor', 'oui_prefix', 'transmission', 'assignment',
                      'is_multicast', 'is_locally_administered')),
        ('Address Anatomy (EUI-48)',
         ('eui64_expansion', 'ipv6_interface_id', 'ipv6_link_local_hint',
          'randomization_hint')),
        ('Location (crowd-sourced)',
         ('lat', 'lon', 'accuracy_range', 'time')),
        ('Network (WiGLE)', ('ssid', 'encryption', 'last_seen')),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def plate_sections(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = result.get('info', {})
    sections: List[Dict[str, Any]] = []
    for title, keys in (
        ('Format Analysis', ('normalized', 'country_prefix', 'country_known',
                             'matched_count', 'match_note')),
        ('Composition', ('length', 'letters_count', 'digits_count',
                         'separators', 'composition_note')),
        ('German City Code', ('german_city_code', 'german_city')),
        ('Style Heuristic', ('style_hint',)),
    ):
        section = _grid(title, keys, info)
        if section['data']:
            sections.append(section)

    matched = info.get('matched_countries')
    if isinstance(matched, list) and matched:
        rows = [[m.get('country', ''), m.get('region', ''), m.get('example', ''),
                 f"{float(m.get('confidence', 0) or 0):.1f}"]
                for m in matched if isinstance(m, dict)]
        if rows:
            sections.append({
                'title': f'Matched Jurisdictions ({len(rows)})',
                'type': 'table',
                'columns': ['Country', 'Region', 'Example', 'Confidence'],
                'rows': rows,
            })

    rest = _fields_grid('Other Fields', info)
    used = _used_labels(sections)
    rest['data'] = {k: v for k, v in rest['data'].items() if k not in used}
    if rest['data']:
        sections.append(rest)
    sections.append(sources_table(result))
    return [s for s in sections if s.get('data') or s.get('rows')]


def sections_for(kind: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
    builders = {
        'ip': ip_sections,
        'phone': phone_sections,
        'username': username_sections,
        'email': email_sections,
        'domain': domain_sections,
        # v4.0 kinds
        'url': url_sections,
        'crypto': crypto_sections,
        'hash': hash_sections,
        'cve': cve_sections,
        'asn': asn_sections,
        # v5.0 kinds
        'mac': mac_sections,
        'iban': iban_sections,
        'imei': imei_sections,
        'coords': coords_sections,
        # v6.0 kinds
        'vin': vin_sections,
        'flight': flight_sections,
        'mmsi': mmsi_sections,
        'app': app_sections,
        'bssid': bssid_sections,
        'plate': plate_sections,
    }
    builder = builders.get(kind)
    return builder(result) if builder else []
