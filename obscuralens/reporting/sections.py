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


def sections_for(kind: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
    builders = {
        'ip': ip_sections,
        'phone': phone_sections,
        'username': username_sections,
        'email': email_sections,
        'domain': domain_sections,
    }
    builder = builders.get(kind)
    return builder(result) if builder else []
