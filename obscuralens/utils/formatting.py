"""
Human-friendly rendering of tracker results.

Shared by the interactive console and the non-interactive CLI so both present
fields with the same labels and value formatting. ``LABELS`` maps raw result
keys to readable names; unknown keys fall back to Title Case.
"""

import json
from typing import Any, Dict, List, Optional

# Human-friendly labels for raw field names.
LABELS: Dict[str, str] = {
    'ip': 'IP Address',
    'ip_version': 'IP Version',
    'ip_number': 'IP Number',
    'type': 'Type',
    'continent': 'Continent',
    'continent_code': 'Continent Code',
    'country': 'Country',
    'country_code': 'Country Code',
    'country_code3': 'Country Code (3)',
    'region': 'Region',
    'region_code': 'Region Code',
    'region_name': 'Region Name',
    'city': 'City',
    'postal': 'Postal Code',
    'latitude': 'Latitude',
    'longitude': 'Longitude',
    'is_eu': 'Is EU',
    'calling_code': 'Calling Code',
    'capital': 'Capital',
    'borders': 'Border Countries',
    'flag': 'Flag',
    'asn': 'ASN',
    'asn_full': 'ASN (full)',
    'org': 'Organisation',
    'isp': 'ISP',
    'domain': 'Domain',
    'reverse_dns': 'Reverse DNS (PTR)',
    'timezone': 'Timezone',
    'timezone_abbr': 'Timezone Abbr',
    'timezone_offset': 'Timezone Offset',
    'timezone_utc': 'Timezone UTC',
    'current_time': 'Local Time There',
    'currencies': 'Currencies',
    'currency_code': 'Currency Code',
    'currency_symbol': 'Currency Symbol',
    'currency_plural': 'Currency Name',
    'languages': 'Languages',
    'is_proxy': 'Is Proxy',
    'city_disagreement': 'City (sources disagree)',
    'coordinates_by_source': 'Coordinates By Source',
    'rdap_handle': 'Registry Handle',
    'rdap_name': 'Netblock Name',
    'rdap_type': 'Netblock Type',
    'rdap_org': 'Registered Org',
    'rdap_contact': 'Contact',
    'rdap_address': 'Org Address',
    'rdap_country': 'Registry Country',
    'rdap_cidr': 'CIDR Range',
    'rdap_range': 'Address Range',
    'rdap_status': 'Registry Status',
    'rdap_registered': 'Registered On',
    'rdap_last_changed': 'Last Changed',
    'rdap_abuse_name': 'Abuse Contact Name',
    'rdap_abuse_email': 'Abuse Email',
    'rdap_abuse_phone': 'Abuse Phone',
    'ports': 'Open Ports',
    'vulns': 'Known Vulnerabilities',
    'cpes': 'Software (CPE)',
    'hostnames': 'Hostnames',
    'domains': 'Domains',
    'os': 'Operating System',
    'tags': 'Tags',
    'last_update': 'Last Updated',
    'reputation': 'Reputation',
    'malicious': 'Malicious Detections',
    'suspicious': 'Suspicious Detections',
    'harmless': 'Harmless Detections',
    'undetected': 'Undetected Detections',
    'malicious_score': 'Threat Score %',
    'network': 'Network',
    'as_owner': 'AS Owner',
    'prefixes': 'Announced Prefixes',
    'prefix': 'Announced Prefix',
    'ip_block': 'IP Block Registry',
    'rir': 'RIR',
    'announced_by_count': 'Announced By (ASN count)',
    'bgp_description': 'BGP Description',
    'company': 'Company',
    'company_type': 'Company Type',
    'company_domain': 'Company Domain',
    'abuse_contact': 'Abuse Contact',
    'is_datacenter': 'Datacenter IP',
    'is_abuser': 'Reported Abuser',
    'is_crawler': 'Crawler / Bot',
    'is_mobile_ip': 'Mobile Network',
    'is_satellite': 'Satellite Connection',
    'is_tor': 'Tor Exit Node',
    'is_vpn': 'VPN',
    'ipinfo_asn_name': 'IPinfo AS Name',
    'ipinfo_hostname': 'IPinfo Hostname',
    'ipinfo_privacy': 'IPinfo Privacy',
    'abuse_confidence': 'Abuse Confidence %',
    'abuse_total_reports': 'Abuse Reports',
    'abuse_last_reported': 'Last Abused',
    'abuse_usage_type': 'Usage Type',
    'abuse_domain': 'Reporting Domain',
    'abuse_country': 'Reporter Country',
    'email': 'Email',
    'domain_created': 'Domain Created',
    'domain_expires': 'Domain Expires',
    'domain_updated': 'Domain Updated',
    'domain_age_days': 'Domain Age (days)',
    'expires_in_days': 'Expires In (days)',
    'registrar': 'Registrar',
    'nameservers': 'Name Servers',
    'abuse_email': 'Domain Abuse Email',
    'domain_status': 'Domain Status',
    'mx_records': 'MX Records',
    'mx_count': 'MX Record Count',
    'null_mx': 'Null MX (domain refuses mail)',
    'a_records': 'A Records',
    'aaaa_records': 'AAAA Records',
    'ns_records': 'NS Records',
    'soa_record': 'SOA Record',
    'caa_records': 'CAA Records',
    'txt_records': 'TXT Records',
    'spf_record': 'SPF Record',
    'spf_third_party': 'SPF Uses 3rd Party',
    'dmarc_record': 'DMARC Record',
    'dmarc_policy': 'DMARC Policy',
    'dnssec': 'DNSSEC Signed',
    'dkim_selectors': 'DKIM Selectors Found',
    'disposable': 'Disposable Email',
    'openpgp': 'Has OpenPGP Key',
    'openpgp_key_size': 'OpenPGP Keys',
    'gravatar': 'Gravatar Avatar',
    'is_webmail': 'Webmail Provider',
    'local_part': 'Local Part',
    'local_length': 'Local Part Length',
    'has_digits': 'Local Part Has Digits',
    'digit_count': 'Digit Count',
    'looks_generated': 'Looks Auto-Generated',
    'valid_format': 'Valid Format',
    'mx_exists': 'MX Exists',
    'local_number': 'Local Number',
    'national_number': 'National Number',
    'country_code_phone': 'Country Code',
    'number_length': 'Number Length',
    'e164': 'E.164 Format',
    'international': 'International Format',
    'national_format': 'National Format',
    'rfc3966': 'RFC3966 (URI)',
    'possible': 'Plausible Number',
    'is_mobile': 'Is Mobile',
    'is_voip': 'Is VoIP',
    'is_toll_free': 'Is Toll Free',
    'timezone_count': 'Timezone Count',
    'primary_timezone': 'Primary Timezone',
    'hints': 'Analyst Notes',
    'hibp_breach_count': 'Breach Count',
    'hibp_breached': 'Breached',
    'hibp_classes': 'Exposed Data Types',
    'paste_count': 'Paste Count',
    'hunter_status': 'Hunter Status',
    'hunter_result': 'Hunter Result',
    'hunter_score': 'Hunter Score',
    'hunter_smtp_server': 'SMTP Server',
    'hunter_mx': 'Hunter MX Check',
    'hunter_smtp_check': 'Hunter SMTP Check',
    'hunter_accept_all': 'Accepts All Mail',
    'hunter_blocked': 'Hunter Blocked',
    'hunter_free': 'Free Provider',
    # Domain tracker
    'http_status': 'HTTP Status',
    'http_title': 'Page Title',
    'server': 'Server Header',
    'powered_by': 'Powered By',
    'security_headers': 'Security Headers',
    'missing_security_headers': 'Missing Security Headers',
    'ct_certificates': 'CT Certificates',
    'ct_subdomains': 'Subdomains (crt.sh)',
    'ct_issuers': 'Certificate Issuers',
    'ct_last_seen': 'Last Certificate Seen',
    'robots_txt': 'robots.txt',
    'favicon_hash': 'Favicon Hash',
    'webtech': 'Detected Technologies',
    'urlscan_scans': 'urlscan.io Scans',
    'urlscan_last': 'Last urlscan.io Scan',
    'urlscan_ips': 'Scan IPs (urlscan.io)',
    'urlscan_servers': 'Scan Servers (urlscan.io)',
    'wayback_first': 'Wayback First Capture',
    'wayback_first_url': 'Wayback First URL',
    'wayback_last': 'Wayback Last Capture',
    # Username
    'profile_url': 'Profile URL',
    'verified': 'Verified',
    'joined': 'Joined',
    'created': 'Created',
    'avatar': 'Avatar',
    'bio': 'Bio',
    'links': 'Links',
    'location': 'Location',
    'name': 'Display Name',
    'followers': 'Followers',
    'following': 'Following',
    'subscribers': 'Subscribers',
    'likes': 'Likes',
    'videos': 'Videos',
    'posts': 'Posts',
    'photos': 'Photos',
    'shots': 'Shots',
    'projects': 'Projects',
    'public_repos': 'Public Repos',
    'repositories': 'Repositories',
    'karma': 'Karma',
    'connections': 'Connections',
    'source': 'Source',
    'status': 'Status',
    'confidence': 'Confidence',
    'reason': 'Why',
}

# Fields rendered as a comma-joined list rather than a table.
LIST_FIELDS = {
    'timezones', 'coordinates_by_source', 'mx_records', 'a_records',
    'aaaa_records', 'ns_records', 'caa_records', 'txt_records',
    'hibp_breaches', 'hibp_classes', 'pastes', 'nameservers', 'domain_status',
    'ports', 'vulns', 'hostnames', 'domains', 'tags', 'currencies',
    'languages', 'rdap_status', 'timelines', 'cpes', 'prefixes',
    'security_headers', 'missing_security_headers', 'ct_subdomains',
    'ct_issuers', 'dkim_selectors', 'webtech', 'links', 'urlscan_ips',
    'urlscan_servers',
}

# Keys that are plumbing rather than collected intelligence.
SKIP_FIELDS = {
    'coordinates_by_source', 'city_disagreement', 'errors',
    'field_sources', 'provenance', 'source', 'sources_ok', 'sources_failed',
}


def label(key: str) -> str:
    """Human-readable label for a raw field name."""
    return LABELS.get(key, key.replace('_', ' ').title())


def fmt_value(key: str, value: Any) -> str:
    """Render a single value as display text."""
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        if key == 'coordinates_by_source':
            return ', '.join(
                f"{c['source']}({c['lat']},{c['lon']})" for c in items)
        return ', '.join(str(i) for i in items)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def rows_from_fields(fields: Dict[str, Any],
                     skip: Optional[set] = None) -> List[List[str]]:
    """Convert a flat field dict into table rows, hiding plumbing keys."""
    skip = (skip or set()) | SKIP_FIELDS
    rows = []
    for key, value in fields.items():
        if key in skip:
            continue
        if value in (None, '', [], {}, False):
            continue
        rows.append([label(key), fmt_value(key, value)])
    return rows
