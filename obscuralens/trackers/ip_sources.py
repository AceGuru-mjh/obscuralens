"""
Multi-source IP intelligence aggregation.

Every provider is queried independently; results are merged field-by-field so a
single flaky source cannot blank out the whole report. Sources marked keyless
work without an API key; keyed sources (Shodan, VirusTotal, IPinfo, AbuseIPDB)
layer on when a key is configured. ``app.disabled_sources`` can switch any
source off.

Field provenance is tracked: ``gather_all`` returns which source(s) supplied
each value, so a report can show exactly where a fact came from.
"""

import concurrent.futures as futures
from typing import Any, Dict, List, Optional

from ..config import config
from ..utils.http_client import http

# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _ipwhois_app(ip: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(f"http://ipwhois.app/json/{ip}")
    if not ok or not d or not d.get('success', True):
        return {}
    return {
        'country': d.get('country'),
        'country_code': d.get('country_code'),
        'city': d.get('city'),
        'region': d.get('region'),
        'latitude': d.get('latitude'),
        'longitude': d.get('longitude'),
        'asn': d.get('asn'),
        'org': d.get('org'),
        'isp': d.get('isp'),
        'timezone': d.get('timezone'),
        'capital': d.get('country_capital'),
        'calling_code': d.get('country_phone'),
        'borders': d.get('country_neighbours'),
        'currency_code': d.get('currency_code'),
        'currency_symbol': d.get('currency_symbol'),
        'currency_plural': d.get('currency_plural'),
        'flag': d.get('country_flag'),
    }


def _ipwho_is(ip: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(f"http://ipwho.is/{ip}")
    if not ok or not d or not d.get('success', True):
        return {}
    conn = d.get('connection', {}) or {}
    tz = d.get('timezone', {}) or {}
    flag = d.get('flag', {}) or {}
    return {
        'type': d.get('type'),
        'continent': d.get('continent'),
        'continent_code': d.get('continent_code'),
        'country': d.get('country'),
        'country_code': d.get('country_code'),
        'region': d.get('region'),
        'region_code': d.get('region_code'),
        'city': d.get('city'),
        'postal': d.get('postal'),
        'latitude': d.get('latitude'),
        'longitude': d.get('longitude'),
        'is_eu': d.get('is_eu'),
        'calling_code': d.get('calling_code'),
        'capital': d.get('capital'),
        'borders': d.get('borders'),
        'flag': flag.get('emoji'),
        'asn': conn.get('asn'),
        'org': conn.get('org'),
        'isp': conn.get('isp'),
        'domain': conn.get('domain'),
        'timezone': tz.get('id'),
        'timezone_abbr': tz.get('abbr'),
        'timezone_is_dst': tz.get('is_dst'),
        'timezone_offset': tz.get('offset'),
        'timezone_utc': tz.get('utc'),
        'current_time': tz.get('current_time'),
    }


def _freeipapi(ip: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(f"https://freeipapi.com/api/json/{ip}")
    if not ok or not d:
        return {}
    return {
        'ip_version': d.get('ipVersion'),
        'country': d.get('countryName'),
        'country_code': d.get('countryCode'),
        'city': d.get('cityName'),
        'region': d.get('regionName'),
        'region_code': d.get('regionCode'),
        'postal': d.get('zipCode'),
        'latitude': d.get('latitude'),
        'longitude': d.get('longitude'),
        'continent': d.get('continent'),
        'continent_code': d.get('continentCode'),
        'capital': d.get('capital'),
        'calling_code': d.get('phoneCodes'),
        'asn': d.get('asn'),
        'org': d.get('asnOrganization'),
        'timezone': d.get('timeZones'),
        'currencies': d.get('currencies'),
        'languages': d.get('languages'),
        'is_proxy': d.get('isProxy'),
    }


def _ip_api(ip: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(f"http://ip-api.com/json/{ip}")
    if not ok or not d or d.get('status') != 'success':
        return {}
    return {
        'country': d.get('country'),
        'country_code': d.get('countryCode'),
        'region': d.get('region'),
        'region_name': d.get('regionName'),
        'city': d.get('city'),
        'postal': d.get('zip'),
        'latitude': d.get('lat'),
        'longitude': d.get('lon'),
        'timezone': d.get('timezone'),
        'isp': d.get('isp'),
        'org': d.get('org'),
        'asn_full': d.get('as'),
    }


def _db_ip(ip: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(f"https://api.db-ip.com/v2/free/{ip}")
    if not ok or not d or d.get('error'):
        return {}
    return {
        'country': d.get('countryName'),
        'country_code': d.get('countryCode'),
        'city': d.get('city'),
        'region': d.get('stateProv'),
        'region_code': d.get('stateProvCode'),
        'continent': d.get('continentName'),
        'continent_code': d.get('continentCode'),
    }


def _iplocation_net(ip: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(f"https://api.iplocation.net/?ip={ip}")
    if not ok or not d or d.get('response_code') != '200':
        return {}
    return {
        'ip': d.get('ip'),
        'ip_number': d.get('ip_number'),
        'ip_version': d.get('ip_version'),
        'country': d.get('country_name'),
        'country_code': d.get('country_code2'),
        'country_code3': d.get('country_code3'),
        'isp': d.get('isp'),
    }


def _shodan_internetdb(ip: str) -> Dict[str, Any]:
    """Shodan InternetDB: keyless ports, CVEs, CPEs and hostnames."""
    ok, d, _ = http.get_json(f"https://internetdb.shodan.io/{ip}")
    if not ok or not d or d.get('detail'):
        return {}
    return {
        'ports': d.get('ports'),
        'vulns': d.get('vulns'),
        'cpes': d.get('cpes'),
        'hostnames': d.get('hostnames'),
        'tags': d.get('tags'),
    }


def _ripestat(ip: str) -> Dict[str, Any]:
    """RIPEstat (keyless): announced prefix, origin ASN/holder and RIR."""
    out: Dict[str, Any] = {}

    ok, d, _ = http.get_json(
        f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}")
    if ok and d:
        data = d.get('data') or {}
        if data.get('resource'):
            out['prefix'] = data['resource']
        asns = data.get('asns') or []
        if asns:
            out['asn'] = asns[0].get('asn')
            holders = [a.get('holder') for a in asns if a.get('holder')]
            if holders:
                out['bgp_description'] = '; '.join(holders[:3])
            if len(asns) > 1:
                out['announced_by_count'] = len(asns)
        block = data.get('block') or {}
        if block.get('desc'):
            out['ip_block'] = block['desc']

    ok, d, _ = http.get_json(
        f"https://stat.ripe.net/data/rir/data.json?resource={ip}&lod=0")
    if ok and d:
        rirs = (d.get('data') or {}).get('rirs') or []
        if rirs and rirs[0].get('rir'):
            out['rir'] = rirs[0]['rir']

    return out


def _reverse_dns(ip: str) -> Dict[str, Any]:
    """Reverse DNS (PTR) lookup via Google's DNS-over-HTTPS."""
    if '.' in ip:
        octets = ip.split('.')
        ptr_name = '.'.join(reversed(octets)) + '.in-addr.arpa'
    else:  # IPv6 nibble format
        nibbles = ip.replace(':', '')
        ptr_name = '.'.join(reversed(nibbles)) + '.ip6.arpa'

    ok, d, _ = http.get_json(
        f"https://dns.google/resolve?name={ptr_name}&type=PTR")
    if not ok or not d:
        return {}
    for answer in d.get('Answer', []) or []:
        if answer.get('type') == 12:
            hostname = str(answer.get('data', '')).rstrip('.')
            return {'reverse_dns': hostname}
    return {}


def _rdap_registration(ip: str) -> Dict[str, Any]:
    """
    RDAP registration data: netblock owner, organisation address, abuse
    contact and registration dates. Bootstrap server redirects to the correct
    RIR, so a single ARIN entry point covers ARIN/RIPE/APNIC/LACNIC/AFRINIC.
    """
    ok, d, _ = http.get_json(f"https://rdap.arin.net/registry/ip/{ip}")
    if not ok or not d:
        return {}

    out: Dict[str, Any] = {}
    out['rdap_handle'] = d.get('handle')
    out['rdap_name'] = d.get('name')
    out['rdap_type'] = d.get('type')
    out['rdap_country'] = d.get('country')
    out['rdap_status'] = d.get('status')

    cidrs = d.get('cidr0_cidrs') or []
    if cidrs:
        nets = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in cidrs]
        out['rdap_cidr'] = ', '.join(nets)
    if d.get('startAddress'):
        out['rdap_range'] = f"{d.get('startAddress')} - {d.get('endAddress')}"

    events = d.get('events') or []
    for event in events:
        action = str(event.get('eventAction', '')).lower()
        if action in ('registration', 'registration date'):
            out['rdap_registered'] = event.get('eventDate')
        elif action in ('last changed', 'last update of rdap database'):
            out.setdefault('rdap_last_changed', event.get('eventDate'))

    # Walk nested entities looking for an organisation and an abuse contact.
    def walk(entities: List[Dict[str, Any]], depth: int = 0) -> None:
        if depth > 3:
            return
        for ent in entities or []:
            roles = [str(r).lower() for r in (ent.get('roles') or [])]
            vcard = ent.get('vcardArray')
            fields: Dict[str, str] = {}
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == 'fn':
                        fields['fn'] = item[3]
                    if isinstance(item, list) and len(item) >= 4 and item[0] == 'org':
                        fields['org'] = item[3]
                    if isinstance(item, list) and len(item) >= 4 and item[0] == 'email':
                        fields['email'] = item[3]
                    if isinstance(item, list) and len(item) >= 4 and item[0] == 'tel':
                        fields['tel'] = item[3]
                    if isinstance(item, list) and len(item) >= 4 and item[0] == 'adr':
                        for sub in item[1]:
                            if isinstance(sub, list) and len(sub) >= 4:
                                fields[sub[0]] = sub[3]

            if 'org' in fields and 'rdap_org' not in out:
                out['rdap_org'] = fields['org']
            if 'fn' in fields and 'rdap_contact' not in out:
                out['rdap_contact'] = fields['fn']
            if 'abuse' in roles:
                if 'email' in fields:
                    out['rdap_abuse_email'] = fields['email']
                if 'tel' in fields:
                    out['rdap_abuse_phone'] = fields['tel']
            if 'adr' in fields and 'rdap_address' not in out:
                addr = fields['adr'].split('\n')
                out['rdap_address'] = ', '.join(a for a in addr if a)
            if 'rdap_address' in out and 'abuse' in roles and 'rdap_abuse_name' not in out and 'fn' in fields:
                out['rdap_abuse_name'] = fields['fn']

            if ent.get('entities'):
                walk(ent['entities'], depth + 1)

    walk(d.get('entities') or [])
    return out


# ---------------------------------------------------------------------------
# Keyed sources (optional)
# ---------------------------------------------------------------------------

def _shodan(ip: str, api_key: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(
        f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
    if not ok or not d:
        return {}
    return {
        'ports': d.get('ports'),
        'vulns': d.get('vulns'),
        'hostnames': d.get('hostnames'),
        'domains': d.get('domains'),
        'os': d.get('os'),
        'tags': d.get('tags'),
        'last_update': d.get('last_update'),
        'asn': (d.get('asn') or {}).get('asn') if isinstance(d.get('asn'), dict) else None,
    }


def _virustotal(ip: str, api_key: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={'x-apikey': api_key})
    if not ok or not d:
        return {}
    attrs = d.get('data', {}).get('attributes', {}) or {}
    stats = attrs.get('last_analysis_stats', {}) or {}
    total = sum(v for v in stats.values() if isinstance(v, int))
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    score = int(((malicious + suspicious) / total) * 100) if total else 0
    return {
        'reputation': attrs.get('reputation'),
        'malicious': malicious,
        'suspicious': suspicious,
        'harmless': stats.get('harmless'),
        'undetected': stats.get('undetected'),
        'as_owner': attrs.get('as_owner'),
        'network': attrs.get('network'),
        'country': attrs.get('country'),
        'continent': attrs.get('continent'),
        'malicious_score': score,
    }


def _ipinfo(ip: str, api_key: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(f"https://ipinfo.io/{ip}/json?token={api_key}")
    if not ok or not d or d.get('error'):
        return {}
    lat, lon = None, None
    loc = d.get('loc')
    if isinstance(loc, str) and ',' in loc:
        lat, lon = loc.split(',', 1)
    return {
        'ipinfo_asn_name': (d.get('org') or '').split(' ', 1)[-1],
        'ipinfo_hostname': d.get('hostname'),
        'ipinfo_privacy': d.get('privacy'),
        'postal': d.get('postal'),
        'timezone': d.get('timezone'),
        'city': d.get('city'),
        'region': d.get('region'),
        'country': d.get('country'),
        'latitude': lat,
        'longitude': lon,
    }


def _abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    ok, d, _ = http.get_json(
        'https://api.abuseipdb.com/api/v2/check',
        params={'ipAddress': ip, 'maxAgeInDays': 90},
        headers={'Key': api_key, 'Accept': 'application/json'})
    if not ok or not d:
        return {}
    data = d.get('data', {}) or {}
    return {
        'abuse_confidence': data.get('abuseConfidenceScore'),
        'abuse_total_reports': data.get('totalReports'),
        'abuse_last_reported': data.get('lastReportedAt'),
        'abuse_usage_type': data.get('usageType'),
        'abuse_domain': data.get('domain'),
        'abuse_country': data.get('countryCode'),
        'usage_type': data.get('usageType'),
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'ipwhois.app': _ipwhois_app,
    'ipwho.is': _ipwho_is,
    'freeipapi': _freeipapi,
    'ip-api.com': _ip_api,
    'db-ip.com': _db_ip,
    'iplocation.net': _iplocation_net,
    'internetdb': _shodan_internetdb,
    'ripestat': _ripestat,
    'reverse_dns': _reverse_dns,
    'rdap': _rdap_registration,
}

KEYED_SOURCES: Dict[str, Any] = {
    'shodan': _shodan,
    'virustotal': _virustotal,
    'ipinfo': _ipinfo,
    'abuseipdb': _abuseipdb,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'ipwhois.app': 'Geolocation, ASN, ISP (keyless)',
    'ipwho.is': 'Geolocation, ASN, timezone, flag (keyless)',
    'freeipapi': 'Geolocation, ASN, currencies, proxy flag (keyless)',
    'ip-api.com': 'Geolocation, ASN, ISP (keyless)',
    'db-ip.com': 'Geolocation (keyless)',
    'iplocation.net': 'Geolocation, ISP (keyless)',
    'internetdb': 'Shodan InternetDB: open ports, CVEs, CPEs, hostnames (keyless)',
    'ripestat': 'Announced prefix, origin ASN/holder and RIR via RIPEstat (keyless)',
    'reverse_dns': 'PTR record via DNS-over-HTTPS (keyless)',
    'rdap': 'Registry registration and abuse contact (keyless)',
    'shodan': 'Full Shodan host data (keyed)',
    'virustotal': 'Reputation and detections (keyed)',
    'ipinfo': 'Hostname, org, privacy hints (keyed)',
    'abuseipdb': 'Abuse reports and confidence score (keyed)',
}


def _keep(value: Any) -> bool:
    # Explicit False is a real answer (is_eu=False, is_proxy=False).
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(ip: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable source in parallel and merge the results.

    Args:
        ip: target address
        keys: optional {service: api_key} map for keyed sources

    Returns:
        {
          'fields': merged_field_dict,
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }
    """
    keys = keys or {}
    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name):
            tasks[name] = (lambda f=fn: f(ip))

    for name, fn in _plugin_sources('ip').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name):
            tasks[source_name] = (lambda f=fn: f(ip))

    key_map = {
        'shodan': ('shodan', lambda k: _shodan(ip, k)),
        'virustotal': ('virustotal', lambda k: _virustotal(ip, k)),
        'ipinfo': ('ipinfo', lambda k: _ipinfo(ip, k)),
        'abuseipdb': ('abuseipdb', lambda k: _abuseipdb(ip, k)),
    }
    for service, (source_name, factory) in key_map.items():
        key = keys.get(service)
        if key and config.is_source_enabled(source_name):
            tasks[source_name] = (lambda f=factory, k=key: f(k))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=min(len(tasks), 12)) as ex:
            future_map = {ex.submit(fn): name for name, fn in tasks.items()}
            for future in futures.as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result() or {}
                    results[name] = data
                    status[name] = {'ok': bool(data), 'error': '' if data else 'no data'}
                except Exception as e:  # a broken source must not kill the scan
                    results[name] = {}
                    status[name] = {'ok': False, 'error': type(e).__name__}

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # Free sources disagree on coordinates quite often; keep them all so the
    # caller can show the spread instead of silently picking one.
    coords = []
    for name, data in results.items():
        if data.get('latitude') and data.get('longitude'):
            coords.append({
                'source': name,
                'lat': data['latitude'],
                'lon': data['longitude'],
            })
    if coords:
        merged['coordinates_by_source'] = coords

    cities = [data.get('city') for data in results.values() if data.get('city')]
    if len(set(cities)) > 1:
        merged['city_disagreement'] = sorted(set(cities))

    return {'fields': merged, 'sources': status, 'provenance': provenance}
