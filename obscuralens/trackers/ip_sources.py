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
import contextlib
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.helpers import fanout_workers
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
# v4.0 keyless additions
# ---------------------------------------------------------------------------

def _ipapi_co(ip: str) -> Dict[str, Any]:
    """ipapi.co (keyless, rate-limited): geo, ASN, currency, languages."""
    ok, d, _ = http.get_json(f"https://ipapi.co/{ip}/json/", cache_ttl=1800)
    if not ok or not d or d.get('error'):
        return {}
    return {
        'ip_version': d.get('version'),
        'country': d.get('country_name'),
        'country_code': d.get('country'),
        'continent_code': d.get('continent_code'),
        'city': d.get('city'),
        'region': d.get('region'),
        'region_code': d.get('region_code'),
        'postal': d.get('postal'),
        'latitude': d.get('latitude'),
        'longitude': d.get('longitude'),
        'asn': d.get('asn'),
        'org': d.get('org'),
        'timezone': d.get('timezone'),
        'utc_offset': d.get('utc_offset'),
        'calling_code': d.get('country_calling_code'),
        'currency_code': d.get('currency'),
        'currency_name': d.get('currency_name'),
        'languages': d.get('languages'),
        'in_eu': d.get('in_eu'),
    }


def _otx(ip: str) -> Dict[str, Any]:
    """
    AlienVault OTX (keyless, optional API key): pulse count, whitelist flag,
    associated malware samples and passive-DNS hostnames.
    """
    headers = {}
    key = config.get_api_key('otx')
    if key:
        headers['X-OTX-API-KEY'] = key

    out: Dict[str, Any] = {}
    ok, d, _ = http.get_json(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers)
    if ok and isinstance(d, dict):
        pulse_info = d.get('pulse_info') or {}
        pulses = pulse_info.get('pulses') or []
        count = pulse_info.get('count')
        if count is None:
            count = len(pulses)
        out['otx_pulses'] = count
        if pulses:
            stamps = [p.get('created') or p.get('modified')
                      for p in pulses if isinstance(p, dict)]
            stamps = [s for s in stamps if s]
            if stamps:
                out['otx_last_pulse'] = max(stamps)
            tags = []
            for pulse in pulses:
                for tag in (pulse.get('tags') or []):
                    if isinstance(tag, str) and tag not in tags:
                        tags.append(tag)
            if tags:
                out['otx_tags'] = tags[:10]
        validation = d.get('validation') or {}
        if 'whitelisted' in validation:
            out['otx_whitelisted'] = bool(validation.get('whitelisted'))
        malware = d.get('malware') or {}
        samples = malware.get('samples') or []
        if isinstance(samples, list) and samples:
            out['otx_malware_samples'] = len(samples)

    ok, d, _ = http.get_json(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns",
        headers=headers)
    if ok and isinstance(d, dict):
        records = d.get('passive_dns') or []
        hostnames = []
        for record in records:
            if not isinstance(record, dict):
                continue
            hostname = str(record.get('hostname') or '').rstrip('.')
            if hostname and hostname not in hostnames:
                hostnames.append(hostname)
        if hostnames:
            out['passive_dns_hostnames'] = hostnames[:15]
            out['passive_dns_count'] = len(records)
    return out


def _hackertarget(ip: str) -> Dict[str, Any]:
    """hackertarget.com reverse IP lookup (keyless, limited daily quota)."""
    ok, text, _ = http.get_text(
        f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if not ok or not text:
        return {}
    low = text.strip().lower()
    if low.startswith('error') or 'invalid' in low or 'quota' in low:
        return {}
    hostnames = [h.strip() for h in text.strip().splitlines() if h.strip()]
    if not hostnames:
        return {}
    return {
        'reverse_ip_hostnames': hostnames[:20],
        'reverse_ip_count': len(hostnames),
    }


def _threat_feeds(ip: str) -> Dict[str, Any]:
    """
    Cross-check the address against threat intelligence:
    Tor exit list + relay details and the Spamhaus DROP / Feodo / FireHOL
    level-1 blocklists plus (v5.0) the abuse.ch URLhaus and ThreatFox IOC
    feeds. Feeds are cached for ``app.feed_cache_ttl``.
    """
    if not config.app_config.feeds_enabled:
        return {}
    try:  # lazy import keeps the intel package optional at import time
        from ..intel import feeds as intel_feeds
    except ImportError:
        return {}

    try:
        verdict = intel_feeds.check_ip(ip)
    except Exception:
        return {}
    if not isinstance(verdict, dict) or verdict.get('disabled'):
        return {}

    out: Dict[str, Any] = {
        'tor_exit': bool(verdict.get('tor')),
        'spamhaus_drop': bool(verdict.get('spamhaus_drop')),
        'feodo_tracker': bool(verdict.get('feodo')),
        'firehol_level1': bool(verdict.get('firehol_level1')),
        'urlhaus_listed': bool(verdict.get('urlhaus')),
        'threatfox_listed': bool(verdict.get('threatfox')),
        'threat_feeds_listed': verdict.get('listed_count', 0),
    }
    relay = verdict.get('relay') or {}
    if isinstance(relay, dict) and relay.get('is_relay'):
        out['tor_relay'] = True
        if relay.get('nickname'):
            out['tor_relay_nickname'] = relay.get('nickname')
        if relay.get('first_seen'):
            out['tor_relay_first_seen'] = relay.get('first_seen')
    return out


# ---------------------------------------------------------------------------
# v4.0 keyed additions
# ---------------------------------------------------------------------------

def _greynoise(ip: str) -> Dict[str, Any]:
    """
    GreyNoise community context (keyless, optional key for higher limits).

    The community endpoint answers without authentication; a configured key
    is attached for higher rate limits. HTTP 404 with a JSON body means the
    address was "not observed" scanning the internet — a real negative answer,
    not a failure — so its message is kept alongside explicit False flags.
    """
    headers = {'Accept': 'application/json'}
    key = config.get_api_key('greynoise')
    if key:
        headers['key'] = key

    try:
        response = http.get(f"https://api.greynoise.io/v3/community/{ip}",
                            headers=headers)
    except Exception:
        return {}
    if response.status_code not in (200, 404):
        return {}
    try:
        d = response.json()
    except ValueError:
        return {}
    if not isinstance(d, dict) or d.get('error'):
        return {}

    out: Dict[str, Any] = {
        'gn_noise': bool(d.get('noise')),
        'gn_riot': bool(d.get('riot')),
        'gn_classification': d.get('classification'),
        'gn_name': d.get('name'),
        'gn_last_seen': d.get('last_seen'),
        'gn_message': d.get('message'),
    }
    return {k: v for k, v in out.items() if _keep(v)}


# ---------------------------------------------------------------------------
# v5.0 keyless additions
# ---------------------------------------------------------------------------

def _ipapi_is(ip: str) -> Dict[str, Any]:
    """
    ipapi.is (keyless): geo, ASN, company and hosting/proxy flags.

    Endpoint: ``https://api.ipapi.is/?q={ip}`` (free tier, rate-limited).

    The payload shape depends on the tier: the keyless tier answers with
    flat fields (``company`` and ``asn`` as strings like
    ``"AS54113 Fastly, Inc."``), while richer tiers nest them
    (``company.name``, ``asn`` as an integer plus ``asn.desc``, a
    ``location`` object with ``country_code``/``postal`` and boolean flags
    such as ``is_datacenter`` / ``is_vpn``). Both shapes are normalised
    here: ``asn`` becomes the bare AS number, ``asn_org`` its description,
    ``company`` the organisation name, and the datacenter / VPN / proxy /
    Tor booleans become report fields. A ``risk_score`` (0-100) is passed
    through when present. Transport or quota failures yield ``{}``.
    """
    ok, d, _ = http.get_json(f"https://api.ipapi.is/?q={ip}", cache_ttl=1800)
    if not ok or not isinstance(d, dict) or d.get('is_bogon') is True:
        return {}

    location = d.get('location') if isinstance(d.get('location'), dict) else {}
    company = d.get('company')
    if isinstance(company, dict):
        company = company.get('name')
    asn_raw = d.get('asn')

    asn: Any = None
    asn_org: Optional[str] = None
    if isinstance(asn_raw, dict):
        asn = asn_raw.get('asn')
        asn_org = asn_raw.get('desc') or asn_raw.get('as_name')
    elif isinstance(asn_raw, int):
        asn = asn_raw
    elif isinstance(asn_raw, str) and asn_raw:
        # Free-tier form: "AS54113 Fastly, Inc."
        parts = asn_raw.split(None, 1)
        number = parts[0].upper().removeprefix('AS')
        try:
            asn = int(number)
        except ValueError:
            asn = None
        asn_org = parts[1].strip() if len(parts) > 1 else None

    return {
        'country': d.get('country') or location.get('country'),
        'country_code': d.get('country_code') or location.get('country_code'),
        'continent': d.get('continent') or location.get('continent'),
        'city': d.get('city') or location.get('city'),
        'region': d.get('region') or location.get('region'),
        'postal': d.get('postal') or location.get('postal'),
        'latitude': d.get('lat') or location.get('lat'),
        'longitude': d.get('lon') or location.get('lng'),
        'timezone': d.get('timezone') or location.get('timezone'),
        'asn': asn,
        'asn_org': asn_org,
        'company': company,
        'datacenter': d.get('is_datacenter'),
        'vpn': d.get('is_vpn'),
        'is_proxy': d.get('is_proxy'),
        'is_tor': d.get('is_tor'),
        'is_mobile': d.get('is_mobile'),
        'risk_score': d.get('risk_score'),
    }


def _ipinfo_io(ip: str) -> Dict[str, Any]:
    """
    ipinfo.io (keyless free tier): geo, hostname, timezone and ASN/org.

    Endpoint: ``https://ipinfo.io/{ip}/json`` - no token required for the
    anonymous free tier (about 1000 requests/day; a keyed ``ipinfo`` source
    also exists above for higher volume).

    The response is flat: ``city`` / ``region`` / ``country`` (a two-letter
    code, so it feeds ``country_code`` rather than ``country``) /
    ``postal`` / ``timezone`` / ``loc`` ("lat,lon") / ``org``
    ("AS15169 Google LLC") / optional ``hostname``. The ``org`` string is
    split into an AS number and an organisation name, mirroring the field
    names the keyed reader already uses (``ipinfo_asn`` /
    ``ipinfo_asn_name`` / ``ipinfo_hostname``) so provenance merges when
    both run. Quota or transport failures (including the JSON ``error``
    body) yield ``{}``.
    """
    ok, d, _ = http.get_json(f"https://ipinfo.io/{ip}/json", cache_ttl=1800)
    if not ok or not isinstance(d, dict) or d.get('error'):
        return {}

    lat: Optional[str] = None
    lon: Optional[str] = None
    loc = d.get('loc')
    if isinstance(loc, str) and ',' in loc:
        lat, lon = loc.split(',', 1)

    asn_number: Any = None
    asn_name: Optional[str] = None
    org = d.get('org') or ''
    if isinstance(org, str) and org:
        parts = org.split(None, 1)
        number = parts[0].upper().removeprefix('AS')
        try:
            asn_number = int(number)
        except ValueError:
            asn_number = None
            asn_name = org
        if asn_number is not None:
            asn_name = parts[1].strip() if len(parts) > 1 else None

    return {
        'city': d.get('city'),
        'region': d.get('region'),
        'country_code': d.get('country'),
        'postal': d.get('postal'),
        'timezone': d.get('timezone'),
        'latitude': lat,
        'longitude': lon,
        'ipinfo_asn': asn_number,
        'ipinfo_asn_name': asn_name,
        'ipinfo_hostname': d.get('hostname'),
    }


# ---------------------------------------------------------------------------
# v6.1 addition: proxycheck.io - the one keyless source whose VPN/proxy
# verdict is its primary product. Probed live (positive 8.8.8.8) before
# shipping; the free tier allows 100 queries/day without a key and 1000/day
# with a free key.
# ---------------------------------------------------------------------------

def _proxycheck(ip: str) -> Dict[str, Any]:
    """
    proxycheck.io (keyless free tier): VPN/proxy/relay verdict + risk score.

    Endpoint: ``https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1`` - the
    anonymous tier answers about 100 queries per day. The verdict dimension
    is orthogonal to the geo sources: ipapi.is may say "datacenter" while
    proxycheck says "no proxy", and the field provenance shows both.

    Response shape: ``{"status": "ok", "<ip>": {...fields...}}``. A quota
    exhaustion answers ``status: "error"`` and maps to ``{}`` (honest
    no-data, never a crash). Fields carry the ``proxycheck_`` prefix so
    they merge alongside the ipapi.is risk fields without collisions.
    """
    ok, d, _ = http.get_json(
        f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1", cache_ttl=1800)
    if not ok or not isinstance(d, dict) or d.get('status') != 'ok':
        return {}

    info = d.get(ip)
    if not isinstance(info, dict):
        return {}

    out: Dict[str, Any] = {}
    proxy = info.get('proxy')
    if isinstance(proxy, str) and proxy:
        out['proxycheck_proxy'] = proxy.lower() == 'yes'
    vpn = info.get('vpn') if isinstance(info.get('vpn'), str) else None
    if vpn is not None:
        out['proxycheck_vpn'] = vpn.lower() == 'yes'
    risk = info.get('risk')
    if risk is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['proxycheck_risk'] = int(risk)
    if info.get('type'):
        out['proxycheck_type'] = str(info.get('type')).lower()
    if info.get('provider'):
        out['proxycheck_provider'] = info.get('provider')
    asn = info.get('asn')
    if asn is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['proxycheck_asn'] = int(str(asn).removeprefix('AS'))
    return out


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
    'ipapi.co': _ipapi_co,
    'otx': _otx,
    'hackertarget': _hackertarget,
    'threat_feeds': _threat_feeds,
    'greynoise': _greynoise,
    'ipapi.is': _ipapi_is,
    'ipinfo.io': _ipinfo_io,
    'proxycheck': _proxycheck,
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
    'ipapi.co': 'Geolocation, ASN, currency and language hints (keyless)',
    'otx': 'AlienVault OTX pulses, malware samples and passive DNS (keyless)',
    'hackertarget': 'Reverse IP hostnames (keyless, daily quota)',
    'threat_feeds': 'Tor exit list, Spamhaus DROP, Feodo and FireHOL level-1 (keyless)',
    'ipapi.is': 'Geolocation, ASN, company, datacenter/VPN/proxy flags and risk score (keyless)',
    'ipinfo.io': 'Geolocation, hostname, timezone and ASN via ipinfo.io free tier (keyless)',
    'proxycheck': 'VPN/proxy/relay verdict and risk score via proxycheck.io free tier (keyless; v6.1)',
    'shodan': 'Full Shodan host data (keyed)',
    'virustotal': 'Reputation and detections (keyed)',
    'ipinfo': 'Hostname, org, privacy hints (keyed)',
    'abuseipdb': 'Abuse reports and confidence score (keyed)',
    'greynoise': 'GreyNoise community: scanned/noise, Riot CDN (keyless, optional key)',
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
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(ip))

    for name, fn in _plugin_sources('ip').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(ip))

    key_map = {
        'shodan': ('shodan', lambda k: _shodan(ip, k)),
        'virustotal': ('virustotal', lambda k: _virustotal(ip, k)),
        'ipinfo': ('ipinfo', lambda k: _ipinfo(ip, k)),
        'abuseipdb': ('abuseipdb', lambda k: _abuseipdb(ip, k)),
    }
    for service, (source_name, factory) in key_map.items():
        key = keys.get(service)
        if key and config.is_source_enabled(source_name) \
                and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=factory, k=key: f(k))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=fanout_workers(len(tasks))) as ex:
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

    health.record_batch('ip', status)

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
