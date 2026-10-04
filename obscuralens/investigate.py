"""
Universal investigation: detect a target's kind, run the matching tracker and
follow a bounded set of pivots to related entities.

Pivots (depth 1):
  * email   -> its domain is looked up as a domain
  * domain  -> up to ``max_pivots`` A records are looked up as IPs
  * ip      -> its PTR hostname is looked up as a domain

v4.0 pivots:
  * url     -> its host is looked up as a domain
  * ip      -> InternetDB/Shodan vulnerabilities are looked up as CVEs
  * domain  -> the first A record's ASN is looked up as an AS number
  * cve     -> no pivot (reference data)

v5.0 kinds (mac / iban / imei / coords) are reference data too: the MAC
vendor, the IBAN bank, the IMEI manufacturer and the coordinates' place are
all attributes of the target itself, so they surface as graph facts instead
of pivot lookups (like cve and hash). The v6.0 kinds (vin / flight / mmsi /
app / bssid / plate) follow the same rule: the manufacturer and assembly
plant of a VIN, the airline behind a flight designator, the flag state of a
maritime identity, the registry behind a package coordinate, the vendor of
an access point and the issuing jurisdiction of a plate are attributes, not
new lookup targets.

The result is a self-contained payload with per-kind tracker results plus an
entity list and a relationship list, renderable as a table, JSON or a Mermaid
graph.
"""

import re
from typing import Any, Callable, Dict, List, Optional

from .reporting.sections import sections_for
from .utils.validators import (
    normalize_app,
    normalize_bssid,
    normalize_cve,
    normalize_flight,
    normalize_iban,
    normalize_imei,
    normalize_mmsi,
    normalize_vin,
    validate_asn,
    validate_coords,
    validate_crypto_address,
    validate_cve,
    validate_domain,
    validate_email,
    validate_hash,
    validate_ip,
    validate_mac,
    validate_phone,
    validate_plate,
    validate_url,
    validate_username,
)

KINDS = ('ip', 'phone', 'username', 'email', 'domain', 'url', 'crypto',
         'hash', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords',
         # v6.0 kinds
         'vin', 'flight', 'mmsi', 'app', 'bssid', 'plate')


def detect_kind(target: str) -> Optional[str]:
    """Best-effort target type detection; None when nothing matches."""
    value = (target or '').strip()
    if not value:
        return None
    if validate_ip(value)[0]:
        return 'ip'
    if validate_email(value)[0]:
        return 'email'
    # v6.0 flight: right after email because nothing earlier can match a
    # designator (no ':', no '@', no 'CVE-' prefix, no 32+ hex run), while
    # everything later either would swallow it or cannot match at all:
    # designators carry letters so the phone/imei/coords validators reject
    # them, they have no dot so the domain check skips them, but the ASN
    # branch below matches 'AS1234'-shaped strings (Alaska Airlines uses
    # IATA 'AS') and the username catch-all at the very end accepts any
    # 3-30 character alphanumeric run, so the flight check must run before
    # both. Five-digit and longer ASNs (AS15169) still classify as asn -
    # the flight grammar allows only 1-4 digits - and legacy 1-4-digit
    # AS-number queries keep working via the explicit `obscuralens asn`
    # command. Shape only (normalize_flight); carrier existence is the
    # airline pack's job inside the tracker.
    if normalize_flight(value):
        return 'flight'
    # v6.0 app: after email/flight and before url - an app coordinate
    # ('pypi:requests', 'docker:library/nginx') carries a single ':', which
    # never collides with emails (they need '@') or URLs (they need '://'),
    # while the username catch-all at the end would otherwise swallow it.
    # The five ecosystem prefixes are all 4-6 letters, so a 'DE:'-style
    # plate prefix can never be mistaken for one.
    if normalize_app(value):
        return 'app'
    # URLs and CVEs both contain ':' / '-' shapes; check URL before domain so
    # "https://example.com" is not mistaken for a domain.
    if '://' in value and validate_url(value)[0]:
        return 'url'
    if validate_cve(value)[0]:
        return 'cve'
    if validate_hash(value)[0]:
        return 'hash'
    if value.lower().startswith(('as',)) and validate_asn(value)[0] \
            and re.match(r'^as\d+$', value.strip(), re.I):
        return 'asn'
    # v5.0 MAC: after url/cve/hash (longer, unambiguous shapes) but before
    # domain and phone - a Cisco dotted MAC "b827.ebdc.aabb" is also a
    # syntactically valid domain, and a digits-only MAC such as
    # "12-34-56-78-90-12" matches the phone validator once its dashes are
    # stripped. validate_mac accepts colon, dash and dot notations.
    if validate_mac(value)[0]:
        return 'mac'
    # v6.0 bssid: a BSSID is grammatically an EUI-48 MAC address, so the
    # mac branch above already claims every separator-notation form -
    # investigate auto-detection deliberately prefers 'mac', and a BSSID
    # lookup is an explicit statement that the address is an access point
    # (run `obscuralens bssid ...`). The branch still catches bare-hex
    # 12-digit strings, which validate_mac rejects (it requires
    # separators) but the BSSID grammar accepts.
    if normalize_bssid(value):
        return 'bssid'
    # v6.0 VIN: after mac (a MAC is 12 hex characters with separators - a
    # different charset and length, so the two shapes can never collide)
    # but before iban: the IBAN branch below is deliberately shape-only,
    # and its shape (2 letters + 2 digits + 10-30 alphanumeric, total
    # 14-34) happily accepts a 17-character VIN whose WMI starts with two
    # letters followed by two digits. VINs are ALWAYS exactly 17
    # characters, so testing the fixed length first is the only way to
    # keep both shapes distinguishable. Shape only (normalize_vin) - the
    # ISO 3779 check digit verdict belongs to the tracker, so a typo'd
    # VIN still classifies as vin.
    if normalize_vin(value):
        return 'vin'
    # v5.0 IBAN: after email (emails carry '@') and after url, and before
    # username (an IBAN is alphanumeric and would otherwise classify as a
    # username). SHAPE ONLY - normalize_iban, not the mod-97 checksum - so a
    # typo'd IBAN still classifies as iban and the tracker reports the
    # checksum failure instead of the kind silently changing.
    if normalize_iban(value):
        return 'iban'
    if '.' in value and validate_domain(value)[0]:
        return 'domain'
    # v5.0 IMEI: before phone because validate_phone happily accepts a bare
    # 15-digit string. After domain so a purely numeric dotted host stays a
    # domain; dash/space separated and bare IMEIs carry no dot and land here.
    # Shape only (normalize_imei) - the Luhn verdict belongs to the tracker.
    if normalize_imei(value):
        return 'imei'
    # v6.0 MMSI: after imei because the IMEI branch above grabs 15/16-digit
    # runs while an MMSI is exactly nine digits, and before coords/phone
    # because validate_phone accepts any 8-15 digit string, so a bare
    # nine-digit MMSI would otherwise classify as a phone number. Nothing
    # between imei and phone can match: hash needs 32+ hex characters,
    # domains need a dot, coordinates need a separator or hemisphere
    # letters. Shape only (normalize_mmsi) - there is no checksum in
    # ITU-R M.1085, so the station-class verdict belongs to the tracker.
    if normalize_mmsi(value):
        return 'mmsi'
    # v5.0 coords: before phone because the DD pair separator class includes
    # spaces ("48.8584 2.2945") and validate_phone strips spaces and dots
    # before counting digits, so a space-separated pair would otherwise be
    # classified as a phone number. Barely anything else can look like DD,
    # DMS, UTM or MGRS shapes, so this stays near the end of the chain.
    if validate_coords(value)[0]:
        return 'coords'
    if validate_phone(value)[0]:
        return 'phone'
    if validate_crypto_address(value)[0]:
        return 'crypto'
    # v6.0 plate: the loosest gate, so it runs last before the username
    # catch-all - every printable 3-20 character string that no earlier
    # validator wanted classifies as plate (domains, URLs, IBANs, hashes
    # and crypto addresses are all longer, dotted or shaped differently
    # and were claimed above). Country-prefixed plates ('DE:B-AB 1234')
    # reach this branch directly; unprefixed plates only when no other
    # kind matched, e.g. a flight-shaped designator wins over an
    # unprefixed German plate.
    if validate_plate(value)[0]:
        return 'plate'
    if validate_username(value)[0]:
        return 'username'
    return None


def _default_checker(kind: str, target: str) -> Dict[str, Any]:
    """Run the real tracker for a kind (imported lazily to avoid cycles)."""
    from .trackers import (
        AppTracker,
        ASNTracker,
        BSSIDTracker,
        CoordsTracker,
        CryptoTracker,
        CVETracker,
        DomainTracker,
        EmailTracker,
        FlightTracker,
        HashTracker,
        IBANTracker,
        IMEITracker,
        IPTracker,
        MACTracker,
        MMSITracker,
        PhoneTracker,
        PlateTracker,
        URLTracker,
        UsernameTracker,
        VINTracker,
    )
    trackers = {
        'ip': IPTracker, 'phone': PhoneTracker, 'username': UsernameTracker,
        'email': EmailTracker, 'domain': DomainTracker,
        'url': URLTracker, 'crypto': CryptoTracker, 'hash': HashTracker,
        'cve': CVETracker, 'asn': ASNTracker,
        'mac': MACTracker, 'iban': IBANTracker,
        'imei': IMEITracker, 'coords': CoordsTracker,
        # v6.0 kinds
        'vin': VINTracker, 'flight': FlightTracker,
        'mmsi': MMSITracker, 'app': AppTracker,
        'bssid': BSSIDTracker, 'plate': PlateTracker,
    }
    return trackers[kind]().track(target)


def _entity_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


class _Graph:
    """Accumulates entities and relationships without duplicates."""

    def __init__(self, target: str, kind: str):
        self.entities: List[Dict[str, Any]] = []
        self.links: List[Dict[str, str]] = []
        self._seen = set()
        self._link_seen = set()
        self.add_entity(kind, target, role='target')

    def add_entity(self, kind: str, value: Any, role: str = 'related',
                   label: str = '') -> Optional[str]:
        if value in (None, '', [], {}):
            return None
        value = str(value)
        eid = _entity_id(kind, value)
        if eid not in self._seen:
            self._seen.add(eid)
            self.entities.append({
                'id': eid, 'type': kind, 'value': value,
                'role': role, 'label': label or value,
            })
        return eid

    def link(self, source: Optional[str], target: Optional[str],
             label: str) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, label)
        if key in self._link_seen:
            return
        self._link_seen.add(key)
        self.links.append({'from': source, 'to': target, 'label': label})


def _add_domain_facts(graph: _Graph, result: Dict[str, Any],
                      subdomain_cap: int = 15) -> None:
    info = result.get('info', {})
    host = graph.add_entity('domain', info.get('domain') or result.get('domain'))
    if not host:
        return

    entries = (
        ('a_records', 'ip', 'a_record', 10),
        ('urlscan_ips', 'ip', 'observed_ip', 5),
        ('ns_records', 'nameserver', 'nameserver', 5),
        ('mx_records', 'mx', 'mx', 5),
        ('ct_subdomains', 'subdomain', 'subdomain', subdomain_cap),
    )
    for key, entity_type, link_label, cap in entries:
        for value in (info.get(key) or [])[:cap]:
            graph.link(host, graph.add_entity(entity_type, value),
                       link_label)

    registrar = graph.add_entity('registrar', info.get('registrar'))
    graph.link(host, registrar, 'registrar')


def _add_ip_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('ip', info.get('ip') or result.get('ip'))
    if not node:
        return
    graph.link(node, graph.add_entity('hostname', info.get('reverse_dns')), 'ptr')
    graph.link(node, graph.add_entity('asn', f"AS{info.get('asn')}"
                                      if info.get('asn') else None),
               'announced_by')
    graph.link(node, graph.add_entity('organisation', info.get('org')),
               'operated_by')
    graph.link(node, graph.add_entity('prefix', info.get('prefix')),
               'prefix')
    for hostname in (info.get('hostnames') or [])[:5]:
        graph.link(node, graph.add_entity('hostname', hostname), 'hostname')
    for hostname in (info.get('passive_dns_hostnames') or [])[:5]:
        graph.link(node, graph.add_entity('hostname', hostname), 'passive_dns')
    for hostname in (info.get('reverse_ip_hostnames') or [])[:5]:
        graph.link(node, graph.add_entity('hostname', hostname), 'reverse_ip')
    for vuln in (info.get('vulns') or [])[:5]:
        graph.link(node, graph.add_entity('cve', normalize_cve(str(vuln))),
                   'exposes')


def _add_email_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('email', info.get('email') or result.get('email'))
    if not node:
        return
    graph.link(node, graph.add_entity('domain', info.get('domain')),
               'email_domain')
    for breach in (info.get('hibp_breaches') or [])[:10]:
        graph.link(node, graph.add_entity('breach', breach.get('name')),
                   'exposed_in')


def _add_phone_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('phone', result.get('phone_number'))
    if not node:
        return
    graph.link(node, graph.add_entity('carrier', info.get('carrier')),
               'carrier')
    graph.link(node, graph.add_entity('region', info.get('region_code')),
               'region')


def _add_username_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    node = graph.add_entity('username', result.get('username'))
    if not node:
        return
    found = [r for r in result.get('results', [])
             if r.get('status') == 'found']
    for record in found[:25]:
        graph.link(node, graph.add_entity('profile', record.get('url'),
                                          label=f"{record.get('platform')}: "
                                                f"{record.get('url', '')}"),
                   'profile_on')


def _add_url_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('url', result.get('url'))
    if not node:
        return
    graph.link(node, graph.add_entity('domain', info.get('domain')
                                      or result.get('domain')),
               'hosted_on')
    final = info.get('final_url')
    if final and final != result.get('url'):
        graph.link(node, graph.add_entity('url', final), 'redirects_to')
    for hop in (info.get('redirect_chain') or [])[:5]:
        if hop.get('url') and hop['url'] != result.get('url'):
            graph.link(node, graph.add_entity('url', hop['url']),
                       'redirect_hop')


def _add_crypto_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('crypto', result.get('address'),
                            label=f"{info.get('chain', 'address')}: "
                                  f"{result.get('address', '')}")
    if not node:
        return


def _add_hash_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('hash', result.get('hash'),
                            label=f"{info.get('algorithm', 'hash')}: "
                                  f"{result.get('hash', '')}")
    if not node:
        return
    if info.get('malware_family'):
        graph.link(node, graph.add_entity('malware_family',
                                          info.get('malware_family')),
                   'classified_as')


def _add_cve_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('cve', result.get('cve'))
    if not node:
        return
    for cpe in (info.get('affected_cpes') or [])[:5]:
        graph.link(node, graph.add_entity('cpe', cpe), 'affects')
    if info.get('cwe'):
        graph.link(node, graph.add_entity('cwe', info.get('cwe')),
                   'weakness')


def _add_asn_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('asn', info.get('asn_display')
                            or f"AS{result.get('asn', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity('organisation', info.get('asn_name')),
               'operated_by')
    graph.link(node, graph.add_entity('country', info.get('asn_country')),
               'registered_in')
    for prefix in (info.get('announced_prefixes')
                   or info.get('bgpview_ipv4_prefixes') or [])[:10]:
        graph.link(node, graph.add_entity('prefix', prefix), 'announces')


def _add_mac_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('mac', result.get('mac'),
                            label=f"{info.get('vendor', 'MAC')}: "
                                  f"{result.get('mac', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity('organisation', info.get('vendor')),
               'made_by')


def _add_iban_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('iban', result.get('iban'),
                            label=f"{info.get('country_name', 'IBAN')}: "
                                  f"{result.get('iban', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity('country', info.get('country_name')),
               'issued_in')
    graph.link(node, graph.add_entity('bank', info.get('bank_name')),
               'held_at')


def _add_imei_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('imei', result.get('imei'),
                            label=f"{info.get('manufacturer', 'IMEI')}: "
                                  f"{result.get('imei', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity('organisation', info.get('manufacturer')),
               'made_by')
    graph.link(node, graph.add_entity('device', info.get('model')),
               'model_family')


def _add_coords_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity('coords', result.get('coords'),
                            label=info.get('formatted_address')
                            or info.get('place_name')
                            or result.get('coords', ''))
    if not node:
        return
    country = info.get('country') or info.get('nearest_country')
    graph.link(node, graph.add_entity('country', country), 'located_in')
    place = info.get('formatted_address') or info.get('place_name') \
        or info.get('city') or info.get('locality')
    graph.link(node, graph.add_entity('place', place), 'near')


# ---------------------------------------------------------------------------
# v6.0 additions: vin / flight / mmsi fact builders
# ---------------------------------------------------------------------------

def _add_vin_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity(
        'vin', result.get('vin'),
        label=f"{info.get('manufacturer') or info.get('vpic_make') or 'VIN'}: "
              f"{result.get('vin', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity(
        'organisation', info.get('manufacturer') or info.get('vpic_make')),
        'made_by')
    graph.link(node, graph.add_entity(
        'country', info.get('country') or info.get('vpic_plant_country')),
        'assembled_in')
    graph.link(node, graph.add_entity('vehicle', info.get('vpic_model')),
               'model_family')
    plant = info.get('vpic_plant_city')
    if info.get('vpic_plant_state'):
        plant = f"{plant}, {info.get('vpic_plant_state')}" if plant \
            else info.get('vpic_plant_state')
    graph.link(node, graph.add_entity('place', plant), 'built_at')


def _add_flight_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    carrier_label = info.get('airline_name') or info.get('callsign') or 'Flight'
    node = graph.add_entity(
        'flight', result.get('flight'),
        label=f"{carrier_label}: {result.get('flight', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity(
        'organisation', info.get('airline_name') or info.get('avstack_airline')),
        'operated_by')
    graph.link(node, graph.add_entity('country', info.get('country')),
               'registered_in')
    graph.link(node, graph.add_entity(
        'airport', info.get('avstack_departure_airport')
        or info.get('avstack_departure_iata')), 'departs_from')
    graph.link(node, graph.add_entity(
        'airport', info.get('avstack_arrival_airport')
        or info.get('avstack_arrival_iata')), 'arrives_at')
    graph.link(node, graph.add_entity(
        'aircraft', info.get('avstack_aircraft_registration')), 'flown_by')


def _add_mmsi_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity(
        'mmsi', result.get('mmsi'),
        label=f"{info.get('station_type') or 'Station'}: "
              f"{result.get('mmsi', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity('country', info.get('country')),
               'flagged_in')
    graph.link(node, graph.add_entity('station_class', info.get('station_type')),
               'station_class')


def _add_app_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity(
        'app', result.get('app'),
        label=f"{info.get('ecosystem_label') or 'Package'}: "
              f"{info.get('name') or result.get('app', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity(
        'ecosystem', info.get('ecosystem_label') or info.get('ecosystem')),
        'distributed_via')
    graph.link(node, graph.add_entity(
        'organisation', info.get('author') or info.get('maintainer')),
        'authored_by')
    graph.link(node, graph.add_entity('license', info.get('license')),
               'licensed_under')
    for vuln in (info.get('vulnerability_ids') or [])[:5]:
        if isinstance(vuln, dict) and vuln.get('id'):
            graph.link(node, graph.add_entity('cve', vuln.get('id')),
                       'affected_by')


def _add_bssid_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity(
        'bssid', result.get('bssid'),
        label=f"{info.get('vendor') or 'Access point'}: "
              f"{result.get('bssid', '')}")
    if not node:
        return
    graph.link(node, graph.add_entity('organisation', info.get('vendor')),
               'manufactured_by')
    graph.link(node, graph.add_entity(
        'network', info.get('ssid'),
        label=f"SSID {info.get('ssid')}" if info.get('ssid') else ''),
        'anchors')
    lat, lon = info.get('lat'), info.get('lon')
    if lat is not None and lon is not None:
        graph.link(node, graph.add_entity(
            'coords', f"{lat}, {lon}",
            label=f"~{int(info.get('accuracy_range') or 0)} m"), 'located_at')


def _add_plate_facts(graph: _Graph, result: Dict[str, Any]) -> None:
    info = result.get('info', {})
    node = graph.add_entity(
        'plate', result.get('plate'),
        label=f"{info.get('country_prefix') or 'Plate'}: "
              f"{result.get('plate', '')}")
    if not node:
        return
    for match in (info.get('matched_countries') or [])[:5]:
        if isinstance(match, dict) and match.get('country'):
            graph.link(node, graph.add_entity(
                'country', match.get('country'),
                label=f"{match.get('country')}"
                      f"{' / ' + match['region'] if match.get('region') else ''}"),
                'issued_by')
    graph.link(node, graph.add_entity('city', info.get('german_city')),
               'registered_in')


_GRAPH_BUILDERS = {
    'domain': _add_domain_facts,
    'ip': _add_ip_facts,
    'email': _add_email_facts,
    'phone': _add_phone_facts,
    'username': _add_username_facts,
    'url': _add_url_facts,
    'crypto': _add_crypto_facts,
    'hash': _add_hash_facts,
    'cve': _add_cve_facts,
    'asn': _add_asn_facts,
    'mac': _add_mac_facts,
    'iban': _add_iban_facts,
    'imei': _add_imei_facts,
    'coords': _add_coords_facts,
    # v6.0 kinds
    'vin': _add_vin_facts,
    'flight': _add_flight_facts,
    'mmsi': _add_mmsi_facts,
    'app': _add_app_facts,
    'bssid': _add_bssid_facts,
    'plate': _add_plate_facts,
}


def investigate(target: str, pivot: bool = True, max_pivots: int = 3,
                checker: Optional[Callable[[str, str], Dict[str, Any]]] = None
                ) -> Dict[str, Any]:
    """
    Investigate any supported target and follow bounded pivots.

    Args:
        target: any supported kind value (IP / domain / email / phone /
            username / url / crypto / hash / cve / asn / mac / iban /
            imei / coords / vin / flight / mmsi / app / bssid / plate)
        pivot: follow related targets (email->domain, domain->A, ip->PTR)
        max_pivots: maximum related lookups of each kind
        checker: injectable ``callable(kind, value) -> result`` for tests

    Returns:
        Payload with per-kind results, entities, links and errors.
    """
    kind = detect_kind(target)
    if kind is None:
        raise ValueError(f"cannot determine target type: {target!r}")

    checker = checker or _default_checker
    value = target.strip()
    payload: Dict[str, Any] = {
        'target': value,
        'kind': kind,
        'order': [kind],
        'results': {},
        'entities': [],
        'links': [],
        'errors': [],
    }

    def run(kind_name: str, target_value: str) -> Optional[Dict[str, Any]]:
        try:
            result = checker(kind_name, target_value)
        except Exception as e:
            payload['errors'].append(
                f"{kind_name} {target_value}: {type(e).__name__}")
            return None
        return result

    primary = run(kind, value)
    if primary is None:
        return payload
    payload['results'][kind] = primary

    if pivot:
        seen = {(kind, value.lower())}

        def pivot_to(kind_name: str, pivot_value: str) -> None:
            key = (kind_name, pivot_value.lower())
            if key in seen or len(payload['results']) >= max_pivots + 1:
                return
            seen.add(key)
            result = run(kind_name, pivot_value)
            if result is not None:
                payload['results'][kind_name] = result

        if kind == 'email':
            domain = (primary.get('info') or {}).get('domain')
            if domain:
                pivot_to('domain', domain)
        elif kind == 'domain':
            info = primary.get('info') or {}
            for record in (info.get('a_records') or [])[:max_pivots]:
                pivot_to('ip', str(record))
        elif kind == 'ip':
            info = primary.get('info') or {}
            ptr = info.get('reverse_dns')
            if ptr and validate_domain(str(ptr))[0]:
                pivot_to('domain', str(ptr))
            # v4.0: follow known vulnerabilities as CVE pivots.
            for vuln in (info.get('vulns') or [])[:max_pivots]:
                cve_id = normalize_cve(str(vuln))
                if cve_id:
                    pivot_to('cve', cve_id)
        elif kind == 'url':
            # v4.0: a URL pivots to the domain of its host.
            domain = primary.get('domain') or (primary.get('info') or {}).get('domain')
            if domain and validate_domain(str(domain))[0]:
                pivot_to('domain', str(domain))
        # v5.0 mac / iban / imei / coords need no pivot branches: like cve
        # and hash they are reference data whose attributes (vendor, bank,
        # manufacturer, place) surface as graph facts, not as new lookups.
        # v6.0 vin / flight / mmsi are reference data for the same reason:
        # the vehicle, the airline and the flag state are attributes of the
        # identifier itself (and the optional aviationstack live-status
        # fields arrive as facts, not as pivot lookups). v6.0 app / bssid /
        # plate follow suit: the registry, the vendor and the issuing
        # jurisdiction are attributes of the identifier (vulnerability ids
        # COULD pivot to cve, but the CVE kind re-queries the same advisory
        # for less context than the OSV records already carry).

    graph = _Graph(value, kind)
    for kind_name, result in payload['results'].items():
        builder = _GRAPH_BUILDERS.get(kind_name)
        if builder:
            builder(graph, result)
    payload['entities'] = graph.entities
    payload['links'] = graph.links
    payload['order'] = list(payload['results'].keys())
    return payload


def to_mermaid(payload: Dict[str, Any]) -> str:
    """Render the entity graph as a Mermaid flowchart."""
    node_ids: Dict[str, str] = {}

    def node_id(entity_id: str) -> str:
        if entity_id not in node_ids:
            slug = re.sub(r'[^0-9A-Za-z]', '_', entity_id)[:48].strip('_')
            node_ids[entity_id] = f"n{len(node_ids)}_{slug}" if slug else \
                f"n{len(node_ids)}"
        return node_ids[entity_id]

    def esc(text: Any) -> str:
        return str(text).replace('"', "'").replace('\n', ' ')[:80]

    lines = ['graph LR']
    for entity in payload.get('entities', []):
        label = esc(f"{entity['type']}: {entity.get('label') or entity['value']}")
        lines.append(f'    {node_id(entity["id"])}["{label}"]')
    for link in payload.get('links', []):
        lines.append(f'    {node_id(link["from"])} -->|{esc(link["label"])}| '
                     f'{node_id(link["to"])}')
    return '\n'.join(lines)


def investigate_sections(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Report sections for an investigation payload."""
    summary = {
        'Target': payload.get('target'),
        'Detected kind': payload.get('kind'),
        'Lookups': ', '.join(payload.get('order', [])),
        'Entities': len(payload.get('entities', [])),
        'Relationships': len(payload.get('links', [])),
    }
    sections: List[Dict[str, Any]] = [
        {'title': 'Investigation Summary', 'type': 'grid', 'data': summary},
    ]

    for kind in payload.get('order', []):
        result = payload.get('results', {}).get(kind)
        if not result:
            continue
        for section in sections_for(kind, result):
            section = dict(section)
            section['title'] = f"{kind.upper()}: {section['title']}"
            sections.append(section)

    entities = payload.get('entities', [])
    if entities:
        sections.append({
            'title': 'Entities', 'type': 'table',
            'columns': ['Type', 'Value', 'Role'],
            'rows': [[e['type'], e['value'], e['role']] for e in entities],
        })
    links = payload.get('links', [])
    if links:
        sections.append({
            'title': 'Relationships', 'type': 'table',
            'columns': ['From', 'Relationship', 'To'],
            'rows': [[link['from'], link['label'], link['to']]
                     for link in links],
        })
    if payload.get('errors'):
        sections.append({
            'title': 'Errors', 'type': 'table', 'columns': ['Error'],
            'rows': [[error] for error in payload['errors']],
        })
    return sections
