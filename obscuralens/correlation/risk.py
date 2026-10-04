"""
Heuristic risk scoring for technical indicators (v4.0).

Scores are **explainable sums of weighted technical signals**: abuse
confidence, missing mail-security records, engine detections, CVSS bands.
This is explicitly NOT a verdict about people -- it describes technical
indicators only, and every signal carries the real values it fired on so an
analyst can audit the arithmetic.

Result shape::

    {
      'score': int 0-100,            # sum of weights, floored at 0, capped at 100
      'verdict': 'clean'|'low'|'medium'|'high'|'critical'|'unknown',
      'signals': [{'id', 'weight', 'detail'}, ...],
      'summary': str,
    }

Verdict bands: 0-14 clean, 15-39 low, 40-69 medium, 70-89 high, 90+
critical. A payload without populated fields scores 'unknown'. Crypto and
username scores are framed as activity/exposure profiles, not risk.

v5.0 adds identifier-integrity scorers for the mac / iban / imei / coords
kinds: they weigh checksum verdicts, randomized/virtualization bits,
curated-pack misses and unresolved reverse geocoding - still technical
signals about identifiers, never statements about people.
"""

import contextlib
import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ..config import config
from .timeline import _parse_date

__all__ = ['attach_risk', 'risk_sections', 'score']

_LOG = logging.getLogger(__name__)

#: Verdict band edges (score -> verdict).
_VERDICTS = ('clean', 'low', 'medium', 'high', 'critical', 'unknown')

#: Domain title markers that indicate a parked page.
_PARKING_MARKERS = ('park', 'for sale', 'domain is for sale')

#: Credential-harvesting path keywords.
_CREDENTIAL_KEYWORDS = ('login', 'signin', 'verify', 'account', 'password')

#: Ports that never raise an eyebrow.
_STANDARD_PORTS = (80, 443, 8080)

#: Narratives that avoid risk language for people-adjacent kinds.
_FLAVOR = {'crypto': 'activity profile', 'username': 'exposure profile'}

#: Days below which a freshly-registered domain/address counts as new.
_NEW_DOMAIN_DAYS = 30
_VERY_NEW_DOMAIN_DAYS = 7
_RECENT_BREACH_DAYS = 90

#: Virtualization NIC vendors: a VM's MAC says nothing about a physical
#: device, so it is surfaced as an informational signal, not suspicion.
_VIRTUALIZATION_VENDORS = ('vmware', 'virtualbox', 'qemu', 'kvm', 'hyper-v', 'xen')

#: Heuristic list of issuer countries whose banking secrecy makes an IBAN
#: worth a second look (classic shell-company jurisdictions). This is a
#: reputation heuristic, NOT an allegation: legitimate accounts exist everywhere.
_SECRECY_JURISDICTIONS = frozenset((
    'panama', 'cayman islands', 'liechtenstein', 'seychelles', 'belize',
    'vanuatu', 'marshall islands', 'cyprus', 'bahamas', 'cook islands',
))

#: Geohash precision at or beyond which a position is meter-level (7 chars
#: ~ 150 m cells, 9 chars ~ 5 m cells).
_METER_PRECISION_GEOHASH = 7


# ---------------------------------------------------------------------------
# Defensive field helpers
# ---------------------------------------------------------------------------

def _fields(kind: str, payload: Any) -> Dict[str, Any]:
    """The field mapping of a payload (flat for username-style results)."""
    if not isinstance(payload, dict):
        return {}
    info = payload.get('info')
    if isinstance(info, dict):
        return info
    if kind == 'username':
        # Username results are flat; a junk non-dict 'info' key is not a field.
        return {key: value for key, value in payload.items() if key != 'info'}
    return {}


def _populated(info: Dict[str, Any]) -> bool:
    """Whether any collected field carries a value (explicit False counts)."""
    if not isinstance(info, dict):
        return False
    return any(value is not None and value != '' and value != [] and value != {}
               for value in info.values())


def _num(value: Any) -> Optional[float]:
    """Numeric form of a value (None for bools/strings-that-are-not-numbers)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def _int(value: Any) -> Optional[int]:
    """Integer form of a value; list/tuple/set lengths also count."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return None
        return int(number)
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _list(value: Any) -> List[Any]:
    """List form of a value (only real sequences qualify)."""
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item is not None]
    return []


def _text(value: Any) -> str:
    """String form of a scalar value ('' for containers/None/bools)."""
    if value is None or isinstance(value, (bool, dict, list, tuple, set)):
        return ''
    return str(value).strip()


def _days_since(value: Any) -> Optional[int]:
    """Whole days between a parseable date and now (None when unparseable)."""
    parsed = _parse_date(value)
    if not parsed:
        return None
    try:
        moment = datetime.fromisoformat(parsed)
    except ValueError:
        return None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return (now - moment).days


def _fmt(number: float) -> str:
    """Compact number formatting for detail strings."""
    return f"{number:g}"


# ---------------------------------------------------------------------------
# Per-kind scorers -- each returns [{'id', 'weight', 'detail'}, ...]
# ---------------------------------------------------------------------------

def _score_ip(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    confidence = _num(info.get('abuse_confidence'))
    if confidence is not None and confidence >= 75:
        add('abuse_confidence_high', 45,
            f"AbuseIPDB abuse confidence {_fmt(confidence)}%")
    elif confidence is not None and confidence >= 50:
        add('abuse_confidence_elevated', 30,
            f"AbuseIPDB abuse confidence {_fmt(confidence)}%")
    elif confidence is not None and confidence >= 25:
        add('abuse_confidence_moderate', 15,
            f"AbuseIPDB abuse confidence {_fmt(confidence)}%")

    malicious = _int(info.get('malicious'))
    if malicious is not None and malicious >= 2:
        add('vt_malicious_engines', 20,
            f"{malicious} VirusTotal engines flag this IP malicious")

    suspicious = _int(info.get('suspicious'))
    if suspicious is not None and suspicious >= 2:
        add('vt_suspicious_engines', 10,
            f"{suspicious} VirusTotal engines find this IP suspicious")

    if info.get('is_proxy') is True:
        add('known_proxy', 10, 'flagged as a proxy/VPN host')

    tor_exit = info.get('tor_exit')
    if tor_exit is None:
        tor_exit = info.get('is_tor')
    if tor_exit is True:
        add('tor_exit', 15, 'listed as a Tor exit node')

    vulns = _int(info.get('vulns'))
    if vulns is not None and vulns >= 5:
        add('many_open_vulns', 25,
            f"{vulns} vulnerable services reported by InternetDB")
    elif vulns is not None and vulns >= 1:
        add('open_vulns', 10,
            f"{vulns} vulnerable service(s) reported by InternetDB")

    ports = _int(info.get('ports'))
    if ports is not None and ports >= 10:
        add('many_open_ports', 5, f"{ports} open ports exposed")

    tags = [str(tag).lower() for tag in _list(info.get('tags'))]
    risky = sorted({tag for tag in tags
                    if 'self-signed' in tag or 'vnc' in tag})
    if risky:
        add('risky_service_tags', 5,
            f"risky service banner(s): {', '.join(risky)}")

    for flag in ('spamhaus_drop', 'feodo', 'firehol'):
        if info.get(flag):
            add(f"{flag}_listed", 25,
                f"IP present on the {flag} drop/blocklist")

    if not info.get('reverse_dns') and not _list(info.get('hostnames')):
        add('no_dns_presence', 0,
            'no reverse DNS or hostnames recorded (informational)')

    return signals


def _domain_age_days(info: Dict[str, Any]) -> Optional[int]:
    """Age in days from domain_age_days or the earliest creation date."""
    age = _num(info.get('domain_age_days'))
    if age is not None and age >= 0:
        return int(age)
    for field in ('created', 'rdap_registered', 'domain_created'):
        days = _days_since(info.get(field))
        if days is not None:
            return max(0, days)
    return None


def _score_domain(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    age = _domain_age_days(info)
    if age is not None:
        if age < _VERY_NEW_DOMAIN_DAYS:
            add('very_new_domain', 25, f"domain registered {age} day(s) ago")
        elif age < _NEW_DOMAIN_DAYS:
            add('new_domain', 15, f"domain registered {age} day(s) ago")

    # Mail/DNS posture only scores when a posture probe actually ran
    # (a bare a_records entry proves nothing about TXT/MX lookups).
    posture_queried = any(key in info for key in (
        'mx_records', 'null_mx', 'mx_exists', 'spf_record', 'dmarc_record',
        'txt_records', 'ns_records', 'dnssec'))
    if posture_queried:
        mx_present = bool(_list(info.get('mx_records'))) \
            or info.get('mx_exists') is True
        if not mx_present:
            add('no_mx', 5, 'no MX records (cannot receive mail)')
        if not info.get('spf_record'):
            add('no_spf', 10, 'no SPF policy published')
        if not info.get('dmarc_record'):
            add('no_dmarc', 10, 'no DMARC policy published')
        elif str(info.get('dmarc_policy') or '').strip().lower() == 'none':
            add('dmarc_monitor_only', 5,
                'DMARC policy is p=none (monitoring only, no enforcement)')
        if info.get('dnssec') is False:
            add('no_dnssec', 5, 'DNSSEC not enabled')
    if 'a_records' in info and not _list(info.get('a_records')) \
            and not _list(info.get('aaaa_records')):
        add('no_a_records', 5, 'no A/AAAA records resolved')

    subdomains = _int(info.get('ct_subdomains'))
    if subdomains is not None and subdomains > 50:
        add('many_subdomains', 5,
            f"{subdomains} subdomains observed in certificate transparency")

    title = _text(info.get('http_title'))
    if title and any(marker in title.lower() for marker in _PARKING_MARKERS):
        add('parked_domain', 15, f"parked-domain title: {title!r}")

    verdicts = _int(info.get('urlscan_malicious_verdicts'))
    if verdicts is not None and verdicts >= 1:
        add('urlscan_malicious', 25,
            f"{verdicts} urlscan.io scan(s) judged this domain malicious")

    typosquat = _text(info.get('typosquat_of_popular'))
    if typosquat:
        add('typosquat_of_popular', 20,
            f"hostname resembles popular domain: {typosquat}")

    status = _text(info.get('domain_status')).lower()
    expires_in = _num(info.get('expires_in_days'))
    if 'expired' in status or (expires_in is not None and expires_in < 0):
        add('domain_expired', 5, 'domain registration has expired')

    return signals


def _breach_count(info: Dict[str, Any]) -> Optional[int]:
    """Number of HIBP breaches (explicit count or list length)."""
    count = _int(info.get('hibp_breach_count'))
    if count is not None:
        return count
    return _int(info.get('hibp_breaches'))


def _recent_breach_days(info: Dict[str, Any]) -> Optional[int]:
    """Days since the most recently listed breach (None when unparseable)."""
    days: List[int] = []
    for breach in _list(info.get('hibp_breaches')):
        if not isinstance(breach, dict):
            continue
        for field in ('added', 'breach_date', 'date'):
            since = _days_since(breach.get(field))
            if since is not None:
                days.append(since)
                break
    return min(days) if days else None


def _score_email(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    if info.get('disposable') is True:
        add('disposable_mailbox', 15, 'address uses a disposable mail provider')

    if info.get('mx_exists') is False or info.get('null_mx') is True \
            or info.get('mx_records') == []:
        add('no_mx', 20, 'mail domain has no MX records')

    breaches = _breach_count(info)
    if breaches is not None and breaches >= 5:
        add('multiple_breaches', 25,
            f"address appears in {breaches} known data breaches")
    elif breaches is not None and breaches >= 1:
        add('breached', 10,
            f"address appears in {breaches} known data breach(es)")

    reputation = _num(info.get('emailrep_reputation'))
    if reputation is None:
        reputation = _num(info.get('reputation'))
    if reputation is not None:
        if reputation <= 10:
            add('emailrep_bad_reputation', 20,
                f"EmailRep reputation {_fmt(reputation)}/100")
        elif reputation <= 25:
            add('emailrep_low_reputation', 15,
                f"EmailRep reputation {_fmt(reputation)}/100")

    if info.get('credentials_leaked') is True:
        add('credentials_leaked', 20, 'credentials leaked for this address')
    else:
        classes = [str(item).lower() for item in _list(info.get('hibp_classes'))]
        if any('password' in item for item in classes):
            add('credentials_leaked', 20,
                'breach data classes include passwords')

    recent = _recent_breach_days(info)
    if recent is not None and recent <= _RECENT_BREACH_DAYS:
        add('recent_breach', 10,
            f"most recent breach was listed {recent} day(s) ago")

    return signals


def _score_url(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    if info.get('gsb_malicious') is True:
        threats = [str(t) for t in _list(info.get('gsb_threat_types'))]
        detail = 'flagged malicious by Google Safe Browsing'
        if threats:
            detail += f" ({', '.join(threats)})"
        add('gsb_malicious', 50, detail)

    vt_malicious = _int(info.get('vt_malicious'))
    if vt_malicious is not None and vt_malicious >= 2:
        add('vt_malicious', 25,
            f"{vt_malicious} VirusTotal engines flag this URL malicious")
    elif vt_malicious is not None and vt_malicious >= 1:
        add('vt_malicious', 15,
            f"{vt_malicious} VirusTotal engine flags this URL malicious")

    redirects = _int(info.get('redirect_count'))
    if redirects is not None and redirects >= 5:
        add('redirect_chain', 10, f"{redirects} redirects before landing")

    if info.get('host_is_ip') is True:
        add('ip_hosted_url', 15, 'URL points at a raw IP address, not a name')

    host = _text(info.get('host')).lower()
    candidates = (host, _text(payload.get('url')).lower(),
                  _text(info.get('final_url')).lower())
    if any('xn--' in candidate for candidate in candidates):
        add('punycode_host', 20,
            'hostname uses punycode (non-ASCII look-alike characters)')

    verdicts = _int(info.get('urlscan_malicious_verdicts'))
    if verdicts is not None and verdicts >= 1:
        add('urlscan_malicious', 25,
            f"{verdicts} urlscan.io scan(s) judged this URL malicious")

    paths = []
    for url in (payload.get('url'), info.get('final_url')):
        with contextlib.suppress(Exception):
            paths.append(str(urlsplit(str(url or '')).path).lower())
    if any(keyword in path for path in paths for keyword in _CREDENTIAL_KEYWORDS):
        add('credential_keywords', 5,
            'URL path contains credential-harvesting keywords '
            f"({', '.join(_CREDENTIAL_KEYWORDS)})")

    port = _int(info.get('port'))
    if port is not None and port not in _STANDARD_PORTS:
        add('nonstandard_port', 5, f"non-standard port {port}")

    return signals


def _score_hash(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    malicious = _int(info.get('malicious'))
    if malicious is not None and malicious >= 5:
        add('vt_malicious_heavy', 50,
            f"{malicious} VirusTotal engines detect this file as malicious")
    elif malicious is not None and malicious >= 1:
        add('vt_malicious', 25,
            f"{malicious} VirusTotal engine(s) detect this file as malicious")

    suspicious = _int(info.get('suspicious'))
    if suspicious is not None and suspicious >= 1:
        add('vt_suspicious', 10,
            f"{suspicious} VirusTotal engine(s) find this file suspicious")

    family = _text(info.get('malware_family'))
    if family:
        add('malware_family', 30, f"classified as malware family: {family}")

    pulses = _int(info.get('otx_pulses'))
    if pulses is not None and pulses >= 3:
        add('otx_pulses', 10, f"tracked in {pulses} OTX threat pulses")

    if info.get('known_file') is True or info.get('otx_whitelisted') is True:
        add('benign_known_file', -20,
            'known-good/whitelisted file (CIRCL hashlookup / OTX whitelist)')

    threat_label = _text(info.get('vt_threat_label'))
    if threat_label:
        add('vt_threat_label', 10,
            f"VirusTotal suggested threat label: {threat_label}")

    return signals


def _first_present(info: Dict[str, Any], keys: Any) -> Optional[Any]:
    """First non-None value among ordered field candidates."""
    for key in keys:
        if info.get(key) is not None:
            return info.get(key)
    return None


def _score_crypto(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Activity observations only -- deliberately no risk language.
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    first_days = _days_since(info.get('first_seen'))
    if first_days is not None and first_days <= _NEW_DOMAIN_DAYS:
        add('new_address', 10,
            f"first on-chain activity {first_days} day(s) ago")

    tx_count = _int(_first_present(info, (
        'tx_count', 'btc_tx_count', 'blockstream_tx_count',
        'blockchair_tx_count', 'eth_tx_sample_count')))
    if tx_count is not None and tx_count == 0:
        add('unused_address', 0, 'no transactions recorded (unused address)')

    balance = _num(_first_present(info, (
        'balance', 'btc_balance', 'eth_balance', 'blockchair_balance')))
    if balance is not None and balance > 0:
        add('funded_address', 0, f"current balance {_fmt(balance)} (holds value)")

    return signals


def _score_username(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Exposure indicator only -- never a statement about the person.
    signals: List[Dict[str, Any]] = []

    found = _int(info.get('found_count'))
    if found is None:
        found = len([record for record in _list(info.get('results'))
                     if isinstance(record, dict)
                     and record.get('status') == 'found'])
    if found is not None and found >= 10:
        signals.append({
            'id': 'broad_footprint', 'weight': 5,
            'detail': f"username confirmed on {found} platforms (exposure "
                      "indicator)"})

    return signals


def _score_cve(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    cvss = _num(info.get('cvss_score'))
    if cvss is not None and cvss >= 9.0:
        add('cvss_critical', 60, f"CVSS base score {_fmt(cvss)} (critical)")
    elif cvss is not None and cvss >= 7.0:
        add('cvss_high', 40, f"CVSS base score {_fmt(cvss)} (high)")
    elif cvss is not None and cvss >= 4.0:
        add('cvss_medium', 20, f"CVSS base score {_fmt(cvss)} (medium)")

    epss = _num(info.get('epss_score'))
    if epss is not None and epss >= 90:
        add('epss_very_likely', 15,
            f"EPSS exploitation probability {_fmt(epss)}%")
    elif epss is not None and epss >= 50:
        add('epss_likely', 5, f"EPSS exploitation probability {_fmt(epss)}%")

    references = [str(ref).lower() for ref in _list(info.get('references'))]
    exploits = [ref for ref in references if 'exploit' in ref]
    if exploits:
        add('exploit_reference', 15,
            f"{len(exploits)} reference(s) link to exploit code")

    severity = _text(info.get('cvss_severity'))
    if severity:
        add('cvss_severity_label', 0, f"NVD severity rating: {severity}")

    return signals


def _score_asn(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Routing footprint is descriptive, not risky: informational only.
    signals: List[Dict[str, Any]] = []

    prefixes = _int(info.get('announced_prefix_count'))
    if prefixes is not None and prefixes > 1000:
        signals.append({
            'id': 'large_transit', 'weight': 0,
            'detail': f"{prefixes} announced prefixes (large transit network)"})

    peers = _int(info.get('peer_count'))
    if peers is not None and peers > 500:
        signals.append({
            'id': 'large_peering', 'weight': 0,
            'detail': f"{peers} peers (major peering presence)"})

    return signals


def _score_mac(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # NIC provenance and address-class signals: who burned the OUI and
    # whether the bits say "real hardware NIC" at all.
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    if info.get('is_multicast') is True:
        add('multicast_bit', 10,
            'multicast/broadcast address, not a device NIC')

    if info.get('is_locally_administered') is True:
        add('locally_administered', 8,
            'randomized/privacy MAC or virtual NIC - vendor from OUI pack '
            'may be arbitrary')

    vendor = _text(info.get('vendor'))
    if vendor:
        lowered = vendor.lower()
        if any(name in lowered for name in _VIRTUALIZATION_VENDORS):
            add('virtualization_vendor', 3,
                f"virtualization NIC ({vendor})")
    else:
        add('unknown_vendor', 2,
            'OUI not in curated pack (offline IEEE subset miss)')

    return signals


def _score_iban(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Structural integrity plus issuer context; jurisdiction weight is a
    # heuristic about commonly-abused secrecy centres, never an allegation.
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    # The tracker gates on mod-97 before any source runs, so checksum_valid
    # is normally True; structure_ok alone (openiban-style payloads) still
    # earns the informational verdict.
    if info.get('checksum_valid') is True \
            or (info.get('checksum_valid') is None
                and info.get('structure_ok') is True):
        add('checksum_valid', 0,
            'mod-97 checksum verified - structurally genuine')

    bank = _text(info.get('bank_name'))
    if bank:
        add('bank_identified', 0, f"issuing bank identified: {bank}")

    country = _text(info.get('country_name'))
    if country:
        if country.strip().lower() in _SECRECY_JURISDICTIONS:
            add('high_risk_jurisdiction', 10,
                f"issuer country {country} is a commonly-abused secrecy "
                'jurisdiction (heuristic)')
    else:
        add('unknown_country', 5, 'issuer country unresolved '
            '(prefix not in the structure pack)')

    return signals


def _score_imei(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Identifier integrity: a failed Luhn check is the classic marker of a
    # re-stamped or fabricated handset identity.
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    luhn = info.get('luhn_valid')
    if luhn is True:
        add('luhn_valid', 0, 'passes the Luhn check digit')
    elif luhn is False:
        expected = _text(info.get('expected_check_digit'))
        detail = 'checksum mismatch - altered or fabricated IMEI'
        if expected:
            detail += f" (expected check digit {expected})"
        add('luhn_invalid', 15, detail)

    if not _text(info.get('manufacturer')):
        add('tac_unknown', 4,
            'TAC not in curated pack - rare or modified device')

    body = _text(info.get('reporting_body'))
    if body:
        identifier = _text(info.get('reporting_body_identifier'))
        add('reporting_body', 0,
            f"certified by reporting body {body}"
            + (f" (RBI {identifier})" if identifier else ''))

    return signals


def _score_coords(info: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Position precision and reverse-geocode coverage: descriptive signals
    # about the coordinate, not about anyone standing there.
    signals: List[Dict[str, Any]] = []

    def add(sid: str, weight: int, detail: str) -> None:
        signals.append({'id': sid, 'weight': weight, 'detail': detail})

    geohash = _text(info.get('geohash'))
    if len(geohash) >= _METER_PRECISION_GEOHASH:
        add('precision', 0,
            f"geohash {geohash} carries {len(geohash)} characters - "
            'meter-level precision')

    elevation = _num(info.get('elevation_m'))
    if elevation is not None:
        add('elevation_present', 0,
            f"terrain elevation {_fmt(elevation)} m above sea level")

    place = _text(info.get('formatted_address')) or _text(info.get('place_name')) \
        or _text(info.get('city')) or _text(info.get('locality'))
    country = _text(info.get('country')) or _text(info.get('nearest_country'))
    if place or country:
        add('resolved_place', 0,
            'reverse-geocoded to ' + (country or place))
    else:
        add('unresolved_place', 3,
            'reverse geocoding failed - remote/ocean position or service down')

    return signals


_SCORERS = {
    'ip': _score_ip,
    'domain': _score_domain,
    'email': _score_email,
    'url': _score_url,
    'hash': _score_hash,
    'crypto': _score_crypto,
    'username': _score_username,
    'cve': _score_cve,
    'asn': _score_asn,
    'mac': _score_mac,
    'iban': _score_iban,
    'imei': _score_imei,
    'coords': _score_coords,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _verdict_of(value: int) -> str:
    if value >= 90:
        return 'critical'
    if value >= 70:
        return 'high'
    if value >= 40:
        return 'medium'
    if value >= 15:
        return 'low'
    return 'clean'


def score(kind: str, payload: Any) -> Dict[str, Any]:
    """
    Heuristic technical risk score for one tracker payload.

    Args:
        kind: tracker kind ('ip', 'domain', 'email', 'username', 'url',
            'hash', 'crypto', 'cve', 'asn', 'mac', 'iban', 'imei',
            'coords'); other kinds score 0/clean
        payload: tracker result payload in any shape (never raises)

    Returns:
        ``{'score': 0-100, 'verdict', 'signals': [{'id', 'weight',
        'detail'}], 'summary'}``. Empty payloads return verdict 'unknown'.
        Signals include 0-weight informational entries and negative
        benign-known weights (the total is floored at 0).
    """
    kind = str(kind or '').strip().lower()
    if not isinstance(payload, dict):
        payload = {}
    info = _fields(kind, payload)
    if not _populated(info):
        return {'score': 0, 'verdict': 'unknown', 'signals': [],
                'summary': 'no collected fields to score'}

    handler = _SCORERS.get(kind)
    try:
        signals = handler(info, payload) if handler else []
    except Exception as exc:
        # A broken scorer must never break a lookup; the payload keeps a
        # neutral verdict and the failure is left in the debug log for
        # diagnosis instead of surfacing to the analyst.
        _LOG.debug('risk scorer for %r failed: %s', kind, exc, exc_info=True)
        signals = []

    total = sum(signal['weight'] for signal in signals)
    value = max(0, min(100, total))
    verdict = _verdict_of(value)
    flavor = _FLAVOR.get(kind, '')
    if flavor:
        summary = (f"{flavor}: {value}/100 ({verdict}) from "
                   f"{len(signals)} observation(s)")
    else:
        summary = (f"heuristic score {value}/100 ({verdict}) from "
                   f"{len(signals)} signal(s)")
    return {'score': value, 'verdict': verdict, 'signals': signals,
            'summary': summary}


def attach_risk(kind: str, payload: Any) -> Any:
    """
    Attach a heuristic risk block to a tracker payload (in place).

    Adds ``payload['risk'] = score(kind, payload)`` when
    ``config.app_config.risk_enabled`` is true; the payload is returned
    unchanged (no 'risk' key) when scoring is disabled. Never raises.
    """
    if not isinstance(payload, dict):
        return payload
    with contextlib.suppress(Exception):
        if config.app_config.risk_enabled:
            payload['risk'] = score(kind, payload)
    return payload


def risk_sections(risk: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Report sections for a :func:`score` result.

    A grid (Score / Verdict / Summary) plus a table of the individual
    signals (id / weight / detail), shapes matching
    ``investigate.investigate_sections``.
    """
    risk = risk if isinstance(risk, dict) else {}
    sections: List[Dict[str, Any]] = [{
        'title': 'Risk Assessment', 'type': 'grid', 'data': {
            'Score': f"{risk.get('score', 0)}/100",
            'Verdict': risk.get('verdict', 'unknown'),
            'Summary': risk.get('summary', ''),
        }}]
    signals = risk.get('signals') or []
    if signals:
        sections.append({
            'title': 'Risk Signals', 'type': 'table',
            'columns': ['Signal', 'Weight', 'Detail'],
            'rows': [[signal.get('id'), signal.get('weight'),
                      signal.get('detail')] for signal in signals],
        })
    return sections
