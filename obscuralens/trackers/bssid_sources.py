"""
WiFi BSSID (access point) intelligence sources (v6.0).

A BSSID answers "which access point is this": the EUI-48 address of a WiFi
radio - 24 bits of IEEE-assigned OUI naming the hardware vendor plus 24
bits of device-unique extension. The address bits themselves carry the
multicast/local flags, and crowd-sourced geolocation databases place
observed BSSIDs on the map. This module mixes two offline sources, one
keyless online API and one keyed online API:

* ``oui_vendor`` - offline curated IEEE OUI pack shipped at
                   ``obscuralens/data/oui.txt`` (766 curated
                   ``AABBCC|Vendor Name`` entries), resolving the access
                   point vendor without touching the network. Reuses the
                   same pack the mac kind reads but reports its fields
                   under BSSID-specific names (``vendor`` /
                   ``oui_prefix``).
* ``bssid_math`` - pure-Python EUI-48 bit decomposition: the multicast
                   (group) bit, the locally-administered bit (the U/L bit
                   - a set bit means a randomized privacy MAC, a virtual
                   NIC or a hand-crafted address rather than a burned-in
                   radio address), the EUI-64 expansion and the derived
                   IPv6 interface identifier.
* ``mylnikov``   - api.mylnikov.org crowd-sourced WiFi geolocation
                   (keyless): latitude, longitude and accuracy range for
                   BSSIDs observed by the community, with a 0.3s polite
                   delay between requests.
* ``wigle``      - WiGLE.net network search (keyed, Basic-auth
                   ``base64(id:token)``): the observed SSID, coordinates,
                   encryption and last-seen timestamp for the network this
                   BSSID anchors.

Every provider is queried independently; results are merged field-by-field
so a single flaky source cannot blank out the whole report. Field provenance
is tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.data_packs import DATA_DIR
from ..utils.helpers import fanout_workers
from ..utils.http_client import http
from ..utils.validators import normalize_bssid

#: Vendor strings longer than this are truncated for report sanity (the IEEE
#: registry contains a few pathological legal-entity names).
_MAX_VENDOR_CHARS = 160

#: Polite delay before each mylnikov.org request (the free tier is
#: community-funded and rate limited; one request per BSSID is the deal).
_MYLNIKOV_DELAY = 0.3

#: Parsed OUI pack cache: 6-hex-digit prefix -> vendor name (original case).
#: ``None`` means "not loaded yet"; a dict (possibly empty) is the cache.
_OUI_CACHE: Optional[Dict[str, str]] = None


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _canonical_bssid(value: Any) -> str:
    """
    Coerce ``'00:1A:2B:3C:4D:5E'``, ``'00-1a-2b-3c-4d-5e'``, a Cisco dotted
    ``'001a.2b3c.4d5e'`` or bare hex into the canonical lowercase colon
    form; ``''`` when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_bssid(str(value or ''))


def _load_oui_pack() -> Dict[str, str]:
    """
    Parse the shipped OUI pack into a ``{prefix: vendor}`` map.

    The pack is a plain-text file at ``obscuralens/data/oui.txt`` with one
    ``AABBCC|Vendor Name`` entry per line, ``#``-comments and blank lines
    ignored - the very same pack the mac kind reads (one IEEE registry,
    two consumers). It is parsed directly (not via ``load_data_pack``)
    because vendor names are case-sensitive - "Cisco Systems, Inc" must not
    be lowercased - and cached at module level for the process lifetime. A
    missing or unreadable pack yields an empty dict without raising and
    without caching, so a later call can retry after the file is fixed.
    """
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE

    entries: Dict[str, str] = {}
    path: Path = DATA_DIR / 'oui.txt'
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, ValueError):  # OSError + UnicodeDecodeError
        return entries

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        prefix, _sep, vendor = stripped.partition('|')
        prefix = prefix.strip().upper()
        vendor = vendor.strip()
        if len(prefix) == 6 and len(vendor) >= 2:
            entries.setdefault(prefix, vendor)
    _OUI_CACHE = entries
    return entries


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _oui_vendor(bssid_value: Any) -> Dict[str, Any]:
    """
    Offline curated IEEE OUI pack lookup: the access point vendor.

    The pack carries 766 hand-curated assignments (the vendors an OSINT
    operator actually meets: Cisco, Apple, Ubiquiti, TP-Link, ...). A miss
    means "not in this curated subset", NOT "unknown vendor" - mylnikov /
    wigle still run, and the bit decomposition carries the report either
    way. Fields are reported under BSSID-specific names so a merged report
    can tell the OUI-derived vendor from any future online vendor source.
    """
    bssid = _canonical_bssid(bssid_value)
    if not bssid:
        return {}

    # The pack stores prefixes in IEEE registry casing (AABBCC), so the
    # lowercase canonical prefix is uppercased before the lookup.
    prefix = bssid.replace(':', '')[:6].upper()
    vendor = _load_oui_pack().get(prefix)
    if not vendor:
        # A miss is an EXPECTED outcome for a curated subset (766 of ~40,000
        # public prefixes), not a pack failure: answer with an explicit
        # "no vendor" instead of {} so source health records the execution
        # as OK and the circuit breaker never trips on ordinary misses. The
        # merge layer drops None values, so no vendor field is reported.
        return {'vendor': None}
    return {
        'vendor': vendor[:_MAX_VENDOR_CHARS],
        'oui_prefix': prefix[:2] + ':' + prefix[2:4] + ':' + prefix[4:6],
    }


def _bssid_math(bssid_value: Any) -> Dict[str, Any]:
    """
    Pure-Python EUI-48 bit decomposition - the always-available offline half.

    Derives everything the address bits themselves encode:

    * ``is_multicast``            - I/G bit (least-significant bit of the
                                    first octet): a group address can never
                                    be a real access point BSSID.
    * ``is_locally_administered`` - U/L bit (the local bit, second bit of
                                    the first octet): a set bit means the
                                    address was crafted, not burned in.
    * ``transmission``            - human-readable unicast/multicast class.
    * ``assignment``              - human-readable universal/local class.
    * ``eui64_expansion``         - the EUI-64 form with ``ff:fe`` inserted
                                    in the middle.
    * ``ipv6_interface_id``       - modified EUI-64 (U/L bit flipped) used
                                    by SLAAC, e.g. ``'02:1a:2b:ff:fe:...``.
    * ``ipv6_link_local_hint``    - the predictable ``fe80::`` address an
                                    interface with this BSSID would get.
    * ``randomization_hint``      - only when the local bit is set: the
                                    address may be a privacy-randomized MAC
                                    (iOS/Android/Windows), a virtual NIC or
                                    a hand-crafted address, so the OUI does
                                    not identify a real vendor.
    """
    bssid = _canonical_bssid(bssid_value)
    if not bssid:
        return {}

    octets = bssid.split(':')
    first = int(octets[0], 16)
    is_multicast = bool(first & 0x01)
    is_local = bool(first & 0x02)

    out: Dict[str, Any] = {
        'is_multicast': is_multicast,
        'is_locally_administered': is_local,
        'transmission': 'multicast (group address)' if is_multicast
                        else 'unicast (individual address)',
        'assignment': 'locally administered (LAA)' if is_local
                      else 'globally unique (UAA)',
    }

    # EUI-64 expansion: insert ff:fe between octet 3 and octet 4.
    eui64 = octets[:3] + ['ff', 'fe'] + octets[3:]
    out['eui64_expansion'] = ':'.join(eui64)

    # Modified EUI-64 (RFC 4291): flip the U/L bit for the IPv6 interface id.
    modified = [format(first ^ 0x02, '02x')] + eui64[1:]
    out['ipv6_interface_id'] = ':'.join(modified)
    iid_hex = ''.join(modified)
    out['ipv6_link_local_hint'] = 'fe80::' + ':'.join(
        iid_hex[i:i + 4] for i in range(0, len(iid_hex), 4))

    if is_local:
        out['randomization_hint'] = (
            'locally administered bit set - may be a privacy-randomized MAC '
            '(iOS/Android/Windows), a virtual NIC (Docker/QEMU/VMware) or a '
            'hand-crafted address; the OUI does not identify a real vendor')
    return out


def _mylnikov(bssid_value: Any) -> Dict[str, Any]:
    """
    api.mylnikov.org crowd-sourced WiFi geolocation (keyless).

    Endpoint: ``GET https://api.mylnikov.org/geolocation/wifi?v=1.2&bssid=
    {mac}``. A successful fix answers ``{'result': 200, 'data': {'lat': ...,
    'lon': ..., 'range': ...}}``; ``result != 200`` or an empty ``data``
    block means the community has not observed this BSSID - a clean "no
    data" rather than an error. A 0.3 second polite delay runs before the
    request (the service is free and community-funded).
    """
    bssid = _canonical_bssid(bssid_value)
    if not bssid:
        return {}

    time.sleep(_MYLNIKOV_DELAY)
    ok, data, _err = http.get_json(
        f"https://api.mylnikov.org/geolocation/wifi?v=1.2&bssid={bssid}")
    if not ok or not isinstance(data, dict):
        return {}
    if data.get('result') != 200:
        return {}
    fix = data.get('data')
    if not isinstance(fix, dict) or not fix:
        return {}

    out: Dict[str, Any] = {}
    for api_key, field in (('lat', 'lat'), ('lon', 'lon')):
        raw = fix.get(api_key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            out[field] = float(raw)
    raw = fix.get('range')
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        out['accuracy_range'] = float(raw)
    value = str(fix.get('time') or '').strip()
    if value:
        out['time'] = value[:40]
    return out


def _wigle(bssid_value: Any, key: str) -> Dict[str, Any]:
    """
    WiGLE.net network search (keyed): the observed network record.

    Endpoint: ``GET https://api.wigle.net/api/v2/network/search?onlymine=
    false&netid={mac}`` with ``Authorization: Basic {key}`` - the key is
    the base64 of ``<registered-id>:<api-token>`` exactly as WiGLE's
    account page shows it. The response carries a ``results`` list whose
    first entry describes the network this BSSID anchors: SSID, trilat /
    trilong coordinates, encryption type and the last-seen timestamp.
    Only runs when a key is configured; failures degrade to ``{}`` so the
    offline sources carry the report.
    """
    bssid = _canonical_bssid(bssid_value)
    if not bssid or not key:
        return {}

    headers = {'Authorization': f'Basic {key}'}
    ok, data, _err = http.get_json(
        'https://api.wigle.net/api/v2/network/search'
        f"?onlymine=false&netid={bssid}",
        headers=headers)
    if not ok or not isinstance(data, dict):
        return {}
    results = data.get('results')
    if not isinstance(results, list) or not results:
        return {}
    record = results[0]
    if not isinstance(record, dict):
        return {}

    out: Dict[str, Any] = {}
    for api_key, field in (
        ('ssid', 'ssid'),
        ('lastupdt', 'last_seen'),
    ):
        value = str(record.get(api_key) or '').strip()
        if value:
            out[field] = value[:64]
    for api_key, field in (
        ('trilat', 'lat'),
        ('trilong', 'lon'),
    ):
        raw = record.get(api_key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            out[field] = float(raw)
    encryption = str(record.get('encryption') or '').strip()
    if encryption:
        out['encryption'] = encryption[:32]
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'oui_vendor': _oui_vendor,
    'bssid_math': _bssid_math,
    'mylnikov': _mylnikov,
}

# WiGLE needs an API key (free account tier exists); the reader takes
# (value, key) and is dispatched through the key map in gather_all.
KEYED_SOURCES: Dict[str, Any] = {
    'wigle': _wigle,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'oui_vendor': 'Offline curated IEEE OUI pack (obscuralens/data/oui.txt)',
    'bssid_math': 'Offline EUI-48 bit decomposition: flags, EUI-64, IPv6 hints',
    'mylnikov': 'api.mylnikov.org crowd-sourced WiFi geolocation (keyless)',
    'wigle': 'WiGLE.net network search: SSID, coordinates, encryption (API key)',
}


def _keep(value: Any) -> bool:
    # A BSSID that is NOT multicast (is_multicast == False) is a real answer,
    # so only None / '' / [] / {} count as "no data". Pack readers also use
    # an explicit None value as the "ran fine, nothing curated" marker,
    # which this same rule filters out of the merged fields.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(bssid_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable BSSID source in parallel and merge the results.

    Args:
        bssid_value: BSSID in colon, dash, Cisco dot or bare hex notation
        keys: optional {service: api_key} map - ``{'wigle': key}`` unlocks
            the keyed WiGLE network search

    Returns:
        {
          'fields': merged_field_dict (always includes 'bssid'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as a BSSID.
    """
    keys = keys or {}
    bssid = _canonical_bssid(bssid_value)
    if not bssid:
        raise ValueError(f"invalid BSSID: {bssid_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(bssid))

    for name, fn in _plugin_sources('bssid').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(bssid))

    key_map = {
        'wigle': ('wigle', lambda k: _wigle(bssid, k)),
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

    health.record_batch('bssid', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the shipped curated pack beats the crowd-sourced APIs on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the canonical lowercase colon-separated form every consumer expects.
    merged['bssid'] = bssid

    return {'fields': merged, 'sources': status, 'provenance': provenance}
