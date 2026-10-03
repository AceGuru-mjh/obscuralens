"""
MAC address (EUI-48) vendor and structure intelligence sources.

A MAC address answers "which organisation made this NIC": the first three
octets (the OUI, Organizationally Unique Identifier) map to a vendor in the
IEEE public registry, the two low bits of the first octet reveal whether the
address is unicast or multicast and globally-unique or locally-administered,
and a 48-bit MAC expands deterministically into an EUI-64 (and from there
into an IPv6 interface identifier). This module mixes one offline pack, one
offline math source and two keyless online APIs:

* ``oui_pack``   - offline curated IEEE OUI pack shipped at
                   ``obscuralens/data/oui.txt`` (766 curated ``AABBCC|Vendor
                   Name`` entries: enterprise networking gear, laptop/phone
                   makers, virtualization platforms, NAS/CCTV/IoT vendors,
                   printers). Resolves the vendor without touching the
                   network, so vendor lookups keep working fully offline.
* ``macvendors`` - api.macvendors.com plain-text lookup against the complete
                   IEEE registry (keyless; empty body / 404 / "Not Found"
                   means no vendor, not an error).
* ``maclookup``  - api.maclookup.app v2 JSON lookup: company, country,
                   registered address and assignment block type (keyless).
* ``mac_math``   - pure-Python EUI-48 decomposition: OUI, multicast and
                   locally-administered bit flags, transmission/assignment
                   classification, IETF reserved-block detection (01:00:5E
                   IPv4 multicast, 33:33 IPv6 multicast), Docker 02:42
                   vNIC detection with the embedded container IPv4, the
                   EUI-64 expansion, the modified-EUI-64 IPv6 interface id
                   plus link-local hint, and a randomization hint when the
                   local bit is set (iOS/Android/Windows privacy MACs).

Every provider is queried independently; results are merged field-by-field
so a single flaky source cannot blank out the whole report. Field provenance
is tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import config
from ..health import health
from ..utils.data_packs import DATA_DIR
from ..utils.http_client import http
from ..utils.validators import normalize_mac

#: Vendor strings longer than this are truncated for report sanity (the IEEE
#: registry contains a few pathological legal-entity names).
_MAX_VENDOR_CHARS = 160

#: Registered-address strings from maclookup capped for the same reason.
_MAX_ADDRESS_CHARS = 200

#: Parsed OUI pack cache: 6-hex-digit prefix -> vendor name (original case).
#: ``None`` means "not loaded yet"; a dict (possibly empty) is the cache.
_OUI_CACHE: Optional[Dict[str, str]] = None

#: IETF reserved EUI-48 blocks reported from the address bits themselves
#: (never present in the OUI pack by design). Multicast prefixes have the
#: multicast bit forced, so their first octets are odd.
_RESERVED_BLOCKS = (
    ('01005e', 'IPv4 multicast block (01:00:5E, RFC 1112) - no vendor assignment'),
    ('3333', 'IPv6 multicast block (33:33, RFC 2464) - no vendor assignment'),
)

#: Locally-administered prefixes that name their platform outright. Docker
#: burns 02:42:xx:xx:xx:xx vNICs whose last four octets embed the container
#: IPv4 (02:42:ac:11:0a:14 -> 172.17.10.20 on the default bridge), which is
#: worth decoding outright - no registry can tell you that.
_VIRTUALIZATION_PREFIXES = (
    ('0242', 'Docker container vNIC (02:42, locally administered)'),
)


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _canonical_mac(value: Any) -> str:
    """
    Coerce ``'B8:27:EB:AA:BB:CC'``, ``'b8-27-eb-aabbcc'`` or a Cisco dotted
    ``'b827.ebdc.aabb'`` into the canonical lowercase colon form; ``''`` when
    unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_mac(str(value or ''))


def _pretty_oui(mac: str) -> str:
    """First three octets of a canonical MAC as a ``'b8:27:eb'`` string."""
    return mac[:8]


def _load_oui_pack() -> Dict[str, str]:
    """
    Parse the shipped OUI pack into a ``{prefix: vendor}`` map.

    The pack is a plain-text file at ``obscuralens/data/oui.txt`` with one
    ``AABBCC|Vendor Name`` entry per line, ``#``-comments and blank lines
    ignored. It is parsed directly (not via ``load_data_pack``) because
    vendor names are case-sensitive - "Cisco Systems, Inc" must not be
    lowercased - and cached at module level for the process lifetime. A
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

def _oui_pack(mac_value: Any) -> Dict[str, Any]:
    """
    Offline curated IEEE OUI pack lookup: the vendor for the first three
    octets.

    The pack carries 766 hand-curated assignments (the vendors an OSINT
    operator actually meets: Cisco, Apple, Samsung, Raspberry Pi, VMware,
    QEMU, ...) with vendor names in their original registry casing. A miss
    means "not in this curated subset", NOT "unknown vendor" - the
    macvendors / maclookup online sources query the full registry, and
    mac_math still decomposes the address either way.
    """
    mac = _canonical_mac(mac_value)
    if not mac:
        return {}

    # The pack stores prefixes in IEEE registry casing (AABBCC), so the
    # lowercase canonical prefix is uppercased before the lookup.
    prefix = mac.replace(':', '')[:6].upper()
    vendor = _load_oui_pack().get(prefix)
    if not vendor:
        # A miss is an EXPECTED outcome for a curated subset (766 of ~40,000
        # public prefixes), not a pack failure: answer with an explicit
        # "no vendor" instead of {} so source health records the execution
        # as OK and the circuit breaker never trips on ordinary misses. The
        # merge layer drops None values, so no vendor field is reported.
        return {'vendor': None}
    return {'vendor': vendor[:_MAX_VENDOR_CHARS], 'oui': _pretty_oui(mac)}


def _macvendors(mac_value: Any) -> Dict[str, Any]:
    """
    api.macvendors.com (keyless): plain-text vendor for the full registry.

    Endpoint: ``GET https://api.macvendors.com/<colon-separated MAC>``. The
    body is the vendor name and nothing else; an unknown OUI answers 404
    (or an empty / "Not Found" body on older gateway versions), which is a
    "no data" outcome rather than an error. The service is rate limited
    (~1k requests/day per IP), so a 429 simply marks the source failed.
    """
    mac = _canonical_mac(mac_value)
    if not mac:
        return {}

    ok, text, _err = http.get_text(f"https://api.macvendors.com/{mac}")
    if not ok or not text:
        return {}

    vendor = text.strip().strip('"').strip()
    if not vendor or vendor.lower() in ('not found', 'not found.', 'error'):
        return {}
    return {'vendor': vendor[:_MAX_VENDOR_CHARS]}


def _maclookup(mac_value: Any) -> Dict[str, Any]:
    """
    api.maclookup.app v2 (keyless): JSON vendor record.

    Endpoint: ``GET https://api.maclookup.app/v2/macs/<MAC>``. Successful
    responses carry ``{"success": true, "found": true, "macPrefix": ...,
    "company": ..., "country": ..., "address": ..., "type": "MA-L"}``;
    ``found: false`` (unknown OUI) is a clean "no data". ``type`` is the
    IEEE assignment flavour (MA-L / MA-M / MA-S / IAB28 / IAB36).
    """
    mac = _canonical_mac(mac_value)
    if not mac:
        return {}

    ok, data, _err = http.get_json(f"https://api.maclookup.app/v2/macs/{mac}")
    if not ok or not isinstance(data, dict):
        return {}
    if data.get('found') is False or not data.get('success', True):
        return {}

    out: Dict[str, Any] = {}
    company = str(data.get('company') or '').strip()
    if company:
        out['vendor'] = company[:_MAX_VENDOR_CHARS]
    country = str(data.get('country') or '').strip()
    if country:
        out['vendor_country'] = country
    address = str(data.get('address') or '').strip()
    if address:
        out['vendor_address'] = address[:_MAX_ADDRESS_CHARS]
    block_type = str(data.get('type') or '').strip()
    if block_type:
        out['assignment_type'] = block_type
    return out


def _mac_math(mac_value: Any) -> Dict[str, Any]:
    """
    Pure-Python EUI-48 decomposition - the always-available offline half.

    Derives everything the address bits themselves encode:

    * ``oui``                       - first three octets (``'b8:27:eb'``).
    * ``is_multicast``              - I/G bit (least-significant bit of the
                                      first octet): group vs individual.
    * ``is_locally_administered``   - U/L bit (second bit): universal IEEE
                                      assignment vs locally crafted.
    * ``transmission``              - human-readable unicast/multicast class.
    * ``assignment``                - human-readable universal/local class.
    * ``eui64_expansion``           - the EUI-64 form with ``ff:fe``
                                      inserted in the middle.
    * ``ipv6_interface_id``         - modified EUI-64 (U/L bit flipped) used
                                      by SLAAC, e.g. ``'ba:27:eb:ff:fe:...``.
    * ``ipv6_link_local_hint``      - the predictable ``fe80::`` address an
                                      interface with this MAC would get.
    * ``randomization_hint``        - only when the local bit is set: the
                                      address may be a privacy-randomized
                                      MAC (iOS/Android/Windows) or a
                                      virtual NIC / hand-crafted address.
    * ``reserved_block``            - only for the IETF multicast blocks
                                      (01:00:5E / 33:33), which the OUI pack
                                      deliberately omits.
    * ``virtualization_hint``       - only for platform-owned locally
                                      administered prefixes (Docker 02:42).
    * ``embedded_ipv4``             - only for Docker 02:42 vNICs: the
                                      container IPv4 the last four octets
                                      encode (``'172.17.10.20'``).
    """
    mac = _canonical_mac(mac_value)
    if not mac:
        return {}

    octets = mac.split(':')
    first = int(octets[0], 16)
    is_multicast = bool(first & 0x01)
    is_local = bool(first & 0x02)

    out: Dict[str, Any] = {
        'oui': mac[:8],
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

    prefix = mac.replace(':', '')
    for block_prefix, description in _RESERVED_BLOCKS:
        if prefix.startswith(block_prefix):
            out['reserved_block'] = description
            break

    for virtual_prefix, description in _VIRTUALIZATION_PREFIXES:
        if prefix.startswith(virtual_prefix):
            out['virtualization_hint'] = description
            if virtual_prefix == '0242':
                out['embedded_ipv4'] = '.'.join(str(int(o, 16)) for o in octets[2:])
            break
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'oui_pack': _oui_pack,
    'macvendors': _macvendors,
    'maclookup': _maclookup,
    'mac_math': _mac_math,
}

# MAC vendor intelligence is fully keyless today; the registry stays here so
# future keyed sources (e.g. paid full-registry API mirrors) slot in without
# touching the tracker or the CLI.
KEYED_SOURCES: Dict[str, Any] = {}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'oui_pack': 'Offline curated IEEE OUI pack (obscuralens/data/oui.txt)',
    'macvendors': 'api.macvendors.com full-registry vendor lookup (keyless)',
    'maclookup': 'api.maclookup.app vendor record, country and block type (keyless)',
    'mac_math': 'Offline EUI-48 bit decomposition: flags, EUI-64, IPv6 hints',
}


def _keep(value: Any) -> bool:
    # A MAC that is NOT multicast (is_multicast == False) is a real answer,
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


def gather_all(mac_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable MAC source in parallel and merge the results.

    Args:
        mac_value: MAC address in colon, dash or Cisco dot notation
        keys: optional {service: api_key} map - unused today, accepted for
            interface compatibility with the other source modules

    Returns:
        {
          'fields': merged_field_dict (always includes 'mac'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as a MAC address.
    """
    keys = keys or {}
    mac = _canonical_mac(mac_value)
    if not mac:
        raise ValueError(f"invalid MAC address: {mac_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(mac))

    for name, fn in _plugin_sources('mac').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(mac))

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

    health.record_batch('mac', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the shipped curated pack beats third-party API mirrors on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the canonical lowercase colon-separated form every consumer expects.
    merged['mac'] = mac

    return {'fields': merged, 'sources': status, 'provenance': provenance}
