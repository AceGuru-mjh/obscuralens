"""
STIX 2.1 bundle generator (v6.0 Part 4).

STIX is the lingua franca of threat-intel exchange: TAXII stores, SIEM
feeds and multi-vendor case tools all speak it. This module turns one
ObscuraLens tracker envelope into a self-contained STIX 2.1 bundle -
**generated as pure JSON, never validated against a schema** - so an
analyst can drop a lookup straight into any STIX-aware platform.

Deterministic identities: every object id is a UUIDv5 of
``'obscuralens-stix-<type>-<seed>'`` under the standard URL namespace,
so re-exporting the same indicator yields byte-identical ids and
re-imports merge instead of duplicating.

Object vocabulary:

* :func:`build_indicator` - an Indicator SDO for the target itself.
* :func:`build_observed_data` - an Observed Data SDO whose ``objects``
  graph carries one standard observable (``ipv4-addr``, ``domain-name``,
  ...) when the kind maps, plus an ``x-obscuralens`` custom object
  holding **every** ``info`` key of the tracker envelope - information
  density first. STIX 2.1 explicitly allows custom object types and
  properties; this build consistently uses the ``x-obscuralens`` prefix.
* :func:`build_vulnerability` - a Vulnerability SDO for CVE lookups
  (a CVE is an identity of a flaw, not an observable to match on).
* :func:`build_note` - a Note SDO carrying the provenance (sources
  OK/failed, field counts, errors) as human-readable content.
* :func:`build_identity` - the fixed ObscuraLens tool identity that
  ``created_by_ref``-style consumers can attribute exports to.
* :func:`build_relationship` - a generic Relationship SDO.
* :func:`build_bundle` - the one-shot packer: identity + indicator (or
  vulnerability) + observed data + provenance note, wired with a
  ``related-to`` relationship.
* :func:`dump_bundle` - pretty-printed UTF-8 file write with an
  ``{'ok', 'path', 'bytes'}`` receipt.

Kind-to-pattern map (see :func:`kind_to_indicator_pattern`):

===================  =========================================================
kind                 STIX pattern
===================  =========================================================
ip                   ``[ipv4-addr:value = '...']`` (or ``ipv6-addr``)
domain               ``[domain-name:value = '...']``
url                  ``[url:value = '...']``
email                ``[email-addr:value = '...']``
mac / bssid          ``[mac-addr:value = '...']``
hash                 ``[file:hashes.'SHA-256' = '...']`` (length-picked)
username             ``[user-account:user_id = '...']``
phone                ``[x-obscuralens:phone = '...']`` (custom - STIX
                     has no phone observable)
crypto               ``[x-obscuralens:crypto-address = '...']`` (custom)
cve                  no pattern - use :func:`build_vulnerability`
others (vin,         ``[x-obscuralens:<kind> = '...']`` (custom)
flight, mmsi, app,
plate, iban, imei,
asn, coords, ...)
===================  =========================================================
"""

import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    'STIX_VERSION',
    'build_bundle',
    'build_identity',
    'build_indicator',
    'build_note',
    'build_observed_data',
    'build_relationship',
    'build_vulnerability',
    'dump_bundle',
    'kind_to_indicator_pattern',
]

#: STIX spec version stamped on every generated object.
STIX_VERSION = '2.1'

#: Hard cap on ``info`` keys carried into observed data (bundle size
#: defence - a tracker envelope with thousands of keys cannot blow up
#: the export).
_MAX_INFO_KEYS = 200

#: Hard cap on string values inside the custom observable.
_MAX_VALUE_CHARS = 2000

#: Hard cap on list length inside the custom observable.
_MAX_LIST_ITEMS = 25

#: Fixed creation stamp for the tool identity (a synthetic Organisation
#: does not age; a fixed stamp keeps exported bundles reproducible).
_IDENTITY_CREATED = '2024-01-01T00:00:00.000Z'

#: Seed prefix folded into every deterministic object id.
_ID_SEED_PREFIX = 'obscuralens-stix-'


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

def _stix_id(object_type: str, seed: str) -> str:
    """
    Deterministic STIX id: ``<type>--<uuid5>``.

    The UUIDv5 is taken over ``'obscuralens-stix-<type>-<seed>'`` under
    :data:`uuid.NAMESPACE_URL`, so the same ``(type, seed)`` pair always
    maps to the same id - re-exports merge, they never duplicate.

    Args:
        object_type: STIX object type ('indicator', 'observed-data'...).
        seed: stable distinguishing text (typically ``kind:value``).

    Returns:
        The composite id string.
    """
    digest = uuid.uuid5(uuid.NAMESPACE_URL,
                        f'{_ID_SEED_PREFIX}{object_type}-{seed}')
    return f'{object_type}--{digest}'


def _now_iso() -> str:
    """Current UTC time as a millisecond-precision ``Z``-suffixed stamp."""
    from datetime import datetime, timezone
    return (datetime.now(timezone.utc).isoformat(timespec='milliseconds')
            .replace('+00:00', 'Z'))


def _seed(kind: str, value: str) -> str:
    """Canonical id seed for one target: ``kind:value``."""
    return f'{str(kind or "unknown").lower()}:{str(value or "")}'


def _escape_pattern_string(value: Any) -> str:
    """
    Escape a string for a single-quoted STIX pattern literal.

    Backslashes and single quotes are the only characters STIX pattern
    grammar escapes inside a quoted string literal.
    """
    return str(value or '').replace('\\', '\\\\').replace("'", "\\'")


def _sanitize_key(key: Any) -> str:
    """
    Coerce an ``info`` key into a STIX-safe property name.

    STIX property names must be lowercase alphanumerics and underscores;
    anything else (hyphens, spaces, capitals, unicode) is folded to
    ``_`` so hostile tracker output can never produce a broken object.
    """
    text = str(key or '').strip().lower()
    cleaned = ''.join(ch if (ch.isalnum() and ch.isascii()) or ch == '_'
                      else '_' for ch in text)
    return cleaned or 'field'


def _clip_value(value: Any, depth: int = 0) -> Any:
    """
    Recursively clip a JSON value for the custom observable.

    Strings are capped at :data:`_MAX_VALUE_CHARS`, lists/tuples at
    :data:`_MAX_LIST_ITEMS` items, dicts at :data:`_MAX_INFO_KEYS` keys
    and two levels of nesting; anything the JSON encoder cannot express
    falls back to its ``str()`` form. Never raises.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if value == value else 0.0  # NaN guard
    if isinstance(value, str):
        text = value
        return text if len(text) <= _MAX_VALUE_CHARS \
            else text[:_MAX_VALUE_CHARS - 1] + '…'
    if isinstance(value, (list, tuple, set)):
        if depth >= 2:
            return f'[{len(value)} items]'
        return [_clip_value(item, depth + 1)
                for item in list(value)[:_MAX_LIST_ITEMS]]
    if isinstance(value, dict):
        if depth >= 2:
            return f'{{{len(value)} keys}}'
        return {_sanitize_key(key): _clip_value(item, depth + 1)
                for key, item in list(value.items())[:_MAX_INFO_KEYS]}
    return str(value)


def _value_of(tracker_result: Dict[str, Any], kind: str,
              value: str = '') -> str:
    """
    The target value behind an envelope: the explicit argument, else the
    kind key (``result['ip']``), else ``result['value']``, else ``''``.
    """
    if value:
        return str(value)
    if isinstance(tracker_result, dict):
        raw = tracker_result.get(kind)
        if raw is None:
            raw = tracker_result.get('value')
        if raw is not None:
            return str(raw)
    return ''


# ---------------------------------------------------------------------------
# Pattern mapping
# ---------------------------------------------------------------------------

def _is_ipv6(value: str) -> bool:
    """Whether a value looks like an IPv6 address (colon-hex grammar)."""
    try:
        import ipaddress
        return ipaddress.ip_address(value).version == 6
    except (ValueError, TypeError):
        return ':' in str(value)


def _hash_algorithm(value: str) -> str:
    """Hash algorithm name for a hex digest, by its length."""
    length = len(str(value or ''))
    if length == 64:
        return 'SHA-256'
    if length == 40:
        return 'SHA-1'
    if length == 32:
        return 'MD5'
    return 'SHA-256'


def kind_to_indicator_pattern(kind: str, value: str
                              ) -> Tuple[Optional[str], str]:
    """
    Map one ObscuraLens kind to a STIX indicator pattern.

    Standard STIX observables are used wherever the vocabulary has one
    (ip/domain/url/email/mac/hash/username). STIX has **no** phone or
    crypto-address observable, and no observable at all for the v6.0
    sensor kinds, so those use the ``x-obscuralens`` custom-extension
    prefix that STIX 2.1 explicitly permits; consumers that do not know
    the extension simply see an opaque custom pattern.

    Args:
        kind: target kind ('ip', 'domain', 'phone', 'vin'...).
        value: the indicator value.

    Returns:
        ``(pattern, pattern_type)`` where ``pattern_type`` is ``'stix'``
        for every mapping; for ``kind='cve'`` the pattern is ``None``
        (``''`` pattern type) because a CVE is exported as a
        Vulnerability SDO via :func:`build_vulnerability`, not as an
        indicator pattern.
    """
    kind = str(kind or '').strip().lower()
    literal = _escape_pattern_string(value)
    if kind == 'ip':
        if _is_ipv6(str(value or '')):
            return f"[ipv6-addr:value = '{literal}']", 'stix'
        return f"[ipv4-addr:value = '{literal}']", 'stix'
    if kind == 'domain':
        return f"[domain-name:value = '{literal}']", 'stix'
    if kind == 'url':
        return f"[url:value = '{literal}']", 'stix'
    if kind == 'email':
        return f"[email-addr:value = '{literal}']", 'stix'
    if kind in ('mac', 'bssid'):
        return f"[mac-addr:value = '{literal}']", 'stix'
    if kind == 'hash':
        algorithm = _hash_algorithm(str(value or ''))
        return f"[file:hashes.'{algorithm}' = '{literal}']", 'stix'
    if kind == 'username':
        return f"[user-account:user_id = '{literal}']", 'stix'
    if kind == 'cve':
        # A CVE identifies a flaw, not an observable: export it as a
        # vulnerability SDO (build_vulnerability) instead of a pattern.
        return None, ''
    if kind == 'phone':
        return f"[x-obscuralens:phone = '{literal}']", 'stix'
    if kind == 'crypto':
        return f"[x-obscuralens:crypto-address = '{literal}']", 'stix'
    return f"[x-obscuralens:{kind or 'value'} = '{literal}']", 'stix'


def _standard_observable(kind: str, value: str) -> Optional[Dict[str, Any]]:
    """
    The standard STIX observable object for a kind, when one exists.

    Returns:
        An observable dict (``{'type': 'ipv4-addr', 'value': ...}`` etc.)
        or ``None`` for kinds with no standard observable (phone,
        crypto, cve, vin, ...) - those live only in the ``x-obscuralens``
        custom object.
    """
    kind = str(kind or '').strip().lower()
    if not value:
        return None
    if kind == 'ip':
        address_type = 'ipv6-addr' if _is_ipv6(value) else 'ipv4-addr'
        return {'type': address_type, 'value': value}
    if kind == 'domain':
        return {'type': 'domain-name', 'value': value}
    if kind == 'url':
        return {'type': 'url', 'value': value}
    if kind == 'email':
        return {'type': 'email-addr', 'value': value}
    if kind in ('mac', 'bssid'):
        return {'type': 'mac-addr', 'value': value}
    if kind == 'hash':
        return {'type': 'file',
                'hashes': {_hash_algorithm(value): value}}
    if kind == 'username':
        return {'type': 'user-account', 'user_id': value}
    return None


# ---------------------------------------------------------------------------
# SDO builders
# ---------------------------------------------------------------------------

def build_indicator(kind: str, value: str, labels: Optional[List[str]] = None,
                    confidence: Optional[int] = None) -> Dict[str, Any]:
    """
    Build a STIX 2.1 Indicator SDO for one target.

    Args:
        kind: target kind ('ip', 'domain', ...; 'cve' degrades to a
            custom ``x-obscuralens`` pattern - prefer
            :func:`build_vulnerability` for CVEs).
        value: the indicator value.
        labels: optional label list (default ``['obscuralens', kind]``).
        confidence: optional 0-100 confidence (clamped; omitted when
            unparseable).

    Returns:
        The Indicator SDO dict with a deterministic id.
    """
    kind = str(kind or 'unknown').strip().lower()
    value = str(value or '')
    pattern, pattern_type = kind_to_indicator_pattern(kind, value)
    if pattern is None:
        # Defensive fallback so the indicator is always pattern-bearing.
        pattern = (f"[x-obscuralens:{kind} = "
                   f"'{_escape_pattern_string(value)}']")
        pattern_type = 'stix'
    now = _now_iso()
    indicator: Dict[str, Any] = {
        'type': 'indicator',
        'spec_version': STIX_VERSION,
        'id': _stix_id('indicator', _seed(kind, value)),
        'created': now,
        'modified': now,
        'name': f'{kind}: {value}' if value else f'{kind} indicator',
        'description': (f'Indicator generated by ObscuraLens from a '
                        f'{kind} lookup'),
        'pattern': pattern,
        'pattern_type': pattern_type,
        'valid_from': now,
        'indicator_types': ['unknown'],
        'labels': [str(item) for item in labels] if labels
        else ['obscuralens', kind],
    }
    try:
        score = int(confidence)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        score = None
    if score is not None:
        indicator['confidence'] = max(0, min(100, score))
    return indicator


def build_observed_data(kind: str, tracker_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a STIX 2.1 Observed Data SDO from a tracker envelope.

    The ``objects`` graph (2.0-style embedded objects - chosen over
    2.1 ``object_refs`` so the bundle is self-contained without extra
    SRO/SCO ids) carries:

    * ``'0'`` - the standard observable for the kind, when one exists
      (``ipv4-addr``, ``domain-name``, ``file``, ``user-account``...).
    * the ``x-obscuralens`` custom object - ``kind``, ``value`` and
      **every** ``info`` key of the envelope (capped at
      :data:`_MAX_INFO_KEYS` for bundle-size defence), plus an
      ``x_provenance`` property holding ``sources_ok`` /
      ``sources_failed`` / ``field_sources`` / ``field_count`` /
      ``success`` / ``errors``.

    Args:
        kind: target kind.
        tracker_result: the tracker envelope dict (``info`` key
            expected; anything else yields an empty custom object).

    Returns:
        The Observed Data SDO dict with a deterministic id,
        ``first_observed``/``last_observed`` set to now and
        ``number_observed`` of 1.
    """
    kind = str(kind or 'unknown').strip().lower()
    envelope = tracker_result if isinstance(tracker_result, dict) else {}
    value = _value_of(envelope, kind)
    now = _now_iso()
    objects: Dict[str, Any] = {}
    standard = _standard_observable(kind, value)
    if standard is not None:
        objects['0'] = standard
    custom: Dict[str, Any] = {'type': 'x-obscuralens', 'kind': kind}
    if value:
        custom['value'] = value
    info = envelope.get('info')
    if isinstance(info, dict):
        for key, item in list(info.items())[:_MAX_INFO_KEYS]:
            custom[_sanitize_key(key)] = _clip_value(item)
    provenance: Dict[str, Any] = {}
    sources_ok = envelope.get('sources_ok')
    if isinstance(sources_ok, (list, tuple)):
        provenance['sources_ok'] = [str(name) for name in sources_ok]
    sources_failed = envelope.get('sources_failed')
    if isinstance(sources_failed, dict):
        provenance['sources_failed'] = {
            _sanitize_key(name): _clip_value(detail)
            for name, detail in list(sources_failed.items())[:_MAX_INFO_KEYS]}
    field_sources = envelope.get('field_sources')
    if isinstance(field_sources, dict):
        provenance['field_sources'] = {
            _sanitize_key(name): _clip_value(sources)
            for name, sources in list(field_sources.items())[:_MAX_INFO_KEYS]}
    field_count = envelope.get('field_count')
    if field_count is not None:
        try:
            provenance['field_count'] = int(field_count)
        except (TypeError, ValueError):
            provenance['field_count'] = str(field_count)
    if 'success' in envelope:
        provenance['success'] = bool(envelope.get('success'))
    errors = envelope.get('errors')
    if isinstance(errors, (list, tuple)):
        provenance['errors'] = [str(item) for item in errors[:_MAX_LIST_ITEMS]]
    if provenance:
        custom['x_provenance'] = provenance
    objects[str(len(objects))] = custom
    return {
        'type': 'observed-data',
        'spec_version': STIX_VERSION,
        'id': _stix_id('observed-data', _seed(kind, value)),
        'created': now,
        'modified': now,
        'first_observed': now,
        'last_observed': now,
        'number_observed': 1,
        'objects': objects,
    }


def _cve_description(tracker_result: Dict[str, Any]) -> str:
    """Best-effort human description from a CVE envelope's info block."""
    envelope = tracker_result if isinstance(tracker_result, dict) else {}
    info = envelope.get('info')
    if not isinstance(info, dict):
        return ''
    for key in ('description', 'summary', 'title', 'overview'):
        text = str(info.get(key) or '').strip()
        if text:
            return text[:_MAX_VALUE_CHARS]
    for value in info.values():
        if isinstance(value, str) and len(value.strip()) > 20:
            return value.strip()[:_MAX_VALUE_CHARS]
    return ''


def build_vulnerability(cve_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a STIX 2.1 Vulnerability SDO from a CVE tracker envelope.

    The CVE id comes from the envelope's ``cve`` key (falling back to
    ``value``); the description from the first substantial ``info``
    string; the external reference points at the canonical
    ``cve.org`` record.

    Args:
        cve_result: the CVE tracker envelope (or any dict carrying a
            ``cve``/``value`` key).

    Returns:
        The Vulnerability SDO dict with a deterministic id.
    """
    envelope = cve_result if isinstance(cve_result, dict) else {}
    cve_id = str(envelope.get('cve') or envelope.get('value') or '').strip()
    now = _now_iso()
    vulnerability: Dict[str, Any] = {
        'type': 'vulnerability',
        'spec_version': STIX_VERSION,
        'id': _stix_id('vulnerability', _seed('cve', cve_id)),
        'created': now,
        'modified': now,
    }
    if cve_id:
        vulnerability['name'] = cve_id
    description = _cve_description(envelope)
    if description:
        vulnerability['description'] = description
    if cve_id:
        vulnerability['external_references'] = [{
            'source_name': 'cve.org',
            'external_id': cve_id,
            'url': f'https://www.cve.org/CVERecord?id={cve_id}',
        }]
    return vulnerability


def build_identity() -> Dict[str, Any]:
    """
    The fixed ObscuraLens tool identity (an ``organization`` SDO).

    The id is deterministic and the creation stamp is a fixed constant,
    so every bundle this build has ever produced shares one identity
    object - downstream platforms merge them instead of duplicating.

    Returns:
        The Identity SDO dict.
    """
    return {
        'type': 'identity',
        'spec_version': STIX_VERSION,
        'id': _stix_id('identity', 'obscuralens'),
        'created': _IDENTITY_CREATED,
        'modified': _IDENTITY_CREATED,
        'name': 'ObscuraLens',
        'description': ('ObscuraLens OSINT investigation platform '
                        '(export generator)'),
        'identity_class': 'organization',
    }


def _note_content(subject_kind: str, subject_value: str,
                  tracker_result: Dict[str, Any]) -> str:
    """Human-readable provenance text for the note SDO."""
    envelope = tracker_result if isinstance(tracker_result, dict) else {}
    lines = [f'ObscuraLens provenance for {subject_kind} {subject_value}:']
    success = envelope.get('success')
    if success is not None:
        lines.append(f"- Result: {'success' if success else 'failure'}")
    field_count = envelope.get('field_count')
    sources_ok = envelope.get('sources_ok')
    if field_count is not None or isinstance(sources_ok, (list, tuple)):
        lines.append(f"- Fields: {field_count if field_count is not None else '?'}"
                     f" from {len(sources_ok) if isinstance(sources_ok, (list, tuple)) else '?'}"
                     ' source(s)')
    if isinstance(sources_ok, (list, tuple)) and sources_ok:
        lines.append(f"- Sources OK: {', '.join(str(s) for s in sources_ok[:_MAX_LIST_ITEMS])}")
    sources_failed = envelope.get('sources_failed')
    if isinstance(sources_failed, dict) and sources_failed:
        details = '; '.join(f'{name} ({detail})' for name, detail
                            in list(sources_failed.items())[:_MAX_LIST_ITEMS])
        lines.append(f'- Sources failed: {details}')
    errors = envelope.get('errors')
    if isinstance(errors, (list, tuple)) and errors:
        lines.append(f"- Errors: {'; '.join(str(e) for e in errors[:_MAX_LIST_ITEMS])}")
    return '\n'.join(lines)


def build_note(subject_kind: str, subject_value: str,
               tracker_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a STIX 2.1 Note SDO carrying the tracker's provenance.

    The note references the subject's SDO - the vulnerability for a
    ``cve`` subject, the indicator for everything else - so platforms
    that render notes attach the source reliability context directly to
    the object it describes.

    Args:
        subject_kind: target kind of the referenced object.
        subject_value: the target value.
        tracker_result: the tracker envelope (provenance source).

    Returns:
        The Note SDO dict with a deterministic id.
    """
    subject_kind = str(subject_kind or 'unknown').strip().lower()
    subject_value = str(subject_value or '')
    if subject_kind == 'cve':
        subject_id = _stix_id('vulnerability', _seed('cve', subject_value))
    else:
        subject_id = _stix_id('indicator', _seed(subject_kind, subject_value))
    now = _now_iso()
    return {
        'type': 'note',
        'spec_version': STIX_VERSION,
        'id': _stix_id('note', _seed(subject_kind, subject_value)),
        'created': now,
        'modified': now,
        'abstract': 'ObscuraLens provenance',
        'content': _note_content(subject_kind, subject_value, tracker_result),
        'object_refs': [subject_id],
    }


def build_relationship(source_id: str, target_id: str,
                       rel_type: str) -> Dict[str, Any]:
    """
    Build a STIX 2.1 Relationship SRO between two object ids.

    Args:
        source_id: the ``source_ref`` object id.
        target_id: the ``target_ref`` object id.
        rel_type: relationship type vocabulary entry ('related-to',
            'derived-from'...; unknown values are passed through -
            this module generates, it does not validate).

    Returns:
        The Relationship SRO dict with a deterministic id seeded by all
        three inputs.
    """
    source_id = str(source_id or '')
    target_id = str(target_id or '')
    rel_type = str(rel_type or 'related-to')
    now = _now_iso()
    return {
        'type': 'relationship',
        'spec_version': STIX_VERSION,
        'id': _stix_id('relationship',
                       f'{rel_type}:{source_id}->{target_id}'),
        'created': now,
        'modified': now,
        'relationship_type': rel_type,
        'source_ref': source_id,
        'target_ref': target_id,
    }


# ---------------------------------------------------------------------------
# Bundle assembly
# ---------------------------------------------------------------------------

def build_bundle(kind: str, value: str, tracker_result: Dict[str, Any],
                 include_observed: bool = True,
                 include_notes: bool = True) -> Dict[str, Any]:
    """
    One-shot packer: a complete STIX 2.1 bundle for one tracker result.

    Bundle contents (in order):

    1. the fixed ObscuraLens :func:`build_identity`;
    2. the subject - a :func:`build_vulnerability` for ``kind='cve'``,
       a :func:`build_indicator` for everything else;
    3. when ``include_observed``: the :func:`build_observed_data` graph
       plus a ``related-to`` :func:`build_relationship` wiring subject →
       observed data;
    4. when ``include_notes``: the provenance :func:`build_note`.

    Args:
        kind: target kind.
        value: the target value (falls back to the envelope's kind key
            when empty).
        tracker_result: the tracker envelope.
        include_observed: include the observed-data object + relationship.
        include_notes: include the provenance note.

    Returns:
        ``{'type': 'bundle', 'id': ..., 'objects': [...]}`` with a
        deterministic bundle id seeded by the kind and value.
    """
    kind = str(kind or 'unknown').strip().lower()
    envelope = tracker_result if isinstance(tracker_result, dict) else {}
    value = _value_of(envelope, kind, str(value or ''))
    objects: List[Dict[str, Any]] = [build_identity()]
    if kind == 'cve':
        if value:
            envelope = {**envelope, 'cve': value}
        subject = build_vulnerability(envelope)
    else:
        subject = build_indicator(kind, value)
    objects.append(subject)
    if include_observed:
        observed = build_observed_data(kind, envelope)
        objects.append(observed)
        objects.append(build_relationship(subject['id'], observed['id'],
                                          'related-to'))
    if include_notes:
        objects.append(build_note(kind, value, envelope))
    return {
        'type': 'bundle',
        'id': _stix_id('bundle', _seed(kind, value)),
        'objects': objects,
    }


def dump_bundle(bundle: Dict[str, Any], path: Any) -> Dict[str, Any]:
    """
    Serialise a bundle to a pretty-printed UTF-8 JSON file.

    Args:
        bundle: the dict from :func:`build_bundle` (any JSON-safe dict
            is accepted; unserialisable content becomes ``str()``).
        path: destination file path (parent directories are created).

    Returns:
        ``{'ok': True, 'path': str, 'bytes': int, 'error': ''}`` or
        ``{'ok': False, 'path': str, 'bytes': 0, 'error': reason}`` when
        the write failed (unwritable directory, unusable path...).
        Never raises.
    """
    target = Path(str(path or 'bundle.json'))
    try:
        text = json.dumps(bundle if isinstance(bundle, dict) else {},
                          ensure_ascii=False, indent=2, default=str)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return {'ok': True, 'path': str(target),
                'bytes': len(text.encode('utf-8')), 'error': ''}
    except (OSError, TypeError, ValueError) as exc:
        return {'ok': False, 'path': str(target), 'bytes': 0,
                'error': f'{type(exc).__name__}: {exc}'}
