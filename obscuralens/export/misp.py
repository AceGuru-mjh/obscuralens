"""
MISP core JSON event export (v6.0 Part 4).

MISP is where shared indicators go to be curated, correlated and pushed
on to the next team. This module turns one ObscuraLens tracker envelope
into a single **MISP core format** event - the JSON shape MISP itself
accepts on import - with no external libraries: just deterministic
UUIDv5 ids, Unix timestamps and a plain dict assembly.

Event shape::

    {'Event': {'id', 'info', 'date' ('YYYY-MM-DD'), 'threat_level_id'
               ('1'..'4'), 'analysis' ('0' = initial), 'published'
               (False), 'timestamp' (Unix int), 'orgc': {'name':
               'ObscuraLens', 'uuid': <fixed>}, 'Attribute': [...],
               'Tag': [{'name': ...}, ...]}}

Public surface:

* :func:`kind_to_attribute` - the kind → MISP attribute mapping
  (ip → ``ip-src``, domain → ``domain``, url → ``url``, email →
  ``email-src``, hashes → ``sha256``/``sha1``/``md5`` by digest length;
  username and every kind MISP has no native type for degrade to
  ``text`` with the kind in the comment).
* :func:`build_event` - an empty event shell with the fixed ObscuraLens
  orgc identity and a deterministic event id.
* :func:`result_to_attributes` - every ``info`` field of a tracker
  envelope as one ``text`` attribute (comment = field name, capped at
  200 attributes) plus one ``sources_ok`` provenance attribute.
* :func:`build_misp_event` - the one-shot packer: target attribute +
  field attributes + source attribute inside one event, threat level
  mapped from the envelope (3 = clean success, 2 = anything errored).
* :func:`threat_level_for` - the threat-level mapping as a pure helper.
* :func:`dump_event` - pretty-printed UTF-8 file write with an
  ``{'ok', 'path', 'bytes'}`` receipt.

Everything is generated, not validated: values are clipped, keys are
sanitised and hostile input degrades into well-formed MISP JSON rather
than an exception.
"""

import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = [
    'MISP_ORG_NAME',
    'MISP_ORG_UUID',
    'build_event',
    'build_misp_event',
    'dump_event',
    'kind_to_attribute',
    'result_to_attributes',
    'threat_level_for',
]

#: Fixed exporting organisation identity (MISP ``orgc`` block).
MISP_ORG_NAME = 'ObscuraLens'

#: Deterministic UUID for the exporting organisation - every event this
#: build has ever produced shares one orgc identity, so importing
#: platforms merge instead of duplicating.
MISP_ORG_UUID = str(uuid.uuid5(uuid.NAMESPACE_URL, 'obscuralens-misp-orgc'))

#: Hard cap on ``info``-derived attributes per event (bundle size
#: defence - a tracker envelope with thousands of keys cannot blow up
#: the export).
_MAX_ATTRIBUTES = 200

#: Hard cap on one attribute value (MISP accepts more, but a 2 MB info
#: blob helps nobody's event listing).
_MAX_VALUE_CHARS = 1000

#: Seed prefix folded into every deterministic attribute uuid.
_ID_SEED_PREFIX = 'obscuralens-misp-'


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

def _now_unix() -> int:
    """Current Unix timestamp as an int (MISP's timestamp convention)."""
    return int(time.time())


def _today() -> str:
    """Local today as ``YYYY-MM-DD`` (MISP's event date convention)."""
    return datetime.now().strftime('%Y-%m-%d')


def _clip(text: Any, limit: int = _MAX_VALUE_CHARS) -> str:
    """Clip a value to ``limit`` characters with an ellipsis marker."""
    value = str(text if text is not None else '')
    if len(value) <= limit:
        return value
    return value[:limit - 1] + '…'


def _value_to_text(value: Any) -> str:
    """
    Render one ``info`` field value as attribute text.

    Scalars stringify; lists join with ``, ``; dicts render as compact
    JSON (``str`` fallback for the exotic). Empty values return ``''``
    so the caller can skip them.
    """
    if value is None:
        return ''
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        parts = [_value_to_text(item) for item in value]
        return ', '.join(part for part in parts if part)
    if isinstance(value, dict):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _attribute_uuid(kind: str, value: str, comment: str) -> str:
    """
    Deterministic attribute UUID (uuidv5 over kind/value/comment).

    Re-exporting the same target yields the same attribute uuid, so
    repeated imports update in place instead of duplicating.
    """
    seed = f'{_ID_SEED_PREFIX}attribute-{kind}:{value}:{comment}'
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def _text_attribute(value: str, comment: str = '',
                    category: str = 'Other') -> Dict[str, Any]:
    """
    One generic ``text`` attribute (the catch-all MISP representation).

    Args:
        value: the attribute value (clipped to :data:`_MAX_VALUE_CHARS`).
        comment: provenance comment ('field name', 'sources_ok'...).
        category: MISP category (default ``'Other'``).

    Returns:
        The MISP attribute dict.
    """
    kind = 'text'
    return {
        'category': category,
        'type': kind,
        'value': _clip(value),
        'comment': _clip(comment, 200),
        'to_ids': False,
        'timestamp': _now_unix(),
        'uuid': _attribute_uuid(kind, str(value), str(comment)),
    }


def _hash_type(value: str) -> str:
    """MISP hash type for a hex digest, by its length."""
    length = len(str(value or ''))
    if length == 40:
        return 'sha1'
    if length == 32:
        return 'md5'
    return 'sha256'


# ---------------------------------------------------------------------------
# Kind mapping
# ---------------------------------------------------------------------------

def kind_to_attribute(kind: str, value: str) -> Dict[str, Any]:
    """
    Map one ObscuraLens kind to a MISP attribute for the target itself.

    Mapping table:

    =========  ==================  ==================  ==============
    kind       MISP type           category            comment
    =========  ==================  ==================  ==============
    ip         ``ip-src``          Network activity    ''
    domain     ``domain``          Network activity    ''
    url        ``url``             Network activity    ''
    email      ``email-src``       Payload delivery    ''
    hash       ``sha256``/``sha1`` Payload delivery    ''
               /``md5`` (by digest length)
    username   ``text``            Attribution         'username'
    others     ``text``            Other               the kind name
    (phone, crypto, cve, asn, mac, bssid, iban, imei,
    vin, flight, mmsi, app, plate, coords, ...)
    =========  ==================  ==================  ==============

    MISP has no official phone/crypto-address/cve-sensor types in this
    build's conservative vocabulary, so those degrade to ``text``
    attributes that keep the kind in the comment - a curator sees
    exactly what the value is and can retag it in MISP itself.
    ``to_ids`` is always False: an OSINT lookup is evidence, not yet a
    blocking rule.

    Args:
        kind: target kind.
        value: the target value.

    Returns:
        ``{'category', 'type', 'value', 'comment', 'to_ids',
        'timestamp', 'uuid'}`` with a deterministic uuid.
    """
    kind = str(kind or '').strip().lower()
    value = _clip(str(value or '').strip())
    if kind == 'ip':
        attribute_type, category, comment = 'ip-src', 'Network activity', ''
    elif kind == 'domain':
        attribute_type, category, comment = 'domain', 'Network activity', ''
    elif kind == 'url':
        attribute_type, category, comment = 'url', 'Network activity', ''
    elif kind == 'email':
        attribute_type, category, comment = 'email-src', 'Payload delivery', ''
    elif kind == 'hash':
        attribute_type = _hash_type(value)
        category, comment = 'Payload delivery', ''
    elif kind == 'username':
        attribute_type, category, comment = 'text', 'Attribution', 'username'
    else:
        attribute_type, category, comment = 'text', 'Other', kind or 'target'
    return {
        'category': category,
        'type': attribute_type,
        'value': value,
        'comment': comment,
        'to_ids': False,
        'timestamp': _now_unix(),
        'uuid': _attribute_uuid(attribute_type, value, comment),
    }


# ---------------------------------------------------------------------------
# Event assembly
# ---------------------------------------------------------------------------

def _event_id(title: str) -> str:
    """
    Deterministic numeric event id (uuidv5 hex prefix as an int).

    MISP event ids are numeric strings; deriving one from the title
    keeps repeated exports of the same investigation stable instead of
    colliding every event on ``'1'``.
    """
    digest = uuid.uuid5(uuid.NAMESPACE_URL,
                        f'{_ID_SEED_PREFIX}event-{title}')
    return str(int(digest.hex[:8], 16))


def build_event(title: str, info: str, threat_level: int = 3,
                tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Build an empty MISP core-format event shell.

    Args:
        title: the event headline (merged into ``Event.info`` - see
            below).
        info: longer human description of the event.
        threat_level: MISP threat level 1-4 (3 = high/medium default
            here, 2 = medium, 1 = low... clamped into range).
        tags: optional tag names rendered as ``[{'name': ...}]``.

    Returns:
        ``{'Event': {..., 'Attribute': [], 'Tag': [...]}}`` where
        ``info`` is the title and description composed - ``"title -
        description"`` when both are given, whichever is non-empty
        otherwise, ``'ObscuraLens export'`` as the last resort.
    """
    title = str(title or '').strip()
    info = str(info or '').strip()
    summary = f'{title} - {info}' if title and info \
        else title or info or 'ObscuraLens export'
    try:
        level = max(1, min(4, int(threat_level)))
    except (TypeError, ValueError):
        level = 3
    tag_names = tags if isinstance(tags, (list, tuple)) else []
    return {
        'Event': {
            'id': _event_id(summary),
            'info': summary,
            'date': _today(),
            'threat_level_id': str(level),
            'analysis': '0',       # 0 = initial analysis
            'published': False,    # export, not a disclosure decision
            'timestamp': _now_unix(),
            'orgc': {'name': MISP_ORG_NAME, 'uuid': MISP_ORG_UUID},
            'Attribute': [],
            'Tag': [{'name': str(name)} for name in tag_names if str(name)],
        },
    }


def result_to_attributes(tracker_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Explode a tracker envelope's ``info`` block into text attributes.

    Every non-empty ``info`` field becomes one ``text`` attribute whose
    comment is the field name (so a MISP curator sees the semantic of
    every value), capped at :data:`_MAX_ATTRIBUTES` attributes; the
    envelope's ``sources_ok`` list becomes one extra ``text`` attribute
    with comment ``sources_ok`` carrying the comma-joined source names.

    Args:
        tracker_result: the tracker envelope (anything not a dict is
            treated as empty).

    Returns:
        List of MISP attribute dicts (empty when the envelope carries
        no renderable content).
    """
    envelope = tracker_result if isinstance(tracker_result, dict) else {}
    attributes: List[Dict[str, Any]] = []
    info = envelope.get('info')
    if isinstance(info, dict):
        for key, value in list(info.items())[:_MAX_ATTRIBUTES]:
            text = _value_to_text(value)
            if not text:
                continue
            attributes.append(_text_attribute(text, str(key)))
    sources_ok = envelope.get('sources_ok')
    if isinstance(sources_ok, (list, tuple)) and sources_ok:
        names = ', '.join(str(name) for name in sources_ok
                         if str(name or '').strip())
        if names:
            attributes.append(_text_attribute(names, 'sources_ok'))
    return attributes[:_MAX_ATTRIBUTES]


def threat_level_for(tracker_result: Dict[str, Any]) -> int:
    """
    Map a tracker envelope onto a MISP threat level (pure helper).

    A successful lookup with no errors means the platform trusts the
    data (threat level 3); any error at all - partial source failures
    or a full lookup failure - downgrades the event to 2, inviting the
    curator to review before it propagates.

    Args:
        tracker_result: the tracker envelope.

    Returns:
        3 when ``success`` is truthy and ``errors`` is empty, else 2.
    """
    envelope = tracker_result if isinstance(tracker_result, dict) else {}
    errors = envelope.get('errors')
    has_errors = bool(errors) if isinstance(errors, (list, tuple, dict,
                                                     str)) else False
    if envelope.get('success') and not has_errors:
        return 3
    return 2


def build_misp_event(kind: str, value: str, tracker_result: Dict[str, Any],
                     title: Optional[str] = None) -> Dict[str, Any]:
    """
    One-shot packer: a complete MISP core-format event for one lookup.

    The event carries the fixed ObscuraLens ``orgc``, a deterministic
    id, the tag ``obscuralens:<kind>``, the target attribute from
    :func:`kind_to_attribute`, the ``info``-field attributes from
    :func:`result_to_attributes`, and a threat level from
    :func:`threat_level_for`. The ``info`` summary line reports the
    field count, source counts and error count of the envelope.

    Args:
        kind: target kind.
        value: the target value (falls back to the envelope's kind key
            when empty).
        tracker_result: the tracker envelope.
        title: optional event headline (default
            ``"ObscuraLens <kind> lookup: <value>"``).

    Returns:
        The MISP event dict (``{'Event': {...}}``).
    """
    kind = str(kind or 'unknown').strip().lower()
    envelope = tracker_result if isinstance(tracker_result, dict) else {}
    if not str(value or '').strip():
        raw = envelope.get(kind)
        if raw is None:
            raw = envelope.get('value')
        value = str(raw or '')
    value = str(value)
    info_block = envelope.get('info')
    field_count = len(info_block) if isinstance(info_block, dict) else 0
    sources_ok = envelope.get('sources_ok')
    source_count = len(sources_ok) if isinstance(sources_ok, (list, tuple)) \
        else 0
    errors = envelope.get('errors')
    error_count = len(errors) if isinstance(errors, (list, tuple)) else 0
    headline = str(title or '').strip() \
        or f'ObscuraLens {kind} lookup: {value}'
    description = (f'{field_count} field(s) from {source_count} source(s), '
                   f'{error_count} error(s)')
    event = build_event(headline, description,
                        threat_level=threat_level_for(envelope),
                        tags=[f'obscuralens:{kind}'])
    attributes = [kind_to_attribute(kind, value)]
    attributes.extend(result_to_attributes(envelope))
    event['Event']['Attribute'] = attributes
    return event


def dump_event(event: Dict[str, Any], path: Any) -> Dict[str, Any]:
    """
    Serialise a MISP event to a pretty-printed UTF-8 JSON file.

    Args:
        event: the dict from :func:`build_misp_event` (any JSON-safe
            dict is accepted; unserialisable content becomes ``str()``).
        path: destination file path (parent directories are created).

    Returns:
        ``{'ok': True, 'path': str, 'bytes': int, 'error': ''}`` or
        ``{'ok': False, 'path': str, 'bytes': 0, 'error': reason}`` when
        the write failed. Never raises.
    """
    target = Path(str(path or 'misp-event.json'))
    try:
        text = json.dumps(event if isinstance(event, dict) else {},
                          ensure_ascii=False, indent=2, default=str)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return {'ok': True, 'path': str(target),
                'bytes': len(text.encode('utf-8')), 'error': ''}
    except (OSError, TypeError, ValueError) as exc:
        return {'ok': False, 'path': str(target), 'bytes': 0,
                'error': f'{type(exc).__name__}: {exc}'}
