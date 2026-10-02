"""
Timeline construction across stored lookups (v4.0).

Collects every date-ish field a tracker payload carries -- registration
dates, breach listing dates, first/last archive captures, CVSS publication
dates -- into one chronological event list so an analyst can see when a
target's infrastructure actually changed.

The registry (:data:`DATE_FIELD_REGISTRY`) maps known field names per kind
to human labels; list-shaped fields (HIBP breaches, username profiles,
Blockchair seen-dates) are walked specially. Every parse is defensive: a
value that does not look like an epoch or an ISO date is silently dropped
and nothing in this module ever raises.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import config

__all__ = ['DATE_FIELD_REGISTRY', 'build_timeline', 'extract_events',
           'timeline_sections']

#: Known date-ish field names per kind, with human labels for reports.
DATE_FIELD_REGISTRY: Dict[str, Dict[str, str]] = {
    'ip': {
        'rdap_registered': 'RDAP registered',
        'rdap_last_changed': 'RDAP last changed',
        'abuse_last_reported': 'Last abuse report',
        'last_update': 'Last InternetDB update',
        'vt_last_analysis': 'Last VirusTotal analysis',
    },
    'domain': {
        'created': 'Created',
        'expires': 'Expires',
        'updated': 'Updated',
        'domain_created': 'Created',
        'domain_expires': 'Expires',
        'domain_updated': 'Updated',
        'rdap_registered': 'RDAP registered',
        'ct_last_seen': 'Last certificate seen',
        'urlscan_last': 'Last urlscan scan',
        'wayback_first': 'First Wayback capture',
        'wayback_last': 'Last Wayback capture',
        'wayback_first_capture': 'First Wayback capture',
        'wayback_last_capture': 'Last Wayback capture',
    },
    'email': {
        'domain_created': 'Domain created',
        'domain_expires': 'Domain expires',
        'domain_updated': 'Domain updated',
    },
    'crypto': {
        'first_seen': 'First seen',
        'last_seen': 'Last seen',
        'blockstream_last_activity': 'Last on-chain activity',
        'eth_tx_first_seen': 'First Ethereum transaction',
        'eth_tx_last_seen': 'Last Ethereum transaction',
    },
    'url': {
        'wayback_first_capture': 'First Wayback capture',
        'wayback_last_capture': 'Last Wayback capture',
        'urlscan_last_scan': 'Last urlscan scan',
        'vt_last_analysis': 'Last VirusTotal analysis',
    },
    'hash': {
        'first_seen': 'First seen',
        'last_seen': 'Last seen',
        'vt_created': 'VirusTotal first seen',
        'otx_last_pulse': 'Last OTX pulse',
    },
    'cve': {
        'published': 'Published',
        'last_modified': 'Last modified',
        'cna_published': 'CNA published',
        'cna_updated': 'CNA updated',
        'osv_published': 'OSV published',
        'osv_modified': 'OSV modified',
        'epss_date': 'EPSS score date',
    },
    'username': {},  # profile joined/created dates are walked specially
    'asn': {},
}

#: Identity field(s) per kind used to label events with their target.
_TARGET_FIELDS: Dict[str, Any] = {
    'ip': ('ip',),
    'domain': ('domain',),
    'email': ('email',),
    'username': ('username',),
    'crypto': ('address',),
    'hash': ('hash',),
    'url': ('url',),
    'cve': ('cve',),
    'asn': ('asn_display', 'asn'),
}

_NUMERIC = re.compile(r'^[+-]?\d+(?:\.\d+)?$')

#: HIBP breach date fields, most authoritative first.
_BREACH_DATE_FIELDS = ('added', 'breach_date', 'date', 'modified')

#: Username profile fields that carry a join/creation date.
_PROFILE_DATE_FIELDS = ('joined', 'created')


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------

def _epoch_to_iso(number: float) -> Optional[str]:
    """Epoch seconds (or milliseconds, detected by magnitude) -> ISO string."""
    if number != number or number <= 0:  # NaN / non-positive guard
        return None
    if number >= 1e12:
        number = number / 1000.0  # millisecond precision
    if number < 1e9 or number >= 1e15:
        return None
    try:
        moment = datetime.fromtimestamp(number, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.strftime('%Y-%m-%dT%H:%M:%S')


def _iso_to_iso(text: str) -> Optional[str]:
    """'YYYY-MM-DD[THH:MM:SS...]' -> normalised 'YYYY-MM-DD[T...]' string."""
    candidate = text[:-1] + '+00:00' if text.endswith(('Z', 'z')) else text
    try:
        moment = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if len(candidate) == 10:
        return moment.strftime('%Y-%m-%d')
    return moment.strftime('%Y-%m-%dT%H:%M:%S')


def _parse_date(value: Any) -> Optional[str]:
    """
    Robust date parser.

    Accepts epoch integers/floats above 1e9 (seconds) or 1e12 (milliseconds),
    numeric strings of the same, ISO dates ('YYYY-MM-DD') and ISO datetimes
    (with optional 'Z' suffix or offset). 'DD/MM/YYYY' is deliberately NOT
    parsed. Returns a normalised ISO string usable as a lexical sort key,
    or None when the value is not a date.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return _epoch_to_iso(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if _NUMERIC.match(text):
            return _epoch_to_iso(float(text))
        return _iso_to_iso(text)
    return None


# ---------------------------------------------------------------------------
# Event extraction
# ---------------------------------------------------------------------------

def _info_of(payload: Any) -> Dict[str, Any]:
    """The field mapping of a tracker payload (payload itself for usernames)."""
    if not isinstance(payload, dict):
        return {}
    info = payload.get('info')
    if isinstance(info, dict):
        return info
    return payload


def _text(value: Any) -> str:
    """String form of a scalar value ('' for containers/None/bools)."""
    if value is None or isinstance(value, (bool, dict, list, tuple, set)):
        return ''
    return str(value).strip()


def _list(value: Any) -> List[Any]:
    """List form of a value (only real sequences qualify)."""
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item is not None]
    return []


def _target_of(kind: str, payload: Any) -> str:
    """Best-effort target label for events extracted from one payload."""
    info = _info_of(payload)
    for field in _TARGET_FIELDS.get(kind, ()):
        text = _text(info.get(field))
        if text:
            return text
    return ''


def _event(kind: str, target: str, label: str, field: str, value: Any,
           date: str) -> Dict[str, Any]:
    return {'date': date, 'sort_key': date, 'kind': kind, 'target': target,
            'label': label, 'field': field, 'value': value}


def _hibp_events(kind: str, target: str, info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One event per HIBP breach (first parseable date, labelled by name)."""
    if kind != 'email':
        return []
    events: List[Dict[str, Any]] = []
    for breach in _list(info.get('hibp_breaches')):
        if not isinstance(breach, dict):
            continue
        name = _text(breach.get('name'))
        for field in _BREACH_DATE_FIELDS:
            raw = breach.get(field)
            date = _parse_date(raw)
            if date:
                label = f"Breached: {name}" if name else 'Data breach listed'
                events.append(_event(kind, target, label,
                                     f"hibp_breaches.{field}", raw, date))
                break
    return events


def _blockchair_events(kind: str, target: str,
                       info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Any blockchair_* first/last-seen date on a crypto payload."""
    if kind != 'crypto':
        return []
    events: List[Dict[str, Any]] = []
    for field, value in info.items():
        if not field.startswith('blockchair_'):
            continue
        if 'seen' not in field and 'activity' not in field:
            continue
        date = _parse_date(value)
        if date:
            label = field.replace('blockchair_', '').replace('_', ' ').title()
            events.append(_event(kind, target, label, field, value, date))
    return events


def _username_events(kind: str, target: str,
                     payload: Any) -> List[Dict[str, Any]]:
    """Join/creation dates found in confirmed username profiles."""
    if kind != 'username':
        return []
    info = _info_of(payload)
    events: List[Dict[str, Any]] = []
    for record in _list(info.get('results')):
        if not isinstance(record, dict) or record.get('status') != 'found':
            continue
        profile = record.get('profile')
        if not isinstance(profile, dict):
            continue
        platform = _text(record.get('platform'))
        for field in _PROFILE_DATE_FIELDS:
            raw = profile.get(field)
            date = _parse_date(raw)
            if date:
                label = f"Joined {platform}" if platform else 'Profile joined'
                events.append(_event(kind, target, label,
                                     f"profile.{field}", raw, date))
    return events


def _dedupe_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """First-occurrence-wins de-duplication on (date, label)."""
    seen = set()
    unique: List[Dict[str, Any]] = []
    for event in events:
        key = (event['date'], event['label'])
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)
    return unique


def extract_events(kind: str, payload: Any) -> List[Dict[str, Any]]:
    """
    Extract dated events from one tracker payload.

    Args:
        kind: tracker kind (see :data:`DATE_FIELD_REGISTRY`)
        payload: tracker result payload in any shape

    Returns:
        List of ``{'date', 'sort_key', 'kind', 'target', 'label', 'field',
        'value'}`` dicts; ``date``/``sort_key`` are normalised ISO strings.
        Never raises; unparseable fields are dropped.
    """
    try:
        kind = str(kind or '').strip().lower()
        info = _info_of(payload)
        target = _target_of(kind, payload)
        events: List[Dict[str, Any]] = []
        for field, label in (DATE_FIELD_REGISTRY.get(kind) or {}).items():
            raw = info.get(field)
            date = _parse_date(raw)
            if date:
                events.append(_event(kind, target, label, field, raw, date))
        events.extend(_hibp_events(kind, target, info))
        events.extend(_blockchair_events(kind, target, info))
        events.extend(_username_events(kind, target, payload))
        return _dedupe_events(events)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Timeline assembly
# ---------------------------------------------------------------------------

def build_timeline(payloads: Optional[List[Dict[str, Any]]],
                   cap: Optional[int] = None) -> Dict[str, Any]:
    """
    Build one chronological timeline across several tracker payloads.

    Args:
        payloads: list of ``{'kind', 'value', 'payload'}`` dicts; events whose
            payload carries no target identity fall back to ``value``
        cap: maximum number of events kept (defaults to
            ``config.app_config.timeline_max_events``); the most recent
            events are kept when truncating

    Returns:
        ``{'events': [...sorted oldest -> newest...], 'count': n,
        'first': <oldest date or None>, 'last': <newest date or None>}``.
    """
    if cap is None:
        cap = int(config.app_config.timeline_max_events or 0)
    events: List[Dict[str, Any]] = []
    for entry in payloads or []:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get('kind') or '').strip().lower()
        fallback = entry.get('value')
        for event in extract_events(kind, entry.get('payload')):
            if not event.get('target'):
                event['target'] = fallback
            events.append(event)
    events.sort(key=lambda event: str(event.get('sort_key') or ''))
    if cap and len(events) > cap:
        events = events[-cap:]
    return {
        'events': events,
        'count': len(events),
        'first': events[0]['date'] if events else None,
        'last': events[-1]['date'] if events else None,
    }


# ---------------------------------------------------------------------------
# Report sections (investigate_sections shape)
# ---------------------------------------------------------------------------

def timeline_sections(timeline: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Report sections for a :func:`build_timeline` result.

    A summary grid (event count, earliest, latest) plus a chronology table
    with Date / Target / Event / Source columns, oldest first.
    """
    timeline = timeline if isinstance(timeline, dict) else {}
    events = timeline.get('events') or []
    sections: List[Dict[str, Any]] = [{
        'title': 'Timeline Summary', 'type': 'grid', 'data': {
            'Events': timeline.get('count', len(events)),
            'Earliest': timeline.get('first') or '-',
            'Latest': timeline.get('last') or '-',
        }}]
    if events:
        sections.append({
            'title': 'Chronology (oldest first)', 'type': 'table',
            'columns': ['Date', 'Target', 'Event', 'Source'],
            'rows': [[event.get('date'), event.get('target'),
                      event.get('label'), event.get('field')]
                     for event in events],
        })
    return sections
