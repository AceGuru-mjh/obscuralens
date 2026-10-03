"""
Typed models for ObscuraLens REST API payloads.

Every model is a tolerant dataclass built from the JSON the server actually
returns (see ``obscuralens/web/app.py``): unknown keys are ignored, missing
keys fall back to sane defaults, and nothing ever raises on payload shape.
The raw payload is always preserved on ``.raw`` so power users can reach
fields the dataclasses do not model yet.

Construct models directly from response dicts via the ``from_dict``
classmethod::

    from obscuralens.sdk import ObscuraLensClient, LookupResult

    client = ObscuraLensClient()
    payload = client.raw_get('/api/lookup/ip/8.8.8.8')
    result = LookupResult.from_dict(payload, kind='ip')
    print(result.summary())
"""

from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

__all__ = [
    'from_dict',
    'SourceStatus',
    'ProvenanceEntry',
    'Provenance',
    'LookupResult',
    'RiskReport',
    'TimelineEvent',
    'Timeline',
    'CorrelationCluster',
    'CorrelationResult',
    'PairComparison',
    'CaseItem',
    'CaseNote',
    'Case',
    'WatchEntry',
    'WatchDiff',
    'DiffReport',
    'SourceHealthEntry',
    'StatsSummary',
    'InvestigationReport',
    'ToolboxResult',
    'KindInfo',
    'ServiceKey',
    'HistoryItem',
    'HistoryResult',
    'AlertEntry',
    'AlertConfig',
    'PatternFinding',
    'PatternReport',
    'BatchEntry',
    'BatchProgress',
    'IntelVerdict',
    'TARGET_KEYS',
    'KINDS',
]

#: The 14 target kinds supported by the v5.x API (mirrors web/app.py KINDS).
KINDS: Sequence[str] = ('ip', 'phone', 'username', 'email', 'domain', 'url',
                        'crypto', 'hash', 'cve', 'asn', 'mac', 'iban',
                        'imei', 'coords')

#: Field each tracker uses to echo back the queried target (mirrors
#: ``_TARGET_KEY`` in ``obscuralens/web/app.py``).
TARGET_KEYS: Dict[str, str] = {
    'ip': 'ip',
    'phone': 'phone_number',
    'username': 'username',
    'email': 'email',
    'domain': 'domain',
    'url': 'url',
    'crypto': 'address',
    'hash': 'hash',
    'cve': 'cve',
    'asn': 'asn',
    'mac': 'mac',
    'iban': 'iban',
    'imei': 'imei',
    'coords': 'coords',
}

#: Verdict band edges used when a payload lacks an explicit verdict
#: (mirrors correlation/risk.py: 0-14 clean, 15-39 low, 40-69 medium,
#: 70-89 high, 90+ critical).
BAND_EDGES = ((90, 'critical'), (70, 'high'), (40, 'medium'), (15, 'low'))

_VERDICTS = ('clean', 'low', 'medium', 'high', 'critical', 'unknown')


# ---------------------------------------------------------------------------
# Tolerant coercion helpers
# ---------------------------------------------------------------------------

def from_dict(data: Any) -> Dict[str, Any]:
    """
    Normalise any payload into a plain dict (shared from_dict helper).

    Args:
        data: a mapping, ``None`` or anything else.

    Returns:
        ``dict(data)`` for mappings, ``{}`` otherwise — extra keys are kept,
        missing keys simply stay absent. Never raises.

    Example:
        >>> from_dict(None)
        {}
        >>> from_dict({'a': 1})
        {'a': 1}
    """
    if isinstance(data, Mapping):
        return dict(data)
    return {}


def _pick(data: Mapping[str, Any], *keys: str,
          default: Any = None) -> Any:
    """Return the first present, non-None value among ``keys``."""
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def _as_str(value: Any, default: str = '') -> str:
    """Coerce to ``str`` (``None`` and missing values become ``default``)."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _as_int(value: Any, default: int = 0) -> int:
    """Coerce to ``int``; floats are truncated, junk falls back."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any) -> Optional[float]:
    """Coerce to ``float`` or ``None`` — never raises."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any, default: bool = False) -> bool:
    """Coerce to ``bool`` with an explicit default for ``None``."""
    if value is None:
        return default
    return bool(value)


def _as_str_list(value: Any) -> List[str]:
    """Coerce a list-ish value into ``List[str]`` (a scalar wraps)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [_as_str(item) for item in value]
    return [_as_str(value)]


def _as_str_dict(value: Any) -> Dict[str, str]:
    """Coerce a mapping into ``Dict[str, str]`` (values stringified)."""
    if not isinstance(value, Mapping):
        return {}
    return {_as_str(key): _as_str(item) for key, item in value.items()}


def _parse_iso(value: Any) -> Optional[datetime]:
    """Best-effort ISO-8601 parse; ``None`` for junk or missing values."""
    text = _as_str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        pass
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y/%m/%d %H:%M:%S'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _score_band(score: int) -> str:
    """Map a 0-100 score onto the verdict band name."""
    for edge, band in BAND_EDGES:
        if score >= edge:
            return band
    return 'clean'


def _normalise_verdict(value: Any) -> str:
    """Lower-case verdict names, keeping unknown ones as-is."""
    text = _as_str(value).strip().lower()
    if text in _VERDICTS:
        return text
    return text if text else 'unknown'


# ---------------------------------------------------------------------------
# Sources / provenance
# ---------------------------------------------------------------------------

@dataclass
class SourceStatus:
    """One named data source and whether it answered during a lookup."""

    name: str = ''
    ok: bool = False
    latency_ms: Optional[float] = None
    error: str = ''

    @classmethod
    def from_dict(cls, data: Any) -> 'SourceStatus':
        """
        Build from a source-status dict (``{ok, error, latency_ms}`` shapes).

        Args:
            data: the source status mapping.

        Returns:
            A populated :class:`SourceStatus`; junk input yields defaults.
        """
        payload = from_dict(data)
        return cls(
            name=_as_str(_pick(payload, 'name', 'source')),
            ok=_as_bool(payload.get('ok')),
            latency_ms=_as_float(_pick(payload, 'latency_ms', 'elapsed',
                                       'response_time')),
            error=_as_str(payload.get('error')),
        )

    def summary(self) -> str:
        """One-line status: ``name: ok (123ms)`` or ``name: FAILED: err``."""
        if self.ok:
            latency = f' ({self.latency_ms:.0f}ms)' if self.latency_ms is not None else ''
            return f'{self.name or "source"}: ok{latency}'
        return f'{self.name or "source"}: FAILED: {self.error or "unknown error"}'


@dataclass
class ProvenanceEntry:
    """
    Which sources supplied one field (one ``field_sources`` entry).

    Attributes:
        field: the field name (e.g. ``country``).
        sources: source names that supplied it, in confidence order.
    """

    field: str = ''
    sources: List[str] = dc_field(default_factory=list)

    @property
    def source_count(self) -> int:
        """How many distinct sources supplied this field."""
        return len(self.sources)

    @property
    def primary(self) -> Optional[str]:
        """The first (highest-confidence) source, or ``None``."""
        return self.sources[0] if self.sources else None

    @classmethod
    def from_dict(cls, data: Any, field: str = '') -> 'ProvenanceEntry':
        """
        Build from one ``field_sources`` value.

        Args:
            data: a source-name list or a single source name.
            field: the field name when not present in the mapping.

        Returns:
            A populated :class:`ProvenanceEntry`.
        """
        return cls(field=_as_str(field), sources=_as_str_list(data))


@dataclass
class Provenance:
    """
    The ``field_sources`` map of a lookup — field name -> supplying sources.

    Wraps the raw ``Dict[str, List[str]]`` with lookup helpers so callers
    can ask "who supplied this field?" and "what did source X supply?".
    """

    entries: Dict[str, List[str]] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'Provenance':
        """
        Build from a tracker payload (or its ``field_sources`` value).

        Args:
            data: a lookup payload or a provenance mapping.

        Returns:
            A :class:`Provenance` with stringified source lists.
        """
        payload = from_dict(data)
        if 'field_sources' in payload and isinstance(payload['field_sources'], Mapping):
            payload = payload['field_sources']
        entries: Dict[str, List[str]] = {}
        for key, value in payload.items():
            entries[_as_str(key)] = _as_str_list(value)
        return cls(entries=entries)

    def sources_for(self, field: str) -> List[str]:
        """
        Sources that supplied one field.

        Args:
            field: field name.

        Returns:
            Source names (empty list when the field is unknown).

        Example:
            >>> provenance = Provenance.from_dict({'country': ['ipwhois.app']})
            >>> provenance.sources_for('country')
            ['ipwhois.app']
        """
        return list(self.entries.get(field, ()))

    def fields_from(self, source: str) -> List[str]:
        """
        Fields supplied by one source.

        Args:
            source: source name (case-insensitive).

        Returns:
            Field names, in payload order.
        """
        needle = source.lower()
        return [name for name, sources in self.entries.items()
                if any(item.lower() == needle for item in sources)]

    def entry_for(self, field: str) -> ProvenanceEntry:
        """One field's :class:`ProvenanceEntry` (empty when unknown)."""
        return ProvenanceEntry(field=field,
                               sources=self.sources_for(field))

    @property
    def fields(self) -> List[str]:
        """Every field that carries provenance."""
        return list(self.entries.keys())


# ---------------------------------------------------------------------------
# Lookup / risk
# ---------------------------------------------------------------------------

@dataclass
class LookupResult:
    """
    One tracker lookup result — the standard API envelope.

    The server envelope is ``{<target key>, info, field_sources,
    sources_ok, sources_failed, field_count, success, errors}``; this
    model renames ``info`` to :attr:`fields` and keeps the rest.

    Attributes:
        kind: the tracker kind (``ip``, ``domain``, ...).
        target: the looked-up value.
        fields: merged field values (the envelope's ``info``).
        field_sources: field -> supplying source names.
        sources_ok: sources that answered successfully.
        sources_failed: source name -> error message.
        field_count: how many fields carry a value.
        elapsed: wall-clock seconds the server took, when reported.
        success: True when at least one source answered.
        errors: server-side error strings.
        raw: the untouched payload.
    """

    kind: str = ''
    target: str = ''
    fields: Dict[str, Any] = dc_field(default_factory=dict)
    field_sources: Dict[str, List[str]] = dc_field(default_factory=dict)
    sources_ok: List[str] = dc_field(default_factory=list)
    sources_failed: Dict[str, str] = dc_field(default_factory=dict)
    field_count: int = 0
    elapsed: Optional[float] = None
    success: bool = False
    errors: List[str] = dc_field(default_factory=list)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any, kind: Optional[str] = None) -> 'LookupResult':
        """
        Build from a tracker envelope.

        Args:
            data: the raw JSON payload from ``GET /api/lookup/...`` (or any
                dict shaped like it — ``risk()`` envelopes parse too).
            kind: the tracker kind when the caller knows it; otherwise it
                is read from ``data['kind']`` or left blank.

        Returns:
            A populated :class:`LookupResult`; junk input yields defaults
            and never raises.

        Example:
            >>> result = LookupResult.from_dict(
            ...     {'ip': '8.8.8.8', 'info': {'country': 'US'},
            ...      'field_sources': {'country': ['ipwhois.app']},
            ...      'sources_ok': ['ipwhois.app'], 'field_count': 1,
            ...      'success': True}, kind='ip')
            >>> result.get('country')
            'US'
        """
        payload = from_dict(data)
        resolved_kind = _as_str(kind or payload.get('kind'))
        target = ''
        for key in (TARGET_KEYS.get(resolved_kind, ''), 'target', 'value'):
            if key and key in payload and payload[key] is not None:
                target = _as_str(payload[key])
                break
        fields_raw = payload.get('info')
        if not isinstance(fields_raw, Mapping):
            fields_raw = payload.get('fields')
        fields = from_dict(fields_raw)
        field_count = _pick(payload, 'field_count')
        if field_count is None:
            field_count = sum(1 for value in fields.values()
                              if value not in (None, '', [], {}))
        return cls(
            kind=resolved_kind,
            target=target,
            fields=fields,
            field_sources={_as_str(key): _as_str_list(value)
                           for key, value in
                           from_dict(payload.get('field_sources')).items()},
            sources_ok=_as_str_list(payload.get('sources_ok')),
            sources_failed=_as_str_dict(payload.get('sources_failed')),
            field_count=_as_int(field_count),
            elapsed=_as_float(payload.get('elapsed')),
            success=_as_bool(payload.get('success'),
                             default=bool(payload.get('sources_ok'))),
            errors=_as_str_list(payload.get('errors')),
            raw=payload,
        )

    # -- accessors ----------------------------------------------------------

    def get(self, name: str, default: Any = None) -> Any:
        """
        Read one merged field.

        Args:
            name: field name (e.g. ``'country'``).
            default: value returned when the field is absent/``None``.

        Returns:
            The field value or ``default``.

        Example:
            >>> LookupResult.from_dict({'ip': '8.8.8.8',
            ...     'info': {'asn': 'AS15169'}}).get('asn')
            'AS15169'
        """
        return self.fields.get(name, default)

    @property
    def ok(self) -> bool:
        """Alias for :attr:`success`."""
        return self.success

    @property
    def provenance(self) -> Provenance:
        """The field -> sources map wrapped with helpers."""
        return Provenance(entries=dict(self.field_sources))

    @property
    def source_names(self) -> List[str]:
        """Every source name mentioned (ok and failed together)."""
        return self.sources_ok + list(self.sources_failed)

    def sources_for(self, field: str) -> List[str]:
        """Sources that supplied one field (empty list when unknown)."""
        return list(self.field_sources.get(field, ()))

    def summary(self) -> str:
        """
        One-line human summary of the lookup.

        Returns:
            ``"ip 8.8.8.8: 12 fields from 3 source(s) (2 failed)"`` — with
            a trailing error note when every source failed.

        Example:
            >>> print(LookupResult.from_dict(
            ...     {'ip': '8.8.8.8', 'info': {'a': 1}, 'sources_ok': ['s'],
            ...      'field_count': 1, 'success': True}, kind='ip').summary())
            ip 8.8.8.8: 1 field(s) from 1 source(s), 0 failed
        """
        label = f'{self.kind} ' if self.kind else ''
        head = f'{label}{self.target or "?"}: {self.field_count} field(s) ' \
               f'from {len(self.sources_ok)} source(s), ' \
               f'{len(self.sources_failed)} failed'
        if not self.success and self.errors:
            head = f'{head} — {"; ".join(self.errors)}'
        return head


@dataclass
class RiskReport:
    """
    Explainable heuristic risk score for one target.

    The server attaches ``{"score", "verdict", "signals", "summary"}`` to a
    lookup envelope under the ``risk`` key; :meth:`from_dict` accepts the
    whole envelope *or* the bare risk block.

    Attributes:
        kind: the scored target's kind.
        target: the scored target value.
        score: 0-100 weighted signal sum.
        band: verdict band — clean / low / medium / high / critical
            (``unknown`` when the payload had no collected fields).
        signals: ``[{id, weight, detail}]`` — why the score is what it is.
        summary: server-generated one-liner.
        lookup: the lookup envelope as a :class:`LookupResult`, when the
            payload was a full ``risk()`` response.
        raw: the untouched risk block.
    """

    kind: str = ''
    target: str = ''
    score: int = 0
    band: str = 'unknown'
    signals: List[Dict[str, Any]] = dc_field(default_factory=list)
    summary: str = ''
    lookup: Optional[LookupResult] = None
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any, kind: Optional[str] = None,
                  target: Optional[str] = None) -> 'RiskReport':
        """
        Build from a ``risk`` envelope or a bare risk block.

        Args:
            data: either a full lookup envelope carrying ``risk`` (the
                ``GET /api/risk/...`` response) or the risk block itself.
            kind: target kind when known (else read from the envelope).
            target: target value when known (else read from the envelope).

        Returns:
            A populated :class:`RiskReport`.

        Example:
            >>> report = RiskReport.from_dict(
            ...     {'risk': {'score': 42, 'verdict': 'medium',
            ...               'signals': [], 'summary': 's'}},
            ...     kind='domain', target='example.com')
            >>> report.is_medium()
            True
        """
        payload = from_dict(data)
        block = payload.get('risk') if isinstance(payload.get('risk'), Mapping) else None
        envelope: Optional[Dict[str, Any]] = None
        if block is None:
            block = payload
        else:
            envelope = payload
        block = from_dict(block)
        score = _as_int(block.get('score'))
        verdict_raw = _pick(block, 'verdict', 'band')
        if verdict_raw is not None:
            band = _normalise_verdict(verdict_raw)
        elif 'score' in block:
            band = _score_band(score)
        else:
            band = 'unknown'
        lookup = None
        if envelope is not None:
            lookup = LookupResult.from_dict(envelope, kind=kind)
            if not target:
                target = lookup.target
            if not kind:
                kind = lookup.kind
        return cls(
            kind=_as_str(kind),
            target=_as_str(target),
            score=score,
            band=band or 'unknown',
            signals=[dict(item) for item in block.get('signals') or []
                     if isinstance(item, Mapping)],
            summary=_as_str(_pick(block, 'summary', 'note')),
            lookup=lookup,
            raw=block,
        )

    # -- band helpers ---------------------------------------------------------

    def is_clean(self) -> bool:
        """True when the verdict band is exactly ``clean``."""
        return self.band == 'clean'

    def is_low(self) -> bool:
        """True when the verdict band is exactly ``low``."""
        return self.band == 'low'

    def is_medium(self) -> bool:
        """True when the verdict band is exactly ``medium``."""
        return self.band == 'medium'

    def is_high(self) -> bool:
        """True when the verdict band is exactly ``high``."""
        return self.band == 'high'

    def is_critical(self) -> bool:
        """True when the verdict band is exactly ``critical``."""
        return self.band == 'critical'

    def is_high_or_worse(self) -> bool:
        """True for ``high`` or ``critical`` — the alert-worthy bands."""
        return self.band in ('high', 'critical')

    def is_elevated(self) -> bool:
        """True for ``medium`` / ``high`` / ``critical``."""
        return self.band in ('medium', 'high', 'critical')

    def is_unknown(self) -> bool:
        """True when nothing could be scored (no collected fields)."""
        return self.band == 'unknown'

    def explain(self) -> List[str]:
        """
        Human-readable signal lines, sorted by weight (heaviest first).

        Returns:
            ``["risky_service_tags (+5): risky banner(s): ssh", ...]``.

        Example:
            >>> report = RiskReport.from_dict({'score': 5, 'verdict': 'low',
            ...     'signals': [{'id': 'x', 'weight': 5, 'detail': 'd'}]})
            >>> report.explain()
            ['x (+5): d']
        """
        lines = []
        signals = sorted(self.signals,
                         key=lambda item: -_as_int(item.get('weight')))
        for signal in signals:
            weight = _as_int(signal.get('weight'))
            lines.append(f"{_as_str(signal.get('id'))} (+{weight}): "
                         f"{_as_str(signal.get('detail'))}")
        return lines


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    """One dated event on the history timeline."""

    timestamp: str = ''
    kind: str = ''
    target: str = ''
    description: str = ''
    label: str = ''
    field: str = ''
    value: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'TimelineEvent':
        """
        Build from one ``timeline['events']`` entry.

        The server events carry ``date``/``kind``/``target``/``label``/
        ``field``/``value``; the description falls back through label,
        field and value so something readable is always available.

        Args:
            data: one event mapping.

        Returns:
            A populated :class:`TimelineEvent`.
        """
        payload = from_dict(data)
        description = _pick(payload, 'label', 'event', 'description',
                            'field', 'value')
        return cls(
            timestamp=_as_str(_pick(payload, 'date', 'timestamp', 'when')),
            kind=_as_str(payload.get('kind')),
            target=_as_str(payload.get('target')),
            description=_as_str(description),
            label=_as_str(payload.get('label')),
            field=_as_str(payload.get('field')),
            value=_as_str(payload.get('value')),
            raw=payload,
        )

    def when(self) -> Optional[datetime]:
        """The parsed timestamp, or ``None`` when unparseable."""
        return _parse_iso(self.timestamp)


@dataclass
class Timeline:
    """
    The ``GET /api/timeline`` response — events oldest → newest.

    Attributes:
        events: parsed events, oldest first.
        count: event count as reported by the server.
        first: oldest event date (string) or ``None``.
        last: newest event date (string) or ``None``.
        span_days: days between first and last event, when computable.
        raw: the untouched payload.
    """

    events: List[TimelineEvent] = dc_field(default_factory=list)
    count: int = 0
    first: Optional[str] = None
    last: Optional[str] = None
    span_days: Optional[float] = None
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'Timeline':
        """
        Build from a ``GET /api/timeline`` payload.

        Args:
            data: ``{'events': [...], 'count': n, 'first': ..., 'last': ...}``.

        Returns:
            A populated :class:`Timeline`.

        Example:
            >>> timeline = Timeline.from_dict(
            ...     {'events': [{'date': '2024-01-01', 'kind': 'ip',
            ...                  'target': '8.8.8.8', 'label': 'created'}],
            ...      'count': 1, 'first': '2024-01-01',
            ...      'last': '2024-01-01'})
            >>> timeline.events[0].target
            '8.8.8.8'
        """
        payload = from_dict(data)
        events = [TimelineEvent.from_dict(item)
                  for item in payload.get('events') or []
                  if isinstance(item, Mapping)]
        first = _pick(payload, 'first')
        last = _pick(payload, 'last')
        span_days = None
        first_dt, last_dt = _parse_iso(first), _parse_iso(last)
        if first_dt is not None and last_dt is not None:
            span_days = (last_dt - first_dt).total_seconds() / 86400.0
        return cls(
            events=events,
            count=_as_int(payload.get('count'), default=len(events)),
            first=_as_str(first) if first is not None else None,
            last=_as_str(last) if last is not None else None,
            span_days=span_days,
            raw=payload,
        )

    @property
    def targets(self) -> List[str]:
        """Distinct target values in first-appearance order."""
        seen: Dict[str, None] = {}
        for event in self.events:
            if event.target:
                seen.setdefault(event.target, None)
        return list(seen.keys())

    def for_target(self, target: str) -> List[TimelineEvent]:
        """Events whose target equals ``target`` (case-insensitive)."""
        needle = target.lower()
        return [event for event in self.events
                if event.target.lower() == needle]


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

@dataclass
class CorrelationCluster:
    """One connected component of the correlation graph."""

    cluster_id: str = ''
    size: int = 0
    entities: List[str] = dc_field(default_factory=list)
    strength: Optional[int] = None
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'CorrelationCluster':
        """
        Build from one ``clusters`` entry (``{id, size, entities}``).

        Args:
            data: one cluster mapping.

        Returns:
            A populated :class:`CorrelationCluster` — ``strength`` mirrors
            ``size`` when the payload does not carry its own strength.
        """
        payload = from_dict(data)
        size = _as_int(_pick(payload, 'size', 'count'))
        return cls(
            cluster_id=_as_str(_pick(payload, 'id', 'cluster_id')),
            size=size,
            entities=_as_str_list(payload.get('entities')),
            strength=_as_int(payload.get('strength'), default=size)
            if payload.get('strength') is not None else size,
            raw=payload,
        )


@dataclass
class CorrelationResult:
    """
    The ``GET /api/correlate`` graph response.

    Attributes:
        entities: ``[{id, type, value, label}]`` graph nodes.
        links: ``[{from, to, label}]`` graph edges.
        clusters: connected components, largest first.
        bridges: high-degree entities (the cross-target connectors).
        stats: the server stats block (targets/entities/links/...).
        degree: entity id -> degree.
        raw: the untouched payload.
    """

    entities: List[Dict[str, Any]] = dc_field(default_factory=list)
    links: List[Dict[str, Any]] = dc_field(default_factory=list)
    clusters: List[CorrelationCluster] = dc_field(default_factory=list)
    bridges: List[Dict[str, Any]] = dc_field(default_factory=list)
    stats: Dict[str, Any] = dc_field(default_factory=dict)
    degree: Dict[str, int] = dc_field(default_factory=dict)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'CorrelationResult':
        """
        Build from a ``GET /api/correlate`` payload.

        Args:
            data: ``{'entities', 'links', 'clusters', 'stats', 'degree'}``
                (the empty-history shape ``{'entities': [], ...}`` parses
                cleanly too).

        Returns:
            A populated :class:`CorrelationResult`.
        """
        payload = from_dict(data)
        stats = from_dict(payload.get('stats'))
        return cls(
            entities=[dict(item) for item in payload.get('entities') or []
                      if isinstance(item, Mapping)],
            links=[dict(item) for item in payload.get('links') or []
                   if isinstance(item, Mapping)],
            clusters=[CorrelationCluster.from_dict(item)
                      for item in payload.get('clusters') or []
                      if isinstance(item, Mapping)],
            bridges=[dict(item)
                     for item in _pick(stats, 'bridges', default=[]) or []
                     if isinstance(item, Mapping)],
            stats=stats,
            degree={_as_str(key): _as_int(value)
                    for key, value in from_dict(payload.get('degree')).items()},
            raw=payload,
        )

    def largest_cluster(self) -> Optional[CorrelationCluster]:
        """The biggest cluster, or ``None`` when history is empty."""
        return self.clusters[0] if self.clusters else None

    def entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """One entity payload by id, or ``None``."""
        for item in self.entities:
            if _as_str(item.get('id')) == entity_id:
                return item
        return None

    def summary(self) -> str:
        """One-liner: ``"12 entities, 15 links, 3 clusters, 2 bridges"``."""
        return (f'{len(self.entities)} entities, {len(self.links)} links, '
                f'{len(self.clusters)} clusters, {len(self.bridges)} bridges')


@dataclass
class PairComparison:
    """
    The ``GET /api/correlate/pair`` shared-infrastructure comparison.

    Attributes:
        targets: the two compared values ``[a, b]``.
        shared: ``[{entity, type, via_a, via_b}]`` shared infrastructure.
        connections: number of shared entities.
        related: whether the two targets are related within 3 hops.
    """

    targets: List[str] = dc_field(default_factory=list)
    shared: List[Dict[str, Any]] = dc_field(default_factory=list)
    connections: int = 0
    related: bool = False
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'PairComparison':
        """
        Build from a ``correlate/pair`` payload.

        Args:
            data: ``{'targets': [a, b], 'shared': [...],
                'connections': n, 'related': bool}``.

        Returns:
            A populated :class:`PairComparison`.
        """
        payload = from_dict(data)
        shared = [dict(item) for item in payload.get('shared') or []
                  if isinstance(item, Mapping)]
        return cls(
            targets=_as_str_list(payload.get('targets')),
            shared=shared,
            connections=_as_int(_pick(payload, 'connections'),
                                default=len(shared)),
            related=_as_bool(payload.get('related'),
                             default=bool(shared)),
            raw=payload,
        )

    def is_related(self) -> bool:
        """Alias for :attr:`related`."""
        return self.related

    def summary(self) -> str:
        """One-liner: ``"8.8.8.8 <-> dns.google: 2 shared, related"``."""
        left, right = (self.targets + ['?', '?'])[:2]
        state = 'related' if self.related else 'unrelated'
        return f'{left} <-> {right}: {self.connections} shared, {state}'


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@dataclass
class CaseItem:
    """One indicator attached to a case (``case_items`` row)."""

    id: Optional[int] = None
    case_id: Optional[int] = None
    kind: str = ''
    value: str = ''
    note: str = ''
    added_at: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'CaseItem':
        """
        Build from a case item row.

        Args:
            data: ``{id, case_id, kind, value, note, added_at}`` — the
                ``target`` key used by the POST body is accepted as an
                alias for ``value``.

        Returns:
            A populated :class:`CaseItem`.
        """
        payload = from_dict(data)
        return cls(
            id=_as_int(payload.get('id')) or None,
            case_id=_as_int(payload.get('case_id')) or None,
            kind=_as_str(payload.get('kind')),
            value=_as_str(_pick(payload, 'value', 'target')),
            note=_as_str(_pick(payload, 'note', 'text')),
            added_at=_as_str(_pick(payload, 'added_at', 'created_at')),
            raw=payload,
        )


@dataclass
class CaseNote:
    """One free-form note attached to a case (``case_notes`` row)."""

    id: Optional[int] = None
    case_id: Optional[int] = None
    text: str = ''
    created_at: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'CaseNote':
        """
        Build from a case note row.

        Args:
            data: ``{id, case_id, note|text, created_at}``.

        Returns:
            A populated :class:`CaseNote`.
        """
        payload = from_dict(data)
        return cls(
            id=_as_int(payload.get('id')) or None,
            case_id=_as_int(payload.get('case_id')) or None,
            text=_as_str(_pick(payload, 'text', 'note')),
            created_at=_as_str(_pick(payload, 'created_at', 'added_at')),
            raw=payload,
        )


@dataclass
class Case:
    """
    One investigation case (``GET /api/cases/{id}`` row shape).

    Attributes:
        id: numeric case id.
        title: the case name (server key: ``name``).
        description: free-form description.
        status: ``open`` / ``closed`` / ``archived``.
        items: attached indicators.
        notes: attached notes.
        tags: tag strings.
        created_at / updated_at: ISO timestamps.
        item_count / note_count / tag_count: row counts (list endpoint).
        items_by_kind: kind -> item count breakdown (list endpoint).
        raw: the untouched payload.
    """

    id: Optional[int] = None
    title: str = ''
    description: str = ''
    status: str = 'open'
    items: List[CaseItem] = dc_field(default_factory=list)
    notes: List[CaseNote] = dc_field(default_factory=list)
    tags: List[str] = dc_field(default_factory=list)
    created_at: str = ''
    updated_at: str = ''
    item_count: int = 0
    note_count: int = 0
    tag_count: int = 0
    items_by_kind: Dict[str, int] = dc_field(default_factory=dict)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'Case':
        """
        Build from a case row (list or get shape — both parse).

        Args:
            data: the case JSON; ``items``/``notes``/``tags`` may be absent
                (the list endpoint omits them) and counts are derived.

        Returns:
            A populated :class:`Case`.
        """
        payload = from_dict(data)
        items = [CaseItem.from_dict(item)
                 for item in payload.get('items') or []
                 if isinstance(item, Mapping)]
        notes = [CaseNote.from_dict(item)
                 for item in payload.get('notes') or []
                 if isinstance(item, Mapping)]
        tags = _as_str_list(payload.get('tags'))
        return cls(
            id=_as_int(payload.get('id')) or None,
            title=_as_str(_pick(payload, 'title', 'name')),
            description=_as_str(payload.get('description')),
            status=_as_str(payload.get('status'), default='open'),
            items=items,
            notes=notes,
            tags=tags,
            created_at=_as_str(payload.get('created_at')),
            updated_at=_as_str(payload.get('updated_at')),
            item_count=_as_int(_pick(payload, 'item_count'), default=len(items)),
            note_count=_as_int(_pick(payload, 'note_count'), default=len(notes)),
            tag_count=_as_int(_pick(payload, 'tag_count'), default=len(tags)),
            items_by_kind={_as_str(key): _as_int(value) for key, value in
                           from_dict(payload.get('items_by_kind')).items()},
            raw=payload,
        )

    def is_open(self) -> bool:
        """True when the case status is ``open``."""
        return self.status == 'open'

    def is_archived(self) -> bool:
        """True when the case status is ``archived``."""
        return self.status == 'archived'

    def summary(self) -> str:
        """One-liner: ``"#3 acme-phishing [open]: 4 items, 2 notes"``."""
        return (f'#{self.id or "?"} {self.title or "untitled"} '
                f'[{self.status}]: {self.item_count} items, '
                f'{self.note_count} notes, {self.tag_count} tags')


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------

@dataclass
class WatchEntry:
    """One watched target (``GET /api/watch`` row shape)."""

    id: Optional[int] = None
    target: str = ''
    kind: str = ''
    label: str = ''
    created_at: Optional[str] = None
    last_checked: Optional[str] = None
    snapshots: int = 0
    changes: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'WatchEntry':
        """
        Build from a watch row.

        Args:
            data: ``{id, target, kind, label, created_at, last_checked,
                snapshots}`` — an optional ``changes`` block (recent diff)
                is preserved when present.

        Returns:
            A populated :class:`WatchEntry`.
        """
        payload = from_dict(data)
        changes = payload.get('changes') if isinstance(
            payload.get('changes'), Mapping) else None
        return cls(
            id=_as_int(payload.get('id')) or None,
            target=_as_str(payload.get('target')),
            kind=_as_str(payload.get('kind')),
            label=_as_str(payload.get('label')),
            created_at=_as_str(payload.get('created_at')) or None,
            last_checked=_as_str(payload.get('last_checked')) or None,
            snapshots=_as_int(payload.get('snapshots')),
            changes=changes,
            raw=payload,
        )

    def summary(self) -> str:
        """One-liner: ``"domain example.com (2 snapshots, corp site)"``."""
        label = f', {self.label}' if self.label else ''
        return (f'{self.kind or "?"} {self.target}: {self.snapshots} '
                f'snapshot(s){label}')


@dataclass
class WatchDiff:
    """One watch-check change record (``POST /api/watch/check`` output)."""

    watch_id: Optional[int] = None
    target: str = ''
    kind: str = ''
    checked_at: str = ''
    is_first: bool = False
    added: Dict[str, str] = dc_field(default_factory=dict)
    removed: Dict[str, str] = dc_field(default_factory=dict)
    changed: Dict[str, Any] = dc_field(default_factory=dict)
    success: bool = True
    error: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'WatchDiff':
        """
        Build from one watch-check record.

        Args:
            data: ``{watch_id, target, kind, checked_at, is_first, added,
                removed, changed, success, error}``.

        Returns:
            A populated :class:`WatchDiff`.
        """
        payload = from_dict(data)
        changed_raw = payload.get('changed')
        changed = {key: (dict(value) if isinstance(value, Mapping)
                         else {'from': value, 'to': value})
                   for key, value in from_dict(changed_raw).items()}
        return cls(
            watch_id=_as_int(payload.get('watch_id')) or None,
            target=_as_str(payload.get('target')),
            kind=_as_str(payload.get('kind')),
            checked_at=_as_str(payload.get('checked_at')),
            is_first=_as_bool(payload.get('is_first')),
            added=_as_str_dict(payload.get('added')),
            removed=_as_str_dict(payload.get('removed')),
            changed=changed,
            success=_as_bool(payload.get('success'), default=True),
            error=_as_str(payload.get('error')),
            raw=payload,
        )

    def has_changes(self) -> bool:
        """True when anything was added, removed or changed."""
        return bool(self.added or self.removed or self.changed)


@dataclass
class DiffReport:
    """The ``GET /api/diff/{kind}/{target}`` snapshot-diff response."""

    target: str = ''
    kind: str = ''
    changed_any: bool = False
    added: Dict[str, str] = dc_field(default_factory=dict)
    removed: Dict[str, str] = dc_field(default_factory=dict)
    changed: Dict[str, Any] = dc_field(default_factory=dict)
    previous: Optional[str] = None
    current: Optional[str] = None
    note: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'DiffReport':
        """
        Build from a diff payload (single-snapshot notes included).

        Args:
            data: ``{target, kind, changed_any, added, removed, changed,
                previous, current, note?}``.

        Returns:
            A populated :class:`DiffReport`.
        """
        payload = from_dict(data)
        return cls(
            target=_as_str(payload.get('target')),
            kind=_as_str(payload.get('kind')),
            changed_any=_as_bool(payload.get('changed_any')),
            added=_as_str_dict(payload.get('added')),
            removed=_as_str_dict(payload.get('removed')),
            changed=from_dict(payload.get('changed')),
            previous=_as_str(payload.get('previous')) or None,
            current=_as_str(payload.get('current')) or None,
            note=_as_str(payload.get('note')),
            raw=payload,
        )

    def has_changes(self) -> bool:
        """Alias for :attr:`changed_any`."""
        return self.changed_any


# ---------------------------------------------------------------------------
# Health / stats
# ---------------------------------------------------------------------------

@dataclass
class SourceHealthEntry:
    """One data-source health row (from ``GET /api/stats`` source_health)."""

    name: str = ''
    tracker: str = ''
    successes: int = 0
    failures: int = 0
    breaker_open: bool = False
    last_error: str = ''
    state: str = 'untested'
    reliability: float = 0.0
    last_ok: Optional[str] = None
    last_failure: Optional[str] = None
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'SourceHealthEntry':
        """
        Build from one health row.

        Args:
            data: ``{source, kind, ok_count, fail_count, last_error,
                reliability, state, ...}``.

        Returns:
            A populated :class:`SourceHealthEntry` — ``breaker_open`` is
            derived from ``state == 'tripped'``.
        """
        payload = from_dict(data)
        state = _as_str(payload.get('state'), default='untested')
        return cls(
            name=_as_str(_pick(payload, 'source', 'name')),
            tracker=_as_str(_pick(payload, 'kind', 'tracker')),
            successes=_as_int(_pick(payload, 'ok_count', 'successes')),
            failures=_as_int(_pick(payload, 'fail_count', 'failures')),
            breaker_open=state == 'tripped',
            last_error=_as_str(payload.get('last_error')),
            state=state,
            reliability=_as_float(payload.get('reliability')) or 0.0,
            last_ok=_as_str(payload.get('last_ok')) or None,
            last_failure=_as_str(payload.get('last_failure')) or None,
            raw=payload,
        )

    def is_healthy(self) -> bool:
        """True when the state is ``healthy``."""
        return self.state == 'healthy'

    @property
    def total_calls(self) -> int:
        """Successes + failures."""
        return self.successes + self.failures

    def summary(self) -> str:
        """One-liner: ``"ipwhois.app [ip]: 98.5% over 200 calls (healthy)"``."""
        return (f'{self.name or "source"} [{self.tracker or "?"}]: '
                f'{self.reliability:.1f}% over {self.total_calls} calls '
                f'({self.state})')


@dataclass
class StatsSummary:
    """
    The ``GET /api/stats`` payload — database, cache, network and health.

    Tolerant and dict-backed: the four server blocks are kept as plain
    dicts (their shapes evolve with the server), with convenience
    accessors for the headline numbers.
    """

    database: Dict[str, Any] = dc_field(default_factory=dict)
    cache: Dict[str, Any] = dc_field(default_factory=dict)
    network: Dict[str, Any] = dc_field(default_factory=dict)
    source_health: List[SourceHealthEntry] = dc_field(default_factory=list)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'StatsSummary':
        """
        Build from a ``GET /api/stats`` payload.

        Args:
            data: ``{'database': {...}, 'cache': {...}, 'network': {...},
                'source_health': [...]}``.

        Returns:
            A populated :class:`StatsSummary`.
        """
        payload = from_dict(data)
        return cls(
            database=from_dict(payload.get('database')),
            cache=from_dict(payload.get('cache')),
            network=from_dict(payload.get('network')),
            source_health=[SourceHealthEntry.from_dict(item)
                           for item in payload.get('source_health') or []
                           if isinstance(item, Mapping)],
            raw=payload,
        )

    @property
    def total_lookups(self) -> int:
        """Total stored lookups (database block, key-tolerant)."""
        return _as_int(_pick(self.database, 'total', 'total_queries',
                             'total_lookups'))

    @property
    def by_kind(self) -> Dict[str, int]:
        """Lookups per kind (database block, key-tolerant)."""
        raw = _pick(self.database, 'by_type', 'by_kind', 'queries_by_type')
        return {_as_str(key): _as_int(value)
                for key, value in from_dict(raw).items()}

    @property
    def cache_hits(self) -> int:
        """HTTP cache hits (network block)."""
        return _as_int(self.network.get('cache_hits'))

    @property
    def uptime(self) -> Optional[str]:
        """Server uptime text when the server reports one."""
        text = _pick(self.database, 'uptime', 'since')
        return _as_str(text) if text is not None else None

    def healthy_sources(self) -> List[SourceHealthEntry]:
        """Health rows in the ``healthy`` state."""
        return [entry for entry in self.source_health if entry.is_healthy()]

    def tripped_sources(self) -> List[SourceHealthEntry]:
        """Health rows whose circuit breaker is open."""
        return [entry for entry in self.source_health if entry.breaker_open]

    def summary(self) -> str:
        """One-liner: ``"500 lookups, 61.2% cache hits, 3/40 sources tripped"``."""
        tripped = len(self.tripped_sources())
        total = len(self.source_health)
        return (f'{self.total_lookups} lookups, '
                f'{self.network.get("cache_hit_rate", 0)}% cache hits, '
                f'{tripped}/{total} sources tripped')


# ---------------------------------------------------------------------------
# Investigation / toolbox / registry
# ---------------------------------------------------------------------------

@dataclass
class InvestigationReport:
    """
    The ``GET /api/investigate`` payload — auto-detected target + pivots.

    Attributes:
        target: the investigated value.
        kind: the detected kind.
        pivots: the kinds that ran, in order (server key: ``order``).
        results: per-kind :class:`LookupResult` envelopes.
        entities: ``[{type, value, role}]`` graph facts.
        links: ``[{from, label, to}]`` relationships.
        errors: per-pivot error strings.
        mermaid: the Mermaid graph text when the payload carries one.
        sections: report sections when the payload carries them.
        raw: the untouched payload.
    """

    target: str = ''
    kind: str = ''
    pivots: List[str] = dc_field(default_factory=list)
    results: Dict[str, LookupResult] = dc_field(default_factory=dict)
    entities: List[Dict[str, Any]] = dc_field(default_factory=list)
    links: List[Dict[str, Any]] = dc_field(default_factory=list)
    errors: List[str] = dc_field(default_factory=list)
    mermaid: Optional[str] = None
    sections: List[Dict[str, Any]] = dc_field(default_factory=list)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'InvestigationReport':
        """
        Build from a ``GET /api/investigate`` payload.

        Args:
            data: ``{target, kind, order, results, entities, links,
                errors}`` — plus optional ``mermaid``/``sections`` blocks.

        Returns:
            A populated :class:`InvestigationReport`.
        """
        payload = from_dict(data)
        results_raw = from_dict(payload.get('results'))
        results = {kind: LookupResult.from_dict(item, kind=kind)
                   for kind, item in results_raw.items()
                   if isinstance(item, Mapping)}
        return cls(
            target=_as_str(payload.get('target')),
            kind=_as_str(payload.get('kind')),
            pivots=_as_str_list(_pick(payload, 'order', 'pivots')),
            results=results,
            entities=[dict(item) for item in payload.get('entities') or []
                      if isinstance(item, Mapping)],
            links=[dict(item) for item in payload.get('links') or []
                   if isinstance(item, Mapping)],
            errors=_as_str_list(payload.get('errors')),
            mermaid=_as_str(payload.get('mermaid')) or None,
            sections=[dict(item) for item in payload.get('sections') or []
                      if isinstance(item, Mapping)],
            raw=payload,
        )

    def result_for(self, kind: str) -> Optional[LookupResult]:
        """
        The lookup envelope one pivot kind produced.

        Args:
            kind: pivot kind (``'ip'``, ``'domain'``, ...).

        Returns:
            The :class:`LookupResult`, or ``None`` when that kind did not
            run or failed outright.
        """
        return self.results.get(kind)

    def summary(self) -> str:
        """One-liner: ``"domain example.com: 2 lookups, 9 entities"``."""
        return (f'{self.kind or "?"} {self.target or "?"}: '
                f'{len(self.pivots)} lookup(s), {len(self.entities)} '
                f'entities, {len(self.links)} link(s)')


@dataclass
class ToolboxResult:
    """Generic wrapper for a ``/api/tools/*`` response."""

    tool: str = ''
    input: str = ''
    output: Dict[str, Any] = dc_field(default_factory=dict)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any, tool: str = '',
                  input_value: Optional[str] = None) -> 'ToolboxResult':
        """
        Build from any toolbox payload.

        Args:
            data: the tool's JSON response.
            tool: tool name (``'jwt'``, ``'hash-id'``, ...) when known.
            input_value: the input value when the response omits it.

        Returns:
            A :class:`ToolboxResult` — ``output`` is the payload minus the
            obvious echo keys, ``raw`` keeps everything.
        """
        payload = from_dict(data)
        echo = {'text': None, 'value': None, 'token': None, 'input': None,
                'domain': None, 'scheme': None, 'tool': None}
        output = {key: item for key, item in payload.items()
                  if key not in echo}
        resolved_input = input_value
        if resolved_input is None:
            resolved_input = _pick(payload, 'text', 'value', 'token',
                                   'input', 'domain')
        return cls(tool=_as_str(tool or payload.get('tool')),
                   input=_as_str(resolved_input),
                   output=output,
                   raw=payload)

    def get(self, key: str, default: Any = None) -> Any:
        """Read one key from the raw tool payload."""
        return self.raw.get(key, default)


@dataclass
class KindInfo:
    """One target-kind registry entry (``GET /api/kinds``)."""

    kind: str = ''
    label: str = ''
    example: str = ''
    blurb: str = ''
    sources: List[str] = dc_field(default_factory=list)
    source_count: int = 0
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'KindInfo':
        """
        Build from one kinds-registry entry.

        Args:
            data: ``{kind, label, example, blurb, sources,
                source_count}`` (``description`` accepted as blurb alias).

        Returns:
            A populated :class:`KindInfo`.
        """
        payload = from_dict(data)
        sources = _as_str_list(payload.get('sources'))
        return cls(
            kind=_as_str(payload.get('kind')),
            label=_as_str(_pick(payload, 'label', 'title')),
            example=_as_str(payload.get('example')),
            blurb=_as_str(_pick(payload, 'blurb', 'description')),
            sources=sources,
            source_count=_as_int(payload.get('source_count'),
                                 default=len(sources)),
            raw=payload,
        )

    def summary(self) -> str:
        """One-liner: ``"ip — IP address (12 sources): Geo, ASN, ..."``."""
        return f'{self.kind} — {self.label} ({self.source_count} sources): {self.blurb}'


@dataclass
class ServiceKey:
    """One keyed-service status entry (``GET /api/keys``)."""

    service: str = ''
    configured: bool = False
    description: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'ServiceKey':
        """
        Build from one keys-status entry.

        Args:
            data: ``{service, configured, description}``.

        Returns:
            A populated :class:`ServiceKey`.
        """
        payload = from_dict(data)
        return cls(
            service=_as_str(payload.get('service')),
            configured=_as_bool(payload.get('configured')),
            description=_as_str(payload.get('description')),
            raw=payload,
        )


@dataclass
class HistoryItem:
    """One stored lookup-history row (``GET /api/history`` item)."""

    id: Optional[int] = None
    kind: str = ''
    value: str = ''
    timestamp: str = ''
    success: bool = False
    field_count: int = 0
    error: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'HistoryItem':
        """
        Build from one history item.

        Args:
            data: ``{id, kind, value, timestamp, success, field_count,
                error}``.

        Returns:
            A populated :class:`HistoryItem`.
        """
        payload = from_dict(data)
        return cls(
            id=_as_int(payload.get('id')) or None,
            kind=_as_str(payload.get('kind')),
            value=_as_str(payload.get('value')),
            timestamp=_as_str(_pick(payload, 'timestamp', 'created_at')),
            success=_as_bool(payload.get('success')),
            field_count=_as_int(payload.get('field_count')),
            error=_as_str(payload.get('error')),
            raw=payload,
        )

    def when(self) -> Optional[datetime]:
        """The parsed timestamp, or ``None``."""
        return _parse_iso(self.timestamp)


@dataclass
class HistoryResult:
    """The ``GET /api/history`` response — filtered stored lookups."""

    items: List[HistoryItem] = dc_field(default_factory=list)
    count: int = 0
    limit: int = 100
    kind: str = ''
    q: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'HistoryResult':
        """
        Build from a history payload.

        Args:
            data: ``{'items': [...], 'count': n, 'limit': n, 'kind': '',
                'q': ''}``.

        Returns:
            A populated :class:`HistoryResult`.
        """
        payload = from_dict(data)
        items = [HistoryItem.from_dict(item)
                 for item in payload.get('items') or []
                 if isinstance(item, Mapping)]
        return cls(
            items=items,
            count=_as_int(payload.get('count'), default=len(items)),
            limit=_as_int(payload.get('limit'), default=100),
            kind=_as_str(payload.get('kind')),
            q=_as_str(payload.get('q')),
            raw=payload,
        )


# ---------------------------------------------------------------------------
# Alerts / patterns / batch
# ---------------------------------------------------------------------------

@dataclass
class AlertEntry:
    """One webhook-alert event-log entry (``GET /api/alerts`` recent)."""

    ts: str = ''
    event: str = ''
    payload: Dict[str, Any] = dc_field(default_factory=dict)
    delivery: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'AlertEntry':
        """
        Build from one alert-log entry.

        Args:
            data: ``{'ts', 'event', 'payload', 'delivery'}`` (``when`` and
            ``ok``/``detail`` aliases accepted).

        Returns:
            A populated :class:`AlertEntry`.
        """
        payload = from_dict(data)
        delivery = _pick(payload, 'delivery', 'status')
        if delivery is None:
            ok = payload.get('ok')
            detail = _as_str(payload.get('detail'))
            if ok is not None:
                delivery = 'ok' if ok else f'failed: {detail}'
        return cls(
            ts=_as_str(_pick(payload, 'ts', 'when')),
            event=_as_str(payload.get('event')),
            payload=from_dict(payload.get('payload')),
            delivery=_as_str(delivery),
            raw=payload,
        )

    def when(self) -> Optional[datetime]:
        """The parsed timestamp, or ``None``."""
        return _parse_iso(self.ts)


@dataclass
class AlertConfig:
    """The ``GET /api/alerts`` webhook configuration + event log."""

    webhook_url: str = ''
    events: List[str] = dc_field(default_factory=list)
    enabled: bool = False
    recent: List[AlertEntry] = dc_field(default_factory=list)
    event_types: List[str] = dc_field(default_factory=list)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'AlertConfig':
        """
        Build from an alerts payload.

        Args:
            data: ``{'webhook_url', 'events', 'enabled', 'recent': [...],
                'event_types': [...]}``.

        Returns:
            A populated :class:`AlertConfig`.
        """
        payload = from_dict(data)
        return cls(
            webhook_url=_as_str(payload.get('webhook_url')),
            events=_as_str_list(payload.get('events')),
            enabled=_as_bool(payload.get('enabled'),
                             default=bool(payload.get('webhook_url'))),
            recent=[AlertEntry.from_dict(item)
                    for item in payload.get('recent') or []
                    if isinstance(item, Mapping)],
            event_types=_as_str_list(_pick(payload, 'event_types', 'EVENT_TYPES')),
            raw=payload,
        )

    def is_enabled(self) -> bool:
        """True when a webhook URL is configured."""
        return bool(self.webhook_url)


@dataclass
class PatternFinding:
    """One pattern-of-life finding — a burst window or verdict line."""

    kind: str = ''
    detail: str = ''
    count: int = 0
    start: str = ''
    end: str = ''
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'PatternFinding':
        """
        Build from one finding/burst entry.

        Args:
            data: a burst ``{start, end, count}`` or any finding mapping.

        Returns:
            A populated :class:`PatternFinding`.
        """
        payload = from_dict(data)
        count = _as_int(payload.get('count'))
        detail = _pick(payload, 'detail', 'description', 'verdict')
        if detail is None and payload.get('start'):
            detail = (f'burst of {count} lookups between '
                      f'{payload.get("start")} and {payload.get("end")}')
        return cls(
            kind=_as_str(_pick(payload, 'kind', 'category')),
            detail=_as_str(detail),
            count=count,
            start=_as_str(payload.get('start')),
            end=_as_str(payload.get('end')),
            raw=payload,
        )


@dataclass
class PatternReport:
    """The ``GET /api/patterns`` pattern-of-life response."""

    kind: str = ''
    target: str = ''
    hour_histogram: List[int] = dc_field(default_factory=list)
    weekday_histogram: List[int] = dc_field(default_factory=list)
    activity_matrix: List[List[int]] = dc_field(default_factory=list)
    cadence: Dict[str, Any] = dc_field(default_factory=dict)
    bursts: List[PatternFinding] = dc_field(default_factory=list)
    peak_window: Dict[str, Any] = dc_field(default_factory=dict)
    verdict: List[str] = dc_field(default_factory=list)
    records_analyzed: int = 0
    findings: List[PatternFinding] = dc_field(default_factory=list)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'PatternReport':
        """
        Build from a patterns payload.

        Args:
            data: ``{'kind', 'value', 'hour_histogram', 'weekday_histogram',
                'activity_matrix', 'cadence', 'bursts', 'peak_window',
                'verdict', 'records_analyzed'}``.

        Returns:
            A populated :class:`PatternReport` — verdict lines become
            :class:`PatternFinding` entries in ``findings`` alongside the
            parsed ``bursts``.
        """
        payload = from_dict(data)
        bursts = [PatternFinding.from_dict(item)
                  for item in payload.get('bursts') or []
                  if isinstance(item, Mapping)]
        verdict = _as_str_list(payload.get('verdict'))
        findings = bursts + [PatternFinding(kind='verdict', detail=line)
                             for line in verdict]
        hour_raw = payload.get('hour_histogram')
        weekday_raw = payload.get('weekday_histogram')
        return cls(
            kind=_as_str(payload.get('kind')),
            target=_as_str(_pick(payload, 'value', 'target')),
            hour_histogram=[_as_int(item) for item in hour_raw or []],
            weekday_histogram=[_as_int(item) for item in weekday_raw or []],
            activity_matrix=[[_as_int(cell) for cell in row or []]
                             for row in payload.get('activity_matrix') or []],
            cadence=from_dict(payload.get('cadence')),
            bursts=bursts,
            peak_window=from_dict(payload.get('peak_window')),
            verdict=verdict,
            records_analyzed=_as_int(payload.get('records_analyzed')),
            findings=findings,
            raw=payload,
        )

    @property
    def observations(self) -> int:
        """Alias for :attr:`records_analyzed`."""
        return self.records_analyzed

    @property
    def peak_hour(self) -> Optional[int]:
        """The busiest hour (0-23), or ``None`` when the histogram is empty."""
        if not self.hour_histogram:
            return None
        return max(range(len(self.hour_histogram)),
                   key=lambda hour: self.hour_histogram[hour])


@dataclass
class BatchEntry:
    """One target's outcome inside a batch run."""

    target: str = ''
    success: bool = False
    field_count: int = 0
    error: str = ''
    result: Optional[LookupResult] = None
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'BatchEntry':
        """
        Build from one batch ``results`` entry.

        Args:
            data: ``{'target', 'success', 'field_count', 'error',
                'result': {tracker envelope}}``.

        Returns:
            A populated :class:`BatchEntry` — ``result`` is parsed into a
            :class:`LookupResult` when present.
        """
        payload = from_dict(data)
        result_raw = payload.get('result')
        result = (LookupResult.from_dict(result_raw)
                  if isinstance(result_raw, Mapping) else None)
        return cls(
            target=_as_str(payload.get('target')),
            success=_as_bool(payload.get('success')),
            field_count=_as_int(payload.get('field_count')),
            error=_as_str(payload.get('error')),
            result=result,
            raw=payload,
        )


@dataclass
class BatchProgress:
    """The ``POST /api/tools/batch`` response (one entry per target)."""

    kind: str = ''
    risk: bool = False
    skipped: int = 0
    stopped: bool = False
    results: List[BatchEntry] = dc_field(default_factory=list)
    summary: Dict[str, Any] = dc_field(default_factory=dict)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'BatchProgress':
        """
        Build from a batch payload.

        Args:
            data: ``{'kind', 'risk', 'skipped', 'stopped', 'results': [...],
                'summary': {'total', 'ok', 'failed', 'elapsed',
                'fields_total'}}``.

        Returns:
            A populated :class:`BatchProgress`.
        """
        payload = from_dict(data)
        return cls(
            kind=_as_str(payload.get('kind')),
            risk=_as_bool(payload.get('risk')),
            skipped=_as_int(payload.get('skipped')),
            stopped=_as_bool(payload.get('stopped')),
            results=[BatchEntry.from_dict(item)
                     for item in payload.get('results') or []
                     if isinstance(item, Mapping)],
            summary=from_dict(payload.get('summary')),
            raw=payload,
        )

    @property
    def total(self) -> int:
        """Total targets processed (summary block)."""
        return _as_int(self.summary.get('total'), default=len(self.results))

    @property
    def ok(self) -> int:
        """Successfully looked-up targets."""
        return _as_int(self.summary.get('ok'))

    @property
    def failed(self) -> int:
        """Failed targets."""
        return _as_int(self.summary.get('failed'))

    @property
    def elapsed(self) -> Optional[float]:
        """Wall-clock seconds the server took."""
        return _as_float(self.summary.get('elapsed'))

    @property
    def is_complete(self) -> bool:
        """True when the run was not stopped early."""
        return not self.stopped

    def entry_for(self, target: str) -> Optional[BatchEntry]:
        """One target's batch entry (case-insensitive), or ``None``."""
        needle = target.lower()
        for entry in self.results:
            if entry.target.lower() == needle:
                return entry
        return None


@dataclass
class IntelVerdict:
    """The ``GET /api/intel/{ip}`` threat-intel verdict."""

    ip: str = ''
    feeds: Dict[str, Any] = dc_field(default_factory=dict)
    tor_exit: bool = False
    relay: Dict[str, Any] = dc_field(default_factory=dict)
    raw: Dict[str, Any] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> 'IntelVerdict':
        """
        Build from an intel payload.

        Args:
            data: ``{'ip', 'feeds': {...}, 'tor_exit': bool,
                'relay': {...}}``.

        Returns:
            A populated :class:`IntelVerdict`.
        """
        payload = from_dict(data)
        return cls(
            ip=_as_str(payload.get('ip')),
            feeds=from_dict(payload.get('feeds')),
            tor_exit=_as_bool(payload.get('tor_exit')),
            relay=from_dict(payload.get('relay')),
            raw=payload,
        )

    @property
    def listed_count(self) -> int:
        """How many blocklist feeds list this IP."""
        return _as_int(self.feeds.get('listed_count'))

    def is_tor_exit(self) -> bool:
        """Alias for :attr:`tor_exit`."""
        return self.tor_exit

    def summary(self) -> str:
        """One-liner: ``"45.148.10.99: 2 feed(s), tor exit"``."""
        extra = ', tor exit' if self.tor_exit else ''
        return f'{self.ip or "?"}: {self.listed_count} feed hit(s){extra}'
