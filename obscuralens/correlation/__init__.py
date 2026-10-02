"""
ObscuraLens correlation package (v4.0).

Cross-target entity resolution, timeline construction and heuristic risk
scoring over stored lookups::

    from obscuralens.correlation import (
        attach_risk, build_graph, build_timeline, correlate,
        correlation_sections, extract_entities, extract_events,
        history_records, risk_sections, score, timeline_sections,
    )

    records = history_records()              # stored lookups as records
    graph = build_graph(records)             # entity graph + clusters/stats
    report = correlation_sections(graph)     # report-ready sections
    pair = correlate('a.example', 'b.example')
    timeline = build_timeline(records)       # oldest -> newest events
    risk = score('ip', payload)              # explainable heuristic score
"""

from .engine import (
    KINDS,
    EntityGraph,
    build_graph,
    correlate,
    correlation_sections,
    extract_entities,
    history_records,
)
from .risk import attach_risk, risk_sections, score
from .timeline import (
    DATE_FIELD_REGISTRY,
    build_timeline,
    extract_events,
    timeline_sections,
)

__all__ = [
    'DATE_FIELD_REGISTRY',
    'KINDS',
    'EntityGraph',
    'attach_risk',
    'build_graph',
    'build_timeline',
    'correlate',
    'correlation_sections',
    'extract_entities',
    'extract_events',
    'history_records',
    'risk_sections',
    'score',
    'timeline_sections',
]
