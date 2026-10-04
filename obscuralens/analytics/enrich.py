"""
History enrichment: turning the query log into analysis material (v6.0 Part 2).

Every lookup ObscuraLens runs lands in the SQLite history table - kind,
value, result payload, timestamp, success flag. That table quietly
accumulates exactly the longitudinal evidence the analytics package
craves: which kinds dominate the workload, when the operator works, which
sources keep failing, which targets get re-queried obsessively, and which
days the activity spikes.

This module is the bridge: it reads the history through the platform's
own ``db`` singleton, shapes the rows into the Part 2 data structures
(:class:`~obscuralens.analytics.timeseries.TimeSeriesPoint` lists,
frequency tables, :class:`~obscuralens.analytics.anomaly.AnomalyScore`
records) and hands them to the math layer. The CLI, web UI and MCP server
get a whole behavioural statistics dossier for one call each.

Row contract (``database.get_history`` returns ``QueryRecord`` objects
carrying ``query_type`` / ``query_value`` / ``result_data`` (a JSON
string) / ``created_at`` (SQLite ``YYYY-MM-DD HH:MM:SS``, UTC) /
``success``): field counts come from
:meth:`obscuralens.database.DatabaseManager.count_fields`, source health
from the tracker envelopes' ``sources_ok`` / ``sources_failed`` keys, and
every timestamp is interpreted as UTC because that is what SQLite's
``CURRENT_TIMESTAMP`` writes.

Design contract (mirrored across the analytics package):

* **Defensive by default.** An unavailable database, a locked file, an
  unparseable timestamp or a corrupt ``result_data`` JSON costs one row
  or one empty structure - never an exception.
* **Read-only.** Nothing here writes, prunes or mutates history; the
  enrichment layer observes, it does not touch.
* **Bounded by ``limit``.** Every function reads the newest ``limit``
  rows (negative limits are clamped to 0 rather than letting SQLite's
  ``LIMIT -1`` mean "unlimited").
"""

import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..database import DatabaseManager, db
from .anomaly import AnomalyScore, ensemble_anomalies
from .stats import histogram, summarize
from .timeseries import TimeSeriesPoint

__all__ = [
    'activity_anomalies',
    'enrichment_report',
    'field_count_distribution',
    'history_points',
    'hour_of_day_profile',
    'kind_frequency',
    'source_reliability',
    'success_rate_by_kind',
    'top_targets',
    'weekday_profile',
]

#: Accepted ``created_at`` formats (SQLite writes the first; the others
#: guard against hand-migrated databases and future schema tweaks).
_TIMESTAMP_FORMATS: Tuple[str, ...] = (
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%dT%H:%M:%S.%f',
)

#: ISO weekday names, Monday-first (``datetime.weekday()`` indexing).
_WEEKDAY_NAMES: Tuple[str, ...] = (
    'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday',
    'Sunday',
)

#: Default row budgets: the one-shot report's window and its target cap.
_REPORT_LIMIT = 500
_REPORT_TOP_TARGETS = 10


# ---------------------------------------------------------------------------
# Row access and parsing
# ---------------------------------------------------------------------------

def _clamped_limit(limit: Any, default: int) -> int:
    """Coerce a limit argument to a non-negative int (never raises).

    Negative values become 0 rather than falling through to SQLite, where
    ``LIMIT -1`` paradoxically means *no* limit.
    """
    if isinstance(limit, bool) or not isinstance(limit, (int, float)):
        return default
    number = float(limit)
    if not math.isfinite(number):
        return default
    value = int(number)
    return value if value > 0 else 0


def _records(limit: Any, default: int) -> List[Any]:
    """Newest-first history rows from the shared ``db`` singleton.

    Any database failure (locked file, missing table, unsupported
    backend) is swallowed into an empty list: enrichment observes, and an
    unreadable history is simply no observation.
    """
    try:
        return list(db.get_history(limit=_clamped_limit(limit, default)))
    except Exception:  # noqa: BLE001 - a broken DB must not break analytics
        return []


def _parse_created_at(value: Any) -> Optional[datetime]:
    """Parse a history timestamp into an aware UTC ``datetime``.

    Accepts the SQLite ``YYYY-MM-DD HH:MM:SS`` string (always UTC), close
    ISO variants, and existing ``datetime`` objects (naive ones are
    assumed UTC). Unparseable values yield ``None`` - the row is skipped
    downstream, never fatal.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for fmt in _TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _stamped(records: List[Any]) -> List[Tuple[Any, datetime]]:
    """Pair each record with its parsed timestamp, dropping unparsable rows."""
    stamped: List[Tuple[Any, datetime]] = []
    for record in records:
        moment = _parse_created_at(getattr(record, 'created_at', None))
        if moment is not None:
            stamped.append((record, moment))
    return stamped


def _payload(record: Any) -> Optional[Dict[str, Any]]:
    """Parse one record's ``result_data`` JSON into a dict (None on failure)."""
    raw = getattr(record, 'result_data', None)
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _field_count(record: Any) -> int:
    """Populated-field count of one record via the platform's own counter."""
    raw = getattr(record, 'result_data', None)
    if not isinstance(raw, str):
        return 0
    try:
        return DatabaseManager.count_fields(raw)
    except Exception:  # noqa: BLE001 - corrupt JSON counts as zero fields
        return 0


def _source_status(payload: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    """Extract ``(sources_ok, sources_failed)`` from one result payload.

    Tracker envelopes carry both keys at the top level; the nested
    ``'info'`` dict is consulted as a fallback for payloads shaped by
    older code paths.
    """
    ok_list = _as_str_list(payload.get('sources_ok'))
    failed_map = _as_str_map(payload.get('sources_failed'))
    if not ok_list and not failed_map:
        info = payload.get('info')
        if isinstance(info, dict):
            ok_list = _as_str_list(info.get('sources_ok'))
            failed_map = _as_str_map(info.get('sources_failed'))
    return ok_list, failed_map


def _as_str_list(value: Any) -> List[str]:
    """Keep only the string items of a value intended as a list of names."""
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _as_str_map(value: Any) -> Dict[str, Any]:
    """Keep only the str-keyed items of a value intended as a source->error map."""
    if not isinstance(value, dict):
        return {}
    return {key: item for key, item in value.items()
            if isinstance(key, str) and key}


# ---------------------------------------------------------------------------
# Time series and frequency profiles
# ---------------------------------------------------------------------------

def history_points(limit: int = 500) -> List[TimeSeriesPoint]:
    """Chronological time-series of per-query evidence volume.

    Each history row becomes one point: the timestamp is the row's
    creation moment, the value is how many populated fields that query
    produced (``DatabaseManager.count_fields``), falling back to ``1``
    when a query yielded nothing countable - a failed lookup is still one
    unit of activity, and the activity curve is the point of the series.
    The label carries the query kind so the series can be split per kind.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        Points sorted by timestamp ascending. Empty when the history is
        empty or unreadable. Never raises.

    Example:
        >>> history_points(limit=0)   # nothing requested
        []
    """
    stamped = _stamped(_records(limit, 500))
    points: List[TimeSeriesPoint] = []
    for record, moment in stamped:
        volume = _field_count(record)
        points.append(TimeSeriesPoint(
            timestamp=moment.timestamp(),
            value=float(volume) if volume > 0 else 1.0,
            label=getattr(record, 'query_type', None),
        ))
    points.sort(key=lambda point: point.timestamp)
    return points


def kind_frequency(limit: int = 500) -> List[Dict[str, Any]]:
    """How often each target kind appears in recent history.

    The workload census: which kinds the operator actually leans on, with
    each kind's share of the queried total.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        List of ``{'kind', 'count', 'percentage'}`` dicts sorted by count
        descending, ties broken alphabetically. Empty for empty history.
        Never raises.

    Example:
        >>> kind_frequency(limit=0)
        []
    """
    return _kind_frequency(_records(limit, 500))


def hour_of_day_profile(limit: int = 1000) -> List[Dict[str, Any]]:
    """Query activity by hour of day (UTC), all 24 hours, zero-filled.

    The circadian fingerprint of an investigation desk - or of the bot
    that never sleeps: hours with no queries appear with count 0 so the
    profile renders as a complete 24-bar chart.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        24 ``{'hour', 'count', 'percentage'}`` dicts in hour order
        (0-23, UTC). Rows without a parsable timestamp are skipped. Never
        raises.

    Example:
        >>> profile = hour_of_day_profile(limit=0)
        >>> len(profile), profile[0]['count']
        (24, 0)
    """
    return _hour_profile(_stamped(_records(limit, 1000)))


def weekday_profile(limit: int = 1000) -> List[Dict[str, Any]]:
    """Query activity by weekday (Monday-first), all 7 days, zero-filled.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        Seven ``{'weekday', 'name', 'count', 'percentage'}`` dicts in
        Monday-to-Sunday order (``weekday`` is ``datetime.weekday()``
        indexing, 0 = Monday). Rows without a parsable timestamp are
        skipped. Never raises.

    Example:
        >>> profile = weekday_profile(limit=0)
        >>> profile[0]['name'], profile[0]['count']
        ('Monday', 0)
    """
    return _weekday_profile(_stamped(_records(limit, 1000)))


def success_rate_by_kind(limit: int = 500) -> List[Dict[str, Any]]:
    """Success rate of recent queries, broken down by target kind.

    The "which sensor is healthy" table: a kind whose queries keep
    failing points at broken sources, rate limits or validator drift -
    and at an operator who keeps retrying anyway.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        List of ``{'kind', 'total', 'succeeded', 'failed',
        'success_rate'}`` dicts (rate in percent, 0.0 for kinds with no
        queries) sorted by total descending, ties alphabetically. Never
        raises.

    Example:
        >>> success_rate_by_kind(limit=0)
        []
    """
    return _success_rates(_records(limit, 500))


def field_count_distribution(limit: int = 500) -> Dict[str, Any]:
    """Distribution of populated-field counts across recent queries.

    How much evidence does a query typically return? The answer as a
    histogram plus the stats module's one-shot summary, ready for the
    report's "data yield" block.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        Dict with ``'count'`` (queries measured), ``'histogram'`` (ten
        equal-width bins via :func:`obscuralens.analytics.stats.histogram`)
        and ``'summary'`` (:func:`obscuralens.analytics.stats.summarize`).
        Empty history yields count 0 with empty histogram/summary
        envelopes. Never raises.

    Example:
        >>> field_count_distribution(limit=0)['count']
        0
    """
    return _field_stats(_records(limit, 500))


# ---------------------------------------------------------------------------
# Source health, anomalies, repeat targets
# ---------------------------------------------------------------------------

def source_reliability(limit: int = 500) -> List[Dict[str, Any]]:
    """Per-source ok/failure counts aggregated from stored result payloads.

    Every tracker envelope persists ``sources_ok`` (a list of source
    names that answered) and ``sources_failed`` (a mapping of source name
    to error); this function folds the newest ``limit`` payloads into one
    reliability table per source. Rows whose ``result_data`` fails to
    parse are skipped - one corrupt row costs itself, not the report.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        List of ``{'source', 'ok', 'failed', 'total', 'reliability'}``
        dicts (reliability = ok/total in percent, 0.0 when a source only
        ever failed) sorted by total descending, ties alphabetically.
        Never raises.

    Example:
        >>> source_reliability(limit=0)
        []
    """
    return _source_reliability_rows(_records(limit, 500))


def activity_anomalies(limit: int = 500) -> List[AnomalyScore]:
    """Days whose query volume is anomalous (multi-detector ensemble).

    Rows are bucketed into UTC calendar days, the per-day counts become
    a series, and :func:`obscuralens.analytics.anomaly.ensemble_anomalies`
    (z-score + IQR + MAD, two agreeing votes) flags the days that break
    the pattern - the night someone dumped a whole watchlist through the
    CLI. Each hit carries the day itself in ``detail['day']`` so the
    verdict is self-locating in a report.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        :class:`~obscuralens.analytics.anomaly.AnomalyScore` records
        (``method='ensemble'``) whose ``detail`` extends the detector's
        output with ``'day'`` (the ``YYYY-MM-DD`` that was flagged) and
        ``'day_index'``. Empty when fewer than three distinct days exist
        or nothing is flagged. Never raises.

    Example:
        >>> activity_anomalies(limit=0)
        []
    """
    return _activity_anomalies(_stamped(_records(limit, 500)))


def top_targets(limit: int = 500, top: int = 10) -> List[Dict[str, Any]]:
    """The most re-queried target values.

    Repetition is signal: a value queried five times in a week is either
    a live investigation or a stuck automation loop - both worth seeing
    in a dashboard. The kind reported is the one from the most recent
    lookup of that value (the history is read newest-first), and
    ``last_seen`` carries that lookup's timestamp.

    Args:
        limit: How many newest rows to read (negative values become 0).
        top: Maximum targets returned (negative values become 0).

    Returns:
        List of ``{'target', 'kind', 'count', 'last_seen'}`` dicts sorted
        by count descending, ties broken alphabetically. ``last_seen`` is
        the raw ``created_at`` string of the newest query for that
        target (``None`` when absent). Never raises.

    Example:
        >>> top_targets(limit=0)
        []
    """
    return _top_targets(_records(limit, 500), top)


# ---------------------------------------------------------------------------
# One-shot report
# ---------------------------------------------------------------------------

def enrichment_report(limit: int = 500) -> Dict[str, Any]:
    """The full history dossier in one call.

    Reads the newest ``limit`` rows once and aggregates every profile in
    this module: totals, span, kind census, hour/weekday rhythms, success
    rates, field-count distribution, source reliability, anomalous days
    and the most re-queried targets. The payload the web analytics view
    and the MCP ``history_report`` tool render straight from.

    Args:
        limit: How many newest rows to read (negative values become 0).

    Returns:
        Dict with keys ``'total_queries'``, ``'span_days'`` (rounded days
        between the oldest and newest parsed timestamps, 0.0 otherwise),
        ``'kind_frequency'``, ``'hour_profile'``, ``'weekday_profile'``,
        ``'success_rates'``, ``'field_stats'``, ``'source_reliability'``,
        ``'anomalies'``, ``'top_targets'`` and ``'generated_at'`` (UTC
        ISO-8601). Every sub-structure degrades to its empty envelope
        when the history is empty or unreadable. Never raises.

    Example:
        >>> report = enrichment_report(limit=0)
        >>> report['total_queries'], report['generated_at'][:4].isdigit()
        (0, True)
    """
    rows = _records(limit, _REPORT_LIMIT)
    stamped = _stamped(rows)
    timestamps = [moment.timestamp() for _record, moment in stamped]

    span_days = 0.0
    if len(timestamps) >= 2:
        span_days = round((max(timestamps) - min(timestamps)) / 86400.0, 2)
    return {
        'total_queries': len(rows),
        'span_days': span_days,
        'kind_frequency': _kind_frequency(rows),
        'hour_profile': _hour_profile(stamped),
        'weekday_profile': _weekday_profile(stamped),
        'success_rates': _success_rates(rows),
        'field_stats': _field_stats(rows),
        'source_reliability': _source_reliability_rows(rows),
        'anomalies': _activity_anomalies(stamped),
        'top_targets': _top_targets(rows, _REPORT_TOP_TARGETS),
        'generated_at': datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Internal profiles over pre-fetched rows (shared by the public wrappers)
# ---------------------------------------------------------------------------

def _kind_frequency(rows: List[Any]) -> List[Dict[str, Any]]:
    """Kind census over already-fetched rows."""
    counts: Dict[str, int] = {}
    for record in rows:
        kind = getattr(record, 'query_type', None)
        if isinstance(kind, str) and kind:
            counts[kind] = counts.get(kind, 0) + 1
    total = sum(counts.values())
    if not total:
        return []
    entries = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{'kind': kind, 'count': count,
             'percentage': round(count * 100.0 / total, 2)}
            for kind, count in entries]


def _hour_profile(stamped: List[Tuple[Any, datetime]]) -> List[Dict[str, Any]]:
    """Zero-filled 24-hour UTC activity profile over stamped rows."""
    counts = [0] * 24
    for _record, moment in stamped:
        counts[moment.hour] += 1
    total = sum(counts)
    return [{'hour': hour, 'count': counts[hour],
             'percentage': round(counts[hour] * 100.0 / total, 2) if total else 0.0}
            for hour in range(24)]


def _weekday_profile(stamped: List[Tuple[Any, datetime]]) -> List[Dict[str, Any]]:
    """Zero-filled Monday-first weekday profile over stamped rows."""
    counts = [0] * 7
    for _record, moment in stamped:
        counts[moment.weekday()] += 1
    total = sum(counts)
    return [{'weekday': day, 'name': _WEEKDAY_NAMES[day], 'count': counts[day],
             'percentage': round(counts[day] * 100.0 / total, 2) if total else 0.0}
            for day in range(7)]


def _success_rates(rows: List[Any]) -> List[Dict[str, Any]]:
    """Per-kind success-rate table over already-fetched rows."""
    totals: Dict[str, int] = {}
    successes: Dict[str, int] = {}
    for record in rows:
        kind = getattr(record, 'query_type', None)
        if not isinstance(kind, str) or not kind:
            continue
        totals[kind] = totals.get(kind, 0) + 1
        if getattr(record, 'success', False):
            successes[kind] = successes.get(kind, 0) + 1
    entries = sorted(totals.items(), key=lambda item: (-item[1], item[0]))
    report: List[Dict[str, Any]] = []
    for kind, total in entries:
        succeeded = successes.get(kind, 0)
        report.append({
            'kind': kind,
            'total': total,
            'succeeded': succeeded,
            'failed': total - succeeded,
            'success_rate': round(succeeded * 100.0 / total, 2) if total else 0.0,
        })
    return report


def _field_stats(rows: List[Any]) -> Dict[str, Any]:
    """Field-count histogram and summary over already-fetched rows."""
    values = [float(_field_count(record)) for record in rows]
    return {
        'count': len(values),
        'histogram': histogram(values, bins=10),
        'summary': summarize(values),
    }


def _source_reliability_rows(rows: List[Any]) -> List[Dict[str, Any]]:
    """Per-source reliability table over already-fetched rows."""
    ok_counts: Dict[str, int] = {}
    failed_counts: Dict[str, int] = {}
    for record in rows:
        payload = _payload(record)
        if payload is None:
            continue
        ok_list, failed_map = _source_status(payload)
        for source in ok_list:
            ok_counts[source] = ok_counts.get(source, 0) + 1
        for source in failed_map:
            failed_counts[source] = failed_counts.get(source, 0) + 1

    entries: List[Dict[str, Any]] = []
    for source in set(ok_counts) | set(failed_counts):
        ok = ok_counts.get(source, 0)
        failed = failed_counts.get(source, 0)
        total = ok + failed
        entries.append({
            'source': source,
            'ok': ok,
            'failed': failed,
            'total': total,
            'reliability': round(ok * 100.0 / total, 2) if total else 0.0,
        })
    entries.sort(key=lambda entry: (-entry['total'], entry['source']))
    return entries


def _activity_anomalies(stamped: List[Tuple[Any, datetime]]) -> List[AnomalyScore]:
    """Ensemble anomaly detection over per-day counts of stamped rows."""
    daily: Dict[str, int] = {}
    for _record, moment in stamped:
        day = moment.strftime('%Y-%m-%d')
        daily[day] = daily.get(day, 0) + 1
    days = sorted(daily)
    counts = [float(daily[day]) for day in days]
    hits = ensemble_anomalies(counts)
    flagged: List[AnomalyScore] = []
    for hit in hits:
        index = hit.detail.get('index')
        day = days[int(index)] if isinstance(index, int) and 0 <= index < len(days) \
            else None
        detail = dict(hit.detail)
        detail['day'] = day
        detail['day_index'] = index
        flagged.append(AnomalyScore(
            value=hit.value,
            score=hit.score,
            method=hit.method,
            detail=detail,
        ))
    return flagged


def _top_targets(rows: List[Any], top: Any) -> List[Dict[str, Any]]:
    """Most re-queried target values over already-fetched (newest-first) rows."""
    counts: Dict[str, int] = {}
    kinds: Dict[str, str] = {}
    last_seen: Dict[str, Optional[str]] = {}
    for record in rows:
        target = getattr(record, 'query_value', None)
        if not isinstance(target, str) or not target:
            continue
        counts[target] = counts.get(target, 0) + 1
        if target not in kinds:
            kind = getattr(record, 'query_type', None)
            if isinstance(kind, str) and kind:
                kinds[target] = kind
            last_seen[target] = getattr(record, 'created_at', None)

    maximum = _clamped_limit(top, 10)
    entries = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{'target': target, 'kind': kinds.get(target, ''),
             'count': count, 'last_seen': last_seen.get(target)}
            for target, count in entries[:maximum]]
