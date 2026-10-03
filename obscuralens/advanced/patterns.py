"""
Pattern-of-life analysis over stored lookup history (v5.0).

Every query ObscuraLens has ever answered is timestamped in the local
history database. Looked at one row at a time that is a journal; looked
at as a *series* it is behavioural evidence. When was this target
actually looked up? Does the analyst (or whoever else uses this install)
touch it in bursts, on a weekday rhythm, at 3am? Pattern-of-life analysis
answers those questions from data that never leaves the machine:

* :func:`pattern_report` - the full workup for one target: hour-of-day
  and weekday histograms, a 7x24 activity matrix, lookup cadence (mean /
  median gap, span, extremes), burst detection (3+ lookups inside a
  30-minute window), the peak activity cell and a short analyst
  narrative in ``verdict`` - the lines you paste into a case note.
* :func:`all_targets_pattern` - a mini pattern for every distinct
  ``(kind, value)`` with at least three stored lookups: event count,
  peak hour and night ratio (the fraction of lookups between 22:00 and
  06:00). Sorted by activity, capped at 100 - the "what is this
  installation actually obsessed with" leaderboard.
* :func:`heatmap_ascii` - the 7x24 matrix as a terminal heatmap using the
  ``' .:-=+*#%@'`` density scale, for CLI panes and plain-text reports.

Everything here is pure local aggregation over stored history: the
module performs no network calls whatsoever. Timestamps are parsed
defensively (epoch seconds or milliseconds, ISO 8601 with ``Z`` or
offset, space-separated and slash-date fallbacks) so rows written by any
historical version of the tool still contribute; junk rows are silently
skipped and a target with fewer than two usable timestamps yields
None-safe cadence fields instead of an error.

Use-case framing: repeated bursts around a hash point at a live
investigation; night-heavy lookups on a username hint at a different
time zone (or a different analyst); a regular ~24h cadence usually means
an automated watch, not a human.
"""

import re
from datetime import datetime, timezone
from statistics import fmean, median
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    'WEEKDAYS',
    'all_targets_pattern',
    'heatmap_ascii',
    'pattern_report',
]

#: Weekday labels, Monday-first (``datetime.weekday()`` indexing).
WEEKDAYS: Tuple[str, ...] = (
    'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday',
)

#: History rows scanned when records are loaded from the database.
_HISTORY_LIMIT = 2000

#: Kinds the correlation engine's ``history_records`` helper filters out;
#: those rows are loaded straight from the database so all 14 kinds can
#: be pattern-analysed.
_DIRECT_KINDS: Tuple[str, ...] = ('phone', 'mac', 'iban', 'imei', 'coords')

#: Lookups counted as "night" activity (22:00 inclusive -> 06: exclusive).
_NIGHT_START = 22
_NIGHT_END = 6

#: A burst is this many lookups (or more) inside a 30-minute window.
_BURST_MIN = 3
_BURST_WINDOW_SECONDS = 30 * 60

#: Maximum burst groups reported per target.
_MAX_BURSTS = 20

#: Maximum targets returned by :func:`all_targets_pattern`.
_MAX_TARGETS = 100

#: Minimum stored lookups before a target gets a mini pattern.
_MIN_EVENTS = 3

#: Strings that are plain decimal numbers (epoch seconds / milliseconds).
_NUMERIC = re.compile(r'^[+-]?\d+(?:\.\d+)?$')

#: Fallback timestamp formats tried when ``datetime.fromisoformat`` fails.
_STRPTIME_FORMATS = (
    '%Y-%m-%dT%H:%M:%S%z',
    '%Y-%m-%d %H:%M:%S%z',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d',
    '%Y/%m/%d %H:%M:%S',
    '%Y/%m/%d',
    '%d %b %Y %H:%M:%S',
    '%d %b %Y',
)

#: Alternate keys a caller-supplied record may carry for the record kind.
_KIND_KEYS = ('kind', 'query_type', 'type')
#: Alternate keys a caller-supplied record may carry for the target value.
_VALUE_KEYS = ('value', 'query_value', 'target')
#: Alternate keys a caller-supplied record may carry for the timestamp.
_TIME_KEYS = ('created_at', 'timestamp', 'time', 'date', 'queried_at')

#: Density scale for :func:`heatmap_ascii`, low -> high.
_HEAT_SCALE = ' .:-=+*#%@'


# ---------------------------------------------------------------------------
# History record plumbing
# ---------------------------------------------------------------------------

def _first_present(source: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
    """First key of ``keys`` present in ``source`` (None when absent)."""
    for key in keys:
        if key in source:
            return source[key]
    return None


def _normalise_records(records: Any) -> List[Dict[str, Any]]:
    """
    Coerce caller-supplied records into this module's canonical shape.

    The canonical record is ``{'kind', 'value', 'timestamp'}`` with the
    kind lowercased and the value stripped. Correlation-engine records
    (``created_at``), raw database rows (``query_type`` / ``query_value``)
    and API-shaped records (``timestamp``) are all accepted; payloads are
    tolerated but ignored (pattern analysis is about *when*, not what).
    Anything that is not a dict is silently dropped so a wrong-shaped
    argument yields ``[]`` instead of an error.
    """
    if records is None:
        return []
    try:
        candidates = list(records)
    except TypeError:
        return []
    normalised: List[Dict[str, Any]] = []
    for record in candidates:
        if not isinstance(record, dict):
            continue
        normalised.append({
            'kind': str(_first_present(record, _KIND_KEYS) or '').strip().lower(),
            'value': str(_first_present(record, _VALUE_KEYS) or '').strip(),
            'timestamp': _first_present(record, _TIME_KEYS),
        })
    return normalised


def _direct_rows(kinds: Tuple[str, ...]) -> List[Dict[str, Any]]:
    """
    Stored lookups of the given kinds, read straight from the database.

    The correlation engine's :func:`history_records` only returns kinds
    it can extract entities from, so the remaining kinds are queried
    here in the very same record shape. Database failures degrade to
    ``[]`` and never raise.
    """
    from ..database import db  # lazy: database on first use
    records: List[Dict[str, Any]] = []
    for kind in kinds:
        try:
            rows = db.get_history(query_type=kind, limit=_HISTORY_LIMIT)
        except Exception:
            continue
        for row in rows or []:
            records.append({
                'kind': kind,
                'value': str(getattr(row, 'query_value', '') or ''),
                'timestamp': getattr(row, 'created_at', None),
            })
    return records


def _load_records() -> List[Dict[str, Any]]:
    """
    All pattern-relevant history records (newest first as stored).

    Uses ``correlation.history_records`` capped at
    :data:`_HISTORY_LIMIT` and appends the kinds that helper filters
    out. Reading never touches the network and never raises.
    """
    records: List[Dict[str, Any]] = []
    try:
        from ..correlation import history_records  # lazy: correlation engine
        loaded = history_records(limit=_HISTORY_LIMIT)
    except Exception:
        loaded = []
    records.extend(_normalise_records(loaded or []))
    records.extend(_direct_rows(_DIRECT_KINDS))
    return records


def _records(records: Any = None) -> List[Dict[str, Any]]:
    """
    Resolve the shared ``records`` argument.

    ``None`` loads the stored history; any other value is normalised
    verbatim, keeping every public function pure and offline-testable.
    """
    if records is None:
        return _load_records()
    return _normalise_records(records)


# ---------------------------------------------------------------------------
# Timestamp parsing (multi-format, never raises)
# ---------------------------------------------------------------------------

def _epoch_moment(number: float) -> Optional[datetime]:
    """
    Epoch seconds (or milliseconds, detected by magnitude) -> aware UTC.

    Values below 1e9 or beyond 1e15 seconds are not plausible lookup
    times and yield ``None``; so do NaN and non-positive numbers.
    """
    if number != number or number <= 0:  # NaN / non-positive guard
        return None
    if number >= 1e12:
        number = number / 1000.0  # millisecond precision
    if number < 1e9 or number >= 1e15:
        return None
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Parse a stored timestamp defensively into a timezone-aware datetime.

    Accepted forms: ``datetime`` objects (naive values read as UTC),
    epoch numbers and numeric strings (seconds or milliseconds), ISO
    dates and datetimes (with ``Z`` suffix or offset, space or ``T``
    separator) and a small set of ``dd Mon YYYY`` / slash fallbacks -
    the same multi-format parser the geospatial module uses. Values that
    match nothing return ``None``; the function never raises.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return _epoch_moment(float(value))
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if _NUMERIC.match(text):
        return _epoch_moment(float(text))
    candidate = text[:-1] + '+00:00' if text.endswith(('Z', 'z')) else text
    moment: Optional[datetime] = None
    try:
        moment = datetime.fromisoformat(candidate)
    except ValueError:
        moment = None
    if moment is None:
        for fmt in _STRPTIME_FORMATS:
            try:
                moment = datetime.strptime(text, fmt)
            except ValueError:
                continue
            break
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment: Optional[datetime]) -> Optional[str]:
    """Second-resolution ISO rendering of a datetime (None passes through)."""
    if moment is None:
        return None
    return moment.isoformat(timespec='seconds')


# ---------------------------------------------------------------------------
# Core analytics helpers
# ---------------------------------------------------------------------------

def _is_night(moment: datetime) -> bool:
    """Whether a moment falls in the 22:00-06:00 window of its day."""
    return moment.hour >= _NIGHT_START or moment.hour < _NIGHT_END


def _cadence(moments: List[datetime]) -> Dict[str, Any]:
    """
    Rhythm statistics for a sorted list of lookup moments.

    All gap statistics are ``None`` when fewer than two moments exist, so
    a single-lookup target renders cleanly instead of crashing a report.
    """
    lookups = len(moments)
    first = moments[0] if moments else None
    last = moments[-1] if moments else None
    span_days: Optional[float] = None
    intervals: List[float] = []
    if lookups >= 2 and first is not None and last is not None:
        span_days = round((last - first).total_seconds() / 86400.0, 2)
        intervals = [(b - a).total_seconds() / 3600.0
                     for a, b in zip(moments, moments[1:])]
    return {
        'lookups': lookups,
        'first_seen': _iso(first),
        'last_seen': _iso(last),
        'span_days': span_days,
        'mean_interval_hours': round(fmean(intervals), 2) if intervals else None,
        'median_interval_hours': round(median(intervals), 2) if intervals else None,
        'min_interval_minutes':
            round(min(intervals) * 60.0, 1) if intervals else None,
        'max_interval_days': round(max(intervals) / 24.0, 2) if intervals else None,
    }


def _bursts(moments: List[datetime]) -> List[Dict[str, Any]]:
    """
    Groups of :data:`_BURST_MIN` or more lookups inside 30-minute windows.

    A burst window opens at its first lookup and closes when the next
    lookup falls more than 30 minutes after that opener (or the series
    ends). Groups below the threshold are dropped; the list is capped at
    :data:`_MAX_BURSTS`.
    """
    groups: List[Dict[str, Any]] = []
    run: List[datetime] = []
    for moment in moments:
        if run and (moment - run[0]).total_seconds() > _BURST_WINDOW_SECONDS:
            if len(run) >= _BURST_MIN:
                groups.append({'start': _iso(run[0]), 'end': _iso(run[-1]),
                               'count': len(run)})
            run = []
        run.append(moment)
    if len(run) >= _BURST_MIN:
        groups.append({'start': _iso(run[0]), 'end': _iso(run[-1]),
                       'count': len(run)})
    return groups[:_MAX_BURSTS]


def _peak_window(matrix: List[List[int]]) -> Dict[str, Any]:
    """
    The busiest cell of a 7x24 activity matrix (Monday-first rows).

    Ties resolve to the earliest weekday, then the earliest hour, so the
    answer is deterministic for identical data.
    """
    peak = {'hour': None, 'weekday': None, 'weekday_name': None, 'count': 0}
    best = -1
    for weekday, row in enumerate(matrix):
        for hour, count in enumerate(row):
            if count > best:
                best = count
                peak = {'hour': hour, 'weekday': weekday,
                        'weekday_name': WEEKDAYS[weekday] if weekday < 7 else None,
                        'count': count}
    return peak


def _verdict_lines(cadence: Dict[str, Any], bursts: List[Dict[str, Any]],
                   peak: Dict[str, Any], night_count: int) -> List[str]:
    """
    The analyst narrative: short human sentences summarising the pattern.

    These strings are the lines that end up in case notes and the history
    report - concrete, quantitative and free of hedging.
    """
    lines: List[str] = []
    lookups = int(cadence.get('lookups') or 0)
    if lookups == 0:
        return ['no stored lookups match yet - run a lookup first']
    if peak.get('count'):
        hour = int(peak['hour'])
        lines.append(
            f"most active {peak.get('weekday_name') or 'day'} "
            f"{hour:02d}:00-{hour + 1:02d}:00 ({peak['count']} lookups)")
    if bursts:
        lines.append(f"{len(bursts)} burst"
                     f"{'s' if len(bursts) != 1 else ''} detected "
                     f"(3+ lookups within 30 minutes)")
    elif lookups >= 3:
        lines.append('no burst activity detected')
    median_hours = cadence.get('median_interval_hours')
    mean_hours = cadence.get('mean_interval_hours')
    if median_hours is not None and mean_hours is not None and median_hours > 0:
        ratio = mean_hours / median_hours
        if 0.75 <= ratio <= 1.33:
            lines.append(f"regular cadence ~{median_hours:g}h between lookups")
        else:
            lines.append(f"median gap between lookups ~{median_hours:g}h")
    if night_count:
        lines.append(
            f"{night_count}/{lookups} lookups between 22:00 and 06:00")
    span = cadence.get('span_days')
    if span is not None and span >= 1:
        lines.append(f"activity spans {span:g} days")
    return lines


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def pattern_report(kind: str, value: str,
                   records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Pattern-of-life report for every stored lookup of one target.

    Args:
        kind: the tracker kind to filter on (case-insensitive)
        value: the target value to filter on - a case-insensitive
            *substring* match, so ``'DE89'`` picks up every German IBAN
            row and ``'8.8.8'`` every mention of the resolver range
        records: optional pre-loaded records (``correlation.history_records``
            output or any record-shaped list); ``None`` loads the stored
            history (capped at 2000 rows, including the kinds the
            correlation engine skips)

    Returns:
        ``{'kind', 'value', 'hour_histogram' (24 counts),
        'weekday_histogram' (7 counts, Monday-first), 'activity_matrix'
        (7x24 ints), 'cadence' (gap statistics), 'bursts',
        'peak_window' ({'hour', 'weekday', 'weekday_name', 'count'}),
        'verdict' ([str, ...]), 'records_analyzed'}``. Targets with no
        stored lookups yield all-zero histograms, None-safe cadence and a
        verdict saying so - never an exception.
    """
    kind = str(kind or '').strip().lower()
    needle = str(value or '').strip().lower()
    matched: List[Dict[str, Any]] = []
    if needle:
        for record in _records(records):
            if record.get('kind') != kind:
                continue
            if needle in str(record.get('value') or '').lower():
                matched.append(record)

    moments: List[datetime] = []
    for record in matched:
        moment = _parse_timestamp(record.get('timestamp'))
        if moment is not None:
            moments.append(moment)
    moments.sort()

    hour_histogram = [0] * 24
    weekday_histogram = [0] * 7
    activity_matrix = [[0] * 24 for _ in range(7)]
    night_count = 0
    for moment in moments:
        hour_histogram[moment.hour] += 1
        weekday_histogram[moment.weekday()] += 1
        activity_matrix[moment.weekday()][moment.hour] += 1
        if _is_night(moment):
            night_count += 1

    cadence = _cadence(moments)
    bursts = _bursts(moments)
    peak = _peak_window(activity_matrix)
    return {
        'kind': kind,
        'value': str(value or '').strip(),
        'hour_histogram': hour_histogram,
        'weekday_histogram': weekday_histogram,
        'activity_matrix': activity_matrix,
        'cadence': cadence,
        'bursts': bursts,
        'peak_window': peak,
        'verdict': _verdict_lines(cadence, bursts, peak, night_count),
        'records_analyzed': len(matched),
    }


def all_targets_pattern(records: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """
    Mini pattern-of-life for every target with at least three lookups.

    The "what does this install keep coming back to" view: each distinct
    ``(kind, value)`` pair with :data:`_MIN_EVENTS` or more stored
    lookups is summarised by event count, peak hour and night ratio
    (fraction of lookups between 22:00 and 06:00 of the stored
    timestamp). Rows with unparseable timestamps still count toward
    ``count`` but contribute no hour statistics.

    Args:
        records: optional pre-loaded records; ``None`` loads the stored
            history the same way :func:`pattern_report` does

    Returns:
        List of ``{'kind', 'value', 'count', 'peak_hour', 'night_ratio'}``
        dicts sorted by count descending (kind, then value, as
        tie-breaks), capped at :data:`_MAX_TARGETS`.
    """
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for record in _records(records):
        kind = record.get('kind') or ''
        value = record.get('value') or ''
        if not value:
            continue
        key = (kind, value)
        group = groups.setdefault(key, {'count': 0, 'moments': []})
        group['count'] += 1
        moment = _parse_timestamp(record.get('timestamp'))
        if moment is not None:
            group['moments'].append(moment)

    out: List[Dict[str, Any]] = []
    for (kind, value), group in groups.items():
        if group['count'] < _MIN_EVENTS:
            continue
        moments: List[datetime] = group['moments']
        peak_hour: Optional[int] = None
        if moments:
            hour_counts: Dict[int, int] = {}
            for moment in moments:
                hour_counts[moment.hour] = hour_counts.get(moment.hour, 0) + 1
            ranked = sorted(hour_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            peak_hour = ranked[0][0]
        night = sum(1 for moment in moments if _is_night(moment))
        night_ratio = round(night / len(moments), 3) if moments else 0.0
        out.append({'kind': kind, 'value': value, 'count': group['count'],
                    'peak_hour': peak_hour, 'night_ratio': night_ratio})
    out.sort(key=lambda item: (-item['count'], item['kind'], item['value']))
    return out[:_MAX_TARGETS]


def heatmap_ascii(matrix: Any) -> str:
    """
    Render an activity matrix as a terminal heatmap.

    Rows are weekdays (Monday-first, three-letter labels), columns the
    24 hours of the day, density-coded with the ``' .:-=+*#%@'`` scale -
    blank means zero, ``@`` means the busiest cell in the matrix. An hour
    ruler (units digit of each hour) sits above the grid. Any non-matrix
    input yields an empty string rather than an error, so callers can
    feed :func:`pattern_report` output blindly.

    Args:
        matrix: the 7x24 ``activity_matrix`` (other shapes are rendered
            best-effort with generic row labels)

    Returns:
        Multi-line ASCII art terminated without a trailing newline.
    """
    if not isinstance(matrix, (list, tuple)):
        return ''
    rows: List[List[Any]] = []
    for row in matrix:
        if isinstance(row, (list, tuple)):
            rows.append(list(row))
    if not rows:
        return ''
    width = max(len(row) for row in rows)

    peak = 0.0
    for row in rows:
        for cell in row:
            if isinstance(cell, (int, float)) and not isinstance(cell, bool) and cell > peak:
                peak = float(cell)
    scale_max = len(_HEAT_SCALE) - 1

    lines: List[str] = ['     ' + ''.join(str(hour % 10) for hour in range(width))]
    for index, row in enumerate(rows):
        label = WEEKDAYS[index][:3] if index < len(WEEKDAYS) else f'r{index:02d}'
        chars: List[str] = []
        for hour in range(width):
            cell = row[hour] if hour < len(row) else 0
            if isinstance(cell, (int, float)) and not isinstance(cell, bool) \
                    and peak > 0 and cell > 0:
                level = int(round(cell / peak * scale_max))
                chars.append(_HEAT_SCALE[min(scale_max, max(0, level))])
            elif isinstance(cell, (int, float)) and not isinstance(cell, bool) \
                    and cell > 0:
                chars.append(_HEAT_SCALE[scale_max])
            else:
                chars.append(' ')
        lines.append(f'{label:<5}{"".join(chars)}')
    return '\n'.join(lines)
