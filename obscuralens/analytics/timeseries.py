"""
Time-series analysis over timestamped observations (v6.0 Part 2).

An OSINT platform is quietly a time-series database: every tracker response
carries a latency, every watchlist check a risk score, every stored lookup a
timestamp. Once those numbers are lined up chronologically they answer
questions a single snapshot cannot: is this source getting slower, did the
target's activity pattern shift last week, is the spike real or noise?

This module provides that line-up with a deliberately small toolbox - the
smoothing, detrending, CUSUM changepoint detection and daily resampling that
cover 90% of analyst questions - implemented on pure stdlib so the analytics
package has zero install friction.

Design contract:

* **One data shape.** Everything is a :class:`TimeSeriesPoint` (epoch-second
  timestamp, float value, optional label). :func:`to_points` converts the
  awkward shapes callers actually have - ``[(ts, value), ...]`` pairs, dicts,
  existing points - and sorts them chronologically.
* **Order-in, order-out.** Functions that report indices
  (:func:`detect_changepoints`, :func:`seasonality_hint`) process points in
  *list order* so reported indices always match the caller's list; use
  :func:`to_points` first when input order is not guaranteed chronological.
* **Defensive by default.** ``None``, empty input, invalid points, degenerate
  parameters (``window=0``, ``alpha=7``, non-finite values) all return empty
  lists or ``None`` summaries - never exceptions. A malformed row is dropped,
  not fatal: one bad sensor reading should not kill the whole trend line.
* **No calendar magic.** Timestamps are epoch seconds; "a day" is 86400 of
  them (UTC in :func:`resample_daily`). No locale, no DST, no surprises.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    'TimeSeriesPoint',
    'cumulative_sum',
    'detect_changepoints',
    'detrend',
    'ewma',
    'linear_trend',
    'moving_average',
    'rate_of_change',
    'resample_daily',
    'seasonality_hint',
    'series_summary',
    'to_points',
]

#: Seconds per day - the only calendar constant this module believes in.
_SECONDS_PER_DAY = 86400.0

#: CUSUM drift allowance (in robust-z units) for :func:`detect_changepoints`.
#: 0.5 is the classical default: half a robust standard deviation of slack
#: so ordinary wandering does not trip the accumulator.
_CUSUM_DRIFT = 0.5

#: Default CUSUM alarm threshold when the caller passes a non-finite or
#: non-positive value.
_CUSUM_DEFAULT_THRESHOLD = 2.0

#: Slopes flatter than this (value units per second) count as 'flat'.
_FLAT_SLOPE = 1e-12

#: Alternate keys a dict row may carry for the timestamp.
_TS_KEYS: Tuple[str, ...] = ('timestamp', 'ts', 'time')
#: Alternate keys a dict row may carry for the value.
_VALUE_KEYS: Tuple[str, ...] = ('value', 'v', 'val', 'y')
#: Alternate keys a dict row may carry for the label.
_LABEL_KEYS: Tuple[str, ...] = ('label', 'name', 'tag')

#: Seasonality verdict threshold: variance ratio above this reads seasonal.
_SEASONAL_RATIO = 0.5


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TimeSeriesPoint:
    """A single timestamped observation.

    Attributes:
        timestamp: Epoch seconds (float). Naive datetimes passed through
            :func:`to_points` are interpreted as UTC.
        value: The measured quantity (must be finite to be usable).
        label: Optional free-form annotation (target name, source tag).
    """

    timestamp: float
    value: float
    label: Optional[str] = None


# ---------------------------------------------------------------------------
# Parsing and cleaning
# ---------------------------------------------------------------------------

def _to_float(item: Any) -> Optional[float]:
    """Coerce one item to a finite float, or None when impossible."""
    if isinstance(item, bool) or not isinstance(item, (int, float)):
        return None
    try:
        number = float(item)
    except (TypeError, ValueError, OverflowError):  # pragma: no cover - defensive
        return None
    return number if math.isfinite(number) else None


def _parse_timestamp(item: Any) -> Optional[float]:
    """Parse an epoch number or ``datetime`` into finite epoch seconds.

    Timezone-aware datetimes convert through their own offset; naive ones are
    assumed UTC (an OSINT pipeline has no local-time business).
    """
    if isinstance(item, datetime):
        stamp = item.timestamp() if item.tzinfo else item.replace(
            tzinfo=timezone.utc
        ).timestamp()
        stamp = float(stamp)
        return stamp if math.isfinite(stamp) else None
    return _to_float(item)


def _parse_label(item: Any) -> Optional[str]:
    """Normalise a label: None stays None, everything else becomes str."""
    if item is None:
        return None
    if isinstance(item, str):
        return item
    return str(item)


def to_points(pairs: Any) -> List[TimeSeriesPoint]:
    """Defensively parse an iterable of rows into chronological points.

    Accepted row shapes (anything unrecognised is skipped, not fatal):

    * an existing :class:`TimeSeriesPoint` (kept as-is);
    * a 2-item tuple/list ``(timestamp, value)``;
    * a 3-item tuple/list ``(timestamp, value, label)``;
    * a dict with a timestamp key (``'timestamp'`` / ``'ts'`` / ``'time'``),
      a value key (``'value'`` / ``'v'`` / ``'val'`` / ``'y'``) and an
      optional label key (``'label'`` / ``'name'`` / ``'tag'``).

    Timestamps may be epoch numbers or ``datetime`` objects; values must be
    finite numbers. The result is sorted by timestamp ascending (stable, so
    equal timestamps keep their input order).

    Args:
        pairs: Iterable of rows in any of the shapes above; ``None`` yields
            an empty list.

    Returns:
        Chronologically sorted list of :class:`TimeSeriesPoint`. Never
        raises; unparseable rows simply do not appear in the output.

    Example:
        >>> to_points([(2, 5.0), (1, 3.0)])[0].value
        3.0
        >>> to_points([{'ts': 0, 'value': 4}])[0].value
        4.0
    """
    if pairs is None:
        return []
    if isinstance(pairs, TimeSeriesPoint):
        return [pairs]
    try:
        iterator = iter(pairs)
    except TypeError:
        return []

    points: List[TimeSeriesPoint] = []
    for row in iterator:
        timestamp: Optional[float] = None
        value: Optional[float] = None
        label: Optional[str] = None
        if isinstance(row, TimeSeriesPoint):
            timestamp = _to_float(row.timestamp)
            value = _to_float(row.value)
            label = row.label
        elif isinstance(row, dict):
            for key in _TS_KEYS:
                if key in row:
                    timestamp = _parse_timestamp(row[key])
                    break
            for key in _VALUE_KEYS:
                if key in row:
                    value = _to_float(row[key])
                    break
            for key in _LABEL_KEYS:
                if key in row:
                    label = _parse_label(row[key])
                    break
        elif isinstance(row, (list, tuple)) and len(row) in (2, 3):
            timestamp = _parse_timestamp(row[0])
            value = _to_float(row[1])
            label = _parse_label(row[2]) if len(row) == 3 else None
        if timestamp is None or value is None:
            continue
        points.append(TimeSeriesPoint(timestamp, value, label))
    return sorted(points, key=lambda point: point.timestamp)


def _valid_points(points: Any) -> List[TimeSeriesPoint]:
    """Keep only genuine points with finite timestamp and value.

    ``None``, non-iterables, foreign objects and points carrying NaN/inf
    timestamps or values are dropped so downstream arithmetic stays clean.
    Order is preserved (no sorting) - index-reporting functions rely on it.
    """
    if points is None:
        return []
    try:
        iterator = iter(points)
    except TypeError:
        return []
    kept: List[TimeSeriesPoint] = []
    for item in iterator:
        if isinstance(item, TimeSeriesPoint) and _to_float(item.timestamp) is not None \
                and _to_float(item.value) is not None:
            kept.append(item)
    return kept


# ---------------------------------------------------------------------------
# Smoothing
# ---------------------------------------------------------------------------

def moving_average(points: Any, window: int) -> List[TimeSeriesPoint]:
    """Trailing (right-anchored) moving average.

    Each output point at index ``i >= window - 1`` averages the ``window``
    values ending at ``i`` and keeps that point's timestamp and label. The
    first ``window - 1`` positions have no complete window and are omitted -
    trailing windows never peek into the future, which matters when the
    series is being inspected live.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped and list order is used as-is.
        window: Window length in points.

    Returns:
        Smoothed points. Empty when the window is invalid (``< 1``) or
        larger than the number of usable points.

    Example:
        >>> series = to_points([(0, 1), (1, 2), (2, 3)])
        >>> moving_average(series, 2)[0].value
        1.5
    """
    try:
        size = int(window)
    except (TypeError, ValueError):
        return []
    if size < 1:
        return []
    series = _valid_points(points)
    if size > len(series):
        return []
    result: List[TimeSeriesPoint] = []
    for i in range(size - 1, len(series)):
        chunk = series[i - size + 1:i + 1]
        average = sum(p.value for p in chunk) / size
        result.append(TimeSeriesPoint(series[i].timestamp, average, series[i].label))
    return result


def ewma(points: Any, alpha: float = 0.3) -> List[TimeSeriesPoint]:
    """Exponentially weighted moving average.

    Recursive form ``y[0] = x[0]``, ``y[t] = alpha * x[t] + (1 - alpha) *
    y[t-1]``: every point keeps a memory of all earlier ones with weight
    ``alpha`` deciding how fast the past fades. EWMA needs no window length,
    which makes it the default smoothing for irregular OSINT series where
    "the last 10 observations" is not a meaningful span.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped and list order is used as-is.
        alpha: Decay factor in ``(0, 1]`` - the weight given to the newest
            observation. Non-finite values or values outside the range
            return an empty list.

    Returns:
        Smoothed points carrying the original timestamps and labels.

    Example:
        >>> series = to_points([(0, 10), (1, 20), (2, 30)])
        >>> [round(p.value, 2) for p in ewma(series, alpha=0.5)]
        [10.0, 15.0, 22.5]
    """
    factor = _to_float(alpha)
    if factor is None or factor <= 0.0 or factor > 1.0:
        return []
    series = _valid_points(points)
    if not series:
        return []
    smoothed: List[TimeSeriesPoint] = [
        TimeSeriesPoint(series[0].timestamp, series[0].value, series[0].label)
    ]
    for point in series[1:]:
        previous = smoothed[-1].value
        value = factor * point.value + (1.0 - factor) * previous
        smoothed.append(TimeSeriesPoint(point.timestamp, value, point.label))
    return smoothed


# ---------------------------------------------------------------------------
# Trend
# ---------------------------------------------------------------------------

def _linear_fit(series: List[TimeSeriesPoint]) -> Optional[Tuple[float, float, float]]:
    """Least-squares fit ``value = slope * timestamp + intercept``.

    Returns ``(slope, intercept, r_squared)`` or None when a fit is
    impossible (fewer than two points, or all timestamps identical, which
    leaves no time axis to regress on). Computation is centred on the means
    to avoid the catastrophic cancellation that raw epoch-scale squares
    would cause.
    """
    count = len(series)
    if count < 2:
        return None
    xs = [p.timestamp for p in series]
    ys = [p.value for p in series]
    x_mean = sum(xs) / count
    y_mean = sum(ys) / count
    sxx = sum((x - x_mean) ** 2 for x in xs)
    if sxx <= 0.0:
        return None
    sxy = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = y_mean - slope * x_mean
    ss_res = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - y_mean) ** 2 for y in ys)
    r_squared = 1.0 - ss_res / ss_tot if ss_tot > 0.0 else 1.0
    return (slope, intercept, r_squared)


def linear_trend(points: Any) -> Optional[Dict[str, Any]]:
    """Least-squares linear trend over epoch timestamps.

    Fits ``value = slope * timestamp + intercept`` and translates the result
    into analyst language: how fast per *day*, in which direction, and how
    much of the variance the line actually explains.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped and list order is used as-is.

    Returns:
        Dict with keys:

        * ``'slope'`` - value change per second (raw regression slope).
        * ``'intercept'`` - fitted value at timestamp 0.
        * ``'r_squared'`` - coefficient of determination (1.0 for a perfect
          line; 1.0 is also reported for constant series).
        * ``'trend_direction'`` - ``'rising'`` / ``'falling'`` /
          ``'flat'`` (``|slope| < 1e-12``).
        * ``'slope_per_day'`` - slope scaled by 86400, the human unit.
        * ``'n'`` - number of points used.

        ``None`` when fewer than two usable points exist or every timestamp
        is identical (no time axis).

    Example:
        >>> trend = linear_trend(to_points([(0, 1), (86400, 2), (172800, 3)]))
        >>> trend['trend_direction']
        'rising'
        >>> trend['slope_per_day']
        1.0
    """
    series = _valid_points(points)
    fit = _linear_fit(series)
    if fit is None:
        return None
    slope, intercept, r_squared = fit
    if abs(slope) < _FLAT_SLOPE:
        direction = 'flat'
    elif slope > 0.0:
        direction = 'rising'
    else:
        direction = 'falling'
    return {
        'slope': slope,
        'intercept': intercept,
        'r_squared': r_squared,
        'trend_direction': direction,
        'slope_per_day': slope * _SECONDS_PER_DAY,
        'n': len(series),
    }


def detrend(points: Any) -> List[TimeSeriesPoint]:
    """Remove the linear trend: keep only the residuals.

    Subtracting the fitted line isolates the short-term behaviour - the
    seasonal wiggle, the spikes, the changepoints - from the slow drift that
    would otherwise mask them.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped and list order is used as-is.

    Returns:
        Points whose values are ``observed - fitted``; timestamps and labels
        pass through untouched. Empty for fewer than two usable points or a
        degenerate time axis (all timestamps equal).

    Example:
        >>> resid = detrend(to_points([(0, 1), (86400, 2), (172800, 3)]))
        >>> all(abs(p.value) < 1e-9 for p in resid)
        True
    """
    series = _valid_points(points)
    fit = _linear_fit(series)
    if fit is None:
        return []
    slope, intercept, _ = fit
    return [
        TimeSeriesPoint(
            p.timestamp,
            p.value - (intercept + slope * p.timestamp),
            p.label,
        )
        for p in series
    ]


# ---------------------------------------------------------------------------
# Transformations
# ---------------------------------------------------------------------------

def cumulative_sum(points: Any) -> List[TimeSeriesPoint]:
    """Running total of the values, in list order.

    The classic "how much has happened so far" curve for volume evidence -
    queries executed, bytes seen, alerts raised.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped and list order is used as-is.

    Returns:
        Points whose values are the cumulative sum; timestamps and labels
        pass through. Empty input yields empty output.

    Example:
        >>> [p.value for p in cumulative_sum(to_points([(0, 1), (1, 2), (2, 3)]))]
        [1.0, 3.0, 6.0]
    """
    series = _valid_points(points)
    result: List[TimeSeriesPoint] = []
    running = 0.0
    for point in series:
        running += point.value
        result.append(TimeSeriesPoint(point.timestamp, running, point.label))
    return result


def rate_of_change(points: Any) -> List[TimeSeriesPoint]:
    """First-order differences (n-1 points).

    Each output point carries the change ``value[i+1] - value[i]`` and the
    timestamp/label of the *later* point - the moment the change became
    visible.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped and list order is used as-is.

    Returns:
        Difference series; empty for fewer than two usable points.

    Example:
        >>> [p.value for p in rate_of_change(to_points([(0, 1), (1, 2), (2, 3)]))]
        [1.0, 1.0]
    """
    series = _valid_points(points)
    result: List[TimeSeriesPoint] = []
    for i in range(1, len(series)):
        delta = series[i].value - series[i - 1].value
        result.append(TimeSeriesPoint(series[i].timestamp, delta, series[i].label))
    return result


def resample_daily(points: Any) -> List[TimeSeriesPoint]:
    """Aggregate to one mean-value point per UTC day.

    Sparse history (a lookup here, a lookup there) becomes a tidy daily
    average series that smoothing and trend tools can chew on. Each output
    point sits at UTC midnight of its day and carries the day's ``YYYY-MM-DD``
    as label.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped. Points are bucketed by ``floor(timestamp / 86400)``,
            which is exactly the UTC calendar day.

    Returns:
        One point per observed day, ordered by day; the value is the
        arithmetic mean of that day's values.

    Example:
        >>> daily = resample_daily(to_points([(0, 10), (43200, 20), (86400, 30)]))
        >>> [(p.value, p.label) for p in daily]
        [(15.0, '1970-01-01'), (30.0, '1970-01-02')]
    """
    series = _valid_points(points)
    buckets: Dict[int, List[float]] = {}
    for point in series:
        day = int(math.floor(point.timestamp / _SECONDS_PER_DAY))
        buckets.setdefault(day, []).append(point.value)
    result: List[TimeSeriesPoint] = []
    for day in sorted(buckets):
        values = buckets[day]
        midnight = day * _SECONDS_PER_DAY
        label = datetime.fromtimestamp(midnight, tz=timezone.utc).strftime('%Y-%m-%d')
        result.append(TimeSeriesPoint(midnight, sum(values) / len(values), label))
    return result


# ---------------------------------------------------------------------------
# Changepoints and seasonality
# ---------------------------------------------------------------------------

def detect_changepoints(points: Any, threshold: float = 2.0) -> List[Dict[str, Any]]:
    """CUSUM changepoint detection on robust-z-scaled values.

    Values are standardised with the median/MAD robust z-score, then two
    cumulative sums track upward and downward drift with the classical 0.5
    slack: ``S+ = max(0, S+ + z - drift)``, ``S- = max(0, S- - z - drift)``.
    When either accumulator crosses ``threshold`` a changepoint is reported
    at that index and both accumulators reset. Because the scaling is
    robust, a single extreme value inflates neither the baseline nor the
    sensitivity the way a mean/stdev CUSUM would.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped. Points are processed in **list order** - sort via
            :func:`to_points` if order is not guaranteed.
        threshold: Alarm level in robust-z units (default 2.0). Non-finite
            or non-positive values fall back to 2.0.

    Returns:
        List of event dicts, each with:

        * ``'index'`` - position in the (cleaned) input list;
        * ``'timestamp'`` - epoch seconds of the triggering point;
        * ``'direction'`` - ``'up'`` or ``'down'``;
        * ``'magnitude'`` - ``value - median`` of the baseline at that point;
        * ``'score'`` - the CUSUM accumulator value when the alarm tripped.

        Empty for fewer than three points or a zero-MAD (constant-middle)
        series - nothing to detect there.

    Example:
        >>> vals = [5, 6, 5, 6, 5, 6, 5, 6, 20, 21, 20, 21]
        >>> events = detect_changepoints(to_points(list(zip(range(12), vals))))
        >>> events[0]['direction'], events[0]['index']
        ('up', 8)
    """
    level = _to_float(threshold)
    if level is None or level <= 0.0:
        level = _CUSUM_DEFAULT_THRESHOLD
    series = _valid_points(points)
    if len(series) < 3:
        return []
    values = [p.value for p in series]
    ordered = sorted(values)
    count = len(ordered)
    middle = (
        ordered[count // 2] if count % 2 == 1
        else (ordered[count // 2 - 1] + ordered[count // 2]) / 2.0
    )
    deviations = sorted(abs(v - middle) for v in values)
    mad = (
        deviations[count // 2] if count % 2 == 1
        else (deviations[count // 2 - 1] + deviations[count // 2]) / 2.0
    )
    if mad <= 0.0:
        return []

    events: List[Dict[str, Any]] = []
    high = 0.0
    low = 0.0
    for i, value in enumerate(values):
        z = 0.6745 * (value - middle) / mad
        high = max(0.0, high + z - _CUSUM_DRIFT)
        low = max(0.0, low - z - _CUSUM_DRIFT)
        if high > level:
            events.append({
                'index': i,
                'timestamp': series[i].timestamp,
                'direction': 'up',
                'magnitude': value - middle,
                'score': high,
            })
            high = 0.0
            low = 0.0
        elif low > level:
            events.append({
                'index': i,
                'timestamp': series[i].timestamp,
                'direction': 'down',
                'magnitude': value - middle,
                'score': low,
            })
            high = 0.0
            low = 0.0
    return events


def seasonality_hint(points: Any, period: int) -> Optional[Dict[str, Any]]:
    """Cheap seasonality test on detrended residuals.

    The series is detrended (see :func:`detrend`) and the residuals grouped
    by phase ``index % period``. If grouping explains more than half the
    residual variance - ``between-group variance / total variance > 0.5`` -
    the verdict is ``'seasonal'``. This is a *hint*, not a periodogram: it
    only confirms a caller-supplied candidate period (24 for hourly data, 7
    for daily data, and so on), which is exactly what an analyst triaging a
    watchlist needs.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped. Points are processed in **list order** (phase comes
            from position).
        period: Candidate season length in points. Must be >= 2, and the
            series must hold at least ``2 * period`` points (two full
            cycles) - otherwise None.

    Returns:
        Dict with keys ``'period'``, ``'ratio'`` (0..1), ``'verdict'``
        (``'seasonal'`` / ``'not_seasonal'``) and ``'group_means'``
        (per-phase residual means); ``None`` when the hint is uncomputable
        (bad period, too few points, degenerate time axis).

    Example:
        >>> hours = [(h, 10.0 if h % 2 == 0 else 0.0) for h in range(8)]
        >>> seasonality_hint(to_points(hours), period=2)['verdict']
        'seasonal'
    """
    try:
        cycle = int(period)
    except (TypeError, ValueError):
        return None
    if cycle < 2:
        return None
    residuals = detrend(points)
    if len(residuals) < 2 * cycle:
        return None

    groups: List[List[float]] = [[] for _ in range(cycle)]
    for i, point in enumerate(residuals):
        groups[i % cycle].append(point.value)
    total_count = len(residuals)
    grand_mean = sum(p.value for p in residuals) / total_count
    total_var = sum((p.value - grand_mean) ** 2 for p in residuals) / total_count

    between_var = 0.0
    group_means: List[float] = []
    for bucket in groups:
        bucket_mean = sum(bucket) / len(bucket) if bucket else 0.0
        group_means.append(bucket_mean)
        weight = len(bucket) / total_count
        between_var += weight * (bucket_mean - grand_mean) ** 2

    ratio = 0.0 if total_var <= 0.0 else between_var / total_var
    return {
        'period': cycle,
        'ratio': ratio,
        'verdict': 'seasonal' if ratio > _SEASONAL_RATIO else 'not_seasonal',
        'group_means': group_means,
    }


# ---------------------------------------------------------------------------
# One-shot summary
# ---------------------------------------------------------------------------

def series_summary(points: Any) -> Dict[str, Any]:
    """One-stop structural summary of a series.

    Bundles the numbers a triage view wants at a glance: how many points,
    over how many days, trending which way, centred where, with how many
    changepoints.

    Args:
        points: Iterable of :class:`TimeSeriesPoint`; invalid entries are
            dropped and list order is used as-is.

    Returns:
        Dict with keys ``'count'``, ``'first_timestamp'``,
        ``'last_timestamp'``, ``'span_days'``, ``'trend'`` (the full
        :func:`linear_trend` dict or None), ``'direction'`` (trend direction
        or None), ``'mean'``, ``'variance'`` (sample) and
        ``'changepoint_count'``. Empty input yields a well-formed dict with
        zeroed/None fields - never an exception.

    Example:
        >>> summary = series_summary(to_points([(0, 1), (86400, 3)]))
        >>> summary['count'], summary['direction']
        (2, 'rising')
    """
    series = _valid_points(points)
    count = len(series)
    empty = {
        'count': 0,
        'first_timestamp': None,
        'last_timestamp': None,
        'span_days': None,
        'trend': None,
        'direction': None,
        'mean': None,
        'variance': None,
        'changepoint_count': 0,
    }
    if count == 0:
        return empty
    values = [p.value for p in series]
    timestamps = [p.timestamp for p in series]
    trend = linear_trend(series)
    avg = sum(values) / count
    sample_var = (
        sum((v - avg) ** 2 for v in values) / (count - 1) if count >= 2 else None
    )
    return {
        'count': count,
        'first_timestamp': min(timestamps),
        'last_timestamp': max(timestamps),
        'span_days': (max(timestamps) - min(timestamps)) / _SECONDS_PER_DAY,
        'trend': trend,
        'direction': trend['trend_direction'] if trend else None,
        'mean': avg,
        'variance': sample_var,
        'changepoint_count': len(detect_changepoints(series)),
    }
