"""
Outlier and anomaly detection for numeric evidence (v6.0 Part 2).

An OSINT pipeline drinks from flaky sources, so "is this number wrong?" is a
daily question: a latency of 90 seconds from a source that usually answers in
2, a risk score ten standard deviations from its peers, a coordinate that
jumps an ocean. Throwing humans at every suspicious number does not scale;
throwing a fixed threshold at it does not survive source changes.

This module implements four statistical detectors - z-score, Tukey IQR
fences, MAD-based robust z, and the Grubbs outlier test - plus an ensemble
that votes across them and a hard floor/ceiling check for contract-style
bounds. Each detector returns :class:`AnomalyScore` records carrying the
offending value, a comparable score, the method name and a detail dict, so
downstream alerting can rank, filter and explain hits without re-deriving
anything.

Design contract:

* **Every method returns a list** (Grubbs returns its single best candidate
  or None) and **never raises**: dirty input yields an empty list, not a
  crash mid-investigation.
* **n < 3 means "not enough evidence"** - all detectors return empty for
  fewer than three usable values. Two points cannot agree on an outlier.
* **Scores are method-specific but comparable within a method** - |z| for
  z-score, fence distance in IQR units, 0.6745-scaled robust z, the Grubbs G
  statistic. The ensemble reports the strongest agreeing score.
* **Indices are reported, not just values**: ``detail['index']`` points at
  the position in the cleaned value list, so hits can be traced back to the
  original observation even when duplicates exist.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

__all__ = [
    'AnomalyScore',
    'detect_anomalies',
    'ensemble_anomalies',
    'grubbs_test',
    'iqr_anomalies',
    'mad_anomalies',
    'threshold_anomalies',
    'zscore_anomalies',
]

#: Minimum usable observations before any detector will speak up.
_MIN_N = 3

#: Normal-consistent MAD scaling constant (median absolute deviation of a
#: standard normal is 1/0.6745).
_MAD_SCALE = 0.6745

#: Grubbs critical values (two-sided) for n = 3..30 at alpha = 0.05, from the
#: standard Grubbs & Beck (1972) tables as republished by NIST/SEMATECH.
_GRUBBS_05: Dict[int, float] = {
    3: 1.153, 4: 1.463, 5: 1.672, 6: 1.822, 7: 1.938, 8: 2.032, 9: 2.110,
    10: 2.176, 11: 2.234, 12: 2.285, 13: 2.331, 14: 2.371, 15: 2.409,
    16: 2.443, 17: 2.475, 18: 2.504, 19: 2.532, 20: 2.557, 21: 2.580,
    22: 2.602, 23: 2.623, 24: 2.642, 25: 2.660, 26: 2.677, 27: 2.693,
    28: 2.709, 29: 2.724, 30: 2.738,
}

#: Grubbs critical values (two-sided) for n = 3..30 at alpha = 0.01.
_GRUBBS_01: Dict[int, float] = {
    3: 1.155, 4: 1.496, 5: 1.764, 6: 1.973, 7: 2.139, 8: 2.274, 9: 2.387,
    10: 2.482, 11: 2.564, 12: 2.636, 13: 2.699, 14: 2.755, 15: 2.806,
    16: 2.852, 17: 2.894, 18: 2.932, 19: 2.968, 20: 3.001, 21: 3.031,
    22: 3.060, 23: 3.087, 24: 3.112, 25: 3.135, 26: 3.157, 27: 3.178,
    28: 3.199, 29: 3.218, 30: 3.236,
}

#: Normal quantiles used by the large-sample Grubbs approximation.
_Z_05 = 1.96
_Z_01 = 2.576


# ---------------------------------------------------------------------------
# Data model and input cleaning
# ---------------------------------------------------------------------------

@dataclass
class AnomalyScore:
    """One flagged observation.

    Attributes:
        value: The offending numeric value.
        score: Method-specific anomaly strength (higher = more anomalous).
        method: Detector name (``'zscore'``, ``'iqr'``, ``'mad'``,
            ``'grubbs'``, ``'ensemble'`` or ``'threshold'``).
        detail: Method-specific context; always contains ``'index'`` (the
            position in the cleaned value list).
    """

    value: float
    score: float
    method: str
    detail: Dict[str, Any] = field(default_factory=dict)


def _to_float(item: Any) -> Optional[float]:
    """Coerce one item to a finite float, or None when impossible."""
    if isinstance(item, bool) or not isinstance(item, (int, float)):
        return None
    try:
        number = float(item)
    except (TypeError, ValueError, OverflowError):  # pragma: no cover - defensive
        return None
    return number if math.isfinite(number) else None


def _clean_values(values: Iterable[Any]) -> List[float]:
    """Materialise an arbitrary iterable into finite floats (never raises)."""
    if values is None:
        return []
    try:
        iterator = iter(values)
    except TypeError:
        return []
    cleaned: List[float] = []
    for item in iterator:
        number = _to_float(item)
        if number is not None:
            cleaned.append(number)
    return cleaned


def _median_of(sorted_values: List[float]) -> Optional[float]:
    """Median of an already-sorted list (None for empty input)."""
    count = len(sorted_values)
    if not count:
        return None
    middle = count // 2
    if count % 2 == 1:
        return sorted_values[middle]
    return (sorted_values[middle - 1] + sorted_values[middle]) / 2.0


def _sample_stdev(cleaned: List[float]) -> Optional[float]:
    """Sample standard deviation (None below two values or zero variance)."""
    count = len(cleaned)
    if count < 2:
        return None
    avg = sum(cleaned) / count
    ss = sum((x - avg) ** 2 for x in cleaned)
    if ss <= 0.0:
        return None
    return math.sqrt(ss / (count - 1))


# ---------------------------------------------------------------------------
# Single-method detectors
# ---------------------------------------------------------------------------

def zscore_anomalies(values: Iterable[Any], threshold: float = 3.0) -> List[AnomalyScore]:
    """Flag values whose classic z-score exceeds a threshold (both tails).

    The textbook detector: fast, intuitive, and fragile exactly one way - a
    single huge outlier inflates the standard deviation and hides itself
    ("masking"). Still the right first call for well-behaved bulk data.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        threshold: |z| alarm level (default 3.0, i.e. roughly the 0.27%
            two-tailed normal tails). Non-finite or non-positive values fall
            back to 3.0.

    Returns:
        Hits sorted by index, ``score = |z|``; ``detail`` carries ``'index'``,
        ``'z'`` (signed), ``'direction'`` (``'high'``/``'low'``), ``'mean'``
        and ``'stdev'``. Empty for n < 3, zero variance or no hits.

    Example:
        >>> hits = zscore_anomalies([1, 1, 1, 1, 10], threshold=1.5)
        >>> hits[0].value, round(hits[0].score, 4)
        (10.0, 1.7889)
    """
    level = _to_float(threshold)
    if level is None or level <= 0.0:
        level = 3.0
    cleaned = _clean_values(values)
    if len(cleaned) < _MIN_N:
        return []
    avg = sum(cleaned) / len(cleaned)
    stdev = _sample_stdev(cleaned)
    if stdev is None:
        return []
    hits: List[AnomalyScore] = []
    for i, value in enumerate(cleaned):
        z = (value - avg) / stdev
        if abs(z) > level:
            hits.append(AnomalyScore(
                value=value,
                score=abs(z),
                method='zscore',
                detail={
                    'index': i,
                    'z': z,
                    'direction': 'high' if z > 0 else 'low',
                    'mean': avg,
                    'stdev': stdev,
                },
            ))
    return hits


def iqr_anomalies(values: Iterable[Any], factor: float = 1.5) -> List[AnomalyScore]:
    """Tukey fence detector: values outside ``Q1 - factor*IQR`` / ``Q3 + factor*IQR``.

    Boxplot logic, made quantitative. Resistant to tails by construction
    (quartiles ignore the extreme 25% on each side), which is why it is the
    default "is this weird" check for skewed evidence. With ``factor=3.0``
    the fences become the "far out" extremes Tukey reserved for real
    investigation.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        factor: Fence width in IQR units (default 1.5). Non-finite or
            non-positive values fall back to 1.5.

    Returns:
        Hits sorted by index with ``score`` = distance beyond the violated
        fence in IQR units (when the IQR is zero the fallback score is the
        absolute distance from the median, so degenerate data still
        reports); ``detail`` carries ``'lower_fence'``, ``'upper_fence'``,
        ``'q1'``, ``'q3'``, ``'iqr'`` and ``'direction'``. Empty for n < 3.

    Example:
        >>> hits = iqr_anomalies([1, 2, 3, 4, 100])
        >>> hits[0].value, hits[0].detail['upper_fence']
        (100.0, 7.0)
    """
    width = _to_float(factor)
    if width is None or width <= 0.0:
        width = 1.5
    cleaned = _clean_values(values)
    if len(cleaned) < _MIN_N:
        return []
    ordered = sorted(cleaned)

    def quartile(rank: float) -> float:
        position = (rank / 100.0) * (len(ordered) - 1)
        lower = int(math.floor(position))
        upper = int(math.ceil(position))
        if lower == upper:
            return ordered[lower]
        return ordered[lower] + (position - lower) * (ordered[upper] - ordered[lower])

    q1 = quartile(25.0)
    q3 = quartile(75.0)
    iqr = q3 - q1
    lower_fence = q1 - width * iqr
    upper_fence = q3 + width * iqr
    median = _median_of(ordered)

    hits: List[AnomalyScore] = []
    for i, value in enumerate(cleaned):
        if value > upper_fence or value < lower_fence:
            if iqr > 0.0:
                score = max((value - upper_fence) / iqr, (lower_fence - value) / iqr)
            else:
                # Degenerate middle half: fall back to distance from median.
                score = abs(value - median) if median is not None else 0.0
            hits.append(AnomalyScore(
                value=value,
                score=score,
                method='iqr',
                detail={
                    'index': i,
                    'lower_fence': lower_fence,
                    'upper_fence': upper_fence,
                    'q1': q1,
                    'q3': q3,
                    'iqr': iqr,
                    'direction': 'high' if value > upper_fence else 'low',
                },
            ))
    return hits


def mad_anomalies(values: Iterable[Any], threshold: float = 3.5) -> List[AnomalyScore]:
    """Median/MAD robust z-score detector (Iglewicz-Hoaglin style).

    Scores each value as ``0.6745 * |value - median| / MAD``. The median and
    MAD barely move when outliers arrive, so this detector survives exactly
    the contamination that breaks :func:`zscore_anomalies`; the customary
    3.5 cutoff flags roughly the outer 0.05% of normal data.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        threshold: Robust-z alarm level (default 3.5). Non-finite or
            non-positive values fall back to 3.5.

    Returns:
        Hits sorted by index with ``score`` = the robust z; ``detail``
        carries ``'index'``, ``'robust_z'`` (signed), ``'direction'``,
        ``'median'`` and ``'mad'``. Empty for n < 3, zero MAD (more than half
        the values identical - every deviation would be infinite) or no hits.

    Example:
        >>> hits = mad_anomalies([1, 2, 3, 4, 100])
        >>> hits[0].value, round(hits[0].score, 2)
        (100.0, 65.43)
    """
    level = _to_float(threshold)
    if level is None or level <= 0.0:
        level = 3.5
    cleaned = _clean_values(values)
    if len(cleaned) < _MIN_N:
        return []
    ordered = sorted(cleaned)
    median = _median_of(ordered)
    if median is None:  # pragma: no cover - defensive
        return []
    deviations = sorted(abs(x - median) for x in cleaned)
    mad = _median_of(deviations)
    if mad is None or mad <= 0.0:
        return []
    hits: List[AnomalyScore] = []
    for i, value in enumerate(cleaned):
        robust_z = _MAD_SCALE * (value - median) / mad
        if abs(robust_z) > level:
            hits.append(AnomalyScore(
                value=value,
                score=abs(robust_z),
                method='mad',
                detail={
                    'index': i,
                    'robust_z': robust_z,
                    'direction': 'high' if robust_z > 0 else 'low',
                    'median': median,
                    'mad': mad,
                },
            ))
    return hits


# ---------------------------------------------------------------------------
# Grubbs test
# ---------------------------------------------------------------------------

def _grubbs_critical(count: int, alpha: float) -> float:
    """Critical Grubbs value G(n, alpha) - table lookup plus approximation.

    For ``n <= 30`` the published two-sided Grubbs & Beck tables (0.05 /
    0.01) are used verbatim. Above 30 the approximation
    ``G = sqrt(n) * z / sqrt(n - 1 + z^2)`` with ``z`` = 1.96 (alpha 0.05) or
    2.576 (alpha 0.01) takes over. The approximation is deliberately simple
    (no t-quantile solver in a stdlib-only package) and is *conservative in
    shape only* - it grows slowly with n, so treat large-n verdicts as a
    screening hint rather than a formal test. ``alpha`` values other than
    0.01 map to the 0.05 table.
    """
    table = _GRUBBS_01 if alpha <= 0.011 else _GRUBBS_05
    if count in table:
        return table[count]
    z = _Z_01 if alpha <= 0.011 else _Z_05
    return math.sqrt(count) * z / math.sqrt(count - 1 + z * z)


def grubbs_test(values: Iterable[Any], alpha: float = 0.05) -> Optional[AnomalyScore]:
    """Grubbs test for a *single* outlier: the most deviant value, or None.

    Finds ``G = max |x - mean| / stdev`` and compares it with the critical
    value G(n, alpha) from the standard tables (see
    :func:`_grubbs_critical` for the n > 30 approximation). Grubbs answers
    exactly one question - "does the single worst point break the sample?" -
    which makes it ideal for sanity-checking a batch of measurements before
    any other statistics are computed, and wrong for finding many outliers
    at once.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        alpha: Significance level; only 0.05 and 0.01 are table-supported,
            anything above 0.011 behaves as 0.05.

    Returns:
        An :class:`AnomalyScore` for the most deviant value (score = the G
        statistic; ``detail`` carries ``'index'``, ``'critical_value'``,
        ``'alpha'``, ``'mean'``, ``'stdev'``, ``'n'``, ``'direction'`` and
        ``'approximate'`` - True when n > 30 used the approximation) **only
        when G exceeds the critical value**; otherwise ``None``. ``None`` as
        well for n < 3 or zero variance.

    Example:
        >>> hit = grubbs_test([1, 2, 3, 4, 100])
        >>> hit.value, round(hit.score, 4)
        (100.0, 1.7883)
        >>> grubbs_test([1, 2, 3, 4, 5]) is None
        True
    """
    significance = _to_float(alpha)
    if significance is None or significance <= 0.0 or significance >= 1.0:
        significance = 0.05
    cleaned = _clean_values(values)
    if len(cleaned) < _MIN_N:
        return None
    avg = sum(cleaned) / len(cleaned)
    stdev = _sample_stdev(cleaned)
    if stdev is None:
        return None
    worst_index = 0
    worst_deviation = -1.0
    for i, value in enumerate(cleaned):
        deviation = abs(value - avg)
        if deviation > worst_deviation:
            worst_deviation = deviation
            worst_index = i
    statistic = worst_deviation / stdev
    critical = _grubbs_critical(len(cleaned), significance)
    if statistic <= critical:
        return None
    worst_value = cleaned[worst_index]
    return AnomalyScore(
        value=worst_value,
        score=statistic,
        method='grubbs',
        detail={
            'index': worst_index,
            'critical_value': critical,
            'alpha': significance,
            'mean': avg,
            'stdev': stdev,
            'n': len(cleaned),
            'direction': 'high' if worst_value > avg else 'low',
            'approximate': len(cleaned) > 30,
        },
    )


# ---------------------------------------------------------------------------
# Combination detectors
# ---------------------------------------------------------------------------

def _grubbs_as_list(values: List[float]) -> List[AnomalyScore]:
    """Adapt :func:`grubbs_test` to the list-of-hits detector interface."""
    hit = grubbs_test(values)
    return [hit] if hit is not None else []


def ensemble_anomalies(
    values: Iterable[Any],
    methods: Sequence[str] = ('zscore', 'iqr', 'mad'),
    votes: int = 2,
) -> List[AnomalyScore]:
    """Vote across several detectors; keep values enough methods agree on.

    Each listed detector runs with its default parameters. Every hit is
    bucketed by the value's index; indices accumulating at least ``votes``
    hits are reported once with ``method='ensemble'``, the strongest agreeing
    score as ``score`` and the full per-method breakdown in ``detail``. Two
    agreeing methods out of three filters the "one detector, one opinion"
    false positives that plague single-statistic alerting.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        methods: Detector names to run, subset of ``('zscore', 'iqr',
            'mad', 'grubbs')``; unknown names are skipped. A single string is
            treated as a one-element list.
        votes: Minimum agreeing detectors (default 2); values below 1 are
            clamped to 1.

    Returns:
        Ensemble hits sorted by index, or empty for n < 3 / no survivors.

    Example:
        >>> hits = ensemble_anomalies([1, 2, 3, 4, 100])
        >>> hits[0].method, sorted(hits[0].detail['methods_hit'])
        ('ensemble', ['iqr', 'mad'])
    """
    cleaned = _clean_values(values)
    if len(cleaned) < _MIN_N:
        return []
    if isinstance(methods, str):
        methods = (methods,)
    try:
        required = int(votes)
    except (TypeError, ValueError):
        required = 2
    if required < 1:
        required = 1

    registry = {
        'zscore': zscore_anomalies,
        'iqr': iqr_anomalies,
        'mad': mad_anomalies,
        'grubbs': _grubbs_as_list,
    }
    hits_by_index: Dict[int, Dict[str, float]] = {}
    for name in methods:
        detector = registry.get(name)
        if detector is None:
            continue
        for hit in detector(cleaned):
            index = hit.detail.get('index')
            if isinstance(index, int):
                hits_by_index.setdefault(index, {})[name] = hit.score

    results: List[AnomalyScore] = []
    for index in sorted(hits_by_index):
        agreements = hits_by_index[index]
        if len(agreements) < required:
            continue
        results.append(AnomalyScore(
            value=cleaned[index],
            score=max(agreements.values()),
            method='ensemble',
            detail={
                'index': index,
                'votes': len(agreements),
                'methods_hit': sorted(agreements),
                'scores': dict(sorted(agreements.items())),
            },
        ))
    return results


def detect_anomalies(
    values: Iterable[Any],
    method: str = 'ensemble',
    **kwargs: Any,
) -> List[AnomalyScore]:
    """Unified detector entry point - one call, any method, kwargs passed on.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        method: One of ``'zscore'``, ``'iqr'``, ``'mad'``, ``'grubbs'``,
            ``'ensemble'``, ``'threshold'``. Unknown names return an empty
            list (defensive: a typo in a pipeline YAML must not crash a run).
        **kwargs: Forwarded to the chosen detector, e.g.
            ``threshold=2.5`` for z-score, ``factor=3.0`` for IQR,
            ``floor``/``ceiling`` for the bound check, ``methods``/``votes``
            for the ensemble. Keyword mismatches degrade to an empty list.

    Returns:
        The detector's hits; Grubbs' optional result is normalised to a list.

    Example:
        >>> hits = detect_anomalies([1, 2, 3, 4, 100], method='iqr', factor=1.5)
        >>> len(hits)
        1
    """
    registry = {
        'zscore': zscore_anomalies,
        'iqr': iqr_anomalies,
        'mad': mad_anomalies,
        'grubbs': grubbs_test,
        'ensemble': ensemble_anomalies,
        'threshold': threshold_anomalies,
    }
    detector = registry.get(method) if isinstance(method, str) else None
    if detector is None:
        return []
    try:
        result = detector(values, **kwargs)
    except TypeError:
        # Unexpected keyword for this detector: refuse quietly, keep running.
        return []
    if result is None:
        return []
    if isinstance(result, AnomalyScore):
        # Grubbs speaks in single candidates; the entry point speaks in lists.
        return [result]
    return result


def threshold_anomalies(
    values: Iterable[Any],
    floor: Optional[float],
    ceiling: Optional[float],
) -> List[AnomalyScore]:
    """Hard bound check: values below a floor or above a ceiling.

    The non-statistical member of the family: instead of learning what is
    normal from the data, the analyst states the contract ("latency must
    stay under 5 s", "score must stay in 0..100") and this detector names
    every violator. Exactly at the bound is compliant - the checks are
    strict.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        floor: Lower bound (exclusive); None disables the lower check.
        ceiling: Upper bound (exclusive); None disables the upper check.
            Both None (or both invalid) yields an empty list - no contract,
            no violation.

    Returns:
        Hits sorted by index with ``score`` = distance beyond the violated
        bound; ``detail`` carries ``'index'``, ``'bound'``
        (``'floor'``/``'ceiling'``), ``'limit'`` and ``'direction'``.
        Consistent with the statistical detectors, fewer than three usable
        values yield an empty list.

    Example:
        >>> hits = threshold_anomalies([1, 50, 100], floor=0.0, ceiling=10.0)
        >>> [h.value for h in hits]
        [50.0, 100.0]
    """
    cleaned = _clean_values(values)
    if len(cleaned) < _MIN_N:
        return []
    lower = _to_float(floor)
    upper = _to_float(ceiling)
    if lower is None and upper is None:
        return []
    hits: List[AnomalyScore] = []
    for i, value in enumerate(cleaned):
        if lower is not None and value < lower:
            hits.append(AnomalyScore(
                value=value,
                score=lower - value,
                method='threshold',
                detail={
                    'index': i,
                    'bound': 'floor',
                    'limit': lower,
                    'direction': 'low',
                },
            ))
        elif upper is not None and value > upper:
            hits.append(AnomalyScore(
                value=value,
                score=value - upper,
                method='threshold',
                detail={
                    'index': i,
                    'bound': 'ceiling',
                    'limit': upper,
                    'direction': 'high',
                },
            ))
    return hits
