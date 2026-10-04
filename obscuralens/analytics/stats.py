"""
Descriptive statistics for investigation-grade numeric analysis (v6.0 Part 2).

ObscuraLens accumulates numeric evidence everywhere: response latencies per
source, risk scores per rule hit, coordinate jitter per target, lookup counts
per day, hash-match confidence, CVE impact numbers. A raw column of floats is
easy to collect and hard to argue with in a case note. This module turns
scattered measurements into defensible summary statistics using nothing but
the Python standard library, so the analytics layer stays installable on
air-gapped hosts where numpy is not an option.

Design contract:

* **Defensive by default.** Every public function accepts anything: ``None``,
  empty lists, mixed junk, NaN and infinity. Non-numeric items are silently
  filtered, non-finite values are dropped, and empty results return ``None``
  (or a safe empty structure) instead of raising. An analyst feeding dirty
  evidence into a statistic should get a shrug, not a stack trace - the rest
  of the pipeline keeps running either way.
* **Pure functions.** No state, no side effects, no I/O: each call is safe to
  run in parallel, cache, or replay inside a report template. Results depend
  only on the argument values, which matters when the same function is called
  twice in a rendered report and must not disagree with itself.
* **Classic, documented definitions.** Quartiles use the same linear
  interpolation as ``numpy.percentile`` (method ``'linear'``); skewness and
  kurtosis are the bias-corrected sample estimators ``G1`` / ``G2`` so they
  match ``scipy.stats.skew`` / ``scipy.stats.kurtosis`` with ``bias=False``.
  No silent method switches - each docstring states the exact formula.

Numeric acceptance rules (module-wide, enforced by :func:`_clean_values`):

* ``bool`` is rejected even though it subclasses ``int``: ``True`` is a flag,
  not a measurement.
* Numeric strings are *not* coerced. Quietly turning ``'5'`` into ``5.0`` in
  an investigation tool hides data-quality bugs; call ``float(x)`` upstream if
  that is really intended.
* ``NaN`` and ``±inf`` are dropped before any arithmetic, so a single poisoned
  measurement cannot poison a mean or a variance.
"""

import math
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = [
    'coefficient_of_variation',
    'histogram',
    'iqr',
    'kurtosis',
    'mean',
    'median',
    'min_max_range',
    'mode',
    'percentile',
    'pstdev',
    'quartiles',
    'robust_zscore',
    'shannon_entropy',
    'skewness',
    'stdev',
    'summarize',
    'value_counts',
    'variance',
    'zscore',
]

#: Absolute tolerance below which a mean is treated as "near zero" for
#: coefficient-of-variation purposes (spec: near-zero mean returns None).
_ZERO_TOL = 1e-12

#: Number formatting used by histogram bin labels (6 significant digits).
_BOUND_FMT = '.6g'


# ---------------------------------------------------------------------------
# Input cleaning - the single funnel every public function goes through
# ---------------------------------------------------------------------------

def _to_float(item: Any) -> Optional[float]:
    """Coerce one item to a finite float, or None when impossible.

    Accepts ``int`` and ``float`` only. Booleans are rejected (flag, not
    measurement), strings are rejected on purpose (see module docstring) and
    non-finite results (NaN/inf) are treated as unusable.
    """
    if isinstance(item, bool) or not isinstance(item, (int, float)):
        return None
    try:
        number = float(item)
    except (TypeError, ValueError, OverflowError):  # pragma: no cover - defensive
        return None
    return number if math.isfinite(number) else None


def _clean_values(values: Iterable[Any]) -> List[float]:
    """Materialise an arbitrary iterable into a list of finite floats.

    ``None``, non-iterable input, non-numeric items and non-finite numbers are
    silently dropped, so every downstream statistic works on a guaranteed
    finite, float-only sequence.
    """
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


# ---------------------------------------------------------------------------
# Central tendency
# ---------------------------------------------------------------------------

def mean(values: Iterable[Any]) -> Optional[float]:
    """Arithmetic mean of a numeric sequence.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        The arithmetic mean as a float, or ``None`` when no usable numbers
        remain. This function never raises for bad input.

    Example:
        >>> mean([1, 2, 3, 4, 5])
        3.0
        >>> mean([]) is None
        True
    """
    cleaned = _clean_values(values)
    if not cleaned:
        return None
    return sum(cleaned) / len(cleaned)


def median(values: Iterable[Any]) -> Optional[float]:
    """Median (50th percentile) of a numeric sequence.

    For an even number of observations the average of the two middle values
    is returned, matching :func:`statistics.median`.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        The median as a float, or ``None`` for empty input.

    Example:
        >>> median([1, 3, 5, 7])
        4.0
    """
    cleaned = sorted(_clean_values(values))
    if not cleaned:
        return None
    count = len(cleaned)
    middle = count // 2
    if count % 2 == 1:
        return float(cleaned[middle])
    return (cleaned[middle - 1] + cleaned[middle]) / 2.0


def mode(values: Iterable[Any]) -> List[float]:
    """All modal values (most frequent), ascending.

    A distribution can have several modes when values tie at the maximum
    frequency; every one is returned. When every value occurs exactly once
    (the all-tie case) every value is modal, mirroring
    :func:`statistics.multimode`.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        Sorted list of modal values. Empty list for empty input - never None,
        so callers can iterate unconditionally.

    Example:
        >>> mode([1, 2, 2, 3])
        [2.0]
        >>> mode([1, 1, 2, 2])
        [1.0, 2.0]
    """
    cleaned = _clean_values(values)
    if not cleaned:
        return []
    counts = Counter(cleaned)
    top = max(counts.values())
    return sorted(value for value, count in counts.items() if count == top)


# ---------------------------------------------------------------------------
# Dispersion
# ---------------------------------------------------------------------------

def variance(values: Iterable[Any], sample: bool = True) -> Optional[float]:
    """Variance of a numeric sequence.

    With ``sample=True`` (default) the unbiased estimator
    ``sum((x - mean)^2) / (n - 1)`` is used, matching
    :func:`statistics.variance`; with ``sample=False`` the population
    estimator divides by ``n`` instead, matching :func:`statistics.pvariance`.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        sample: Use the sample (n-1) estimator when True, population (n)
            estimator when False.

    Returns:
        The variance as a float. ``None`` when there are too few values for
        the requested estimator (sample needs n >= 2, population n >= 1).

    Example:
        >>> variance([1, 2, 3, 4, 5])
        2.5
        >>> variance([1, 2, 3, 4, 5], sample=False)
        2.0
    """
    cleaned = _clean_values(values)
    count = len(cleaned)
    if (sample and count < 2) or (not sample and count < 1):
        return None
    avg = sum(cleaned) / count
    ss = sum((x - avg) ** 2 for x in cleaned)
    return ss / (count - 1) if sample else ss / count


def stdev(values: Iterable[Any]) -> Optional[float]:
    """Sample standard deviation (n-1 denominator).

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        Square root of the sample variance, or ``None`` when fewer than two
        usable values exist (a single observation has no spread).

    Example:
        >>> round(stdev([1, 2, 3, 4, 5]), 6)
        1.581139
    """
    var = variance(values, sample=True)
    return math.sqrt(var) if var is not None else None


def pstdev(values: Iterable[Any]) -> Optional[float]:
    """Population standard deviation (n denominator).

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        Square root of the population variance, or ``None`` for empty input.
        A single observation returns ``0.0`` (population spread of one point).

    Example:
        >>> round(pstdev([1, 2, 3, 4, 5]), 6)
        1.414214
    """
    var = variance(values, sample=False)
    return math.sqrt(var) if var is not None else None


def coefficient_of_variation(values: Iterable[Any]) -> Optional[float]:
    """Relative dispersion: sample standard deviation over the mean.

    The CV (a.k.a. RSD) makes spread comparable across series with different
    units or magnitudes - "latency varies by 30%" travels between reports in
    a way an absolute milliseconds figure cannot.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        ``stdev / mean`` as an unsigned ratio (percentage = x100), or ``None``
        when fewer than two usable values exist or the mean is near zero
        (``|mean| < 1e-12``) - a division that would explode otherwise.

    Example:
        >>> coefficient_of_variation([10, 20, 30])
        0.5
        >>> coefficient_of_variation([5, 5, 5])
        0.0
        >>> coefficient_of_variation([1e-13, -1e-13]) is None
        True
    """
    cleaned = _clean_values(values)
    if len(cleaned) < 2:
        return None
    avg = sum(cleaned) / len(cleaned)
    if abs(avg) < _ZERO_TOL:
        return None
    var = variance(cleaned, sample=True)
    if var is None:
        return None
    return math.sqrt(var) / abs(avg)


# ---------------------------------------------------------------------------
# Quantiles
# ---------------------------------------------------------------------------

def percentile(values: Iterable[Any], q: float) -> Optional[float]:
    """Percentile via linear interpolation between closest ranks.

    Implements the ``'linear'`` method used by ``numpy.percentile``: the sorted
    data is treated as a piecewise-linear function and evaluated at
    ``q / 100 * (n - 1)``. ``q=0`` is the minimum, ``q=100`` the maximum,
    ``q=50`` the median (identical to :func:`median`).

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        q: Percentile rank in ``[0, 100]``. Values outside that range, or
            non-numeric input, return ``None``.

    Returns:
        The interpolated percentile as a float, or ``None`` for empty data or
        an invalid ``q``.

    Example:
        >>> percentile([1, 2, 3, 4], 25)
        1.75
        >>> percentile([1, 2, 3, 4], 0)
        1.0
    """
    rank = _to_float(q)
    if rank is None or rank < 0.0 or rank > 100.0:
        return None
    cleaned = sorted(_clean_values(values))
    if not cleaned:
        return None
    if len(cleaned) == 1:
        return cleaned[0]
    position = (rank / 100.0) * (len(cleaned) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return cleaned[lower]
    fraction = position - lower
    return cleaned[lower] + fraction * (cleaned[upper] - cleaned[lower])


def quartiles(values: Iterable[Any]) -> Optional[Tuple[float, float, float]]:
    """The three quartiles Q1 / Q2 / Q3 (25th / 50th / 75th percentile).

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        Tuple ``(q1, q2, q3)`` computed with the same linear interpolation as
        :func:`percentile`, or ``None`` for empty input.

    Example:
        >>> quartiles([1, 2, 3, 4])
        (1.75, 2.5, 3.25)
    """
    cleaned = _clean_values(values)
    if not cleaned:
        return None
    q1 = percentile(cleaned, 25.0)
    q2 = percentile(cleaned, 50.0)
    q3 = percentile(cleaned, 75.0)
    if q1 is None or q2 is None or q3 is None:  # pragma: no cover - defensive
        return None
    return (q1, q2, q3)


def iqr(values: Iterable[Any]) -> Optional[float]:
    """Interquartile range: ``Q3 - Q1``.

    The IQR is the workhorse of robust spread estimation: it ignores the
    tails entirely, which is exactly where contaminated OSINT measurements
    (one source timing out, one bogus coordinate) live.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        ``Q3 - Q1`` as a float, or ``None`` for empty input.

    Example:
        >>> iqr([1, 2, 3, 4])
        1.5
    """
    quart = quartiles(values)
    if quart is None:
        return None
    return quart[2] - quart[0]


# ---------------------------------------------------------------------------
# Shape - skewness and kurtosis
# ---------------------------------------------------------------------------

def _central_moments(cleaned: List[float], order: int) -> Optional[float]:
    """Central moment ``m_k = mean((x - mean)^k)`` for k >= 2, or None."""
    count = len(cleaned)
    if count < 1:
        return None
    avg = sum(cleaned) / count
    return sum((x - avg) ** order for x in cleaned) / count


def skewness(values: Iterable[Any]) -> Optional[float]:
    """Bias-corrected sample skewness (Fisher-Pearson ``G1``).

    Skewness signs which tail is heavy: positive means unusually large
    values dominate (a few very slow responses), negative means unusually
    small ones. The biased plug-in ``g1 = m3 / m2^1.5`` underestimates in
    small samples, so the standard correction
    ``G1 = sqrt(n(n-1)) / (n-2) * g1`` is applied, matching
    ``scipy.stats.skew(x, bias=False)``.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        ``G1`` as a float, or ``None`` when ``n < 3`` (skewness undefined) or
        the variance is zero (constant data has no shape).

    Example:
        >>> round(skewness([2, 2, 2, 2, 9]), 6)
        2.236068
        >>> skewness([1, 2, 3, 4, 5])
        0.0
    """
    cleaned = _clean_values(values)
    count = len(cleaned)
    if count < 3:
        return None
    m2 = _central_moments(cleaned, 2)
    m3 = _central_moments(cleaned, 3)
    if m2 is None or m3 is None or m2 <= 0.0:
        return None
    g1 = m3 / (m2 ** 1.5)
    return math.sqrt(count * (count - 1)) / (count - 2) * g1


def kurtosis(values: Iterable[Any]) -> Optional[float]:
    """Bias-corrected excess kurtosis (``G2``, Fisher convention).

    Excess kurtosis is zero for a normal distribution: positive values mean
    heavy tails / peaked centre (bursty outliers), negative values mean flat,
    uniform-ish data. The biased ``g2 = m4 / m2^2 - 3`` is corrected with
    ``G2 = ((n + 1) * g2 + 6) * (n - 1) / ((n - 2) * (n - 3))``, matching
    ``scipy.stats.kurtosis(x, fisher=True, bias=False)``.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        ``G2`` as a float, or ``None`` when ``n < 4`` (the bias correction is
        undefined) or the variance is zero.

    Example:
        >>> round(kurtosis([2, 2, 2, 2, 9]), 6)
        5.0
        >>> round(kurtosis([1, 2, 3, 4, 5]), 6)
        -1.2
    """
    cleaned = _clean_values(values)
    count = len(cleaned)
    if count < 4:
        return None
    m2 = _central_moments(cleaned, 2)
    m4 = _central_moments(cleaned, 4)
    if m2 is None or m4 is None or m2 <= 0.0:
        return None
    g2 = m4 / (m2 ** 2) - 3.0
    return ((count + 1) * g2 + 6.0) * (count - 1) / ((count - 2) * (count - 3))


# ---------------------------------------------------------------------------
# Range and one-shot summary
# ---------------------------------------------------------------------------

def min_max_range(values: Iterable[Any]) -> Optional[Dict[str, float]]:
    """Minimum, maximum, range and midpoint of a numeric sequence.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        Dict with keys ``'min'``, ``'max'``, ``'range'`` (max - min) and
        ``'midpoint'`` ((min + max) / 2), or ``None`` for empty input.

    Example:
        >>> min_max_range([3, 1, 4, 1, 5])
        {'min': 1.0, 'max': 5.0, 'range': 4.0, 'midpoint': 3.0}
    """
    cleaned = _clean_values(values)
    if not cleaned:
        return None
    low = float(min(cleaned))
    high = float(max(cleaned))
    return {
        'min': low,
        'max': high,
        'range': high - low,
        'midpoint': (low + high) / 2.0,
    }


def summarize(values: Iterable[Any]) -> Dict[str, Optional[float]]:
    """One-shot descriptive summary: the numbers a report actually cites.

    Computes count, centre (mean/median), spread (sample stdev, min/max,
    quartiles, IQR) and shape (skewness, excess kurtosis) in a single sweep
    over the cleaned data, so a template can render one consistent block
    instead of ten slightly-different calls.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        Dict with keys ``'count'`` (float), ``'mean'``, ``'median'``,
        ``'stdev'``, ``'min'``, ``'max'``, ``'q1'``, ``'q3'``, ``'iqr'``,
        ``'skew'``, ``'kurt'``. Uncomputable fields are ``None`` (e.g.
        ``stdev`` for a single point, ``skew`` below three points); the dict
        itself is always returned - never None, never an exception.

    Example:
        >>> summary = summarize([2, 2, 2, 2, 9])
        >>> summary['count']
        5.0
        >>> summary['mean']
        3.4
    """
    cleaned = _clean_values(values)
    quart = quartiles(cleaned)
    q1 = quart[0] if quart else None
    q3 = quart[2] if quart else None
    return {
        'count': float(len(cleaned)) if cleaned else 0.0,
        'mean': mean(cleaned),
        'median': median(cleaned),
        'stdev': stdev(cleaned),
        'min': float(min(cleaned)) if cleaned else None,
        'max': float(max(cleaned)) if cleaned else None,
        'q1': q1,
        'q3': q3,
        'iqr': (q3 - q1) if (q1 is not None and q3 is not None) else None,
        'skew': skewness(cleaned),
        'kurt': kurtosis(cleaned),
    }


# ---------------------------------------------------------------------------
# Distribution shape helpers
# ---------------------------------------------------------------------------

def histogram(values: Iterable[Any], bins: int = 10) -> Dict[str, Any]:
    """Equal-width histogram of a numeric sequence.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.
        bins: Number of equal-width bins spanning ``[min, max]``. Values
            below 1 (or non-numeric) yield an empty-but-well-formed result.

    Returns:
        Dict with keys:

        * ``'bin_edges'`` - ``bins + 1`` ascending edges (floats).
        * ``'bin_counts'`` - ``bins`` integer counts; the final bin is
          closed on the right so the maximum always lands inside.
        * ``'bin_labels'`` - human-readable ``'[lo, hi)'`` labels, with the
          last label ``'[lo, hi]'``.

        For empty data (or invalid ``bins``) all three lists are empty.
        Degenerate all-equal data uses a synthetic span of ``[x, x + 1]`` so
        every observation lands in bin 0.

    Example:
        >>> histogram([1, 2, 3, 4, 5], bins=2)['bin_counts']
        [2, 3]
    """
    cleaned = _clean_values(values)
    try:
        bin_count = int(bins)
    except (TypeError, ValueError):
        bin_count = 0
    if bin_count < 1 or not cleaned:
        return {'bin_edges': [], 'bin_counts': [], 'bin_labels': []}

    low = float(min(cleaned))
    high = float(max(cleaned))
    if high == low:
        # Constant data: give it a synthetic unit span so bin 0 holds it all.
        high = low + 1.0
    width = (high - low) / bin_count

    counts = [0] * bin_count
    for value in cleaned:
        index = int((value - low) / width)
        # Guard both ends against float dust; value == high belongs to the
        # last (right-closed) bin.
        index = max(0, min(index, bin_count - 1))
        counts[index] += 1

    edges = [low + i * width for i in range(bin_count)] + [high]
    labels = []
    for i in range(bin_count):
        left = format(edges[i], _BOUND_FMT)
        right = format(edges[i + 1], _BOUND_FMT)
        closer = ']' if i == bin_count - 1 else ')'
        labels.append('[{}, {}{}'.format(left, right, closer))
    return {'bin_edges': edges, 'bin_counts': counts, 'bin_labels': labels}


def value_counts(values: Iterable[Any]) -> List[Dict[str, Any]]:
    """Frequency table of a numeric sequence, most common first.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        List of dicts ``{'value': float, 'count': int, 'percentage': float}``
        sorted by count descending, ties broken by value ascending.
        ``percentage`` is relative to the number of *usable* values (100 *
        count / total). Empty list for empty input.

    Example:
        >>> value_counts([1, 1, 2])[0]
        {'value': 1.0, 'count': 2, 'percentage': 66.66666666666667}
    """
    cleaned = _clean_values(values)
    if not cleaned:
        return []
    total = len(cleaned)
    counts = Counter(cleaned)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [
        {
            'value': float(value),
            'count': count,
            'percentage': 100.0 * count / total,
        }
        for value, count in ordered
    ]


def shannon_entropy(values: Iterable[Any]) -> Optional[float]:
    """Shannon entropy of the symbol distribution of a numeric sequence.

    Each distinct numeric value is treated as one symbol; the entropy of the
    resulting categorical distribution is ``H = -sum(p * log2(p))`` in bits.
    This measures *diversity* of the evidence, not of any ordering: a stream
    of 20 different usernames has far higher entropy than 20 repeats of one,
    which is often the difference between a bot and a person.

    Args:
        values: Any iterable; non-numeric and non-finite items are dropped.

    Returns:
        Entropy in bits (0.0 <= H <= log2(k) for k distinct values), or
        ``None`` for empty input. Constant sequences return ``0.0``.

    Example:
        >>> round(shannon_entropy([1, 1, 2]), 6)
        0.918296
        >>> shannon_entropy([7, 7, 7])
        0.0
    """
    cleaned = _clean_values(values)
    if not cleaned:
        return None
    total = len(cleaned)
    entropy = 0.0
    for count in Counter(cleaned).values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


# ---------------------------------------------------------------------------
# Standardisation helpers
# ---------------------------------------------------------------------------

def zscore(value: Any, values: Iterable[Any]) -> Optional[float]:
    """Classic z-score of ``value`` against a reference sample.

    Args:
        value: The observation to score; non-numeric input returns None.
        values: Reference sample; non-numeric and non-finite items dropped.

    Returns:
        ``(value - mean) / sample_stdev``, or ``None`` when the reference has
        fewer than two usable values, its standard deviation is zero (every
        z-score would be 0/0), or ``value`` is not a finite number.

    Example:
        >>> round(zscore(5, [1, 2, 3, 4, 5]), 6)
        1.264911
    """
    target = _to_float(value)
    if target is None:
        return None
    cleaned = _clean_values(values)
    if len(cleaned) < 2:
        return None
    avg = sum(cleaned) / len(cleaned)
    var = variance(cleaned, sample=True)
    if var is None or var <= 0.0:
        return None
    return (target - avg) / math.sqrt(var)


def robust_zscore(value: Any, values: Iterable[Any]) -> Optional[float]:
    """Outlier-resistant z-score based on median and MAD.

    Uses the standard normal-consistent scaling
    ``0.6745 * (value - median) / MAD`` where MAD is the median absolute
    deviation. Unlike :func:`zscore` a single extreme observation cannot
    inflate the scale, which is why the anomaly detectors in this package
    prefer it.

    Args:
        value: The observation to score; non-numeric input returns None.
        values: Reference sample; non-numeric and non-finite items dropped.

    Returns:
        The robust z-score, or ``None`` when no usable reference values
        exist, the MAD is zero (more than half the values identical - the
        ratio is undefined), or ``value`` is not finite.

    Example:
        >>> round(robust_zscore(10, [1, 2, 3, 4, 5]), 4)
        4.7215
        >>> robust_zscore(9, [2, 2, 2, 2, 9]) is None
        True
    """
    target = _to_float(value)
    if target is None:
        return None
    cleaned = _clean_values(values)
    if not cleaned:
        return None
    middle = median(cleaned)
    if middle is None:  # pragma: no cover - defensive
        return None
    deviations = [abs(x - middle) for x in cleaned]
    mad = median(deviations)
    if mad is None or mad <= 0.0:
        return None
    return 0.6745 * (target - middle) / mad
