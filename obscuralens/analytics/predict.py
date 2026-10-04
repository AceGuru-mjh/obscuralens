"""
Prediction models on the standard library alone (v6.0 Part 2).

Sometimes the evidence is a table: latency versus retry count, days since
first sighting versus account age, risk score versus breach count. This
module fits simple models to such tables with hand-rolled gradient
descent - linear regression, logistic classification, an index-based
trend extrapolation and binary-classification scoring - using nothing but
``math``, so the analytics stack stays installable anywhere the CLI runs.

Honesty notes baked into the design:

* **These are screening tools, not prophecies.** :func:`simple_forecast`
  literally says so in its return value (``'confidence': 'low'``); a
  least-squares line through a handful of OSINT observations is a
  headline for an analyst to verify, never a decision.
* **Sample-size floors.** Fewer than five rows, ragged feature vectors
  or mismatched targets return ``None`` - an under-determined model is
  silence, not noise.
* **Standardised inside, raw outside.** Optimisation runs on z-scored
  features (so gradient descent converges regardless of unit scale) but
  the fitted weights are un-scaled back to raw feature units, so
  :func:`predict_linear` / :func:`predict_logistic` take features exactly
  as collected.

Design contract (mirrored across the analytics package): defensive input
handling everywhere, safe ``None`` / empty results for unusable input,
pure functions, no I/O.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    'LinearModel',
    'classify',
    'evaluate_binary',
    'fit_linear',
    'fit_logistic',
    'predict_linear',
    'predict_logistic',
    'simple_forecast',
]

#: Minimum number of training rows any fitter will accept.
_MIN_SAMPLES = 5

#: Default gradient-descent hyperparameters (linear / logistic).
_DEFAULT_RATE_LINEAR = 0.01
_DEFAULT_RATE_LOGISTIC = 0.1
_DEFAULT_ITERATIONS_LINEAR = 500
_DEFAULT_ITERATIONS_LOGISTIC = 1000

#: Convergence tolerance on loss improvement between iterations.
_CONVERGENCE_TOL = 1e-8

#: Slopes flatter than this are "flat" for trend verdicts.
_FLAT_EPSILON = 1e-12

#: Probability clamp for the cross-entropy loss (keeps log() finite).
_PROB_CLAMP = 1e-12


@dataclass
class LinearModel:
    """A fitted linear model (regression or logistic).

    Attributes:
        weights: One coefficient per raw input feature (the model is
            ``bias + sum(weight * feature)``); logistic models carry the
            same shape and are squashed through a sigmoid at prediction
            time.
        bias: The constant term, in raw target units for regression.
        iterations: Gradient-descent iterations actually executed
            (bounded by the caller's budget; may stop early on
            convergence).
        r_squared: Coefficient of determination for regression fits; for
            logistic fits this field carries the training accuracy
            instead (documented per-function).
        loss_history: Optimisation loss after each executed iteration -
            mean squared error (standardised space) for regression,
            mean cross-entropy for logistic. Useful for convergence
            diagnostics in a report.
    """

    weights: List[float]
    bias: float = 0.0
    iterations: int = 0
    r_squared: float = 0.0
    loss_history: List[float] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Input cleaning
# ---------------------------------------------------------------------------

def _to_float(item: Any) -> Optional[float]:
    """Coerce one item to a finite float, or None when impossible.

    ``bool`` is rejected even though it subclasses ``int``: ``True`` is a
    flag, not a measurement.
    """
    if isinstance(item, bool) or not isinstance(item, (int, float)):
        return None
    number = float(item)
    return number if math.isfinite(number) else None


def _clean_matrix(features: Any, targets: Any) -> Optional[Tuple[List[List[float]], List[float]]]:
    """Strictly coerce a feature matrix plus target vector.

    Every row must be a tuple/list of finite numbers; every row must share
    the same dimension (at least one); targets must be finite numbers of
    the same count as rows. One bad row invalidates the whole set - a
    ragged matrix has no honest model - so the caller reports ``None``
    rather than silently training on a subset.
    """
    if not isinstance(features, (list, tuple)) or not isinstance(targets, (list, tuple)):
        return None
    rows: List[List[float]] = []
    dimension: Optional[int] = None
    for row in features:
        if isinstance(row, (str, bytes)) or not isinstance(row, (list, tuple)):
            return None
        values: List[float] = []
        for item in row:
            number = _to_float(item)
            if number is None:
                return None
            values.append(number)
        if not values:
            return None
        if dimension is None:
            dimension = len(values)
        elif len(values) != dimension:
            return None
        rows.append(values)
    labels: List[float] = []
    for item in targets:
        number = _to_float(item)
        if number is None:
            return None
        labels.append(number)
    if len(rows) != len(labels):
        return None
    return rows, labels


def _as_float(value: Any, default: float) -> float:
    """Finite-float coercion with a fallback (never raises)."""
    number = _to_float(value)
    return default if number is None else number


def _as_int(value: Any, default: int) -> int:
    """Best-effort integer coercion with a fallback (never raises)."""
    number = _to_float(value)
    return default if number is None else int(number)


def _standardize(rows: List[List[float]]) -> Tuple[List[List[float]], List[float], List[float]]:
    """Z-score every feature column; zero-spread columns stay zero.

    Returns ``(scaled_rows, means, stds)`` where ``stds[j]`` is 0.0 for a
    constant column - the scaled column is then all zeros and the caller
    must treat the raw weight as 0 (no variance, no signal).
    """
    count = len(rows)
    dimension = len(rows[0])
    means: List[float] = []
    stds: List[float] = []
    for column in range(dimension):
        total = sum(row[column] for row in rows)
        mean = total / count
        variance = sum((row[column] - mean) ** 2 for row in rows) / count
        stds.append(math.sqrt(variance))
        means.append(mean)
    scaled: List[List[float]] = []
    for row in rows:
        scaled.append([(row[column] - means[column]) / stds[column]
                       if stds[column] > 0.0 else 0.0
                       for column in range(dimension)])
    return scaled, means, stds


def _dot(weights: Sequence[float], features: Sequence[float]) -> Optional[float]:
    """Dot product of equal-length numeric sequences (None on mismatch)."""
    if len(weights) != len(features):
        return None
    total = 0.0
    for weight, value in zip(weights, features):
        number = _to_float(value)
        if number is None:
            return None
        total += weight * number
    return total


# ---------------------------------------------------------------------------
# Linear regression
# ---------------------------------------------------------------------------

def fit_linear(features: Any, targets: Any, learning_rate: float = 0.01,
               iterations: int = 500) -> Optional[LinearModel]:
    """Fit ordinary linear regression by batch gradient descent.

    Features and targets are z-scored internally (standardised-space
    gradient descent converges regardless of whether one feature is
    "milliseconds" and another "years"); the resulting weights are then
    un-scaled back to **raw feature units**, so the returned model
    predicts directly from features as collected. The loss history
    records standardised-space mean squared error after each iteration.

    Convergence: the loop stops early once the loss improvement between
    iterations drops below ``1e-8``.

    Args:
        features: Training rows - a list/tuple of equal-length
            lists/tuples of finite numbers. Ragged, non-numeric or
            mismatched input returns ``None``.
        targets: One finite number per row, same count as rows.
        learning_rate: Step size (default 0.01; non-finite or
            non-positive values fall back to the default).
        iterations: Maximum descent steps (default 500; values below 1
            become 1).

    Returns:
        A fitted :class:`LinearModel` with raw-unit weights, or ``None``
        when fewer than 5 usable rows exist or the input is malformed.
        Never raises.

    Example:
        >>> model = fit_linear([[1.0], [2.0], [3.0], [4.0], [5.0]],
        ...                     [2.0, 4.0, 6.0, 8.0, 10.0],
        ...                     learning_rate=0.1, iterations=2000)
        >>> round(model.weights[0], 3), round(model.r_squared, 4)
        (2.0, 1.0)
        >>> round(predict_linear(model, [10.0]), 2)
        20.0

        With the default hyperparameters the same fit converges more
        loosely (batch descent at rate 0.01 walks ~2% per step), which is
        fine for screening-grade regression.
    """
    cleaned = _clean_matrix(features, targets)
    if cleaned is None:
        return None
    rows, labels = cleaned
    if len(rows) < _MIN_SAMPLES:
        return None

    rate = _as_float(learning_rate, _DEFAULT_RATE_LINEAR)
    if rate <= 0.0:
        rate = _DEFAULT_RATE_LINEAR
    budget = max(1, _as_int(iterations, _DEFAULT_ITERATIONS_LINEAR))

    scaled, _means, _stds = _standardize(rows)
    label_mean = sum(labels) / len(labels)
    label_variance = sum((value - label_mean) ** 2 for value in labels) / len(labels)
    label_std = math.sqrt(label_variance)
    scaled_labels = [((value - label_mean) / label_std) if label_std > 0.0 else 0.0
                     for value in labels]

    dimension = len(rows[0])
    count = len(rows)
    weights = [0.0] * dimension
    bias = 0.0
    loss_history: List[float] = []
    previous_loss: Optional[float] = None
    executed = 0

    for _step in range(budget):
        executed += 1
        gradient_w = [0.0] * dimension
        gradient_b = 0.0
        loss = 0.0
        for row, target in zip(scaled, scaled_labels):
            error = bias
            for column in range(dimension):
                error += weights[column] * row[column]
            error -= target
            loss += error * error
            gradient_b += error
            for column in range(dimension):
                gradient_w[column] += error * row[column]
        loss /= count
        gradient_b /= count
        gradient_w = [value / count for value in gradient_w]
        bias -= rate * gradient_b
        weights = [weights[column] - rate * gradient_w[column]
                   for column in range(dimension)]
        loss_history.append(loss)
        if previous_loss is not None and abs(previous_loss - loss) < _CONVERGENCE_TOL:
            break
        previous_loss = loss

    raw_weights = _unscale_weights(weights, _stds, label_std)
    raw_bias = _unscale_bias(bias, raw_weights, _means, label_mean, label_std)
    r_squared = _r_squared(rows, labels, raw_weights, raw_bias)
    return LinearModel(
        weights=raw_weights,
        bias=raw_bias,
        iterations=executed,
        r_squared=r_squared,
        loss_history=loss_history,
    )


def _unscale_weights(weights: Sequence[float], stds: Sequence[float],
                     label_std: float) -> List[float]:
    """Convert standardised-space weights to raw feature units.

    A zero-spread column carried no signal in the standardised space (its
    scaled values were all zero, so its weight stayed ~0); its raw weight
    is pinned to exactly 0.0 to avoid a division by the zero std.
    """
    raw: List[float] = []
    for weight, std in zip(weights, stds):
        raw.append((label_std * weight / std) if std > 0.0 else 0.0)
    return raw


def _unscale_bias(bias: float, raw_weights: Sequence[float], means: Sequence[float],
                  label_mean: float, label_std: float) -> float:
    """Convert the standardised-space intercept to raw units."""
    shift = sum(weight * mean for weight, mean in zip(raw_weights, means))
    return label_std * bias + label_mean - shift


def _r_squared(rows: List[List[float]], labels: List[float],
               weights: Sequence[float], bias: float) -> float:
    """Coefficient of determination of a raw-unit model on its training data.

    A constant target (``ss_tot == 0``) is perfectly described by the
    fitted constant, so the convention here - matching the timeseries
    module's trend fit - is 1.0.
    """
    label_mean = sum(labels) / len(labels)
    ss_res = 0.0
    ss_tot = 0.0
    for row, target in zip(rows, labels):
        prediction = bias
        for weight, value in zip(weights, row):
            prediction += weight * value
        ss_res += (target - prediction) ** 2
        ss_tot += (target - label_mean) ** 2
    if ss_tot <= 0.0:
        return 1.0
    return 1.0 - ss_res / ss_tot


def predict_linear(model: Any, features: Any) -> Optional[float]:
    """Predict with a fitted regression model.

    Args:
        model: A :class:`LinearModel` (anything else yields ``None``).
        features: One feature row - a list/tuple of finite numbers whose
            length matches the model's weights.

    Returns:
        ``bias + dot(weights, features)``, or ``None`` when the model or
        row is malformed. Never raises.

    Example:
        >>> model = LinearModel(weights=[2.0], bias=1.0)
        >>> predict_linear(model, [3.0])
        7.0
    """
    if not isinstance(model, LinearModel) or not isinstance(features, (list, tuple)):
        return None
    total = _dot(model.weights, features)
    if total is None:
        return None
    return total + model.bias


# ---------------------------------------------------------------------------
# Logistic classification
# ---------------------------------------------------------------------------

def _sigmoid(value: float) -> float:
    """Numerically stable logistic function (never overflows, returns [0, 1])."""
    if value >= 0.0:
        return 1.0 / (1.0 + math.exp(-value))
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


def _clean_labels(targets: List[float]) -> Optional[List[int]]:
    """Coerce cleaned numeric targets to 0/1 ints (None unless every row is 0 or 1)."""
    labels: List[int] = []
    for value in targets:
        if value in (0.0, 1.0):
            labels.append(int(value))
        else:
            return None
    return labels


def fit_logistic(features: Any, targets: Any, learning_rate: float = 0.1,
                 iterations: int = 1000) -> Optional[LinearModel]:
    """Fit binary logistic regression by batch gradient descent.

    Features are z-scored internally and the weights un-scaled back to
    raw feature units afterwards (same contract as :func:`fit_linear`);
    targets stay in their raw ``{0, 1}`` space because the cross-entropy
    loss is defined on probabilities of those labels. The optimisation
    minimises mean binary cross-entropy
    ``-mean(y*log(p) + (1-y)*log(1-p))`` with probabilities clamped away
    from 0 and 1.

    Args:
        features: Training rows (see :func:`fit_linear` for the shape
            contract).
        targets: One value per row, every value exactly ``0`` or ``1``
            (floats ``0.0`` / ``1.0`` accepted); anything else returns
            ``None``.
        learning_rate: Step size (default 0.1; non-finite or
            non-positive values fall back to the default).
        iterations: Maximum descent steps (default 1000; values below 1
            become 1).

    Returns:
        A :class:`LinearModel` whose ``r_squared`` field carries the
        **training accuracy** (share of rows classified correctly at the
        0.5 threshold) and whose ``loss_history`` records mean
        cross-entropy per executed iteration; ``None`` for fewer than 5
        rows or malformed input. Never raises.

    Example:
        >>> model = fit_logistic([[0.0], [1.0], [2.0], [3.0], [4.0]],
        ...                      [0, 0, 0, 1, 1])
        >>> predict_logistic(model, [0.0]) < 0.5 < predict_logistic(model, [4.0])
        True
    """
    cleaned = _clean_matrix(features, targets)
    if cleaned is None:
        return None
    rows, raw_labels = cleaned
    if len(rows) < _MIN_SAMPLES:
        return None
    labels = _clean_labels(raw_labels)
    if labels is None:
        return None

    rate = _as_float(learning_rate, _DEFAULT_RATE_LOGISTIC)
    if rate <= 0.0:
        rate = _DEFAULT_RATE_LOGISTIC
    budget = max(1, _as_int(iterations, _DEFAULT_ITERATIONS_LOGISTIC))

    scaled, means, stds = _standardize(rows)
    dimension = len(rows[0])
    count = len(rows)
    weights = [0.0] * dimension
    bias = 0.0
    loss_history: List[float] = []
    correct = 0
    previous_loss: Optional[float] = None
    executed = 0

    for _step in range(budget):
        executed += 1
        gradient_w = [0.0] * dimension
        gradient_b = 0.0
        loss = 0.0
        correct = 0
        for row, label in zip(scaled, labels):
            score = bias
            for column in range(dimension):
                score += weights[column] * row[column]
            probability = _sigmoid(score)
            if (probability >= 0.5) == (label == 1):
                correct += 1
            clamped = min(max(probability, _PROB_CLAMP), 1.0 - _PROB_CLAMP)
            loss += -(label * math.log(clamped)
                      + (1 - label) * math.log(1.0 - clamped))
            error = probability - label
            gradient_b += error
            for column in range(dimension):
                gradient_w[column] += error * row[column]
        loss /= count
        gradient_b /= count
        gradient_w = [value / count for value in gradient_w]
        bias -= rate * gradient_b
        weights = [weights[column] - rate * gradient_w[column]
                   for column in range(dimension)]
        loss_history.append(loss)
        if previous_loss is not None and abs(previous_loss - loss) < _CONVERGENCE_TOL:
            break
        previous_loss = loss

    raw_weights = _unscale_weights(weights, stds, 1.0)
    raw_bias = _unscale_bias(bias, raw_weights, means, 0.0, 1.0)
    accuracy = correct / count if count else 0.0
    return LinearModel(
        weights=raw_weights,
        bias=raw_bias,
        iterations=executed,
        r_squared=accuracy,
        loss_history=loss_history,
    )


def predict_logistic(model: Any, features: Any) -> Optional[float]:
    """Predict the positive-class probability with a fitted logistic model.

    Args:
        model: A :class:`LinearModel` fitted by :func:`fit_logistic`
            (anything else yields ``None``).
        features: One feature row - a list/tuple of finite numbers whose
            length matches the model's weights.

    Returns:
        ``sigmoid(bias + dot(weights, features))`` in ``[0, 1]``, or
        ``None`` when the model or row is malformed. Never raises.

    Example:
        >>> model = LinearModel(weights=[1.0], bias=0.0)
        >>> round(predict_logistic(model, [0.0]), 4)
        0.5
    """
    if not isinstance(model, LinearModel) or not isinstance(features, (list, tuple)):
        return None
    total = _dot(model.weights, features)
    if total is None:
        return None
    return _sigmoid(total + model.bias)


def classify(model: Any, features: Any, threshold: float = 0.5) -> Optional[int]:
    """Threshold a logistic probability into a hard class label.

    Args:
        model: A fitted :class:`LinearModel` (logistic or otherwise -
            any model :func:`predict_logistic` accepts).
        features: One feature row matching the model's weights.
        threshold: Decision boundary in ``[0, 1]`` (default 0.5;
            non-finite or out-of-range values fall back to 0.5).

    Returns:
        ``1`` when the predicted probability is at least the threshold,
        else ``0``; ``None`` when the model or row is malformed. Never
        raises.

    Example:
        >>> model = LinearModel(weights=[10.0], bias=0.0)
        >>> classify(model, [0.3])
        1
    """
    probability = predict_logistic(model, features)
    if probability is None:
        return None
    boundary = _as_float(threshold, 0.5)
    if boundary < 0.0 or boundary > 1.0:
        boundary = 0.5
    return 1 if probability >= boundary else 0


# ---------------------------------------------------------------------------
# Trend extrapolation and evaluation
# ---------------------------------------------------------------------------

def simple_forecast(values: Any, horizon: int = 3) -> Dict[str, Any]:
    """Least-squares line through a value sequence, extrapolated forward.

    Fits ``value = slope * index + intercept`` over the sequence in list
    order (index 0, 1, 2, ...) with the closed-form least-squares
    solution and evaluates it at the next ``horizon`` indices. This is
    **an extrapolation, not a prophecy**: it assumes the series keeps its
    linear drift, knows nothing about seasons, ceilings or regime
    changes, and says so by always reporting ``'confidence': 'low'``.
    Treat the numbers as a "if nothing changes" headline to verify.

    Args:
        values: Sequence of numbers (non-numeric and non-finite items are
            dropped, matching the stats module's cleaning policy).
        horizon: How many future values to extrapolate (default 3;
            values below 0 yield an empty forecast list).

    Returns:
        Dict with ``'forecasts'`` (list of extrapolated values),
        ``'slope'`` and ``'intercept'`` (per-index-step change and
        baseline), ``'trend'`` (``'rising'`` / ``'falling'`` / ``'flat'``,
        or ``'unknown'`` when no fit was possible), ``'confidence'``
        (always ``'low'``) and ``'n'`` (values used). Fewer than two
        usable values yield empty forecasts with ``'unknown'`` trend.
        Never raises.

    Example:
        >>> report = simple_forecast([1.0, 2.0, 3.0, 4.0], horizon=2)
        >>> report['forecasts'], report['trend']
        ([5.0, 6.0], 'rising')
    """
    cleaned: List[float] = []
    if isinstance(values, (list, tuple)):
        for item in values:
            number = _to_float(item)
            if number is not None:
                cleaned.append(number)

    steps = _as_int(horizon, 3)
    if steps < 0:
        steps = 0
    if len(cleaned) < 2:
        return {'forecasts': [], 'slope': None, 'intercept': None,
                'trend': 'unknown', 'confidence': 'low', 'n': len(cleaned)}

    count = len(cleaned)
    x_mean = (count - 1) / 2.0
    y_mean = sum(cleaned) / count
    sxx = sum((index - x_mean) ** 2 for index in range(count))
    sxy = sum((index - x_mean) * (value - y_mean)
              for index, value in enumerate(cleaned))
    slope = sxy / sxx if sxx > 0.0 else 0.0
    intercept = y_mean - slope * x_mean
    forecasts = [intercept + slope * (count + step) for step in range(steps)]
    if slope > _FLAT_EPSILON:
        trend = 'rising'
    elif slope < -_FLAT_EPSILON:
        trend = 'falling'
    else:
        trend = 'flat'
    return {
        'forecasts': [round(value, 6) for value in forecasts],
        'slope': round(slope, 9),
        'intercept': round(intercept, 6),
        'trend': trend,
        'confidence': 'low',
        'n': count,
    }


def evaluate_binary(predictions: Any, actuals: Any) -> Dict[str, Any]:
    """Score binary classifications: accuracy, precision, recall, F1.

    Args:
        predictions: Sequence of predicted labels (0/1; ``True``/``False``
            and ``0.0``/``1.0`` accepted).
        actuals: Sequence of ground-truth labels, same conventions. Rows
            where either side is not a clean binary value - or where the
            two sequences disagree in length - are skipped; a mismatched
            pair is a data bug, not a verdict.

    Returns:
        Dict with ``'accuracy'``, ``'precision'``, ``'recall'``,
        ``'f1'`` (all 0.0 when their denominators are zero - an honest
        "could not compute" for empty predictions) plus the confusion
        counts ``'tp'``, ``'fp'``, ``'tn'``, ``'fn'`` and ``'n'`` pairs
        scored. Never raises.

    Example:
        >>> report = evaluate_binary([1, 1, 0, 0], [1, 0, 0, 0])
        >>> report['accuracy'], report['precision'], report['recall']
        (0.75, 0.5, 1.0)
    """
    def _as_label(item: Any) -> Optional[int]:
        if isinstance(item, bool):
            return int(item)
        number = _to_float(item)
        if number is None:
            return None
        if number in (0.0, 1.0):
            return int(number)
        return None

    pairs: List[Tuple[int, int]] = []
    if isinstance(predictions, (list, tuple)) and isinstance(actuals, (list, tuple)):
        for predicted, actual in zip(predictions, actuals):
            label_p = _as_label(predicted)
            label_a = _as_label(actual)
            if label_p is not None and label_a is not None:
                pairs.append((label_p, label_a))

    tp = sum(1 for predicted, actual in pairs if predicted == 1 and actual == 1)
    fp = sum(1 for predicted, actual in pairs if predicted == 1 and actual == 0)
    tn = sum(1 for predicted, actual in pairs if predicted == 0 and actual == 0)
    fn = sum(1 for predicted, actual in pairs if predicted == 0 and actual == 1)
    scored = len(pairs)
    accuracy = (tp + tn) / scored if scored else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn,
        'n': scored,
    }
