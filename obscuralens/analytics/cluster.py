"""
Unsupervised clustering for evidence grouping (v6.0 Part 2).

Clustering answers the question every bulk OSINT run ends with: "these 4,000
rows of IP latencies / coordinates / risk vectors - how many *kinds* of
thing am I actually looking at?" Three algorithms cover the practical space:

* :func:`dbscan` - density clustering that finds arbitrary-shaped groups and
  explicitly labels the leftovers as noise (-1). The default choice for
  investigation data, because "this point belongs to nothing" is exactly the
  finding an analyst wants surfaced rather than hidden.
* :func:`kmeans` - the classic partitioner with k-means++ seeding. Fast,
  spherical clusters, needs ``k`` up front.
* :func:`hierarchical` - agglomerative single-link merging with a distance
  cutoff, for when "clusters joined at distance d" is the natural reading.

Everything operates on plain ``List[Sequence[float]]`` vectors - no numpy, no
pandas, no framework objects - and returns the shared :class:`ClusterResult`
envelope, so downstream code (labels in a report, colours on a map) learns
one shape.

Design contract:

* **Defensive by default.** Empty input, ``k`` out of range, inconsistent
  dimensions, non-numeric coordinates, ``None`` anywhere: the result is an
  empty-but-valid :class:`ClusterResult`, never an exception. Dimension
  consistency is enforced strictly - one 3-D row in a 2-D set invalidates
  the whole input rather than silently corrupting distances.
* **Determinism where it matters.** :func:`kmeans` takes an explicit
  ``seed`` (``random.Random``), so the same evidence always yields the same
  partition - repeatable reports are a requirement, not a nicety.
* **Noise is a first-class label.** DBSCAN assigns ``-1``; ``noise_count``
  carries the tally; :func:`silhouette_score` and :func:`cluster_summary`
  both skip or report it rather than pretending it is a cluster.
* **Honest complexity.** Pairwise-distance algorithms are O(n^2) or worse;
  they are intended for the hundreds-to-low-thousands scale of an
  investigation batch, not a data warehouse.
"""

import math
import random
from collections import deque
from dataclasses import dataclass
from statistics import median
from typing import Any, Dict, List, Optional, Sequence

__all__ = [
    'ClusterResult',
    'cluster_summary',
    'dbscan',
    'hierarchical',
    'kmeans',
    'normalize_points',
    'optimal_eps',
    'silhouette_score',
]

#: Label reserved for "no cluster" in :attr:`ClusterResult.assignments`.
NOISE_LABEL = -1

#: Fallback k-nearest rank for :func:`optimal_eps` when k is unusable.
_DEFAULT_KNN = 4

#: Multiplier applied to the median k-distance in :func:`optimal_eps`.
_KDIST_SCALE = 1.5


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ClusterResult:
    """The shared result envelope for every clustering algorithm.

    Attributes:
        assignments: One label per input point, in input order. ``-1`` means
            noise / unassigned (DBSCAN); otherwise labels are contiguous
            cluster ids starting at 0.
        centroids: Per-cluster mean vector, index-aligned with cluster ids
            (empty for a noise-only or empty result).
        sizes: Points per cluster, index-aligned with cluster ids.
        noise_count: How many points carry the noise label.
        method: Algorithm name (``'dbscan'`` / ``'kmeans'`` / ``'hierarchical'``).
    """

    assignments: List[int]
    centroids: List[List[float]]
    sizes: List[int]
    noise_count: int
    method: str


def _empty_result(method: str) -> ClusterResult:
    """The safe return for invalid/empty input: a valid, empty result."""
    return ClusterResult([], [], [], 0, method)


# ---------------------------------------------------------------------------
# Input coercion and distance
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


def _safe_int(item: Any, default: int) -> int:
    """Best-effort integer coercion with a fallback (never raises)."""
    number = _to_float(item)
    if number is None:
        return default
    return int(number)


def _as_points(points: Any) -> Optional[List[List[float]]]:
    """Strictly coerce input into float vectors, or None when impossible.

    Every row must be a tuple/list of finite numbers, and every row must
    share the same dimension. Clustering distances are meaningless with
    ragged or non-numeric vectors, so - unlike the stats module's drop-the-
    bad-item policy - one bad row invalidates the whole set and the caller
    reports an empty result. An empty input list coerces to ``[]`` (a valid,
    empty point set).
    """
    if points is None:
        return None
    try:
        iterator = iter(points)
    except TypeError:
        return None
    rows: List[List[float]] = []
    dimension: Optional[int] = None
    for item in iterator:
        if isinstance(item, (str, bytes)) or not isinstance(item, (list, tuple)):
            return None
        row: List[float] = []
        for coordinate in item:
            number = _to_float(coordinate)
            if number is None:
                return None
            row.append(number)
        if not row:
            return None
        if dimension is None:
            dimension = len(row)
        elif len(row) != dimension:
            return None
        rows.append(row)
    return rows


def _distance(a: Sequence[float], b: Sequence[float]) -> float:
    """Euclidean distance between two equal-length float vectors."""
    total = 0.0
    for x, y in zip(a, b):
        diff = x - y
        total += diff * diff
    return math.sqrt(total)


def _centroids_from(points: List[List[float]], labels: List[int]) -> List[List[float]]:
    """Mean vector per cluster id (0..max label), in id order."""
    cluster_count = max(labels) + 1 if labels else 0
    if cluster_count <= 0:
        return []
    dimension = len(points[0])
    sums = [[0.0] * dimension for _ in range(cluster_count)]
    counts = [0] * cluster_count
    for point, label in zip(points, labels):
        if 0 <= label < cluster_count:
            counts[label] += 1
            for d in range(dimension):
                sums[label][d] += point[d]
    return [
        [value / counts[cid] for value in sums[cid]] if counts[cid] else []
        for cid in range(cluster_count)
    ]


# ---------------------------------------------------------------------------
# DBSCAN - density-based clustering with true reachability expansion
# ---------------------------------------------------------------------------

def dbscan(points: List[Sequence[float]], eps: float = 0.5, min_samples: int = 3) -> ClusterResult:
    """DBSCAN: density clusters of arbitrary shape plus explicit noise.

    A point is a **core** point when at least ``min_samples`` points (itself
    included) sit within ``eps``. Clusters grow by true density-reachability:
    a work queue starts from an unvisited core point, every freshly labelled
    core point enqueues its own neighbourhood, and points previously written
    off as noise can be adopted later as border points of a cluster that
    reaches them. That queue expansion - not a single-link shortcut over
    pairwise distances - is what makes chains of densely connected points
    one cluster while genuinely isolated points stay noise.

    Args:
        points: List of coordinate tuples/lists (all same dimension, all
            numeric). Invalid input yields an empty result.
        eps: Neighbourhood radius (Euclidean). Non-finite values fall back
            to 0.5. ``eps <= 0`` degenerates to exact-duplicate grouping.
        min_samples: Core-point threshold including the point itself;
            values below 1 are clamped to 1.

    Returns:
        :class:`ClusterResult` with ``method='dbscan'``. ``assignments``
        uses ``-1`` for noise; cluster ids are contiguous from 0.
        ``centroids`` are cluster means (noise has no centroid).

    Example:
        >>> result = dbscan([[0, 0], [0, 0.1], [0, 0.2], [10, 10]], eps=0.5, min_samples=2)
        >>> result.assignments, result.noise_count
        ([0, 0, 0, -1], 1)
    """
    vectors = _as_points(points)
    if not vectors:
        return _empty_result('dbscan')
    radius = _to_float(eps)
    if radius is None:
        radius = 0.5
    core = max(1, _safe_int(min_samples, 3))

    count = len(vectors)
    # Precomputed adjacency: neighbours[i] holds every j (i included) within eps.
    neighbours: List[List[int]] = [[] for _ in range(count)]
    for i in range(count):
        neighbours[i].append(i)
    for i in range(count):
        for j in range(i + 1, count):
            if _distance(vectors[i], vectors[j]) <= radius:
                neighbours[i].append(j)
                neighbours[j].append(i)

    # Labels: -2 unvisited, -1 noise, >= 0 cluster id.
    labels = [-2] * count
    cluster_id = -1
    for seed in range(count):
        if labels[seed] != -2:
            continue
        if len(neighbours[seed]) < core:
            labels[seed] = NOISE_LABEL
            continue
        cluster_id += 1
        labels[seed] = cluster_id
        # True density-reachability: expand through core points only.
        queue = deque(neighbours[seed])
        while queue:
            j = queue.popleft()
            if labels[j] == NOISE_LABEL:
                # Earlier noise, now reached: adopt as border point. Border
                # points are not cores, so they never expand the cluster.
                labels[j] = cluster_id
                continue
            if labels[j] != -2:
                continue
            labels[j] = cluster_id
            if len(neighbours[j]) >= core:
                queue.extend(neighbours[j])

    centroids = _centroids_from(vectors, labels)
    sizes = [labels.count(cid) for cid in range(cluster_id + 1)]
    return ClusterResult(labels, centroids, sizes, labels.count(NOISE_LABEL), 'dbscan')


# ---------------------------------------------------------------------------
# k-means - seeded k-means++ initialisation plus Lloyd iterations
# ---------------------------------------------------------------------------

def _nearest_centroid(point: Sequence[float], centroids: List[List[float]]) -> int:
    """Index of the closest centroid (ties resolve to the lower index)."""
    best_index = 0
    best_distance = _distance(point, centroids[0])
    for index in range(1, len(centroids)):
        candidate = _distance(point, centroids[index])
        if candidate < best_distance:
            best_distance = candidate
            best_index = index
    return best_index


def kmeans(
    points: List[Sequence[float]],
    k: int,
    iterations: int = 50,
    seed: int = 42,
) -> ClusterResult:
    """k-means with k-means++ seeding and deterministic seeding.

    Initial centres are drawn by the k-means++ scheme through a dedicated
    ``random.Random(seed)``: the first centre uniformly at random, each next
    centre sampled with probability proportional to its squared distance
    from the nearest centre already chosen. Lloyd iterations then alternate
    assignment and centroid update until stable or ``iterations`` exhausted.
    An empty cluster keeps its previous centroid unchanged rather than
    collapsing or stealing a point.

    Args:
        points: List of coordinate tuples/lists (same dimension, numeric).
        k: Number of clusters; ``k <= 0`` or ``k > len(points)`` yields an
            empty result (nothing sensible to partition).
        iterations: Maximum Lloyd rounds (at least 1; non-numeric becomes 50).
        seed: RNG seed for reproducible centre selection.

    Returns:
        :class:`ClusterResult` with ``method='kmeans'`` - every point gets a
        label in ``0..k-1`` (no noise), centroids are final means, and
        ``noise_count`` is always 0.

    Example:
        >>> result = kmeans([[0], [1], [10], [11]], k=2, seed=42)
        >>> result.sizes
        [2, 2]
    """
    vectors = _as_points(points)
    if not vectors:
        return _empty_result('kmeans')
    count = len(vectors)
    cluster_count = _safe_int(k, 0)
    if cluster_count <= 0 or cluster_count > count:
        return _empty_result('kmeans')
    rounds = max(1, _safe_int(iterations, 50))
    rng = random.Random(_safe_int(seed, 42))

    # --- k-means++ initialisation ---
    first = rng.randrange(count)
    centroids: List[List[float]] = [list(vectors[first])]
    while len(centroids) < cluster_count:
        squared: List[float] = []
        total = 0.0
        for point in vectors:
            gap = _distance(point, centroids[-1])
            for centroid in centroids[:-1]:
                gap = min(gap, _distance(point, centroid))
            squared.append(gap * gap)
            total += gap * gap
        if total <= 0.0:
            # All points coincide with chosen centres: sample uniformly.
            centroids.append(list(vectors[rng.randrange(count)]))
            continue
        target = rng.random() * total
        accumulated = 0.0
        chosen = count - 1
        for index, weight in enumerate(squared):
            accumulated += weight
            if accumulated >= target:
                chosen = index
                break
        centroids.append(list(vectors[chosen]))

    # --- Lloyd iterations ---
    assignments: List[int] = [-1] * count
    previous: Optional[List[int]] = None
    for _ in range(rounds):
        assignments = [_nearest_centroid(point, centroids) for point in vectors]
        if assignments == previous:
            break
        previous = assignments
        for cid in range(cluster_count):
            members = [vectors[i] for i in range(count) if assignments[i] == cid]
            if not members:
                # Empty cluster: the contract keeps the old centroid.
                continue
            dimension = len(members[0])
            centroids[cid] = [
                sum(member[d] for member in members) / len(members)
                for d in range(dimension)
            ]
    sizes = [assignments.count(cid) for cid in range(cluster_count)]
    return ClusterResult(assignments, centroids, sizes, 0, 'kmeans')


# ---------------------------------------------------------------------------
# Hierarchical - agglomerative single-link merging
# ---------------------------------------------------------------------------

def hierarchical(points: List[Sequence[float]], threshold: float = 1.0) -> ClusterResult:
    """Agglomerative clustering, single-linkage, stopped at a distance cutoff.

    Starts with every point in its own cluster and repeatedly merges the
    pair of clusters with the smallest single-link distance (the minimum
    pairwise point distance across the pair) while that distance stays
    ``<= threshold``. Cluster ids are handed out in order of each cluster's
    first point, so the output is stable for a given input.

    Single-link is the deliberate choice for investigation data: it chains
    through bridges - a trail of DNS records drifting one small hop at a
    time - which centroid-based linkage would cut. The price is sensitivity
    to exactly those chains; use :func:`dbscan` when noise must be filtered
    instead of chained.

    Args:
        points: List of coordinate tuples/lists (same dimension, numeric).
        threshold: Merge cutoff (Euclidean). Non-finite values fall back to
            1.0; negative values clamp to 0.0 (exact duplicates only).

    Returns:
        :class:`ClusterResult` with ``method='hierarchical'`` and
        ``noise_count`` 0 (agglomeration has no noise concept; unmerged
        singletons are simply size-1 clusters).

    Example:
        >>> result = hierarchical([[0], [0.2], [5], [5.3]], threshold=1.0)
        >>> result.assignments
        [0, 0, 1, 1]
    """
    vectors = _as_points(points)
    if not vectors:
        return _empty_result('hierarchical')
    cutoff = _to_float(threshold)
    if cutoff is None:
        cutoff = 1.0
    if cutoff < 0.0:
        cutoff = 0.0

    count = len(vectors)
    distances = [[0.0] * count for _ in range(count)]
    for i in range(count):
        for j in range(i + 1, count):
            gap = _distance(vectors[i], vectors[j])
            distances[i][j] = gap
            distances[j][i] = gap

    clusters: List[List[int]] = [[i] for i in range(count)]
    while len(clusters) > 1:
        best_pair = (0, 1)
        best_gap = math.inf
        for a in range(len(clusters)):
            for b in range(a + 1, len(clusters)):
                gap = min(
                    distances[x][y]
                    for x in clusters[a]
                    for y in clusters[b]
                )
                if gap < best_gap:
                    best_gap = gap
                    best_pair = (a, b)
        if best_gap > cutoff:
            break
        a, b = best_pair
        clusters[a].extend(clusters[b])
        del clusters[b]

    labels = [0] * count
    for next_label, members in enumerate(clusters):
        for index in members:
            labels[index] = next_label
    centroids = _centroids_from(vectors, labels)
    sizes = [len(members) for members in clusters]
    return ClusterResult(labels, centroids, sizes, 0, 'hierarchical')


# ---------------------------------------------------------------------------
# Cluster evaluation
# ---------------------------------------------------------------------------

def silhouette_score(points: List[Sequence[float]], assignments: List[int]) -> Optional[float]:
    """Mean silhouette coefficient of a labelling (1 perfect, 0 ambiguous).

    For every point ``i`` in a cluster of two or more: ``a(i)`` is its mean
    distance to its own cluster, ``b(i)`` the smallest mean distance to any
    *other* cluster, and ``s(i) = (b - a) / max(a, b)``. Noise points
    (label < 0) and singleton clusters (``a`` undefined) are skipped rather
    than counted as zero, which would drag the score down for reasons that
    have nothing to do with cluster quality.

    Args:
        points: Coordinate tuples/lists matching the assignment list.
        assignments: One label per point; negative labels are noise.

    Returns:
        The mean silhouette in ``[-1, 1]``, or ``None`` when the input is
        malformed, fewer than two real clusters exist, or no point is
        scorable (every cluster a singleton).

    Example:
        >>> round(silhouette_score([[0], [0.1], [10], [10.1]], [0, 0, 1, 1]), 4)
        0.99
    """
    vectors = _as_points(points)
    if not vectors:
        return None
    if not isinstance(assignments, (list, tuple)) or len(assignments) != len(vectors):
        return None
    groups: Dict[int, List[int]] = {}
    for index, raw_label in enumerate(assignments):
        label = _safe_int(raw_label, NOISE_LABEL)
        if label < 0:
            continue
        groups.setdefault(label, []).append(index)
    if len(groups) < 2:
        return None

    scores: List[float] = []
    for members in groups.values():
        if len(members) < 2:
            continue  # singleton: a(i) undefined
        for i in members:
            own = sum(_distance(vectors[i], vectors[j]) for j in members if j != i)
            a_score = own / (len(members) - 1)
            b_score = math.inf
            for other_members in groups.values():
                if other_members is members:
                    continue
                cross = sum(_distance(vectors[i], vectors[j]) for j in other_members)
                cross /= len(other_members)
                b_score = min(b_score, cross)
            if b_score == math.inf:  # pragma: no cover - guarded by >= 2 groups
                continue
            denominator = max(a_score, b_score)
            scores.append(0.0 if denominator == 0.0 else (b_score - a_score) / denominator)
    if not scores:
        return None
    return sum(scores) / len(scores)


def optimal_eps(points: List[Sequence[float]], k: int = 4) -> float:
    """Heuristic DBSCAN radius from the k-distance plot (k-NN elbow).

    For every point the distance to its ``k``-th nearest neighbour is
    computed, the resulting k-distances are sorted, and the elbow is read
    off as ``median * 1.5``. Sorting the k-distances produces the classic
    knee curve: dense-region points hug the floor, outliers shoot up, and a
    cut somewhere above the floor separates them - the median scaled by 1.5
    is a robust, parameter-free place to cut.

    Args:
        points: Coordinate tuples/lists; invalid input returns 0.0.
        k: Neighbour rank (the spec's default is 4). Values below 1 become
            1; values at or above ``len(points)`` clamp to ``len(points)-1``.

    Returns:
        The suggested ``eps`` (never negative, 0.0 for unusable input).
        This is a *starting point* for :func:`dbscan`, not a guarantee.

    Example:
        >>> optimal_eps([[0], [1], [2], [3], [10]], k=2)
        3.0
    """
    vectors = _as_points(points)
    if not vectors or len(vectors) < 2:
        return 0.0
    rank = _safe_int(k, _DEFAULT_KNN)
    if rank < 1:
        rank = 1
    if rank > len(vectors) - 1:
        rank = len(vectors) - 1
    k_distances: List[float] = []
    for i, point in enumerate(vectors):
        gaps = sorted(
            _distance(point, other)
            for j, other in enumerate(vectors)
            if j != i
        )
        k_distances.append(gaps[rank - 1])
    k_distances.sort()
    return median(k_distances) * _KDIST_SCALE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_points(points: List[Sequence[float]]) -> List[List[float]]:
    """Per-dimension z-score normalisation of a point set.

    Scale kills distance-based clustering: one coordinate measured in
    milliseconds dwarfs another measured in CVE counts, and DBSCAN then
    "sees" only the big dimension. This helper standardises every dimension
    to mean 0 / population standard deviation 1 so all axes compete on equal
    terms. Dimensions with zero variance are left untouched (their raw,
    constant value passes through) - dividing by zero would be worse than
    not normalising.

    Args:
        points: Coordinate tuples/lists. Unlike the strict clusterers, this
            helper *drops* unparseable rows (first valid row sets the
            expected dimension) because it has no label alignment to
            preserve.

    Returns:
        The normalised vectors; empty for empty or wholly invalid input.

    Example:
        >>> normalize_points([[0], [5], [10]])[1]
        [0.0]
    """
    if points is None:
        return []
    try:
        iterator = iter(points)
    except TypeError:
        return []
    rows: List[List[float]] = []
    dimension: Optional[int] = None
    for item in iterator:
        if isinstance(item, (str, bytes)) or not isinstance(item, (list, tuple)):
            continue
        row: List[float] = []
        for coordinate in item:
            number = _to_float(coordinate)
            if number is not None:
                row.append(number)
        if not row:
            continue
        if dimension is None:
            dimension = len(row)
        elif len(row) != dimension:
            continue
        rows.append(row)
    if not rows:
        return []

    count = len(rows)
    dim = dimension or len(rows[0])
    means = [sum(row[d] for row in rows) / count for d in range(dim)]
    spreads = [
        math.sqrt(sum((row[d] - means[d]) ** 2 for row in rows) / count)
        for d in range(dim)
    ]
    return [
        [
            (row[d] - means[d]) / spreads[d] if spreads[d] > 0.0 else row[d]
            for d in range(dim)
        ]
        for row in rows
    ]


def cluster_summary(points: List[Sequence[float]], result: ClusterResult) -> Dict[str, Any]:
    """Human-readable dossier over a :class:`ClusterResult`.

    For every cluster: size, centroid, radius (farthest member distance from
    the centroid) and tightness (mean member distance from the centroid) -
    the two numbers that separate "one tight group" from "a loose cloud the
    algorithm bundled together". Noise gets a count and a share of the whole
    set, which for DBSCAN is itself a finding ("40% of these contacts match
    nothing").

    Args:
        points: The coordinate tuples/lists the result was computed from.
        result: A :class:`ClusterResult`.

    Returns:
        Dict with ``'method'``, ``'n_points'``, ``'n_clusters'``,
        ``'clusters'`` (list of ``{'id', 'size', 'centroid', 'radius',
        'tightness'}``) and ``'noise_count'`` / ``'noise_ratio'``. Mismatched
        input (wrong lengths, invalid points, non-ClusterResult) returns the
        same shape zeroed - never an exception.

    Example:
        >>> summary = cluster_summary([[0], [0.2], [5], [5.3]], hierarchical([[0], [0.2], [5], [5.3]]))
        >>> summary['n_clusters'], summary['noise_count']
        (2, 0)
    """
    zeroed = {
        'method': 'unknown',
        'n_points': 0,
        'n_clusters': 0,
        'clusters': [],
        'noise_count': 0,
        'noise_ratio': 0.0,
    }
    vectors = _as_points(points)
    if vectors is None or not isinstance(result, ClusterResult):
        return zeroed
    assignments = result.assignments
    if len(assignments) != len(vectors):
        return zeroed

    total = len(vectors)
    clusters: List[Dict[str, Any]] = []
    label_ids = sorted({label for label in assignments if label >= 0})
    noise = sum(1 for label in assignments if label < 0)
    for cid in label_ids:
        members = [vectors[i] for i, label in enumerate(assignments) if label == cid]
        if not members:  # pragma: no cover - label_ids come from assignments
            continue
        dimension = len(members[0])
        centroid = [
            sum(member[d] for member in members) / len(members)
            for d in range(dimension)
        ]
        gaps = [_distance(member, centroid) for member in members]
        clusters.append({
            'id': cid,
            'size': len(members),
            'centroid': centroid,
            'radius': max(gaps),
            'tightness': sum(gaps) / len(gaps),
        })
    method = result.method if isinstance(result.method, str) else 'unknown'
    return {
        'method': method,
        'n_points': total,
        'n_clusters': len(clusters),
        'clusters': clusters,
        'noise_count': noise,
        'noise_ratio': noise / total if total else 0.0,
    }
