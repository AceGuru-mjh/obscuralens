"""
Analytics benchmarks: descriptive statistics, anomaly detection,
time-series workups, clustering, string similarity, text metrics, graph
metrics and the gradient-descent prediction models.

Every input is synthetic and deterministic - series come from
``random.Random(42)`` so results are reproducible machine to machine - and
every measured function is pure (the analytics package contract), so no
isolation glue is needed: nothing here touches disk, configuration or
global state.

Register everything with :func:`build_benches` (consumed by
:mod:`benchmarks.run`).
"""

import random
from typing import Any, Callable, Dict, List, Optional, Tuple

from obscuralens.analytics import (
    anomaly,
    cluster,
    graphmetrics,
    predict,
    similarity,
    stats,
    textmetrics,
    timeseries,
)
from obscuralens.analytics.geoanalytics import cluster_points

from .harness import BenchSpec

# --- synthetic inputs (seeded, deterministic) --------------------------------

#: Seeded generator for every synthetic series in this module.
_RNG = random.Random(42)

#: Gaussian value pools reused across the stats/anomaly benches.
VALUES_100 = [_RNG.gauss(50, 10) for _ in range(100)]
VALUES_1K = [_RNG.gauss(50, 10) for _ in range(1000)]
VALUES_10K = [_RNG.gauss(50, 10) for _ in range(10000)]

#: 365-point daily series with a gentle upward trend plus noise.
SERIES_365 = [_RNG.gauss(100 + i * 0.5, 8) for i in range(365)]

#: 10,000 (index, value) tuples for the to_points parser.
PAIRS_10K = [(i, _RNG.gauss(0, 1)) for i in range(10000)]

#: 500 [lat, lon] points spread around three city hotspots.
_HOTSPOTS = ((48.8566, 2.3522), (51.5074, -0.1278), (35.6762, 139.6503))
GEO_500 = [
    [_RNG.gauss(_HOTSPOTS[i % 3][0], 0.02), _RNG.gauss(_HOTSPOTS[i % 3][1], 0.02)]
    for i in range(500)
]

#: 1,000 generic 2-D points in four loose blobs for k-means.
POINTS_2D_1K = [
    [center + _RNG.gauss(0, 3) for center in ((0, 0), (30, 0), (0, 30), (30, 30))[i % 4]]
    for i in range(1000)
]

#: 100-point series for the index-based forecast.
FORECAST_100 = [_RNG.gauss(10 + i * 0.2, 1.5) for i in range(100)]

#: 200 x 3 synthetic feature matrix with a noisy linear target.
FEATURES_200X3 = [[_RNG.gauss(0, 1), _RNG.gauss(5, 2), _RNG.gauss(-3, 0.5)]
                  for _ in range(200)]
TARGETS_200 = [2.0 * f[0] - 1.5 * f[1] + 0.75 * f[2] + _RNG.gauss(0, 0.1)
               for f in FEATURES_200X3]

#: Word pairs (identity-resolution style) for the similarity benches.
WORD_PAIRS: Tuple[Tuple[str, str], ...] = (
    ('john smith', 'jon smyth'),
    ('example.com', 'exarnple.com'),
    ('alice bethany', 'alise bethanie'),
    ('security platform', 'security plataform'),
    ('obscuralens', 'obscura-lens'),
    (' reconnaissance', 'reconaissance'),
    ('aisha khan', 'ayesha khaan'),
    ('münchen hbf', 'munchen hbf'),
    ('742 evergreen terrace', '742 evergreen terace'),
    ('rasmussen', 'rasmusssen'),
)

#: Sparse term-count vectors for the cosine bench.
VEC_A = {'threat': 3, 'intel': 2, 'report': 5, 'sensor': 1}
VEC_B = {'threat': 2, 'intel': 4, 'report': 1, 'analysis': 3}

#: ~2,000-word corpus assembled from a fixed vocabulary (seeded).
_VOCAB = ('threat', 'intelligence', 'sensor', 'platform', 'report',
          'investigation', 'target', 'domain', 'address', 'network',
          'analysis', 'indicator', 'compromise', 'infrastructure', 'signal')
CORPUS_2K = ' '.join(_RNG.choice(_VOCAB) for _ in range(2000))

#: One snippet per script family for the language detector.
LANG_SNIPPETS: Tuple[str, ...] = (
    'The quick brown fox jumps over the lazy dog near the river bank.',
    'Быстрая бурая лиса прыгает через ленивую собаку у реки.',
    '素早い茶色のキツネは怠け者の犬を飛び越えて川に向かう。',
    '敏捷的棕色狐狸跳过了懒狗并在河边徘徊。',
)

#: Two prose samples for the four-metric text similarity report.
TEXT_A = ('The investigation uncovered a coordinated phishing campaign '
          'targeting energy sector employees across three countries.')
TEXT_B = ('The inquiry revealed a organised phishing operation aimed at '
          'power industry staff in several nations.')


def _graph(nodes: int, links_per_node: int) -> Tuple[List[Dict[str, Any]],
                                                      List[Dict[str, Any]]]:
    """
    Deterministic investigation-style graph: node ids 0..n-1, links
    ``i -> (i * 7 + 1) % n`` repeated ``links_per_node`` times with a
    shifted multiplier so every node keeps a healthy degree.
    """
    entities = [{'id': f'entity-{i}', 'type': 'node', 'value': i}
                for i in range(nodes)]
    links = []
    for mult in (7, 11, 13):
        for i in range(nodes):
            target = (i * mult + 1) % nodes
            if target != i:
                links.append({'source': f'entity-{i}', 'target': f'entity-{target}',
                              'label': 'related'})
    return entities, links[:nodes * links_per_node]


GRAPH_100 = _graph(100, 3)
GRAPH_500 = _graph(500, 3)


# --- builder -----------------------------------------------------------------

def build_benches(workdir: Optional[str] = None) -> List[BenchSpec]:
    """
    Build every analytics benchmark.

    Args:
        workdir: accepted for signature parity with the other bench
            modules; analytics functions are pure so it is unused.

    Returns:
        :class:`~benchmarks.harness.BenchSpec` list, registration order.
    """
    specs: List[BenchSpec] = []
    specs.extend(_stats_benches())
    specs.extend(_anomaly_benches())
    specs.extend(_timeseries_benches())
    specs.extend(_cluster_benches())
    specs.extend(_similarity_benches())
    specs.extend(_text_benches())
    specs.extend(_graph_benches())
    specs.extend(_predict_benches())
    return specs


def _stats_benches() -> List[BenchSpec]:
    """summarize at three sizes plus a 10k/50-bin histogram."""

    def summarize_100() -> None:
        stats.summarize(VALUES_100)

    def summarize_1k() -> None:
        stats.summarize(VALUES_1K)

    def summarize_10k() -> None:
        stats.summarize(VALUES_10K)

    def histogram_10k() -> None:
        stats.histogram(VALUES_10K, bins=50)

    return [
        BenchSpec('stats_summarize_100', summarize_100, repeat=5, number=50,
                  tags=('analytics',)),
        BenchSpec('stats_summarize_1000', summarize_1k, repeat=5, number=20,
                  tags=('analytics',)),
        BenchSpec('stats_summarize_10000', summarize_10k, repeat=5, number=5,
                  tags=('analytics',)),
        BenchSpec('stats_histogram_10k_50bins', histogram_10k, repeat=5, number=20,
                  tags=('analytics',)),
    ]


def _anomaly_benches() -> List[BenchSpec]:
    """Every detector behind detect_anomalies on the 1,000-sample series."""

    def run(method: str, **kwargs: Any) -> Callable[[], None]:
        def call() -> None:
            anomaly.detect_anomalies(VALUES_1K, method=method, **kwargs)
        return call

    return [
        BenchSpec('anomaly_zscore_1k', run('zscore', threshold=2.5),
                  repeat=5, number=50, tags=('analytics', 'anomaly')),
        BenchSpec('anomaly_iqr_1k', run('iqr', factor=1.5),
                  repeat=5, number=50, tags=('analytics', 'anomaly')),
        BenchSpec('anomaly_mad_1k', run('mad'),
                  repeat=5, number=50, tags=('analytics', 'anomaly')),
        BenchSpec('anomaly_grubbs_1k', run('grubbs'),
                  repeat=5, number=50, tags=('analytics', 'anomaly')),
        BenchSpec('anomaly_ensemble_1k', run('ensemble'),
                  repeat=5, number=20, tags=('analytics', 'anomaly')),
    ]


def _timeseries_benches() -> List[BenchSpec]:
    """series_summary over 365 points and to_points over 10k tuples."""
    points365 = timeseries.to_points(list(enumerate(SERIES_365)))

    def summary() -> None:
        timeseries.series_summary(points365)

    def parse() -> None:
        timeseries.to_points(PAIRS_10K)

    return [
        BenchSpec('timeseries_series_summary_365', summary, repeat=5, number=20,
                  tags=('analytics',)),
        BenchSpec('timeseries_to_points_10k', parse, repeat=5, number=5,
                  tags=('analytics',)),
    ]


def _cluster_benches() -> List[BenchSpec]:
    """Geo DBSCAN over 500 hotspot points; k-means over 1,000 2-D points."""

    def geo_dbscan() -> None:
        cluster_points(GEO_500, eps_km=25.0, min_points=3)

    def kmeans_1k() -> None:
        cluster.kmeans(POINTS_2D_1K, k=4, iterations=50, seed=42)

    return [
        BenchSpec('cluster_geo_dbscan_500', geo_dbscan, repeat=3, number=1,
                  tags=('analytics', 'cluster')),
        BenchSpec('cluster_kmeans_1000_2d', kmeans_1k, repeat=3, number=1,
                  tags=('analytics', 'cluster')),
    ]


def _similarity_benches() -> List[BenchSpec]:
    """String-similarity kernels over the fixed word-pair list."""

    def jaro_winkler() -> None:
        for a, b in WORD_PAIRS:
            similarity.jaro_winkler(a, b)

    def levenshtein_ratio() -> None:
        for a, b in WORD_PAIRS:
            similarity.levenshtein_ratio(a, b)

    def bigram_jaccard() -> None:
        for a, b in WORD_PAIRS:
            similarity.ngram_similarity(a, b, n=2)

    def cosine() -> None:
        for _ in range(10):
            similarity.cosine_similarity(VEC_A, VEC_B)

    return [
        BenchSpec('similarity_jaro_winkler', jaro_winkler, repeat=5, number=50,
                  tags=('analytics', 'similarity')),
        BenchSpec('similarity_levenshtein_ratio', levenshtein_ratio,
                  repeat=5, number=50, tags=('analytics', 'similarity')),
        BenchSpec('similarity_bigram_jaccard', bigram_jaccard, repeat=5, number=50,
                  tags=('analytics', 'similarity')),
        BenchSpec('similarity_cosine_sparse', cosine, repeat=5, number=100,
                  tags=('analytics', 'similarity')),
    ]


def _text_benches() -> List[BenchSpec]:
    """Keyword mining, script/language fingerprinting, similarity reports."""

    def keywords() -> None:
        textmetrics.extract_keywords(CORPUS_2K, top=10)

    def languages() -> None:
        for snippet in LANG_SNIPPETS:
            textmetrics.detect_language_script(snippet)

    def similarity_report() -> None:
        textmetrics.text_similarity_report(TEXT_A, TEXT_B)

    return [
        BenchSpec('textmetrics_extract_keywords_2k', keywords, repeat=5,
                  number=50, tags=('analytics', 'text')),
        BenchSpec('textmetrics_detect_language_script', languages, repeat=5,
                  number=50, tags=('analytics', 'text')),
        BenchSpec('textmetrics_similarity_report', similarity_report, repeat=5,
                  number=50, tags=('analytics', 'text')),
    ]


def _graph_benches() -> List[BenchSpec]:
    """graph_summary dossiers over two deterministic synthetic graphs."""

    def small() -> None:
        graphmetrics.graph_summary(GRAPH_100[0], GRAPH_100[1])

    def large() -> None:
        graphmetrics.graph_summary(GRAPH_500[0], GRAPH_500[1])

    return [
        BenchSpec('graph_summary_100n_300l', small, repeat=5, number=10,
                  tags=('analytics', 'graph')),
        BenchSpec('graph_summary_500n_1500l', large, repeat=3, number=5,
                  tags=('analytics', 'graph')),
    ]


def _predict_benches() -> List[BenchSpec]:
    """Forecast, gradient-descent fit and prediction over the linear setup."""

    def forecast() -> None:
        predict.simple_forecast(FORECAST_100)

    def fit() -> Any:
        return predict.fit_linear(FEATURES_200X3, TARGETS_200)

    # fit_linear is the expensive half (~200 ms/call); the fitted model is
    # reused by the prediction bench through module-level state captured
    # lazily on the first warmup call.
    fitted: Dict[str, Any] = {}

    def fit_once() -> None:
        fitted['model'] = predict.fit_linear(FEATURES_200X3, TARGETS_200)

    def predict_rows() -> None:
        model = fitted['model']
        if model is None:
            fitted['model'] = model = predict.fit_linear(FEATURES_200X3, TARGETS_200)
        for row in FEATURES_200X3:
            predict.predict_linear(model, row)

    return [
        BenchSpec('predict_simple_forecast_100', forecast, repeat=5, number=100,
                  tags=('analytics', 'predict')),
        BenchSpec('predict_fit_linear_200x3', fit, repeat=3, number=1,
                  tags=('analytics', 'predict')),
        BenchSpec('predict_predict_linear_200', predict_rows, repeat=5,
                  number=10, setup=fit_once, tags=('analytics', 'predict')),
    ]


__all__ = ['build_benches']
