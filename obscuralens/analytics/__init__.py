"""
ObscuraLens analytics intelligence package (v6.0 Part 2).

Part 1 of the v6.0 program widened the sensor matrix to 20 target kinds;
Part 2 gives the platform a brain for the numbers those sensors produce.
This package is the analysis layer: descriptive statistics, time-series
workups, anomaly detection, clustering, string similarity, text metrics,
graph metrics, spatial analytics, prediction models and history
enrichment, all built on the Python standard library alone so the whole
intelligence stack installs anywhere ObscuraLens itself runs - air-gapped
hosts, slim containers, the frozen desktop executable - with zero new
dependencies.

Module map:

* :mod:`obscuralens.analytics.stats` - descriptive statistics: central
  tendency, spread, quantiles (numpy-compatible linear interpolation),
  bias-corrected skewness/kurtosis, histograms, frequency tables, Shannon
  entropy, classic and robust z-scores, and the one-shot
  :func:`obscuralens.analytics.stats.summarize`.
* :mod:`obscuralens.analytics.timeseries` - chronological analysis over
  :class:`~obscuralens.analytics.timeseries.TimeSeriesPoint`: trailing
  moving average, EWMA, least-squares trend with direction verdicts,
  detrending, cumulative sums, rates of change, UTC daily resampling,
  CUSUM changepoint detection, seasonality hints and
  :func:`~obscuralens.analytics.timeseries.series_summary`.
* :mod:`obscuralens.analytics.anomaly` - outlier detection with a shared
  :class:`~obscuralens.analytics.anomaly.AnomalyScore` record: z-score,
  Tukey IQR fences, MAD robust z, the Grubbs single-outlier test, a
  multi-method voting ensemble, hard floor/ceiling bounds and the unified
  :func:`~obscuralens.analytics.anomaly.detect_anomalies` entry point.
* :mod:`obscuralens.analytics.cluster` - unsupervised grouping with the
  shared :class:`~obscuralens.analytics.cluster.ClusterResult` envelope:
  DBSCAN (true density-reachability expansion plus explicit noise),
  seeded k-means++ k-means, agglomerative single-link hierarchical
  clustering, silhouette scoring, a k-distance ``eps`` heuristic,
  per-dimension normalisation and cluster dossiers.
* :mod:`obscuralens.analytics.similarity` - identity resolution and fuzzy
  matching: Levenshtein distance/ratio (rolling two-row), exact Jaro and
  Jaro-Winkler, American Soundex, a simplified Metaphone hint, n-gram
  Jaccard and Sørensen-Dice, sparse-vector cosine, ranked
  :func:`~obscuralens.analytics.similarity.most_similar` retrieval and the
  domain-squatting oriented
  :func:`~obscuralens.analytics.similarity.typosquat_score`.
* :mod:`obscuralens.analytics.textmetrics` - prose analytics for paste
  dumps and advisories: Unicode tokenisation, n-grams, classic TF-IDF,
  stopword-filtered keyword mining, Flesch readability, script and
  language fingerprints, character profiles, extractive summaries,
  redaction sweeps over the validator-driven entity pipeline and the
  four-metric :func:`~obscuralens.analytics.textmetrics.text_similarity_report`.
* :mod:`obscuralens.analytics.graphmetrics` - investigation graphs as
  measurements over the investigate/correlation ``entities``/``links``
  payloads: degree and PageRank centrality, Brandes betweenness (skipped
  above 200 nodes), connected components, seeded label-propagation
  communities, Tarjan bridges (the relationships that hold clusters
  together), BFS shortest paths and the one-shot
  :func:`~obscuralens.analytics.graphmetrics.graph_summary` dossier.
* :mod:`obscuralens.analytics.geoanalytics` - spatial analytics over
  :class:`~obscuralens.analytics.geoanalytics.GeoPoint` sets: bounding
  boxes, planar centroids, pairwise great-circle distances (delegating to
  the platform's ``coordinate_math.haversine_km``), kilometre-space
  DBSCAN clustering, geofence checks with bearings, Tukey outlier points,
  distance matrices, route lengths and
  :func:`~obscuralens.analytics.geoanalytics.geo_summary`.
* :mod:`obscuralens.analytics.predict` - screening-grade models with
  hand-rolled gradient descent: standardised-input linear regression,
  logistic classification over :class:`~obscuralens.analytics.predict.LinearModel`,
  index-based trend extrapolation (:func:`~obscuralens.analytics.predict.simple_forecast`,
  confidence always ``'low'`` - an extrapolation, not a prophecy) and
  binary evaluation with zero-division-safe precision/recall/F1.
* :mod:`obscuralens.analytics.enrich` - the read-only bridge from the
  platform's query history to every structure above: per-query evidence
  time series, kind/hour/weekday activity profiles, per-kind success
  rates, field-count distributions, source reliability from stored
  tracker envelopes, ensemble day-volume anomalies, most re-queried
  targets and the one-shot
  :func:`~obscuralens.analytics.enrich.enrichment_report` dossier.

Package contract (mirrored by every module):

* **Python 3.9+ pure stdlib** - ``typing.Optional/List/Dict`` style
  annotations, no third-party imports, no global state. The single
  sanctioned exception is :mod:`obscuralens.analytics.enrich`, the
  designated observer of the shared ``db`` history singleton (read-only;
  everything else in the package stays pure).
* **Defensive everywhere** - ``None``, empty, malformed or non-numeric
  input produces safe defaults (``None``, empty lists, empty result
  envelopes), never an exception; a broken row is dropped, not fatal.
* **Pure functions and value objects** - results depend only on arguments,
  safe to cache, parallelise and replay inside reports.

Use :func:`analytics_summary` for a machine-readable capability inventory -
handy for the web/MCP layers that want to advertise what this build offers
without importing every symbol.
"""

from typing import Any, Dict, List

from .anomaly import (
    AnomalyScore,
    detect_anomalies,
    ensemble_anomalies,
    grubbs_test,
    iqr_anomalies,
    mad_anomalies,
    threshold_anomalies,
    zscore_anomalies,
)
from .cluster import (
    ClusterResult,
    cluster_summary,
    dbscan,
    hierarchical,
    kmeans,
    normalize_points,
    optimal_eps,
    silhouette_score,
)
from .enrich import (
    activity_anomalies,
    enrichment_report,
    field_count_distribution,
    history_points,
    hour_of_day_profile,
    kind_frequency,
    source_reliability,
    success_rate_by_kind,
    top_targets,
    weekday_profile,
)
from .geoanalytics import (
    GeoPoint,
    bounding_box,
    centroid,
    cluster_points,
    distance_matrix,
    geo_summary,
    geofence_check,
    outlier_points,
    pairwise_distances,
    route_length,
)
from .graphmetrics import (
    betweenness_centrality,
    bridges,
    build_adjacency,
    connected_components,
    degree_centrality,
    graph_summary,
    label_propagation_communities,
    pagerank,
    shortest_path,
    top_entities,
)
from .predict import (
    LinearModel,
    classify,
    evaluate_binary,
    fit_linear,
    fit_logistic,
    predict_linear,
    predict_logistic,
    simple_forecast,
)
from .similarity import (
    cosine_similarity,
    dice_coefficient,
    jaro,
    jaro_winkler,
    levenshtein,
    levenshtein_ratio,
    metaphone_hint,
    most_similar,
    ngram_similarity,
    soundex,
    typosquat_score,
)
from .stats import (
    coefficient_of_variation,
    histogram,
    iqr,
    kurtosis,
    mean,
    median,
    min_max_range,
    mode,
    percentile,
    pstdev,
    quartiles,
    robust_zscore,
    shannon_entropy,
    skewness,
    stdev,
    summarize,
    value_counts,
    variance,
    zscore,
)
from .textmetrics import (
    char_profile,
    detect_language_script,
    extract_keywords,
    ngrams,
    readability,
    redaction_sweep,
    summarize_text,
    term_frequencies,
    text_similarity_report,
    tfidf,
    tokenize,
)
from .timeseries import (
    TimeSeriesPoint,
    cumulative_sum,
    detect_changepoints,
    detrend,
    ewma,
    linear_trend,
    moving_average,
    rate_of_change,
    resample_daily,
    seasonality_hint,
    series_summary,
    to_points,
)

__all__ = [
    'AnomalyScore',
    'ClusterResult',
    'GeoPoint',
    'LinearModel',
    'TimeSeriesPoint',
    'activity_anomalies',
    'analytics_summary',
    'betweenness_centrality',
    'bounding_box',
    'bridges',
    'build_adjacency',
    'centroid',
    'char_profile',
    'classify',
    'cluster_points',
    'cluster_summary',
    'coefficient_of_variation',
    'connected_components',
    'cosine_similarity',
    'cumulative_sum',
    'dbscan',
    'degree_centrality',
    'detect_anomalies',
    'detect_changepoints',
    'detect_language_script',
    'detrend',
    'dice_coefficient',
    'distance_matrix',
    'enrichment_report',
    'ensemble_anomalies',
    'evaluate_binary',
    'ewma',
    'extract_keywords',
    'field_count_distribution',
    'fit_linear',
    'fit_logistic',
    'geofence_check',
    'geo_summary',
    'graph_summary',
    'grubbs_test',
    'hierarchical',
    'histogram',
    'history_points',
    'hour_of_day_profile',
    'iqr',
    'iqr_anomalies',
    'jaro',
    'jaro_winkler',
    'kind_frequency',
    'kmeans',
    'kurtosis',
    'label_propagation_communities',
    'levenshtein',
    'levenshtein_ratio',
    'linear_trend',
    'mad_anomalies',
    'mean',
    'median',
    'metaphone_hint',
    'min_max_range',
    'mode',
    'most_similar',
    'moving_average',
    'ngram_similarity',
    'ngrams',
    'normalize_points',
    'optimal_eps',
    'outlier_points',
    'pagerank',
    'pairwise_distances',
    'percentile',
    'predict_linear',
    'predict_logistic',
    'pstdev',
    'quartiles',
    'rate_of_change',
    'readability',
    'redaction_sweep',
    'resample_daily',
    'robust_zscore',
    'route_length',
    'seasonality_hint',
    'series_summary',
    'shannon_entropy',
    'shortest_path',
    'silhouette_score',
    'simple_forecast',
    'skewness',
    'soundex',
    'source_reliability',
    'stdev',
    'success_rate_by_kind',
    'summarize',
    'summarize_text',
    'term_frequencies',
    'text_similarity_report',
    'tfidf',
    'threshold_anomalies',
    'to_points',
    'tokenize',
    'top_entities',
    'top_targets',
    'typosquat_score',
    'value_counts',
    'variance',
    'weekday_profile',
    'zscore',
    'zscore_anomalies',
]

#: Capability inventory: module name -> exported callables/classes.
_CAPABILITIES: Dict[str, List[str]] = {
    'stats': [
        'mean', 'median', 'mode', 'variance', 'stdev', 'pstdev',
        'percentile', 'quartiles', 'iqr', 'skewness', 'kurtosis',
        'min_max_range', 'summarize', 'histogram', 'value_counts',
        'coefficient_of_variation', 'shannon_entropy', 'zscore',
        'robust_zscore',
    ],
    'timeseries': [
        'TimeSeriesPoint', 'to_points', 'moving_average', 'ewma', 'detrend',
        'linear_trend', 'cumulative_sum', 'rate_of_change',
        'detect_changepoints', 'seasonality_hint', 'resample_daily',
        'series_summary',
    ],
    'anomaly': [
        'AnomalyScore', 'zscore_anomalies', 'iqr_anomalies', 'mad_anomalies',
        'grubbs_test', 'ensemble_anomalies', 'detect_anomalies',
        'threshold_anomalies',
    ],
    'cluster': [
        'ClusterResult', 'dbscan', 'kmeans', 'hierarchical',
        'silhouette_score', 'optimal_eps', 'normalize_points',
        'cluster_summary',
    ],
    'similarity': [
        'levenshtein', 'levenshtein_ratio', 'jaro', 'jaro_winkler',
        'soundex', 'metaphone_hint', 'ngram_similarity', 'dice_coefficient',
        'cosine_similarity', 'most_similar', 'typosquat_score',
    ],
    'textmetrics': [
        'tokenize', 'ngrams', 'term_frequencies', 'tfidf',
        'extract_keywords', 'readability', 'detect_language_script',
        'char_profile', 'summarize_text', 'redaction_sweep',
        'text_similarity_report',
    ],
    'graphmetrics': [
        'build_adjacency', 'degree_centrality', 'pagerank',
        'betweenness_centrality', 'connected_components',
        'label_propagation_communities', 'top_entities', 'bridges',
        'graph_summary', 'shortest_path',
    ],
    'geoanalytics': [
        'GeoPoint', 'bounding_box', 'centroid', 'pairwise_distances',
        'cluster_points', 'geofence_check', 'outlier_points',
        'distance_matrix', 'route_length', 'geo_summary',
    ],
    'predict': [
        'LinearModel', 'fit_linear', 'predict_linear', 'fit_logistic',
        'predict_logistic', 'classify', 'simple_forecast', 'evaluate_binary',
    ],
    'enrich': [
        'history_points', 'kind_frequency', 'hour_of_day_profile',
        'weekday_profile', 'success_rate_by_kind', 'field_count_distribution',
        'source_reliability', 'activity_anomalies', 'top_targets',
        'enrichment_report',
    ],
}


def analytics_summary() -> Dict[str, Any]:
    """Machine-readable inventory of the analytics package's capabilities.

    Intended for the web UI's capability banner, the MCP server's tool
    discovery and smoke tests: one call answers "what analysis can this
    build do?" without importing or introspecting every module.

    Returns:
        Dict with keys:

        * ``'package'`` - dotted package name.
        * ``'modules'`` - mapping of module name to its exported
          callables/classes.
        * ``'module_count'`` / ``'function_count'`` - inventory tallies.
        * ``'stdlib_only'`` - always True (the zero-dependency guarantee).
        * ``'python_requires'`` - minimum supported interpreter.

    Example:
        >>> summary = analytics_summary()
        >>> summary['module_count'], summary['stdlib_only']
        (10, True)
    """
    return {
        'package': 'obscuralens.analytics',
        'modules': {name: list(entries) for name, entries in _CAPABILITIES.items()},
        'module_count': len(_CAPABILITIES),
        'function_count': sum(len(entries) for entries in _CAPABILITIES.values()),
        'stdlib_only': True,
        'python_requires': '3.9',
    }
