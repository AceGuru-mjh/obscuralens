"""
Tests for the v6.0 Part 2 analytics package and its wiring.

Ten module groups exercise the pure functions (stats, timeseries, anomaly,
cluster, similarity, textmetrics, graphmetrics, geoanalytics, predict,
enrich); three wiring groups exercise the CLI ``analytics`` command group,
the ``/api/analytics/*`` web endpoints and the ``analytics_*`` MCP tools.
Everything runs offline - the only side effect is writing a few rows into
the shared test-history database for the enrich/web-history tests, exactly
like the existing history/timeline tests do.
"""

import json

import pytest

from obscuralens import commands
from obscuralens.analytics import (
    AnomalyScore,
    ClusterResult,
    GeoPoint,
    LinearModel,
    TimeSeriesPoint,
    activity_anomalies,
    betweenness_centrality,
    bounding_box,
    bridges,
    build_adjacency,
    centroid,
    char_profile,
    classify,
    cluster_points,
    cluster_summary,
    coefficient_of_variation,
    connected_components,
    cosine_similarity,
    cumulative_sum,
    dbscan,
    degree_centrality,
    detect_anomalies,
    detect_changepoints,
    detect_language_script,
    detrend,
    dice_coefficient,
    distance_matrix,
    enrichment_report,
    ensemble_anomalies,
    evaluate_binary,
    ewma,
    extract_keywords,
    field_count_distribution,
    fit_linear,
    fit_logistic,
    geo_summary,
    geofence_check,
    graph_summary,
    grubbs_test,
    hierarchical,
    histogram,
    history_points,
    hour_of_day_profile,
    iqr,
    iqr_anomalies,
    jaro,
    jaro_winkler,
    kind_frequency,
    kmeans,
    kurtosis,
    label_propagation_communities,
    levenshtein,
    levenshtein_ratio,
    linear_trend,
    mad_anomalies,
    mean,
    median,
    metaphone_hint,
    min_max_range,
    mode,
    most_similar,
    moving_average,
    ngram_similarity,
    ngrams,
    normalize_points,
    optimal_eps,
    outlier_points,
    pagerank,
    pairwise_distances,
    percentile,
    predict_linear,
    predict_logistic,
    pstdev,
    quartiles,
    rate_of_change,
    readability,
    redaction_sweep,
    resample_daily,
    robust_zscore,
    route_length,
    seasonality_hint,
    series_summary,
    shannon_entropy,
    shortest_path,
    silhouette_score,
    simple_forecast,
    skewness,
    soundex,
    source_reliability,
    stdev,
    success_rate_by_kind,
    summarize,
    summarize_text,
    term_frequencies,
    text_similarity_report,
    tfidf,
    threshold_anomalies,
    to_points,
    tokenize,
    top_entities,
    top_targets,
    typosquat_score,
    value_counts,
    variance,
    weekday_profile,
    zscore,
    zscore_anomalies,
)

# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

class TestStats:
    """Descriptive statistics: centres, spread, shape, tables, entropy."""

    def test_mean_and_median(self):
        assert mean([1, 2, 3, 4]) == 2.5
        assert median([5, 1, 3]) == 3
        assert median([1, 2, 3, 4]) == 2.5

    def test_mean_drops_non_numeric(self):
        assert mean(['a', 2, None, 4.0]) == 3.0
        assert mean([]) is None
        assert mean(None) is None

    def test_mode_ties_and_single(self):
        assert mode([1, 1, 2, 3]) == [1.0]
        assert mode([5]) == [5.0]
        assert mode([1, 1, 2, 2]) == [1.0, 2.0]
        assert mode([]) == []

    def test_variance_sample_vs_population(self):
        assert variance([1, 2, 3]) == 1.0
        assert variance([1, 2, 3], sample=False) == pytest.approx(2.0 / 3.0)
        assert stdev([1, 2, 3]) == 1.0
        assert pstdev([1, 2, 3]) == pytest.approx(0.8164965, rel=1e-6)

    def test_coefficient_of_variation(self):
        assert coefficient_of_variation([2, 4, 6]) == pytest.approx(0.5)
        assert coefficient_of_variation([]) is None

    def test_percentile_linear_interpolation(self):
        assert percentile([1, 2, 3, 4], 50) == 2.5
        assert percentile([1, 2, 3, 4], 0) == 1
        assert percentile([1, 2, 3, 4], 100) == 4
        assert percentile([], 50) is None

    def test_quartiles_numpy_compatible(self):
        assert quartiles([1, 2, 3, 4]) == (1.75, 2.5, 3.25)
        assert quartiles([]) is None

    def test_iqr(self):
        assert iqr([1, 2, 3, 4]) == pytest.approx(1.5)
        assert iqr([]) is None

    def test_skewness_symmetric_zero_and_right_skew(self):
        assert skewness([1, 2, 3]) == pytest.approx(0.0, abs=1e-12)
        assert skewness([2, 2, 2, 2, 9]) > 1.0
        assert skewness([1, 2]) is None

    def test_kurtosis_flat_below_normal(self):
        assert kurtosis([1, 2, 3, 4, 5]) == pytest.approx(-1.2)
        assert kurtosis([1, 2]) is None

    def test_min_max_range(self):
        span = min_max_range([3, 1, 2])
        assert span == {'min': 1.0, 'max': 3.0, 'range': 2.0,
                        'midpoint': 2.0}
        assert min_max_range([]) is None

    def test_summarize_key_completeness(self):
        summary = summarize([2, 2, 2, 2, 9])
        assert set(summary) == {'count', 'mean', 'median', 'stdev', 'min',
                                'max', 'q1', 'q3', 'iqr', 'skew', 'kurt'}
        assert summary['count'] == 5.0
        assert summary['mean'] == pytest.approx(3.4)
        assert summary['stdev'] is not None

    def test_summarize_empty_and_single(self):
        empty = summarize([])
        assert empty['count'] == 0.0
        assert empty['mean'] is None
        single = summarize([7])
        assert single['mean'] == 7.0
        assert single['stdev'] is None

    def test_histogram_bins_and_counts(self):
        hist = histogram([1, 2, 3, 4, 5], bins=2)
        assert hist['bin_counts'] == [2, 3]
        assert len(hist['bin_edges']) == 3
        assert hist['bin_labels'][-1].endswith(']')

    def test_histogram_constant_data_uses_unit_span(self):
        hist = histogram([5, 5, 5], bins=4)
        assert hist['bin_counts'] == [3, 0, 0, 0]

    def test_histogram_invalid_bins_empty(self):
        assert histogram([1, 2], bins=0)['bin_counts'] == []
        assert histogram([], bins=5)['bin_counts'] == []

    def test_value_counts_ordering(self):
        counts = value_counts([1, 1, 2])
        assert counts[0] == {'value': 1.0, 'count': 2,
                             'percentage': pytest.approx(66.6667, rel=1e-3)}
        assert counts[1]['value'] == 2.0

    def test_shannon_entropy_binary_split(self):
        assert shannon_entropy([1, 2]) == pytest.approx(1.0)
        assert shannon_entropy([1, 1, 2, 2]) == pytest.approx(1.0)
        assert shannon_entropy([1, 2, 3, 4]) == pytest.approx(2.0)
        assert shannon_entropy([7, 7]) == 0.0
        assert shannon_entropy([]) is None

    def test_zscore_and_robust_zscore(self):
        assert zscore(3, [1, 2, 3, 4, 5]) == pytest.approx(0.0, abs=1e-12)
        assert robust_zscore(100, [1, 2, 3, 4, 100]) > 10.0
        assert zscore(1, [1, 1]) is None


# ---------------------------------------------------------------------------
# timeseries
# ---------------------------------------------------------------------------

class TestTimeseries:
    """Time-series workups: parsing, smoothing, trend, changepoints."""

    def test_to_points_tuples_sorted_ascending(self):
        points = to_points([(2, 5.0), (1, 3.0)])
        assert points[0].value == 3.0
        assert isinstance(points[0], TimeSeriesPoint)

    def test_to_points_dict_keys(self):
        assert to_points([{'ts': 0, 'v': 4}])[0].value == 4.0
        assert to_points([{'time': 1, 'y': 2.0}])[0].value == 2.0

    def test_to_points_labelled_rows(self):
        point = to_points([(1, 2, 'lbl')])[0]
        assert point.label == 'lbl'

    def test_to_points_defensive_garbage(self):
        assert to_points(None) == []
        assert to_points(42) == []
        assert to_points('nope') == []
        assert to_points([('a', 1)]) == []
        assert to_points([{'garbage': 1}]) == []
        assert to_points([[1, 2], 'x', None]) == [(to_points([[1, 2]])[0])]

    def test_moving_average_window_sizes(self):
        points = to_points([(0, 1.0), (1, 2.0), (2, 3.0)])
        assert len(moving_average(points, window=1)) == 3
        averaged = moving_average(points, window=2)
        assert [p.value for p in averaged] == [1.5, 2.5]
        assert moving_average(points, window=5) == []
        assert moving_average(points, window=0) == []

    def test_ewma_alpha_edges(self):
        points = to_points([(0, 1.0), (1, 2.0)])
        assert [p.value for p in ewma(points, alpha=1.0)] == [1.0, 2.0]
        assert ewma(points, alpha=0.0) == []

    def test_linear_trend_directions(self):
        rising = linear_trend(to_points([(0, 1.0), (1, 2.0), (2, 3.0)]))
        assert rising['trend_direction'] == 'rising'
        assert rising['slope'] == pytest.approx(1.0)
        falling = linear_trend(to_points([(0, 9.0), (1, 6.0), (2, 3.0)]))
        assert falling['trend_direction'] == 'falling'
        flat = linear_trend(to_points([(0, 5.0), (1, 5.0), (2, 5.0)]))
        assert flat['trend_direction'] == 'flat'
        assert linear_trend([]) is None

    def test_detrend_removes_linear_component(self):
        residuals = detrend(to_points([(0, 1.0), (86400, 2.0),
                                       (86400 * 2, 3.0)]))
        assert all(abs(r.value) < 1e-6 for r in residuals)

    def test_cumulative_sum(self):
        running = cumulative_sum(to_points([(0, 1.0), (1, 2.0), (2, 3.0)]))
        assert [p.value for p in running] == [1.0, 3.0, 6.0]

    def test_rate_of_change_per_day(self):
        changes = rate_of_change(to_points([(0, 10.0), (86400, 20.0)]))
        assert changes[0].value == pytest.approx(10.0)

    def test_detect_changepoints_catches_level_shift(self):
        values = [5, 6, 5, 6, 5, 6, 5, 6, 20, 21, 20, 21]
        events = detect_changepoints(to_points(list(zip(range(12), values))))
        assert events
        assert events[0]['direction'] == 'up'
        assert events[0]['index'] == 8

    def test_detect_changepoints_constant_series_none(self):
        assert detect_changepoints(to_points([(i, 1.0) for i in range(8)])) == []

    def test_resample_daily_aggregates_by_utc_day(self):
        daily = resample_daily(to_points([(0, 5.0), (3600, 7.0), (86400, 9.0)]))
        assert [p.value for p in daily] == [6.0, 9.0]
        assert daily[0].label == '1970-01-01'

    def test_seasonality_hint_verdicts(self):
        seasonal = seasonality_hint(
            to_points([(i, float(i % 7)) for i in range(28)]), 7)
        assert seasonal['verdict'] == 'seasonal'
        drifting = seasonality_hint(
            to_points([(i, float(i)) for i in range(28)]), 7)
        assert drifting['verdict'] == 'not_seasonal'

    def test_series_summary_keys_and_direction(self):
        summary = series_summary(to_points([(0, 1.0), (86400, 3.0)]))
        assert set(summary) == {'count', 'first_timestamp', 'last_timestamp',
                                'span_days', 'trend', 'direction', 'mean',
                                'variance', 'changepoint_count'}
        assert summary['count'] == 2
        assert summary['direction'] == 'rising'
        assert summary['span_days'] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# anomaly
# ---------------------------------------------------------------------------

class TestAnomaly:
    """Outlier detectors: z-score, IQR fences, MAD, Grubbs, ensemble."""

    def test_zscore_extreme_value_detected(self):
        hits = zscore_anomalies([10.0] * 20 + [100.0])
        assert [hit.value for hit in hits] == [100.0]
        assert hits[0].method == 'zscore'
        assert isinstance(hits[0].detail.get('index'), int)

    def test_zscore_masking_on_small_sample(self):
        # One 10000 in five observations inflates the stdev enough to hide
        # itself - the classic z-score masking failure.
        assert zscore_anomalies([1.0, 2.0, 3.0, 4.0, 10000.0]) == []

    def test_iqr_fences_flag_outlier(self):
        hits = iqr_anomalies([1, 2, 3, 4, 100])
        assert len(hits) == 1
        assert hits[0].value == 100.0
        assert hits[0].detail['q1'] == 2.0
        assert hits[0].detail['q3'] == 4.0
        assert hits[0].detail['upper_fence'] == 7.0
        assert hits[0].detail['direction'] == 'high'

    def test_mad_robust_against_masking(self):
        # The same masked sequence the z-score missed: MAD still finds it.
        hits = mad_anomalies([1.0, 2.0, 3.0, 4.0, 10000.0])
        assert [hit.value for hit in hits] == [10000.0]
        assert hits[0].method == 'mad'

    def test_mad_clean_series_empty(self):
        assert mad_anomalies([10.0] * 20 + [11.0]) == []

    def test_grubbs_single_outlier_and_clean_none(self):
        hit = grubbs_test([1, 2, 3, 4, 100])
        assert hit is not None
        assert hit.value == 100.0
        assert hit.method == 'grubbs'
        assert grubbs_test([1.0, 2.0, 3.0, 4.0, 5.0]) is None

    def test_ensemble_voting_requires_agreement(self):
        hits = ensemble_anomalies([1, 2, 3, 4, 100])
        assert len(hits) == 1
        assert hits[0].method == 'ensemble'
        assert hits[0].detail['votes'] >= 2
        assert sorted(hits[0].detail['methods_hit']) == ['iqr', 'mad']

    def test_detect_anomalies_dispatches_every_method(self):
        values = [1, 2, 3, 4, 100]
        assert detect_anomalies(values, method='zscore') == []
        assert len(detect_anomalies(values, method='iqr')) == 1
        assert len(detect_anomalies(values, method='mad')) == 1
        assert grubbs_test(values) is not None
        assert len(detect_anomalies(values, method='ensemble')) == 1

    def test_detect_anomalies_unknown_method_returns_empty(self):
        assert detect_anomalies([1, 2, 3], method='nope') == []

    def test_detect_anomalies_forwards_threshold(self):
        assert len(detect_anomalies(
            [1, 2, 3, 4, 100], method='zscore', threshold=1.0)) == 1

    def test_small_samples_return_empty(self):
        assert zscore_anomalies([1, 2]) == []
        assert mad_anomalies([1.0]) == []
        assert ensemble_anomalies([1, 2]) == []

    def test_threshold_anomalies_bounds(self):
        hits = threshold_anomalies([1, 2, 99], floor=0, ceiling=10)
        assert [hit.value for hit in hits] == [99.0]
        assert hits[0].detail['bound'] == 'ceiling'

    def test_anomaly_score_record_shape(self):
        record = AnomalyScore(value=5.0, score=1.0, method='zscore',
                              detail={'index': 0})
        assert (record.value, record.score, record.method) == (5.0, 1.0,
                                                               'zscore')


# ---------------------------------------------------------------------------
# cluster
# ---------------------------------------------------------------------------

class TestCluster:
    """Unsupervised grouping: DBSCAN, k-means, hierarchical, scoring."""

    def test_dbscan_two_clusters_with_noise(self):
        points = [[0, 0], [0.5, 0], [10, 10], [10.5, 10], [50, 50]]
        result = dbscan(points, eps=1.0, min_samples=2)
        assert isinstance(result, ClusterResult)
        assert result.assignments[0] == result.assignments[1]
        assert result.assignments[2] == result.assignments[3]
        assert result.assignments[0] != result.assignments[2]
        assert result.assignments[4] == -1
        assert result.noise_count == 1
        assert result.sizes == [2, 2]
        assert result.method == 'dbscan'

    def test_dbscan_malformed_input_empty_result(self):
        result = dbscan([[0, 0], [1, 'x'], [2, 2]])
        assert result.assignments == [] and result.noise_count == 0
        assert dbscan(None).assignments == []
        assert dbscan([[0, 0], [1, 2, 3]]).assignments == []

    def test_kmeans_deterministic_with_same_seed(self):
        points = [[0, 0], [0.5, 0], [10, 10], [10.5, 10], [0, 0.5],
                  [10, 10.5]]
        first = kmeans(points, k=2, seed=7)
        second = kmeans(points, k=2, seed=7)
        assert first.assignments == second.assignments
        assert first.centroids == second.centroids

    def test_kmeans_finds_true_centroids(self):
        points = [[0, 0], [0.5, 0], [10, 10], [10.5, 10], [0, 0.5],
                  [10, 10.5]]
        result = kmeans(points, k=2, seed=7)
        centroids = sorted(result.centroids)
        assert centroids[0] == pytest.approx([0.1667, 0.1667], abs=1e-3)
        assert centroids[1] == pytest.approx([10.1667, 10.1667], abs=1e-3)
        assert result.method == 'kmeans'
        assert sum(result.sizes) == 6

    def test_hierarchical_threshold_cut(self):
        result = hierarchical([[0, 0], [0.4, 0], [10, 10], [10.4, 10],
                               [5, 5]], threshold=1.0)
        assert result.assignments[:2] == [result.assignments[0]] * 2
        assert result.assignments[2:4] == [result.assignments[2]] * 2
        assert result.assignments[4] not in (result.assignments[0],
                                             result.assignments[2])
        assert result.method == 'hierarchical'

    def test_silhouette_single_cluster_none(self):
        assert silhouette_score([[0, 0], [1, 1]], [0, 0]) is None

    def test_silhouette_two_tight_clusters_high(self):
        score = silhouette_score([[0, 0], [0.1, 0], [10, 10], [10.1, 10]],
                                 [0, 0, 1, 1])
        assert score > 0.9

    def test_optimal_eps_positive(self):
        assert optimal_eps([[0, 0], [0.5, 0], [10, 10], [10.5, 10]]) > 0.0

    def test_cluster_summary_dossier(self):
        points = [[0, 0], [1, 0], [10, 10], [11, 10]]
        result = dbscan(points, eps=2, min_samples=2)
        dossier = cluster_summary(points, result)
        assert set(dossier) == {'method', 'n_points', 'n_clusters',
                                'clusters', 'noise_count', 'noise_ratio'}
        assert dossier['n_points'] == 4
        assert dossier['n_clusters'] == 2
        assert dossier['clusters'][0]['size'] == 2
        assert 'centroid' in dossier['clusters'][0]

    def test_normalize_points_scales_each_dimension(self):
        normalized = normalize_points([[0, 5], [0, 7], [1, 5], [1, 7]])
        assert normalized == [[-1.0, -1.0], [-1.0, 1.0], [1.0, -1.0],
                              [1.0, 1.0]]

    def test_normalize_points_zero_variance_dimension(self):
        normalized = normalize_points([[0, 3], [0, 3], [1, 3]])
        # The constant dimension passes through untouched; the varying one
        # is standardised (mean zero).
        assert [row[1] for row in normalized] == [3.0, 3.0, 3.0]
        assert abs(sum(row[0] for row in normalized)) < 1e-9

    def test_normalize_malformed_input(self):
        assert normalize_points(None) == []
        assert normalize_points([]) == []
        assert normalize_points(['junk']) == []

    def test_kmeans_malformed_returns_empty(self):
        result = kmeans([[0], [1], ['x']], k=2)
        assert result.assignments == []


# ---------------------------------------------------------------------------
# similarity
# ---------------------------------------------------------------------------

class TestSimilarity:
    """String metrics for identity resolution and squat screening."""

    def test_levenshtein_classic_pairs(self):
        assert levenshtein('kitten', 'sitting') == 3
        assert levenshtein('flaw', 'lawn') == 2

    def test_levenshtein_empty_strings(self):
        assert levenshtein('', '') == 0
        assert levenshtein('abc', '') == 3

    def test_levenshtein_casefolds_by_default(self):
        assert levenshtein('ABC', 'abc') == 0
        assert levenshtein('ABC', 'abc', casefold=False) == 3
        assert levenshtein('kitten', 'sitting') == 3

    def test_levenshtein_ratio(self):
        assert levenshtein_ratio('kitten', 'sitting') == pytest.approx(
            0.5714, rel=1e-3)

    def test_jaro_martha_marhta(self):
        assert jaro('MARTHA', 'MARHTA') == pytest.approx(0.9444, rel=1e-3)
        assert jaro('ABC', 'abc', casefold=False) == 0.0
        assert jaro('ABC', 'abc') == 1.0

    def test_jaro_winkler_dwayne_duane(self):
        assert jaro_winkler('DWAYNE', 'DUANE') == pytest.approx(0.84)
        assert jaro_winkler('martha', 'marhta') > jaro('martha', 'marhta')

    def test_soundex_robert_rupert(self):
        assert soundex('Robert') == 'R163'
        assert soundex('Rupert') == 'R163'
        assert soundex('Ashcraft') != soundex('Robert')

    def test_soundex_edge_cases(self):
        assert soundex('') == ''
        assert soundex(None) == ''

    def test_metaphone_hint(self):
        assert metaphone_hint('robert') == 'ROBERT'
        assert metaphone_hint('') == ''

    def test_ngram_similarity(self):
        assert ngram_similarity('night', 'nacht') == pytest.approx(
            0.142857, rel=1e-3)
        assert ngram_similarity('same', 'same') == 1.0

    def test_dice_coefficient(self):
        assert dice_coefficient('night', 'nacht') == 0.25
        assert dice_coefficient('abc', 'abc') == 1.0

    def test_cosine_similarity_sparse_vectors(self):
        assert cosine_similarity({'a': 1, 'b': 1}, {'a': 1, 'b': 1}) == \
            pytest.approx(1.0)
        assert cosine_similarity({'a': 1}, {'b': 1}) == 0.0
        assert cosine_similarity({}, {}) == 0.0

    def test_most_similar_ranking(self):
        ranked = most_similar('paypal', ['paypa1', 'paypal', 'gnome'])
        assert [entry['value'] for entry in ranked[:2]] == ['paypal', 'paypa1']
        assert ranked[0]['score'] == 1.0
        assert ranked[0]['method'] == 'jaro_winkler'

    def test_most_similar_unknown_method_empty(self):
        assert most_similar('a', ['b'], method='nope') == []

    def test_typosquat_scores(self):
        assert typosquat_score('paypa1.com', 'paypal.com') > 0.85
        assert typosquat_score('google.com', 'paypal.com') < 0.5
        assert typosquat_score('example.com', 'example.com') == 1.0

    def test_similarity_non_string_inputs_safe(self):
        assert levenshtein(None, None) == 0
        assert jaro(None, None) == 1.0
        assert 0.0 <= typosquat_score(None, None) <= 1.0


# ---------------------------------------------------------------------------
# textmetrics
# ---------------------------------------------------------------------------

class TestTextMetrics:
    """Prose analytics: tokens, TF-IDF, keywords, readability, language."""

    def test_tokenize_lowercases_and_strips_punctuation(self):
        assert tokenize('Hello, World! hello') == ['hello', 'world', 'hello']

    def test_tokenize_defensive(self):
        assert tokenize(None) == []
        assert tokenize(123) == []

    def test_ngrams_join_tokens(self):
        assert ngrams(['a', 'b', 'c'], n=2) == ['a b', 'b c']
        assert ngrams(['a'], n=2) == []

    def test_term_frequencies(self):
        assert term_frequencies(['a', 'a', 'b']) == {'a': 2, 'b': 1}

    def test_tfidf_rare_word_outweighs_common(self):
        scores = tfidf([['rare', 'common'], ['common', 'common']])
        assert scores[0]['rare'] > scores[0]['common']

    def test_extract_keywords_filters_stopwords(self):
        keywords = extract_keywords(
            'the quick brown fox jumps over the lazy dog', top=3)
        terms = [entry['term'] for entry in keywords]
        assert 'the' not in terms
        assert set(terms) <= {'quick', 'brown', 'fox', 'jumps', 'lazy',
                              'dog'}
        assert keywords[0]['count'] >= 1

    def test_readability_ranges_and_keys(self):
        report = readability('The cat sat. The dog ran. It was good.')
        assert set(report) == {'flesch_reading_ease', 'flesch_kincaid_grade',
                               'flesch_label', 'sentences', 'words',
                               'syllables', 'avg_words_per_sentence',
                               'avg_syllables_per_word'}
        assert report['sentences'] == 3
        assert report['flesch_reading_ease'] >= 0.0
        assert isinstance(report['flesch_label'], str)

    @pytest.mark.parametrize('sample,expected', [
        ('The quick brown fox jumps over the lazy dog near the river',
         'en'),
        ('Der schnelle braune Fuchs springt uber den faulen Hund', 'de'),
        ('Le renard brun rapide saute par-dessus le chien paresseux', 'fr'),
        ('El zorro marron rapido salta sobre el perro perezoso', 'es'),
        ('Это не так и он не знает что это', 'ru'),
        ('这是一个测试', 'zh'),
        ('これは テスト です', 'ja'),
        ('이 것 은 우리 의 집 이다', 'ko'),
    ])
    def test_detect_language_script_eight_languages(self, sample, expected):
        profile = detect_language_script(sample)
        assert profile['language_guess'] == expected
        assert profile['confidence'] > 0.0

    def test_detect_language_script_dominant_scripts(self):
        assert detect_language_script('Привет')['dominant_script'] == 'Cyrillic'
        assert detect_language_script('こんにちは')['dominant_script'] == \
            'Hiragana'
        assert detect_language_script('안녕하세요')['dominant_script'] == \
            'Hangul'

    def test_detect_language_script_empty_input(self):
        profile = detect_language_script('')
        assert profile['dominant_script'] == 'unknown'
        assert profile['language_guess'] is None
        assert sum(profile['script_counts'].values()) == 0
        assert len(profile['script_counts']) == 11

    def test_char_profile_counts(self):
        profile = char_profile('aabbc')
        assert profile['length'] == 5
        assert profile['letters'] == 5
        assert profile['unique_chars'] == 3
        assert profile['digits'] == 0

    def test_char_profile_defensive(self):
        assert char_profile(None)['length'] == 0

    def test_summarize_text_picks_longest_sentences(self):
        text = ('A short sentence. A much longer sentence with many words '
                'here. Another one.')
        summary = summarize_text(text, max_sentences=1)
        assert 'much longer sentence' in summary

    def test_redaction_sweep_email_and_ip(self):
        report = redaction_sweep('mail me at bob@example.com or 8.8.8.8')
        assert report['counts']['emails'] == 1
        assert report['counts']['ipv4'] == 1
        assert '[EMAIL #1]' in report['preview']
        assert '[IPV4 #1]' in report['preview']

    def test_redaction_sweep_clean_text(self):
        report = redaction_sweep('nothing to redact here')
        assert report['total'] == 0

    def test_text_similarity_report_four_metrics(self):
        report = text_similarity_report('kitten', 'sitting')
        assert set(report) == {'jaro_winkler', 'levenshtein_ratio', 'ngram',
                               'cosine', 'mean', 'length_a', 'length_b'}
        assert 0.0 <= report['mean'] <= 1.0
        assert report['length_a'] == 6


# ---------------------------------------------------------------------------
# graphmetrics
# ---------------------------------------------------------------------------

class TestGraphMetrics:
    """Investigation-graph measurements over entities/links payloads."""

    def test_build_adjacency_basic(self):
        adjacency = build_adjacency([{'id': 'a'}, {'id': 'b'}],
                                    [{'source': 'a', 'target': 'b'}])
        assert adjacency == {'a': {'b'}, 'b': {'a'}}

    def test_build_adjacency_dangling_endpoint_registered(self):
        adjacency = build_adjacency([{'id': 'a'}],
                                    [{'source': 'a', 'target': 'zzz'}])
        assert 'zzz' in adjacency

    def test_build_adjacency_self_loop_and_malformed_dropped(self):
        adjacency = build_adjacency(
            [{'id': 'a'}],
            [{'source': 'a', 'target': 'a'}, {'source': 'a'},
             'garbage'])
        assert adjacency == {'a': set()}

    def test_build_adjacency_from_to_keys(self):
        adjacency = build_adjacency([{'id': 'a'}, {'id': 'b'}],
                                    [{'from': 'a', 'to': 'b'}])
        assert adjacency['a'] == {'b'}

    def test_build_adjacency_malformed(self):
        assert build_adjacency(None, None) == {}
        assert build_adjacency('nope', 'nope') == {}
        assert build_adjacency([{'id': ''}], []) == {}

    def test_degree_centrality_star_center_is_one(self):
        entities = [{'id': eid} for eid in ('c', 'l1', 'l2', 'l3', 'l4')]
        links = [{'source': 'c', 'target': leaf}
                 for leaf in ('l1', 'l2', 'l3', 'l4')]
        centrality = degree_centrality(build_adjacency(entities, links))
        assert centrality['c'] == 1.0
        assert centrality['l1'] == 0.25

    def test_pagerank_sums_to_one(self):
        entities = [{'id': eid} for eid in ('a', 'b', 'c')]
        links = [{'source': 'a', 'target': 'b'},
                 {'source': 'b', 'target': 'c'}]
        ranks = pagerank(build_adjacency(entities, links))
        assert sum(ranks.values()) == pytest.approx(1.0)
        assert ranks['b'] > ranks['a']

    def test_betweenness_centrality_bridge_node(self):
        entities = [{'id': eid} for eid in ('a', 'b', 'c')]
        links = [{'source': 'a', 'target': 'b'},
                 {'source': 'b', 'target': 'c'}]
        scores = betweenness_centrality(build_adjacency(entities, links))
        assert scores['b'] == 1.0
        assert scores['a'] == 0.0

    def test_connected_components_islands(self):
        entities = [{'id': eid} for eid in ('a', 'b', 'c')]
        links = [{'source': 'a', 'target': 'b'}]
        components = connected_components(build_adjacency(entities, links))
        assert sorted(components) == [['a', 'b'], ['c']]

    def test_label_propagation_two_cliques(self):
        entities = [{'id': eid} for eid in ('a', 'b', 'c', 'd', 'e', 'f')]
        links = [{'source': 'a', 'target': 'b'},
                 {'source': 'a', 'target': 'c'},
                 {'source': 'b', 'target': 'c'},
                 {'source': 'd', 'target': 'e'},
                 {'source': 'd', 'target': 'f'},
                 {'source': 'e', 'target': 'f'}]
        communities = label_propagation_communities(
            build_adjacency(entities, links))
        assert sorted(map(sorted, communities)) == \
            [['a', 'b', 'c'], ['d', 'e', 'f']]

    def test_top_entities_ranking(self):
        entities = [{'id': eid} for eid in ('c', 'l1', 'l2')]
        links = [{'source': 'c', 'target': 'l1'},
                 {'source': 'c', 'target': 'l2'}]
        ranked = top_entities(build_adjacency(entities, links), top=2)
        assert ranked[0]['id'] == 'c'
        assert ranked[0]['degree'] == 2
        assert set(ranked[0]) == {'id', 'degree', 'degree_centrality',
                                  'pagerank', 'betweenness'}

    def test_bridges_path_graph_every_edge(self):
        entities = [{'id': eid} for eid in ('a', 'b', 'c', 'd')]
        links = [{'source': 'a', 'target': 'b'},
                 {'source': 'b', 'target': 'c'},
                 {'source': 'c', 'target': 'd'}]
        found = bridges(build_adjacency(entities, links))
        assert sorted(found) == [('a', 'b'), ('b', 'c'), ('c', 'd')]

    def test_shortest_path_length_and_unreachable(self):
        entities = [{'id': eid} for eid in ('a', 'b', 'c', 'd')]
        links = [{'source': 'a', 'target': 'b'},
                 {'source': 'b', 'target': 'c'},
                 {'source': 'c', 'target': 'd'}]
        adjacency = build_adjacency(entities, links)
        assert shortest_path(adjacency, 'a', 'd') == ['a', 'b', 'c', 'd']
        assert shortest_path(adjacency, 'a', 'zzz') is None

    def test_graph_summary_key_completeness(self):
        summary = graph_summary([{'id': 'a'}, {'id': 'b'}, {'id': 'c'}],
                                [{'source': 'a', 'target': 'b'},
                                 {'source': 'b', 'target': 'c'}])
        assert set(summary) == {'node_count', 'edge_count', 'density',
                                'avg_degree', 'component_count',
                                'largest_component_size', 'community_count',
                                'top_entities', 'bridge_count', 'bridges',
                                'isolated_nodes'}
        assert summary['node_count'] == 3
        assert summary['bridge_count'] == 2

    def test_graph_summary_empty_graph(self):
        summary = graph_summary([], [])
        assert summary['node_count'] == 0
        assert summary['top_entities'] == []
        assert summary['density'] == 0.0


# ---------------------------------------------------------------------------
# geoanalytics
# ---------------------------------------------------------------------------

class TestGeoAnalytics:
    """Spatial analytics over GeoPoint sets."""

    def test_bounding_box(self):
        box = bounding_box([[52.0, 13.0], [52.2, 13.2], [52.1, 13.1]])
        assert box['min_lat'] == 52.0
        assert box['max_lat'] == 52.2
        assert box['min_lon'] == 13.0
        assert box['max_lon'] == 13.2

    def test_bounding_box_empty(self):
        assert bounding_box([]) is None
        assert bounding_box(None) is None

    def test_centroid(self):
        assert centroid([[52.0, 13.0], [52.2, 13.2]]) == (52.1, 13.1)

    def test_pairwise_distances_ascending(self):
        distances = pairwise_distances([[0, 0], [0, 1], [0, 2]])
        kilometres = [entry['km'] for entry in distances]
        assert kilometres == sorted(kilometres)
        assert all(entry['km'] > 0 for entry in distances)
        assert {'a', 'b', 'label_a', 'label_b', 'km'} == \
            set(distances[0])

    def test_cluster_points_groups_nearby(self):
        clusters = cluster_points(
            [[52.0, 13.0], [52.01, 13.01], [52.02, 13.02], [48.0, 2.0]],
            eps_km=25)
        assert len(clusters) == 1
        assert clusters[0]['size'] == 3
        assert set(clusters[0]) == {'centroid', 'members', 'size',
                                    'radius_km', 'labels'}

    def test_geofence_inside_and_outside(self):
        inside = geofence_check([52.0, 13.0], [52.0, 13.0], 10)
        assert inside['inside'] is True
        assert inside['distance_km'] == 0.0
        outside = geofence_check([53.0, 14.0], [52.0, 13.0], 10)
        assert outside['inside'] is False

    def test_outlier_points_flags_far_point(self):
        flagged = outlier_points([[52.0, 13.0], [52.0, 13.01],
                                  [52.0, 13.02], [60.0, 20.0]])
        assert [entry['index'] for entry in flagged] == [3]
        assert flagged[0]['distance_km'] > 500.0

    def test_distance_matrix_symmetric(self):
        matrix = distance_matrix([[52.0, 13.0], [52.1, 13.1]])
        assert matrix['point_0']['point_1'] == matrix['point_1']['point_0']

    def test_route_length(self):
        length = route_length([[52.0, 13.0], [52.1, 13.1], [52.2, 13.2]])
        assert length == pytest.approx(26.1, rel=1e-2)

    def test_geo_summary_keys(self):
        summary = geo_summary([[52.0, 13.0], [52.1, 13.1]])
        assert set(summary) == {'point_count', 'bounding_box', 'centroid',
                                'farthest_pair', 'average_pair_distance_km',
                                'cluster_count', 'clusters',
                                'route_length_km'}
        assert summary['point_count'] == 2

    def test_geo_summary_empty(self):
        summary = geo_summary([])
        assert summary['point_count'] == 0
        assert summary['bounding_box'] is None
        assert summary['clusters'] == []

    def test_malformed_points_safe(self):
        assert pairwise_distances([[0, 0], ['x', 1]]) == []
        assert cluster_points([[52.0, 13.0], 'junk']) == []
        # Single-coordinate rows are not [lat, lon] pairs: dropped, not fatal.
        assert geo_summary([[52.0], [13.0]])['point_count'] == 0

    def test_geopoint_record(self):
        point = GeoPoint(lat=52.0, lon=13.0, label='home')
        assert (point.lat, point.lon, point.label) == (52.0, 13.0, 'home')


# ---------------------------------------------------------------------------
# predict
# ---------------------------------------------------------------------------

class TestPredict:
    """Screening-grade models: linear, logistic, forecast, evaluation."""

    def test_fit_linear_perfect_line_r_squared(self):
        model = fit_linear([[1], [2], [3], [4], [5]], [2, 4, 6, 8, 10])
        assert isinstance(model, LinearModel)
        assert model.r_squared > 0.99

    def test_predict_linear_value(self):
        model = fit_linear([[1], [2], [3], [4], [5]], [2, 4, 6, 8, 10])
        assert predict_linear(model, [6]) == pytest.approx(12.0, abs=0.2)

    def test_fit_linear_too_few_samples(self):
        assert fit_linear([[1], [2]], [1, 2]) is None
        assert fit_linear([], []) is None

    def test_fit_logistic_separable_accuracy(self):
        model = fit_logistic([[0], [0.5], [1], [2], [8], [9], [10], [11]],
                             [0, 0, 0, 0, 1, 1, 1, 1])
        assert model is not None
        assert model.r_squared > 0.8

    def test_predict_logistic_within_unit_interval(self):
        model = fit_logistic([[0], [0.5], [1], [2], [8], [9], [10], [11]],
                             [0, 0, 0, 0, 1, 1, 1, 1])
        assert 0.0 <= predict_logistic(model, [0.2]) < 0.5
        assert 0.5 < predict_logistic(model, [10]) <= 1.0

    def test_classify_threshold_decisions(self):
        model = fit_logistic([[0], [0.5], [1], [2], [8], [9], [10], [11]],
                             [0, 0, 0, 0, 1, 1, 1, 1])
        assert classify(model, [0.2]) == 0
        assert classify(model, [10]) == 1
        assert classify(model, [3], threshold=0.9) == 0

    def test_fit_logistic_rejects_non_binary_labels(self):
        assert fit_logistic([[1], [2], [3], [4], [5]], [1, 2, 3, 4, 5]) \
            is None

    def test_simple_forecast_rising_series(self):
        forecast = simple_forecast([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        assert forecast['trend'] == 'rising'
        assert forecast['forecasts'][0] > 10.0
        assert forecast['confidence'] == 'low'

    def test_simple_forecast_defensive(self):
        empty = simple_forecast([])
        assert empty['trend'] == 'unknown'
        assert empty['forecasts'] == []
        assert empty['n'] == 0

    def test_evaluate_binary_zero_division_safe(self):
        report = evaluate_binary([0, 0], [1, 1])
        assert report['precision'] == 0.0
        assert report['recall'] == 0.0
        assert report['f1'] == 0.0
        assert report['fn'] == 2

    def test_evaluate_binary_perfect(self):
        report = evaluate_binary([1, 1, 0, 0], [1, 1, 0, 0])
        assert report['accuracy'] == 1.0
        assert report['precision'] == 1.0
        assert report['tp'] == 2 and report['tn'] == 2

    def test_predict_malformed_inputs(self):
        model = fit_linear([[1], [2], [3], [4], [5]], [2, 4, 6, 8, 10])
        assert predict_linear(model, [[6]]) is None
        assert predict_linear('nope', [6]) is None
        assert predict_linear(model, ['x']) is None

    def test_fit_linear_dimension_mismatch(self):
        assert fit_linear([[1, 2], [1, 2]], [1, 2]) is None


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

@pytest.fixture()
def history_rows():
    """A few ip/phone rows with mixed success, written into the shared db."""
    from obscuralens.database import db

    db.save_query('ip', '203.0.113.7', {
        'ip': '203.0.113.7',
        'sources_ok': ['ipwho.is', 'ip-api'],
        'sources_failed': {},
        'info': {'country': 'Germany', 'city': 'Berlin'},
    }, True)
    db.save_query('ip', '203.0.113.7', {
        'ip': '203.0.113.7',
        'sources_ok': ['ipwho.is'],
        'sources_failed': {'ip-api': 'timeout'},
    }, True)
    db.save_query('phone', '+4915199887766', {
        'phone': '+4915199887766',
        'sources_ok': [],
        'sources_failed': {'numverify': 'no key'},
    }, False, 'all sources failed')
    return None


class TestEnrich:
    """The read-only bridge from query history to every structure above."""

    def test_kind_frequency_sees_saved_kinds(self, history_rows):
        kinds = [entry['kind'] for entry in kind_frequency(limit=500)]
        assert 'ip' in kinds
        assert 'phone' in kinds
        entry = kind_frequency(limit=500)[0]
        assert set(entry) == {'kind', 'count', 'percentage'}

    def test_kind_frequency_empty_window(self):
        assert kind_frequency(limit=0) == []

    def test_hour_profile_covers_all_day(self, history_rows):
        hours = hour_of_day_profile(limit=500)
        assert len(hours) == 24
        assert [entry['hour'] for entry in hours] == list(range(24))
        assert sum(entry['count'] for entry in hours) > 0

    def test_weekday_profile_covers_all_week(self, history_rows):
        week = weekday_profile(limit=500)
        assert len(week) == 7
        assert week[0]['name'] == 'Monday'

    def test_success_rate_by_kind_fields(self, history_rows):
        rates = success_rate_by_kind(limit=500)
        by_kind = {entry['kind']: entry for entry in rates}
        assert 'ip' in by_kind
        entry = by_kind['ip']
        assert set(entry) == {'kind', 'total', 'succeeded', 'failed',
                              'success_rate'}
        assert entry['total'] >= 2
        assert entry['succeeded'] >= 1

    def test_top_targets_finds_repeated_target(self, history_rows):
        targets = top_targets(limit=500, top=25)
        repeated = [entry for entry in targets
                    if entry['target'] == '203.0.113.7']
        assert repeated
        assert repeated[0]['count'] >= 2
        assert set(repeated[0]) == {'target', 'kind', 'count', 'last_seen'}

    def test_source_reliability_rows(self, history_rows):
        reliability = source_reliability(limit=500)
        sources = {entry['source'] for entry in reliability}
        assert 'ipwho.is' in sources
        entry = [row for row in reliability if row['source'] == 'ip-api'][0]
        assert entry['failed'] >= 1
        assert set(entry) == {'source', 'ok', 'failed', 'total',
                              'reliability'}

    def test_field_count_distribution_shape(self, history_rows):
        distribution = field_count_distribution(limit=500)
        assert set(distribution) == {'count', 'histogram', 'summary'}
        assert distribution['count'] >= 3

    def test_activity_anomalies_is_a_list(self, history_rows):
        assert isinstance(activity_anomalies(limit=500), list)

    def test_history_points_sorted_ascending(self, history_rows):
        points = history_points(limit=500)
        stamps = [point.timestamp for point in points]
        assert stamps == sorted(stamps)
        assert all(isinstance(point, TimeSeriesPoint) for point in points)

    def test_enrichment_report_key_completeness(self, history_rows):
        report = enrichment_report(limit=500)
        assert set(report) == {'total_queries', 'span_days', 'kind_frequency',
                               'hour_profile', 'weekday_profile',
                               'success_rates', 'field_stats',
                               'source_reliability', 'anomalies',
                               'top_targets', 'generated_at'}
        assert report['total_queries'] >= 3
        assert report['span_days'] is not None

    def test_enrichment_report_empty_window_safe(self):
        report = enrichment_report(limit=0)
        assert report['total_queries'] == 0
        assert report['kind_frequency'] == []


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

class TestAnalyticsCLI:
    """The ``obscuralens analytics <analysis>`` command group."""

    def test_stats_table_output(self, capsys):
        assert commands.run(
            ['analytics', 'stats', '--values', '1,2,3,4,100']) == 0
        out = capsys.readouterr().out
        assert 'DESCRIPTIVE STATISTICS' in out
        assert 'mean' in out
        assert 'HISTOGRAM' in out

    def test_stats_json_output(self, capsys):
        assert commands.run(
            ['analytics', 'stats', '--values', '1,2,3', '--bins', '1',
             '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['summary']['mean'] == 2.0
        assert payload['histogram']['bin_counts'] == [3]
        assert payload['values'] == [1.0, 2.0, 3.0]

    def test_stats_bad_values_returns_2(self, capsys):
        assert commands.run(
            ['analytics', 'stats', '--values', '1,2,x']) == 2
        assert 'Error' in capsys.readouterr().err

    def test_stats_missing_values_returns_2(self, capsys):
        assert commands.run(['analytics', 'stats']) == 2

    def test_anomalies_table_and_method(self, capsys):
        assert commands.run(
            ['analytics', 'anomalies', '--values', '1,2,3,4,100',
             '--method', 'iqr']) == 0
        out = capsys.readouterr().out
        assert 'ANOMALIES (IQR)' in out
        assert '100' in out

    def test_anomalies_json_shape(self, capsys):
        assert commands.run(
            ['analytics', 'anomalies', '--values', '1,2,3,4,100',
             '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['anomaly_count'] == 1
        assert payload['anomalies'][0]['method'] == 'ensemble'
        assert payload['anomalies'][0]['detail']['index'] == 4

    def test_anomalies_bad_values_returns_2(self, capsys):
        assert commands.run(
            ['analytics', 'anomalies', '--values', 'nope']) == 2

    def test_timeseries_summary(self, capsys):
        assert commands.run(
            ['analytics', 'timeseries', '--values', '5,6,5,6,20,21']) == 0
        out = capsys.readouterr().out
        assert 'TIME SERIES SUMMARY' in out
        assert 'rising' in out

    def test_clusters_table(self, capsys):
        assert commands.run(
            ['analytics', 'clusters', '--points',
             '52.0,13.0;52.01,13.01;52.02,13.02;48.0,2.0']) == 0
        out = capsys.readouterr().out
        assert 'CLUSTERS' in out
        assert 'point_0' in out

    def test_clusters_bad_points_returns_2(self, capsys):
        assert commands.run(
            ['analytics', 'clusters', '--points', '52.0;13.0']) == 2

    def test_keywords_table(self, capsys):
        assert commands.run(
            ['analytics', 'keywords', '--text',
             'the quick brown fox jumps over the lazy dog',
             '--top', '3']) == 0
        out = capsys.readouterr().out
        assert 'KEYWORDS' in out
        assert 'fox' in out

    def test_keywords_json_excludes_stopwords(self, capsys):
        assert commands.run(
            ['analytics', 'keywords', '--text',
             'the quick brown fox jumps over the lazy dog',
             '--top', '3', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        terms = [entry['term'] for entry in payload['keywords']]
        assert 'the' not in terms
        assert 'fox' in terms

    def test_language_table(self, capsys):
        assert commands.run(
            ['analytics', 'language', '--text',
             'Le renard brun rapide saute']) == 0
        out = capsys.readouterr().out
        assert 'LANGUAGE / SCRIPT' in out
        assert 'fr' in out

    def test_similarity_table_and_json(self, capsys):
        assert commands.run(
            ['analytics', 'similarity', '--a', 'kitten',
             '--b', 'sitting']) == 0
        assert 'TEXT SIMILARITY' in capsys.readouterr().out
        assert commands.run(
            ['analytics', 'similarity', '--a', 'kitten', '--b', 'sitting',
             '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['report']['jaro_winkler'] > 0.5

    def test_similarity_missing_side_returns_2(self, capsys):
        assert commands.run(
            ['analytics', 'similarity', '--a', 'x']) == 2

    def test_graph_entities_links(self, capsys):
        assert commands.run(
            ['analytics', 'graph', '--entities', 'a,b,c',
             '--links', 'a-b,b-c']) == 0
        out = capsys.readouterr().out
        assert 'GRAPH SUMMARY' in out
        assert 'TOP ENTITIES' in out
        assert 'BRIDGES' in out

    def test_graph_json_summary(self, capsys):
        assert commands.run(
            ['analytics', 'graph', '--entities', 'a,b,c',
             '--links', 'a-b,b-c', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['summary']['node_count'] == 3
        assert payload['summary']['bridge_count'] == 2
        assert payload['summary']['top_entities'][0]['id'] == 'b'

    def test_graph_missing_input_returns_2(self, capsys):
        assert commands.run(['analytics', 'graph']) == 2

    def test_history_command(self, history_rows, capsys):
        assert commands.run(['analytics', 'history', '--limit', '100']) == 0
        out = capsys.readouterr().out
        assert 'HISTORY ENRICHMENT' in out
        assert 'KIND FREQUENCY' in out

    def test_history_json(self, history_rows, capsys):
        assert commands.run(
            ['analytics', 'history', '--limit', '100', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['report']['total_queries'] >= 3

    def test_analytics_without_action_returns_2(self, capsys):
        assert commands.run(['analytics']) == 2


# ---------------------------------------------------------------------------
# Web API wiring
# ---------------------------------------------------------------------------

class TestAnalyticsWeb:
    """The /api/analytics/* endpoints (all offline, pure computation)."""

    @pytest.fixture()
    def client(self):
        pytest.importorskip('fastapi')
        pytest.importorskip('httpx')
        from fastapi.testclient import TestClient

        from obscuralens.web import create_app
        return TestClient(create_app())

    def test_stats_endpoint(self, client):
        response = client.post('/api/analytics/stats',
                               json={'values': [1, 2, 3, 4, 100]})
        assert response.status_code == 200
        payload = response.json()
        assert payload['summary']['mean'] == 22.0
        assert payload['count'] == 5
        assert payload['histogram']['bin_counts']

    def test_stats_endpoint_drops_non_numeric(self, client):
        response = client.post('/api/analytics/stats',
                               json={'values': ['a', 2, 4]})
        assert response.status_code == 200
        assert response.json()['count'] == 2

    def test_stats_endpoint_missing_values_400(self, client):
        assert client.post('/api/analytics/stats', json={}).status_code == 400

    def test_stats_endpoint_non_numeric_only_400(self, client):
        response = client.post('/api/analytics/stats',
                               json={'values': ['a', 'b']})
        assert response.status_code == 400

    def test_anomalies_endpoint(self, client):
        response = client.post(
            '/api/analytics/anomalies',
            json={'values': [1, 2, 3, 4, 100], 'method': 'iqr'})
        assert response.status_code == 200
        payload = response.json()
        assert payload['anomaly_count'] == 1
        assert payload['anomalies'][0]['method'] == 'iqr'
        assert set(payload['anomalies'][0]) == \
            {'value', 'score', 'method', 'detail'}

    def test_anomalies_endpoint_ensemble_default(self, client):
        response = client.post('/api/analytics/anomalies',
                               json={'values': [1, 2, 3, 4, 100]})
        assert response.status_code == 200
        assert response.json()['method'] == 'ensemble'

    def test_anomalies_endpoint_missing_values_400(self, client):
        assert client.post('/api/analytics/anomalies',
                           json={'method': 'iqr'}).status_code == 400

    def test_timeseries_endpoint(self, client):
        response = client.post('/api/analytics/timeseries',
                               json={'values': [5, 6, 5, 6, 20, 21]})
        assert response.status_code == 200
        summary = response.json()['summary']
        assert summary['direction'] == 'rising'
        assert summary['count'] == 6

    def test_clusters_endpoint(self, client):
        response = client.post(
            '/api/analytics/clusters',
            json={'points': [[52.0, 13.0], [52.01, 13.01], [52.02, 13.02],
                             [48.0, 2.0]],
                  'eps_km': 25})
        assert response.status_code == 200
        payload = response.json()
        assert payload['cluster_count'] == 1
        assert payload['point_count'] == 4

    def test_clusters_endpoint_bad_points_400(self, client):
        assert client.post('/api/analytics/clusters',
                           json={'points': 'nope'}).status_code == 400
        assert client.post('/api/analytics/clusters',
                           json={'points': [['a', 'b']]}).status_code == 400

    def test_keywords_endpoint(self, client):
        response = client.post(
            '/api/analytics/keywords',
            json={'text': 'the quick brown fox', 'top': 3})
        assert response.status_code == 200
        payload = response.json()
        assert payload['keyword_count'] == 3
        assert set(payload['keywords'][0]) == {'term', 'count', 'weight'}

    def test_keywords_endpoint_missing_text_400(self, client):
        assert client.post('/api/analytics/keywords',
                           json={}).status_code == 400

    def test_language_endpoint(self, client):
        response = client.post(
            '/api/analytics/language',
            json={'text': 'Le renard brun rapide saute'})
        assert response.status_code == 200
        payload = response.json()
        assert payload['dominant_script'] == 'Latin'
        assert payload['language_guess'] == 'fr'

    def test_similarity_endpoint(self, client):
        response = client.post('/api/analytics/similarity',
                               json={'a': 'kitten', 'b': 'sitting'})
        assert response.status_code == 200
        payload = response.json()
        assert {'jaro_winkler', 'levenshtein_ratio', 'ngram', 'cosine',
                'mean'} <= set(payload)

    def test_similarity_endpoint_missing_b_400(self, client):
        assert client.post('/api/analytics/similarity',
                           json={'a': 'x'}).status_code == 400

    def test_graph_endpoint(self, client):
        response = client.post(
            '/api/analytics/graph',
            json={'entities': [{'id': 'a'}, {'id': 'b'}, {'id': 'c'}],
                  'links': [{'source': 'a', 'target': 'b'},
                            {'source': 'b', 'target': 'c'}]})
        assert response.status_code == 200
        payload = response.json()
        assert payload['summary']['node_count'] == 3
        assert payload['summary']['bridge_count'] == 2
        assert payload['entity_count'] == 3

    def test_graph_endpoint_missing_lists_400(self, client):
        assert client.post('/api/analytics/graph',
                           json={}).status_code == 400

    def test_history_endpoint(self, history_rows, client):
        response = client.get('/api/analytics/history?limit=100')
        assert response.status_code == 200
        payload = response.json()
        assert payload['total_queries'] >= 3
        assert len(payload['hour_profile']) == 24


# ---------------------------------------------------------------------------
# MCP wiring
# ---------------------------------------------------------------------------

class TestAnalyticsMCP:
    """The seven analytics_* MCP tools (40 -> 47 total)."""

    def test_tools_list_contains_analytics_tools(self):
        from obscuralens.mcp_server import TOOLS

        names = {tool['name'] for tool in TOOLS}
        assert {'analytics_stats', 'analytics_anomalies',
                'analytics_keywords', 'analytics_language',
                'analytics_similarity', 'analytics_graph',
                'analytics_history'} <= names
        assert len(TOOLS) == 63  # 47 + dorks + 5 automation + 10 part-5 ecosystem

    def test_analytics_tool_schemas_valid(self):
        from obscuralens.mcp_server import TOOLS

        schemas = {tool['name']: tool['inputSchema'] for tool in TOOLS}
        for name in ('analytics_stats', 'analytics_anomalies',
                     'analytics_keywords', 'analytics_language',
                     'analytics_similarity', 'analytics_graph',
                     'analytics_history'):
            schema = schemas[name]
            assert schema['type'] == 'object'
            assert isinstance(schema['properties'], dict)
            for prop in schema['properties'].values():
                assert 'type' in prop
        assert schemas['analytics_stats']['required'] == ['values']
        assert schemas['analytics_similarity']['required'] == ['a', 'b']

    def test_call_analytics_stats(self):
        from obscuralens.mcp_server import call_tool

        result = call_tool('analytics_stats', {'values': [1, 2, 3],
                                               'bins': 1})
        assert result['count'] == 3
        assert result['summary']['mean'] == 2.0
        assert result['histogram']['bin_counts'] == [3]

    def test_call_analytics_anomalies(self):
        from obscuralens.mcp_server import call_tool

        result = call_tool('analytics_anomalies',
                           {'values': [1, 2, 3, 4, 100], 'method': 'iqr'})
        assert result['anomaly_count'] == 1
        assert result['anomalies'][0]['value'] == 100.0

    def test_call_analytics_keywords(self):
        from obscuralens.mcp_server import call_tool

        result = call_tool('analytics_keywords',
                           {'text': 'the quick brown fox', 'top': 2})
        assert result['keyword_count'] == 2
        terms = [entry['term'] for entry in result['keywords']]
        assert 'the' not in terms

    def test_call_analytics_language(self):
        from obscuralens.mcp_server import call_tool

        result = call_tool('analytics_language',
                           {'text': 'これは テスト です'})
        assert result['language_guess'] == 'ja'

    def test_call_analytics_similarity(self):
        from obscuralens.mcp_server import call_tool

        result = call_tool('analytics_similarity',
                           {'a': 'paypal', 'b': 'paypa1'})
        assert result['jaro_winkler'] > 0.9
        assert 0.0 <= result['mean'] <= 1.0

    def test_call_analytics_graph(self):
        from obscuralens.mcp_server import call_tool

        result = call_tool('analytics_graph', {
            'entities': [{'id': 'a'}, {'id': 'b'}, {'id': 'c'}],
            'links': [{'source': 'a', 'target': 'b'},
                      {'source': 'b', 'target': 'c'}]})
        assert result['summary']['node_count'] == 3
        assert result['link_count'] == 2

    def test_call_analytics_history(self, history_rows):
        from obscuralens.mcp_server import call_tool

        result = call_tool('analytics_history', {'limit': 100})
        assert result['total_queries'] >= 3
        assert len(result['hour_profile']) == 24

    def test_missing_values_reports_tool_error(self):
        from obscuralens.mcp_server import call_tool

        with pytest.raises(ValueError):
            call_tool('analytics_stats', {})
        with pytest.raises(ValueError):
            call_tool('analytics_stats', {'values': ['x']})

    def test_handle_request_is_error_on_bad_arguments(self):
        from obscuralens.mcp_server import handle_request

        response = handle_request({
            'jsonrpc': '2.0', 'id': 9, 'method': 'tools/call',
            'params': {'name': 'analytics_stats', 'arguments': {}},
        })
        assert response['result']['isError'] is True
        assert 'values is required' in response['result']['content'][0]['text']
