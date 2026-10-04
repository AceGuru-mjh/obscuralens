# ObscuraLens analytics package

v6.0 Part 2 gives the platform a brain for the numbers its sensors produce.
Part 1 widened the sensor matrix to 20 target kinds; the `obscuralens.analytics`
package (10 modules, ~7,500 lines, pure standard library) turns results into
analysis: descriptive statistics, time-series workups, anomaly detection,
clustering, string similarity, text metrics, graph metrics, spatial
analytics, prediction models and history enrichment. Every function is
wired three ways — the `obscuralens analytics` CLI group, the
`/api/analytics/*` REST endpoints and seven `analytics_*` MCP tools — so
the same numbers reach the console, the browser and the LLM assistant.

## Contents

- [stats — descriptive statistics](#stats-descriptive-statistics)
- [timeseries — chronological analysis](#timeseries-chronological-analysis)
- [anomaly — outlier detection](#anomaly-outlier-detection)
- [cluster — unsupervised grouping](#cluster-unsupervised-grouping)
- [similarity — identity resolution](#similarity-identity-resolution)
- [textmetrics — prose analytics](#textmetrics-prose-analytics)
- [graphmetrics — investigation graphs](#graphmetrics-investigation-graphs)
- [geoanalytics — spatial analytics](#geoanalytics-spatial-analytics)
- [predict — screening models](#predict-screening-models)
- [enrich — history enrichment](#enrich-history-enrichment)
- [CLI usage](#cli-usage)
- [Web API endpoints](#web-api-endpoints)
- [MCP tools](#mcp-tools)
- [Philosophy](#philosophy)

## stats — descriptive statistics

| Function | What it answers |
|---|---|
| `mean` / `median` / `mode` | where is the centre? |
| `variance` / `stdev` / `pstdev` | how spread out? (sample vs population) |
| `percentile` / `quartiles` / `iqr` | quantiles with numpy-compatible linear interpolation |
| `skewness` / `kurtosis` | shape (bias-corrected) |
| `min_max_range` | extremes, span and midpoint |
| `summarize` | all of the above in one call |
| `histogram` / `value_counts` | distribution tables |
| `shannon_entropy` | diversity in bits |
| `zscore` / `robust_zscore` | classic and MAD-robust standardisation |

Non-numeric and non-finite items are dropped, never fatal; uncomputable
fields come back `None` instead of raising.

```python
from obscuralens.analytics import summarize, histogram

summarize([2, 2, 2, 2, 9])   # {'count': 5.0, 'mean': 3.4, 'median': 2.0, ...}
histogram([1, 2, 3, 4, 5], bins=2)['bin_counts']   # [2, 3]
```

## timeseries — chronological analysis

| Function | What it answers |
|---|---|
| `to_points` | defensive parsing of `(ts, value)` rows, dicts or points |
| `moving_average` / `ewma` | trailing smoothing, exponential smoothing |
| `linear_trend` | least-squares slope/intercept/r² with direction verdict |
| `detrend` | residuals after removing the trend |
| `cumulative_sum` / `rate_of_change` | running totals, per-day deltas |
| `detect_changepoints` | CUSUM on robust-z-scaled values |
| `seasonality_hint` | cheap period test on detrended residuals |
| `resample_daily` | UTC day aggregation |
| `series_summary` | the one-shot triage dossier |

```python
from obscuralens.analytics import detect_changepoints, to_points

vals = [5, 6, 5, 6, 5, 6, 5, 6, 20, 21, 20, 21]
events = detect_changepoints(to_points(list(zip(range(12), vals))))
events[0]['direction'], events[0]['index']   # ('up', 8)
```

## anomaly — outlier detection

| Function | What it answers |
|---|---|
| `zscore_anomalies` | classic z-score alarm (fast, fragile to masking) |
| `iqr_anomalies` | Tukey fences with per-hit fence detail |
| `mad_anomalies` | MAD robust z — survives the 10000 that masks a z-score |
| `grubbs_test` | single-outlier test with critical values |
| `ensemble_anomalies` | voting across detectors (default 2 of 3) |
| `threshold_anomalies` | hard floor/ceiling bounds |
| `detect_anomalies` | unified entry point, kwargs forwarded |

Every detector returns the shared `AnomalyScore` record (`value`, `score`,
`method`, `detail` with the index), so a report renders one table for any
method. Sequences below three usable values yield an empty list.

```python
from obscuralens.analytics import detect_anomalies

detect_anomalies([1, 2, 3, 4, 100], method='iqr')
# [AnomalyScore(value=100.0, score=46.5, method='iqr',
#               detail={'index': 4, 'q1': 2.0, 'q3': 4.0, ...})]
```

## cluster — unsupervised grouping

| Function | What it answers |
|---|---|
| `dbscan` | density clustering with explicit noise (`-1`) |
| `kmeans` | seeded k-means++ (deterministic per seed) |
| `hierarchical` | agglomerative single-link with threshold cut |
| `silhouette_score` | cluster quality (None for a single cluster) |
| `optimal_eps` | k-distance eps heuristic |
| `normalize_points` | per-dimension z-scores for mixed-scale axes |
| `cluster_summary` | per-cluster size/centroid/radius/tightness dossier |

All clusterers share the `ClusterResult` envelope (`assignments`,
`centroids`, `sizes`, `noise_count`, `method`). One malformed row
invalidates the whole set (distances are meaningless with ragged vectors)
and returns a valid, empty result.

```python
from obscuralens.analytics import cluster_summary, dbscan

points = [[0, 0], [0.5, 0], [10, 10], [10.5, 10], [50, 50]]
summary = cluster_summary(points, dbscan(points, eps=1.0, min_samples=2))
summary['n_clusters'], summary['noise_count']   # (2, 1)
```

## similarity — identity resolution

| Function | What it answers |
|---|---|
| `levenshtein` / `levenshtein_ratio` | edit distance (rolling two-row) |
| `jaro` / `jaro_winkler` | record-linkage classics |
| `soundex` / `metaphone_hint` | phonetic keys |
| `ngram_similarity` / `dice_coefficient` | n-gram Jaccard / Sørensen-Dice |
| `cosine_similarity` | sparse-vector cosine |
| `most_similar` | ranked retrieval with method selection |
| `typosquat_score` | domain-deception screening score |

```python
from obscuralens.analytics import jaro_winkler, soundex, typosquat_score

levenshtein('kitten', 'sitting')               # 3
jaro('MARTHA', 'MARHTA')                       # 0.9444
soundex('Robert') == soundex('Rupert')         # True ('R163')
typosquat_score('paypa1.com', 'paypal.com')    # 0.908 - very high risk
```

## textmetrics — prose analytics

| Function | What it answers |
|---|---|
| `tokenize` / `ngrams` / `term_frequencies` | Unicode tokenisation |
| `tfidf` | classic TF-IDF per document |
| `extract_keywords` | stopword-filtered keyword mining |
| `readability` | Flesch reading ease / Kincaid grade |
| `detect_language_script` | 11-script census + 8-language guess |
| `char_profile` | letters/digits/symbols/entropy profile |
| `summarize_text` | extractive summary (longest sentences) |
| `redaction_sweep` | validator-driven entity redaction preview |
| `text_similarity_report` | four similarity metrics in one call |

```python
from obscuralens.analytics import detect_language_script, redaction_sweep

detect_language_script('これは テスト です')['language_guess']   # 'ja'
redaction_sweep('mail me at bob@example.com or 8.8.8.8')['counts']
# {'emails': 1, 'domains': 1, 'ipv4': 1}
```

## graphmetrics — investigation graphs

| Function | What it answers |
|---|---|
| `build_adjacency` | entities/links payloads → undirected graph |
| `degree_centrality` / `pagerank` | who matters? |
| `betweenness_centrality` | who bridges clusters? (Brandes, ≤200 nodes) |
| `connected_components` | how many islands? |
| `label_propagation_communities` | seeded community detection |
| `bridges` | Tarjan — edges whose removal splits the graph |
| `shortest_path` | BFS hops between entities |
| `top_entities` / `graph_summary` | ranked dossiers |

The input is the exact `entities`/`links` shape `investigate()` and the
correlation engine emit, so a live investigation graph can be measured
without conversion.

```python
from obscuralens.analytics import graph_summary

summary = graph_summary([{'id': 'a'}, {'id': 'b'}, {'id': 'c'}],
                        [{'source': 'a', 'target': 'b'},
                         {'source': 'b', 'target': 'c'}])
summary['bridge_count'], summary['top_entities'][0]['id']   # (2, 'b')
```

## geoanalytics — spatial analytics

| Function | What it answers |
|---|---|
| `bounding_box` / `centroid` | extent and centre of a point set |
| `pairwise_distances` / `distance_matrix` | great-circle distances |
| `cluster_points` | kilometre-space DBSCAN over `[lat, lon]` |
| `geofence_check` | inside/outside with distance and bearing |
| `outlier_points` | Tukey outliers in distance-from-centroid space |
| `route_length` | path length through the points in order |
| `geo_summary` | the one-shot spatial dossier |

```python
from obscuralens.analytics import geo_summary, geofence_check

geofence_check([52.0, 13.0], [52.0, 13.0], 10)['inside']   # True
geo_summary([[52.0, 13.0], [52.1, 13.1]])['cluster_count']  # 1
```

## predict — screening models

| Function | What it answers |
|---|---|
| `fit_linear` / `predict_linear` | standardised gradient-descent regression |
| `fit_logistic` / `predict_logistic` / `classify` | binary classification |
| `simple_forecast` | index-based extrapolation (confidence always `low`) |
| `evaluate_binary` | zero-division-safe precision/recall/F1 |

Fewer than five rows, ragged dimensions or non-binary labels return `None`
— a screening model that refuses to guess beats one that fabricates.

```python
from obscuralens.analytics import evaluate_binary, fit_linear

model = fit_linear([[1], [2], [3], [4], [5]], [2, 4, 6, 8, 10])
model.r_squared > 0.99                        # True
evaluate_binary([0, 0], [1, 1])['precision']  # 0.0 - safe, not a crash
```

## enrich — history enrichment

| Function | What it answers |
|---|---|
| `history_points` | per-query evidence volume time series |
| `kind_frequency` / `top_targets` | workload census |
| `hour_of_day_profile` / `weekday_profile` | activity rhythms (UTC) |
| `success_rate_by_kind` | per-kind success rates |
| `field_count_distribution` | evidence volume distribution |
| `source_reliability` | per-source ok/failed/reliability |
| `activity_anomalies` | ensemble day-volume outliers |
| `enrichment_report` | everything above in one dossier |

`enrich` is the package's single sanctioned observer of the shared `db`
history singleton — read-only, so the rest of the package stays pure. An
unreadable or empty history yields a well-formed empty report.

```python
from obscuralens.analytics import enrichment_report

report = enrichment_report(limit=500)
report['total_queries'], len(report['hour_profile'])   # e.g. (412, 24)
```

## CLI usage

The `analytics` command group (nested subparsers, `-f json` everywhere,
exit code 2 on malformed input):

```bash
obscuralens analytics stats --values 1,2,3,4,100
obscuralens analytics stats --values 1,2,3 --bins 5 -f json
obscuralens analytics anomalies --values 1,2,3,4,100 --method mad
obscuralens analytics anomalies --values 10,10,10,200 --method zscore --threshold 2.5
obscuralens analytics timeseries --values 5,6,5,6,20,21
obscuralens analytics clusters --points "52.0,13.0;52.1,13.1;52.2,13.2" --eps 25
obscuralens analytics keywords --text "paste your dump text here" --top 10
obscuralens analytics language --text "Это не так и он не знает что это"
obscuralens analytics similarity --a paypa1.com --b paypal.com
obscuralens analytics graph --entities "a,b,c" --links "a-b,b-c"
obscuralens analytics graph --target example.com
obscuralens analytics history --limit 500
```

`graph --target` runs a live `investigate()` and measures the resulting
entity graph; `--entities`/`--links` analyse a graph you supply directly
(fully offline). Table output renders one section per structure (summary
grid, per-hit rows); `-f json` emits the raw payload for pipelines.

## Web API endpoints

All POST bodies are JSON; all computation is local. Missing fields and
lists with no usable numbers return HTTP 400 with a `detail` message.

| Endpoint | Body / Query | Returns |
|---|---|---|
| `POST /api/analytics/stats` | `{"values": [...], "bins": 10}` | summary + histogram |
| `POST /api/analytics/anomalies` | `{"values": [...], "method": "ensemble", "threshold": 3.0}` | AnomalyScore records |
| `POST /api/analytics/timeseries` | `{"values": [...]}` | series_summary |
| `POST /api/analytics/clusters` | `{"points": [[lat, lon], ...], "eps_km": 25, "min_points": 3}` | cluster dossiers |
| `POST /api/analytics/keywords` | `{"text": "...", "top": 10}` | term/count/weight rows |
| `POST /api/analytics/language` | `{"text": "..."}` | script census + guess |
| `POST /api/analytics/similarity` | `{"a": "...", "b": "..."}` | four metrics + mean |
| `POST /api/analytics/graph` | `{"entities": [...], "links": [...]}` | graph_summary |
| `GET /api/analytics/history?limit=500` | — | enrichment_report |

```bash
curl -X POST http://127.0.0.1:8000/api/analytics/stats \
     -H "Content-Type: application/json" \
     -d '{"values": [1, 2, 3, 4, 100]}'
```

## MCP tools

Seven `analytics_*` tools bring the package to LLM clients (47 tools total
after Part 2). Missing required arguments return a clean tool error, never
a server crash.

| Tool | Input | Output |
|---|---|---|
| `analytics_stats` | `values` (required), `bins?` | summary + histogram |
| `analytics_anomalies` | `values` (required), `method?`, `threshold?` | anomaly records |
| `analytics_keywords` | `text` (required), `top?` | keyword rows |
| `analytics_language` | `text` (required) | script/language profile |
| `analytics_similarity` | `a`, `b` (required) | four-metric report |
| `analytics_graph` | `entities`, `links` (required) | graph summary |
| `analytics_history` | `limit?` | enrichment report |

```json
{"name": "analytics_anomalies",
 "arguments": {"values": [1, 2, 3, 4, 100], "method": "iqr"}}
```

## Philosophy

**Pure standard library.** No numpy, no scipy, no scikit-learn — the whole
analysis layer runs on Python 3.9+ stdlib alone. That is a feature, not an
ascetic exercise: ObscuraLens ships as a frozen single-file desktop
executable, runs on air-gapped hosts and slim containers, and every
third-party dependency would have to be bundled, audited and kept
CVE-current in all of those channels. The platform's zero-dependency,
local-first guarantees transfer unchanged to its analysis layer.

**Defensive everywhere.** `None`, empty, malformed or non-numeric input
produces safe defaults — `None`, empty lists, well-formed empty envelopes —
never a traceback. A broken row is dropped, not fatal. A pipeline typo
(`method: 'zscroe'`) degrades to an empty result instead of crashing a
scheduled run at 03:00.

**Analyst-interpretable.** Every hit explains itself: the z-score detector
reports the mean and stdev it used, IQR its fences, Grubbs its critical
value, the ensemble its per-method vote breakdown, cluster dossiers their
centroids and radii. Numbers you cannot defend in a report are numbers you
cannot act on.

**Screening, not prophecy.** `simple_forecast` labels its own confidence
`low`; models refuse to fit on too-thin evidence; the ensemble demands two
agreeing detectors before it flags anything. False positives cost analyst
trust faster than false negatives.
