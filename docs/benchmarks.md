# ObscuraLens benchmarks

The `benchmarks/` suite (part 6 of the v6 program) measures the hot
paths of the platform with deterministic, offline inputs so performance
changes are caught before review instead of argued about after merge.
It is deliberately small: the full run takes ~2 minutes, quick mode
fits inside a CI job, and every benchmark is pure CPU or temp-dir I/O —
no network, no wall-clock sleeps, no unseeded randomness.

Related reading: [architecture.md](architecture.md) § performance notes
explains *why* the platform is shaped the way it is (cache persistence,
pool sizing, `max_workers` plumbing); this page documents the ruler.

## Layout

```
benchmarks/
├── __init__.py          package docstring + guards
├── harness.py           BenchSpec / BenchSuite / timing / compare engine
├── bench_core.py        24 core benchmarks (validators, cache, …)
├── bench_analytics.py   25 analytics-kernel benchmarks
├── bench_platform.py    21 surface-marshalling benchmarks
├── run.py               the python -m benchmarks.run CLI
└── results/             committed baseline.json + per-run latest.json
```

70 benchmarks total, each registered as a `BenchSpec` through the
group's `build_benches()` and tagged for `--only`/`--tags` filtering.

## What is measured

### Core (`bench_core.py`, 24 benchmarks)

The per-lookup hot path — things a 20-source fan-out executes hundreds
of times per sweep.

| Group | Benchmarks | What it exercises |
|---|---|---|
| validators | `validators_ip/email/domain/username/phone`, `detect_kind_all20` | the kind validators + `investigate.detect_kind()` — the gate every lookup passes through (`utils/validators.py`) |
| cache | `cache_get_hit`, `cache_get_miss`, `cache_set_replace` | `HttpCache` get/set round-trips against a temp-dir SQLite file — the v5.2 persistent-connection path (`core/cache.py`) |
| ratelimit | `ratelimit_acquire_url`, `ratelimit_acquire_host` | token-bucket acquire on the shared limiter (`core/ratelimit.py`) |
| metrics | `metrics_record_ops` | the lock-guarded network counters (`core/metrics.py`) |
| formatting | `formatting_rows_from_fields`, `formatting_label_fmt_value` | report-row shaping (`utils/formatting.py`) |
| coords | `coord_haversine_km`, `coord_latlon_to_utm`, `coord_utm_to_latlon`, `coord_latlon_to_geohash`, `coord_geohash_to_latlon`, `coord_latlon_to_mgrs`, `coord_latlon_to_dms` | DD/DMS/UTM/MGRS/geohash maths (`utils/coordinate_math.py`, `utils/geo.py`) |
| dorks | `dorks_all_kinds` | dork-link generation across the 13 kinds (`utils/dorks.py`) |
| catalog | `catalog_lookups`, `catalog_search_countries` | offline data-pack reads (`utils/data_catalog.py`) |

### Analytics (`bench_analytics.py`, 25 benchmarks)

The v6.0 analytics kernels (`obscuralens/analytics/`, pure stdlib) over
deterministic synthetic series:

| Group | Benchmarks |
|---|---|
| stats | `stats_summarize_100/1000/10000`, `stats_histogram_10k_50bins` |
| anomaly | `anomaly_zscore_1k`, `anomaly_iqr_1k`, `anomaly_mad_1k`, `anomaly_grubbs_1k`, `anomaly_ensemble_1k` |
| timeseries | `timeseries_series_summary_365`, `timeseries_to_points_10k` |
| cluster | `cluster_geo_dbscan_500`, `cluster_kmeans_1000_2d` |
| similarity | `similarity_jaro_winkler`, `similarity_levenshtein_ratio`, `similarity_bigram_jaccard`, `similarity_cosine_sparse` |
| text | `textmetrics_extract_keywords_2k`, `textmetrics_detect_language_script`, `textmetrics_similarity_report` |
| graph | `graph_summary_100n_300l`, `graph_summary_500n_1500l` |
| predict | `predict_simple_forecast_100`, `predict_fit_linear_200x3`, `predict_predict_linear_200` |

### Platform (`bench_platform.py`, 21 benchmarks)

The marshalling layers users actually feel — envelope construction and
serialization between the engine and the four surfaces:

| Group | Benchmarks |
|---|---|
| mcp | `mcp_tools_list_json`, `mcp_tools_encode`, `mcp_tools_hash_id`, `mcp_analytics_stats`, `mcp_data_pack_lookup` |
| sdk | `sdk_build_url`, `sdk_lookup_result_from_dict`, `sdk_investigation_report_from_dict`, `sdk_session_200_steps` |
| reporting | `reporting_sections_all_kinds`, `reporting_render_markdown`, `reporting_render_standalone_html` |
| export | `export_stix_bundle`, `export_misp_event` |
| plugins | `plugins_load_cycle` |
| completion | `completion_command_tree`, `completion_bash`, `completion_zsh`, `completion_fish` |
| i18n | `i18n_translations_7locales` |
| database | `database_get_history_500` |

## Usage

```bash
python -m benchmarks.run                       # full suite (~2 min)
python -m benchmarks.run --quick               # fast subset for CI
python -m benchmarks.run --only cache          # substring filter (repeatable)
python -m benchmarks.run --tags analytics      # tag filter (repeatable)
python -m benchmarks.run --list                # every name + tags
python -m benchmarks.run --json                # machine-readable report on stdout
python -m benchmarks.run --save PATH           # write results (default results/latest.json)
python -m benchmarks.run --compare PATH        # diff against a baseline
python -m benchmarks.run --tolerance 0.5       # regression band (default 0.35)
python -m benchmarks.run --fail-on-regression  # exit 2 on any 'slower' verdict
```

Exit codes: `0` normal (slower verdicts alone never fail a run), `1`
when a benchmark raised, `2` with `--fail-on-regression` and at least
one `slower` verdict.

Runs are **hermetic**: `run.py` redirects every on-disk artefact
(config, database, cache, reports) into a private temp directory via
`OBSCURALENS_*` env vars *before* importing `obscuralens`, so a
benchmark run never touches your config, history or cache — and never
writes into the repository working directory.

Make targets (the part-6 orchestrator wires these into the `Makefile` /
`justfile`):

```bash
make bench          # full suite with compare + fail-on-regression
make bench-quick    # --quick subset, the CI shape
```

The committed baseline lives at `benchmarks/results/baseline.json`;
runs compare against it by default when it exists.

## Reading the report

Each benchmark reports **ops/sec** (throughput over the measured
repeats) plus **min / median / p95** per-operation latency. In compare
mode each row gets a verdict against the baseline:

| Verdict | Meaning |
|---|---|
| `faster` | median improved beyond +tolerance |
| `stable` | within tolerance — the expected verdict for untouched code |
| `slower` | median regressed beyond −tolerance |
| `new` | benchmark not present in the baseline |
| `missing` | benchmark in the baseline but not in this run |

The default tolerance is **35 %**. That number is not science, it is CI
reality: GitHub-hosted runners vary by tens of percent between
machines, and a tighter gate would fail PRs that changed nothing. The
suite compensates with **median-based** comparison and deterministic
inputs — the variance is the machine, not the data. If you need a
trustworthy number for a specific optimization, run the full suite
twice on your own hardware and compare those two runs.

## Baseline policy

- The baseline (`benchmarks/results/baseline.json`) is **committed** and
  **never auto-written** — regular runs save to
  `benchmarks/results/latest.json`; a run that regresses cannot quietly
  rewrite the ruler.
- Regenerate it only after an **intentional** performance change:

  ```bash
  python -m benchmarks.run --save benchmarks/results/baseline.json
  ```

  then commit the file together with the change that justifies it.
- A PR that makes rows `slower` should either fix the regression,
  explain it (feature cost), or (if deliberate) refresh the baseline in
  the same PR with the reason in the commit message.
- `tests/test_benchmarks.py` keeps the suite honest: it asserts the
  registry is non-empty, benchmarks are deterministic (two runs give
  the same shape) and side effects stay inside temp dirs.

## Adding a benchmark

Follow the registry pattern in the existing `bench_*.py` modules:

1. Write a function with **deterministic inputs** — fixed vectors,
   seeded generators only if the shape needs randomness, canned
   payloads captured from real module output.
2. Register it as a `BenchSpec` inside the group's builder
   (`_validator_benches()`-style helper appended to `build_benches()`)
   with a short, stable name and appropriate tags — renaming a
   benchmark orphans its baseline row.
3. **Side effects only in temp dirs** — never the user's `data/`, never
   the repository tree; take the `workdir` parameter when your group
   manages on-disk state.
4. Keep the full suite under ~2 minutes: prefer 100–10,000 iterations
   of something measurable over millions of something trivial; size
   inputs like the existing specs (`_1k`, `_10k` suffixes document
   scale).
5. Verify with `python -m benchmarks.run --only <name>` twice — same
   shape, sane numbers — then refresh the baseline so new rows land as
   `new` only until it includes them.

When to add one: you touched a hot path (validators, cache, rate
limiter, fan-out, merge, an analytics kernel, MCP/SDK marshalling) or
you are about to claim "this makes X faster" in a PR. The benchmark is
the claim's evidence.
