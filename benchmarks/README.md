# ObscuraLens Benchmark Suite

A self-contained, **offline, deterministic** timing suite for the platform's
pure-computation hot paths.  It measures the code every lookup, report,
export and SDK call executes — not the network — so numbers are comparable
between runs, machines and CI jobs.

* **Offline** — no network, no real API calls.  The SDK benches talk to an
  in-memory `StaticTransport`; the MCP benches call only the purely offline
  tools; everything else is pure computation.
* **Deterministic** — inputs are fixed literals or `random.Random(42)`
  series; the suite redirects the app's on-disk artefacts (history DB,
  cache, reports) into a private temp directory before importing
  `obscuralens`, so a run never touches your config or the repository
  working directory.
* **Fast** — a full run finishes in well under two minutes; `--quick` mode
  in a handful of seconds.

## Running

```bash
python -m benchmarks.run                 # full run -> benchmarks/results/latest.json
python -m benchmarks.run --quick         # CI mode (work divided by 5)
python -m benchmarks.run --list          # every benchmark with its tags
python -m benchmarks.run --only cache    # substring filter (repeatable)
python -m benchmarks.run --tags analytics# tag filter (repeatable)
python -m benchmarks.run --json          # machine-readable report on stdout
python -m benchmarks.run --compare benchmarks/results/baseline.json
python -m benchmarks.run --tolerance 0.5 --fail-on-regression
```

Exit codes: `0` normal (`slower` verdicts alone never fail a run),
`1` when a benchmark raised, `2` when `--fail-on-regression` flagged at
least one `slower` verdict.

## What is measured

70 benchmarks across three modules (use `--list` for the live registry).

### bench_core.py — the per-lookup foundation (`core` tag)

| Group | Benchmarks | What it exercises |
|---|---|---|
| validators | `validators_{ip,email,domain,username,phone}` | the five input validators over valid + invalid samples |
| detection | `detect_kind_all20` | `investigate.detect_kind` across one sample per supported kind (20) |
| cache | `cache_get_hit`, `cache_get_miss`, `cache_set_replace` | SQLite TTL cache read/write on a private temp database |
| rate limiting | `ratelimit_acquire_{url,host}` | token-bucket acquire + refill + lock overhead over rotating hosts |
| metrics | `metrics_record_ops` | 1,000 thread-safe counter updates + a snapshot |
| formatting | `formatting_rows_from_fields`, `formatting_label_fmt_value` | label/`fmt_value`/row rendering over a 40-field tracker envelope |
| coordinate maths | `coord_{haversine_km,latlon_to_utm,utm_to_latlon,latlon_to_geohash,geohash_to_latlon,latlon_to_mgrs,latlon_to_dms}` | pure WGS-84 conversions over 10 fixed coordinates |
| dorks | `dorks_all_kinds` | `dorks_for` for one target per dork-shipping kind (13) |
| data catalog | `catalog_lookups`, `catalog_search_countries` | bundled country/port/CWE/HTTP-status packs, incl. misses |

### bench_analytics.py — the analysis layer (`analytics` tag)

| Group | Benchmarks | Scale |
|---|---|---|
| stats | `stats_summarize_{100,1000,10000}`, `stats_histogram_10k_50bins` | 100/1k/10k gaussian samples |
| anomaly | `anomaly_{zscore,iqr,mad,grubbs,ensemble}_1k` | all five detectors on 1,000 samples |
| time series | `timeseries_series_summary_365`, `timeseries_to_points_10k` | 365-point summary; 10k tuple parsing |
| clustering | `cluster_geo_dbscan_500`, `cluster_kmeans_1000_2d` | geo DBSCAN on 500 hotspot points; k-means on 1,000 2-D points |
| similarity | `similarity_{jaro_winkler,levenshtein_ratio,bigram_jaccard,cosine_sparse}` | identity-resolution word pairs |
| text metrics | `textmetrics_{extract_keywords_2k,detect_language_script,similarity_report}` | 2,000-word corpus; en/ru/ja/zh snippets |
| graph metrics | `graph_summary_{100n_300l,500n_1500l}` | deterministic synthetic graphs |
| prediction | `predict_{simple_forecast_100,fit_linear_200x3,predict_linear_200}` | index forecast; 200x3 gradient-descent fit; row predictions |

### bench_platform.py — the ecosystem surfaces (`platform` tag)

| Group | Benchmarks | What it exercises |
|---|---|---|
| MCP | `mcp_tools_list_json`, `mcp_tools_encode`, `mcp_tools_hash_id`, `mcp_analytics_stats`, `mcp_data_pack_lookup` | tools/list payload serialisation; four purely offline tools |
| SDK | `sdk_build_url`, `sdk_lookup_result_from_dict`, `sdk_investigation_report_from_dict`, `sdk_session_200_steps` | URL building, model parsing, 200 recorded session steps over a scripted transport |
| reporting | `reporting_sections_all_kinds`, `reporting_render_markdown`, `reporting_render_standalone_html` | section builders over a synthetic envelope; Jinja rendering |
| export | `export_stix_bundle`, `export_misp_event` | STIX 2.1 bundle and MISP core-format event packing |
| plugins | `plugins_load_cycle` | full force-reload of the three `plugins-examples/` plugins + v2 surface extraction (path reroute applied by the setup function) |
| completion | `completion_{command_tree,bash,zsh,fish}` | CLI tree walk and the three shell generators |
| i18n | `i18n_translations_7locales` | `set_language` + `t()` across seven locales |
| database | `database_get_history_500` | `get_history(limit=500)` on a private temp database seeded with 500 rows |

## How to read the table

```
benchmark                                   ops/sec   min (ms)  median (ms)   p95 (ms)
------------------------------------------------------------------------------------
validators_ip                                  6,123      0.160        0.163     0.171
```

* **ops/sec** — throughput derived from the mean per-call time
  (`1 / mean`); higher is better.
* **min / median / p95 (ms)** — per-call duration statistics over the
  samples (5 repeats by default; each sample times `number` back-to-back
  calls and is normalised to per-call seconds).
* One unmeasured **warmup** call runs before sampling so lazy imports and
  first-touch caches (data packs, the analytics modules) do not pollute
  the numbers.

## Baseline policy

`benchmarks/results/baseline.json` is the committed reference; every run
saves to `benchmarks/results/latest.json` and **never** overwrites the
baseline automatically.  Regenerate deliberately:

```bash
python -m benchmarks.run --save benchmarks/results/baseline.json
```

Regenerate when an *intentional* performance change lands (a faster
algorithm, a bigger default payload) or when the benchmark set itself
changes — new/removed benches show up as `new`/`missing` verdicts until
you do.

### The 35% tolerance

`compare()` flags `slower` only when throughput drops by more than
**35%** (`ratio < 0.65`).  The band is deliberately generous: CI runners
vary by far more than that between jobs (shared vCPUs, thermal states,
noisy neighbours), and a tighter tolerance would make the comparison
noise, not signal.  Inside the band the verdict is `stable`; improvements
beyond `+35%` are `faster`; benchmarks absent from the baseline are `new`;
baseline entries that did not run are `missing`.

```bash
python -m benchmarks.run --quick --compare benchmarks/results/baseline.json
```

```
benchmark                          current    baseline   ratio  verdict
---------------------------------------------------------------------
validators_ip                          6,123       6,010   1.02x  stable
```

## CI usage sketch

```yaml
benchmarks:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with: { python-version: '3.12' }
    - run: pip install -e . && pip install pytest
    # quick mode, compare against the committed baseline; 'slower'
    # verdicts alone do not fail the job
    - run: python -m benchmarks.run --quick
    # opt in to hard failure:
    # - run: python -m benchmarks.run --quick --fail-on-regression
```

Run the benchmark suite's own tests with:

```bash
python -m pytest tests/test_benchmarks.py -q
```

## Adding a benchmark

1. Open the matching module (`bench_core.py`, `bench_analytics.py` or
   `bench_platform.py`) and add a builder function:

   ```python
   def _widget_benches() -> List[BenchSpec]:
       def crunch() -> None:
           for value in SAMPLES:
               widget.crunch(value)

       return [BenchSpec('widget_crunch_100', crunch,
                         repeat=5, number=20, tags=('core', 'widget'))]
   ```

2. Append it inside `build_benches()` in the same module.

3. Keep the contract: **offline**, **deterministic** (fixed literals or
   `random.Random(42)`), no writes outside the caller's workdir.  If the
   bench needs on-disk state, use the `state_dir(workdir, 'name')` helper
   in `setup()` and clean up in `teardown()` — see `_cache_benches()` in
   `bench_core.py` for the full pattern (config patch + restore).

4. Calibrate `repeat`/`number` so one sample takes roughly 5–100 ms
   (`--only <name>` is your friend).  Quick mode divides both by 5.

5. Exercise it once in `tests/test_benchmarks.py` — the per-group smoke
   tests automatically pick up anything added to `build_benches()`.

6. Regenerate the baseline (command above) and commit it together with
   the new benchmark.

## Repository layout

```
benchmarks/
├── __init__.py        # public harness API re-exports
├── harness.py         # Timer, measure, BenchSuite, BenchReport, compare
├── bench_core.py      # validators .. data catalog
├── bench_analytics.py # stats .. prediction
├── bench_platform.py  # mcp, sdk, reporting, export, plugins, completion, i18n, db
├── run.py             # CLI entry point (python -m benchmarks.run)
└── results/
    ├── baseline.json  # committed reference (regenerate deliberately)
    └── latest.json    # per-run output (untracked artifact)
```

Note for maintainers: `benchmarks/results/` must **not** be added to
`.gitignore` — the whole point is shipping `baseline.json` with the code.
