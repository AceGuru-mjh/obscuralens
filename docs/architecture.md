# ObscuraLens architecture

This is the internals document: how the platform is layered, what happens
on every lookup, where state lives, how concurrency is organised and how
the extension surfaces plug in. Every claim here was re-derived from the
tree at v6.1 (`obscuralens/` — 157 Python modules, ~89k lines) and its
fully offline test suite (3,267 tests at the v6.1 tag; the part-6
quality program is expanding it). For user-facing guides start at
[docs/index.md](index.md); for the REST surface see [api.md](api.md).

## Contents

- [The layer map](#the-layer-map)
- [Life of a lookup](#life-of-a-lookup)
- [State & storage](#state--storage)
- [Concurrency model](#concurrency-model)
- [The 20-kinds matrix](#the-20-kinds-matrix)
- [Extension surfaces](#extension-surfaces)
- [The API surfaces](#the-api-surfaces)
- [Performance notes](#performance-notes)
- [Design principles](#design-principles)

---

## The layer map

```
┌───────────────────────────── surfaces ─────────────────────────────┐
│  cli.py          interactive console menu (ObscuraLensCLI)          │
│  commands.py     argparse CLI: 56 top-level commands                │
│  tui.py          Textual terminal UI ([tui] extra)                 │
│  web/app.py      FastAPI REST API (74 /api endpoints) + SPA        │
│  web/static/     single-page app: index.html + css/ + js/          │
│  mcp_server.py   MCP stdio JSON-RPC server (63 tools)              │
│  sdk/            Python SDK: sync + async clients + session        │
│  sdk-js/         TypeScript/JavaScript SDK (zero npm deps)         │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ calls
┌───────────────────────────── services ──────────────────────────────┐
│  trackers/       20 target-kind trackers + 19 *_sources.py         │
│  investigate.py  kind detection + bounded pivot graph              │
│  watchlist.py    snapshot history + change diffs                   │
│  correlation/    engine (entities/links) + timeline + risk +       │
│                  confidence (noisy-OR corroboration)               │
│  analytics/      10 pure-stdlib analysis modules (~7.5k lines)     │
│  automation/     notification centre + cron-shaped scheduler       │
│  advanced/       batch engine, alerts, patterns, geospatial, HTML  │
│  experimental/   toolbox: encoders, JWT, EXIF, stego, crawler …    │
│  cases/          case management (items/notes/tags)                │
│  export/         GraphML/GEXF/DOT/CSV/JSONL + STIX 2.1 + MISP      │
│  intel/          blocklist feeds + Tor exit list                  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ depends on
┌─────────────────────────── platform core ──────────────────────────┐
│  config.py       ConfigManager: defaults ← config.yaml ←           │
│                  secrets.yaml ← OBSCURALENS_* env vars             │
│  database.py     query_history store + save-hook observer          │
│  core/cache.py   SQLite TTL cache (thread-local connections)       │
│  core/ratelimit.py  per-host token buckets + fragile-host overrides│
│  core/metrics.py    in-process network counters                     │
│  health/source_health.py  reliability stats + circuit breaker      │
│  utils/http_client.py  the shared requests session every source    │
│                         goes through                                │
│  utils/validators.py   20 kind validators + normalizers            │
│  utils/dorks.py   search-dork link builder (13 kinds)              │
│  utils/data_catalog.py  typed offline data-pack readers            │
│  rules/           YAML risk rule engine + 21 packs                 │
│  i18n/            14 locale catalogues (stdlib modules)            │
│  plugins/         plugin loader + SDK v2 contracts                 │
│  pipelines/       YAML pipeline engine                             │
│  reporting/       section builders + Jinja2 templates              │
│  data/            21 offline packs (*.txt)                         │
└─────────────────────────────────────────────────────────────────────┘
```

**Surfaces.** Everything the user or another program touches. The CLI is
split in two: `obscuralens/cli.py` is the menu-driven console
(`ObscuraLensCLI`, launched by `python -m obscuralens` with no arguments),
while `obscuralens/commands.py` builds a 56-command argparse parser via
`build_parser()` for scriptable use (`obscuralens ip 8.8.8.8 -f json`).
`tui.py` wraps the same services for Textual. The web surface
(`web/app.py`, ~2,160 lines) is an *extra*: FastAPI/uvicorn import lazily
inside `create_app()` so the core never requires them, and the SPA in
`web/static/` is plain ES modules + canvas — no build step, no CDN.
`mcp_server.py` speaks newline-delimited JSON-RPC 2.0 over stdio
(`python -m obscuralens mcp`). `sdk/` and `sdk-js/` wrap the REST API for
Python and TypeScript programs.

**Services.** The intelligence layer. Trackers (`obscuralens/trackers/`,
20 `<kind>_tracker.py` modules) each aggregate their kind's sources;
`investigate.py` adds kind detection (`detect_kind()`) and the bounded
pivot graph (`investigate()`); `watchlist.py` stores per-target snapshots
and diffs them; `correlation/` turns stored history into entity graphs
(`engine.py`), timelines (`timeline.py`), explainable risk (`risk.py`)
and evidence confidence (`confidence.py`). `analytics/` (v6.0 part 2) is
ten pure-stdlib modules — stats, timeseries, anomaly, cluster,
similarity, textmetrics, graphmetrics, geoanalytics, predict, enrich.
`automation/` (part 4) is the notification centre (`notifications.py`)
and scheduler (`scheduler.py`). `advanced/`, `experimental/`, `cases/`,
`export/` and `intel/` complete the analyst toolset.

**Platform core.** The shared machinery every service builds on:
configuration with layered resolution (`config.py`), the SQLite history
store (`database.py`), the HTTP response cache, rate limiter and network
metrics (`core/`), persisted source health with a circuit breaker
(`health/source_health.py`), the one shared HTTP client
(`utils/http_client.py`), validators, the offline data catalog, risk rule
packs, i18n, the plugin system, the pipeline engine, report rendering and
the `data/*.txt` packs. The dependency arrow only ever points downward —
where a core-adjacent module needs a service (the pipeline engine
executing a `lookup` step), it resolves it lazily by module path
(`pipelines/engine.py`'s `TRACKER_MAP` table) instead of importing it
at module load.

## Life of a lookup

The canonical walkthrough: `obscuralens ip 8.8.8.8 --risk`.

1. **Entry.** `pyproject.toml` maps the `obscuralens` console script to
   `obscuralens.cli:main()`, which delegates to `commands.py` when
   arguments are present. `build_parser()` registered the `ip`
   subcommand (`p_ip = sub.add_parser('ip', …)`) with the common flags
   (`-f/--format`, `-o/--output`, `--no-cache`, `--risk`, `--template`,
   `--timeout`). Dispatch lands in `_cmd_ip()`.

2. **Validation.** `validate_ip()` from `obscuralens/utils/validators.py`
   returns `(ok, error)`; a rejection exits with code 2 before any
   network traffic. Every one of the 20 kinds has a validator registered
   in the `_VALIDATORS` map.

3. **Tracker selection.** `_run_lookup()` calls `_tracker('ip')`, which
   lazily imports `IPTracker` and memoises the instance in `_TRACKERS`
   (module-level dict — one tracker instance per process, reused across
   lookups).

4. **Fan-out construction.** `IPTracker.track(ip)` calls
   `gather_all(ip, self._keys())` in
   `obscuralens/trackers/ip_sources.py`. `gather_all` assembles the task
   map:
   - the 18 keyless readers from the `FREE_SOURCES` registry
     (`ipwhois.app`, `ipwho.is`, `freeipapi`, `ip-api.com`, `db-ip.com`,
     `iplocation.net`, `internetdb`, `ripestat`, `reverse_dns`, `rdap`,
     `ipapi.co`, `otx`, `hackertarget`, `threat_feeds`, `greynoise`,
     `ipapi.is`, `ipinfo.io`, `proxycheck`);
   - plugin sources via `_plugin_sources('ip')` (prefixed `plugin:` in
     results);
   - the 4 keyed readers from `KEYED_SOURCES` (`shodan`, `virustotal`,
     `ipinfo`, `abuseipdb`) — only when a key is configured.

   Every task is double-gated: `config.is_source_enabled(name)` (the
   `disabled_sources` list) and `health.source_allowed(name)` (the
   circuit breaker).

5. **Parallel execution.** 17 of the 19 `*_sources.py` modules expose a
   `gather_all()` that runs its tasks through
   `ThreadPoolExecutor(max_workers=fanout_workers(len(tasks)))`. The
   `fanout_workers()` helper (`obscuralens/utils/helpers.py`) clamps to
   `min(task_count, app.max_workers, 32)` — since v6.1 the fan-out
   honours `max_workers` instead of the old hardcoded 12-thread cap. The
   email kind implements its fan-out inline in `email_tracker.py` (its
   DNS posture sweep in `email_sources.py` uses a small fixed 8-thread
   pool), and `username_tracker.py` sizes its own platform sweep with
   `min(12, max(1, max_workers))`.

6. **Per-source HTTP.** Each reader calls the shared client from
   `obscuralens/utils/http_client.py` — `http.get_json()`, `http.get_text()`
   or `http.fetch()`. One request flows through:
   - **Cache lookup** (`obscuralens/core/cache.py`): `cache.get('json',
     key)` hits the SQLite `http_cache` table (WAL mode, zlib-compressed
     values). A fresh hit returns immediately; an expired row is deleted
     and counted as a miss. TTL default 900 s (`app.cache_ttl`), entries
     capped at 1.5 MB.
   - **Rate limit** (`obscuralens/core/ratelimit.py`):
     `rate_acquire(url)` blocks until the per-host token bucket has a
     token (default 8 req/s, burst 4, from `app.requests_per_second`).
     v6.1 adds `HOST_RATE_OVERRIDES` — eight fragile hosts get slower
     buckets (e.g. `api.ransomware.live` 0.02/s, `api.ethplorer.io`
     0.4/s, `api.adsb.lol` 0.8/s) so a 12-worker sweep cannot trip their
     429s; the slower of default and override wins.
   - **Transport**: the shared `requests.Session` with `Retry(total=2,
     backoff_factor=0.4, status_forcelist=(429, 500, 502, 503, 504))` on
     GET/HEAD, and a connection pool sized `max(48, max_workers * 4)`
     so mid-sweep pool eviction (full TCP+TLS re-handshake per source)
     cannot happen.
   - **Metrics** (`obscuralens/core/metrics.py`): every request, byte,
     cache hit/miss, failure and timeout is counted for
     `obscuralens stats --network`.

7. **Failure isolation.** A reader returns `{}` on ordinary failure and
   never raises; if it does raise anyway, the `as_completed` loop in
   `gather_all` catches it and records `status[name] = {'ok': False,
   'error': type(e).__name__}` — one broken source can never kill the
   scan. Afterwards `health.record_batch('ip', status)` upserts the
   per-`(source, kind)` row in the `source_health` table. The circuit
   breaker (`source_health.py`) trips a source out of the request path
   when `consecutive_failures` reaches `app.source_failure_threshold`
   (default 4) **and** the last failure is younger than
   `app.source_cooldown_seconds` (default 600 s) — after the cooldown the
   next lookup retries it. Everything fails open: unknown sources,
   disabled tracking and SQLite errors never block a lookup.

8. **Field merge + provenance.** `gather_all` walks `results` in task
   order: `merged.setdefault(key, value)` (earlier source wins
   conflicts), `provenance.setdefault(key, []).append(name)` — so every
   field carries the list of sources that supplied it. The IP tracker
   additionally keeps `coordinates_by_source` (free geo APIs disagree
   often enough that hiding the spread would be dishonest) and
   `city_disagreement` when cities collide.

9. **Envelope.** `IPTracker.track()` wraps the merge into the standard
   envelope every kind returns:

   ```python
   {
     'ip': '8.8.8.8',            # the target (key name varies per kind)
     'info': {...},               # merged fields
     'field_sources': {...},      # provenance map
     'sources_ok': [...],         # sorted list of healthy sources
     'sources_failed': {...},     # {source: error}
     'field_count': 24,           # populated fields only
     'success': True,             # at least one source answered
     'errors': [...],
   }
   ```

10. **Persistence.** `db.save_query('ip', ip, result, success)` in
    `obscuralens/database.py` — secret-looking strings are redacted by
    `sanitize_secrets()` first, the row lands in `query_history`, old
    rows are pruned beyond `app.max_history_entries` (1,000), and the
    optional `_SAVE_HOOK` observer fires. The core package never sets
    the hook; the web layer registers one (`set_save_hook()`) so the SSE
    event bus can publish a `lookup` event to connected dashboards.

11. **Confidence.** Back in `_run_lookup()`,
    `attach_confidence(result)` (`obscuralens/correlation/confidence.py`)
    scores every field with the noisy-OR corroboration model:
    `1 - Π(1 - trust(source))` over the field's provenance list, using
    the curated `SOURCE_TRUST` table (offline standards packs 0.95,
    first-party registries/RPCs 0.9, default 0.8, community aggregators
    0.75). The block lands under `result['confidence']` with an
    `overall` mean, a `band`, `fields_scored`, `corroborated` (2+ source
    fields) and per-field detail. It never changes the lookup and never
    raises.

12. **Risk (optional).** `--risk` triggers `attach_risk(kind, result)`
    (`obscuralens/correlation/risk.py`) — explainable per-kind signals
    evaluated from the YAML rule packs in `rules/packs/` (21 files: one
    per kind plus `shared.yaml`).

13. **Rendering.** `_emit_result()` builds report sections via
    `reporting/sections.py` (`sections_for(kind, result)`), adds the
    confidence and risk sections, and renders through
    `reporting/report_generator.py` (table/JSON/Markdown/HTML/CSV/
    Mermaid) or a Jinja2 template from `reporting/templates/`
    (`standalone_report.html.j2`, `report.md.j2`, `summary.html.j2`).
    Exit code 0 on success, 1 when every source failed.

The same envelope, provenance map and confidence block flow identically
through the web route `GET /api/lookup/{kind}/{target}`, the MCP tool
`ip_lookup` and both SDKs — the surfaces are thin adapters over
`<Kind>Tracker.track()`.

### The walkthrough as a diagram

```
obscuralens ip 8.8.8.8 --risk
│
├─ cli.py:main() → commands.py build_parser() → _cmd_ip()
│    └─ validate_ip() ── invalid? exit 2, no traffic
│
├─ _run_lookup() → _tracker('ip') → IPTracker (memoised)
│
├─ IPTracker.track('8.8.8.8')
│    └─ ip_sources.gather_all(ip, keys)
│         ├─ tasks = FREE_SOURCES(18) + plugin:* + KEYED_SOURCES(4 if keys)
│         │    each gated by config.is_source_enabled() + health.source_allowed()
│         ├─ ThreadPoolExecutor(fanout_workers(len(tasks)))
│         │    └─ per reader: http.get_json(url)
│         │         ├─ cache.get('json', url) ──── hit? return (25-75x path)
│         │         ├─ rate_acquire(url)          token bucket per host
│         │         └─ session.get(url)           Retry(2), pooled connections
│         ├─ as_completed → results[name] / status[name]  (raises isolated)
│         ├─ health.record_batch('ip', status)   → source_health table
│         └─ merge in registry order → fields + provenance
│
├─ envelope {info, field_sources, sources_ok, sources_failed, field_count,
│            success, errors}
│    └─ db.save_query('ip', …) → query_history + sanitize_secrets
│         └─ _SAVE_HOOK → web SSE bus (registered only by `serve`)
│
├─ attach_confidence(result)   noisy-OR over provenance (v6.1)
├─ attach_risk('ip', result)   YAML rule packs (--risk)
│
└─ _emit_result() → sections_for('ip') → ReportGenerator → table/json/…
     exit 0 (some source ok) | 1 (all failed)
```

## State & storage

Everything is local. Nothing leaves the machine except the source API
calls themselves.

| Store | Path | Contents |
|---|---|---|
| Main database | `data/obscuralens.db` (`database.sqlite_path`) | `query_history`, `source_health`, `watchlist`, `watch_snapshots`, `cases`, `case_items`, `case_notes`, `case_tags` — one SQLite file, opened with short-lived connections (15 s busy timeout, `sqlite3.Row`) |
| HTTP cache | `data/http_cache.db` (`app.cache_path`) | `http_cache(key, value BLOB, expires_at, created_at)` — zlib-compressed JSON of successful 200 responses; persistent thread-local connections |
| Notification state | `data/notifications.json` | channels, subscriptions, quiet hours, dedup window (beside the SQLite path — `automation/notifications.py` `_state_path()`) |
| Scheduler state | `data/scheduler.json` | task specs + last-run bookkeeping (`automation/scheduler.py` `_state_path()`) |
| Alert state | `data/alerts.json` | webhook alert configs (`advanced/alerts.py`) |
| Configuration | `config/config.yaml` | non-sensitive settings (`app:`, `database:` sections) |
| Secrets | `config/secrets.yaml` | service credentials (flat keys, chmod 600 on write) — see [SECURITY.md](../SECURITY.md) |
| Watch targets | `watch_targets.txt` | targets for the scheduled GitHub Actions check |

The config directory resolves as `OBSCURALENS_CONFIG_DIR`, then a local
`./config` folder (checkout runs), then the per-user directory
(`%APPDATA%/ObscuraLens` on Windows, `~/.config/obscuralens` elsewhere).
Resolution order for values: env vars `OBSCURALENS_*` → `secrets.yaml`
(keys) / `config.yaml` → built-in defaults (`obscuralens/config.py`).

History and cache are purged through `obscuralens cache clear`, the
interactive console's clear-history action (`db.clear_history()`), and
simply deleting the files under `data/`.

## Concurrency model

The platform is thread-based, not asyncio-based. Reasons: the transport
is `requests` (a sync library with excellent connection pooling), the
workload is many small independent HTTP calls (a fan-out, not a stream),
and a ThreadPoolExecutor gives that shape in ~10 lines of stdlib.
asyncio appears only where an event loop already exists — the FastAPI
SSE endpoint and the async SDK facade.

Where threads are used:

- **Per-lookup fan-out**: every `gather_all()` (and the email/username
  trackers' own sweeps) runs its source readers in a
  `ThreadPoolExecutor` sized by `fanout_workers()`.
- **Batch engines**: `IPTracker.batch_track()` (workers=5 default) and
  `advanced/batch.py`'s fan-out stack lookups the same way.
- **Scheduler daemon**: `automation start` boots one `threading.Thread`
  (daemon) that ticks `run_due()` on schedule (`scheduler.py` `_THREAD`).
- **SSE event bus**: the web layer's `_EventBus` is publishable from any
  thread — lookups run in the FastAPI threadpool, and cross-thread
  deliveries hop through `loop.call_soon_threadsafe` so only the owning
  event loop touches its `asyncio.Queue` (`web/app.py`).
- **Async SDK**: `AsyncObscuraLensClient` submits the *sync* client's
  calls to a private `ThreadPoolExecutor` via `loop.run_in_executor`
  (Python 3.9-safe; `sdk/async_client.py`).

What is lock-protected:

- `HttpCache._lock` serialises cache get/set/prune around the
  thread-local connections (`core/cache.py`).
- `RateLimiter._lock` guards the per-host token buckets
  (`core/ratelimit.py`); waiting happens outside the lock.
- `NetworkMetrics._lock` guards the counters (`core/metrics.py`).
- `health/source_health.py` module-level `_LOCK` serialises health
  upserts so the gather pool cannot race writes.
- The JSON-state modules (`notifications.py`, `scheduler.py`,
  `advanced/alerts.py`) each hold a `threading.Lock` around
  read-modify-write cycles and write atomically (temp file + replace).

SQLite and threads: `core/cache.py` keeps **persistent, thread-local**
connections (one per worker thread, schema DDL once per connection,
`PRAGMA journal_mode=WAL` + `synchronous=NORMAL`, self-healing by
dropping a broken connection) — the v5.2 fix that took cache ops from
~1-3 ms to ~0.04 ms. The history/cases/watch/health stores instead open
short-lived connections per operation, which sidesteps cross-thread
sharing entirely.

## The 20-kinds matrix

Counts were derived by importing each `*_sources.py` registry
(`FREE_SOURCES` + `KEYED_SOURCES`) — "offline" rows are pure local
computation (validator decomposition + curated `data/` packs), not HTTP
sources.

| Kind | Tracker module | Live sources | Notes |
|---|---|---|---|
| `ip` | `trackers/ip_tracker.py` | 18 keyless + 4 keyed | plus threat feeds, dual DoH, proxycheck.io |
| `phone` | `trackers/phone_tracker.py` | offline + 1 keyed | libphonenumber metadata + optional numverify |
| `username` | `trackers/username_tracker.py` | 112 platforms | 101 HTML + 11 JSON API; honest 3-state verdicts |
| `email` | `trackers/email_tracker.py` | 8 keyless + 3 keyed | DNS posture, disposable pack, breaches |
| `domain` | `trackers/domain_tracker.py` | 13 keyless | RDAP, dual DoH, CT logs, HSTS preload |
| `url` | `trackers/url_tracker.py` | 4 keyless + 2 keyed | redirect walk, urlscan, Wayback, OpenPhish |
| `crypto` | `trackers/crypto_tracker.py` | 14 keyless + 1 keyed | 10 chains incl. TRON/NEAR/ATOM |
| `hash` | `trackers/hash_tracker.py` | 3 keyless + 1 keyed | MalwareBazaar, CIRCL, OTX |
| `cve` | `trackers/cve_tracker.py` | 8 keyless | NVD, OSV, cvelistV5, CVE Program, GHSA, EPSS, CIRCL, CISA KEV |
| `asn` | `trackers/asn_tracker.py` | 4 keyless | RIPEstat, BGPView, CAIDA AS-Rank, PeeringDB |
| `mac` | `trackers/mac_tracker.py` | 2 online + 2 offline | `macvendors`, `maclookup` + IEEE OUI pack (766 vendors) + bit decomposition |
| `iban` | `trackers/iban_tracker.py` | 1 online + 2 offline | `openiban` + mod-97 + 124-country structure pack |
| `imei` | `trackers/imei_tracker.py` | 2 (offline TAC + Luhn) | 139-entry TAC pack |
| `coords` | `trackers/coords_tracker.py` | 4 online + 2 offline | Nominatim, BigDataCloud, elevation, Open-Meteo + geohash/centroid maths |
| `vin` | `trackers/vin_tracker.py` | 1 online + 1 offline | NHTSA vPIC decoder + ISO 3779 decomposition (166-entry WMI pack) |
| `flight` | `trackers/flight_tracker.py` | 1 online + 2 offline + 1 keyed | adsb.lol live ADS-B + airline/designator packs + keyed aviationstack |
| `mmsi` | `trackers/mmsi_tracker.py` | 2 (offline) | ITU-R M.1085 + 97-state MID pack |
| `app` | `trackers/app_tracker.py` | 6 online + 1 offline | PyPI, npm, crates, Docker Hub, GitHub, OSV + `pack_meta` anatomy |
| `bssid` | `trackers/bssid_tracker.py` | 1 online + 2 offline + 1 keyed | mylnikov geolocation + OUI/EUI-48 maths + keyed WiGLE |
| `plate` | `trackers/plate_tracker.py` | 2 (offline) | 79-jurisdiction format pack |

Validators all live in `obscuralens/utils/validators.py` (one
`validate_<kind>()` per kind, registered in the `_VALIDATORS` maps of
`commands.py`, `web/app.py` and `investigate.py`). Username platforms:
91 HTML platforms are declared in `username_tracker.py`'s
`HTML_PLATFORMS`, 10 more in `username_sources.HTML_PLATFORMS`, and 11
JSON API platforms in `username_sources.API_PLATFORMS` — 112 total.

## Extension surfaces

- **Plugins v2** — plain `*.py` files dropped into `<repo>/plugins/` or
  `<config_dir>/plugins/` (priority order, `_`-prefixed files ignored).
  A v1 plugin is just a `SOURCES` dict of per-kind reader callables. v2
  (`obscuralens/plugins/contracts.py`, `SUPPORTED_PLUGIN_API = 2`) adds
  `PLUGIN_META` manifests, `COMMANDS` (CLI subcommands run through
  `obscuralens plugins run`), `REPORT_SECTIONS` (extra report blocks),
  `TOOLS` (MCP-exposed handlers) and `ANALYTICS` (pure functions) — each
  piece validated independently by `extract_plugin_surface()`, so a
  malformed piece is dropped without losing the rest. Registries live in
  `plugins/__init__.py` (`plugin_sources()`, `plugin_commands()`,
  `plugin_report_sections()`, `plugin_tools()`, `plugin_analytics()`).
  Examples: `plugins-examples/` (3 files). Guide: [plugins.md](plugins.md).
- **Pipelines** — YAML workflow files in `pipelines/` (engine:
  `pipelines/engine.py`) with `lookup`/`risk`/`timeline`/`correlate`/
  `assert`/`output`/`notify`/`export` steps and `$variables`. 19 worked
  examples ship in `pipelines/examples/`.
- **Rule packs** — YAML risk rules in `rules/packs/*.yaml` (21 files),
  evaluated by `rules/engine.py`'s DSL (23 operators). Every hit carries
  its own explanation. Guide: [rules.md](rules.md).
- **Report templates** — Jinja2 templates in
  `reporting/templates/*.j2` (3 shipped), rendered by
  `reporting/template_render.py` with `esc`/`nl2br`/`fmt_pct` filters and
  wired into every lookup via `--template NAME`.
- **i18n catalogues** — one Python module per locale in
  `i18n/locales/` (14 languages: ar, de, en, es, fr, hi, it, ja, ko, nl,
  pl, pt, ru, zh), each defining a flat `STRINGS` dict. Works unchanged
  inside the frozen exe because catalogues are code, not data files.
  Guide: [i18n.md](i18n.md).
- **Data packs** — the curated `data/*.txt` files (21 packs) behind the
  typed, never-raising readers of `utils/data_catalog.py` (14 packs
  exposed through the `obscuralens data` CLI) plus the validator-side
  packs (OUI, TAC, MID, WMI, IBAN structures, plate formats, centroids,
  airlines, disposable domains, phishing keywords). Guide:
  [data-packs.md](data-packs.md).

## The API surfaces

Four wire surfaces stay in sync by sharing the same service layer, and
each is pinned by tests that assert the exact contract:

- **REST** — 74 `/api/*` endpoints in `obscuralens/web/app.py` (counted
  from the route decorators; plus the `/` SPA route). Groups: lookup &
  investigate, platform management (kinds/history/keys/settings),
  analysis (timeline/correlate/risk/report/patterns/diff/alerts), the
  13-endpoint analyst toolbox, 9 analytics endpoints, notify (6),
  automation (6), exports (graph/STIX/MISP), cases (7), watch (4),
  profile/compare/map views and the SSE stream. Reference:
  [api.md](api.md).
- **MCP** — 63 tools in `obscuralens/mcp_server.py` (verified against
  `TOOLS`): 20 kind lookups (`ip_lookup` … `plate_lookup`), 5
  investigation/history views (`investigate`, `risk_report`,
  `correlate`, `timeline`, `history_search`), 2 intel/health views
  (`threat_intel`, `source_health`), 6 watch/case tools (`watch_list`,
  `watch_check`, `watch_add`, `watch_remove`, `case_list`,
  `case_create`), 13 `tools_*` toolbox wrappers (encode/decode/JWT/
  hash-id/extract/squat/dorks/exif/stego/coords-convert/geo-profile/
  patterns/batch), 10 `analytics_*` tools (stats, anomalies, keywords,
  language, similarity, graph, history, clusters, trend, forecast), 4
  automation/notify tools (`automation_tasks`, `automation_run_due`,
  `notify_channels`, `notify_broadcast`), 2 export tools
  (`export_stix`, `export_misp`) and `data_pack_lookup`. The `TOOLS`
  list carries the JSON schemas; `_HANDLERS` maps 45 names to handlers
  (the remaining 18 are branch-dispatched builtins). Wire format:
  newline-delimited JSON-RPC 2.0 over stdio.
- **Python SDK** — `obscuralens/sdk/`: `client.py` (sync, ~3.3k lines),
  `async_client.py` (executor-backed coroutines), `models.py` (~3k
  lines of tolerant dataclasses), `session.py`
  (`InvestigationSession` fluent workflow with JSON receipts),
  `transport.py` (`StaticTransport` test double), `exceptions.py`. 58
  public exports. Reference: [sdk.md](sdk.md).
- **TypeScript SDK** — `sdk-js/`: dependency-free ESM client with the
  full v6.1 surface, strict-mode types, `FetchTransport` +
  `StaticTransport`, shipped compiled in `dist/`. Reference:
  [sdk-js/README.md](../sdk-js/README.md).

The sync guarantees: `tests/test_web.py` + `tests/test_web_ui_v6.py`
pin the REST routes, `tests/test_mcp_server.py` pins all 63 tool names,
schemas and JSON-RPC round-trips, `tests/test_sdk.py` +
`tests/test_sdk_v6.py` (331 tests) pin the Python client against a
scripted `StaticTransport`, and `sdk-js/test/*.test.mjs` (78 node:test
cases) pin the TS client the same way. A surface that drifts fails CI.

## Performance notes

- **The v5.2 cache fix (25-75×).** Before v5.2, `HttpCache` opened a
  fresh SQLite connection *and re-ran the schema DDL* on every get/set —
  ~1-3 ms per cache hit, paid twenty times per 20-source fan-out, and
  serialised behind the global lock. Now connections are persistent and
  thread-local, the DDL runs once per connection, WAL +
  `synchronous=NORMAL` keep commits cheap, and a SQLite error drops the
  offending connection so the next call self-heals
  (`obscuralens/core/cache.py`). Only 200 responses are cached;
  failures are never cached.
- **Connection pooling.** The shared session's urllib3 pool is sized
  `max(48, max_workers * 4)` (`utils/http_client.py`) — the old fixed
  20/20 pool evicted pools mid-sweep (a full TCP+TLS handshake per
  source) and forced reconnect storms.
- **`max_workers` plumbing.** `fanout_workers()` (v6.1) clamps sweeps to
  `min(tasks, app.max_workers, 32)`; the HTTP pool, the fan-out and the
  batch engines all read the same setting now.
- **Rate-limit overrides.** The eight `HOST_RATE_OVERRIDES` entries keep
  fragile community APIs below their published limits so parallel sweeps
  don't spend their retries on 429s.
- **Lazy imports.** Trackers are imported on first use
  (`_tracker()` memoisation), FastAPI only inside `create_app()`, plugin
  loaders on first scan — `import obscuralens` stays cheap and works
  without the optional extras installed.
- **Measured numbers live in [benchmarks.md](benchmarks.md)** — the
  `benchmarks/` suite tracks 70 benchmarks across core, analytics and
  platform groups with a committed baseline and a 35 % CI tolerance.

## Packaging surfaces

The same platform ships in four shapes:

- **Source checkout / pip install** — `pip install -e ".[dev]"`; the
  `obscuralens` console script and `python -m obscuralens` both land in
  `cli.py:main()`.
- **Docker image** — `Dockerfile` installs `.[web]`, runs as an
  unprivileged uid 10001, keeps all state in the `/data` volume
  (`OBSCURALENS_SQLITE_PATH` / `OBSCURALENS_CACHE_PATH` env overrides),
  published to GHCR from CI. `docker-compose.yml` serves the web UI.
- **Standalone executable** — `scripts/obscuralens.spec` (PyInstaller)
  bundles the web and TUI stacks *and every offline data pack, rule pack
  and report template*; CI smoke-tests `--version` and boots the frozen
  `serve` until `/api/health` answers before uploading the artifact.
- **Desktop beta** — `obscuralens/desktop/` (launcher, single-instance
  lock, free-port probing, diagnostics, GitHub-Releases updater that
  never auto-downloads). Tag-triggered `desktop-beta.yml` builds
  Windows/Linux/macOS binaries with SHA-256 checksums. Guide:
  [desktop-beta.md](desktop-beta.md).

## Design principles

1. **Stdlib-first.** Nine hard dependencies (`pyproject.toml`: requests,
   phonenumbers, PyYAML, tabulate, jinja2, matplotlib, numpy, wordcloud,
   reportlab) — everything else, including the entire analytics package,
   the automation centre, the export formats and the i18n runtime, is
   standard library. Optional stacks (web, tui, exe) are extras.
2. **Offline-testable.** The test suite (3,267 tests at the v6.1 tag,
   still growing) runs with zero network:
   the `fake_http` fixture in `tests/conftest.py` monkeypatches the
   shared client, and the SDKs test against `StaticTransport`. Live
   checks are opt-in (`pytest -m integration`, `scripts/smoke_live.py`).
3. **Provenance on every fact.** Every field carries its source list
   (`field_sources`), every platform verdict carries its reason, and
   since v6.1 every field carries a noisy-OR corroboration score. No
   silent single-source facts.
4. **Keyless-first sources.** The platform works with zero keys; keyed
   sources layer on automatically when configured. Honest three-state
   username verdicts; bot-walled platforms are excluded rather than
   guessed at.
5. **Never-fatal errors.** A source fails → `{}` and a status entry. A
   plugin fails to import → skipped with a recorded reason. SQLite
   dies → safe defaults. Confidence/risk scoring raising → swallowed.
   Lookups only exit non-zero when *every* source failed.
6. **Passive collection.** Lookups are HTTP GETs against public
   endpoints (see [SECURITY.md](../SECURITY.md) for the OPSEC stance).
7. **The server is the contract.** Four wire surfaces, one service
   layer, tests asserting the exact wire format on each.
