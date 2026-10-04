# ObscuraLens

## Changelog

## 6.2.0 — Quality, Benchmarks & Docs

v6.2 completes the six-part v6.0 programme: the benchmark suite, a
1,319-case test expansion over the weakest modules, the full
documentation set (architecture / contributing / security), CI jobs for
the benchmarks and the TypeScript SDK, and two genuine bug fixes found
by the new tests.

### Added — Benchmark suite (`benchmarks/`)

- **70 offline benchmarks** in three groups: core (validators for every
  kind, HTTP cache get/set, rate-limiter buckets, metrics, coordinate
  maths across UTM/MGRS/geohash/Maidenhead/DMS, dork generation,
  data-catalog lookups), analytics (descriptive stats and histograms on
  series up to 10,000 points, all five anomaly detectors, DBSCAN and
  k-means clustering on synthetic geo/feature data, similarity metrics,
  keyword/language fingerprinting, trend and changepoint summaries,
  graph metrics to 500 nodes, linear forecasting) and platform (MCP
  `tools/list` marshalling and offline tool calls, SDK URL building and
  model hydration, report and template rendering, STIX/MISP export,
  plugin loading, shell-completion generation, i18n, seeded-database
  history reads).
- A deterministic **timing harness** (`harness.py`): warmup + repeat ×
  number sampling with min/mean/median/p95/stdev and ops-per-second,
  tag/substring filtering, a CI-safe `--quick` mode (seconds, not
  minutes), JSON reports, and baseline comparison with a 35% tolerance
  band (CI machine variance) and verdicts faster/stable/slower/new/
  missing; `--fail-on-regression` gates exit code 2.
- A **committed baseline** (`benchmarks/results/baseline.json`) — never
  auto-overwritten; regenerate deliberately after intentional
  performance changes. `make bench` / `make bench-quick` /
  `just bench` / `just bench-quick`; 497 lines of contract tests in
  `tests/test_benchmarks.py`.
- Hermetic by construction: stateful benches isolate into per-run
  tempdirs; the CLI's env bootstrap is applied at import and **restored
  when `main()` returns**, so importing the runner from pytest never
  leaks benchmark paths into the surrounding process.

### Added — Test expansion (+1,319 cases; 3,267 → 4,586)

Deep offline suites for the previously weakest modules, with measured
coverage lifts:

| Module | Before | After |
|---|---|---|
| `advanced/report_builder.py` | 11% | 100% |
| `advanced/batch.py` | 13% | 85%+ |
| `advanced/alerts.py` | 14% | 85%+ |
| `advanced/patterns.py` | 14% | 85%+ |
| `advanced/geospatial.py` | 16% | 99% |
| `utils/coordinate_math.py` | 19% | 99% |
| `reporting/sections.py` | 31% | 97% |
| `visualization/charts.py` | ~0% | 100% |
| `cli.py` (interactive console) | ~0% | 98% |

Highlights: round-trip anchors for every coordinate format (including
zone-boundary longitudes and polar solar edges), full SVG-report
rendering (sparklines, bars, donuts, chips, escaping, determinism),
interactive-console flows driven end-to-end through scripted `input`
answers with stubbed trackers, batch/alert/pattern state machines with
hermetic state files, and the geospatial record pipeline over synthetic
history.

### Fixed

- **The Makefile used spaces instead of tabs** — every `make` target
  failed with "missing separator" (17 recipe lines converted; `make
  test` / `make bench` now work).
- **`build_history_report` crashed** (IndexError) when stored records
  existed but none carried a parseable timestamp — the day-bucket chart
  now renders an honest note instead of indexing into an empty list.
- `benchmarks/run.py` no longer leaks `OBSCURALENS_*` hermetic env
  overrides into a surrounding pytest process (restored on `main()`
  exit; previously broke `test_cases` ordering).

### Added — Documentation set

- **[docs/architecture.md](docs/architecture.md)**: the internals guide
  — layer map, life-of-a-lookup walkthrough (fan-out → per-source HTTP
  through cache/rate-limit/circuit-breaker → merge → provenance and
  noisy-OR confidence → persistence → surfaces), state & storage
  inventory, concurrency model, the 20-kinds × source-count matrix, and
  the extension surfaces.
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: setup, workflow, code style,
  and step-by-step guides for adding a data source, a target kind, an
  MCP tool, a REST endpoint, an SDK method or a benchmark.
- **[SECURITY.md](SECURITY.md)**: vulnerability disclosure, the passive
  OPSEC stance, secrets handling, local-data sensitivity and purging,
  supply-chain policy, no-telemetry statement.
- **[docs/index.md](docs/index.md)**: the reading map by audience;
  **[docs/benchmarks.md](docs/benchmarks.md)**: usage, baseline policy,
  adding benchmarks.
- CI: new `benchmarks` (quick suite + contract tests) and `sdk-js`
  (78 node:test cases on Node 22) jobs.

## 6.0-part5 — Ecosystem

Part 5 of the v6.0 series: everything that makes ObscuraLens embeddable
in someone else's program. Python SDK to full v6 coverage, a second SDK
in TypeScript, the MCP surface at 63 tools, plugins that extend more
than sources, and shell completions. See [docs/ecosystem.md](docs/ecosystem.md).

### Added — Python SDK v6

- Six new kind conveniences on both clients: `vin`, `flight`, `mmsi`,
  `app` (+ friendly `package` alias), `bssid`, `plate` — the SDK now
  models all 20 kinds.
- `dorks(target, kind=None)` with a `DorkReport` model (`.links()`).
- Nine `analytics_*` methods (stats, anomalies, timeseries, clusters,
  keywords, language, similarity, graph, history) returning a tagged
  `AnalyticsEnvelope`.
- Six `notify_*` and six `automation_*` methods with
  `NotifyChannel`/`NotifyChannels`/`NotifyDelivery` and
  `AutomationTask`/`AutomationTasks` models.
- `export_stix` / `export_misp` with `StixBundle` and `MispEvent`
  models; `set_stream_topics(topics)` (list or comma-string).
- New fluent workflow API `InvestigationSession`
  (`obscuralens.sdk.session`): step log with durations, error capture
  (strict mode optional), notes, sorted target collection,
  `to_case()` fan-out, `summary()` reports and dump/load JSON receipts
  that replay without a client.
- 142 new offline tests (`tests/test_sdk_v6.py`) asserting the exact
  wire contract of every new method via `StaticTransport`.

### Added — TypeScript/JavaScript SDK (`sdk-js/`)

- A dependency-free ESM SDK for Node 18+/browsers: `FetchTransport`
  (injectable fetch, `AbortSignal.timeout`), retry/backoff with
  `Retry-After`, the Python-parity typed error hierarchy, 80+ typed
  client methods covering the entire v6.1 REST surface, a TypeScript
  `InvestigationSession`, and `StaticTransport` for offline tests.
- TypeScript 5 strict-mode clean; compiled `dist/` + `.d.ts` ship in
  the repo. 78 node:test cases including two real `node:http`
  end-to-end smokes.

### Added — MCP server 53 → 63 tools

- `export_misp` (MISP core-format event from stored history),
  `analytics_clusters` (great-circle DBSCAN), `analytics_trend`
  (least-squares + CUSUM), `analytics_forecast` (linear-trend
  forecast, horizon 1-24), `history_search` (substring search over
  stored lookups), `watch_add`/`watch_remove`, `case_list`/
  `case_create` (with optional first target), and `data_pack_lookup`
  (offline country/port/language/currency/http_status/cwe/airline/
  wmi/mid lookups).

### Added — Plugin SDK v2

- Plugins may now define `PLUGIN_META` manifests, `COMMANDS` (dispatched
  via `obscuralens plugins run <name> [<args>...]`), `REPORT_SECTIONS`,
  `TOOLS` (MCP surface) and `ANALYTICS` hooks alongside the v1 `SOURCES`
  contract; v1 plugins load unchanged, `requires_api` gating protects
  forward compatibility, and every piece is validated in isolation.
- New CLI: `obscuralens plugins check <file>` (isolated plugin linter)
  and `plugins run`; `plugins list` reports the v2 surface per plugin.
- Three documented example plugins ship in `plugins-examples/`.

### Added — Shell completions

- `obscuralens completion bash|zsh|fish` generates self-contained,
  deterministic completion scripts from the live argparse parser —
  every subcommand, nested group, option string and `-f/--format`
  choice.

## 6.1.0 — Corroboration & Coverage

ObscuraLens 6.1 is a trust-and-reach release. It adds **evidence
confidence scoring** — every field now carries a noisy-OR corroboration
score computed from which sources supplied it, the differentiator that
separates graph-first tools like Umbra and Estorides from single-source
lookups — plus a **search-dork builder** across 13 kinds, **17 new
keyless data sources** (every endpoint live-verified before shipping),
**three new blockchains** (TRON, NEAR, ATOM) and a **keyless live-flight**
reader. On the performance side, the source fan-out finally honours
`max_workers` (the hardcoded 12-thread cap that ignored the setting is
gone, everywhere) and fragile community APIs get their own slower
rate-limit buckets so a parallel sweep cannot trip their 429s.

> Note: the v6.0 sensor kinds (vin / flight / mmsi / app / bssid / plate)
> shipped without a changelog entry; see the 6.0.0 backfill below.

### Added — Evidence confidence scoring (the Umbra-style corroboration layer)

- **`confidence` block on every lookup result** (CLI, web API, investigate
  pivots and MCP): `overall` score + band, per-field
  `{score, sources, named}`, and a corroborated-fields count. Computed
  from the existing `field_sources` provenance map — no extra network
  round trips, purely additive, never gates a lookup.
- **Noisy-OR combination over a curated source-trust table**: offline
  standards maths and curated packs rate 0.95, first-party authoritative
  records (registries, the CVE Program, chain RPCs, PeeringDB, CAIDA)
  rate 0.9, community aggregators and scrapes rate 0.75, everything
  else defaults to 0.8. Two independent sources corroborating each other
  compound above either alone — five aggregators still cannot outvote
  one authoritative record.
- **Table/Markdown/HTML reports gain an EVIDENCE CONFIDENCE section**
  (overall band, corroborated count, top-20 per-field scores with the
  named sources behind each fact).

### Added — Three new blockchains (7 → 10 chains)

- **TRON** via TronGrid (`wallet/getaccount`): TRX balance, account
  type, decoded contract names, creation time. Never-activated addresses
  answer `{}` — reported as a real zero-balance negative, the same honest
  treatment the Solana reader gives.
- **NEAR** via the public RPC (`query`/`view_account`): balance, locked
  stake, contract code hash, storage usage. Named accounts
  (`alice.near`) route to the crypto kind ahead of the domain validator —
  `.near` is not an ICANN TLD, so no real domain can be hijacked.
  `UNKNOWN_ACCOUNT` errors are real negatives, not failures.
- **ATOM (Cosmos Hub)** via the cosmos.directory REST proxy (the official
  `api.cosmos.network` front door has been serving TLS errors): uatom
  and IBC token balances, account number and sequence.
- **Cross-chain enrichment for ETH addresses**: `avax_cchain` checks the
  same 0x address on the Avalanche C-chain public RPC (balance + nonce);
  `ethplorer` (freekey tier) adds the ERC-20 token portfolio, spot price
  and tx count on top of the existing Etherscan/Blockchair/BlockCypher
  coverage; `xrpl_public` gives XRP a fully independent second opinion
  via the xrplcluster.com community RPC (provenance stacks with XRPScan).

### Added — Keyless sources across seven kinds

- **CVE + CISA KEV**: the Known Exploited Vulnerabilities catalog (via
  CISA's own cisagov/kev-data GitHub mirror — the cisa.gov feed sits
  behind datacenter-hostile bot rules). A KEV listing is the single
  highest-signal fact a CVE report can carry: actively-exploited
  verdict, ransomware/actor flags, due date. A miss is a real negative.
- **IP + proxycheck.io**: VPN/proxy/relay verdict and 0-100 risk score —
  the orthogonal second opinion on proxy verdicts next to ipapi.is.
- **Email + XposedOrNot**: keyless breach analytics (risk profile,
  exposing sites, paste count) that cross-confirms the keyed HIBP
  verdict; clean addresses are real negatives.
- **Domain + hstspreload.org** (Chromium preload status, a durable trust
  signal) and **+ ransomware.live** (leak-site victim check: which group
  listed the domain and when; 1 req/min, cached six hours).
- **ASN + CAIDA AS-Rank** (global customer-cone ranking, RIR source)
  and **+ PeeringDB** (the operator-maintained peering record: traffic
  volume, IX presence, policy).
- **Flight + adsb.lol**: the first keyless **live** flight reader —
  position, altitude, ground speed, registration and squawk for the
  aircraft broadcasting the designator right now (IATA and ICAO callsign
  forms both tried). Nothing airborne is an honest negative; a transport
  failure is never misreported as "not airborne".
- **Coords + Open-Meteo**: current weather, wind and an independent
  elevation cross-check (photo verification: was it really raining at
  that geotag?).

### Added — Username sweep 104 → 112 platforms

- **6 HTML platforms** live-verified with clean splits: Calendly,
  Gumroad, OpenSea, Bandcamp (200-vs-404), Ko-fi (homepage-fallback
  title rule) and Codeforces (profile-title rule).
- **2 JSON API platforms**: Stack Exchange (users API with exact
  display-name matching — the API's `inname` search is substring-based,
  so the verdict engine now supports username-aware verdict functions)
  and Duolingo (the 2017-06-30 users endpoint: `users: []` for missing
  accounts).
- Bot-walled candidates were probed and deliberately left out
  (unsplash, producthunt, researchgate, scribd, discogs, genius,
  chess.com, kickstarter, 500px's SPA shell, lobste.rs) — from scripted
  clients they can only ever answer "unknown".

### Added — Search-dork builder (13 kinds)

- **`obscuralens dorks <target>`** builds ready-to-open search-engine
  links for any auto-detected target: domain exposed-file hunting
  (`site: ext:env`), email leak context, username platform-scoped
  searches, CVE exploit hunting, IP threat-intel mentions and more,
  across Google, Bing, DuckDuckGo, Yandex and GitHub code search.
  `--kind` overrides detection, `--list` shows coverage, `-f json`
  machine-reads it.
- **Web toolbox tab** ("Search dorks") with kind selector and clickable
  links; **`GET /api/tools/dorks`** endpoint; **MCP `tools_dorks`** tool
  for AI agents. Link generation is purely local — the analyst stays in
  control of every active query, keeping the tool's passive-first
  promise intact.

### Changed — Performance and politeness

- **The source fan-out honours `max_workers`**: every `gather_all` used
  to hardcode `min(len(tasks), 12)`, silently capping users who raised
  the setting (the HTTP pool already scaled with it). A shared
  `fanout_workers()` helper (capped at a sane 32) now drives all 17
  source modules.
- **Per-host rate-limit overrides**: hosts with documented or
  empirically verified limits below the configured default
  (`api.ethplorer.io` 0.4/s, `api.ransomware.live` 0.02/s,
  `api.adsb.lol` 0.8/s, the chain RPCs) get their own slower token
  buckets, so a 12-worker sweep cannot trip a fragile community API into
  a 429. `snapshot()` now lists the overridden hosts in effect.

### Testing & docs

- 99 new offline tests (`tests/test_v61_sources.py`) covering every new
  reader (parse, real-negative and transport-failure paths), the new
  chains, the confidence math, the dork builder, the rate overrides and
  the fan-out helper; the full suite now stands at **2423 passed** /
  3 skipped with ruff clean.
- `docs/sources.md`, README and the CLI/web/MCP surfaces updated for the
  new catalog; version metadata de-staled (the package still claimed
  "14 target kinds" in `pyproject.toml` after v6.0 shipped 20).

## 6.0.0 — Sensor Matrix (backfill)

Six new target kinds grew the matrix from 14 to 20 kinds: vehicle VINs
(NHTSA vPIC + offline ISO 3779 decomposition), flight designators
(offline airline pack + aviationstack when keyed), maritime MMSIs
(offline ITU-R decomposition + flag-state pack), software packages
(PyPI/npm/crates/Docker Hub registries + OSV advisories), WiFi BSSIDs
(IEEE OUI pack + WiGLE when keyed) and license plates (offline country
format pack). Four new offline data packs (WMI, TAC, MID, plate formats)
joined `obscuralens/data/`, and every kind gained a rule pack.

## 5.2.0 — Sources & Speed

ObscuraLens 5.2 is a coverage-and-performance release: the username sweep
more than doubles (41 → 104 platforms, every addition live-verified before
shipping), four new blockchains gain aggregated sources, CVE and domain
lookups gain the authoritative primary records, the threat-intel feed count
grows from five to eight — and the HTTP cache gets a persistent-connection
rewrite that removes the per-operation SQLite reopen that dominated cache
latency since v3.

### Added — Username sweep 41 → 104 platforms

- **57 new HTML platforms** (Gitee, Hugging Face, GoodReads, SourceForge,
  Strava, MyAnimeList, RubyGems, Issuu, Itch.io, Launchpad, Sketchfab,
  SpeakerDeck, About.me, Credly, Disqus, Instructables, MyMiniFactory,
  Scratch, TradingView, WakaTime, Geocaching, HackMD, Crowdin, Freesound,
  GitBook, HubPages, IFTTT, Kongregate, Laracast, Memrise, OpenGameArt,
  Pokemon Showdown, Tenor, TheMovieDB, Windy, YouPic, Exophase, write.as,
  Bitwarden/Ionic/n8n/Rclone/Joplin/Ubuntu/Rust/Blender community forums,
  Linktree, AtCoder, MyDramaList, 9GAG, VK, OK.ru, HackerOne, LinuxFR,
  Fosstodon, Pixelfed, Hashnode). Every one was probed live: existing
  accounts answer HTTP 200 and missing accounts answer 404.
- **Bluesky** via the public App View JSON API (`app.bsky.actor.getProfile`)
  — DID-confirmed existence, high-confidence verdicts; bare usernames
  default to `<name>.bsky.social` handles, dotted handles are used verbatim.
- **Dailymotion** via `api.dailymotion.com/user/{name}` with an explicit
  field list; 404-for-missing splits.
- Bot-walled platforms (Codepen, Codewars, LeetCode, npm, ArtStation, Trakt,
  osu!, Wikipedia, Fandom, Imgur, Speedrun.com and others) were probed and
  **deliberately not added** — from scripted clients they can only ever
  answer "unknown", which would be noise, not coverage.

### Fixed — dead registries that shipped since v5.0

- `STATUS_RELIABLE` was declared but never consulted by the verdict engine;
  it is now wired into `_verdict` (after marker checks, platform rules and
  profile evidence, so nothing that already worked changes its verdict).
- The Patreon/Etsy/Substack/Replit entries that `username_sources` has
  always declared — with bespoke verdict rules — were documented as scanned
  but never unioned into the platform registry; `_build_platforms()` now
  merges them, and their `HTML_VERDICT_RULES` are dispatched alongside the
  tracker's own rules (Patreon/Etsy bot-wall honesty, Substack title split,
  Replit login-redirect split, Hashnode user-not-found title split).

### Added — crypto chains xrp / ada / sol (and BlockCypher for LTC/DOGE)

- `xrpscan` (XRP, keyless): XRP balance, sequence, owner count and the
  latest affecting transaction with its ledger index.
- `koios` (ADA, keyless POST): lovelace balance, stake address, script flag,
  UTXO count and UTXO-derived last activity.
- `solana` (SOL, keyless JSON-RPC): lamports balance, owner program,
  executable flag and data size; never-funded accounts report
  `sol_account_active: False` instead of a failure.
- `blockcypher` (BTC/ETH/LTC/DOGE, keyless): balance, received/sent totals
  and tx counters — LTC and DOGE finally get a second aggregated source.
- Solana address detection (`32-44 char base58`, checked after the prefixed
  base58 families so Bitcoin wins any length overlap). Every validated
  chain except xmr (balances unobservable by design) now has sources.

### Added — CVE, domain and threat-intel sources

- `cveawg` (CVE, keyless): the CVE Program's authoritative record API at
  cveawg.mitre.org — same CVE 5.1 schema as cvelist, so the two readers
  cross-confirm with stacked provenance (the record parser is shared).
- `ghsa` (CVE, keyless with optional `github` key): GitHub Security
  Advisories — GHSA ids, highest severity, CVSS score and CWE list.
- `doh.cloudflare` (domain, keyless): A/AAAA/MX/NS via the Cloudflare
  1.1.1.1 DoH resolver with the `Accept: application/dns-json` header —
  a third independent DNS vantage point stacking with `dns` and `doh.google`.
- Intel feeds +**CINS Army** (15k active-attacker IPs), +**blocklist.de**
  (~8k 48h abuse IPs), +**OpenPhish** (hourly phishing URL feed).
- `openphish` URL source: exact-URL and host-level phishing membership for
  the `url` tracker — a feed-clear is reported as a fact, not a failure,
  and the download is shared with the IP-side feed through the HTTP cache.

### Changed — performance

- **SQLite cache persistent connections** (thread-local, schema created
  once per connection): cache get/set previously reopened the database and
  re-ran the DDL on *every* call (~1-3 ms each, twenty times per lookup);
  now 0.04 ms per operation — a 25-75x cache-latency reduction. Corrupt
  rows drop the connection so the next call self-heals; `synchronous=NORMAL`
  keeps WAL commits cheap.
- **Connection pools sized for the fan-out**: `pool_connections` /
  `pool_maxsize` scale with `app.max_workers` (min 48) instead of the fixed
  20/20 that evicted pools mid-sweep and forced full TCP+TLS reconnects.
- Deep username scans on the new platforms extract a light Open-Graph
  profile (`name`/`bio`/`avatar`) — enrichment only, never verdict
  evidence, so JS shells cannot fabricate hits.

### Tests

- 61 new offline tests (`tests/test_v52_sources.py`): persistent-cache
  reuse/path-change/thread-locality/self-healing, platform registry
  completeness, STATUS_RELIABLE verdict paths, Bluesky/Dailymotion verdicts
  and profiles (including the HTTP-400 miss mapping), the four new crypto
  readers, cveawg/ghsa parsing, Cloudflare DoH field merging, the new feed
  parsers and the OpenPhish URL source (exact/host/clear/unavailable).
- Full suite: 2016 passed / 3 skipped (was 1955).

## 5.1.0-beta.1 — Desktop Beta

ObscuraLens 5.1 launches the **Desktop Beta program**: the whole platform as
a downloadable single-file executable, plus a large offline/reference layer —
14 languages, a 10-pack data catalog, a Python SDK, explainable risk rule
packs and report templates. Tagged pre-releases are published automatically
by CI; see [docs/desktop-beta.md](docs/desktop-beta.md) for the download
guide and [docs/v5.1.md](docs/v5.1.md) for the full notes.

### Added — Desktop Beta

- `obscuralens desktop` — single-instance desktop launcher: acquires a lock
  file, probes free ports (8000-8020), boots the local web UI, polls
  readiness, opens the browser and shuts down gracefully on Ctrl+C.
  Flags: `--host`, `--port`, `--no-browser`, `--channel`,
  `--diagnostics`, `--check-update`.
- `obscuralens update check` — GitHub Releases update check with
  semver pre-release ordering (beta.2 > beta.1, rc > beta, nightly lowest);
  channel-aware (beta/stable/nightly); never auto-downloads.
- `obscuralens-desktop` console script (pyproject entry point) plus the
  `desktop` optional extra.
- Desktop package: branding (ASCII banner, channel badge, about text),
  channel registry, updater, single-instance lock with stale takeover,
  diagnostics report (runtime, paths, dependencies, data packs, network).
- **Release workflows**: `desktop-beta.yml` (triggered by `v*-beta*` tags or
  manual dispatch) builds win-x64 / linux-x64 / macos-arm64 binaries,
  smoke-tests each, attaches SHA-256 checksums and publishes a pre-release
  with download instructions; `desktop-nightly.yml` refreshes a rolling
  nightly pre-release at 03:00 UTC. New `desktop` CI job runs the focused
  v5.1 test surface plus CLI smoke tests.

### Added — Internationalization (14 languages)

- `obscuralens.i18n`: Python-module catalogues for en, zh, ja, ko, de, fr,
  es, pt, ru, it, nl, pl, ar, hi (220 keys each, 100% coverage); `t()`
  interpolation, `tp()` plurals (zero/one/many), English fallback chain,
  Accept-Language `best_match`, RTL awareness.
- `obscuralens i18n list|show|match` CLI commands.

### Added — Offline data catalog (10 packs)

- IANA port/service registry (~2,600 entries), ISO 3166-1 countries,
  ISO 639 languages, ISO 4217 currencies, HTTP status codes, a MITRE CWE
  selection, the IANA root-zone TLD list (~1,400), file extensions, MIME
  types and a user-agent rotation pool (~317 realistic current agents).
- Typed, never-raising `obscuralens.utils.data_catalog` API plus the
  `obscuralens data country|port|tld|cwe|status|ua|mime|stats` CLI family.

### Added — Python SDK

- `obscuralens.sdk`: sync `ObscuraLensClient` and `AsyncObscuraLensClient`
  covering every REST endpoint, stdlib-only transport, retries with
  exponential backoff and Retry-After honouring, typed exception hierarchy
  (ApiError/NotFoundError/RateLimitError/...), injectable `StaticTransport`
  for offline tests.

### Added — Explainable risk rule packs

- `obscuralens.rules`: YAML rule DSL with 23 operators (`in_cidr`,
  `age_lt_days`, `known_pack`, regex, comparisons, membership, ...) and 15
  packs (shared + all 14 kinds, ~165 rules). Every hit carries an
  explanation; scores accumulate to a 0-100 band
  (clean/watch/elevated/high/critical).

### Added — Reports, pipelines, docs

- Jinja2 report templates: standalone HTML (self-contained CSS, print
  styles, accessible tables), Markdown and an executive summary card, plus
  the `template_render` module with `esc`/`nl2br`/`fmt_pct` filters.
- 8 new pipeline examples (email triage, phishing URL review, CVE patch
  priority, crypto screening, malware hash response, brand username audit,
  network sweep, weekly exec brief).
- New docs: desktop-beta.md, i18n.md, data-packs.md, sdk.md, rules.md,
  v5.1.md.

### Fixed

- The PyInstaller spec now bundles **all package data** (offline data packs,
  rule packs, report templates) via `collect_data_files` — previously the
  standalone exe silently shipped without them. pyproject package-data
  globs added for wheels too.

## 5.0.0 — 2026-10-03

ObscuraLens grows from 10 to **14 target kinds**, gains a local-first analyst
toolbox, an advanced-analysis package (batch, alerts, pattern-of-life,
geospatial profiling, HTML report builder), a complete single-page web
application and a one-command launcher that installs and opens the UI in a
single step.

### Added

- **Four new trackers** (kind count 10 → 14):
  - `obscuralens mac <addr>` — EUI-48 MAC addresses: offline curated IEEE OUI
    pack (766 vendors), keyless macvendors.com full-registry lookup, keyless
    maclookup.app record (company, country, address, assignment type) and an
    offline bit decomposition (multicast/local flags, 01:00:5E / 33:33
    reserved blocks, Docker 02:42 vNIC decode with embedded container IPv4,
    EUI-64 expansion, modified-EUI-64 IPv6 interface id, privacy-randomization
    hint). Colon, dash and Cisco dot notations accepted.
  - `obscuralens iban <iban>` — ISO 13616 IBANs: offline mod-97 checksum,
    per-country structure pack (124 countries → bank code + account slices),
    pretty/masked forms and keyless openiban.com validation with BIC
    resolution. Printed IBANs with spaces and a leading `iban:` are accepted;
    failed checksums are rejected before any source is contacted.
  - `obscuralens imei <num>` — IMEI/IMEISV: offline 3GPP TS 23.003
    decomposition (TAC, reporting-body identifier, SNR, Luhn check digit)
    plus an offline TAC pack (139 entries → manufacturer + model). Separators
    tolerated; 16-digit IMEISV recognised.
  - `obscuralens coords <lat, lon>` — geographic coordinates in decimal
    degrees, DMS, UTM or MGRS: reverse geocoding via keyless OpenStreetMap
    Nominatim and BigDataCloud, Open-Elevation terrain height, and a fully
    offline maths source (geohash, Maidenhead, DMS/DDM, UTM, MGRS, timezone
    hint, NOAA solar position) backed by a 115-country centroid pack.
- **New sources for existing trackers**:
  - Username: 4 new HTML platforms — Patreon, Etsy, Substack and Replit
    (45 platforms total: 38 HTML + 7 JSON API), with honest three-state
    verdict rules (bot-walled Patreon/Etsy answer `unknown`, never "hit").
  - IP: keyless ipapi.is (geo, ASN, company, datacenter/VPN/proxy flags,
    risk score) and keyless ipinfo.io (country, org, hostname, lat/lon);
    the `threat_feeds` source now also reports `urlhaus_listed` /
    `threatfox_listed`.
  - Domain: `doh.google` — DNS-over-HTTPS resolver (dns.google) cross-checking
    A/AAAA/MX/NS answers against the classic DoH source.
  - CVE: CIRCL cveproxy records (CVE-5.1 and legacy schemas), merged onto the
    NVD field names plus CIRCL-specific extras.
  - Crypto: keyless mempool.space (BTC balance, received/sent, tx count,
    pending-tx counter) reusing blockchain.info's field names so provenance
    stacks.
  - Threat-intel feeds: abuse.ch URLhaus (malicious-URL host network list)
    and ThreatFox (recent IOC CSV export — the keyed JSON API now requires
    an Auth-Key, so the keyless export is used); feed tokenizer registry
    added, 20 000-network cap per feed.
- **Experimental analyst toolbox** (`obscuralens/experimental/`, exposed as
  `obscuralens tools …`): `encoders` (13 encode schemes + auto-decode ranking
  + all-checksums), `jwt_tools` (decode + inspect, never verify), `hash_identify`
  (structural digest identification with same-length alternatives and the
  Keccak-256 trap), `entity_extract` (validator-driven extraction of 16
  entity kinds from free text + reversible redaction), `squatting` (15
  typosquat families with deception-risk scoring), `exif_reader` (zero-
  dependency JPEG/PNG/GIF/BMP/WebP metadata triage, fully local) and
  `steganography` (PNG/BMP/GIF LSB plane statistics, entropy profiling and
  embedded-file carving, fully local).
- **Advanced analysis package** (`obscuralens/advanced/`): `batch`
  (`run_batch(kind, targets, risk, max_workers)` fan-out engine), `alerts`
  (webhook notifications for `lookup_failed` / `watch_diff` / `risk_high` /
  `source_tripped`), `patterns` (`pattern_report(kind, value)` pattern-of-life
  over stored history), `geospatial` (country breakdown, targets-by-country,
  geohash clusters, top regions, GeoJSON export, one-call profile summary)
  and `report_builder` (`build_report(kind, target)` self-contained HTML
  investigation report).
- **Complete web SPA rewrite** (`obscuralens/web/static/`, no build step, no
  CDN, fully offline ES modules): 10 views (dashboard, lookup workbench,
  investigate graph, timeline, cases, watchlist, sources, tools, history,
  settings), ⌘K command palette with fuzzy matching, dark/light themes,
  zero-dependency canvas chart library (line/donut/bars/sparkline/heatmap/
  scatter) and a force-directed entity-graph engine (pan/zoom/drag, PNG
  export). See the new [docs/web-ui.md](docs/web-ui.md).
- **One-command launcher**: `./start.sh` (Linux/macOS) and `start.ps1`
  (Windows) create `.venv`, install dependencies plus web extras and run
  `obscuralens serve --open` at http://127.0.0.1:8000; also `make start` /
  `just start`. Flags: `--no-open`, `--port`.
- **New CLI commands**: `mac`, `iban`, `imei`, `coords`; `tools
  encode|decode|jwt|hash-id|coords|extract|squat|exif|stego`; `report`;
  `patterns`; `geo profile|clusters|regions`; `alerts show|set|test`; and
  `serve --open`.
- **MCP server: 34 tools** — 16 new (`mac_lookup`, `iban_lookup`,
  `imei_lookup`, `coords_lookup`, `tools_encode`, `tools_decode`, `tools_jwt`,
  `tools_hash_id`, `tools_extract`, `tools_squat`, `tools_exif`, `tools_stego`,
  `tools_coords_convert`, `tools_geo_profile`, `tools_patterns`,
  `tools_batch`) alongside the existing 18.
- **REST API v5**: `/api/kinds`, `/api/history`, `/api/keys` (GET/POST/DELETE),
  `/api/settings` (GET/POST), `/api/tools/encodings|decode|jwt|hash-id|coords|
  extract|squat|batch`, `/api/tools/file/exif|stego` (multipart),
  `/api/report/{kind}/{target}`, `/api/patterns`, `/api/alerts`
  (GET/POST + `/test`), `/api/diff/{kind}/{target}`, and case item/note/tag
  sub-resources (`POST /api/cases/{id}/items|notes|tags`, `PATCH
  /api/cases/{id}`). All v4 endpoints keep working unchanged.
- **Offline data packs** (`obscuralens/data/`): `oui.txt` (766 curated IEEE
  OUI assignments), `tac.txt` (139 TAC→manufacturer/model entries),
  `iban_structures.txt` (124 country structures) and `country_centroids.txt`
  (115 country centroids).

### Changed

- Version bump to 5.0.0 across package metadata, banner and user agent.
- Every kind-aware surface now handles 14 kinds: `investigate`, `batch`,
  `history`, `case add` auto-detection, watchlist, risk, timeline,
  correlation, graph exports, MCP and the web API.
- `obscuralens serve` serves the new SPA from `web/static/` at `/` (OpenAPI
  docs stay at `/docs`); `serve --open` launches a browser at the dashboard.
- The interactive console and non-interactive CLI gained a Tools menu and
  v5 commands (agent integration wave).
- The username tracker sweeps 45 platforms (was 41); the platform registry is
  shared with the permutation sweeper.
- `intel feeds` lists six feeds (Tor exit list, Spamhaus DROP, Feodo,
  FireHOL level-1, URLhaus, ThreatFox).

## 4.0.0 — 2026-10-01

ObscuraLens grows from a lookup console into an investigation platform: 10
target kinds, correlation and timelines across stored history, explainable
risk scoring, case management, YAML pipelines and graph exports.

### Added

- **Five new trackers**:
  - `obscuralens url <url>` — manual redirect walk (chain, count, final URL,
    status, title, server), urlscan.io scan history and malicious verdicts,
    Wayback Machine captures via the CDX API, plus keyed Google Safe
    Browsing (`gsb_malicious`, clean responses count as a verdict) and
    VirusTotal URL detections.
  - `obscuralens crypto <address>` — BTC/ETH/LTC/DOGE (XMR/XRP/ADA detected
    but unsourced): blockchain.info and Blockstream Esplora balances and
    activity, Blockchair address stats across four chains, keyed Etherscan
    balance and transaction timestamps. Chain routing: an ETH address never
    hits the BTC explorers.
  - `obscuralens hash <hash>` — MalwareBazaar (family, file names, tags;
    optional Auth-Key), CIRCL hashlookup known-file corpus, AlienVault OTX
    pulses and keyed VirusTotal file reports (detections, reputation, threat
    label). MD5/SHA-1/SHA-256 routed per algorithm.
  - `obscuralens cve <id>` — NVD 2.0 (CVSS V3.1 > V3.0 > V2 preference,
    CWE, references, CPEs; optional API key), Google OSV.dev (affected
    packages, severity vector), the raw cvelistV5 CNA record and FIRST.org
    EPSS exploitation probability.
  - `obscuralens asn <num>` — RIPEstat overview + announced prefixes and
    BGPView record, prefixes and peers.
- **New sources for existing trackers**:
  - IP: ipapi.co, AlienVault OTX (pulses, malware samples, passive DNS),
    hackertarget reverse IP, a `threat_feeds` source (Tor exit list,
    Spamhaus DROP, Feodo Tracker, FireHOL level-1) and keyed GreyNoise
    community context.
  - Domain: crt.sh certificate transparency, hackertarget hostsearch and
    RFC 9116 security.txt disclosure contacts.
  - Email: EmailRep.io reputation, GitHub commit authorship search and a
    disposable-domain check backed by an offline pack of 3,000+ domains.
  - Username: 8 new HTML platforms — Steam, Mastodon, Wattpad, SlideShare,
    Redbubble, Hackaday.io, Last.fm and Kaggle (41 platforms total:
    34 HTML + 7 JSON API).
  - Phone: offline geo enrichment from a full ISO 3166-1 country table
    (country name, flag emoji, continent).
- **Correlation package** (`obscuralens/correlation/`): entity extraction
  from every tracker payload, a cross-record entity graph with
  case-insensitive dedupe, BFS **clusters**, **bridge entities** (degree ≥ 3)
  and `correlate(a, b)` shared-infrastructure comparison over stored history
  (`obscuralens correlate --all` / pair mode).
- **Timeline builder**: chronological events from dated fields across all
  kinds (registration dates, certificate sightings, first/last-seen stamps,
  breach dates, CVE publication, on-chain activity), sorted oldest → newest
  with a configurable cap (`obscuralens timeline`).
- **Heuristic risk scoring**: per-kind explainable signals
  (`{'score', 'verdict', 'signals', 'summary'}`) — technical indicators only,
  never verdicts about people; every signal carries a weight and a detail
  string naming the observed values. `obscuralens risk`, the `--risk` flag
  on every lookup, and `attach_risk()` for reports.
- **Case management** (`obscuralens/cases/`, 14 CLI subactions): SQLite
  cases with items (auto kind detection), notes, tags, close/reopen/archive,
  `find` by value and markdown/JSON export.
- **YAML pipelines** (`obscuralens/pipelines/`): `lookup`, `risk`,
  `timeline`, `correlate`, `assert` (==/!=/</>/in/contains/exists over
  dotted result fields) and `output` (table/json/markdown) steps with
  `$variable` interpolation; `pipeline list|run|init` and three commented
  examples in `pipelines/examples/` (domain-review, ip-triage, brand-abuse).
- **Experimental features** (`obscuralens/experimental/`, gated by
  `app.experimental_features`): OpenAI-compatible LLM narrative summaries,
  username permutation generation + bounded platform sweeps, a robots-aware
  same-domain web crawler and a phishing heuristic score over offline packs.
- **Graph exports** (`obscuralens/export/`): GraphML, GEXF 1.3, Graphviz
  DOT (stable per-type node colours), JSONL and CSV edge lists via
  `obscuralens export`, `investigate --export` and `correlate --export`.
- **Source health + circuit breaker** (`obscuralens/health/`): persisted
  per-source success/failure statistics with reliability percentages;
  sources failing `source_failure_threshold` times in a row are tripped for
  `source_cooldown_seconds`. `obscuralens sources health [--reset SOURCE]`.
- **Threat-intel package** (`obscuralens/intel/`): Tor bulk exit list and
  Onionoo relay details (nickname, fingerprint, flags, bandwidth), plus the
  Spamhaus DROP / Feodo / FireHOL level-1 blocklist feeds — all cached for
  6 hours (`obscuralens intel ip|tor|feeds`).
- **Offline data packs** (`obscuralens/data/`, shipped via package-data):
  disposable_email_domains (3,000+), popular_domains (335) and
  phishing_keywords (629), loaded through a caching loader
  (`utils/data_packs.py`); `utils/geo.py` adds the full ISO 3166-1 country
  table, flag emoji, haversine distance and coordinate-spread helpers.
- **14 new CLI commands** — `url`, `crypto`, `hash`, `cve`, `asn`, `risk`,
  `timeline`, `correlate`, `diff` (field-by-field comparison of stored
  results), `export`, `case`, `pipeline`, `intel`, `experimental` — plus
  `sources health`, a `--risk` flag on all lookups and
  `investigate --export/--timeline/--llm`.
- **MCP server: 18 tools** — new `url_lookup`, `crypto_lookup`,
  `hash_lookup`, `cve_lookup`, `asn_lookup`, `risk_report`, `correlate`,
  `timeline`, `threat_intel` and `source_health` alongside the original 8.
- **Web API**: new `/api/risk/{kind}/{target}`, `/api/timeline`,
  `/api/correlate` (+ `/api/correlate/pair`), `/api/intel/{ip}`,
  `/api/cases` (GET/POST, GET by id) and `/api/export/{fmt}/{target}`
  endpoints; `/api/stats` now includes source-health rows.
- **New keyed services**: `etherscan`, `greynoise`, `otx`,
  `google_safe_browsing`, `github`, `nvd`, `malwarebazaar`, `securitytrails`
  and `llm` (experimental summaries).

### Changed

- Version bump to 4.0.0 across package metadata, banner and user agent.
- `investigate` follows new v4 pivots: URL → host domain, IP → InternetDB
  vulnerabilities as CVEs, domain → first A record's ASN; target detection
  now recognises URLs, CVEs, hashes and AS numbers.
- `batch` and `history` accept the five new kinds; `sources` lists the
  per-kind catalogs (or `health` reliability rows) and `keys` shows all 17
  services.
- pyproject ships `obscuralens/data/*.txt` as package-data so the offline
  packs work from wheels and the standalone executable.
- Unit suite grew from ~160 to 738 tests (correlation, cases, pipelines,
  experimental, export, health, intel, geo and the five new trackers), all
  fully offline.

## 3.1.0 — 2026-10-01

### Added

- **Launch methods**:
  - `obscuralens serve` — FastAPI web UI (self-contained dashboard) + REST API
    with OpenAPI docs; optional `[web]` extra.
  - `obscuralens tui` — Textual terminal UI; optional `[tui]` extra.
  - `obscuralens mcp` — dependency-free MCP stdio server exposing eight tools
    (`ip_lookup`, `phone_lookup`, `username_lookup`, `email_lookup`,
    `domain_lookup`, `investigate`, `watch_list`, `watch_check`).
  - `Dockerfile`, `docker-compose.yml` and GHCR publishing from CI.
  - PyInstaller single-file executable (`scripts/obscuralens.spec`), built and
    uploaded as a CI artifact.
  - `run.ps1` / `run.sh` one-command launchers and pipx/uv instructions.
  - `scripts/scheduled_check.py`, `docs/scheduling.md` and a daily
    `.github/workflows/watch.yml` for cron/Task Scheduler/GitHub Actions.
  - Dev container, VS Code tasks/launch configs, `Makefile` and `justfile`.
- **CI**: new `web`, `tui`, `docker` and `exe` jobs; the sanity job now also
  imports the MCP server.

### Changed

- Version bump to 3.1.0 across package metadata, banner and user agent.
- New optional extras `web`, `tui`, `exe`; dev extras gain `httpx`.
- `.gitignore` un-ignores the committed `.vscode/*.json` configs.

## 3.0.0 — 2026-10-01

### Added

- **Universal investigation** (`investigate` command and console menu):
  automatic target-type detection, bounded pivots (email → domain,
  domain → A records, ip → PTR), an entity/relationship graph and Mermaid
  export (`--format mermaid`, `--graph FILE`).
- **Watchlist** (`watch add|list|remove|check`): stores result snapshots in
  SQLite and diffs successive runs — new/removed/changed fields with volatile
  fields (timestamps, ages) ignored, username status tracked per platform.
- **Plugin system** (`obscuralens plugins list|reload`, `docs/plugins.md`):
  drop-in data sources for ip/domain/email from `<project>/plugins` or
  `<config_dir>/plugins`, exposed in results as `plugin:<file>:<name>`,
  error-isolated and switchable with `app.enable_plugins`.
- New keyless sources: RIPEstat (announced prefix, origin ASN/holder, RIR),
  urlscan.io (scan history, observed IPs/servers) and the Wayback Machine
  (first/last capture) — 14 keyless sources plus 8 optional keyed ones.
- Interactive menu entries for Watchlist and Universal Investigate.

### Changed

- Version bump to 3.0.0 across package metadata, banner and user agent.
- `.gitignore` scratch patterns are now anchored to the project root so
  package `__init__.py` files can never be ignored by accident.
- `obscuralens sources` / `keys` and the source catalogs include the new
  sources; plugin failures are reported per source like any other source.

## 2.0.0 — 2026-10-01

### Added

- **Domain tracker** (`obscuralens domain <domain>`): RDAP registration dates
  and registrar, DNS (MX/A/AAAA/NS/SOA/CAA/TXT), SPF/DMARC/DKIM/DNSSEC posture,
  Certificate Transparency issuance history and subdomains via Cert Spotter,
  HTTP status/title/security headers and robots.txt — with batch support.
- **Non-interactive CLI** (`obscuralens/commands.py`): `ip`, `phone`,
  `username`, `email`, `domain`, `batch`, `history`, `stats`, `sources`, `keys`,
  `cache`, `config`, `--version`. Formats: table, json, markdown, html, csv;
  `-o/--output` writes to a file; `--timeout/--no-cache/--no-color` per run.
  Results go to stdout, diagnostics to stderr, with meaningful exit codes.
- **Field provenance**: every IP/email/domain result carries `field_sources`
  mapping each field to the source(s) that supplied it; the console exposes it
  under "Show field sources".
- **New IP sources**: Shodan InternetDB (keyless — open ports, CVEs, CPEs,
  hostnames, tags); keyed IPinfo and AbuseIPDB integrations.
- **Expanded DNS/email posture**: AAAA/NS/SOA/CAA/TXT records, DNSSEC signing
  detection, DKIM selector discovery (records with an empty `p=` anti-abuse key
  are correctly ignored), null MX detection, domain age and days-to-expiry.
- **New username platforms**: 7 JSON API platforms (Keybase, HackerNews,
  Lichess, Codeberg, Docker Hub, Dev.to, Chess.com) with high-confidence
  verdicts, joining the existing 26 HTML platforms. `--platforms` can restrict
  a scan.
- **Infrastructure**: SQLite TTL response cache (zlib-compressed, size-capped),
  per-host token-bucket rate limiting, proxy support, process network metrics
  (`obscuralens stats`), `OBSCURALENS_CONFIG_DIR` and per-user config fallback.
- **Engineering**: `pyproject.toml` (PEP 621) with dev extras, pytest unit
  suite with fully mocked network (~90 tests), GitHub Actions CI (lint + tests
  on Python 3.9–3.13), ruff configuration, shared report-section builders used
  by console, CLI and exports, `render_markdown`/`render_html` string APIs on
  the report generator.

### Fixed

- `print_table` crashed on row-list data, breaking virtually every interactive
  result view (`AttributeError: 'list' object has no attribute 'keys'`).
- `cli.py` called `json.dumps` in `_fmt_value` without importing `json`.
- DMARC records were filtered before unquoting DoH answers, so `dmarc_record`
  was frequently missed.
- MX parsing could emit an empty host for null MX (`0 .`); now reported as
  `null_mx`.
- `max_history_entries` was never enforced; history is now pruned on write.
- Version/author metadata was inconsistent (`__init__` said 3.0 while the
  package said 1.0.0 and credited the original author).
- `ChartGenerator`/`ReportGenerator` now honour `report_dir`/`chart_dir`
  configuration instead of hardcoding paths.

### Changed

- HTTP client is cache/rate-limit/proxy aware and records metrics; HIBP/Hunter
  calls bypass the cache so breach data is always fresh.
- Email verification checks (OpenPGP, Gravatar) now use cached status fetches.
- Removed the unused `obscuralens/apis/` package (dead duplicate clients; the
  trackers contain the maintained implementations).
- Removed the unused `dnspython` dependency (DNS runs over DNS-over-HTTPS).
- ANSI colours auto-disable when stdout is not a terminal or `NO_COLOR` is set.

## 1.0.0

- Initial packaged, multi-module release.
- Multi-source IP aggregation (8 keyless sources + RDAP + PTR), email tracker
  (MX/A/SPF/DMARC, disposable, OpenPGP, domain RDAP, Gravatar, pattern
  analysis), phone metadata, honest three-state username detection.
- Concurrent batch lookups, HTML/JSON/Markdown/CSV/PDF reports, charts,
  SQLite history with search and statistics, 4-layer configuration.
