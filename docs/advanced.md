# Advanced guide

v4.0 turns stored lookups into an investigation workflow: entity graphs and
pivots, correlation across history, chronological timelines, explainable
risk scoring, case management, YAML pipelines and graph exports. v5.0 adds
the **advanced analysis package**: batch fan-out, webhook alerts,
pattern-of-life reports, geospatial profiling and self-contained HTML
reports. This guide walks through each piece with concrete commands.

## The investigation graph and pivots

`obscuralens investigate <target>` auto-detects the target kind (all fourteen
are recognised), runs the matching tracker and follows a **bounded** set of
pivots to related entities, building an entity/relationship graph that can
be rendered as a table, JSON, Mermaid or exported for external tools.

Pivots (capped by `--max-pivots`, default 3):

| From | Pivot | To |
|---|---|---|
| email | its mail domain is looked up | domain |
| domain | up to N A records are looked up | ip |
| ip | its PTR hostname is looked up | domain |
| url | its host is looked up | domain |
| ip | InternetDB/Shodan vulnerabilities are looked up | cve |
| domain | the first A record's ASN is looked up | asn |
| cve | no pivot (reference data) | — |

```powershell
obscuralens investigate example.com
obscuralens investigate alice@example.com -f json
obscuralens investigate 8.8.8.8 -f mermaid --graph ip.mmd
obscuralens investigate https://example.com --no-pivot
obscuralens investigate example.com --export graphml -f json
obscuralens investigate example.com --timeline --risk
```

`--export FMT` writes the entity graph as GraphML/GEXF/DOT/JSONL/CSV (next
to `-f mermaid`/`--graph` which emit Mermaid inline). `--timeline` appends a
chronological event section; `--llm` appends an experimental narrative
summary ([docs/experimental.md](experimental.md)).

Every lookup is stored in the SQLite history database
(`data/obscuralens.db`), which is what powers the features below.

## Correlation engine

The `correlation` package extracts entities from every stored tracker
payload (IPs, domains, hostnames, ASN peers, breach names, CVE CPEs, crypto
prefixes, profile URLs, …), merges them into one cross-record graph and
answers two questions: *what clusters together?* and *are these two targets
related?*

- **`build_graph(records)`** — entity graph plus **clusters** (BFS connected
  components over the undirected link graph, largest first) and **bridges**
  (entities with degree ≥ 3, i.e. shared infrastructure several targets hang
  off — a hosting IP, a registrar, a nameserver).
- **`correlate(a, b)`** — shared-infrastructure comparison: shared
  neighbours with the edge labels on both sides, direct hits, and a
  `related` boolean that also fires on multi-hop paths (≤ 3 hops).
- **`history_records()`** — reads the stored history (capped by
  `app.correlation_max_history`, default 500 rows) so correlation improves
  automatically as you keep looking things up.

```powershell
obscuralens correlate 8.8.8.8 dns.google     # pair mode: shared entities
obscuralens correlate --all                   # clusters + bridges over history
obscuralens correlate --all --limit 200       # consider fewer history rows
obscuralens correlate --all --export gexf     # write correlation.gexf
```

Pair mode output lists each shared entity with the relation that connected
it to both targets ("Shared Infrastructure" table). `--all` prints graph
stats (targets, entities, links, clusters, largest cluster, bridges) plus
the bridge and cluster tables.

> Correlation reads **your** history: two targets only connect if something
> you already gathered links them (a shared IP, registrar, peer, breach,
> host, …). Run lookups first, then correlate.

## Timeline builder

`obscuralens timeline` walks dated fields across all stored results —
registration/expiry dates, certificate sightings, archive captures, breach
added dates, profile join dates, on-chain first/last activity, CVE
publication — and renders one chronological event table, oldest → newest.
The most recent events are kept when the cap truncates
(`app.timeline_max_events`, default 200; `--limit` overrides per run).

```powershell
obscuralens timeline                    # every stored target
obscuralens timeline example.com        # rows mentioning one target
obscuralens timeline --limit 50 -f json
obscuralens investigate example.com --timeline   # inline after a lookup
```

## Risk scoring

`obscuralens risk <kind> <target>` runs a lookup, scores the merged fields
and attaches an explainable block:

```
{'score': 0-100, 'verdict': ..., 'signals': [{'id', 'weight', 'detail'}], 'summary': ...}
```

Verdict bands: `clean` 0–14, `low` 15–39, `medium` 40–69, `high` 70–89,
`critical` 90+. Unknown/empty payloads score `unknown`.

**Philosophy.** The score is a heuristic sum of weighted *technical
indicators* — abuse reports, blocklist hits, mail posture, registration age,
detection counts. It is deliberately:

- **Explainable** — every signal names its weight and the observed value
  ("AbuseIPDB abuse confidence 87%", "domain registered 3 day(s) ago").
  Nothing is hidden inside a model.
- **Technical only** — it describes infrastructure and exposure. It is never
  a verdict about a person, and the username/crypto scorers deliberately
  frame their output as *exposure/activity* indicators with zero or minimal
  weights.
- **Cautious with absence** — e.g. domain mail-posture signals (no MX / no
  SPF / no DMARC) only fire when a posture probe actually ran, so partial
  payloads never mis-score.

Attach risk inline with `--risk` on any lookup, or in bulk inside a
pipeline (`risk: true` step). `app.risk_enabled: false` disables attachment
everywhere.

```powershell
obscuralens risk domain example.com
obscuralens risk ip 45.148.10.99 -f json
obscuralens url https://example.com --risk
```

### Signal reference (per kind)

Weights are added; `benign_known_file` is negative (caps at 0); 0-weight
signals are informational only.

| Kind | Signal (weight) |
|---|---|
| **ip** | `abuse_confidence_high` (≥75% → 45), `abuse_confidence_elevated` (≥50% → 30), `abuse_confidence_moderate` (≥25% → 15), `vt_malicious_engines` (20), `vt_suspicious_engines` (10), `known_proxy` (10), `tor_exit` (15), `many_open_vulns` (≥5 → 25), `open_vulns` (10), `many_open_ports` (5), `risky_service_tags` (5), `spamhaus_drop`/`feodo`/`firehol` listed (25 each), `no_dns_presence` (0, informational) |
| **domain** | `very_new_domain` (<7d → 25), `new_domain` (<30d → 15), `no_mx` (5), `no_spf` (10), `no_dmarc` (10), `dmarc_monitor_only` (5), `no_dnssec` (5), `no_a_records` (5), `many_subdomains` (5), `parked_domain` (15), `urlscan_malicious` (25), `typosquat_of_popular` (20), `domain_expired` (5) |
| **email** | `disposable_mailbox` (15), `no_mx` (20), `multiple_breaches` (≥5 → 25), `breached` (10), `emailrep_bad_reputation` (20), `emailrep_low_reputation` (15), `credentials_leaked` (20), `recent_breach` (≤90d → 10) |
| **url** | `gsb_malicious` (50), `vt_malicious` (1 engine → 15, ≥2 → 25), `redirect_chain` (≥5 hops → 10), `ip_hosted_url` (15), `punycode_host` (20), `urlscan_malicious` (25), `credential_keywords` (5), `nonstandard_port` (5) |
| **hash** | `vt_malicious_heavy` (≥5 engines → 50), `vt_malicious` (25), `vt_suspicious` (10), `malware_family` (30), `otx_pulses` (≥3 → 10), `benign_known_file` (−20), `vt_threat_label` (10) |
| **cve** | `cvss_critical` (≥9.0 → 60), `cvss_high` (≥7.0 → 40), `cvss_medium` (≥4.0 → 20), `epss_very_likely` (≥90 → 15), `epss_likely` (≥50 → 5), `exploit_reference` (15), `cvss_severity_label` (0, echo) |
| **crypto** | `new_address` (≤30d → 10), `unused_address` (0), `funded_address` (0) — activity profile only |
| **username** | `broad_footprint` (≥10 platforms → 5) — exposure indicator only |
| **asn** | `large_transit` / `large_peering` (0) — informational |
| **phone** | (no signals today — parsed metadata only) |

## Case management

`obscuralens case` keeps investigation state in the same SQLite database:
cases with items, notes, tags, a status lifecycle
(open → closed → archived, reopenable) and export. 14 subactions:

`new`, `list`, `show`, `add`, `remove-item`, `note`, `tag`, `untag`,
`close`, `reopen`, `archive`, `delete`, `find`, `export`, `stats`.

```powershell
obscuralens case new "acme-phishing" --description "Brand-abuse investigation"
obscuralens case add 1 https://secure-login.example-verify.com --kind url
obscuralens case add 1 45.148.10.99                  # kind auto-detected
obscuralens case add 1 alice@example.com --kind email --note "victim address"
obscuralens case note 1 "GSB flagged the URL today."
obscuralens case tag 1 phishing
obscuralens case tag 1 brand-abuse
obscuralens case show 1
obscuralens case list                # counts + per-kind item breakdown
obscuralens case find 45.148.10.99   # which cases contain this value?
obscuralens case export 1 -f markdown --path acme-case.md
obscuralens case export 1 -f json
obscuralens case stats
obscuralens case close 1             # items freeze; notes still allowed
obscuralens case reopen 1
obscuralens case archive 1           # hidden from `case list` (use --all)
```

Rules worth knowing: `--kind auto` (the default) detects the item kind from
the value; duplicates are detected per (case, kind, value); closed/archived
cases reject new items but still accept notes (closing remarks); `export`
writes markdown (title, status grid, tags, items table, dated notes) or the
full case JSON. Cases share the lookup database, so anything you have looked
up before can be added by value.

## Pipelines

A pipeline is a YAML file describing a repeatable multi-step investigation:
lookups, risk scoring, timelines, correlation, assertions and output.
Variables (`$name` or `${name}`) are interpolated into any step string;
callers override file defaults with `--set`.

### Schema reference

```yaml
name: my-pipeline            # required
description: what it does     # optional
variables:                    # default values, overridable with --set
  target: example.com

steps:                        # required list; each step is a mapping
  - lookup: $target                 # auto-detect kind from the value
  - lookup:                        # ...or be explicit
      kind: domain                 # ip/phone/username/email/domain/url/
      target: $target              # crypto/hash/cve/asn
  - risk: true                     # attach risk scores to gathered results
  - timeline: true                 # build the event timeline
  - correlate: true                # correlate results + stored history
  - assert:                        # soft quality/escalation checks
      field: abuse_confidence      # dotted path 'info.x' or bare field name
      op: '>='                     # ==, !=, >, >=, <, <=, in, contains, exists
      value: 50                    # numbers compare numerically
      message: address flagged by AbuseIPDB
  - output:
      format: table                # table | json | markdown
      path: report-$target.md      # '' = console; relative → report_dir
```

Step semantics:

- **lookup** — runs a tracker; the kind is auto-detected unless given.
  Unknown kinds/targets record an error and the run continues.
- **risk / timeline / correlate** — boolean steps; set `false` to skip.
  Failing assertions never abort the run.
- **assert** — evaluated against the first result carrying the field; a
  passing assertion becomes a *finding* in the report, a failing one a
  warning. `op: exists` with `value: false` asserts *absence*.
- **output** — writes (or prints) the run report; the JSON snapshot is
  serialised before the step itself is appended (no self-recursion).

Assertion operators:

| Operator | Meaning |
|---|---|
| `==` / `!=` | equal / not equal (numeric when both sides parse as numbers) |
| `>` `>=` `<` `<=` | numeric comparison (string fallback) |
| `in` | the field value is in the expected list, or a substring when both are strings |
| `contains` | the field contains the expected value (string, list or dict fields) |
| `exists` | field present (or absent with `value: false`) |

### Running pipelines

```powershell
obscuralens pipeline list                          # scanned + shipped examples
obscuralens pipeline run ip-triage --set target=45.148.10.99
obscuralens pipeline run pipelines/examples/brand-abuse.yaml --set target=https://x.example/
obscuralens pipeline init my-first-pipeline        # writes a starter YAML
obscuralens pipeline run my-first-pipeline -f json
```

`pipeline list` scans `app.pipeline_dir` (default `pipelines/`) *and* the
shipped `pipelines/examples/`; a pipeline can be run by path or by name.
Three commented examples ship with the repo:

| Example | What it does |
|---|---|
| `domain-review` | domain lookup + IP pivot + risk + timeline + correlate + registrar assert |
| `ip-triage` | IP lookup + risk + AbuseIPDB ≥ 50 escalation assert + JSON export |
| `brand-abuse` | URL + domain lookups + Google Safe Browsing assert + markdown report |

## Graph exports

The investigation entity graph can be written in five formats for external
tools:

| Format | Tooling | Notes |
|---|---|---|
| `graphml` | Gephi, yEd, Cytoscape | typed node/edge attributes |
| `gexf` | Gephi, Sigma.js | GEXF 1.3 |
| `dot` | Graphviz, OmniGraffle | stable per-entity-type colours |
| `jsonl` | anything line-oriented | node records first, then edges |
| `csv` | spreadsheets, SIEMs | edge list: source, relationship, target |

```powershell
obscuralens export graphml example.com          # reports/<slug>.graphml
obscuralens export dot example.com -o graph.dot
obscuralens export gexf example.com --no-pivot
obscuralens export jsonl example.com --from-json saved-investigation.json
obscuralens correlate --all --export csv
obscuralens investigate example.com --export graphml
```

`--from-json FILE` re-exports a saved `investigate -f json` payload without
re-running any lookup. Malformed rows are skipped; edges referencing unknown
entities are dropped from the graph documents (they must stay valid) but
kept in JSONL/CSV as raw relationship records.

Visualise with Graphviz:

```powershell
dot -Tpng graph.dot -o graph.png
```

...or open the `.graphml`/`.gexf` file directly in Gephi.

## Advanced analysis (v5.0)

The `obscuralens/advanced/` package holds five engines that operate on live
lookups and your stored history. Programmatic entry points are importable
as `obscuralens.advanced.<module>`; every one is also wired to a CLI command,
the REST API and (where useful) MCP.

### Batch fan-out

`advanced/batch.py` runs one tracker kind over many targets with a bounded
thread pool:

```python
from obscuralens.advanced.batch import run_batch

results = run_batch('ip', ['8.8.8.8', '1.1.1.1', '45.148.10.99'],
                    risk=True, max_workers=4)
# {'results': [{'target': '8.8.8.8', 'result': {…tracker envelope…}}, …],
#  'summary': {'total': 3, 'ok': 3, 'failed': 0, 'skipped': 0, …}}
```

- **`run_batch(kind, targets=None, risk=False, max_workers=6, progress=None,
  stop_flag=None)`** — each target gets the standard tracker envelope
  (fields, provenance, sources OK/failed, plus an optional `risk` block);
  individual failures never abort the batch, they mark that target's
  result. The engine caps at **200 targets** (`MAX_TARGETS` — the surplus
  is skipped and counted in the summary) and defaults to 6 worker threads;
  `progress`/`stop_flag` let a UI observe and cancel a long run.
- The existing `obscuralens batch ip targets.txt -f csv -o results.csv`
  command now routes through this engine (and accepts all 14 kinds).
- The REST surface is `POST /api/tools/batch {"kind": …, "targets": […],
  "risk": bool}` — capped at **25 targets per request** so an oversized
  payload cannot pin the server; use the CLI for longer lists. The MCP
  `tools_batch` wrapper is stricter still (10 targets, summary + one-line
  entries only) to keep assistant context small.

### Alerts

`advanced/alerts.py` delivers webhook notifications when notable events
happen. Configure once, then leave the server (or scheduled checks)
running:

```powershell
obscuralens alerts show                                  # current config + log
obscuralens alerts set --url https://hooks.example/ol `
  --events risk_high,watch_diff,source_tripped
obscuralens alerts test                                  # fire a test event
```

Canonical events (the programmatic surface is `alerts.configure`,
`alerts.notify`, `alerts.recent`, `alerts.test`):

| Event | Fires when |
|---|---|
| `lookup_failed` | a lookup errored or returned no data |
| `watch_diff` | a watched target changed between snapshots |
| `risk_high` | a lookup scored as high risk |
| `source_tripped` | a source tripped its failure circuit breaker |

Each notification is a small JSON POST to your `webhook_url`, and recent
notifications are logged (that log is what `alerts show` prints and what
`GET /api/alerts` returns, alongside the configuration).

> **Privacy — read this first.** A webhook forwards event data **off your
> machine** to a URL you choose. Point it at an endpoint you control (a
> self-hosted receiver, an internal relay) unless you are comfortable with
> the destination seeing alert payloads naming your targets. Leave the
> webhook empty and the feature stays dormant — nothing is sent anywhere.

### Pattern-of-life

`advanced/patterns.py` answers "when is this target active?" from the
stored history: `pattern_report(kind, value, records=None)` aggregates that
target's past lookups into a behavioural summary — total observations,
first/last seen, inter-observation gaps, burstiness (are lookups clustered
or evenly spread), busiest weekday/hour buckets and a plain-language
interpretation. `value` is a case-insensitive *substring* match, so
`'DE89'` picks up every German IBAN you have looked up.

```powershell
obscuralens patterns username johndoe
obscuralens patterns ip 45.148.10.99 -f json
# {'kind': 'ip', 'target': '45.148.10.99', 'observations': 14,
#  'first_seen': '…', 'last_seen': '…', 'gaps': {…},
#  'bursts': 3, 'weekday_histogram': […], 'hour_histogram': [...],
#  'interpretation': '…', …}
```

The REST surface is `GET /api/patterns?kind=&value=`; the MCP surface is the
`tools_patterns` tool. The report only describes **your own observation
history** — it is a schedule of when you looked, not telemetry from the
target itself. Say that aloud in any report you paste it into.

### Geospatial profiling

`advanced/geospatial.py` aggregates the geographic footprint of everything
in your stored history (country fields from IP lookups, reverse-geocoded
countries and lat/lon from coords lookups, registration countries from
RDAP):

| Function | Returns |
|---|---|
| `country_breakdown(records=None)` | per-country histogram with lookup counts, `total_records` and an `unknown` bucket for unresolvable IP records |
| `targets_by_country(country, records=None)` | stored IP targets that resolved into a country — case-insensitive substring match, so `'fr'`, `'FR'` and `'France'` all work |
| `geohash_clusters(records=None, precision=4)` | coordinate lookups clustered by shared geohash prefix (~20 × 20 km at the default precision), each with its centre and member targets |
| `most_looked_up_regions(records=None, limit=10)` | top state/subdivision-level regions with counts and contributing targets |
| `to_geojson(breakdown)` | a `country_breakdown` result as a GeoJSON `FeatureCollection` (centroid pins, `[lon, lat]` order — drops into Leaflet / mapbox-gl / deck.gl) |
| `geo_profile_summary(records=None)` | the one-call analyst summary: distinct countries, top country/region, coords lookup count, geohash cluster count, history span in days |

Every function accepts an optional pre-loaded `records=` list (pure and
offline-testable); without one they read the stored history (capped at 800
rows, plus the coordinate lookups the correlation engine skips).

```powershell
obscuralens geo profile      # distinct countries, top region, span
obscuralens geo clusters     # geohash clusters
obscuralens geo regions      # top countries and regions
# deeper shapes: -f json; GeoJSON export via the to_geojson() API
```

The MCP `tools_geo_profile` tool exposes the summary. Like every
history-based feature, the profile is only as good as the lookups you have
run — and it describes where your *targets* are, not where you are.

### Report builder

`advanced/report_builder.py` renders a **self-contained HTML investigation
report** for one target: `build_report(kind, target, result=None,
payload=None)` runs the lookup (or reuses a result you already hold) and
returns a single HTML document with embedded CSS, no external assets, no
scripts — safe to email, archive or open in an air-gapped browser.

```powershell
obscuralens report domain example.com            # writes reports/<slug>.html
obscuralens report ip 45.148.10.99 --output triage.html
```

The REST surface is `GET /api/report/{kind}/{target}` (returns the HTML
document directly — a browser pointed at it renders the report). The report
reuses the merged-fields + provenance layout of the console output, so every
fact names its source.

## Source health and circuit breaker

Every gather records per-source success/failure into a `source_health`
table in the same SQLite database. From it ObscuraLens derives:

- **reliability** — `ok / (ok + fail)` percentage per source;
- **state** — `healthy`, `untested`, or `tripped`.

A source that fails `app.source_failure_threshold` (default 4) times in a
row is **tripped** (circuit open) for `app.source_cooldown_seconds`
(default 600s); a later success resets the breaker. Health is orthogonal to
`disabled_sources`: the breaker is *observed* behaviour, the list is *your*
choice.

```powershell
obscuralens sources health                    # reliability table (worst first)
obscuralens sources health -f json
obscuralens sources health --reset ip-api.com # wipe one source's stats
```

Config knobs:

```yaml
app:
  source_health_enabled: true   # record stats (off = no table writes)
  source_failure_threshold: 4   # consecutive failures before tripping
  source_cooldown_seconds: 600  # how long a tripped source stays off
```

`/api/stats` and the MCP `source_health` tool expose the same rows.

## Diff command

`obscuralens diff LEFT RIGHT` compares two stored results field by field —
either history ids (from `obscuralens history`) or stored target values —
and reports added / removed / changed fields. Use it after a `watch check`,
between two lookups of the same target, or to compare a suspicious domain
against a known-good one.

```powershell
obscuralens history --search example.com     # find the ids first
obscuralens diff 12 15
obscuralens diff example.com evil-example.com
obscuralens diff 12 15 -f json
```

Changed fields show both sides; username results diff per platform status.

## Where state lives

Everything above reads and writes two SQLite files under `data/` (both
configurable via `app.*` / `database.*` keys):

| File | Contents | Knobs |
|---|---|---|
| `data/obscuralens.db` | lookup history (pruned to `max_history_entries`, default 1000), watchlist snapshots, cases + items/notes/tags, source-health rows | `save_history`, `max_history_entries`, `cases_enabled` |
| `data/http_cache.db` | TTL response cache for keyless GETs (zlib-compressed, size-capped) | `cache_enabled`, `cache_ttl` |

Correlation, timelines, `diff` and `case find` are only as good as this
history: `correlation_max_history` (500) caps how far back `correlate` and
the `/api/correlate` endpoint look. HIBP/Hunter breach calls bypass the
response cache so exposure data is always fresh.

## An end-to-end workflow

A realistic triage of a reported phishing site, using only what this guide
covered:

```powershell
# 1. Score the URL heuristically (offline, instant)
obscuralens experimental phish https://secure-login.example-verify.com/

# 2. Full URL lookup with verdicts + risk, and enrich the host domain
obscuralens url https://secure-login.example-verify.com/ --risk -f json
obscuralens domain example-verify.com --risk

# 3. Follow pivots automatically and export the graph for the report
obscuralens investigate https://secure-login.example-verify.com/ --timeline
obscuralens export graphml example-verify.com

# 4. Check the hosting IP against threat feeds
obscuralens intel ip 45.148.10.99

# 5. Open a case, capture everything, hand it over
obscuralens case new "acme-phishing" --description "reported 2026-10-01"
obscuralens case add 1 https://secure-login.example-verify.com/ --kind url
obscuralens case add 1 example-verify.com --kind domain
obscuralens case add 1 45.148.10.99 --kind ip --note "kit host"
obscuralens case note 1 "GSB flagged; hosting IP on Feodo list."
obscuralens case tag 1 phishing
obscuralens case export 1 -f markdown --path acme-case.md

# 6. Later: did anything change?
obscuralens watch add example-verify.com --label "phish kit"
obscuralens watch check
obscuralens history --search example-verify.com   # grab two run ids
obscuralens diff 12 15                             # field-by-field
```

Steps 1–4 each also exist as one `pipeline run brand-abuse --set target=…`
invocation when the workflow stabilises.

## AI assistants: the MCP surface

`obscuralens mcp` exposes the same building blocks as 34 stdio tools for
MCP clients (Claude Desktop, Cursor, …):

`ip_lookup`, `phone_lookup`, `username_lookup`, `email_lookup`,
`domain_lookup`, `url_lookup`, `crypto_lookup`, `hash_lookup`, `cve_lookup`,
`asn_lookup`, `mac_lookup`, `iban_lookup`, `imei_lookup`, `coords_lookup`,
`investigate`, `risk_report`, `correlate` (pair or `all`), `timeline`,
`threat_intel`, `source_health`, `watch_list`, `watch_check`, plus the v5.0
toolbox wrappers `tools_encode`, `tools_decode`, `tools_jwt`,
`tools_hash_id`, `tools_extract`, `tools_squat`, `tools_exif`, `tools_stego`,
`tools_coords_convert`, `tools_geo_profile`, `tools_patterns` and
`tools_batch`.

The web API mirrors them as HTTP endpoints — see [docs/api.md](api.md).

## Where to go next

- [docs/sources.md](sources.md) — the complete data source catalog.
- [docs/experimental.md](experimental.md) — LLM summaries, permutations,
  crawler, phishing score and the v5.0 analyst toolbox.
- [docs/api.md](api.md) — REST API reference.
- [docs/web-ui.md](web-ui.md) — the web UI tour.
- [docs/v5.md](v5.md) — the v5.0 release overview.
- [docs/plugins.md](plugins.md) — writing your own sources.
