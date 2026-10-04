# REST API reference

ObscuraLens ships an optional FastAPI web UI + JSON REST API. Install the
extra and start the server (or just run `./start.sh`, which does all of
it in one command and opens the browser):

```bash
pip install "obscuralens[web]"
obscuralens serve --host 127.0.0.1 --port 8000 --open
# dashboard:    http://127.0.0.1:8000   (v5.0 single-page app)
# OpenAPI docs: http://127.0.0.1:8000/docs
```

Conventions used by every endpoint:

- **kinds** — `ip`, `phone`, `username`, `email`, `domain`, `url`, `crypto`,
  `hash`, `cve`, `asn`, `mac`, `iban`, `imei`, `coords`, and the v6.0
  additions `vin`, `flight`, `mmsi`, `app`, `bssid` and `plate`.
- **errors** — `400` with `{"detail": "..."}` for unknown kinds / invalid
  targets / bad payloads, `404` for missing resources. Tracker failures are
  *not* HTTP errors: they return the standard result envelope with
  `success: false` (the server never leaks a traceback).
- **envelope** — lookup results share the tracker shape:
  `{target key, info, field_sources, sources_ok, sources_failed, field_count, success, errors}``,
  where `info` holds the merged fields and `field_sources` maps each field
  to the source(s) that supplied it.
- API keys, cache, rate limits and the SQLite history are shared with the
  CLI — anything you look up via HTTP is visible to `history`, `correlate`,
  `timeline` and the cases endpoints.
- All v4 endpoints keep working unchanged; v5.0 endpoints are marked
  *(v5.0)* below; the v6.0 Part 2 [analytics endpoints](#analytics-endpoints-v60)
  are pure offline computation.

## Service endpoints

### `GET /` — dashboard *(v5.0)*

Serves the single-page web application from `web/static/` (no external
assets; see [docs/web-ui.md](web-ui.md)). Older browsers without JavaScript
get a pointer to `/docs` and the CLI.

### `GET /api/health`

Liveness probe. Response: `{"status": "ok", "version": "5.0.0"}`.

```bash
curl http://127.0.0.1:8000/api/health
```

## Lookups

### `GET /api/lookup/{kind}/{target}`

Runs the tracker for one kind. `target` must pass that kind's validator
(e.g. a URL with a scheme, a CVE id like `CVE-2021-44228`, an AS number like
`AS15169`).

```bash
curl http://127.0.0.1:8000/api/lookup/ip/8.8.8.8
curl http://127.0.0.1:8000/api/lookup/url/https%3A%2F%2Fexample.com%2F
curl http://127.0.0.1:8000/api/lookup/cve/CVE-2021-44228
curl http://127.0.0.1:8000/api/lookup/mac/b8%3A27%3Aeb%3Aaa%3Abb%3Acc
curl http://127.0.0.1:8000/api/lookup/iban/DE89370400440532013000
curl http://127.0.0.1:8000/api/lookup/imei/356938035643809
curl http://127.0.0.1:8000/api/lookup/coords/48.8584%2C%202.2945
curl http://127.0.0.1:8000/api/lookup/vin/1HGCM82633A004352
curl http://127.0.0.1:8000/api/lookup/flight/BA2490
curl http://127.0.0.1:8000/api/lookup/mmsi/366910000
curl http://127.0.0.1:8000/api/lookup/app/pypi%3Arequests
curl http://127.0.0.1:8000/api/lookup/bssid/00%3A1A%3A2B%3A3C%3A4D%3A5E
curl http://127.0.0.1:8000/api/lookup/plate/DE%3AB-AB%201234
```

Response shape: the tracker envelope (above). For `username`, `info`
carries the per-platform `results` list instead of scalar fields. For
`iban`/`imei`, a failed mod-97/Luhn validation is a `400` *before* any
source is contacted — typos never reach the network; the v6.0 kinds do
the same (`vin` fails its ISO 3779 check digit, `mmsi` its nine-digit
shape, `flight` its designator grammar).

### `GET /api/investigate?target=…&pivot=true`

Auto-detects the target kind and (optionally) follows bounded pivots.
Response: `{target, kind, results: {kind: tracker envelope}, entities, links, errors}`.

```bash
curl "http://127.0.0.1:8000/api/investigate?target=example.com&pivot=true"
```

### `GET /api/risk/{kind}/{target}` *(v4.0)*

Runs a lookup and attaches explainable heuristic risk scoring:

```bash
curl http://127.0.0.1:8000/api/risk/domain/example.com
```

Response shape: the tracker envelope plus a `risk` block
`{"score": 0-100, "verdict", "signals": [{"id", "weight", "detail"}], "summary"}`.
Verdict bands: `clean` / `low` / `medium` / `high` / `critical`.

## Platform management (v5.0)

### `GET /api/kinds`

The registry of every target kind with labels, examples and source lists —
what the web UI and the MCP surface use to describe themselves.

```bash
curl http://127.0.0.1:8000/api/kinds
```

Response shape: `[{"kind": "ip", "label": "IP address",
"description": "…", "example": "8.8.8.8",
"sources": ["ipwhois.app", "ipwho.is", …]}, …]` — one entry per kind
(17 live in this build: the v6.0 `vin`, `flight` and `mmsi` kinds
included; 20 once part 1 completes).

### `GET /api/history?kind=&q=&limit=`

Stored lookup history with filters. `kind` restricts to one kind; `q` is a
case-insensitive substring match on the stored target; `limit` caps the rows
(default 100).

```bash
curl "http://127.0.0.1:8000/api/history?kind=ip&q=8.8.8&limit=50"
```

Response shape: `{"items": [{"kind", "value", "timestamp",
"success", "field_count", …}], "total": n}` — the same rows the CLI
`history` command shows, newest first.

### `GET /api/keys`

API-key status for every supported service (never the key values).

```bash
curl http://127.0.0.1:8000/api/keys
```

Response shape: `[{"service": "shodan", "configured": true,
"description": "…"}, …]`.

### `POST /api/keys/{service}` *(v5.0)*

Store a key for one service. Body: `{"key": "…"}`. The key lands in the
git-ignored `config/secrets.yaml` exactly as if the environment variable
had been set; the response never echoes it. `400` for an unknown service
or an empty key.

```bash
curl -X POST http://127.0.0.1:8000/api/keys/shodan \
  -H "Content-Type: application/json" \
  -d '{"key": "your_key"}'
```

Response shape: `{"service": "shodan", "configured": true}`.

### `DELETE /api/keys/{service}` *(v5.0)*

Remove a stored key. `404` when the service has no key configured.

```bash
curl -X DELETE http://127.0.0.1:8000/api/keys/shodan
```

Response shape: `{"service": "shodan", "configured": false}`.

### `GET /api/settings` *(v5.0)*

The safe application configuration as a flat dotted-path map (no paths, no
secrets — key values never appear).

```bash
curl http://127.0.0.1:8000/api/settings
```

Response shape: `{"app.cache_enabled": true, "app.request_timeout": 30,
"app.max_workers": 12, …}`.

### `POST /api/settings` *(v5.0)*

Update one runtime setting. Body: `{"path": "app.max_workers",
"value": 16}`. `400` for an unknown path or a value that does not typecheck.
Changes apply to the running process immediately (they are not persisted to
`config.yaml`).

```bash
curl -X POST http://127.0.0.1:8000/api/settings \
  -H "Content-Type: application/json" \
  -d '{"path": "app.max_workers", "value": 16}'
```

Response shape: `{"path": "app.max_workers", "value": 16}`.

## Analysis endpoints (v4.0)

### `GET /api/timeline?target=…&limit=100`

Chronological event timeline across stored lookup history. `target`
(optional) filters rows whose stored value contains it (case-insensitive);
`limit` caps the events (most recent kept).

```bash
curl "http://127.0.0.1:8000/api/timeline?limit=50"
curl "http://127.0.0.1:8000/api/timeline?target=example.com"
```

Response shape: `{"events": [{"date", "target", "event", "source"}],
"count", "first", "last"}` — sorted oldest → newest.

### `GET /api/correlate?limit=…`

Correlation graph, clusters and bridge entities built from stored history
(`limit` defaults to `app.correlation_max_history`, 500).

```bash
curl http://127.0.0.1:8000/api/correlate
```

Response shape: `{"entities": [...], "links": [...],
"clusters": [{"id", "size", "entities"}],
"stats": {"targets", "entities", "links", "clusters", "largest_cluster", "bridges"}}`.
Empty history returns empty lists.

### `GET /api/correlate/pair?a=…&b=…`

Shared-infrastructure comparison between two stored targets.

```bash
curl "http://127.0.0.1:8000/api/correlate/pair?a=8.8.8.8&b=dns.google"
```

Response shape: `{"targets": [a, b], "shared": [{"entity", "type",
"via_a", "via_b"}], "connections": n, "related": bool}`.

## Analysis endpoints (v5.0)

### `GET /api/report/{kind}/{target}`

Renders a **self-contained HTML investigation report** (embedded CSS, no
external assets, no scripts) for one target — a browser pointed at the URL
displays the report directly.

```bash
curl http://127.0.0.1:8000/api/report/domain/example.com -o report.html
```

Response: `text/html`. The report runs the lookup first, so it costs the
same as one tracker call.

### `GET /api/patterns?kind=&value=`

Pattern-of-life report for one stored target — observation count,
first/last seen, gaps, burstiness and weekday/hour histograms over *your*
stored lookups of that target. `400` on a missing/unknown kind or value
with no history.

```bash
curl "http://127.0.0.1:8000/api/patterns?kind=ip&value=45.148.10.99"
```

Response shape: `{"kind", "target", "observations", "first_seen",
"last_seen", "gaps", "weekday_histogram", "hour_histogram",
"interpretation", …}`.

### `GET /api/diff/{kind}/{target}`

Snapshot diff for one watched target: the field-level changes between the
two most recent `watch` snapshots (or the latest snapshot versus a fresh
lookup when only one exists). `404` when the target is not watched.

```bash
curl http://127.0.0.1:8000/api/diff/domain/example.com
```

Response shape: `{"kind", "target", "added": […], "removed": […],
"changed": [{"field", "before", "after"}], "checked_at"}` — the same
change records `POST /api/watch/check` produces, for one target.

### `GET /api/alerts`

The webhook-alert configuration plus the recent-notification log.

```bash
curl http://127.0.0.1:8000/api/alerts
```

Response shape: `{"webhook_url": "" | "https://…",
"events": ["lookup_failed", "watch_diff", "risk_high", "source_tripped"],
"recent": [{"event", "when", "ok", "detail"}, …]}`.

### `POST /api/alerts`

Configure the webhook. Body: `{"webhook_url": "https://hooks.example/ol",
"events": ["risk_high", "watch_diff"]}`. An empty URL disables
notifications. Canonical events: `lookup_failed`, `watch_diff`,
`risk_high`, `source_tripped` (unknown names are rejected with `400`).

```bash
curl -X POST http://127.0.0.1:8000/api/alerts \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://hooks.example/ol", "events": ["risk_high"]}'
```

Response shape: `{"webhook_url": "https://hooks.example/ol",
"events": ["risk_high"]}`.

> **Privacy.** A configured webhook sends event data off the machine
> running ObscuraLens — see [docs/advanced.md](advanced.md#alerts). Leave
> it empty and nothing is sent anywhere.

### `POST /api/alerts/test`

Fire a test notification through the configured webhook and report the
outcome. No body required.

```bash
curl -X POST http://127.0.0.1:8000/api/alerts/test
```

Response shape: `{"ok": true, "status": 200, "detail": "…"}` — or
`{"ok": false, …}` with the failure reason when the webhook is
unreachable (not an HTTP error status itself).

## Analytics endpoints (v6.0)

Nine offline endpoints expose the [analytics package](analytics.md) over
REST — pure computation, no sources queried, no network. Missing fields
and lists with no usable numbers after cleaning return `400` with a
`detail` message.

### `POST /api/analytics/stats`

Descriptive statistics plus a histogram for a numeric list. Body:
`{"values": [1, 2, 3, 4, 100], "bins": 10}` (non-numeric items are
dropped).

```bash
curl -X POST http://127.0.0.1:8000/api/analytics/stats \
     -H "Content-Type: application/json" \
     -d '{"values": [1, 2, 3, 4, 100]}'
```

Response shape: `{"count", "summary": {count, mean, median, stdev, min,
max, q1, q3, iqr, skew, kurt}, "histogram": {bin_edges, bin_counts,
bin_labels}}`.

### `POST /api/analytics/anomalies`

Outlier detection. Body: `{"values": [...], "method": "ensemble",
"threshold": 3.0}` — method is one of zscore/iqr/mad/grubbs/ensemble/
threshold; `threshold` applies to the zscore detector.

Response shape: `{"count", "method", "anomaly_count", "anomalies":
[{"value", "score", "method", "detail": {"index", …}}]}`.

### `POST /api/analytics/timeseries`

Trend / changepoint summary for a value sequence indexed as consecutive
days. Body: `{"values": [5, 6, 5, 6, 20, 21]}`.

Response shape: `{"count", "summary": {count, span_days, trend, direction,
mean, variance, changepoint_count, …}}`.

### `POST /api/analytics/clusters`

Kilometre-space clustering of coordinate pairs. Body: `{"points":
[[52.0, 13.0], [52.1, 13.1]], "eps_km": 25, "min_points": 3}`.

Response shape: `{"point_count", "eps_km", "min_points",
"cluster_count", "clusters": [{centroid, members, size, radius_km,
labels}]}`.

### `POST /api/analytics/keywords`

Stopword-filtered keyword mining. Body: `{"text": "…", "top": 10}`.
Response shape: `{"keyword_count", "keywords": [{term, count, weight}]}`.

### `POST /api/analytics/language`

Script and language fingerprint. Body: `{"text": "…"}`. Response shape:
`{"dominant_script", "script_counts", "hint", "language_guess",
"confidence"}` — eleven tracked scripts, eight language guesses.

### `POST /api/analytics/similarity`

Four-metric similarity between two texts. Body: `{"a": "paypal", "b":
"paypa1"}`. Response shape: `{"jaro_winkler", "levenshtein_ratio",
"ngram", "cosine", "mean", "length_a", "length_b"}`.

### `POST /api/analytics/graph`

Graph metrics over an entities/links payload (the investigate/correlation
shape; `from`/`to` link keys accepted). Body: `{"entities": [{"id": "a"},
…], "links": [{"source": "a", "target": "b"}, …]}`.

Response shape: `{"entity_count", "link_count", "summary": {node_count,
edge_count, density, component_count, top_entities, bridges, …}}`.

### `GET /api/analytics/history?limit=500`

Enrichment report over stored query history: kind frequency, hour/weekday
profiles, success rates, source reliability, day-volume anomalies and
top targets. An empty history yields a well-formed empty report.

```bash
curl "http://127.0.0.1:8000/api/analytics/history?limit=500"
```

## Threat intel (v4.0)

### `GET /api/intel/{target}`

Threat-intel verdict for an IP: Tor exit membership, blocklist feeds and
Onionoo relay details. Feed downloads are cached for 6 hours.

```bash
curl http://127.0.0.1:8000/api/intel/45.148.10.99
```

Response shape: `{"ip", "feeds": {"tor", "spamhaus_drop", "feodo",
"firehol_level1", "listed_count", "relay"}, "tor_exit": bool, "relay":
{...}}`.

## Cases (v4.0)

### `GET /api/cases`

Every investigation case (archived included) with item/note/tag counts.

```bash
curl http://127.0.0.1:8000/api/cases
```

### `GET /api/cases/{case_id}`

One case with its items, notes and tags; `404` when unknown.

```bash
curl http://127.0.0.1:8000/api/cases/1
```

### `POST /api/cases`

Create a case. Body: `{"name": "acme-phishing", "description": "…"}`
(`name` required). Returns the created case; `400` on a missing name.

```bash
curl -X POST http://127.0.0.1:8000/api/cases \
  -H "Content-Type: application/json" \
  -d '{"name": "acme-phishing", "description": "Brand abuse"}'
```

### `POST /api/cases/{case_id}/items` *(v5.0)*

Add an item to a case. Body: `{"value": "45.148.10.99", "kind": "ip",
"note": "kit host"}` — `kind` is auto-detected from the value when
omitted. `404` for an unknown case; closed/archived cases reject new items.

```bash
curl -X POST http://127.0.0.1:8000/api/cases/1/items \
  -H "Content-Type: application/json" \
  -d '{"value": "45.148.10.99", "kind": "ip", "note": "kit host"}'
```

Response shape: the created item `{"id", "case_id", "kind", "value",
"note", "added_at"}`.

### `POST /api/cases/{case_id}/notes` *(v5.0)*

Append a free-form note. Body: `{"text": "GSB flagged the URL today."}`.

```bash
curl -X POST http://127.0.0.1:8000/api/cases/1/notes \
  -H "Content-Type: application/json" \
  -d '{"text": "GSB flagged the URL today."}'
```

Response shape: the created note `{"id", "case_id", "text", "created_at"}`.

### `POST /api/cases/{case_id}/tags` *(v5.0)*

Add a tag. Body: `{"tag": "phishing"}`.

```bash
curl -X POST http://127.0.0.1:8000/api/cases/1/tags \
  -H "Content-Type: application/json" \
  -d '{"tag": "phishing"}'
```

Response shape: the case's tag list.

### `PATCH /api/cases/{case_id}` *(v5.0)*

Update a case's mutable fields. Body (any subset): `{"status": "closed",
"description": "…"}` — valid statuses are `open`, `closed`, `archived`
(reopen with `"open"`).

```bash
curl -X PATCH http://127.0.0.1:8000/api/cases/1 \
  -H "Content-Type: application/json" \
  -d '{"status": "closed"}'
```

Response shape: the updated case record.

## Graph export (v4.0)

### `GET /api/export/{fmt}/{target}?pivot=true`

Renders an investigation entity graph as text. `fmt` is one of `graphml`,
`gexf`, `dot`, `jsonl`, `csv`; `pivot` controls whether related lookups run
first.

```bash
curl "http://127.0.0.1:8000/api/export/graphml/example.com" -o graph.graphml
curl "http://127.0.0.1:8000/api/export/dot/example.com?pivot=false"
```

Response shape: `{"target", "format", "graph": "<serialized graph>",
"entities": n, "links": n}` — the `graph` string is ready to save with the
matching file extension (Gephi, yEd, Cytoscape, Graphviz; see
[docs/advanced.md](advanced.md#graph-exports)).

## Sources and stats

### `GET /api/sources`

Source catalogs for the kinds that publish one:
`{"ip": {name: description}, "email": {...}, "domain": {...}, "url": {...},
"crypto": {...}, "hash": {...}, "cve": {...}, "asn": {...},
"vin": {...}, "flight": {...}, "mmsi": {...}}`.

```bash
curl http://127.0.0.1:8000/api/sources
```

### `GET /api/stats`

Database, cache, network and source-health statistics:

```bash
curl http://127.0.0.1:8000/api/stats
```

Response shape: `{"database": {...}, "cache": {...}, "network": {...},
"source_health": [{source, kind, ok_count, fail_count, reliability,
state, ...}]}` — the same rows as `obscuralens sources health`.

## Watchlist

### `GET /api/watch`

Every watched target as a plain dict list.

```bash
curl http://127.0.0.1:8000/api/watch
```

### `POST /api/watch`

Add a target. Body: `{"target": "example.com", "label": "corp site"}`.
Returns `{"id": n}`; `400` on an invalid target.

```bash
curl -X POST http://127.0.0.1:8000/api/watch \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "label": "corp site"}'
```

### `DELETE /api/watch/{identifier}`

Remove a watch by numeric id or target string. Returns `{"removed": …}`;
`404` when not found.

```bash
curl -X DELETE http://127.0.0.1:8000/api/watch/3
```

### `POST /api/watch/check?identifier=…`

Run and diff one watch (id or target) or every watch. Returns the change
records: `[{watch_id, target, kind, is_first, added, removed, changed,
success}]`.

```bash
curl -X POST "http://127.0.0.1:8000/api/watch/check"
curl -X POST "http://127.0.0.1:8000/api/watch/check?identifier=example.com"
```

## Toolbox (v5.0)

The `/api/tools/*` endpoints expose the experimental analyst toolbox
([docs/experimental.md](experimental.md#toolbox-v50)). Every text tool runs
fully offline in-process; the two `/file/` endpoints receive an uploaded
file and analyze it locally — **the file never leaves the server process**.

### `GET /api/tools/encodings?text=…`

Encode one input through every scheme at once.

```bash
curl "http://127.0.0.1:8000/api/tools/encodings?text=admin:password"
```

Response shape: `{"text": "admin:password", "encodings":
{"hex": "61646d…", "base32": "MFUGC…", "base64": "YWRtaW4…",
"base85": "…", "url_percent": "admin%3Apassword",
"html_entity": "…", "rot13": "nqzva…", "caesar": "…",
"binary": "…", "decimal": "…", "reversed": "…",
"morse": "…", "gzip": "…"}, "digests": {"md5": "…",
"sha256": "…", …}}` — every scheme that could encode the input, plus the
`hash_all` digest set.

### `POST /api/tools/decode`

Decode a value with one chosen scheme, or auto-detect when `scheme` is
omitted.

```bash
curl -X POST http://127.0.0.1:8000/api/tools/decode \
  -H "Content-Type: application/json" \
  -d '{"scheme": "hex", "value": "68656c6c6f"}'
# {"scheme": "hex", "result": "hello"}

curl -X POST http://127.0.0.1:8000/api/tools/decode \
  -H "Content-Type: application/json" \
  -d '{"value": "aGVsbG8="}'
# {"auto": [{"scheme": "base64", "result": "hello", "score": 100.0, …}, …]}
```

Schemes (canonical names, shared by the CLI `--scheme` flag): `hex`,
`base32`, `base64`, `base85`, `url_percent`, `html_entity`, `rot13`,
`caesar`, `binary`, `decimal`, `reversed`, `morse`, `gzip`. `400` when a
chosen scheme cannot decode the value (or is unknown — the error lists
the available names).

### `GET /api/tools/jwt?token=…`

Decode and inspect a compact JWS token — header, payload, claim timeline,
algorithm risk, key hints. **No signature verification, by design** (see
[docs/experimental.md](experimental.md#jwt-inspection)).

```bash
curl "http://127.0.0.1:8000/api/tools/jwt?token=eyJhbGciOi…"
```

Response shape: `{"header": {...}, "payload": {...}, "claims":
{"exp": {...}, "iat": {...}, "nbf": {...}}, "alg": {...},
"identifiers": {"iss", "sub", "aud", "jti"}, "key_info": {...},
"token_stats": {...}, "notes": [...], "signature_hex", "signature_length"}`
— malformed tokens return the notes with `400`-free explanatory errors.

### `GET /api/tools/hash-id?value=…`

Identify candidate hash formats for a digest, ranked by confidence.

```bash
curl "http://127.0.0.1:8000/api/tools/hash-id?value=44d88612fea8a8f36de82e1278abb02f"
```

Response shape: `{"value": "...", "candidates": [{"name": "MD5",
"confidence": "high", "length": 16, "charset": "hex", "note": "..."},
{"name": "NTLM", "confidence": "medium", ...}, ...]}` — same-length
alternatives are listed honestly rather than guessed.

### `POST /api/tools/coords`

Parse coordinates in any accepted syntax and convert to every format.

```bash
curl -X POST http://127.0.0.1:8000/api/tools/coords \
  -H "Content-Type: application/json" \
  -d '{"value": "31U DQ 48288 11087"}'
```

Response shape: `{"input": "...", "latitude": 48.8584, "longitude": 2.2945,
"formats": {"decimal": "48.8584, 2.2945", "dms": "N 48° 51' 29.04\"…",
"ddm": "...", "utm": "31U 448288 5411087", "mgrs": "31U DQ 48288 11087",
"geohash": "u09…"}, "geo_names": {...}}` — `400` when no format parses
(DD, DMS, UTM and MGRS are accepted).

### `POST /api/tools/extract`

Extract every OSINT pivot target from free text (validator-confirmed; weak
candidates labelled).

```bash
curl -X POST http://127.0.0.1:8000/api/tools/extract \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact bob@evil.example from 45.148.10.99 re CVE-2021-44228"}'
```

Response shape: `{"emails": [...], "urls": [...], "domains": [...],
"ipv4": [...], "ipv6": [...], "asn": [...], "macs": [...], "ibans": [...],
"imeis": [...], "hashes": [...], "cves": [...], "crypto_addresses": [...],
"coords": [...], "phone_candidates": [...], "user_handles": [...],
"tracking_ids": [...]}` — every key always present (empty lists when no
hits), each capped at 50.

### `POST /api/tools/squat`

Generate typosquat / lookalike variants of a domain with deception-risk
scores.

```bash
curl -X POST http://127.0.0.1:8000/api/tools/squat \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

Response shape: `{"domain": "example.com", "variants": [{"domain":
"exmaple.com", "category": "transposition", "risk": 94, "description":
"..."}, ...]}` — sorted by risk, capped at 300.

### `POST /api/tools/file/exif` (multipart)

Local EXIF / metadata triage for an uploaded image (JPEG, PNG, GIF, BMP,
WebP). Uploads up to 16 MB.

```bash
curl -X POST http://127.0.0.1:8000/api/tools/file/exif \
  -F "file=@IMG_2031.jpg"
```

Response shape: `{"format": "jpeg", "size": 2480000, "sha256": "...",
"camera": "Apple iPhone 13 Pro", "gps": {"latitude": ..., "longitude": ...,
"coords": "48.8584, 2.2945"}, "timeline": [...], "osint_notes": [...],
"exif": {...}, "xmp": {...}}` — the `gps.coords` string is ready for
`/api/lookup/coords/…`.

### `POST /api/tools/file/stego` (multipart)

Local steganography / entropy analysis for an uploaded image (PNG, BMP, GIF
get LSB plane statistics; every format gets entropy profiling and
embedded-file carving).

```bash
curl -X POST http://127.0.0.1:8000/api/tools/file/stego \
  -F "file=@suspicious.png"
```

Response shape: `{"format": "png", "summary": {"suspicion": 71.3,
"verdict": "highly suspicious", "findings": [...]}, "lsb": {...},
"entropy": {...}, "embedded_files": {...}, "strings": [...]}` — verdict
bands: `clean` < 35, `suspicious` < 65, `highly suspicious` ≥ 65.

### `POST /api/tools/batch`

Run one tracker kind over multiple targets (the `run_batch` engine —
[docs/advanced.md](advanced.md#advanced-analysis-v50)). Body:
`{"kind": "ip", "targets": ["8.8.8.8", "1.1.1.1"], "risk": false}`.
Capped at **25 targets** per request; `400` beyond that or on an unknown
kind.

```bash
curl -X POST http://127.0.0.1:8000/api/tools/batch \
  -H "Content-Type: application/json" \
  -d '{"kind": "ip", "targets": ["8.8.8.8", "1.1.1.1"], "risk": true}'
```

Response shape: `[{"target": "8.8.8.8", "result": {…tracker envelope
(+ risk block)…}}, ...]` — one entry per target, failures included as
`success: false` envelopes, never omitted.

## Related

- [docs/advanced.md](advanced.md) — correlation, timelines, risk scoring,
  cases, graph exports, batch/alerts/patterns/geospatial/reports from the
  CLI.
- [docs/experimental.md](experimental.md) — the toolbox modules behind
  `/api/tools/*`.
- [docs/web-ui.md](web-ui.md) — the web application these endpoints serve.
- [docs/sources.md](sources.md) — what each endpoint's sources cover.
- The OpenAPI schema at `/docs` is generated from the same handlers and is
  always in sync with your installed version.
