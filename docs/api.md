# REST API reference

ObscuraLens ships an optional FastAPI web UI + JSON REST API. Install the
extra and start the server:

```bash
pip install "obscuralens[web]"
obscuralens serve --host 127.0.0.1 --port 8000
# dashboard:    http://127.0.0.1:8000
# OpenAPI docs: http://127.0.0.1:8000/docs
```

Conventions used by every endpoint:

- **kinds** — `ip`, `phone`, `username`, `email`, `domain`, `url`, `crypto`,
  `hash`, `cve`, `asn`.
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

## Service endpoints

### `GET /` — dashboard

Self-contained dark dashboard (no external assets) that calls the endpoints
below with `fetch`.

### `GET /api/health`

Liveness probe. Response: `{"status": "ok", "version": "4.0.0"}`.

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
```

Response shape: the tracker envelope (above). For `username`, `info`
carries the per-platform `results` list instead of scalar fields.

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
"crypto": {...}, "hash": {...}, "cve": {...}, "asn": {...}}`.

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

## Related

- [docs/advanced.md](advanced.md) — correlation, timelines, risk scoring,
  cases and graph exports from the CLI.
- [docs/sources.md](sources.md) — what each endpoint's sources cover.
- The OpenAPI schema at `/docs` is generated from the same handlers and is
  always in sync with your installed version.
