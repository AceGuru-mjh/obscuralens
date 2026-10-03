# Web UI guide

ObscuraLens ships a single-page web application served by the optional
FastAPI backend. It is plain ES modules, CSS and canvas — **no build step,
no npm install, no CDN, no external assets** — so it works fully offline
once the package is installed and adds nothing to the dependency tree.

## Starting it

The one-command launcher does everything:

```bash
./start.sh                # Linux/macOS: venv + deps + serve + open browser
# start.ps1               # Windows
make start                # or just start
```

It creates `.venv` (reused on the next run), installs the package with the
`[web]` extra, starts `obscuralens serve --open` on
http://127.0.0.1:8000 and opens your browser. Launcher flags: `--no-open`
(skip the browser) and `--port N`.

The manual equivalent:

```bash
pip install -e ".[web]"
obscuralens serve --host 127.0.0.1 --port 8000 --open
```

The SPA is served at `/`, the OpenAPI docs stay at `/docs`, and every
endpoint the UI calls is the same one documented in
[docs/api.md](api.md).

## Layout

The shell is a fixed structure: **sidebar** (brand, quick search, view
navigation, backend status, theme toggle), **topbar** (current view title,
command palette button), the **view container** and a sticky **footer**
("14 target kinds · provenance-tracked · all processing stays on your
machine"). The sidebar collapses to icons below ~900px and becomes an
off-canvas drawer with a hamburger below ~640px.

Views are grouped into three sections:

| Section | Views |
|---|---|
| **Workspace** | Dashboard · Lookup · History |
| **Investigation** | Investigate · Timeline · Cases · Watchlist |
| **Platform** | Sources · Tools · Settings |

Routing is hash-based and every view deep-links with query parameters, so
`#/lookup?kind=ip&target=8.8.8.8&risk=1` or `#/settings?tab=alerts` are
shareable URLs. After every lookup the workbench silently updates the hash,
so a browser refresh replays the same query.

## The views

### Dashboard

The overview: stat cards (database, cache, network, source-health
statistics), a lookups-over-time line chart with per-kind sparklines, a
kind-distribution donut, a source-health bar card and a recent-activity
list. Every section loads independently — one failing endpoint degrades to
a compact retry callout instead of breaking the page.

### Lookup — the intelligence workbench

The flagship view and the fastest way to run any lookup:

- **15 kind pills** — `auto` plus all 14 kinds. `auto` asks the backend's
  `investigate` endpoint to detect the kind and renders the result with an
  "auto-detected" badge. Your last selection persists across sessions.
- **Target input** with Enter-to-run, Escape-to-clear and a live
  client-side detection hint (display only — the backend still validates).
- **With risk score** checkbox (persists) attaches the explainable risk
  panel; **Investigate pivots** jumps to the graph view for the same
  target.
- **Result hero**: success/failed badge, field count, sources
  OK/failed, round-trip time, and actions — Re-run (replays the *original*
  query), Copy JSON, Download JSON, graph export
  (graphml/gexf/dot/jsonl/csv), **Watch** and **Add to case** (existing
  case picker or inline case creation).
- **Fields table** (Field · Value · Sources): every row shows the merged
  value plus a chip per source that supplied it — the web version of the
  CLI's field provenance. Long values are copyable, objects render as
  compact JSON.
- **Sources panel**: answered chips and failed chips (the failure reason
  is in the tooltip), a **risk panel** (score, verdict, level bar,
  signals table) when risk is on, and a **threat-intel panel** for IP
  lookups (Tor exit badge, feed verdicts, Onionoo relay details).
- **Recent strip**: the last 8 lookups as re-runnable chips (stored
  locally, capped, clearable).

### Investigate — the graph

Type any target; the backend auto-detects the kind and follows bounded
pivots. The view renders the primary result plus every pivot entity in a
**force-directed graph on canvas** (see below): kind-coloured nodes,
relationship labels when zoomed in, an inspection side panel per node
(lookup, risk, case actions) and per-kind result tabs. **Double-click a
node to expand it** into the running investigation. Export the graph as
GraphML/GEXF/DOT/JSONL/CSV or PNG.

### Timeline

Chronological event reconstruction over stored history: dated fields
harvested from past results (registrations, breaches, certificate
lifetimes, first/last-seen stamps) rendered as a vertical rail of
day-grouped event cards, with a summary strip and CSV/JSON export.

### Cases

Investigation case management: a card grid of cases (item/note/tag counts,
status, tags) and a detail view per case with indicator items, free-form
notes and an inline tag input. Items added from the workbench land here.

### Watchlist

Monitored targets and change detection: add targets (kind auto-detected),
check one or all watches, view snapshot diffs (added / removed / changed
fields) and remove entries.

### Sources

Two tabs: **Catalog** — every known source per kind (from `/api/kinds`,
falling back to `/api/sources`), searchable; **Health** — per-source
success/failure counters and circuit-breaker state (the same rows as
`obscuralens sources health`).

### Tools — the analyst toolbox

Eight tabs of local-first utilities, each backed by a `/api/tools/*`
endpoint:

| Tab | What you do |
|---|---|
| Encode/Decode | encode a value through every scheme at once, or decode with one chosen scheme / auto-detection |
| JWT | paste a compact token — header/payload decode, claim timeline, algorithm risk, key hints |
| Hash ID | paste a digest — ranked candidate formats with notes |
| Coordinates | paste DD/DMS/UTM/MGRS — parsed plus every format conversion |
| Extract | paste text — every extracted entity kind as clickable chips that jump to the matching lookup kind |
| Typosquats | enter a domain — scored lookalike variants |
| File analysis | **drag & drop** an image (≤ 16 MB): EXIF/metadata triage and steganography/entropy analysis, both fully local |
| Batch | pick a kind, paste up to 25 targets, run with optional risk scores |

### History

The stored lookup history with a kind filter, debounced free-text search,
limit control, "Load more", CSV export and one-click re-run links into the
workbench.

### Settings

Three tabs (deep-linkable with `?tab=`):

- **API keys** — the service table with configured/not-set badges; set a
  key through a password input (written to the git-ignored
  `config/secrets.yaml`, never transmitted to any source other than its
  own service) or clear it after a confirmation.
- **Runtime** — the safe app configuration as a flat dotted-path map:
  booleans render as toggle switches that save immediately, numbers and
  strings as dirty-tracked inputs with Set buttons.
- **Alerts** — the webhook configuration (URL plus event checkboxes:
  `lookup_failed`, `watch_diff`, `risk_high`, `source_tripped`), a Send
  test button and the recent-notification log. See
  [docs/advanced.md](advanced.md#alerts) — a webhook forwards event data
  off your machine, so point it at an endpoint you control.

## The command palette

Press **⌘K / Ctrl-K** anywhere (or click *Commands* in the topbar):

- **Navigation**: fuzzy-matched "Go to …" commands for all ten views.
- **Theme / docs**: toggle light/dark, open the OpenAPI docs.
- **Targets**: when the query looks like a target (≥ 2 characters), the
  palette offers *Investigate "…"* plus *Look up as <kind>* for all 14
  kinds. **Tab** autocompletes the `kind:` prefix.

`↑`/`↓` move, `↵` runs, `esc` closes. The sidebar's quick-search field
(`/` focuses it) sends Enter straight to the investigate view.

## Keyboard shortcuts

| Key | Action |
|---|---|
| `⌘K` / `Ctrl-K` | command palette |
| `/` | focus the quick target search |
| `T` | toggle light / dark theme |
| `g` then `d`/`l`/`i`/`t`/`c`/`w`/`s`/`o`/`h`/`p` | jump to Dashboard / Lookup / Investigate / Timeline / Cases / Watchlist / Sources / Tools / History / Settings |
| `esc` | close the palette / modal |

## Themes

Dark is the default (background `#0d1117`-family, teal `#14b8a6` accent,
amber `#f59e0b` highlights); light theme switches via `[data-theme=light]`.
The choice persists in `localStorage`. Charts and graphs read their colours
from the CSS custom-property palette on every draw, so switching themes
recolours existing charts without reloading anything.

## Charts and the graph engine

Both are hand-written canvas modules with no dependencies:

- **charts.js** — six primitives (line, donut, bars, sparkline, heatmap,
  scatter) with devicePixelRatio-crisp output, automatic redraw on resize
  (ResizeObserver), hover tooltips, and empty-data guards.
- **graph.js** — a force-directed entity graph (pairwise repulsion, spring
  attraction along links, origin gravity, velocity damping and d3-style
  alpha cooling; capped at 400 nodes). Interactions: pan (drag
  background), zoom toward cursor (0.25–4×), node drag, click to inspect,
  double-click to expand, plus a toolbar (zoom, reset, PNG export) and a
  HUD with node/link counts.

## Privacy notes

- Lookups go to the same sources the CLI uses, with the same cache, rate
  limits and proxy settings. History, cases and the watchlist are stored
  in the same local SQLite database.
- **File analysis never uploads anything**: the browser POSTs the file to
  your own local server, which parses it in-process. No third party sees
  the bytes.
- **Webhook alerts are the one feature that sends data off-host** — by
  design, to a URL you configure. The UI labels it plainly.
- API keys entered in Settings are stored in `config/secrets.yaml`
  (owner-only permissions, git-ignored) exactly as if you had set the
  environment variable yourself.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "backend offline" in the sidebar | the FastAPI server is not running or `/api/health` failed — restart `obscuralens serve` |
| Views show "module unavailable" | a static file failed to load; check the server logs and the `/static/` mount |
| Lookups time out | the default client timeout is 90 s per request; slow sources surface as failed chips with the reason in the tooltip |
| Nothing works after an upgrade | hard-refresh the page (the SPA is cached aggressively by browsers) |

## Related

- [docs/api.md](api.md) — every endpoint the UI calls.
- [docs/v5.md](v5.md) — the rest of the v5.0 release.
