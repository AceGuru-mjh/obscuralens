# ObscuraLens documentation index

Reading map for everything in `docs/` (plus the root guides). The
60-second mental model first:

> 1. **20 target kinds** (IP → license plate), each with a tracker that
>    fans out to every available source in parallel, merges the fields
>    and records **which source supplied each fact** — then scores how
>    well each fact is corroborated (noisy-OR confidence, v6.1).
> 2. **Everything is local and passive**: SQLite history, caches and
>    JSON state under `data/`; rate limits and caches on by default;
>    nothing leaves the machine except the source API calls.
> 3. **Four surfaces, one engine**: the CLI (menu + 56 argparse
>    commands), the web UI/REST API (74 endpoints), the MCP server
>    (63 tools for AI agents) and two SDKs (Python + TypeScript) all
>    drive the same trackers.

Now find yourself in the table below.

## By audience

### New user — "I just installed it"

| Doc | What it gives you |
|---|---|
| [../README.md](../README.md) | install, the ways to run, the full feature tour |
| [scheduling.md](scheduling.md) | cron / Task Scheduler / GitHub Actions monitoring |
| [desktop-beta.md](desktop-beta.md) | the single-file desktop beta program |
| [i18n.md](i18n.md) | running the console in 14 languages |

Start with `./start.sh` (web UI) or `obscuralens` (console menu), then
try `obscuralens ip 8.8.8.8 --risk`. When a lookup matters enough to
monitor: [scheduling.md](scheduling.md).

### Analyst — "I'm investigating a target"

| Doc | What it gives you |
|---|---|
| [sources.md](sources.md) | the full data-source catalog per kind |
| [advanced.md](advanced.md) | investigation workflow: pivots, correlation, timelines, risk, cases, pipelines, source health |
| [rules.md](rules.md) | explainable risk rule packs (YAML DSL) |
| [analytics.md](analytics.md) | the analytics package: stats, anomalies, clustering, trends |
| [automation.md](automation.md) | notification channels, the scheduler, STIX/MISP sharing |
| [web-ui.md](web-ui.md) | the single-page web UI: views, charts, live SSE |
| [experimental.md](experimental.md) | the analyst toolbox: encoders, JWT, EXIF, stego, typosquats |
| [data-packs.md](data-packs.md) | the offline data catalog (`obscuralens data`) |
| [v5.md](v5.md), [v5.1.md](v5.1.md) | what those releases added (history) |

The core loop is `investigate` → `case` → `watch` → `automation`;
[advanced.md](advanced.md) is the spine, [analytics.md](analytics.md)
and [automation.md](automation.md) layer on top.

### Integrator — "I'm embedding this in my program"

| Doc | What it gives you |
|---|---|
| [api.md](api.md) | the REST API reference (all 74 endpoints) |
| [sdk.md](sdk.md) | the Python SDK: sync + async clients, models, `InvestigationSession` |
| [../sdk-js/README.md](../sdk-js/README.md) | the TypeScript/JavaScript SDK (zero npm deps) |
| [ecosystem.md](ecosystem.md) | the MCP server's 63 tools, plugin SDK v2, completions — the v6.0 part-5 tour |
| [plugins.md](plugins.md) | writing plugins (sources, commands, report sections, MCP tools, analytics) |

Pick the surface that matches your runtime; the wire contracts are
pinned by tests, so all four stay in sync.

### Contributor — "I want to change the code"

| Doc | What it gives you |
|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | setup, workflow, code style, the three contribution walkthroughs, release process |
| [architecture.md](architecture.md) | the internals: layers, life of a lookup, state, concurrency |
| [benchmarks.md](benchmarks.md) | the performance suite, baselines, when to add a benchmark |
| [../SECURITY.md](../SECURITY.md) | OPSEC stance, secrets handling, disclosure policy — read before touching network code |

### Internals — "how does it actually work"

[architecture.md](architecture.md) is the map (layer diagram → life of a
lookup → state & storage → concurrency → the 20-kinds matrix →
extension surfaces → API surfaces → performance). The module
docstrings are the second layer of documentation — the repo documents
in place (see any file in `obscuralens/core/` for the house style).

## Where to go next

- **From new user**: `obscuralens sources` to see what you can query;
  [sources.md](sources.md) when you want the details.
- **From analyst**: `obscuralens investigate <target> --format mermaid`
  for the pivot graph, then [advanced.md](advanced.md) § correlation.
- **From integrator**: `pip install obscuralens` + [sdk.md](sdk.md)
  quickstart (or `sdk-js/`), `obscuralens mcp` for agents.
- **From contributor**: [../CONTRIBUTING.md](../CONTRIBUTING.md) →
  "Adding a new data source" — it's the 30-minute path.
