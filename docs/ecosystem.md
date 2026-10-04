# ObscuraLens Ecosystem (v6.0 Part 5)

Part 5 is the ecosystem release: everything that makes ObscuraLens
embeddable in someone *else's* program rather than a console you drive
by hand. Five pieces:

1. **Python SDK v6** — full coverage of the v6 REST surface (all 20
   kinds, analytics, notifications, automation, STIX/MISP exports, the
   dork builder) plus a new fluent `InvestigationSession` workflow API.
   Reference: [docs/sdk.md](sdk.md).
2. **TypeScript/JavaScript SDK** — `sdk-js/`, a dependency-free client
   with the same endpoint coverage, strict-mode-clean types and an
   offline-testable transport. Reference:
   [sdk-js/README.md](../sdk-js/README.md).
3. **MCP server at 63 tools** — ten new ecosystem tools (MISP export,
   geo-clustering, trend + forecast, history search, watch and case
   management, offline data-pack lookups) on top of the 53 from part 4.
4. **Plugin SDK v2** — plugins can now ship CLI commands, report
   sections, MCP tools and analytics hooks, not just data sources.
   Reference: [docs/plugins.md](plugins.md).
5. **Shell completions** — `obscuralens completion bash|zsh|fish`
   generates completion scripts from the live CLI parser.

## Python SDK v6 — what part 5 added

The SDK previously modelled the v5.1 API (14 kinds, no analytics, no
automation). Part 5 closes the gap to the full v6.1 surface:

| Family | Methods | Notes |
|---|---|---|
| Sensor kinds | `vin`, `flight`, `mmsi`, `app`, `package` (alias), `bssid`, `plate` | thin `lookup()` aliases like every other kind |
| Dork builder | `dorks(target, kind=None)` | `DorkReport` with `.links()` |
| Analytics | `analytics_stats/anomalies/timeseries/clusters/keywords/language/similarity/graph/history` | all return `AnalyticsEnvelope` |
| Notifications | `notify_channels`, `add_notify_channel`, `remove_notify_channel`, `test_notify_channel`, `notify_recent`, `notify_broadcast` | `NotifyChannels`/`NotifyChannel`/`NotifyDelivery` models |
| Automation | `automation_tasks`, `add_automation_task`, `remove_automation_task`, `run_automation_task`, `run_due_automation`, `automation_next` | `AutomationTasks`/`AutomationTaskView` models |
| Sharing | `export_stix`, `export_misp` | `StixBundle` / `MispEvent` models |
| Stream | `set_stream_topics(topics)` | list or comma-string |

Every method exists on both `ObscuraLensClient` and
`AsyncObscuraLensClient`, is covered by offline `StaticTransport` tests
(142 new cases in `tests/test_sdk_v6.py`), and follows the SDK's
standing rules: stdlib-only transport, tolerant models, retry with
backoff, typed exceptions.

### InvestigationSession

The headline SDK feature is the session layer — a guided, resumable
workflow object for real investigations:

```python
from obscuralens.sdk import ObscuraLensClient, InvestigationSession

with ObscuraLensClient() as client:
    with InvestigationSession(client, label='phishing-2024') as session:
        session.lookup('ip', '45.33.32.156')
        session.investigate('evil.example.com', pivot=True)
        session.risk('domain', 'evil.example.com')
        session.note('victim reported 2024-05-01')
        session.dorks('evil.example.com')
        session.to_case('Phishing case')     # case + every target as items
        session.export_stix('domain', 'evil.example.com')
        print(session.summary())
        session.dump('receipt.json')
```

Design points: steps are recorded with durations and field counts;
errors are captured as failed steps (strict mode re-raises instead);
`dump()`/`load()` round-trip a JSON receipt that reloads *without* a
client for audit; `to_case()` fans every collected target into a new
case. The full reference is in
[docs/sdk.md § Investigation sessions](sdk.md#investigation-sessions-v60-part-5).

## The TypeScript/JavaScript SDK (`sdk-js/`)

A complete second SDK for the JavaScript/TypeScript world — Node
scripts, web dashboards, serverless functions, SOAR glue. Highlights:

- **Zero npm dependencies.** One `fetch`-based transport
  (`FetchTransport`) with `AbortSignal.timeout`, injectable `fetchFn`,
  retry/backoff with `Retry-After` honouring, and the same typed error
  hierarchy as Python (`BadRequestError`, `NotFoundError`,
  `RateLimitError`, `ServerError`, ...).
- **Full v6.1 surface.** All 20 kind lookups (plus the `package()`
  alias), investigations/risk/timeline/correlate/intel, cases, watch,
  keys/settings, the analyst toolbox with the dork builder, the nine
  analytics endpoints, six notification methods, six automation
  methods, STIX/MISP/graph exports, stream-topic declaration, batch and
  raw escape hatches — 80+ typed methods.
- **Strict types, no build step for consumers.** TypeScript 5 `strict`
  + `noUnusedLocals`, compiled `dist/` (ES2022, NodeNext ESM) and
  `.d.ts` declarations ship in the repo; `types.ts` documents each
  interface with the endpoint it models.
- **Offline-testable.** `StaticTransport` mirrors the Python one
  (scripted responses + call recording); the test suite (78 node:test
  cases) runs hermetically, including two real `node:http` end-to-end
  smokes on an ephemeral port.
- **`InvestigationSession` in TS too** — step log, strict mode, JSON
  receipts, mirroring the Python API design.

```bash
cd sdk-js
npm test              # node --test test/*.test.mjs (78 cases)
```

Consumer quickstart, method reference and the Python-comparison table:
[sdk-js/README.md](../sdk-js/README.md).

## MCP server — 63 tools

Ten new tools join the registry (dispatched through the same
`_HANDLERS` table, same Input/Output docstring contract):

| Tool | What it does |
|---|---|
| `export_misp` | MISP core-format event for the newest stored lookup of a target (the STIX twin of part 4's `export_stix`) |
| `analytics_clusters` | great-circle DBSCAN over `[lat, lon]` pairs (eps_km / min_points) |
| `analytics_trend` | least-squares trend + CUSUM changepoint summary for a value sequence |
| `analytics_forecast` | linear-trend forecast with `horizon` (1–24) |
| `history_search` | substring search over stored lookups (kind filter, limit, no bulky payloads) |
| `watch_add` / `watch_remove` | manage watchlist entries from an assistant |
| `case_list` / `case_create` | list cases (optionally archived); create a case with an optional first target |
| `data_pack_lookup` | offline data-catalog lookups (country / port / language / currency / http_status / cwe / airline / wmi / mid packs) |

`tools/list` now advertises 63 entries; the registry-vs-schema
consistency is asserted in `tests/test_mcp_server.py` (102 tests).

## Plugin SDK v2

Plugins graduate from "extra data sources" to first-class extension
modules. A v2 plugin may define, alongside the v1 `SOURCES` dict:

| Contract | Module-level name | Use |
|---|---|---|
| Manifest | `PLUGIN_META` | name, version, author, description, license, url, `requires_api` |
| CLI commands | `COMMANDS` | `obscuralens plugins run <name>` dispatch with declared argparse arguments |
| Report sections | `REPORT_SECTIONS` | render extra sections for lookup reports (per-kind or all) |
| MCP tools | `TOOLS` | callable tools for the assistant surface |
| Analytics hooks | `ANALYTICS` | pure-function payload → dict analytics |

Backwards compatibility is total: v1 plugins (only `SOURCES`) load
unchanged and get a synthesized manifest; a plugin declaring
`requires_api: 3` against the supported API 2 keeps its sources but has
v2 features skipped with a recorded error. Every piece is validated in
isolation — a malformed command never breaks a working source.

Plugin authors get two CLI affordances:

```bash
obscuralens plugins check path/to/plugin.py   # isolated lint: what will load, what won't, and why
obscuralens plugins run hello --name world    # dispatch a plugin command
```

Three documented example plugins ship in
[`plugins-examples/`](../plugins-examples/) (a source pack, a command
pack, and the full-surface showcase). The complete contract,
`PluginContext` reference and authoring checklist:
[docs/plugins.md](plugins.md).

## Shell completions

```bash
obscuralens completion bash   # print the bash script
obscuralens completion zsh
obscuralens completion fish
```

The scripts are generated from the *live* argparse parser — every
subcommand (including nested groups like `watch add` or `automation
tasks`), every option string, every positional, with `-f/--format`
choices completed. Output is deterministic (sorted commands and
options) and needs no external completion framework beyond the shell
itself.

Install:

| Shell | One-time |
|---|---|
| bash | `obscuralens completion bash > /etc/bash_completion.d/obscuralens` (or `~/.local/share/bash-completion/completions/obscuralens`) |
| zsh | `obscuralens completion zsh > ~/.zsh/completions/_obscuralens` and ensure `fpath` includes it |
| fish | `obscuralens completion fish > ~/.config/fish/completions/obscuralens.fish` |

## Where part 5 lands in the test suite

- `tests/test_sdk_v6.py` — 142 cases: every new method's wire contract,
  model edge cases, session workflows, async mirrors.
- `tests/test_mcp_server.py` — 102 cases (86 new): ten new tools, JSON-RPC
  round-trips, registry consistency.
- `tests/test_plugin_sdk.py` + `tests/test_completion.py` — 143 cases:
  v2 contracts, gating, examples, tree walking, all three shell
  generators, CLI wiring.
- `sdk-js/test/*.test.mjs` — 78 node:test cases including real-HTTP smokes.

Everything runs offline (`python3 -m pytest -m 'not integration'`,
`node --test sdk-js/test/*.test.mjs`); nothing in part 5 adds a runtime
dependency to the Python package.
