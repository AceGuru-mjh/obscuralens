# Contributing to ObscuraLens

Thanks for helping build the platform. This guide covers setup, the
house code style, the three most common contribution shapes (a data
source, a target kind, an API surface), and the release process. Read
[docs/architecture.md](docs/architecture.md) first if you want the full
layer map; read [SECURITY.md](SECURITY.md) before anything that touches
credentials or network behaviour.

## Contents

- [Prerequisites & setup](#prerequisites--setup)
- [Task runners](#task-runners)
- [Workflow: branch, test, PR](#workflow-branch-test-pr)
- [Code style](#code-style)
- [Adding a new data source](#adding-a-new-data-source)
- [Adding a new target kind](#adding-a-new-target-kind)
- [Adding an MCP tool / REST endpoint / SDK method](#adding-an-mcp-tool--rest-endpoint--sdk-method)
- [Writing plugins](#writing-plugins)
- [Benchmarks](#benchmarks)
- [Release process](#release-process)
- [Reporting bugs & security issues](#reporting-bugs--security-issues)

## Prerequisites & setup

- Python **3.9+** (CI tests 3.9 → 3.14; the code is written for 3.9
  semantics — see [Code style](#code-style)).
- Git; `make` or `just` (optional but handy).
- For the TS SDK: Node 18+ (`sdk-js/` — `bunx --bun tsc` builds it).

```bash
git clone https://github.com/AceGuru-mjh/obscuralens.git
cd obscuralens
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\Activate.ps1
pip install -e ".[dev]"             # package + pytest/ruff/build/twine/httpx
obscuralens --version               # smoke test
```

Don't want a manual venv? The one-command launcher does it for the web
UI (it creates `.venv`, installs deps, serves and opens the browser):

```bash
./start.sh            # Linux/macOS   (start.ps1 on Windows)
# flags: --no-open  --port N  --host H  --cli ...  --reset
```

Optional extras: `pip install -e ".[web]"` (FastAPI/uvicorn for `serve`
and the REST tests), `".[tui]"` (Textual), `".[exe]"` (PyInstaller).

## Task runners

Both `make` and `just` wrap the same commands (read `Makefile` /
`justfile` — the tables below are the real targets):

| Target | What it runs |
|---|---|
| `make install` / `just install` | `pip install -e ".[dev]"` |
| `make test` / `just test` | `pytest -m "not integration" --no-color` (the offline suite) |
| `make integration` / `just integration` | `python scripts/smoke_live.py` (real network — opt-in) |
| `make lint` / `just lint` | `ruff check .` |
| `make fmt` / `just fmt` | `ruff check --fix .` |
| `make run` / `just run` | `python -m obscuralens` (interactive console) |
| `make start` / `just start` | `./start.sh` (web UI) |
| `make serve` / `just serve` | `python -m obscuralens serve` |
| `make tui` / `just tui` | `python -m obscuralens tui` |
| `make mcp` / `just mcp` | `python -m obscuralens mcp` (stdio JSON-RPC) |
| `make build` / `just build` | `python -m build` (sdist + wheel) |
| `make clean` / `just clean` | remove caches and build artefacts |
| `make bench` / `make bench-quick` | benchmark suite: full / quick mode (see [docs/benchmarks.md](docs/benchmarks.md)) |

`make help` lists everything.

## Workflow: branch, test, PR

**Branch naming** follows the history: `feature/v6.0-part1-sensors`,
`feature/v6.1-corroboration`, `fix/exe-web-page`,
`chore/rebrand-assets`. The convention:

```
feature/v<major.minor>-<slug>     # feature work (optionally -partN)
fix/<slug>                        # bug fixes
chore/<slug>                      # cleanup, docs, tooling
```

**Before every PR** — the offline suite must pass and lint must be
clean. These are exactly what CI runs:

```bash
pytest -m 'not integration'     # the offline suite (3,267 tests at v6.1,
                                 # growing through part 6), ~30-90s, zero network
ruff check .                    # must be silent
```

If you touched `sdk-js/`: `bunx --bun tsc -p sdk-js/tsconfig.json` and
`node --test sdk-js/test/*.test.mjs` from `sdk-js/`.

**What CI runs** (`.github/workflows/ci.yml`) — push to `main` or
`feature/**` branches and every PR. (Note: the current workflow file
has a typo in its push trigger — `branches: ain, "feature/**"]` —
which is meant to read `[main, "feature/**"]`; the documented set
here is the intended one, PRs always run regardless.)

- **lint**: `ruff check .` on Python 3.13.
- **test**: the offline pytest suite on a 3.9 → 3.14 matrix.
- **sanity**: `compileall` of `obscuralens tests scripts`, an import
  smoke (`import obscuralens, …mcp_server`), `--version`, `pip check`.
- **web**: `pytest tests/test_web.py` with the `[web]` extra.
- **tui**: `pytest tests/test_tui.py` with the `[tui]` extra.
- **desktop**: the desktop/i18n/data-catalog/SDK/rules/template tests
  plus CLI smokes (`desktop --diagnostics`, `data …`, `i18n list`).
- **docker**: builds the image, pushes to GHCR on `main`.
- **exe** (best-effort, `continue-on-error`): PyInstaller build +
  frozen-`serve` boot check on Windows, artifact upload.
- **package**: `python -m build`, `twine check`, wheel install smoke.

**Commits and PRs.** One PR per feature part, with a detailed body —
this is the established convention (see the history: every part of v6.0
landed as its own merge). Commit subjects look like
`v6.0 part 5: ecosystem — SDK v6 (py+ts), 63-tool MCP, plugin SDK v2`
or `feat(v6.1): corroboration & coverage — …` / `chore(cleanup): …`;
the body enumerates what changed per file family. Keep PRs scoped: a
source addition touches one `*_sources.py` plus tests plus
`docs/sources.md`; a new kind touches everything (see below) and
deserves a part-sized PR.

Do not commit directly to `main`; open a PR and let CI validate.

## Code style

The house rules (enforced by ruff where possible — `line-length = 110`,
`target-version = py39`, rules `E, F, W, I, B, C4, SIM` with `E501`
ignored because 110 is the real limit):

- **Python 3.9 typing.** `Optional[X]` / `Dict[str, Any]` /
  `List[int]` from `typing` — never `X | None`, never built-in
  generics. The package imports `from typing import …` at every
  module top.
- **Single quotes** everywhere; double quotes only when the string
  contains single quotes.
- **Imports isort-style** (the `I` rules): stdlib, third-party,
  first-party blocks, alphabetised within blocks.
- **`# ---` separators** to divide sections inside modules and
  functions — e.g. `# -- loading ----`, `# -- storage ----` in
  `obscuralens/config.py`, or the `# v4.0 additions ---` comment blocks
  in registries. Use them; the codebase reads top-down because of them.
- **Docstrings**: triple-quoted, summary line first, blank line, then
  prose. Args/Returns sections for public functions. Doctests are
  welcome but must be deterministic — anything touching the network,
  the clock or the filesystem gets `# doctest: +SKIP`:

  ```python
  def rate_for(host: str) -> float:
      """
      Effective rate for a host: the slower of the configured default
      and any per-host override (v6.1).

      >>> limiter.rate_for('api.ethplorer.io')   # doctest: +SKIP
      0.4
      """
  ```

- **Never-fatal errors**: a data source returns `{}` on failure and
  never raises; module-level singletons swallow SQLite/OS errors and
  return safe defaults; user-facing entry points return
  `{'ok': bool, 'error': str}` shapes. If your code can raise, catch
  it at the boundary and record it in a status/error field.
- **No walrus in hot paths**, no clever one-liners in the fan-out or
  merge code — those loops are read more than they are written.
- **Tests are offline by default.** The `integration` marker is the
  only place real HTTP happens.

## Adding a new data source

The most common contribution. Example: adding a keyless JSON API to the
IP tracker.

1. **Pick the tracker.** Sources live in
   `obscuralens/trackers/<kind>_sources.py` — one reader function per
   source plus a registration entry. (For `email`/`username` the fan-out
   lives in the tracker module; every other kind has a
   `gather_all()` in its `*_sources.py`.)

2. **Write the reader** — a private function taking the target string
   and returning a **flat dict of fields**:

   ```python
   def _myapi(ip: str) -> Dict[str, Any]:
       ok, data, err = http.get_json(f'https://api.myapi.example/v1/{ip}')
       if not ok or not isinstance(data, dict):
           return {}
       out: Dict[str, Any] = {}
       if data.get('country'):
           out['country'] = data['country']
       return out
   ```

   Rules:
   - **Keyless-first.** If the API needs a key, add it to
     `KEYED_SOURCES` and to the `SERVICES` tuple in
     `obscuralens/config.py` (plus an `APIConfig` field) so the
     key plumbing (`secrets.yaml`, env override, web `/api/keys`)
     picks it up.
   - **Return `{}` on failure, never raise** — only populate fields
     you actually got (empty strings/`None`/`[]` are dropped by the
     merge's `_keep()` check).
   - Use the shared client (`from ..utils.http_client import http`) so
     cache, rate limit, retries, proxy and metrics all apply
     automatically. `get_json` returns `(ok, data, err)` — honour it.
   - If the endpoint is rate-fragile, add a `HOST_RATE_OVERRIDES`
     entry in `obscuralens/core/ratelimit.py` with the verified limit.

3. **Register it** in the `FREE_SOURCES` dict *in priority order* —
   registry order is merge priority (earlier source wins field
   conflicts). Add a one-line description to `SOURCE_CATALOG` so
   `obscuralens sources <kind>` shows it.

4. **Provenance is automatic.** `gather_all` builds `field_sources`
   from the merge — you do nothing. Same for source health (the
   status map feeds `record_batch`) and the confidence scoring (the
   noisy-OR model reads the provenance map; optionally add your source
   to `SOURCE_TRUST` in `obscuralens/correlation/confidence.py` if it
   is clearly an authority or clearly an aggregator).

5. **Test offline.** Monkeypatch the shared client with the
   `fake_http` fixture from `tests/conftest.py` — see
   `tests/test_ip_sources.py` for the canonical pattern:

   ```python
   def test_myapi_parses(fake_http):
       fake_http.json = lambda url, **kw: (True, {'country': 'AU'}, '')
       out = ip_sources._myapi('1.1.1.1')
       assert out['country'] == 'AU'

   def test_myapi_gives_up_cleanly(fake_http):
       fake_http.json = lambda url, **kw: (False, None, 'timeout')
       assert ip_sources._myapi('1.1.1.1') == {}
   ```

   For gather-level tests, monkeypatch the registry itself with a
   `_fake_sources()` dict of lambdas (see
   `test_gather_all_merges_deterministically` in the same file).

6. **Update the catalog**: `docs/sources.md` (the per-kind source
   tables) and, if the README's tracker table row counts change, flag
   it in your PR (the README is orchestrator-owned during part
   releases).

## Adding a new target kind

A kind is wired into nine places. The reference implementation is the
v6.0 part-1 commit `6245b22` ("sensor matrix - six new target kinds"),
which added VIN/flight/MMSI/app/BSSID/plate end to end:

1. **Validator + normalizer** — `obscuralens/utils/validators.py`:
   `validate_<kind>()` returning `(ok, error)`, plus a
   `normalize_<kind>()` if inputs need canonicalisation. This is the
   gate every surface reuses.
2. **Data packs** — curated `data/*.txt` packs for offline
   decomposition (OUI/TAC/MID/WMI-style), loaded through
   `utils/data_catalog.py` or directly.
3. **Sources** — `obscuralens/trackers/<kind>_sources.py` with
   `FREE_SOURCES` (+ `KEYED_SOURCES`, + `SOURCE_CATALOG`) and a
   `gather_all()` that follows the fan-out/merge/provenance contract
   (copy the shape from `ip_sources.gather_all`).
4. **Tracker** — `obscuralens/trackers/<kind>_tracker.py`: a
   `track()` that wraps `gather_all` into the standard envelope
   (`info`, `field_sources`, `sources_ok`, `sources_failed`,
   `field_count`, `success`, `errors`) and calls
   `db.save_query(kind, …)`. Export it from
   `obscuralens/trackers/__init__.py`.
5. **CLI** — `obscuralens/commands.py`: add to `KINDS` and
   `_VALIDATORS` and `_TRACKERS`, a `sub.add_parser('<kind>')` with
   `add_common()`, a `_cmd_<kind>()` handler calling
   `_run_lookup()`, and a row in the `_HANDLERS` dispatch dict.
6. **Web** — `obscuralens/web/app.py`: the kind's validator + tracker
   in the module-level maps; `GET /api/lookup/{kind}/{target}` and the
   other kind-parameterised routes pick it up automatically. Consider
   report sections (`reporting/sections.py`).
7. **MCP** — `obscuralens/mcp_server.py`: a tool schema in `TOOLS`
   plus a `_tool_<kind>_lookup` handler registered in `_HANDLERS` in
   the same order.
8. **SDKs** — `obscuralens/sdk/client.py` (a `<kind>()` convenience +
   `KINDS`), `async_client.py` mirror, a model if the payload needs
   one (`sdk/models.py`), and the TS union in `sdk-js/src/types.ts` +
   client method + tests on both sides.
9. **The finishing layer** — a risk rule pack (`rules/packs/<kind>.yaml`),
   i18n strings if the CLI speaks about the kind, report template
   awareness if needed, and docs: `docs/sources.md` (new section),
   `docs/api.md` (if new routes), README table row (orchestrator-owned
   during releases — flag it in the PR).

Tests: a `tests/test_<kind>.py` for the tracker/sources (offline,
`fake_http`), plus updates to the registry-count assertions that pin
the kind/tool totals (`tests/test_app.py`, `tests/test_analytics.py`
assert MCP tool counts; `tests/test_sdk*.py` assert `KINDS == 20` —
bump those baselines deliberately, never silently).

## Adding an MCP tool / REST endpoint / SDK method

The three registries follow the same pattern: schema + handler in one
place, wire-contract tests pinning them.

- **MCP tool** (`obscuralens/mcp_server.py`): append a schema dict to
  `TOOLS` (`name`, `description`, `inputSchema` with
  `additionalProperties: False`), write a `_tool_<name>()` handler
  with `Input:/Output:/Sources:` docstring lines, and register it in
  `_HANDLERS` — the registry test asserts `tools/list` length, handler
  order and schema completeness (`tests/test_mcp_server.py`). Handlers
  reuse the same services the CLI uses; validate args and answer with
  `content`/`isError` JSON-RPC shapes.
- **REST endpoint** (`obscuralens/web/app.py`): add the route inside
  `create_app()`, mirror validation errors as HTTP 400/404 with
  `{'detail': ...}` bodies, and pin the route in
  `tests/test_web.py` (FastAPI TestClient, offline).
- **SDK method** (`obscuralens/sdk/client.py`): follow the `_request`
  patterns — path building, query/body shaping, model wrapping. Mirror
  it in `async_client.py` via `_run`, then in `sdk-js/src/client.ts`.
  Every method gets an offline `StaticTransport` test asserting the
  exact method + URL + body (`tests/test_sdk_v6.py` is the style
  reference; `sdk-js/test/client.test.mjs` on the TS side).

When you add a surface, keep the other three in mind: a new capability
should reach the CLI, the REST API, the MCP server and both SDKs —
that symmetry is a design principle
([docs/architecture.md](docs/architecture.md#the-api-surfaces)).

## Writing plugins

You don't need to touch the core to add sources, CLI commands, report
sections, MCP tools or analytics hooks — that's what plugin SDK v2 is
for. Read [docs/plugins.md](docs/plugins.md) for the full contract and
copy a starting point from `plugins-examples/`
(`example_source_pack.py`, `example_commands.py`,
`example_full.py`). Validate with `obscuralens plugins check <file>`
before filing anything.

## Benchmarks

Performance work should come with a measurement. The `benchmarks/`
suite (harness in `benchmarks/harness.py`, groups for core, analytics
and platform) runs in ~2 minutes and compares against the committed
`benchmarks/results/baseline.json`:

- Run `make bench-quick` (or `python -m benchmarks.run --quick`) while
  iterating; `make bench` for the full suite.
- Add a benchmark when you touch a hot path (validators, cache,
  fan-out, merge, analytics kernels, MCP/SDK marshalling) — follow the
  registry pattern and keep inputs deterministic.
- After an *intentional* performance change, regenerate the baseline
  (`python -m benchmarks.run --save benchmarks/results/baseline.json`)
  and commit it; never overwrite it to make a regression disappear.

Policy and per-group tables: [docs/benchmarks.md](docs/benchmarks.md).

## Release process

Releases are orchestrator-run but reviewable; know the shape:

1. **Version bumps** happen in exactly two places:
   `pyproject.toml` `[project] version` and
   `obscuralens/__init__.py` `__version__` (they must match; the
   `sanity` CI job and `--version` output depend on it).
2. **CHANGELOG discipline**: `CHANGELOG.md` gets a section per part
   (see the `## 6.0-part5 — Ecosystem` shape) — Added/Changed/Fixed
   with concrete counts and file references. A part isn't done until
   its section is written.
3. **Docs**: feature PRs update the relevant `docs/*.md` page
   (`sources.md` for sources, `api.md` for routes, `sdk.md` for SDK
   methods, `analytics.md`/`automation.md`/`ecosystem.md` for their
   parts) and the README interface tables.
4. **Tag-triggered desktop beta**: pushing a `v*-beta*` tag runs
   `.github/workflows/desktop-beta.yml` — it builds Windows/Linux/macOS
   binaries, smoke-tests them, attaches SHA-256 checksums and publishes
   the pre-release. A nightly channel (`desktop-nightly.yml`) rebuilds
   at 03:00 UTC. Never push a beta tag casually.
5. **The package job** in CI already validates `python -m build` +
   `twine check` + a wheel install smoke on every PR, so a release is
   `bump → CHANGELOG → merge → tag`.

## Reporting bugs & security issues

- **Bugs**: open a GitHub issue with the command you ran, the version
  (`obscuralens --version`), Python version, and whether any keys were
  configured. Include `obscuralens desktop --diagnostics` output if it
  boots for you.
- **Security vulnerabilities and OPSEC concerns**: do **not** open a
  public issue — use GitHub's private vulnerability reporting /
  security advisories on the repository. Details and the disclosure
  stance: [SECURITY.md](SECURITY.md).
