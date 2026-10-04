# Security policy

ObscuraLens is an OSINT console that runs on *your* machine and talks to
public data sources. This page covers supported versions, how to report
vulnerabilities, and — because this is an investigation tool — the
operational-security stance the project deliberately takes.

## Supported versions

| Version | Supported |
|---|---|
| `main` branch (latest release line, currently v6.x) | ✅ |
| Older tags (v1–v5) | ❌ — no backports; upgrade |

The desktop beta builds track tagged releases of `main`.

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting** (the
*Report a vulnerability* link under this repository's **Security** tab)
or open a GitHub Security Advisory. Do **not** open a public issue for
anything exploitable or for anything that weakens the OPSEC guarantees
below.

- There is no contact email in this repository — GitHub private
  disclosure is the channel.
- Expect an acknowledgement within a few days; fixes ship through the
  normal PR process and are announced in `CHANGELOG.md`.
- Please include the version (`obscuralens --version`), the module path
  (e.g. `obscuralens/utils/http_client.py`), and a minimal repro.

## OPSEC & safety stance

Be honest with yourself about what this tool does. The design position:

- **Lookups are passive.** Every tracker is HTTP `GET` (plus the rare
  documented POST API such as MalwareBazaar's query endpoint) against
  public endpoints — the same requests a browser makes. No exploits, no
  credential stuffing, no login attempts, nothing that touches the
  target's own systems.
- **The two *active* features are generative only, and the analyst stays
  in control:**
  - The **dork builder** (`obscuralens dorks`, `utils/dorks.py`)
    *generates* search-engine links locally. It never opens them; you
    do, in your own browser, when you choose to.
  - The **typosquat generator** (`tools squat`, `experimental/squatting.py`)
    produces candidate domains locally. It registers nothing.
  - The experimental **web crawler** is bounded (`crawler_max_depth`,
    `crawler_max_pages`, a 1-second polite delay) and robots-aware.
- **No scraping aggression.** Per-host token-bucket rate limiting
  (default 8 req/s, `obscuralens/core/ratelimit.py`) and the HTTP
  response cache are **on by default**; eight known-fragile community
  APIs get slower dedicated buckets (`HOST_RATE_OVERRIDES`) so parallel
  sweeps cannot trip their 429s. Connection pooling and request
  jitter keep traffic looking like a polite client, because it is one.
- **Terms of service are your responsibility.** Sources are public
  endpoints, but you are the operator: check a service's ToS before
  relying on it, and respect the tool's rate limits — they exist to
  keep the platform a welcome client. Keyed services are used under
  *your* account and *your* quota.
- **No telemetry, no phone-home.** The package contains no analytics,
  no error reporters, no update checks that download anything
  (`obscuralens update check` only *polls* the GitHub Releases API
  when you ask it to and never auto-downloads). Verified by grep: the
  only "telemetry" string in the tree is a CVE rule description
  talking about EPSS.

## Secrets handling

- **Two files, one directory.** `config/config.yaml` holds
  non-sensitive settings; `config/secrets.yaml` holds service
  credentials (23 supported services, `SERVICES` in
  `obscuralens/config.py`). Resolution order:
  `OBSCURALENS_*` env vars → `secrets.yaml` → `config.yaml` →
  defaults. Env-var overrides exist for every app/database setting and
  every service key (e.g. `OBSCURALENS_SHODAN_API_KEY`) — the Docker
  image relies on them.
- **secrets.yaml is written owner-only**: `save_secrets()` chmods it
  to 0600 on POSIX filesystems (`obscuralens/config.py`). The file is
  deliberately git-ignored; never commit it.
- **Keyless-first design.** The platform is fully functional with zero
  keys; keyed sources layer on only when configured
  (`obscuralens/config.py` `SERVICES`).
- **The web API never returns key values.** `GET /api/keys` lists
  service names, a configured boolean and a description — values are
  never serialised out (`obscuralens/web/app.py`, `api_keys_list`).
  Writes go through `POST/DELETE /api/keys/{service}` and land in
  `secrets.yaml`. Note that the web UI has no authentication layer:
  bind `serve` to localhost (the default `127.0.0.1`) unless you put
  an authenticating proxy in front of it.
- **History is scrubbed.** `db.save_query()` runs `sanitize_secrets()`
  over targets, error strings and result JSON so a pasted token can
  never persist in the history database
  (`obscuralens/database.py`, `obscuralens/utils/helpers.py`).

## Data sensitivity

This is an investigation tool: **the data it accumulates is
operationally sensitive** (who you looked at, when, and what you
found). All of it stays on your machine:

| Data | Location |
|---|---|
| Full lookup results (targets, verdicts, provenance) | `data/obscuralens.db` (`query_history` table) |
| Raw HTTP responses from sources (zlib-compressed) | `data/http_cache.db` (`http_cache` table) |
| Cases, watchlist snapshots, source health | same `data/obscuralens.db` |
| Notification channels (incl. webhook URLs, bot tokens) | `data/notifications.json` |
| Scheduler tasks | `data/scheduler.json` |
| Webhook alert configs | `data/alerts.json` |

The only outbound traffic is the source API calls you trigger (plus
notification deliveries *you* configured). Nothing is synced, uploaded
or shared anywhere else.

**Purging:**

- Cache: `obscuralens cache clear` (or delete `data/http_cache.db*`).
- History: the interactive console's clear-history action
  (`db.clear_history()`), or delete `data/obscuralens.db` while the
  tool is stopped.
- Everything: remove the whole `data/` directory (and the
  `config/secrets.yaml` file).
- Exports you wrote (`reports/`, STIX/MISP bundles) must be removed
  manually — the tool cannot track files it handed to you.

If an investigation ends, treat `data/` like case evidence: encrypt or
destroy it on purpose.

## Supply chain

- **Small, boring dependency set.** Nine hard dependencies
  (`pyproject.toml`): requests, phonenumbers, PyYAML, tabulate, jinja2,
  matplotlib, numpy, wordcloud, reportlab. Everything else — analytics,
  automation, exports, i18n, the MCP server, the plugin system — is
  standard library. Optional extras add only
  fastapi/uvicorn/python-multipart (`[web]`), textual (`[tui]`) and
  pyinstaller (`[exe]`). The TypeScript SDK has **zero npm
  dependencies**.
- **The exe bundles everything.** The desktop beta is a single-file
  PyInstaller build (`scripts/obscuralens.spec`) that includes the web
  and TUI stacks and every offline data pack; CI boot-tests the frozen
  web UI before publishing. Prefer the GitHub Releases artifact over
  third-party rebuilds, and verify the attached SHA-256 checksums.
- **Docker image**: python:3.12-slim base, unprivileged uid 10001,
  state confined to the `/data` volume, published to GHCR from CI.
- **CI runs `pip check`** on every PR (dependency consistency) and
  `twine check` on the built distributions.

## Docker and hosted deployments

The image binds nothing by default (`ENTRYPOINT obscuralens` →
`--help`); `docker compose up` serves the web UI on :8000. If you
expose `serve` beyond localhost, remember: the API has no built-in
authentication, and `/api/keys` mutations are open to whoever can reach
the port. Front it with an authenticating reverse proxy and keep
`secrets.yaml` out of any shared volume.
