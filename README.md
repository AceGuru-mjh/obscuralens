# ObscuraLens v3.1

> **Founder & maintainer:** MJH

Multi-source OSINT console for IP addresses, phone numbers, usernames, email addresses and domains. Every lookup fans out to all available data sources in parallel, merges the fields, tracks **which source supplied each fact**, and tells you exactly what answered — no silent single-source lookups, no false-positive "hits".

## What's new in v3.1

- **More ways to launch** (see [Ways to run](#ways-to-run)): local web UI + REST API (`serve`), a Textual terminal UI (`tui`), an MCP stdio server for AI assistants (`mcp`), Docker/GHCR, a standalone Windows executable, one-command `run.ps1` / `run.sh`, pipx/uv, scheduled monitoring, and a dev container / VS Code / make setup.
- **v3.0**: universal `investigate` with pivots + Mermaid graph, `watch` snapshots with change detection, a plugin system, and new sources RIPEstat / urlscan.io / Wayback.
- **v2.0**: non-interactive CLI, Domain tracker, field provenance, HTTP cache/rate limiting/proxy, Shodan InternetDB + IPinfo + AbuseIPDB, 7 JSON API username platforms, DNS/DKIM/DNSSEC posture, pytest suite + CI.

## What it does

| Tracker | Sources | Fields (example) |
|---|---|---|
| **IP** | ipwhois.app, ipwho.is, freeipapi, ip-api.com, db-ip, iplocation.net, Shodan InternetDB, RIPEstat, reverse DNS, RDAP + keyed Shodan/VirusTotal/IPinfo/AbuseIPDB | 55+ fields for 8.8.8.8: geo, ASN, PTR (`dns.google`), open ports, announced prefix, RIR, RDAP org/abuse contact/CIDR, per-source coordinates, per-field provenance |
| **Domain** | RDAP, DNS (MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC), Cert Spotter (CT), HTTP headers, urlscan.io, Wayback | registration dates + age, registrar, nameservers, CT subdomains, scan history, first/last archive capture, security headers, robots.txt |
| **Email** | DNS posture, disposable check, OpenPGP, domain RDAP, Gravatar, pattern analysis + keyed HIBP/Hunter | 30+ fields: MX hosts, SPF/DMARC/DKIM/DNSSEC, registrar, domain age, breach exposure |
| **Phone** | Google libphonenumber metadata + derived hints (+ optional numverify) | 19 fields: E.164/international/RFC3966, carrier, type flags, toll-free/VoIP hints |
| **Username** | 26 HTML platforms + 7 JSON API platforms, honest 3-state verdicts | confirmed / ruled-out / inconclusive — JS-shell pages are never claimed as hits |

Keyed sources (Shodan, VirusTotal, HaveIBeenPwned, Hunter.io, numverify, IPinfo, AbuseIPDB) layer on automatically when a key is configured. Zero keys required to start.

## Installation

Requires Python 3.9+.

```powershell
git clone https://github.com/AceGuru-mjh/obscuralens.git
cd obscuralens
pip install -r requirements.txt
python -m obscuralens
```

Development install (editable + `obscuralens` console command + test tools):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e ".[dev]"
obscuralens
```

Optional extras: `pip install -e ".[web]"` (web UI/API), `".[tui]"` (terminal UI), `".[exe]"` (build the standalone executable).

## Ways to run

| Method | Command | Notes |
|---|---|---|
| **Interactive console** | `obscuralens` | menu-driven; no arguments |
| **Non-interactive CLI** | `obscuralens ip 8.8.8.8 -f json` | scriptable, pipes cleanly |
| **One-command launcher** | `.\run.ps1 ip 8.8.8.8` / `./run.sh ip 8.8.8.8` | creates `.venv`, installs deps, runs |
| **pipx / uv (no clone)** | `pipx install obscuralens` · `uvx obscuralens ip 8.8.8.8` | once published to PyPI |
| **Web UI + REST API** | `pip install -e ".[web]"` then `obscuralens serve` | http://127.0.0.1:8000 (OpenAPI at `/docs`) |
| **Terminal UI (TUI)** | `pip install -e ".[tui]"` then `obscuralens tui` | Textual rich interface |
| **MCP server (AI agents)** | `obscuralens mcp` | JSON-RPC over stdio; 8 tools |
| **Docker** | `docker run --rm ghcr.io/aceguru-mjh/obscuralens ip 8.8.8.8` | published to GHCR on `main` |
| **Docker Compose (web)** | `docker compose up` | serves the web UI on :8000 |
| **Standalone executable** | `pyinstaller scripts/obscuralens.spec --noconfirm` | CI uploads `obscuralens-windows-exe` |
| **Scheduled monitoring** | see [docs/scheduling.md](docs/scheduling.md) | cron / Task Scheduler / GitHub Actions |
| **Dev container** | open the folder in VS Code → *Reopen in Container* | `.devcontainer/` ships with the repo |
| **Task runner** | `make help` / `just` | install, test, lint, run, serve, build… |

### Web UI / REST API

```powershell
pip install -e ".[web]"
obscuralens serve --host 127.0.0.1 --port 8000
# dashboard:      http://127.0.0.1:8000
# OpenAPI docs:   http://127.0.0.1:8000/docs
```

Key endpoints: `/api/lookup/{kind}/{target}`, `/api/investigate?target=…`,
`/api/sources`, `/api/stats`, `/api/watch` (GET/POST/DELETE) and
`/api/watch/check`.

### MCP server

`obscuralens mcp` speaks the Model Context Protocol over stdio and exposes
`ip_lookup`, `phone_lookup`, `username_lookup`, `email_lookup`,
`domain_lookup`, `investigate`, `watch_list` and `watch_check` to MCP clients
(Claude Desktop, Cursor, …). Register it as a stdio server whose command is
`obscuralens` with argument `mcp`.

### Docker

```powershell
docker build -t obscuralens .
docker run --rm obscuralens ip 8.8.8.8
docker compose up            # web UI on http://localhost:8000
```

State lives in the `/data` volume. Images are published to
`ghcr.io/<owner>/obscuralens` on every push to `main`.

## Usage

Interactive console (no arguments):

```powershell
python -m obscuralens
```

Non-interactive commands:

```powershell
obscuralens ip 8.8.8.8                    # pretty table
obscuralens domain example.com -f json    # machine-readable
obscuralens username github --fast        # skip profile extraction
obscuralens email user@example.com -f markdown -o report.md
obscuralens batch ip targets.txt -f csv -o results.csv
obscuralens history --search 8.8.8.8
obscuralens stats                         # database + cache + network counters
obscuralens sources domain                # list every data source
obscuralens keys                          # API key status
obscuralens cache clear
obscuralens config
```

Investigate anything and watch it for changes:

```powershell
obscuralens investigate example.com               # domain + A-record pivots
obscuralens investigate alice@example.com -f json # email -> domain
obscuralens investigate 8.8.8.8 -f mermaid --graph ip.mmd
obscuralens watch add example.com --label "corp site"
obscuralens watch check --format json             # diff vs last snapshot
obscuralens watch list
obscuralens plugins list                          # drop-in sources
```

Output goes to stdout, progress to stderr, so results pipe cleanly:

```powershell
obscuralens ip 1.1.1.1 -f json | ConvertFrom-Json
```

Exit codes: `0` success, `1` all sources failed / record missing, `2` invalid input.

## API keys (optional)

Resolution order: `OBSCURALENS_*` environment variables → `config/secrets.yaml` → `config/config.yaml` → defaults. `secrets.yaml` is git-ignored and written with owner-only permissions.

```powershell
$env:OBSCURALENS_SHODAN_API_KEY = "your_key"
$env:OBSCURALENS_VIRUSTOTAL_API_KEY = "your_key"
$env:OBSCURALENS_HAVEIBEENPWNED_API_KEY = "your_key"
$env:OBSCURALENS_HUNTER_API_KEY = "your_key"
$env:OBSCURALENS_ABUSEIPDB_API_KEY = "your_key"
$env:OBSCURALENS_IPINFO_API_KEY = "your_key"
```

Supported: `shodan`, `virustotal`, `haveibeenpwned`, `hunter`, `numverify`, `ipinfo`, `abuseipdb`, `google_maps`. Keys can also be entered via Settings → Configure API keys in the app.

## Configuration

`config/config.yaml` (non-sensitive) supports, among others:

```yaml
app:
  request_timeout: 30
  requests_per_second: 8      # per-host rate limit, 0 disables
  cache_enabled: true         # cache successful HTTP GETs (SQLite, TTL)
  cache_ttl: 900
  max_workers: 12
  proxy: ''                   # e.g. http://127.0.0.1:8080
  enable_plugins: true        # load extra sources from plugins/ folders
  disabled_sources: []        # e.g. [rdap, gravatar] to skip slow sources
  deep_username_scan: true
```

### Plugins

Drop a Python file into `<project>/plugins/` or `<config dir>/plugins`:

```python
def lookup(target):
    return {'my_field': f'value for {target}'}

SOURCES = {'ip': {'MySource': lookup}}
```

Its fields appear in results with `plugin:<file>:<name>` provenance. See
[docs/plugins.md](docs/plugins.md) for the full contract and error handling.

## Verify

Unit tests (no network, fast):

```powershell
pytest
```

Live integration suite (hits real sources, 100+ checks):

```powershell
python test_core.py
# or: pytest -m integration
```

Lint:

```powershell
ruff check .
```

## Project layout

```
ObscuraLens/
├── obscuralens/
│   ├── cli.py               # interactive menu + entry point
│   ├── commands.py          # non-interactive CLI (argparse)
│   ├── config.py            # 4-layer configuration
│   ├── database.py          # SQLite history (with pruning)
│   ├── investigate.py       # universal investigate + Mermaid graph
│   ├── watchlist.py         # target snapshots and change detection
│   ├── mcp_server.py        # MCP stdio server for AI assistants
│   ├── tui.py               # Textual terminal UI (optional)
│   ├── web/                 # FastAPI web UI + REST API (optional)
│   ├── plugins/             # drop-in data-source loader
│   ├── core/                # HTTP cache, rate limiter, metrics
│   ├── trackers/            # ip / phone / username / email / domain (+ per-source readers)
│   ├── reporting/           # html / json / md / csv / pdf + shared sections
│   ├── visualization/       # matplotlib charts
│   └── utils/               # validators, HTTP client, formatting, console output
├── config/                  # config.yaml + secrets.yaml (git-ignored)
├── docs/                    # plugins.md, scheduling.md and other guides
├── plugins/                 # project-level drop-in sources (optional)
├── scripts/                 # scheduled_check.py, PyInstaller spec + entry
├── tests/                   # pytest unit suite (mocked network)
├── .devcontainer/           # VS Code dev container
├── .vscode/                 # tasks, launch configs, extensions
├── Dockerfile / docker-compose.yml
├── Makefile / justfile / run.ps1 / run.sh
├── reports/                 # generated reports and charts
├── data/                    # sqlite database + HTTP cache
└── test_core.py             # live integration suite
```

## Ethics

For educational and authorised research only. Only investigate targets you are permitted to research; respect each source's terms of service and rate limits. Username scans clearly separate **confirmed** hits from **inconclusive** bot-wall responses — treat the latter as unknown, not evidence.

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Highlights:

- **v3.1.0** — launch methods: web UI + REST API, Textual TUI, MCP server, Docker/GHCR, standalone exe, run scripts, scheduled monitoring, dev container and task runners.
- **v3.0.0** — universal investigate with pivots + Mermaid graph, watchlist with change detection, plugin system, RIPEstat/urlscan.io/Wayback sources, interactive menu entries.
- **v2.0.0** — non-interactive CLI, Domain tracker, field provenance, response cache/rate limiting/proxy, new sources (InternetDB, IPinfo, AbuseIPDB, API username platforms), DNS/DKIM/DNSSEC posture, pytest suite + CI, interactive rendering fixes.
- **v1.0.0** — Initial packaged release. Multi-source IP aggregation, enriched email tracker, honest 3-state username detection, batch lookups, 5-format reports, charts, history, 4-layer config.
