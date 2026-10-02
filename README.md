# ObscuraLens v4.0

> **Founder & maintainer:** MJH

Multi-source OSINT console and investigation platform for **10 target kinds**: IP addresses, phone numbers, usernames, email addresses, domains, URLs, crypto addresses, file hashes, CVEs and AS numbers. Every lookup fans out to all available data sources in parallel, merges the fields, tracks **which source supplied each fact**, and tells you exactly what answered — no silent single-source lookups, no false-positive "hits". v4.0 layers an investigation workflow on top: entity graphs and pivots, correlation across your stored history, chronological timelines, explainable heuristic risk scoring, case management, YAML pipelines, threat-intel feeds and graph exports for Gephi/Graphviz.

## What's new in v4.0

- **5 new trackers**: `url` (redirect chains, urlscan.io, Wayback, keyed Google Safe Browsing/VirusTotal), `crypto` (blockchain.info, Blockstream, Blockchair, keyed Etherscan), `hash` (MalwareBazaar, CIRCL hashlookup, OTX, keyed VirusTotal), `cve` (NVD, OSV, cvelistV2, EPSS) and `asn` (RIPEstat, BGPView).
- **New sources for existing trackers**: IP gains ipapi.co, AlienVault OTX (pulses + passive DNS), hackertarget and threat feeds (Tor exit list, Spamhaus DROP, Feodo, FireHOL level-1) plus keyed GreyNoise; domain gains crt.sh, hackertarget hostsearch and RFC 9116 security.txt; email gains EmailRep.io, GitHub commit search and an offline disposable-domain pack (3,000+ domains); username gains 8 HTML platforms (Steam, Mastodon, Wattpad, SlideShare, Redbubble, Hackaday.io, Last.fm, Kaggle); phone gains offline geo enrichment (country name, flag, continent).
- **14 new CLI commands**: `url`, `crypto`, `hash`, `cve`, `asn`, `risk`, `timeline`, `correlate`, `diff`, `export`, `case`, `pipeline`, `intel`, `experimental` — plus `sources health` and a `--risk` flag on every lookup.
- **Correlation, timeline and risk scoring** across your stored lookup history: clusters, bridge entities, chronological event timelines and explainable per-kind risk signals. See [docs/advanced.md](docs/advanced.md).
- **Case management** (SQLite): items, notes, tags, markdown/JSON export.
- **YAML pipelines**: lookup/risk/timeline/correlate/assert/output steps with `$variables`; three examples ship in `pipelines/examples/`.
- **Experimental features**: LLM narrative summaries, username permutations, a bounded robots-aware web crawler and a phishing heuristic score. See [docs/experimental.md](docs/experimental.md).
- **Graph exports**: GraphML, GEXF, DOT, JSONL and CSV for Gephi, yEd, Cytoscape and Graphviz.
- **Source health + circuit breaker**: per-source reliability statistics; failing sources are tripped for a cooldown. See [docs/advanced.md](docs/advanced.md#source-health-and-circuit-breaker).
- Full data-source catalog in [docs/sources.md](docs/sources.md); REST API reference in [docs/api.md](docs/api.md).
- **v3.1**: web UI + REST API, Textual TUI, MCP server, Docker/GHCR, standalone exe, run scripts, scheduled monitoring, dev container and task runners.
- **v3.0**: universal `investigate` with pivots + Mermaid graph, `watch` snapshots with change detection, plugin system, RIPEstat/urlscan.io/Wayback sources.
- **v2.0**: non-interactive CLI, Domain tracker, field provenance, HTTP cache/rate limiting/proxy, Shodan InternetDB + IPinfo + AbuseIPDB, 7 JSON API username platforms, DNS/DKIM/DNSSEC posture, pytest suite + CI.

## What it does

| Tracker | Sources | Fields (example) |
|---|---|---|
| **IP** | ipwhois.app, ipwho.is, freeipapi, ip-api.com, db-ip, iplocation.net, Shodan InternetDB, RIPEstat, reverse DNS, RDAP, ipapi.co, OTX (pulses + passive DNS), hackertarget, threat feeds (Tor/Spamhaus DROP/Feodo/FireHOL) + keyed Shodan/VirusTotal/IPinfo/AbuseIPDB/GreyNoise | geo, ASN, PTR, open ports and CVEs, announced prefix, RIR, RDAP org/abuse contact, Tor/blocklist verdicts, passive DNS, per-field provenance |
| **Domain** | RDAP, DNS (MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC), Cert Spotter, crt.sh, HTTP headers, urlscan.io, Wayback, hackertarget, security.txt (RFC 9116) | registration dates + age, registrar, nameservers, CT subdomains, scan history, first/last archive capture, security headers, robots.txt, disclosure contacts |
| **Email** | DNS posture, disposable check (offline pack of 3,000+ domains), OpenPGP, domain RDAP, Gravatar, EmailRep.io, GitHub commit search, pattern analysis + keyed HIBP/Hunter | MX hosts, SPF/DMARC/DKIM/DNSSEC, registrar, domain age, breach exposure, reputation, linked profiles |
| **Phone** | Google libphonenumber metadata + derived hints + offline geo enrichment (country name/flag/continent) (+ optional numverify) | E.164/international/RFC3966, carrier, type flags, toll-free/VoIP hints |
| **Username** | 41 platforms: 34 HTML + 7 JSON API, honest 3-state verdicts | confirmed / ruled-out / inconclusive — JS-shell pages are never claimed as hits |
| **URL** | Redirect walk, urlscan.io, Wayback CDX + keyed Google Safe Browsing/VirusTotal | redirect chain + count, final URL, status, title, server, urlscan verdicts, archive captures, GSB/VT verdicts |
| **Crypto** | blockchain.info, Blockstream Esplora, Blockchair (BTC/ETH/LTC/DOGE) + keyed Etherscan | balance, received/sent totals, tx counts, first/last activity, mempool counters |
| **Hash** | MalwareBazaar, CIRCL hashlookup, OTX + keyed VirusTotal | malware family, file names/size/type, tags, known-file verdict, detections, reputation, threat label |
| **CVE** | NVD 2.0, OSV.dev, cvelistV2, FIRST EPSS | description, CVSS score/vector/severity, CWE, references, affected CPEs, EPSS probability |
| **ASN** | RIPEstat, BGPView | holder, description, country, website, announced prefixes (v4/v6 counts), peers |

Keyed sources layer on automatically when a key is configured. Zero keys required to start.

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
| **MCP server (AI agents)** | `obscuralens mcp` | JSON-RPC over stdio; 18 tools |
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
`/api/risk/{kind}/{target}`, `/api/timeline`, `/api/correlate` (+ `/pair`),
`/api/intel/{ip}`, `/api/cases`, `/api/export/{fmt}/{target}`, `/api/sources`,
`/api/stats` and `/api/watch`. Full reference: [docs/api.md](docs/api.md).

### MCP server

`obscuralens mcp` speaks the Model Context Protocol over stdio and exposes 18
tools: `ip_lookup`, `phone_lookup`, `username_lookup`, `email_lookup`,
`domain_lookup`, `url_lookup`, `crypto_lookup`, `hash_lookup`, `cve_lookup`,
`asn_lookup`, `investigate`, `risk_report`, `correlate`, `timeline`,
`threat_intel`, `source_health`, `watch_list` and `watch_check` to MCP clients
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

Core lookups (all 10 kinds):

```powershell
obscuralens ip 8.8.8.8 --risk             # pretty table + heuristic risk section
obscuralens domain example.com -f json     # machine-readable
obscuralens username github --fast         # skip profile extraction
obscuralens email user@example.com -f markdown -o report.md
obscuralens url https://example.com        # redirect chain, verdicts, history
obscuralens crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
obscuralens hash 44d88612fea8a8f36de82e1278abb02f
obscuralens cve CVE-2021-44228
obscuralens asn AS15169
obscuralens batch ip targets.txt -f csv -o results.csv
obscuralens history --search 8.8.8.8
obscuralens stats                         # database + cache + network counters
obscuralens sources domain                # list every data source
obscuralens keys                          # API key status
obscuralens cache clear
obscuralens config
```

Investigate anything, score it, timeline it and export the graph:

```powershell
obscuralens investigate example.com                # domain + A-record pivots
obscuralens investigate 8.8.8.8 --timeline --risk  # + chronological events
obscuralens investigate example.com --export graphml -f json
obscuralens risk domain example.com                # score + verdict + signals
obscuralens risk url https://example.com -f json
obscuralens timeline example.com --limit 50        # from stored history
obscuralens correlate 8.8.8.8 dns.google           # shared infrastructure
obscuralens correlate --all                        # clusters + bridges
obscuralens diff 12 15                             # compare stored results
obscuralens export graphml example.com             # GraphML/GEXF/DOT/JSONL/CSV
obscuralens watch add example.com --label "corp site"
obscuralens watch check --format json              # diff vs last snapshot
obscuralens plugins list                           # drop-in sources
```

Case management workflow:

```powershell
obscuralens case new "acme-phishing" --description "Brand-abuse investigation"
obscuralens case add 1 https://secure-login.example-verify.com --kind url
obscuralens case add 1 45.148.10.99 --kind ip --note "hosting the kit"
obscuralens case note 1 "Google Safe Browsing flagged the URL."
obscuralens case tag 1 phishing
obscuralens case list
obscuralens case find 45.148.10.99
obscuralens case export 1 -f markdown --path acme-case.md
obscuralens case close 1
```

Pipelines (see [docs/advanced.md](docs/advanced.md#pipelines) for the schema):

```powershell
obscuralens pipeline list
obscuralens pipeline run ip-triage --set target=45.148.10.99
obscuralens pipeline init my-first-pipeline
```

Threat intel and source health:

```powershell
obscuralens intel ip 45.148.10.99        # Tor exit, DROP/Feodo/FireHOL verdicts
obscuralens intel tor 185.220.101.1      # exit node + Onionoo relay details
obscuralens intel feeds                  # blocklist feed cache status
obscuralens sources health               # reliability + circuit-breaker state
obscuralens sources health --reset ip-api.com
```

Experimental features (see [docs/experimental.md](docs/experimental.md)):

```powershell
obscuralens experimental phish http://paypa1-login.example.com/
obscuralens experimental crawl https://example.com --depth 2 --max-pages 10
obscuralens experimental permute johndoe --scan
obscuralens experimental llm domain example.com
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
$env:OBSCURALENS_ETHERSCAN_API_KEY = "your_key"
$env:OBSCURALENS_GREYNOISE_API_KEY = "your_key"
$env:OBSCURALENS_OTX_API_KEY = "your_key"
$env:OBSCURALENS_GOOGLE_SAFE_BROWSING_API_KEY = "your_key"
$env:OBSCURALENS_GITHUB_API_KEY = "your_key"
$env:OBSCURALENS_NVD_API_KEY = "your_key"
$env:OBSCURALENS_MALWAREBAZAAR_API_KEY = "your_key"
$env:OBSCURALENS_SECURITYTRAILS_API_KEY = "your_key"
$env:OBSCURALENS_LLM_API_KEY = "your_key"    # experimental LLM summaries
```

Supported: `shodan`, `virustotal`, `haveibeenpwned`, `hunter`, `numverify`, `ipinfo`, `abuseipdb`, `google_maps`, `etherscan`, `greynoise`, `otx`, `google_safe_browsing`, `github`, `nvd`, `malwarebazaar`, `securitytrails`, `llm`. Keys can also be entered via Settings → Configure API keys in the app.

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
  # -- v4.0 --
  experimental_features: true       # master switch for experimental modules
  source_health_enabled: true       # persist per-source reliability stats
  source_failure_threshold: 4       # consecutive failures before tripping
  source_cooldown_seconds: 600      # how long a tripped source stays off
  feeds_enabled: true               # check IPs against blocklist feeds
  feed_cache_ttl: 21600             # 6h freshness for downloaded feeds
  risk_enabled: true                # attach heuristic risk scores
  correlation_max_history: 500      # history rows scanned by correlate()
  timeline_max_events: 200          # events kept per timeline
  cases_enabled: true
  pipeline_dir: pipelines           # folder scanned by `pipeline list`
  llm_base_url: ''                  # e.g. https://api.openai.com/v1
  llm_model: gpt-4o-mini
  crawler_max_depth: 2              # experimental web crawler bounds
  crawler_max_pages: 20
  crawler_delay: 1.0                # polite delay between page fetches
  permutation_max_candidates: 48    # experimental username permutations
  permutation_platforms: 5
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

Unit tests (no network, fast) — 738 tests:

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
│   ├── investigate.py       # universal investigate + pivots + graph
│   ├── watchlist.py         # target snapshots and change detection
│   ├── mcp_server.py        # MCP stdio server (18 tools)
│   ├── tui.py               # Textual terminal UI (optional)
│   ├── web/                 # FastAPI web UI + REST API (optional)
│   ├── plugins/             # drop-in data-source loader
│   ├── core/                # HTTP cache, rate limiter, metrics
│   ├── trackers/            # ip / phone / username / email / domain / url /
│   │                        # crypto / hash / cve / asn (+ per-source readers)
│   ├── correlation/         # graph engine, timeline builder, risk scoring
│   ├── cases/               # SQLite case management (items/notes/tags)
│   ├── pipelines/           # YAML pipeline engine
│   ├── experimental/        # llm_summary, permutations, crawler, phish score
│   ├── export/              # GraphML / GEXF / DOT / JSONL / CSV serializers
│   ├── health/              # per-source reliability + circuit breaker
│   ├── intel/               # Tor exit list, Onionoo, blocklist feeds
│   ├── reporting/           # html / json / md / csv / pdf + shared sections
│   ├── visualization/       # matplotlib charts
│   ├── utils/               # validators, HTTP client, geo, data packs, ...
│   └── data/                # offline packs: disposable domains, popular
│                            # domains, phishing keywords
├── pipelines/               # user pipelines + examples/ (3 shipped)
├── config/                  # config.yaml + secrets.yaml (git-ignored)
├── docs/                    # plugins, scheduling, sources, advanced,
│                            # experimental and API guides
├── plugins/                 # project-level drop-in sources (optional)
├── scripts/                 # scheduled_check.py, PyInstaller spec + entry
├── tests/                   # pytest unit suite (mocked network, 738 tests)
├── .devcontainer/           # VS Code dev container
├── .vscode/                 # tasks, launch configs, extensions
├── Dockerfile / docker-compose.yml
├── Makefile / justfile / run.ps1 / run.sh
├── reports/                 # generated reports and charts
├── data/                    # sqlite database + HTTP cache
└── test_core.py             # live integration suite
```

## Ethics

For educational and authorised research only. Only investigate targets you are permitted to research; respect each source's terms of service and rate limits. Username scans clearly separate **confirmed** hits from **inconclusive** bot-wall responses — treat the latter as unknown, not evidence. Risk scores are explainable heuristics over **technical indicators only**: they describe infrastructure and exposure, and are never verdicts about people.

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Highlights:

- **v4.0.0** — investigation platform: 5 new trackers (URL, crypto, hash, CVE, ASN), correlation/timeline/risk, case management, YAML pipelines, threat-intel feeds, graph exports, source health + circuit breaker, experimental features, offline data packs. 738 unit tests.
- **v3.1.0** — launch methods: web UI + REST API, Textual TUI, MCP server, Docker/GHCR, standalone exe, run scripts, scheduled monitoring, dev container and task runners.
- **v3.0.0** — universal investigate with pivots + Mermaid graph, watchlist with change detection, plugin system, RIPEstat/urlscan.io/Wayback sources, interactive menu entries.
- **v2.0.0** — non-interactive CLI, Domain tracker, field provenance, response cache/rate limiting/proxy, new sources (InternetDB, IPinfo, AbuseIPDB, API username platforms), DNS/DKIM/DNSSEC posture, pytest suite + CI, interactive rendering fixes.
- **v1.0.0** — Initial packaged release. Multi-source IP aggregation, enriched email tracker, honest 3-state username detection, batch lookups, 5-format reports, charts, history, 4-layer config.
