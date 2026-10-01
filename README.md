# ObscuraLens v3.0

> **Founder & maintainer:** MJH

Multi-source OSINT console for IP addresses, phone numbers, usernames, email addresses and domains. Every lookup fans out to all available data sources in parallel, merges the fields, tracks **which source supplied each fact**, and tells you exactly what answered — no silent single-source lookups, no false-positive "hits".

## What's new in v3.0

- **Universal investigate** — `obscuralens investigate <anything>` auto-detects the target type and follows bounded pivots (email → domain, domain → A records, ip → PTR), then exports a relationship graph as **Mermaid**.
- **Watchlist & change detection** — `watch add/list/check/remove` stores snapshots in SQLite and reports exactly what changed between runs (new ports, new subdomains, new breaches, username status…), ignoring timestamps and ages.
- **Plugin system** — drop a `*.py` file with a `SOURCES` dict into `plugins/` (project) or `<config dir>/plugins` (user) and its sources join the relevant trackers as `plugin:<file>:<name>`; broken plugins are isolated, and `app.enable_plugins: false` switches the whole mechanism off. See `docs/plugins.md`.
- **New keyless sources** — RIPEstat (announced prefix, origin ASN/holder, RIR), urlscan.io (public scan history, observed IPs/servers) and the Wayback Machine (first/last capture).
- v2.0 (previous release): non-interactive CLI, Domain tracker, field provenance, HTTP cache/rate limiting/proxy, Shodan InternetDB + IPinfo + AbuseIPDB, 7 JSON API username platforms, DNS/DKIM/DNSSEC posture, pytest suite + CI. See CHANGELOG.md.

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
│   ├── plugins/             # drop-in data-source loader
│   ├── core/                # HTTP cache, rate limiter, metrics
│   ├── trackers/            # ip / phone / username / email / domain (+ per-source readers)
│   ├── reporting/           # html / json / md / csv / pdf + shared sections
│   ├── visualization/       # matplotlib charts
│   └── utils/               # validators, HTTP client, formatting, console output
├── config/                  # config.yaml + secrets.yaml (git-ignored)
├── docs/                    # plugins.md and other guides
├── plugins/                 # project-level drop-in sources (optional)
├── tests/                   # pytest unit suite (mocked network)
├── reports/                 # generated reports and charts
├── data/                    # sqlite database + HTTP cache
└── test_core.py             # live integration suite
```

## Ethics

For educational and authorised research only. Only investigate targets you are permitted to research; respect each source's terms of service and rate limits. Username scans clearly separate **confirmed** hits from **inconclusive** bot-wall responses — treat the latter as unknown, not evidence.

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Highlights:

- **v3.0.0** — universal investigate with pivots + Mermaid graph, watchlist with change detection, plugin system, RIPEstat/urlscan.io/Wayback sources, interactive menu entries.
- **v2.0.0** — non-interactive CLI, Domain tracker, field provenance, response cache/rate limiting/proxy, new sources (InternetDB, IPinfo, AbuseIPDB, API username platforms), DNS/DKIM/DNSSEC posture, pytest suite + CI, interactive rendering fixes.
- **v1.0.0** — Initial packaged release. Multi-source IP aggregation, enriched email tracker, honest 3-state username detection, batch lookups, 5-format reports, charts, history, 4-layer config.
