# ObscuraLens v2.0

Multi-source OSINT console for IP addresses, phone numbers, usernames, email addresses and domains. Every lookup fans out to all available data sources in parallel, merges the fields, tracks **which source supplied each fact**, and tells you exactly what answered — no silent single-source lookups, no false-positive "hits".

> **Origin:** rebranded and rewritten from `HunxByts/GhostTrack` v2.2 (a 315-line single-file script, preserved at `GhostTR.py` for reference). Credits to the original author.

## What's new in v2.0

- **Non-interactive CLI** — `obscuralens ip 8.8.8.8 --format json` for scripting and pipelines; the interactive menu still opens when you run `obscuralens` with no arguments.
- **Domain tracker** — RDAP registration, DNS records, SPF/DMARC/DKIM/DNSSEC posture, Certificate Transparency subdomains (Cert Spotter), HTTP status/headers/security-headers and robots.txt in one pass.
- **Field-level provenance** — every result records `field_sources`, so you can see (or export) exactly which source produced each value.
- **Expanded IP sources** — Shodan InternetDB (open ports, CVEs, CPEs) joins the keyless pool; IPinfo and AbuseIPDB join the keyed pool.
- **Expanded DNS/email posture** — A/AAAA/NS/SOA/CAA/TXT, DNSSEC and DKIM selector detection (empty anti-abuse keys are not counted), domain age/expiry in days.
- **7 API-based username platforms** — Keybase, HackerNews, Lichess, Codeberg, Docker Hub, Dev.to, Chess.com. APIs give high-confidence found/not-found verdicts instead of guessing from JavaScript shells.
- **Response cache, per-host rate limiting and proxy support** — repeat lookups are fast and public endpoints stay politely loaded.
- **Reliability fixes** — the interactive result tables no longer crash, DMARC detection works with quoted DoH answers, null MX is reported correctly, and history pruning honors `max_history_entries`.
- **Engineering** — pytest unit suite (network fully mocked), GitHub Actions CI, ruff, `pyproject.toml`, structured report sections shared by the console and the CLI.

## What it does

| Tracker | Sources | Fields (example) |
|---|---|---|
| **IP** | ipwhois.app, ipwho.is, freeipapi, ip-api.com, db-ip, iplocation.net, Shodan InternetDB, reverse DNS, RDAP + keyed Shodan/VirusTotal/IPinfo/AbuseIPDB | 50+ fields for 8.8.8.8: geo, ASN, PTR (`dns.google`), open ports, RDAP org/abuse contact/CIDR, per-source coordinates, per-field provenance |
| **Domain** | RDAP, DNS (MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC), Cert Spotter (CT), HTTP headers | registration dates + age, registrar, nameservers, CT subdomains, security headers, robots.txt |
| **Email** | DNS posture, disposable check, OpenPGP, domain RDAP, Gravatar, pattern analysis + keyed HIBP/Hunter | 30+ fields: MX hosts, SPF/DMARC/DKIM/DNSSEC, registrar, domain age, breach exposure |
| **Phone** | Google libphonenumber metadata + derived hints (+ optional numverify) | 19 fields: E.164/international/RFC3966, carrier, type flags, toll-free/VoIP hints |
| **Username** | 26 HTML platforms + 7 JSON API platforms, honest 3-state verdicts | confirmed / ruled-out / inconclusive — JS-shell pages are never claimed as hits |

Keyed sources (Shodan, VirusTotal, HaveIBeenPwned, Hunter.io, numverify, IPinfo, AbuseIPDB) layer on automatically when a key is configured. Zero keys required to start.

## Installation

Requires Python 3.9+.

```powershell
git clone https://github.com/AceGuru-mjh/ObscuraLens.git
cd ObscuraLens
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
  disabled_sources: []        # e.g. [rdap, gravatar] to skip slow sources
  deep_username_scan: true
```

## Verify

Unit tests (no network, fast):

```powershell
pytest
```

Live integration suite (hits real sources, 80+ checks):

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
│   ├── core/                # HTTP cache, rate limiter, metrics
│   ├── trackers/            # ip / phone / username / email / domain (+ per-source readers)
│   ├── reporting/           # html / json / md / csv / pdf + shared sections
│   ├── visualization/       # matplotlib charts
│   └── utils/               # validators, HTTP client, formatting, console output
├── config/                  # config.yaml + secrets.yaml (git-ignored)
├── tests/                   # pytest unit suite (mocked network)
├── reports/                 # generated reports and charts
├── data/                    # sqlite database + HTTP cache
├── GhostTR.py               # legacy v2.2 single-file script (reference only)
└── test_core.py             # live integration suite
```

## Ethics

For educational and authorised research only. Only investigate targets you are permitted to research; respect each source's terms of service and rate limits. Username scans clearly separate **confirmed** hits from **inconclusive** bot-wall responses — treat the latter as unknown, not evidence.

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Highlights:

- **v2.0.0** — non-interactive CLI, Domain tracker, field provenance, response cache/rate limiting/proxy, new sources (InternetDB, IPinfo, AbuseIPDB, API username platforms), DNS/DKIM/DNSSEC posture, pytest suite + CI, interactive rendering fixes.
- **v1.0.0** — Rebrand from GhostTrack. Multi-source IP aggregation, enriched email tracker, honest 3-state username detection, batch lookups, 5-format reports, charts, history, 4-layer config.
- **v2.2 and earlier** (as GhostTrack) — single-file script with basic IP/phone/username lookup.
