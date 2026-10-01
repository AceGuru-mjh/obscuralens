# ObscuraLens v1.0

Multi-source OSINT (Open Source Intelligence) console for IP addresses, phone numbers, usernames and email addresses. Every lookup fans out to all available data sources in parallel, merges the fields, and tells you exactly which sources answered — no silent single-source lookups, no false-positive "hits".

> **Origin:** rebranded and rewritten from `HunxByts/GhostTrack` v2.2 (a 315-line single-file script, preserved at `GhostTR.py` for reference). Credits to the original author.

## What it does

| Tracker | Keyless sources | Fields (example) |
|---|---|---|
| **IP** | ipwhois.app, ipwho.is, freeipapi, ip-api.com, db-ip, iplocation.net, reverse DNS, RDAP | 51 fields for 8.8.8.8: geo, ASN, PTR (`dns.google`), RDAP org/abuse contact/CIDR, per-source coordinates |
| **Email** | MX/A/SPF/DMARC, disposable check, OpenPGP, domain RDAP, Gravatar, pattern analysis | 27 fields for a gmail address: 5 MX hosts, SPF, DMARC policy, registrar, domain dates |
| **Phone** | Google libphonenumber metadata + derived hints | 19 fields: E.164/international/RFC3966, carrier, type flags, toll-free/VoIP hints |
| **Username** | 26 platforms, honest 3-state verdicts | confirmed / ruled-out / inconclusive — JS-shell pages are never claimed as hits |

Keyed sources (Shodan, VirusTotal, HaveIBeenPwned, Hunter.io, numverify) layer on automatically when a key is configured. Zero keys required to start.

Beyond lookups: **batch operations** (concurrent, order-preserving), **report export** (HTML/JSON/Markdown/CSV/PDF), **charts** (pie/bar/threat gauge/dashboard), **SQLite query history** with search and statistics.

## Installation

Requires Python 3.8+.

```powershell
git clone https://github.com/AceGuru-mjh/ObscuraLens.git
cd ObscuraLens
pip install -r requirements.txt
python -m obscuralens
```

Development install (editable + `obscuralens` console command):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
obscuralens
```

## API keys (optional)

Resolution order: `OBSCURALENS_*` environment variables → `config/secrets.yaml` → `config/config.yaml` → defaults. `secrets.yaml` is git-ignored and written with owner-only permissions.

```powershell
$env:OBSCURALENS_SHODAN_API_KEY = "your_key"
$env:OBSCURALENS_VIRUSTOTAL_API_KEY = "your_key"
$env:OBSCURALENS_HAVEIBEENPWNED_API_KEY = "your_key"
$env:OBSCURALENS_HUNTER_API_KEY = "your_key"
```

Supported: `shodan`, `virustotal`, `haveibeenpwned`, `hunter`, `numverify`, `ipinfo`, `google_maps`. Keys can also be entered via Settings → Configure API keys in the app.

## Verify

```powershell
python test_core.py
```

Runs 71 checks against live sources: validators, database, all four trackers (including a no-false-positives probe with a bogus handle), batch lookups, all five report formats, all chart types and CLI wiring.

## Project layout

```
ObscuraLens/
├── obscuralens/
│   ├── cli.py              # menu console
│   ├── config.py           # 4-layer configuration
│   ├── database.py         # SQLite history
│   ├── trackers/           # ip / phone / username / email (+ per-source readers)
│   ├── apis/               # shodan / virustotal / hibp / hunter clients
│   ├── visualization/      # matplotlib charts
│   ├── reporting/          # html / json / md / csv / pdf reports
│   └── utils/              # validators, shared HTTP client, console output
├── config/                 # config.yaml + secrets.yaml (git-ignored)
├── reports/                # generated reports and charts
├── data/                   # sqlite database
├── GhostTR.py              # legacy v2.2 single-file script (reference only)
└── test_core.py            # live test suite (71 checks)
```

## Ethics

For educational and authorised research only. Only investigate targets you are permitted to research; respect each source's terms of service and rate limits. Username scans clearly separate **confirmed** hits from **inconclusive** bot-wall responses — treat the latter as unknown, not evidence.

## Changelog

- **v1.0.0** — Rebrand from GhostTrack. Multi-source IP aggregation (8 sources + RDAP + PTR), enriched email tracker (DNS/DNSSEC-adjacent/RDAP/OpenPGP), honest 3-state username detection, concurrent batch lookups, 5-format reports, charts, history, 4-layer config.
- **v2.2 and earlier** (as GhostTrack) — single-file script with basic IP/phone/username lookup.
