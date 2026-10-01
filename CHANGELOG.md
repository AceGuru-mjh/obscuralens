# Changelog

## 2.0.0 — 2026-10-01

### Added

- **Domain tracker** (`obscuralens domain <domain>`): RDAP registration dates
  and registrar, DNS (MX/A/AAAA/NS/SOA/CAA/TXT), SPF/DMARC/DKIM/DNSSEC posture,
  Certificate Transparency issuance history and subdomains via Cert Spotter,
  HTTP status/title/security headers and robots.txt — with batch support.
- **Non-interactive CLI** (`obscuralens/commands.py`): `ip`, `phone`,
  `username`, `email`, `domain`, `batch`, `history`, `stats`, `sources`, `keys`,
  `cache`, `config`, `--version`. Formats: table, json, markdown, html, csv;
  `-o/--output` writes to a file; `--timeout/--no-cache/--no-color` per run.
  Results go to stdout, diagnostics to stderr, with meaningful exit codes.
- **Field provenance**: every IP/email/domain result carries `field_sources`
  mapping each field to the source(s) that supplied it; the console exposes it
  under "Show field sources".
- **New IP sources**: Shodan InternetDB (keyless — open ports, CVEs, CPEs,
  hostnames, tags); keyed IPinfo and AbuseIPDB integrations.
- **Expanded DNS/email posture**: AAAA/NS/SOA/CAA/TXT records, DNSSEC signing
  detection, DKIM selector discovery (records with an empty `p=` anti-abuse key
  are correctly ignored), null MX detection, domain age and days-to-expiry.
- **New username platforms**: 7 JSON API platforms (Keybase, HackerNews,
  Lichess, Codeberg, Docker Hub, Dev.to, Chess.com) with high-confidence
  verdicts, joining the existing 26 HTML platforms. `--platforms` can restrict
  a scan.
- **Infrastructure**: SQLite TTL response cache (zlib-compressed, size-capped),
  per-host token-bucket rate limiting, proxy support, process network metrics
  (`obscuralens stats`), `OBSCURALENS_CONFIG_DIR` and per-user config fallback.
- **Engineering**: `pyproject.toml` (PEP 621) with dev extras, pytest unit
  suite with fully mocked network (~90 tests), GitHub Actions CI (lint + tests
  on Python 3.9–3.13), ruff configuration, shared report-section builders used
  by console, CLI and exports, `render_markdown`/`render_html` string APIs on
  the report generator.

### Fixed

- `print_table` crashed on row-list data, breaking virtually every interactive
  result view (`AttributeError: 'list' object has no attribute 'keys'`).
- `cli.py` called `json.dumps` in `_fmt_value` without importing `json`.
- DMARC records were filtered before unquoting DoH answers, so `dmarc_record`
  was frequently missed.
- MX parsing could emit an empty host for null MX (`0 .`); now reported as
  `null_mx`.
- `max_history_entries` was never enforced; history is now pruned on write.
- Version/author metadata was inconsistent (`__init__` said 3.0 while the
  package said 1.0.0 and credited the original author).
- `ChartGenerator`/`ReportGenerator` now honour `report_dir`/`chart_dir`
  configuration instead of hardcoding paths.

### Changed

- HTTP client is cache/rate-limit/proxy aware and records metrics; HIBP/Hunter
  calls bypass the cache so breach data is always fresh.
- Email verification checks (OpenPGP, Gravatar) now use cached status fetches.
- Removed the unused `obscuralens/apis/` package (dead duplicate clients; the
  trackers contain the maintained implementations).
- Removed the unused `dnspython` dependency (DNS runs over DNS-over-HTTPS).
- ANSI colours auto-disable when stdout is not a terminal or `NO_COLOR` is set.

## 1.0.0

- Rebrand of GhostTrack v2.2 into a multi-module package.
- Multi-source IP aggregation (8 keyless sources + RDAP + PTR), email tracker
  (MX/A/SPF/DMARC, disposable, OpenPGP, domain RDAP, Gravatar, pattern
  analysis), phone metadata, honest three-state username detection.
- Concurrent batch lookups, HTML/JSON/Markdown/CSV/PDF reports, charts,
  SQLite history with search and statistics, 4-layer configuration.

## 2.2 and earlier (GhostTrack)

- Single-file script with basic IP/phone/username lookup.
