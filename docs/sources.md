# Data sources

Every ObscuraLens lookup fans out to **all** sources for its kind in parallel,
merges the fields and records which source supplied each fact
(`field_sources` provenance). This page is the complete catalog, per kind.

## Keyless vs keyed

- **Keyless** sources work out of the box — no account, no key, nothing to
  configure. Zero keys are required to start using ObscuraLens.
- **Keyed** sources layer on automatically the moment a key is configured.
  Resolution order: `OBSCURALENS_<SERVICE>_API_KEY` environment variables →
  `config/secrets.yaml` → `config/config.yaml` → defaults. A keyed source
  simply does not run when its key is absent; it is never reported as
  "failed".
- A few sources accept an **optional** key for higher rate limits (marked
  below) — they run keyless but faster with one.

## Disabling sources

Any source in this page can be switched off without touching code:

```yaml
app:
  disabled_sources: [rdap, gravatar, blockchair]
```

`config.is_source_enabled()` gates every reader, and `obscuralens sources`
still lists the source (so you can re-enable it by removing the entry).
Per-source reliability and a circuit breaker for repeatedly failing sources
live under `obscuralens sources health` — see
[docs/advanced.md](advanced.md#source-health-and-circuit-breaker).

## IP (`obscuralens ip`)

| Source | Coverage | Key |
|---|---|---|
| ipwhois.app | Geolocation, ASN, ISP | none |
| ipwho.is | Geolocation, ASN, timezone, flag | none |
| freeipapi | Geolocation, ASN, currencies, proxy flag | none |
| ip-api.com | Geolocation, ASN, ISP | none |
| db-ip.com | Geolocation | none |
| iplocation.net | Geolocation, ISP | none |
| internetdb | Shodan InternetDB: open ports, CVEs, CPEs, hostnames | none |
| ripestat | Announced prefix, origin ASN/holder and RIR via RIPEstat | none |
| reverse_dns | PTR record via DNS-over-HTTPS | none |
| rdap | Registry registration and abuse contact | none |
| ipapi.co | Geolocation, ASN, currency and language hints | none |
| otx | AlienVault OTX pulses, malware samples and passive DNS | optional `otx` |
| hackertarget | Reverse IP hostnames (daily quota) | none |
| threat_feeds | Tor exit list, Spamhaus DROP, Feodo and FireHOL level-1 | none |
| shodan | Full Shodan host data | `shodan` |
| virustotal | Reputation and detections | `virustotal` |
| ipinfo | Hostname, org, privacy hints | `ipinfo` |
| abuseipdb | Abuse reports and confidence score | `abuseipdb` |
| greynoise | GreyNoise community: scanned/noise, Riot CDN | `greynoise` |

## Domain (`obscuralens domain`)

| Source | Coverage | Key |
|---|---|---|
| rdap | Registration dates, registrar, nameservers, abuse contact | none |
| dns | MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC | none |
| certspotter | Certificate Transparency history and subdomains | none |
| http | Status, title, server/security headers, robots.txt | none |
| urlscan | Public urlscan.io scan history, observed IPs and servers | none |
| wayback | First and last Wayback Machine captures | none |
| crt.sh | Certificate Transparency via crt.sh: certificates, subdomains, issuers | none |
| hackertarget | Subdomain/IP host search (daily quota) | none |
| security_txt | RFC 9116 security.txt disclosure contacts and policy | none |

## Email (`obscuralens email`)

| Source | Coverage | Key |
|---|---|---|
| dns | MX/A/AAAA/NS/SOA/CAA/TXT, SPF, DMARC, DKIM, DNSSEC | none |
| disposable | Disposable-mail detection: offline pack (3,000+ domains) + debounce.io | none |
| openpgp | OpenPGP key presence on keys.openpgp.org | none |
| domain_rdap | Domain registration dates, registrar, abuse contact | none |
| gravatar | Gravatar avatar existence | none |
| emailrep | EmailRep.io reputation, linked profiles, leak flags | none |
| github_commits | GitHub commit authorship search (low rate) | optional `github` |
| patterns | Local-part heuristics | none (local) |
| haveibeenpwned | Breach exposure | `haveibeenpwned` |
| hibp_pastes | Paste exposure | `haveibeenpwned` |
| hunter | Deliverability verification | `hunter` |

## Phone (`obscuralens phone`)

| Source | Coverage | Key |
|---|---|---|
| libphonenumber | Local metadata and heuristics: E.164/international/RFC3966 forms, carrier, type flags, toll-free/VoIP hints, offline geo enrichment (country name/flag/continent) | none (local) |
| numverify | Line validation, carrier and location | `numverify` |

## Username (`obscuralens username`)

The username tracker sweeps 41 platforms — 34 HTML platforms and 7 JSON API
platforms — with honest three-state verdicts per platform
(confirmed / ruled-out / inconclusive). JS-shell and bot-wall pages are never
claimed as hits. Restrict a scan with `--platforms steam,kaggle`.

HTML platforms (34): Behance, Bitbucket, Blogger, DeviantArt, Dribbble,
Facebook, Flickr, GitHub, GitLab, Hackaday.io, Instagram, Kaggle, Last.fm,
LinkedIn, Mastodon, Medium, Pinterest, Quora, Redbubble, Reddit, SlideShare,
Snapchat, SoundCloud, Spotify, Steam, Telegram, TikTok, Tumblr, Twitch,
Twitter, Vimeo, Wattpad, WordPress, YouTube.

JSON API platforms (7):

| Platform | Coverage | Key |
|---|---|---|
| Keybase | Profile and proof presence | none |
| HackerNews | Account existence and profile | none |
| Lichess | Account existence and profile | none |
| Codeberg | Account existence and profile | none |
| DockerHub | Account existence and profile | none |
| Dev.to | Account existence and profile | none |
| Chess.com | Account existence and profile | none |

## URL (`obscuralens url`)

| Source | Coverage | Key |
|---|---|---|
| http_probe | Redirect chain, final status, title and server headers | none |
| urlscan | Public urlscan.io scan history and malicious verdicts | none |
| wayback | Wayback Machine capture history via the CDX API | none |
| google_safe_browsing | Google Safe Browsing threat verdicts | `google_safe_browsing` |
| virustotal | URL scan detections and reputation | `virustotal` |

## Crypto (`obscuralens crypto`)

Supported chains: BTC, ETH, DOGE, LTC (validators also recognise XMR, XRP and
ADA addresses — currently no source covers them). Chain routing means an ETH
address never touches the BTC explorers.

| Source | Coverage | Key |
|---|---|---|
| blockchain.info | Bitcoin balance, received/sent totals, tx count, first/last activity (BTC only) | none |
| blockstream.info | Esplora funded/spent sums, tx and mempool counters, last confirmed activity (BTC only) | none |
| blockchair | Address type, balance and first/last seen dates (BTC/ETH/LTC/DOGE, rate-limited) | none |
| etherscan | Ethereum balance and transaction timestamps | `etherscan` |

## Hash (`obscuralens hash`)

Supported algorithms: MD5, SHA-1, SHA-256 (routed per algorithm; SHA-224/
SHA-384/SHA-512 validate but have no sources today).

| Source | Coverage | Key |
|---|---|---|
| malwarebazaar | abuse.ch MalwareBazaar: malware family, file names, tags | optional `malwarebazaar` |
| hashlookup | CIRCL hashlookup known-file corpus: ssdeep/TLSH and file metadata | none |
| otx | AlienVault OTX: pulse count, latest pulse, tags | optional `otx` |
| virustotal | VirusTotal file report: detections, reputation, threat label | `virustotal` |

## CVE (`obscuralens cve`)

| Source | Coverage | Key |
|---|---|---|
| nvd | NVD 2.0: description, CVSS, CWE, references, CPEs | optional `nvd` |
| osv | Google OSV.dev: affected packages and severity vector | none |
| cvelistV2 | CVEProject cvelistV2 raw CNA record | none |
| epss | FIRST.org EPSS exploitation probability | none |

## ASN (`obscuralens asn`)

| Source | Coverage | Key |
|---|---|---|
| ripestat | RIPEstat AS overview and announced prefixes | none |
| bgpview | BGPView AS record, prefixes and peers | none |

## Threat-intel feeds (`obscuralens intel`)

Blocklist feeds are shared by the IP tracker (`threat_feeds` source) and the
`intel` command. All downloads are cached for `app.feed_cache_ttl`
(6 hours by default) and shared across lookups; `app.feeds_enabled` switches
the checks off entirely.

| Feed | Coverage | Key |
|---|---|---|
| Tor exit list | check.torproject.org bulk exit list; Onionoo relay details on hits | none |
| Spamhaus DROP | DROP netset: hijacked/spam-affected ranges | none |
| Feodo Tracker | abuse.ch Feodo C2 IP blocklist | none |
| FireHOL level 1 | Aggregated "do not route" netset | none |

## Adding your own sources

Two routes:

- **Plugins** — drop a Python file into `plugins/` and register extra
  sources for any kind with no packaging; see
  [docs/plugins.md](plugins.md).
- **Keyed services** — new API services slot into `config.SERVICES` and pick
  up the standard env-var/secrets resolution automatically.
