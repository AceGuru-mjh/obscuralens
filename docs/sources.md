# Data sources

Every ObscuraLens lookup fans out to **all** sources for its kind in parallel,
merges the fields and records which source supplied each fact
(`field_sources` provenance). This page is the complete catalog, per kind —
14 kinds as of v5.0.

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
| ipapi.is | Geolocation, ASN, company, datacenter/VPN/proxy/tor flags, risk score | none |
| ipinfo.io | Country, org (ASN + name), hostname, coordinates (keyless free tier; shares field names with the keyed `ipinfo`) | none |
| threat_feeds | Tor exit list, Spamhaus DROP, Feodo, FireHOL level-1, URLhaus and ThreatFox | none |
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
| doh.google | DNS-over-HTTPS resolver (dns.google): A/AAAA/MX/NS answers cross-checking the classic `dns` source, plus a `doh_responded` marker | none |

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

The username tracker sweeps 45 platforms — 38 HTML platforms and 7 JSON API
platforms — with honest three-state verdicts per platform
(confirmed / ruled-out / inconclusive). JS-shell and bot-wall pages are never
claimed as hits. Restrict a scan with `--platforms steam,kaggle`.

HTML platforms (38): Behance, Bitbucket, Blogger, DeviantArt, Dribbble,
Etsy, Facebook, Flickr, GitHub, GitLab, Hackaday.io, Instagram, Kaggle,
Last.fm, LinkedIn, Mastodon, Medium, Patreon, Pinterest, Quora, Redbubble,
Reddit, Replit, SlideShare, Snapchat, SoundCloud, Spotify, Steam, Substack,
Telegram, TikTok, Tumblr, Twitch, Twitter, Vimeo, Wattpad, WordPress,
YouTube.

> Patreon and Etsy sit behind aggressive bot walls: both existing and
> missing accounts answer HTTP 403, so their verdict rules report
> `unknown` (inconclusive) — the same honesty policy as every JS-shell
> platform. Substack resolves via page title ("| Substack" marker) and
> Replit via its login-redirect split, giving real found / not-found
> verdicts.

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
| mempool.space | Bitcoin funded−spent balance, received/sent totals, tx count, pending-tx counter (BTC only; shares field names with blockchain.info so provenance stacks) | none |
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
| circl | CIRCL cveproxy record (CVE-5.1 and legacy schemas): description/CVSS/references merged onto NVD's field names, plus `circl_state`/`circl_title`/`circl_assigner`/`circl_vulnerable_products` | none |

## ASN (`obscuralens asn`)

| Source | Coverage | Key |
|---|---|---|
| ripestat | RIPEstat AS overview and announced prefixes | none |
| bgpview | BGPView AS record, prefixes and peers | none |

## MAC (`obscuralens mac`) *(v5.0)*

EUI-48 MAC addresses in colon, dash or Cisco dot notation; canonicalised to
lowercase colon form. The offline sources mean a MAC lookup still answers
(with bit decomposition always, vendor when curated) with the network down.

| Source | Coverage | Key |
|---|---|---|
| oui_pack | Offline curated IEEE OUI pack (`obscuralens/data/oui.txt`, 766 vendors: networking gear, laptop/phone makers, virtualization platforms, NAS/CCTV/IoT, printers) — vendor + OUI | none (local) |
| macvendors | api.macvendors.com plain-text lookup against the complete IEEE registry (~1k requests/day per IP) | none |
| maclookup | api.maclookup.app v2 JSON record: company, country, registered address, assignment block type (MA-L/MA-M/MA-S/IAB) | none |
| mac_math | Offline EUI-48 bit decomposition: I/G and U/L flags, unicast/multicast and universal/local classes, 01:00:5E / 33:33 reserved blocks, Docker 02:42 vNIC detection with embedded container IPv4, EUI-64 expansion, modified-EUI-64 IPv6 interface id + link-local hint, privacy-randomization hint | none (local) |

Vendor priority: `oui_pack` (curated subset) > `macvendors` (full registry) >
`maclookup` (mirror). A curated-pack miss is an expected answer, not a
source failure — the circuit breaker never trips on it, so offline lookups
stay alive during long batches.

## IBAN (`obscuralens iban`) *(v5.0)*

ISO 13616 IBANs. Printed forms with spaces and a leading `iban:` marker are
accepted; the mod-97 checksum is verified **before** any source runs, so a
typo'd IBAN never leaves your machine.

| Source | Coverage | Key |
|---|---|---|
| iban_math | Offline ISO 13616 arithmetic: country code, check digits, BBAN, length, mod-97 verdict, groups-of-four pretty format, masked account hint | none (local) |
| iban_structure_pack | Offline per-country registry pack (`obscuralens/data/iban_structures.txt`, 124 countries): country name, expected length, `structure_ok` verdict, bank-code and account-number BBAN slices | none (local) |
| openiban | openiban.com online validation with BIC resolution: bank code, bank name, BIC, country | none |

Flat-BBAN countries (bank-code length 0 in the registry) report the account
only, by design. A well-checksummed IBAN of the wrong registry length keeps
`structure_ok: false` — a strong tamper signal worth reading.

## IMEI (`obscuralens imei`) *(v5.0)*

IMEI (15 digits) or IMEISV (16 digits); separators tolerated. The Luhn
check runs before any source is contacted.

| Source | Coverage | Key |
|---|---|---|
| imei_math | Offline 3GPP TS 23.003 decomposition: TAC, reporting-body identifier (01 PTCRB, 35 BABT, 86 TAF, 44, 91, 99), SNR, check digit, Luhn verdict (+ expected check digit on failure), IMEISV software version, pretty AA-BBBBBB-CCCCCC-D format | none (local) |
| tac_pack | Offline curated TAC pack (`obscuralens/data/tac.txt`, 139 entries): manufacturer + model hint | none (local) |

## Coords (`obscuralens coords`) *(v5.0)*

Geographic coordinates in decimal degrees (`48.8584, 2.2945`), DMS
(`N 48° 51' 29", E 2° 17' 40"`), UTM (`31U 448288 5411087`) or MGRS
(`31U DQ 48288 11087`). Latitude ±90 / longitude ±180 enforced.

| Source | Coverage | Key |
|---|---|---|
| nominatim | OpenStreetMap Nominatim reverse geocoding (`/reverse`, zoom 18, address details): formatted address, road/house number, city, county, region, postcode, country + ISO code, OSM ids, place category/type | none (usage policy: identifying User-Agent, low request rate) |
| bigdatacloud | BigDataCloud free `reverse-geocode-client`: locality, city, principal subdivision, country name/code | none |
| open_elevation | Open-Elevation SRTM terrain lookup: elevation in metres | none |
| geohash_local | Offline coordinate maths: geohash (9 chars, ~5 m cells), Maidenhead locator, DMS/DDM strings, hemisphere, UTM and MGRS grid references, solar timezone-offset hint, NOAA solar position (altitude/azimuth, sunrise/sunset, daylight) | none (local) |
| country_centroids | Offline country centroid pack (`obscuralens/data/country_centroids.txt`, 115 countries): nearest country by great-circle distance, with the distance in km so you can judge coarseness | none (local) |

Nominatim's usage policy applies (the request carries the configured
application User-Agent); BigDataCloud's client endpoint occasionally
refuses datacenter IPs — the reader then returns no data and the lookup
degrades gracefully to the other sources.

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
| URLhaus | abuse.ch malicious-URL host network list (plain-text download, ~56k URLs) | none |
| ThreatFox | abuse.ch IOC feed — the keyless recent CSV export (~7k IOCs; the JSON API now requires an Auth-Key), `ip`-typed IOCs only, port/bracket-IPv6 stripped | none |

Feeds are capped at 20 000 networks each (dumps are newest-first, so the
freshest entries survive) and host-type IOCs are tokenized per feed (URLhaus
hosts via URL parsing, ThreatFox hosts from the CSV fields).

## Offline data packs

Shipped as package data (works from wheels and the standalone executable);
`#`-comments and blank lines are ignored, and registry casing is preserved.

| Pack | Entries | Line format | Used by |
|---|---|---|---|
| `disposable_email_domains.txt` | 3,000+ | domain | email `disposable` |
| `popular_domains.txt` | 335 | domain | phishing score, typosquat combo-squatting |
| `phishing_keywords.txt` | 629 | keyword | phishing score, typosquat keyword bonus |
| `oui.txt` | 766 | `AABBCC\|Vendor Name` | mac `oui_pack` |
| `tac.txt` | 139 | `TAC8\|Manufacturer\|Model-hint` | imei `tac_pack` |
| `iban_structures.txt` | 124 | `CC\|length\|bank_code_len\|account_len\|Country name` | iban `iban_structure_pack` |
| `country_centroids.txt` | 115 | `CC\|lat\|lon\|name` | coords `country_centroids`, geospatial GeoJSON pins |

## Adding your own sources

Two routes:

- **Plugins** — drop a Python file into `plugins/` and register extra
  sources for any kind with no packaging; see
  [docs/plugins.md](plugins.md).
- **Keyed services** — new API services slot into `config.SERVICES` and pick
  up the standard env-var/secrets resolution automatically.
