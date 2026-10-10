# Data sources

Every ObscuraLens lookup fans out to **all** sources for its kind in parallel,
merges the fields and records which source supplied each fact
(`field_sources` provenance) — and since v6.1 also scores how well each
fact is corroborated (the `confidence` block). This page is the complete
catalog, per kind — 20 kinds as of v6.0, with the v6.1 source additions
marked per row.

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
| proxycheck | proxycheck.io VPN/proxy/relay verdict and 0-100 risk score (keyless free tier; v6.1) | none |
| shodan | Full Shodan host data | `shodan` |
| virustotal | Reputation and detections | `virustotal` |
| ipinfo | Hostname, org, privacy hints | `ipinfo` |
| abuseipdb | Abuse reports and confidence score | `abuseipdb` |
| greynoise | GreyNoise community: scanned/noise, Riot CDN | optional `greynoise` |

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
| doh.cloudflare | DNS-over-HTTPS via the Cloudflare 1.1.1.1 resolver: the same A/AAAA/MX/NS record set as a third independent DNS vantage point, plus a `doh_cf_responded` marker (v5.2) | none |
| hstspreload | Chromium HSTS preload list status via hstspreload.org: `preloaded`/`pending`/`rejected`/`unknown` plus the preloaded parent domain (v6.1) | none |
| ransomware_live | ransomware.live recent-attack feed: which ransomware group listed the domain on a leak site and when (1 req/min, cached six hours; v6.1) | none |

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
| xposedornot | XposedOrNot breach analytics: 0-100 risk score, exposing breach sites, paste count, weak-password count (v6.1) | none |
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

The username tracker sweeps **112 platforms** — 101 HTML platforms and 11
JSON API platforms — with honest three-state verdicts per platform
(confirmed / ruled-out / inconclusive). JS-shell and bot-wall pages are never
claimed as hits. Restrict a scan with `--platforms steam,kaggle`.

HTML platforms (101): 9GAG, About.me, AtCoder, Bandcamp, Behance,
Bitbucket, Bitwarden Forum, Blender Artists, Blogger, Calendly, Codeforces,
Credly, Crowdin, DeviantArt, Disqus, Dribbble, Etsy, Exophase, Facebook,
Flickr, Fosstodon, Freesound, Geocaching, GitBook, GitHub, GitLab, Gitee,
GoodReads, Gumroad, HackMD, Hackaday.io, HackerOne, Hashnode, HubPages,
Hugging Face, IFTTT, Instagram, Instructables, Ionic Forum, Issuu, Itch.io,
Joplin Forum, Kaggle, Ko-fi, Kongregate, Laracast, Last.fm, Launchpad,
LinkedIn, Linktree, LinuxFR, Mastodon, Medium, Memrise, MyAnimeList,
MyDramaList, MyMiniFactory, OK.ru, OpenGameArt, OpenSea, Patreon, Pinterest,
Pixelfed, Pokemon Showdown, Quora, Rclone Forum, Redbubble, Reddit, Replit,
RubyGems, Rust Users, Scratch, Sketchfab, SlideShare, Snapchat, SoundCloud,
SourceForge, SpeakerDeck, Spotify, Steam, Strava, Substack, Telegram, Tenor,
TheMovieDB, TikTok, TradingView, Tumblr, Twitch, Twitter, Ubuntu Discourse,
VK, Vimeo, WakaTime, Wattpad, Windy, WordPress, YouPic, YouTube, n8n
Community, write.as.

> Patreon and Etsy sit behind aggressive bot walls: both existing and
> missing accounts answer HTTP 403, so their verdict rules report
> `unknown` (inconclusive) — the same honesty policy as every JS-shell
> platform. Substack resolves via page title ("| Substack" marker) and
> Replit via its login-redirect split, giving real found / not-found
> verdicts. Hashnode decides from the page title ("User not found |
> Hashnode" vs a real profile title). Ko-fi decides from its homepage-
> fallback title (missing usernames land on the generic "Ko-fi | …" page)
> and Codeforces from its profile-title signature — both v6.1 additions,
> live-verified before shipping.

The v5.2 HTML additions all ride the `STATUS_RELIABLE` fast path: every one
of them was probed live before shipping, and a plain 200 on the profile
URL counts as a hit only because missing accounts verifiably answer 404.
Calendly, Gumroad, OpenSea and Bandcamp joined that set in v6.1 (their
200-vs-404 splits were re-verified live).
Platforms that bot-wall every scripted client (Codepen, Codewars, LeetCode,
npm, ArtStation, Trakt, osu!, Wikipedia, Fandom, Imgur, Speedrun.com, and
the v6.1 candidates unsplash/producthunt/researchgate/scribd/discogs/
genius/chess.com/kickstarter/500px, …)
were tested and deliberately **not** added — they could only ever report
"unknown".

JSON API platforms (11):

| Platform | Coverage | Key |
|---|---|---|
| Keybase | Profile and proof presence | none |
| HackerNews | Account existence and profile | none |
| Lichess | Account existence and profile | none |
| Codeberg | Account existence and profile | none |
| DockerHub | Account existence and profile | none |
| Dev.to | Account existence and profile | none |
| Chess.com | Account existence and profile | none |
| Bluesky | DID-confirmed profile via the public App View API (`app.bsky.actor.getProfile`); bare usernames resolve `<name>.bsky.social`, dotted handles are used verbatim (v5.2) | none |
| Dailymotion | User via api.dailymotion.com with an explicit field list: screenname, creation date, follower/video/view totals (v5.2) | none |
| Stack Exchange | Stack Overflow account via the users API (`inname` search with exact display-name matching; the verdict engine passes the queried username for the match) (v6.1) | none |
| Duolingo | Learner profile via the 2017-06-30 users JSON API: `users: []` for missing accounts — a clean JSON split (v6.1) | none |

## URL (`obscuralens url`)

| Source | Coverage | Key |
|---|---|---|
| http_probe | Redirect chain, final status, title and server headers | none |
| urlscan | Public urlscan.io scan history and malicious verdicts | none |
| wayback | Wayback Machine capture history via the CDX API | none |
| openphish | OpenPhish community phishing feed membership: exact-URL and host-level matches; a feed-clear is a fact, not a failure (v5.2) | none |
| google_safe_browsing | Google Safe Browsing threat verdicts | `google_safe_browsing` |
| virustotal | URL scan detections and reputation | `virustotal` |

## Crypto (`obscuralens crypto`)

Supported chains: BTC, ETH, DOGE, LTC, XRP, ADA, TRON, ATOM, NEAR, SOL
(validators also recognise XMR addresses — Monero balances are
unobservable by design, so xmr is chain-labelled only; v6.1 adds TRON,
NEAR named accounts like `alice.near`, and Cosmos `cosmos1…` addresses).
Chain routing means an ETH address never touches the BTC explorers.

| Source | Coverage | Key |
|---|---|---|
| blockchain.info | Bitcoin balance, received/sent totals, tx count, first/last activity (BTC only) | none |
| blockstream.info | Esplora funded/spent sums, tx and mempool counters, last confirmed activity (BTC only) | none |
| blockchair | Address type, balance and first/last seen dates (BTC/ETH/LTC/DOGE, rate-limited) | none |
| mempool.space | Bitcoin funded−spent balance, received/sent totals, tx count, pending-tx counter (BTC only; shares field names with blockchain.info so provenance stacks) | none |
| blockcypher | Balance, received/sent totals and tx counters (BTC/ETH/LTC/DOGE, keyless, rate-limited; LTC and DOGE's second aggregated source; v5.2) | none |
| xrpscan | XRP balance, sequence, owner count, latest affecting transaction and ledger index (XRP only; v5.2) | none |
| xrpl_public | Independent `account_info` second opinion from the xrplcluster.com community RPC — same AccountRoot fields as xrpscan reported by a different server, provenance stacks (XRP only; v6.1) | none |
| koios | Lovelace balance, stake address, script flag, UTXO count and UTXO-derived last activity via the Koios Cardano API pool (ADA only; v5.2) | none |
| solana | Lamports balance, owner program, executable flag and data size via the public Solana mainnet JSON-RPC (SOL only; v5.2) | none |
| tron | TRX balance, account type, decoded contract name and creation time via TronGrid `wallet/getaccount`; never-activated addresses are real zero-balance negatives (TRON only; v6.1) | none |
| near | NEAR balance, locked stake, contract code hash and storage usage via the public NEAR RPC `query`/`view_account`; `UNKNOWN_ACCOUNT` is a real negative (NEAR named accounts; v6.1) | none |
| cosmos | ATOM and IBC token balances plus account number/sequence via the cosmos.directory REST proxy (ATOM only; v6.1) | none |
| ethplorer | ERC-20 token portfolio, token symbols, spot price and tx count via the freekey tier; cached an hour against its hard rate limit (ETH only; v6.1) | none |
| avax_cchain | Cross-chain Avalanche C-chain balance and nonce for ETH-format addresses via the public AVAX EVM RPC — the same 0x address checked on a second chain (v6.1) | none |
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
| cvelist | CVEProject cvelistV5 raw CNA record | none |
| cveawg | The CVE Program's authoritative record API (cveawg.mitre.org): same CVE 5.1 schema as cvelist, cross-confirming it with stacked provenance (v5.2) | none |
| ghsa | GitHub Security Advisories: GHSA ids, highest severity, CVSS score and CWE list (v5.2) | optional `github` |
| epss | FIRST.org EPSS exploitation probability | none |
| circl | CIRCL cveproxy record (CVE-5.1 and legacy schemas): description/CVSS/references merged onto NVD's field names, plus `circl_state`/`circl_title`/`circl_assigner`/`circl_vulnerable_products` | none |
| kev | CISA Known Exploited Vulnerabilities catalog via CISA's own cisagov/kev-data GitHub mirror: actively-exploited verdict, known-ransomware/actor flags, due date; a miss is a real negative (v6.1) | none |

## ASN (`obscuralens asn`)

| Source | Coverage | Key |
|---|---|---|
| ripestat | RIPEstat AS overview and announced prefixes | none |
| bgpview | BGPView AS record, prefixes and peers | none |
| asrank | CAIDA AS-Rank: global customer-cone ranking, RIR source, cone size, IXP/seen flags (v6.1) | none |
| peeringdb | PeeringDB operator-maintained record: network name, traffic volume, info type, peering policy, IX count (v6.1) | none |

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
| open_meteo | Open-Meteo current weather (temperature, wind speed/direction, weather code) with the position's timezone, plus an independent second elevation opinion via the dedicated elevation endpoint (v6.1) | none |
| geohash_local | Offline coordinate maths: geohash (9 chars, ~5 m cells), Maidenhead locator, DMS/DDM strings, hemisphere, UTM and MGRS grid references, solar timezone-offset hint, NOAA solar position (altitude/azimuth, sunrise/sunset, daylight) | none (local) |
| country_centroids | Offline country centroid pack (`obscuralens/data/country_centroids.txt`, 115 countries): nearest country by great-circle distance, with the distance in km so you can judge coarseness | none (local) |

Nominatim's usage policy applies (the request carries the configured
application User-Agent); BigDataCloud's client endpoint occasionally
refuses datacenter IPs — the reader then returns no data and the lookup
degrades gracefully to the other sources.

## VIN (`obscuralens vin`) *(v6.0)*

Vehicle Identification Numbers (ISO 3779): 17 characters, no I/O/Q, with
the transliterated mod-11 check digit at position 9 verified **before** any
source runs. Hyphen/space separated forms and lower case are tolerated.
The offline decomposition needs no registry at all, so a VIN report always
answers — the WMI pack and vPIC only enrich it.

| Source | Coverage | Key |
|---|---|---|
| vin_math | Offline ISO 3779 decomposition: WMI, VDS/VIS slices, first-character region hint, model-year code with **both** 30-year-cycle candidates, plant code, six-digit production serial, check-digit verdict (+ expected digit on failure), full 17-position map | none (local) |
| nhtsa_vpic | NHTSA vPIC decoder (`vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues`): make, model, model year, vehicle type, body class, engine and drive details, assembly plant city/state/country, decoder error code — North American market vehicles; European/Asian domestic VINs answer with the error code only | none |

```bash
obscuralens vin 1HGCM82633A004352
```

```text
IDENTITY                ISO 3779 DECOMPOSITION
  Wmi           1HG      Year Code             3
  Manufacturer  Honda    Model Year Candidates 2003, 2033
  Country       United   Model Year Cycle      year code '3' encodes 2003
               States                          or 2033 (VIN year codes repeat
  Region Hint   United                         on a 30-year cycle)
               States    Plant Code            A
                         Serial Number         004352
                         Check Digit           3 (valid)
```

Priority: `vin_math` (standards-derived) > `nhtsa_vpic` (registry mirror).
A WMI absent from the curated pack is an expected answer ("no
manufacturer"), never a source failure — the circuit breaker never trips
on it, so offline VIN batches stay alive.

## Flight (`obscuralens flight`) *(v6.0)*

Flight designators: a 2-letter IATA or 3-letter ICAO carrier code plus a
1-4 digit flight number and an optional suffix letter (`UA1`, `BA2490`,
`DLH400A`). Spaces, hyphens and lower case are tolerated. Both offline
sources answer with the network down; the keyless live ADS-B source joins
keyless with v6.1, and the aviationstack live source layers on with a key.

| Source | Coverage | Key |
|---|---|---|
| airline_pack | Offline curated airline pack (`obscuralens/data/airlines_iata.txt`, 134 carriers): airline name, IATA/ICAO codes, country, radio callsign | none (local) |
| flight_math | Offline designator anatomy: carrier code flavour (IATA vs ICAO), flight number digits + suffix, both flight-code renderings (`UA1`/`UAL1`), the `{ICAO}{number}` radio callsign, odd/even direction and number-band conventions (explicitly labelled as conventions, not evidence) | none (local) |
| adsb_lol | adsb.lol community ADS-B API: the aircraft broadcasting the designator **right now** — live position, barometric altitude, ground speed, track heading, registration, type code, squawk and seconds since last contact. Both the raw designator and the ICAO callsign form are tried. Nothing airborne is an honest negative (`adsb_currently_airborne: false`); a transport failure is never misreported as "not airborne" (v6.1) | none |
| aviationstack | aviationstack.com live flight API: today's status (scheduled/active/landed/cancelled/diverted), airline confirmation, departure/arrival airports + IATA codes + scheduled times, aircraft registration | optional `aviationstack` |

```bash
obscuralens flight BA2490
```

```text
AIRLINE                  DESIGNATOR ANATOMY
  Airline Name  British   Carrier Code         BA (IATA)
               Airways    Flight Number        2490
  Airline Iata  BA         Radio Callsign      BAW2490
  Airline Icao  BAW        Direction Hint      even flight number -
  Country       United                          return/continuation leg
               Kingdom                         (convention only)
  Callsign      SPEEDBIRD  Number Band Hint    900+ - supplemental/extra
                                              sections (convention only)
```

Priority: `airline_pack` (curated) > `flight_math` > `aviationstack`
(live mirror). A carrier missing from the curated subset is an expected
answer ("no airline name"), never a source failure.

## MMSI (`obscuralens mmsi`) *(v6.0)*

Maritime Mobile Service Identities (ITU-R M.1085): nine digits encoding
the station class in the leading digits — `201-775` ship MIDs, `00` coast
stations, `0` group calls, `8` handheld VHF, `99` AIS aids to navigation.
Integers, hyphen/space groups and a `MMSI:` prefix are all accepted. The
kind is fully offline (like `imei`): no source ever touches the network.

| Source | Coverage | Key |
|---|---|---|
| mmsi_math | Offline ITU-R M.1085 structure decode: station class + short code, MID, serial digits, ITU series label, conservative trailing-zero note (zero-ending ship serials, flagged as an unconfirmed convention) | none (local) |
| mid_pack | Offline curated MID pack (`obscuralens/data/mid_codes.txt`, 97 flag states): the MID → country attribution | none (local) |

```bash
obscuralens mmsi 366910000
```

```text
STATION IDENTITY (ITU-R M.1085)   FLAG STATE & SERIAL
  Station Type         individual   Mid             366
                       ship station Country         United
  Station Type Code    ship         Serial Digits   910000
  Itu Series           MID 201-775  Trailing Zero   zero-ending serial -
                       individual   Notes           data/selective-call
                       series                        identity (unconfirmed
                                                    convention, not evidence)
```

A MID absent from the curated pack (97 of several hundred ITU
assignments) is an expected answer ("no country"), never a source failure —
the station-class decode still runs for any nine-digit input.

## Software packages (`obscuralens app`) *(v6.0)*

Software supply-chain intelligence for five ecosystems, addressed as
`<ecosystem>:<name>` coordinates: `pypi:requests`, `npm:lodash`,
`npm:@babel/core`, `crate:serde`, `docker:library/nginx` (or
`docker:bitnami/kafka`), `github:psf/requests`. `gather_all` runs only the
readers that match the named ecosystem — the other registry readers never
join the fan-out, so the sources status is always an honest account of what
was actually queried.

| Source | Coverage | Key |
|---|---|---|
| pack_meta | Offline ecosystem table: registry URL template, name conventions, mirror notes, namespace rules (Docker `library/` completion for official images) | none (local) |
| pypi | PyPI JSON API: version, summary, author, license, homepage, `requires_python` | none |
| npm | npm registry: description, `dist-tags.latest`, version count, maintainers, created/modified timestamps | none |
| crates | crates.io API: downloads, recent downloads (90-day window), max stable version, categories, keywords (sends a descriptive User-Agent per the crates.io API policy) | none |
| dockerhub | Docker Hub v2 repository API: pull count, star count, last update, full description excerpt | none |
| github | GitHub public repository API: stars, forks, open issues, language, SPDX license, `created_at`/`pushed_at`, archived flag, topics count | none |
| osv | OSV.dev advisory query (POST): vulnerability count and up to five advisory IDs/summaries; only runs for name-queryable ecosystems (PyPI, npm, crates.io, Docker Hub) | none |

```bash
obscuralens app pypi:requests
obscuralens app github:psf/requests --risk
```

The rule pack (`rules/packs/app.yaml`) scores supply-chain posture: known
OSV advisories (critical), archived repositories, missing licenses,
two-year-stale records, low download volume, single maintainers and thin
metadata, balanced by positive context rules for clean, documented,
actively-pushed packages.

## WiFi BSSIDs (`obscuralens bssid`) *(v6.0)*

WiFi access-point intelligence for any EUI-48 address (the kind accepts the
same formats as `mac`, but fans out to WiFi-specific sources). BSSIDs and
plain MACs share a format, so `investigate` auto-detection always prefers
`mac`; query `bssid` explicitly for the geolocation and randomization
analysis.

| Source | Coverage | Key |
|---|---|---|
| oui_vendor | Offline curated IEEE OUI pack (`obscuralens/data/oui.txt`): the AP vendor under BSSID-specific field names | none (local) |
| bssid_math | Offline EUI-48 bit decomposition: multicast/local flags, transmission and assignment classes, EUI-64 expansion, modified-EUI-64 IPv6 interface ID, `fe80::` link-local hint, privacy-randomization note | none (local) |
| mylnikov | api.mylnikov.org crowd-sourced WiFi geolocation: lat/lon, accuracy range, last observation time (0.3 s polite delay; keyless) | none |
| wigle | WiGLE.net network search: observed SSID, trilat/trilong coordinates, encryption, last-seen date | optional `wigle` |

```bash
obscuralens bssid 00:1A:2B:3C:4D:5E
```

A multicast bit set (I/G) means the address can never be an access point;
a locally-administered bit set (U/L) flags privacy-randomized or virtual
NICs, where the OUI does not identify a real vendor. mylnikov misses are
expected (the community has simply not observed the BSSID) and degrade to
"no data", never an error.

## License plates (`obscuralens plate`) *(v6.0)*

Offline license-plate format analysis. Values are free plate text with an
optional jurisdiction prefix (`DE:B-AB 1234`, `GB:AB12 CDE`, `US-CA:8ABC123`);
unprefixed plates are matched loosely against every curated format and
return a *candidate list*, never a verdict — several jurisdictions share
common shapes.

| Source | Coverage | Key |
|---|---|---|
| plate_pack | Offline curated format pack (`obscuralens/data/plate_formats.txt`, 70+ jurisdictions): prefix parsing, loose per-series matching, confidence scores (0.9 prefixed, 0.5 pattern-only, 0.4 country-only), match notes | none (local) |
| plate_math | Offline character composition analysis: letter/digit census, separators, composition note, German distinguishing-sign city table (40 entries), EU vs North-American style heuristic | none (local) |

```bash
obscuralens plate "DE:B-AB 1234"
```

The kind is fully offline (like `mmsi`/`imei`): no source ever touches the
network. Quote plate values containing spaces in shells.

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
| CINS Army | cinsscore.com score-based blocklist of currently active attackers (~15k IPs; v5.2) | none |
| blocklist.de | Aggregated abuse list: IPs that attacked mail/HTTP/SSH honeypots in the last 48 hours (~8k IPs; v5.2) | none |
| OpenPhish | OpenPhish community phishing feed — hosts extracted per URL; from the URL tracker the full URLs and hosts are matched exactly (v5.2) | none |

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
| `vin_wmi.txt` | 166 | `WMI\|Manufacturer\|Country` | vin `vin_math`, data catalog `wmi()` |
| `airlines_iata.txt` | 134 | `IATA\|ICAO\|Name\|Country\|Callsign` | flight `airline_pack`, entity extraction, data catalog `airline()` |
| `mid_codes.txt` | 97 | `MID\|Country` | mmsi `mid_pack`, data catalog `mid()` |

## Registry integrity check

The username sweep is the largest hand-maintained table in the project - 112
platform entries (101 HTML plus 11 JSON API) and three satellite tables keyed
by platform name (`EXTRACTORS`, `HTML_VERDICT_RULES`, `SOURCE_CATALOG`). Those
tables rot silently: a platform renames its profile path, an extractor is left
pointing at a platform that was removed, a spec loses its `extract` callable -
and the sweep keeps returning confident verdicts built on a rule that no longer
describes the site.

```bash
obscuralens sources check          # human-readable, exits 1 on any error
obscuralens sources check -f json  # machine-readable report
```

The check is **entirely offline** and runs nine validations:

| Check | Catches |
|---|---|
| `html_entry_shape` | entries that are not `{name, url}` with non-empty strings |
| `name_hygiene` | padded, blank or double-spaced platform names |
| `duplicates` | a platform registered twice (one entry shadows the other); case-only collisions warn |
| `url_templates` | a missing or doubled `{}` placeholder, a non-http(s) scheme, a hostless URL |
| `duplicate_urls` | two platforms sharing one profile URL |
| `api_spec_shape` | a spec missing `api_url`/`url`/`verdict`/`extract`, a non-callable `verdict`, an `err_verdicts` value the tracker will ignore |
| `cross_references` | an `EXTRACTORS` / `HTML_VERDICT_RULES` / `SOURCE_CATALOG` key naming a platform that is not registered |
| `callable_values` | a verdict rule whose signature cannot be called as `rule(username, body, low, response)` |
| `source_catalog_coverage` | catalog coverage below half the registry (warning only) |

Errors fail the build; warnings never do. `err_verdicts` is checked against how
`username_tracker` actually consumes it - an identity test on `False` - so a
`True` or non-bool value is reported as dead config rather than passing
silently.

This is the offline half of rule verification. Proving a rule still matches a
*live* site needs the network and a known-good/known-bad account pair per
platform, which is what `sources health` tracks at runtime from real traffic.

It runs as a CI step in the `sanity` job and as
`tests/test_registry_checks.py`, which asserts the shipped registry is clean
and then verifies each check still detects the defect it exists for.

## Adding your own sources

Two routes:

- **Plugins** — drop a Python file into `plugins/` and register extra
  sources for any kind with no packaging; see
  [docs/plugins.md](plugins.md).
- **Keyed services** — new API services slot into `config.SERVICES` and pick
  up the standard env-var/secrets resolution automatically.
