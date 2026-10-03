# Experimental features

The `obscuralens/experimental/` package holds features that are useful but
not yet battle-hardened enough to promise stability — the v4 modules and the
v5.0 analyst toolbox (marked *(v5.0)* below):

| Module | What it does | CLI |
|---|---|---|
| `llm_summary` | LLM narrative summaries of a finished lookup | `experimental llm` |
| `username_permutations` | username variant generation + bounded sweeps | `experimental permute` |
| `web_crawler` | bounded, robots-aware same-domain crawler | `experimental crawl` |
| `phishing_score` | heuristic phishing score for a URL or domain | `experimental phish` |
| `encoders` *(v5.0)* | polyglot encode/decode workbench + all-checksums | `tools encode` / `tools decode` |
| `jwt_tools` *(v5.0)* | JWT decode + inspection, never verification | `tools jwt` |
| `hash_identify` *(v5.0)* | structural hash-format identification | `tools hash-id` |
| `entity_extract` *(v5.0)* | entity extraction + reversible redaction | `tools extract` |
| `squatting` *(v5.0)* | typosquat variant generation + risk scoring | `tools squat` |
| `exif_reader` *(v5.0)* | zero-dependency image metadata triage (local) | `tools exif` |
| `steganography` *(v5.0)* | LSB steganalysis + entropy + carving (local) | `tools stego` |

**These are experimental and may change or be removed in any release.**
They are covered by tests, but their output shape, config keys and CLI
surface should not be relied upon the way the core trackers are.

## Master switch

All `experimental` subcommands refuse to run unless the master switch is on:

```yaml
app:
  experimental_features: true   # default: true
```

Set it to `false` to disable the whole surface in one place (the command
then exits with code 2 and a clear message). Programmatically, the gate
lives inside `summarize`, `scan_variants` and `crawl`; `phishing_score` and
`generate_variants` are pure functions with no gate. The v5.0 `tools`
commands refuse to run under the same master switch.

## LLM narrative summaries

Turns a finished tracker payload into a short analyst narrative via **any
OpenAI-compatible `/chat/completions` endpoint** — OpenAI itself, LM Studio,
Ollama's OpenAI shim, vLLM, and so on. The payload is compacted first (the
target line, the top facts with list caps, which sources answered and which
failed), then sent with a system prompt that demands a factual, four-section
answer: *Summary / Key findings / Confidence / Suggested next steps*.

### Configuration

```yaml
app:
  llm_base_url: https://api.openai.com/v1   # any OpenAI-compatible base
  llm_model: gpt-4o-mini
```

```powershell
$env:OBSCURALENS_LLM_API_KEY = "your_key"
```

The key resolves like every other service (env var → `secrets.yaml` →
`config.yaml`). Request parameters: temperature 0.2, max 700 tokens — tuned
for cheap summarisation, not creativity.

### Usage

```powershell
obscuralens experimental llm domain example.com
obscuralens experimental llm ip 45.148.10.99 -f json
obscuralens experimental llm auto alice@example.com      # detect the kind
obscuralens investigate example.com --llm                # appended section
```

### Privacy — read this first

**Enabling this feature sends investigation data off your machine** to
whichever endpoint you configure. The compacted payload contains the target
and the merged lookup facts. If that is unacceptable for your case:

- point `llm_base_url` at a local model (Ollama, LM Studio, vLLM) so nothing
  leaves the host, or
- leave the feature unconfigured (`summarize` refuses to run without a base
  URL and key).

### Honest limitations

- The summary is only as good as the model; LLMs can hallucinate. Treat it
  as a narrative *draft* over data you can verify in the JSON payload —
  every claim should trace back to a field.
- Costs and rate limits are the provider's; the request goes through the
  shared HTTP client (timeouts, proxy, metrics) but is never cached.
- Errors are returned, never raised: a broken endpoint degrades to an
  explanatory error section, not a crash.

## Username permutations

Generates plausible variants of a username and optionally sweeps them
across the **same platform registry and verdict logic** the production
username tracker uses (`UsernameTracker._check_platform`), so permutation
hits and normal hits are directly comparable.

### Generation rules

Variants are deterministic, deduplicated and ordered by plausibility
(exact form first):

- the sanitised input itself (lowercased, `[a-z0-9._-]` only, 3–30 chars)
  plus one uppercase form;
- full leet (`a→4 e→3 i→1 o→0 s→5`) and single leet swaps (`s→5`, `o→0`);
- suffixes: `.` `_` `-` `123` `1234` `01` `007` `x` `xx` `official` `real`
  `the` `its` `im` `hi`;
- year suffixes: 1990–2006 and 2020–2025;
- prefixes: `real` `the` `its` `im` `iam` `mr` `dr`;
- doubled forms (`johndoejohndoe`).

The cap defaults to `app.permutation_max_candidates` (48); `--max`
overrides per run.

### Scanning (politeness and caps)

```powershell
obscuralens experimental permute johndoe              # just generate
obscuralens experimental permute johndoe --max 20
obscuralens experimental permute johndoe --scan       # sweep platforms
obscuralens experimental permute johndoe --scan --platforms 3 -f json
```

- Scans run against the first `app.permutation_platforms` (default 5) **HTML
  platforms** — the sweep deliberately keeps its blast radius small.
- A polite pause (`~0.4s` before jitter) is slept between *every* request.
- There is a **hard cap of 60 requests** per run (variants × platforms).
  With the default 48 variants × 5 platforms, only the ~12 most relevant
  variants are actually checked — raise the caps consciously, not casually.
- The tracker's `unknown` verdict (bot walls, JS shells) is reported as
  status `error` with the reason preserved: a sweep cannot confirm anything
  from a bot wall, and it is never counted as a hit.

### Honest limitations

- Generation is generic English-centric heuristics; it knows nothing about
  the target's actual naming habits.
- Platform coverage is a fixed slice of the HTML registry; permutation
  sweeps are not a substitute for a per-platform deep scan.
- A "found" variant is a *lead* — same caveat as every username result:
  platform squatting is common.

## Web crawler

A polite BFS crawler that stays on the start host and records what it saw
per page: status, title, content type, server header, same-host links,
external links, e-mail addresses and technology hints (`X-Powered-By`,
generator meta tag, `wp-content` / `cdn-cgi` markers).

### Bounds and politeness

| Bound | Config default | Flag |
|---|---|---|
| Link-hop depth | `app.crawler_max_depth` = 2 | `--depth` |
| Total pages | `app.crawler_max_pages` = 20 | `--max-pages` |
| Delay between fetches | `app.crawler_delay` = 1.0s (jittered) | `--delay` |

- **Same-host only**: links off the start host (ignoring `www.`) are
  recorded as external links, never fetched. Redirects that leave the host
  cannot widen the crawl either.
- **robots.txt compliance**: robots.txt is fetched once and honoured for a
  subset of the spec — `User-agent` groups (matching `*` or the
  `obscuralens` token), `Disallow` prefix rules with `*` wildcards and `$`
  end anchors; `Allow` lines are ignored. `--ignore-robots` skips the check
  entirely (use only on targets you are authorised to crawl).
- Bodies larger than 1 MB are truncated before parsing; external domains
  are capped at 30, e-mail addresses at 50.

### Usage

```powershell
obscuralens experimental crawl https://example.com
obscuralens experimental crawl https://example.com --depth 3 --max-pages 10
obscuralens experimental crawl https://example.com --delay 2.5 -f json
```

### Honest limitations

- Link extraction is regex-based, not a DOM parser — links rendered only
  by JavaScript are invisible, and malformed HTML can hide real links.
- It fetches pages; it does not execute them, take screenshots or handle
  login walls.
- The robots subset is deliberately small (no `Allow`, no crawl-delay
  parsing) — when in doubt, slow down and stay shallow.

## Phishing score

A heuristic score (0–100) for a URL or domain, computed **fully offline**
from two shipped data packs: `phishing_keywords` (629 keywords) and
`popular_domains` (335 domains). Verdicts: `benign` < 20,
`suspicious` < 50, `likely-phishing` ≥ 50.

### Signal reference

| Signal | Points | Fires when |
|---|---|---|
| `double_extension` | +35 | path ends in an executable double extension (`invoice.pdf.exe`) |
| `brand_token` | +30 | a popular domain's brand label appears in the host under a different registered domain (`paypal.login.example-secure.com`) |
| `punycode` | +30 | host contains an `xn--` label |
| `typosquat` | +25 | host within Levenshtein distance ≤ 2 of a popular domain (`goggle.com`) |
| `userinfo` | +25 | URL carries `user@host` credentials (URL targets only) |
| `ip_host` | +20 | host is a raw IP literal |
| `https_in_host` | +15 | the string `https` appears inside the hostname |
| `keyword` | +12 each (cap 3) | phishing keyword in host / path / query |
| `risky_tld` | +10 | TLD in a risky set (zip, mov, top, xyz, click, tk, ml, cf, …) |
| `young_domain` | +10 | creation date < 30 days ago (needs a date passed programmatically via `fields=`) |
| `odd_port` | +8 | non-standard port |
| `subdomain_depth` | +8 | ≥ 4 labels under the registered domain |
| `hyphens` | +8 | ≥ 3 hyphens in the host |
| `digits` | +6 | ≥ 3 digits in the host |
| `long_host` | +6 | host ≥ 40 characters |
| `long_url` | +5 | URL ≥ 100 characters |

### Usage

```powershell
obscuralens experimental phish https://secure-login.example-verify.com/
obscuralens experimental phish goggle.com -f json
```

Every reason row (`{'id', 'points', 'detail'}`) names the values that fired
it, so a score is always explainable.

### Honest limitations

- It is a lexical heuristic — no live phishing-database lookups (no
  Google Safe Browsing, no PhishTank); combine it with `obscuralens url
  --risk` for verdict-based signals.
- The registered domain is approximated as the last two labels (no public
  suffix list), so `co.uk`-style hosts under-count subdomain depth.
- Benign sites can score points (long hosts, keyword collisions); a score
  is a triage hint, never a blocklist verdict.

## Toolbox (v5.0)

Seven local-first utilities, wired to `obscuralens tools …`, the web UI's
Tools view, `/api/tools/*` and MCP. Everything runs offline unless noted.

### Encoders and decoders

A polyglot workbench for mysterious strings — phishing URL parameters,
webhook payloads, CTF fragments, tokens pasted into chats.

```powershell
obscuralens tools encode "admin:password"
# hex           61646d696e3a70617373776f7264
# base64        YWRtaW46cGFzc3dvcmQ=
# rot13         nqzva:cnffjbeq
# morse         .- -.. -- .. -. .--. .- ... ... .-- --- .-. -.. …
# …one row per scheme, plus the digest table (md5, sha1, …)
obscuralens tools encode "admin:password" --scheme base64
obscuralens tools decode aGVsbG8gSlNPTg==            # auto-rank every scheme
obscuralens tools decode 68656c6c6f --scheme hex     # one chosen scheme
```

- **`encode_all(text)`** — one input encoded through every scheme at once
  (CLI default; `--scheme NAME` restricts to one). Canonical scheme names:
  `hex`, `base32`, `base64`, `base85`, `url_percent`, `html_entity`,
  `rot13`, `caesar`, `binary`, `decimal`, `reversed`, `morse`, `gzip`.
  Schemes that cannot encode the input are silently skipped.
- **`decode_auto(value)`** — the "magic decoder": every scheme tries, only
  candidates decoding to ≥ 90 % printable text survive, each is scored
  (printability, letter ratio, embedded common-English words) and the list
  comes back best-first as
  `{'scheme', 'result', 'score': 0-100, 'note'}`, capped at 24 candidates.
  A note flags "output identical to input" no-op decodes as weak evidence.
- **`hash_all(text)`** — every standard digest at once (md5, sha1, sha224,
  sha256, sha384, sha512, sha3_256, sha3_512, blake2s, blake2b, crc32) —
  paste-ready for hash-lookup services.
- Parameterised helpers live in the Python module: `caesar_encode/decode`
  (any shift) and `xor_key_encode/decode`. **XOR is encoding obfuscation,
  not encryption** — it exists for CTF triage and spotting trivially
  obfuscated exfiltration, and is labelled as such.

Honest limitations: the readability heuristic is English-centric; a valid
non-English decode can score below gibberish. Decode candidates are ranked
guesses, not identifications — always confirm the winner by re-encoding.

### JWT inspection

Splits a compact JWS token (`header.payload.signature`) apart, decodes the
base64url segments and adds analyst notes: claim timelines (`iat`/`nbf`/
`exp` with human datetimes and expiry verdicts), algorithm risk (`alg:
none` is flagged CRITICAL; `jku`/`x5u` header URLs are called out as
key-confusion/SSRF surfaces), key-material hints (`kid`, `x5c` chain) and
token size statistics.

```powershell
obscuralens tools jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIx…
# header    {'alg': 'HS256', 'typ': 'JWT'}
# payload   {'sub': '1234567890', 'name': '…', 'iat': 1516239022}
# claims    exp: 2027-11-01T… (valid) · iat: 2018-01-18T…
# notes     signature is 32 byte(s) - HS256 sized …
```

**No signature verification is attempted — by design.** Verifying an
asymmetric JWT needs the signer's public key; verifying a symmetric one
needs the shared secret; an analyst rarely holds either. Half-verified
tokens are worse than openly-unverified ones, so the module only *decodes
and describes*, and every result carries the standing reminder: **unsigned
claims are untrusted claims** — treat the payload as attacker-controlled
data until the signature is verified with real key material.

### Hash format identification

Paste an opaque digest (breach dump, malware config, database row) and get
the candidate algorithms it could be, ranked by confidence:

```powershell
obscuralens tools hash-id 5d41402abc4b2a76b9719d911017c592
# name        confidence  note
# MD5         high        32 hex characters …
# MD4         medium      same size family …
# NTLM        medium      …
obscuralens tools hash-id $2b$12$KIXQ…
# bcrypt      high        cost factor 12 (strong) …
```

- **`identify_hash(value)`** returns
  `[{'name', 'confidence', 'length', 'charset', 'note'}]`, high → medium →
  low. Recognised shapes: hex digests (8/16/32/40/56/64/96/128 chars),
  base64-armored digests, bcrypt (`$2a$/$2b$/$2y$`, cost extracted),
  Argon2 PHC strings (variant, memory, time, lanes parsed), MySQL 4.1+
  (`*` + 40 hex) and raw JWT compact serializations (redirected to
  `jwt_tools`).
- Detection is **structural only**: length + charset + prefix markers. Two
  algorithms sharing a digest length cannot be split, so same-length
  alternatives are listed at medium confidence with notes — most notably
  the **Keccak-256 trap**: 64 hex characters are *not* necessarily SHA-256;
  Ethereum/EVM hashing uses original-padding Keccak, and assuming SHA-256
  there has burned many an analyst.
- **`checksum_matches(value, candidates)`** is a tiny offline wordlist
  matcher: is this digest the md5/sha1/sha2 of any of these candidate
  plaintexts? (capped at 10 000 candidates, six algorithms). Password-hash
  triage for small lists — not a cracker.

### Entity extraction

Paste an email body, forum post, paste-dump entry or threat-report
paragraph and pull every OSINT pivot target out of it. The pipeline is
**validator-driven**: a regex proposes, the shared `utils.validators`
module disposes — mod-97 for IBANs, Luhn for IMEIs, shape rules for crypto
addresses, range checks for coordinates. The same verdict logic as the
production trackers, not a second drifting copy.

```powershell
obscuralens tools extract "Contact bob@evil.example from 45.148.10.99,
see https://evil.example/login (CVE-2021-44228, BTC 1A1zP1…)"
obscuralens tools extract --file pasted-report.txt
Get-Content leak.txt | obscuralens tools extract --stdin
# emails   [bob@evil.example]
# urls     [https://evil.example/login]
# domains  [evil.example]
# ipv4     [45.148.10.99]
# cves     [CVE-2021-44228]
# crypto_addresses [1A1zP1…]
# …
```

Two-phase design: **strong entities** (emails, URLs, IPs, MACs, IBANs,
IMEIs, crypto, hashes, CVEs, coords, ASNs) are extracted first and masked
out of the working text, so a 15-digit IMEI can never double-report as a
tracking number or phone; **weak candidates** (`phone_candidates`,
`user_handles`, `tracking_ids`) run against the leftovers and are labelled
as leads to verify, not confirmed entities. Domains are scanned against the
original text so hosts inside URLs and emails also count. Every list is
de-duplicated, order-preserving and capped at 50 entries.

`redact_entities(text)` / `redact_with_map(text, kinds)` turn the same
pipeline into a safe-sharing formatter: entities become numbered
placeholders (`[EMAIL #1]`) and the reversible mapping comes back to the
caller — the analyst's private decode table, kept out of the shared
document.

### Typosquat generation

A pure-Python, fully offline re-implementation of the variant families
that made dnstwist the standard tool for domain-defence triage:

```powershell
obscuralens tools squat example.com
# Domain          Category        Risk  Description
# exmaple.com     transposition    94    adjacent letters swapped
# exanple.com     substitution     91    keyboard-adjacent key slip
# example.co      tld_swap         88    different registry …
# …
obscuralens tools squat example.com --min-risk 80     # dangerous first
obscuralens tools squat example.com --category homoglyph
```

- **`generate_variants(domain)`** — fifteen families in a fixed order
  (omission, insertion, substitution, transposition, duplication,
  hyphenation, subdomain, vowel swap, plural, singular, bitsquat,
  homoglyph, ASCII lookalike, TLD swap, combo-squat), each entry
  `{'domain', 'category', 'description'}`; de-duplicated, original
  excluded, capped at 300 variants. URLs are tolerated (scheme/path
  stripped); the registrable core (last two labels) is what mutates.
- **`score_variants(variants, original)`** — adds a 0–100 deception-risk
  score and sorts descending: Damerau-Levenshtein distance from the
  original sets the base (distance 1 → 88, 2 → 74 …), category bonuses
  reward hard-to-spot families (homoglyph +22, bitsquat +18, ASCII +18,
  combo-squat +16, subdomain +14 …) and a `phishing_keywords` pack hit
  adds +8. The full rubric (distance bases, category bonuses, keyword
  bonus) is documented in the module so every score is auditable.
- The list is a **watch list**: feed it to domain registration checks
  (RDAP), passive DNS or the domain tracker to see which lookalikes
  actually resolve. Nothing here proves registration — it ranks what to
  check first.

### EXIF reader — local image metadata triage

Parses JPEG (APP0 JFIF, APP1 EXIF + XMP, APP2 ICC, APP13 Photoshop,
COM comments), PNG (tEXt/zTXt/iTXt/tIME/eXIf with CRC verification), GIF,
BMP and WebP containers **straight from the byte stream using only the
Python standard library** — no Pillow, no exiftool, no network.

```powershell
obscuralens tools exif IMG_2031.jpg
# format     jpeg · 4032×3024 · 2.4 MB
# camera     Apple iPhone 13 Pro (lens: …)
# gps        48.8584, 2.2945  (ready for `obscuralens coords`)
# timeline   2024-06-01T14:32:08 (original) · …
# osint_notes GPS coordinates present; camera timezone offset +02:00
#             suggests the camera clock was set to UTC+2 …
```

`analyze(path_or_bytes)` combines the container metadata with friendly
EXIF, GPS (decimal + DMS + a `lat, lon` string ready for the coords
tracker), a camera summary, timeline hints, interesting strings, file
hashes (md5/sha256) and actionable `osint_notes`. Malformed or truncated
files never raise: you get `{'error': …, 'parsed': …}` partials.
`read_metadata` returns the raw format-specific dict; `strings_report`
extracts embedded ASCII/UTF-16LE strings.

**Privacy framing.** This module is a core reason ObscuraLens can promise
that image triage runs locally and nothing leaves your machine: EXIF
blocks carry GPS coordinates, device serials, owner names and editing
history — precisely the data you should never paste into a random online
EXIF-lookup site. Everything here is parsed in-process.

### Steganography analysis — local LSB steganalysis

Pure-standard-library spatial-domain steganalysis:

```powershell
obscuralens tools stego suspicious.png
# format    png
# suspicion 71.3 / 100
# verdict   highly suspicious
# findings  · LSB: chi-square pair imbalance in plane 0 (r channel)
#           · trailing data: 4 813 bytes after IEND
#           · embedded ZIP blob at offset 0x9c40 …
```

- **PNG** — full chunk walk, IDAT re-inflation and a correct scanline
  unfilter (None/Sub/Up/Average/Paeth), per-channel LSB bit-plane
  statistics for planes 0–3 (run lengths, chi-square pair tests, entropy)
  and a weighted 0–100 suspicion score per plane.
- **BMP** — 24/32-bit bottom-up pixel walk honouring row padding.
- **GIF** — a complete LZW decoder (clear-code aware) so palette-index
  LSBs can be analyzed per frame.
- **Every format** — byte-entropy profiling (Shannon histogram + 64
  sliding windows + high-entropy blob detection) and signature carving
  for embedded ZIP / RAR / 7z / PDF / JPEG / PNG / gzip / ELF / PE /
  SQLite / RIFF blobs, plus trailing-data-after-IEND/EOI detection.

`analyze(path_or_bytes)` returns
`{'format', 'summary': {'suspicion', 'verdict', 'findings'}, 'lsb',
'entropy', 'embedded_files', 'strings'}`. Verdict bands: `clean` < 35,
`suspicious` < 65, `highly suspicious` ≥ 65; the scoring rubric
(`SUSPICION_WEIGHTS`) is exported so every verdict is auditable.

**Privacy framing.** All analysis runs locally, nothing leaves your
machine — stego detection is exactly the task people otherwise paste into
online "stego detector" sites, leaking the very evidence under
investigation. The module never touches the network.

**JPEG note.** DCT-domain stego (jsteg / F5 / outguess class) is out of
scope; for JPEG the module still runs entropy, carving and trailing-data
checks and says so in the findings.

## Stability promise

Core trackers, correlation, cases and pipelines follow semantic versioning.
The modules in this page do not: expect signals, caps, defaults and output
shapes to be tuned between minor releases. Feedback welcome — the flags and
weights above are exactly the knobs worth arguing about.
