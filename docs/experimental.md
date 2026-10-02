# Experimental features

The `obscuralens/experimental/` package holds features that are useful but
not yet battle-hardened enough to promise stability:

| Module | What it does | CLI |
|---|---|---|
| `llm_summary` | LLM narrative summaries of a finished lookup | `experimental llm` |
| `username_permutations` | username variant generation + bounded sweeps | `experimental permute` |
| `web_crawler` | bounded, robots-aware same-domain crawler | `experimental crawl` |
| `phishing_score` | heuristic phishing score for a URL or domain | `experimental phish` |

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
`generate_variants` are pure functions with no gate.

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

## Stability promise

Core trackers, correlation, cases and pipelines follow semantic versioning.
The modules in this page do not: expect signals, caps, defaults and output
shapes to be tuned between minor releases. Feedback welcome — the flags and
weights above are exactly the knobs worth arguing about.
