# Risk rule packs

ObscuraLens v5.1 adds an **explainable YAML rule engine** to complement
the built-in correlation risk scorer (`obscuralens.correlation.risk`).
Where the built-in scorer weighs technical signals in code, the rule
packs under `obscuralens/rules/packs/*.yaml` declare the same style of
OSINT heuristics as *data*: YAML you can read, audit, override and
extend without touching Python.

The contract every rule keeps: **a hit tells you why.** Each rule
carries an id, a title, a plain-language description of why the signal
matters, a severity, a weight and a list of conditions that must all
match (AND semantics). When a rule fires you get the rule's identity and
per-condition explanations against your actual field values -- not an
opaque number.

Framing that the pack headers repeat and we repeat here: these rules
describe **technical indicators, never people**. Rule text and weights
are triage aids for analysts; they are not evidence and not a verdict.

## Rule anatomy

From `obscuralens/rules/packs/domain.yaml`, lightly trimmed:

```yaml
name: domain-rules              # human pack name
description: >-                 # what this pack covers
  Explainable age, mail-security posture and reputation heuristics for
  domain name lookups.
version: 1
rules:
  - id: DOMAIN-001              # stable, pack-unique identifier
    title: Very young domain    # short headline for reports
    description: >-             # WHY the signal matters (1-3 honest sentences)
      The domain was registered within the last 30 days. Newly registered
      domains are heavily over-represented in phishing and malware
      distribution because they are cheap, unburned and unscored by
      reputation feeds. Many legitimate domains are also young, so treat
      this as one input among several.
    severity: medium            # info | low | medium | high | critical
    weight: 20                  # score contribution when the rule fires (0-100)
    tags: [age, phishing]       # free-form filter labels
    references: ["MITRE ATT&CK T1583.001"]   # real refs only; omit when unsure
    conditions:                 # ALL must match (AND semantics)
      - field: registration.age_days
        operator: lte
        value: 30
```

Field-by-field:

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | stable pack-unique identifier (`DOMAIN-001`); duplicates within a pack are dropped with a load warning |
| `title` | yes | short headline shown in reports |
| `description` | no | 1-3 honest sentences on why the signal matters -- the pack authors' rule: if you cannot say why, do not ship the rule |
| `severity` | no (default `medium`) | one of `info`, `low`, `medium`, `high`, `critical`; informational context, not the score |
| `weight` | no (default `10`) | score contribution when the rule fires; clamped to 0-100 |
| `tags` | no | free-form labels for filtering (`age`, `phishing`, `quality`, ...) |
| `references` | no | real technique/context references only (MITRE ATT&CK IDs, RFCs); omitted when the authors are unsure |
| `enabled` | no (default `true`) | `false` skips the rule during evaluation |
| `conditions` | yes | non-empty list; all must match |

## Condition operators

Every operator the engine supports (`obscuralens.rules.engine.OPERATORS`).
All evaluators are defensive: junk field values mean "no match", never an
exception. Equality and membership are case- and numeric-string-tolerant
(`"30"` equals `30`; `"RU"` equals `"ru"`).

| Operator | Example condition | Semantics |
|---|---|---|
| `eq` | `field: country` / `value: RU` | tolerant equality (direct, numeric, case-insensitive text) |
| `neq` | `field: country` / `value: RU` | negation of `eq` |
| `in` | `field: tld` / `value: [xyz, top, zip]` | field equals any listed value (tolerant) |
| `not_in` | `field: tld` / `value: [com, net, org]` | field matches none of the listed values |
| `contains` | `field: spf_record` / `value: "+all"` | substring (scalars), member (lists), or key (dicts); case-insensitive for text |
| `not_contains` | `field: redirect_chain` / `value: "login"` | negation of `contains` |
| `startswith` | `field: cve` / `value: "CVE-202"` | text prefix match |
| `endswith` | `field: domain` / `value: ".ru"` | text suffix match |
| `regex` | `field: spf_record` / `value: "v=spf1 .*\+all"` | `re.search` against the field's text; invalid patterns never match and record an evaluation warning |
| `gt` / `gte` | `field: field_count` / `value: 2` | numeric comparison; non-numeric fields do not match |
| `lt` / `lte` | `field: registration.age_days` / `value: 30` | numeric comparison, same rules |
| `exists` | `field: field_sources` | the field is present (any value, including `None`) |
| `not_exists` | `field: field_sources` | the field is absent |
| `empty` | `field: dmarc_record` | missing, `None`, blank/whitespace string, empty container, or `False`; numbers (even `0`) are real values |
| `not_empty` | `field: mx_records` | negation of `empty` |
| `is_true` | `field: dnssec` | real booleans plus the text flags `true`/`yes`/`on` |
| `is_false` | `field: success` | real `False` plus `false`/`no`/`off` |
| `in_cidr` | `field: ip` / `value: ["185.220.101.0/24"]` | the field is an IP inside any listed CIDR (v4/v6 must match); host bits in the rule value are tolerated |
| `known_pack` | `field: domain` / `value: disposable_email_domains` | the value is listed in a shipped offline data pack; for emails the domain part is checked, and subdomains of listed entries match too |
| `age_lt_days` | `field: registration.created` / `value: 30` | the field parses as a date (ISO string, epoch s/ms, common formats) and is younger than N days |
| `age_gt_days` | `field: registration.created` / `value: 3650` | the field parses as a date and is older than N days |

A missing field only matches the operators that speak about absence:
`not_exists` and `empty` (which treats "missing" as empty). Every other
operator needs a present field to say anything meaningful.

## Dotted field paths

`field: registration.age_days` walks nested dicts:
`fields['registration']['age_days']`. The walk breaks (no match) at
non-dict containers. Trackers return payloads shaped
`{'info': {...}, ...}` while username results are flat, so a path that
misses at the top level is retried as `info.<path>` -- both shapes work
with the same pack. `field_sources`, `sources_ok`, `sources_failed`,
`field_count`, `success` and `errors` (the envelope keys) are addressable
like any other field, which is how the `shared` pack scores data quality.

## Bundled packs

15 packs ship in `obscuralens/rules/packs/`, one per target kind plus the
always-evaluated `shared` pack -- **165 rules total**:

| Pack | Rules | Example rule |
|---|---|---|
| `shared.yaml` | 11 | `SHARED-001` Degraded source coverage |
| `ip.yaml` | 16 | `IP-001` Tor exit node |
| `domain.yaml` | 16 | `DOMAIN-001` Very young domain |
| `email.yaml` | 12 | `EMAIL-001` Disposable mail provider |
| `url.yaml` | 12 | `URL-001` Long redirect chain |
| `cve.yaml` | 11 | `CVE-001` Critical CVSS base score |
| `asn.yaml` | 10 | `ASN-001` Macro announcer |
| `coords.yaml` | 10 | `COORDS-001` Null Island |
| `crypto.yaml` | 10 | `CRYPTO-001` First activity within a month |
| `hash.yaml` | 10 | `HASH-001` Named malware family |
| `iban.yaml` | 10 | `IBAN-001` Structure fails ISO 13616 |
| `phone.yaml` | 10 | `PHONE-001` VoIP line |
| `username.yaml` | 10 | `USERNAME-001` Broad platform footprint |
| `imei.yaml` | 9 | `IMEI-001` Luhn check digit invalid |
| `mac.yaml` | 8 | `MAC-001` VMware virtual NIC |

The `shared` pack is kind-agnostic: `evaluate_rules()` merges it into
every kind's evaluation (itself only once), so data-quality signals --
degraded source coverage, thin enrichment, missing provenance, stale
stamps -- apply everywhere.

## Scoring

A rule that fires contributes its `weight` (clamped 0-100). The pack
score is the **sum of all matching rule weights, capped at 100**. The
band follows `band_for(score)`:

| Score | Band |
|---|---|
| 0-9 | `clean` |
| 10-29 | `watch` |
| 30-59 | `elevated` |
| 60-79 | `high` |
| 80-100 | `critical` |

These bands are deliberately *not* the built-in risk engine's verdict
bands (`clean/low/medium/high/critical` at 0-14/15-39/40-69/70-89/90+):
the two systems score different things (rule packs score declared
heuristics on one lookup's fields; the correlation scorer weighs live
signals across sources), so conflating their scales would be dishonest.
Keep them apart in your reporting.

## Python API

```python
from obscuralens.rules import evaluate_rules, load_pack, load_all_packs, rules_summary

fields = {
    'info': {
        'registration': {'age_days': 4, 'created': '2026-01-20'},
        'spf_record': 'v=spf1 include:_spf.example.com +all',
        'dmarc_record': '',
        'mx_records': [],
        'tld': 'com',
    },
    'sources_ok': 5,
    'sources_failed': 0,
    'field_count': 18,
    'success': True,
    'errors': [],
}

evaluation = evaluate_rules('domain', fields)
print(evaluation.score)          # e.g. 60
print(evaluation.band)           # 'high'
print(evaluation.summary())      # "domain: score 60 (high) via DOMAIN-002, DOMAIN-004, ..."
for hit in evaluation.hits:
    print(hit.rule.id, hit.rule.title, hit.explanations)
    # DOMAIN-004 SPF permits every sender
    #   ['spf_record contains \'+all\'', ...]
```

`evaluate_rules(kind, fields)` loads the kind's pack plus `shared`,
evaluates both, merges hits by rule id (a kind-pack rule always wins
over a shared rule reusing its id), sums the weights and derives the
band. Unknown kinds and non-dict input return a well-formed empty
evaluation; the function never raises.

The objects you get back:

| Object | Attributes / methods |
|---|---|
| `RuleEvaluation` | `.hits`, `.score` (0-100), `.band`, `.kind`, `.matched_ids`, `.summary()`, `.to_dict()` (JSON-friendly, used by report/export layers) |
| `RuleHit` | `.rule`, `.explanations` (one human string per condition), `.score` (the rule's clamped weight), `.to_dict()` |
| `Rule` | `.id`, `.kind`, `.title`, `.description`, `.severity`, `.weight`, `.conditions`, `.tags`, `.references`, `.enabled`; `.matches(fields)`, `.explain(fields)` (one string per condition, including *why it did not fire*), `.to_dict()` |
| `RulePack` | `.kind`, `.name`, `.description`, `.version`, `.rules`, `.rule_count`, `.enabled_count`; `.find(rule_id)`, `.evaluate(fields)`, `.score(fields)`, `.to_dict()` |
| `Condition` | `.field`, `.operator`, `.value`; `.render()` (compact form like `info.country == RU`), `.explain(fields)`, `.to_dict()` |

`rule.explain(fields)` is the "why did this rule not fire" tool: a
non-matching condition renders as
`registration.age_days <= 30 (actual: 4)` or `(field missing)`, so
reports can show near-misses instead of silence.

Pack-level use, with the debug summary:

```python
pack = load_pack('domain')              # -> RulePack or None
print(rules_summary())                  # one-screen table: pack, version,
                                        # rules, enabled counts + warnings
packs = load_all_packs()                # {'domain': RulePack, ...}
```

Loading is tolerant: invalid YAML yields `None`, unknown operators make
the *offending rule* (not the whole pack) be skipped, and every skip is
recorded in `LOAD_WARNINGS` (authoring bugs) or `EVAL_WARNINGS` (data
problems: invalid regex, broken CIDR literals, empty `known_pack` data
packs). `rules_summary()` surfaces the trailing warnings. Results are
cached per (directory, kind); `reset_rule_caches()` forces a reload --
mainly useful in tests and after changing `OBSCURALENS_RULES_DIR`.

## User packs and overrides

The `OBSCURALENS_RULES_DIR` environment variable redirects pack
discovery to your own directories:

```bash
export OBSCURALENS_RULES_DIR=~/my-rules                 # one directory
export OBSCURALENS_RULES_DIR=~/team-rules:~/my-rules    # several, ':'-separated
```

Resolution rules:

- Directories are searched in order; **earlier directories win**, and the
  shipped `obscuralens/rules/packs/` folder is always searched last as a
  fallback for kinds you did not override. So you can replace `ip.yaml`
  wholesale while keeping every other shipped pack.
- The lookup is per kind: `<kind>.yaml` in the first directory that has
  it. There is no partial merging of files at load time.
- YAML-level merging, when you want "the shipped pack but with my
  weights", is what `merge_pack_dicts(base, override)` is for: top-level
  keys from `override` win, rules merge by `id` (an override rule
  replaces the base rule in place; brand-new rules are appended). Neither
  input is mutated. Feed the result to YAML round-tripping or your own
  loader:

  ```python
  import yaml
  from obscuralens.rules import merge_pack_dicts

  base = yaml.safe_load(open('obscuralens/rules/packs/domain.yaml'))
  override = {'rules': [{'id': 'DOMAIN-001', 'weight': 30}]}
  merged = merge_pack_dicts(base, override)   # DOMAIN-001 re-weighted
  ```

- Disabling a rule without deleting it: set `enabled: false` on the rule
  in your overriding pack file; evaluation skips it while the rule stays
  visible (and auditable) in the YAML.

## Integration point (what exists today, honestly)

As of 5.1.0-beta.1 the rule engine is a **public library API**:
`obscuralens.rules` is importable, tested and documented, but no CLI
command, REST endpoint or shipped report template consumes it yet. The
risk blocks you see in `obscuralens risk`, `/api/risk/...` and the HTML
report builder still come from the built-in correlation risk engine;
rule packs are the complementary, analyst-editable layer you consume
programmatically.

The two real pieces that compose cleanly are `RuleEvaluation.to_dict()`
(the JSON-friendly hit/score/band mapping, built for exactly this) and
the v5.1 report renderer
(`obscuralens.reporting.template_render.render_markdown_report` /
`render_standalone_html_report`, documented in
[docs/v5.1.md](v5.1.md)). Wiring them together is a few lines:

```python
from obscuralens.rules import evaluate_rules
from obscuralens.reporting.template_render import render_markdown_report

evaluation = evaluate_rules('domain', lookup_payload)
sections = [{
    'title': 'Rule pack findings ({0}, score {1}, {2})'.format(
        evaluation.kind, evaluation.score, evaluation.band),
    'rows': [[h['id'], h['title'], h['severity'], str(h['weight'])]
             for h in evaluation.to_dict()['hits']],
    'notes': '\n'.join(
        '{0}: {1}'.format(h['id'], ' | '.join(h['explanations']))
        for h in evaluation.to_dict()['hits']),
}]
markdown = render_markdown_report(sections, {'target': 'example.com',
                                              'kind': 'domain'})
```

When a first-class integration lands (a `--rules` flag on `risk`, an API
block, a report section), it will follow the same shapes -- the dict
contract is stable -- and this section will grow the command-level
documentation. Until then: the engine is stable, the packs are data, and
your pipelines can call `evaluate_rules` exactly as above.

See [docs/data-packs.md](data-packs.md) for the offline packs that
`known_pack` conditions read, [docs/advanced.md](advanced.md) for the
built-in risk engine the packs complement, and [docs/v5.1.md](v5.1.md)
for the release notes.
