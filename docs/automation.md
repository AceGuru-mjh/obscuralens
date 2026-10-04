# ObscuraLens automation & sharing

v6.0 Part 4 turns the platform from a console you sit at into an
investigation that runs itself and shares what it finds. Four pieces, all
pure standard library, all local-first: a **notification centre** with five
channel protocols (webhook, Telegram, Discord, Slack, SMTP) and per-channel
filters (event subscriptions, severity floors, quiet hours, dedup); a
**task scheduler** with interval/daily/weekly schedules and five executor
actions; **STIX 2.1 / MISP core-format exports** that turn any stored
lookup into a shareable threat-intel document with deterministic ids; and
two new **pipeline steps** (`notify` / `export`) that wire both into the
YAML pipeline engine. Nothing leaves the machine until you configure a
channel or write an export — the module ships with zero channels, zero
tasks and zero published documents.

## Contents

- [Notification channels](#notification-channels)
- [CLI usage](#cli-usage)
- [Scheduler semantics](#scheduler-semantics)
- [Web API](#web-api)
- [MCP tools](#mcp-tools)
- [Pipeline steps](#pipeline-steps)
- [STIX 2.1 export](#stix-21-export)
- [MISP export](#misp-export)
- [Security notes](#security-notes)

## Notification channels

A channel is one delivery pipe with a unique name. Channels live in
`notifications.json` beside the SQLite database (the same convention as
`alerts.json`), edited through the `notify` CLI, the web API or an MCP
client — never by hand.

| type | `target` syntax | what leaves the machine |
|---|---|---|
| `webhook` | URL, e.g. `https://hooks.example/x` | one JSON POST: `{event, title, body, severity, fields, ts}` |
| `telegram` | `bot_token:chat_id` (split on the *first* colon) | Bot API `sendMessage` |
| `discord` | incoming webhook URL | `**[severity] title**` + body, clipped to 2000 chars |
| `slack` | incoming webhook URL | `*[severity] title*` + body |
| `smtp` | `host:port:from:to[:user:pass]` | UTF-8 `text/plain` mail via `smtplib` |

Every channel carries the same four filters, applied in order inside
`send()`:

| filter | shape | effect |
|---|---|---|
| `events` | comma list, e.g. `lookup,watch_diff` | empty = subscribed to everything |
| `min_severity` | `info` < `low` < `medium` < `high` < `critical` | events below the floor are skipped |
| `quiet_hours` | local hour pair, e.g. `22-07` | no deliveries inside the window (wraps past midnight) |
| dedup | 5-minute window over the `dedup_key` recipe (`event`, `title` or `event+title`; unset disables it) | an identical message is not re-sent |

One channel per protocol, registered with `notify add`:

```bash
# generic webhook for the collector that archives everything
obscuralens notify add --type webhook --name archive \
    --target https://hooks.example/collect \
    --note 'evidence archive, no filters'

# Telegram: the phone in your pocket, only real alerts, silent at night
obscuralens notify add --type telegram --name oncall-phone \
    --target '123456:AAEf…bot_token:chat_id' \
    --events watch_diff,risk_high --min-severity high \
    --quiet-hours 22-07

# Discord / Slack incoming webhooks for the team channels
obscuralens notify add --type discord --name soc-channel \
    --target https://discord.com/api/webhooks/… \
    --min-severity medium --dedup-key event+title
obscuralens notify add --type slack --name case-room \
    --target https://hooks.slack.com/services/… \
    --events pipeline

# SMTP gateway for the audit mailbox (credentials optional)
obscuralens notify add --type smtp --name audit-mail \
    --target 'smtp.example:587:obscuralens@example:audit@example:user:pass' \
    --note 'immutable audit trail'
```

The `target` may be **empty** for telegram/discord/slack/smtp when the
matching global key is configured — then the channel is nothing but a
name plus filters, and the secret lives in one place (see
[Security notes](#security-notes)).

Managing and probing channels:

```bash
obscuralens notify channels                 # table: name/type/target/filters/last sent
obscuralens notify channels -f json         # {count, channels, channel_types, severities}
obscuralens notify test oncall-phone        # one-off probe, bypasses all filters
obscuralens notify remove soc-channel       # delete (delivery history stays behind)
obscuralens notify recent --limit 20        # the last 100 sends/failures/skips
obscuralens notify broadcast --title 'Watch diff' \
    --body 'example.com changed registrar' --severity high \
    --event-type watch_diff                 # fan out to every channel
```

`notify recent` is the audit trail: every send, failure and filter-skip is
recorded (channel, event, severity, title, delivery status, UTC timestamp),
so "did the on-call get paged?" is a query, not a guess.

## CLI usage

The `automation` command group manages the scheduler. Every subcommand
takes `-f json` for machine-readable output and `-o FILE` to write it
somewhere else.

```bash
obscuralens automation tasks                # table: name/action/schedule/next/runs/errors/enabled
obscuralens automation add --name nightly-watch --action watch_check \
    --daily --at 09:00                      # every morning at 09:00 local
obscuralens automation add --name vip-domain --action pipeline \
    --interval 3600 --params '{"name": "vip-domain-monitor"}'
obscuralens automation add --name monday-brief --action report \
    --weekly --weekday 0 --at 08:30 \
    --params '{"title": "Monday intel brief"}'
obscuralens automation run monday-brief     # execute now, ignore the schedule
obscuralens automation run-due              # run everything due (what the loop does)
obscuralens automation next                 # stored + recomputed next_run per task
obscuralens automation remove nightly-watch
obscuralens automation start --interval 30  # foreground tick loop, Ctrl+C to stop
```

Example `automation tasks` output:

```
SCHEDULED TASKS
Name          Action       Schedule        Next Run            Runs  Errors  Enabled
nightly-watch watch_check  daily 09:00     2025-06-02T09:00:00 14    0       yes
vip-domain    pipeline     every 3600s     2025-06-01T21:30:00 168   2       yes
monday-brief  report       weekly 08:30 wd0 2025-06-02T08:30:00 9     0       yes
```

`automation add --action` picks the executor (see the table below);
`--params` passes it a JSON payload. `--interval N` (seconds),
`--daily --at HH:MM` and `--weekly --weekday N --at HH:MM` are mutually
exclusive schedule shapes; `--disabled` registers the task switched off.

## Scheduler semantics

Schedules are pure functions over **local wall-clock time** — `at_time`
means "09:00 where the analyst sits", exactly like a cron line.

| schedule | next run |
|---|---|
| `interval` (`interval_seconds`) | `now + N seconds` |
| `daily` (`at_time` `HH:MM`) | the next occurrence of `HH:MM`; today's slot already passed (or is exactly now) → tomorrow |
| `weekly` (`weekday` 0=Monday…6=Sunday, `at_time`) | the next occurrence of that weekday at `HH:MM`; today counts only while the slot is still ahead |

Task state persists in `scheduler.json` beside the SQLite database, with
atomic write-then-rename and a self-healing read: a corrupt or
hand-edited `next_run` is recomputed from the task's schedule instead of
silently killing the task. `run_due()` runs everything whose `next_run`
has arrived, then persists `last_run`, `run_count`, `error_count`,
`last_error` and a fresh `next_run` **anchored to the due-check moment**
(so slow tasks never skip a slot they already earned). `run_task()` —
used by `automation run`, the web API and MCP — executes immediately and
deliberately leaves the bookkeeping alone, so manual runs cannot corrupt
the cron state.

Five executor actions ship today:

| action | `params` | what it does |
|---|---|---|
| `watch_check` | optional `target`/`identifier` | re-run watchlist checks (all entries, or one) and count first snapshots / diffs / failures |
| `pipeline` | `spec` (inline), or `path`/`name` | execute a YAML pipeline via `run_pipeline` (name resolves inside `app.pipeline_dir`, `.yaml`/`.yml` tried) |
| `report` | optional `limit`, `title` | render a markdown dossier of the query history into `reports/` as `scheduled-<task>-<stamp>.md` |
| `feed_refresh` | optional `feeds` list | force-refresh the threat-intel blocklist feeds and report cached totals |
| `notify_test` | `channel` | probe one notification channel (the same call as `notify test`) |

Every executor is individually try/except-wrapped: a broken pipeline, a
dead webhook or an unwritable report directory surfaces as `error` in the
result, never as an exception into the loop.

**The tick loop.** `automation start` runs the loop in the *foreground*
— one catch-up iteration immediately (so start-up collects overdue
tasks), then every `--interval` seconds (default 30, clamped to at least
0.5). Ctrl+C exits cleanly; a supervisor (systemd, docker, tmux) owns the
lifecycle exactly like `obscuralens serve`. The web UI and MCP use the
same engine through the idempotent daemon thread instead
(`start_background()` returns the existing live thread on a second call
— no duplicate loops, no doubled notifications).

## Web API

Every automation surface is also a REST endpoint (JSON bodies, same
validation reasons as the CLI in `detail`):

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/notify/channels` | — | `{count, channels, channel_types, severities}` |
| POST | `/api/notify/channels` | channel spec `{name, type, target, events, min_severity, quiet_hours, …}` | `{ok, channel}` (400 on a rejected spec) |
| DELETE | `/api/notify/channels/{name}` | — | `{ok, removed}` (404 unknown) |
| POST | `/api/notify/channels/{name}/test` | — | the test receipt `{ok, channel, error}` (404 unknown) |
| GET | `/api/notify/recent?limit=20` | — | `{count, recent}` |
| POST | `/api/notify/broadcast` | `{title, body, severity, event_type}` | `{sent, failed, skipped, total, results}` |
| GET | `/api/automation/tasks` | — | `{count, tasks, actions, schedule_types}` |
| POST | `/api/automation/tasks` | task spec `{name, action, schedule, at_time, params, …}` | `{ok, task}` (400 rejected) |
| DELETE | `/api/automation/tasks/{name}` | — | `{ok, removed}` (404 unknown) |
| POST | `/api/automation/tasks/{name}/run` | — | the run receipt `{ok, started, finished, error, summary}` |
| POST | `/api/automation/run-due` | — | `{ran, results}` |
| GET | `/api/automation/next` | — | `{count, tasks: [{stored_next_run, recomputed_next_run, …}]}` |
| GET | `/api/export/stix/{kind}/{target}` | — | a STIX 2.1 bundle (404 without a stored lookup) |
| GET | `/api/export/misp/{kind}/{target}` | — | a MISP core-format event (404 without a stored lookup) |

```bash
curl -X POST http://127.0.0.1:8000/api/automation/tasks \
     -H "Content-Type: application/json" \
     -d '{"name": "nightly-watch", "action": "watch_check",
          "schedule": "daily", "at_time": "09:00"}'
curl -X POST http://127.0.0.1:8000/api/notify/broadcast \
     -H "Content-Type: application/json" \
     -d '{"title": "Escalation", "body": "risk crossed 80", "severity": "high"}'
curl http://127.0.0.1:8000/api/export/stix/ip/8.8.8.8
```

The export endpoints describe **the newest stored lookup** of that
kind/target — exports match what the analyst saw, they never re-run a
tracker or touch the network.

## MCP tools

Five MCP tools expose the same surfaces to an LLM assistant:

| tool | input | what it does |
|---|---|---|
| `notify_channels` | — | list channels + the protocol vocabularies (local state only) |
| `notify_broadcast` | `{title, body, severity?, event_type?}` | fan one event out to every channel (the only network-talking tool here) |
| `automation_tasks` | — | list tasks with schedules and health counters (nothing executes) |
| `automation_run_due` | — | run every due task and persist the bookkeeping; failures appear per-task, never fail the call |
| `export_stix` | `{kind, target}` | build a STIX 2.1 bundle from the newest stored lookup of the target |

## Pipeline steps

Two new YAML pipeline steps wire sharing into the run itself:

```yaml
name: vip-domain-monitor
steps:
  - lookup:
      kind: domain
      target: $domain
  - risk: true
  - notify:                      # v6.0 part 4: fan out to channels
      title: VIP domain risk escalation
      body: $domain crossed the risk threshold.
      severity: high             # info (default) .. critical
      event_type: watch_diff     # what channels subscribe to (default: pipeline)
  - export:                      # v6.0 part 4: STIX/MISP from the last lookup
      format: stix               # stix | misp (required)
      kind: domain               # optional overrides (default: last lookup)
      target: $domain
      path: vip-$domain-stix.json   # relative paths land under report_dir
```

`- notify: true` (the bare shorthand) broadcasts the run's own summary —
step count, lookups, findings, errors — as an info-severity `pipeline`
event. Per-channel filters apply inside `broadcast`, so a pipeline is a
well-behaved citizen of the quiet-hours/dedup contract. The `export` step
exports the run's **last lookup** (a re-lookup of the same kind
overwrites in place and stays "last"); without `path` the document is
returned inside the step's `output.document` for the caller to consume.
Eight shipped examples live in `pipelines/examples/` — including
`vip-domain-monitor.yaml` (STIX) and `phishing-response-misp.yaml`
(MISP + notify escalation).

## STIX 2.1 export

`obscuralens export stix <kind> <target>` (or `GET /api/export/stix/…`)
turns the newest stored lookup into a self-contained STIX 2.1 bundle —
generated as pure JSON, never schema-validated, so it drops into any
STIX-aware platform:

| object | role |
|---|---|
| `identity` | the fixed ObscuraLens organization SDO every bundle shares |
| `indicator` | the target as a pattern-bearing SDO (default subject) |
| `vulnerability` | the subject for `cve` lookups instead of an indicator |
| `observed-data` | the evidence: the standard observable (when the kind maps) plus an `x-obscuralens` custom object carrying **every** `info` field (capped at 200 keys) with an `x_provenance` block |
| `relationship` | a `related-to` SRO wiring subject → observed data |
| `note` | human-readable provenance: sources OK/failed, field counts, errors |

Kind mapping highlights: `ip` → `[ipv4-addr:value = '…']` (or
`ipv6-addr`), `domain`/`url`/`email`/`mac` map to their STIX observables,
`hash` picks `SHA-256`/`SHA-1`/`MD5` by digest length, `username` →
`user-account:user_id`. STIX has no phone, crypto-address or
vehicle/vessel observables, so those kinds use the `x-obscuralens:`
custom-extension prefix that STIX 2.1 explicitly permits — consumers that
do not know the extension see an opaque custom pattern instead of a
broken document.

**Deterministic ids**: every object id is a UUIDv5 of
`obscuralens-stix-<type>-<seed>` under the URL namespace, so re-exporting
the same indicator yields byte-identical ids — re-imports **merge** on
TAXII stores and SIEM feeds instead of duplicating.

```json
{
  "type": "bundle",
  "id": "bundle--c0ffee00-…",
  "objects": [
    {"type": "identity", "name": "ObscuraLens", "identity_class": "organization", "…": "…"},
    {"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.8.8']",
     "pattern_type": "stix", "labels": ["obscuralens", "ip"], "…": "…"},
    {"type": "observed-data", "number_observed": 1,
     "objects": {"0": {"type": "ipv4-addr", "value": "8.8.8.8"},
                 "1": {"type": "x-obscuralens", "kind": "ip",
                       "value": "8.8.8.8", "country": "US",
                       "x_provenance": {"sources_ok": ["ipapi", "rdap"],
                                        "field_count": 3, "success": true}}},
     "…": "…"},
    {"type": "relationship", "relationship_type": "related-to", "…": "…"},
    {"type": "note", "abstract": "ObscuraLens provenance",
     "content": "ObscuraLens provenance for ip 8.8.8.8:\n- Result: success\n- Fields: 3 from 2 source(s)\n- Sources OK: ipapi, rdap", "…": "…"}
  ]
}
```

Write it to a file with `-o` (`dump_bundle` pretty-prints UTF-8 and
returns an `{ok, path, bytes}` receipt); the `export` pipeline step uses
the same builder.

## MISP export

`obscuralens export misp <kind> <target>` produces a **MISP core format**
event — the JSON shape MISP itself accepts on import:

| ObscuraLens | MISP |
|---|---|
| the lookup | one `Event` (id, info headline, date, threat_level_id, analysis `0`, published `false`, orgc, Tag `obscuralens:<kind>`) |
| target value | one typed attribute — `ip`→`ip-src` (Network activity), `domain`→`domain`, `url`→`url`, `email`→`email-src` (Payload delivery), `hash`→`sha256`/`sha1`/`md5` by length, `username`→`text` (Attribution), everything else → `text` with the kind as comment |
| every `info` field | one `text` attribute whose comment is the field name (capped at 200 attributes) |
| `sources_ok` | one `sources_ok` text attribute naming the sources that answered |
| source health | threat level: `3` clean success, `2` anything errored — the curator's review flag |

`orgc` is the fixed ObscuraLens organisation (one deterministic UUID),
the event id is derived from the info line, and every attribute uuid is a
UUIDv5 over kind/value/comment — repeated imports of the same export
update in place instead of duplicating. `to_ids` is always `false`: an
OSINT lookup is evidence, not yet a blocking rule.

Importing into MISP: `obscuralens export misp ip 8.8.8.8 -o event.json`,
then either `POST` the `Event` block to your MISP instance's
`/events` REST endpoint (with an API-key header), or paste the file into
the web UI's *Add event → JSON import*. Everything is generated, not
validated: values are clipped, keys sanitised and hostile input degrades
into well-formed MISP JSON rather than an exception.

## Security notes

- **Secrets live in `config/secrets.yaml`**, never in the state file: the
  four service keys `telegram_api_key` (composite `bot_token:chat_id`),
  `slack_webhook_url`, `discord_webhook_url` and `smtp_credentials`
  (the full `host:port:from:to[:user:pass]` string). A channel may leave
  `target` empty and inherit the matching key — one secret, many
  channels, one place to rotate. The web UI sets them through
  `POST /api/keys/{service}` (`slack_webhook`, `discord_webhook`,
  `smtp`, `telegram`).
- **Do not pass secrets on the command line.** `--target` with a token
  lands in your shell history and the process list of every user on the
  box. Use `secrets.yaml` (or the keys API) for the credential and let
  channels inherit it; keep `--target` for URLs and throwaway test hooks.
- **Nothing leaves the machine by default.** The notification centre
  ships with zero channels; the scheduler with zero tasks; the exports
  are local files and local HTTP responses. First outbound delivery
  happens the moment *you* configure a channel — and `notify recent`
  shows every packet that ever left.
- **Quiet hours and the 5-minute dedup window** are per-channel noise
  guards, not just conveniences: a flapping watchlist cannot page the
  on-call at 03:00 nor flood a rate-limited chat webhook, because each
  channel decides independently when it is asleep and what counts as
  "the same message".
- **History is redacted before it is stored** (the database layer's
  secret sanitiser), so an exported STIX bundle or MISP event cannot
  leak a token that was pasted into a lookup — but exports still
  describe real investigation data: share bundles and events, not the
  whole history database.
