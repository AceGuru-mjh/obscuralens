# ObscuraLens Python SDK

`obscuralens.sdk` is a first-class Python client for the ObscuraLens REST
API: one class with a typed method for **every endpoint** the server
exposes, plus an async twin. It exists so scripts, notebooks, SOAR
playbooks and test harnesses can drive ObscuraLens without hand-rolling
`requests` calls, URL encoding or retry loops.

Design constraints, because they show up in the API:

- **Sync + async.** `ObscuraLensClient` is synchronous; the async twin
  `AsyncObscuraLensClient` wraps it for event loops. Same methods, same
  models, same error mapping.
- **Standard library only.** The transport is `urllib.request` -- no
  `requests`, no `httpx`, no `aiohttp`. The SDK imports cleanly in the
  frozen desktop executable, in air-gapped environments and anywhere a
  dependency audit would flag a network stack.
- **Tolerant models.** Every response model is a plain dataclass built by
  a `from_dict` that never raises on extra or missing keys; the raw
  payload is always kept on `.raw` for forward compatibility.
- **Testable offline.** The transport is injectable, and the bundled
  `StaticTransport` is a programmable fake server (see [Custom
  transports](#custom-transports-and-statictransport)).

The server-side reference for every endpoint lives in
[docs/api.md](api.md); this document is the client-side view.

## Install and start

The SDK ships inside the `obscuralens` package (Python 3.9+), so any
install includes it:

```bash
git clone https://github.com/AceGuru-mjh/obscuralens.git
cd obscuralens
python -m venv venv && source venv/bin/activate    # Windows: .\venv\Scripts\Activate
pip install -e .
```

Start a server and point the client at it:

```bash
obscuralens serve                # http://127.0.0.1:8000
```

```python
from obscuralens.sdk import ObscuraLensClient

client = ObscuraLensClient("http://127.0.0.1:8000")
```

The default base URL already is `http://127.0.0.1:8000`, so
`ObscuraLensClient()` works out of the box against a local `serve`.
A path prefix (`http://host/obscuralens`) is preserved. `https://` base
URLs verify TLS certificates by default (`verify_ssl=False` to disable,
at your own risk).

## Quickstart

Synchronous -- a lookup, an investigation and a risk verdict:

```python
from obscuralens.sdk import ObscuraLensClient

with ObscuraLensClient() as client:
    # a single lookup, with merged-field access
    result = client.ip("8.8.8.8")
    print(result.summary())          # "ip 8.8.8.8: 14 field(s) from 5 source(s), 1 failed"
    print(result.get("country"))    # merged field value
    print(result.provenance())      # which source supplied which field

    # auto-detected kind + bounded pivots
    report = client.investigate("example.com", pivot=True)
    print(report.summary())

    # explainable risk scoring
    risk = client.risk("domain", "example.com")
    if risk.is_high_or_worse():
        print(risk.explain())       # weighted signal lines
```

Asynchronous -- the same calls as coroutines:

```python
import asyncio
from obscuralens.sdk import AsyncObscuraLensClient

async def main():
    async with AsyncObscuraLensClient() as client:
        result = await client.lookup("domain", "example.com")
        ok = await client.ping()
        print(result.summary(), ok)

asyncio.run(main())
```

Concurrent fan-out with `gather`:

```python
results = await client.gather([
    client.ip("8.8.8.8"),
    client.domain("example.com"),
    client.cve("CVE-2021-44228"),
])
```

## Client configuration

`ObscuraLensClient(...)` (and the async twin, minus `sleep_fn`) accepts:

| Argument | Default | Meaning |
|---|---|---|
| `base_url` | `"http://127.0.0.1:8000"` | scheme + host + port (with or without trailing slash); path prefixes preserved |
| `api_key` | `None` | sent as an `X-API-Key` header on every request. The stock server has no built-in auth; this is for authenticating reverse proxies in front of it |
| `timeout` | `30.0` | per-request timeout in seconds |
| `retries` | `3` | **total attempts per request including the first** (3 = one try plus up to two retries) |
| `backoff` | `0.5` | base sleep between retries; the delay is `backoff * 2**attempt` capped at `max_backoff` |
| `transport` | `None` | a `Transport` implementation; `None` builds the stdlib `UrllibTransport` |
| `verify_ssl` | `True` | forwarded to the default transport for `https://` base URLs; ignored when a custom transport is supplied |
| `sleep_fn` | `time.sleep` | the sleeper used between retries -- injectable so tests run at full speed |
| `max_backoff` | `30.0` | ceiling for any single computed backoff sleep |

Every request carries `Accept: application/json` and
`User-Agent: obscuralens-sdk/<version>`. The client is a context manager;
`close()` is idempotent, and requests after close raise `TransportError`.

## Exceptions

Every error the SDK raises derives from `SdkError`, so one `except`
clause guards a whole session:

| Exception | Parent | Raised when | Extra attributes |
|---|---|---|---|
| `SdkError` | `Exception` | (base class) | `.message`, `.status`, `.payload` |
| `TransportError` | `SdkError` | the request never produced an HTTP response: DNS failure, refused connection, closed client | `.status` is `None` |
| `TimeoutError` | `SdkError` | the transport reported a socket/operation timeout | `.timeout` (seconds in effect, when known) |
| `ApiError` | `SdkError` | the server answered with a non-2xx status | `.status` always set, `.payload` parsed JSON body |
| `BadRequestError` | `ApiError` | HTTP 400 -- invalid kind, failed target validation, bad body | |
| `NotFoundError` | `ApiError` | HTTP 404 -- unknown case id, watch, diff target ... | |
| `RateLimitError` | `ApiError` | HTTP 429 -- server-side rate limiting | `.retry_after` (seconds from a numeric `Retry-After` header, else `None`) |
| `ServerError` | `ApiError` | HTTP 5xx -- the server itself failed | |
| `MalformedResponseError` | `SdkError` | a 2xx body that is not valid JSON | `.body_text` (raw body, possibly truncated) |

`str(exc)` renders the message plus the status code when known
(`"unknown kind (HTTP 400)"`). `ApiError.payload` preserves the parsed
error body (`{"detail": "..."}` for ObscuraLens servers) so callers can
log the server's own explanation.

## Retry semantics

`_send` retries a request when it fails with `TransportError`,
`TimeoutError` or `RateLimitError` -- up to `retries` total attempts.

- The sleep between attempts is exponential: `backoff * 2**attempt`
  (attempt is 0-based), capped at `max_backoff` (default 30 s).
  Defaults: 0.5 s, then 1.0 s.
- A numeric `Retry-After` header on a 429 **overrides** the computed
  backoff -- the client sleeps exactly that long.
- Non-retryable errors (`BadRequestError`, `NotFoundError`,
  `ServerError`, other `ApiError`) raise immediately on the first
  attempt. A 429 that is still being returned on the final attempt
  raises `RateLimitError`.
- Retries go through the injectable `sleep_fn`, so test suites never
  actually wait.
- `ping()` (see below) never raises -- a dead server burns the full
  retry budget and then returns `False`, so pass a small `retries` value
  when pinging aggressively.

## Endpoint methods reference

64 public methods, grouped by family. Signatures are abbreviated
(`kind` = one of the 14 kinds; defaults shown where they matter).
"Returns" names the model from [Models](#models-reference) or the raw
dict/list shape.

### Service

| Method | HTTP | Returns |
|---|---|---|
| `ping()` | `GET /api/stats` | `bool` -- any successful response; never raises |
| `health()` | `GET /api/health` | `dict` -- `{'status', 'version'}` |

### Core lookup and kind conveniences

| Method | HTTP | Returns |
|---|---|---|
| `lookup(kind, target)` | `GET /api/lookup/{kind}/{target}` | `LookupResult` |
| `ip(target)` / `phone(target)` / `username(target)` / `email(target)` / `domain(target)` / `url(target)` / `crypto(target)` / `hash_(target)` / `cve(target)` / `asn(target)` / `mac(target)` / `iban(target)` / `imei(target)` / `coords(target)` | `GET /api/lookup/{kind}/{target}` | `LookupResult` |

The 14 convenience methods are thin aliases for `lookup()` -- `hash_`
carries the trailing underscore because `hash` is a Python builtin.

### Investigation, risk, timeline, correlation, intel

| Method | HTTP | Returns |
|---|---|---|
| `investigate(target, pivot=True)` | `GET /api/investigate?target&pivot` | `InvestigationReport` |
| `risk(kind, target)` | `GET /api/risk/{kind}/{target}` | `RiskReport` |
| `timeline(target=None, limit=100)` | `GET /api/timeline?target&limit` | `Timeline` |
| `correlate(limit=None)` | `GET /api/correlate?limit` | `CorrelationResult` |
| `correlate_pair(a, b)` | `GET /api/correlate/pair?a&b` | `PairComparison` |
| `intel(target)` | `GET /api/intel/{target}` | `IntelVerdict` |

### Sources, stats, kinds, history

| Method | HTTP | Returns |
|---|---|---|
| `sources()` | `GET /api/sources` | `dict` -- `{kind: {source: description}}` |
| `sources_health()` | `GET /api/stats` | `List[SourceHealthEntry]` -- convenience that extracts the `source_health` block; the server has no dedicated health route |
| `stats()` | `GET /api/stats` | `StatsSummary` |
| `kinds()` | `GET /api/kinds` | `List[KindInfo]` |
| `history(kind=None, q=None, limit=100)` | `GET /api/history?kind&q&limit` | `HistoryResult` |

### Keys and settings

| Method | HTTP | Returns |
|---|---|---|
| `keys()` | `GET /api/keys` | `List[ServiceKey]` (values never returned) |
| `set_key(service, key)` | `POST /api/keys/{service}` body `{"key"}` | `dict` -- `{'ok', 'service', 'configured': True}` |
| `clear_key(service)` | `DELETE /api/keys/{service}` | `dict` -- `{'ok', 'service', 'configured': False}` |
| `settings()` | `GET /api/settings` | `dict` -- dotted-path runtime settings |
| `update_settings(path, value)` | `POST /api/settings` body `{"path", "value"}` | `dict` |

### Cases

| Method | HTTP | Returns |
|---|---|---|
| `cases()` | `GET /api/cases` | `List[Case]` |
| `case(case_id)` | `GET /api/cases/{case_id}` | `Case` |
| `create_case(name, description='')` | `POST /api/cases` body `{"name", "description"}` | `Case` |
| `update_case(case_id, status)` | `PATCH /api/cases/{case_id}` body `{"status"}` | `Case` -- status: `open`/`closed`/`archived` |
| `add_case_item(case_id, target, kind='auto', note=None)` | `POST /api/cases/{case_id}/items` body `{"kind", "target", "note"}` | `CaseItem` |
| `add_case_note(case_id, note)` | `POST /api/cases/{case_id}/notes` body `{"note"}` | `CaseNote` |
| `add_case_tag(case_id, tag)` | `POST /api/cases/{case_id}/tags` body `{"tag"}` | `dict` |

### Watchlist and diffs

| Method | HTTP | Returns |
|---|---|---|
| `watch()` | `GET /api/watch` | `List[WatchEntry]` |
| `add_watch(target, label='')` | `POST /api/watch` body `{"target", "label"}` | `dict` -- `{'id': ...}` |
| `remove_watch(identifier)` | `DELETE /api/watch/{identifier}` | `dict` -- `{'removed': ...}`; identifier is the numeric id or the target string |
| `check_watch(identifier=None)` | `POST /api/watch/check?identifier` | `List[WatchDiff]`; `None` checks every watch |
| `diff(kind, target)` | `GET /api/diff/{kind}/{target}` | `DiffReport` |

### Export and reports

| Method | HTTP | Returns |
|---|---|---|
| `export(fmt, target, pivot=True)` | `GET /api/export/{fmt}/{target}?pivot` | `dict` -- `{'target', 'format', 'graph', 'entities', 'links'}`; `fmt`: `graphml`/`gexf`/`dot`/`jsonl`/`csv` |
| `report(kind, target, download=False, save_to=None)` | `GET /api/report/{kind}/{target}?download` | JSON mode: `{'kind', 'target', 'size', 'html'}`; `download=True` returns the raw HTML document; `save_to` writes it to disk |
| `patterns(kind, target)` | `GET /api/patterns?kind&target` | `PatternReport` |

### Alerts

| Method | HTTP | Returns |
|---|---|---|
| `alerts()` | `GET /api/alerts` | `AlertConfig` (webhook URL, event whitelist, recent log) |
| `configure_alerts(webhook_url='', events=None)` | `POST /api/alerts` body `{"webhook_url", "events"}` | `AlertConfig`; an empty URL disables delivery; `events=None` whitelists everything |
| `test_alert()` | `POST /api/alerts/test` | `dict` -- `{'ok', 'status', 'detail'}`; a dead webhook reports `ok: False` instead of raising |

### Analyst toolbox

| Method | HTTP | Returns |
|---|---|---|
| `encodings(text)` | `GET /api/tools/encodings?text` | `ToolboxResult` |
| `decode(value, scheme='auto')` | `POST /api/tools/decode` body `{"scheme", "value"}` | `ToolboxResult` |
| `jwt(token)` | `GET /api/tools/jwt?token` | `ToolboxResult` |
| `hash_id(value)` | `GET /api/tools/hash-id?value` | `ToolboxResult` |
| `coords_convert(value)` | `POST /api/tools/coords` body `{"value"}` | `ToolboxResult` |
| `extract_entities(text)` | `POST /api/tools/extract` body `{"text"}` | `ToolboxResult` |
| `squat(domain)` | `POST /api/tools/squat` body `{"domain"}` | `ToolboxResult` |
| `toolbox(tool, value)` | dispatcher | `ToolboxResult` -- accepts the seven tool names, their aliases (`hash_id`, `entities`, `typosquat`, ...) and any decode scheme name (`base64`, `hex`, ...) which routes to `decode` |
| `exif(data, filename=None)` | `POST /api/tools/file/exif` (multipart) | `dict` -- analysed server-side, in-process, never stored |
| `stego(data, filename=None)` | `POST /api/tools/file/stego` (multipart) | `dict` |

`exif`/`stego` accept raw `bytes`, or a path (`str`/`Path`) which is
read for you; the multipart body is built with the standard library, and
the upload filename defaults to the path basename.

### Batch

| Method | HTTP | Returns |
|---|---|---|
| `batch(kind, targets, risk=False)` | `POST /api/tools/batch` body `{"kind", "targets", "risk"}` | `BatchProgress` |

The run is synchronous: the response already carries one
`BatchEntry` per target (failures included as `success: False`
envelopes, never omitted). The server caps at 25 targets per request;
the surplus is counted in `skipped`. There is no status endpoint to
poll -- the server does not have one.

### Escape hatches

| Method | HTTP | Returns |
|---|---|---|
| `raw_get(path, params=None)` | `GET <any path>` | parsed JSON -- for endpoints this SDK version does not model yet |
| `raw_post(path, json_body=None)` | `POST <any path>` | parsed JSON |

New server endpoints work through the escape hatches without waiting
for an SDK release; they get the same retries, headers and error
mapping as the typed methods.

## Models reference

31 dataclasses in `obscuralens.sdk.models`, all built through
`from_dict()` which tolerates extra and missing keys, and all keep the
original payload on `.raw`. The ones you will meet most:

| Model | Key attributes / methods |
|---|---|
| `LookupResult` | the tracker envelope: the kind-specific target attribute (`ip`, `domain`, ... depending on kind), `.info` (merged fields), `.field_sources` (field -> source attribution), `.sources_ok` / `.sources_failed`, `.field_count`, `.success`, `.errors`; helpers `.get(field)`, `.summary()` (one-line human summary), `.provenance()` |
| `RiskReport` | `.score` (0-100), `.verdict` / `.band`, `.signals` (weighted explanations), `.summary`, `.explain()`; band helpers `.is_medium_or_worse()`, `.is_high_or_worse()`, `.is_critical()` |
| `Timeline` | `.events` (`List[TimelineEvent]`, oldest -> newest), `.first`, `.last`, `.span_days`; each event: `target`, `kind`, `timestamp`, `field` |
| `CorrelationResult` | `.entities`, `.links`, `.clusters` (`List[CorrelationCluster]` with `.size` / `.entities`), `.bridges`, `.largest_cluster()` |
| `PairComparison` | `.a`, `.b`, `.shared_entities`, `.connection_count`, `.related` verdict |
| `Case` | `.id`, `.name`, `.description`, `.status`, `.created`, `.updated`, `.items` (`List[CaseItem]`), `.notes` (`List[CaseNote]`), `.tags` |
| `WatchEntry` | `.id`, `.target`, `.kind`, `.label`, `.added`, `.last_check`, `.snapshot` |
| `WatchDiff` | `.watch_id`, `.target`, `.added` / `.removed` / `.changed` field maps, `.is_first`, `.has_changes()` |
| `SourceHealthEntry` | per-source reliability: name, kind, successes/failures, error rate, circuit-breaker state |
| `StatsSummary` | dict-backed totals with `.total_lookups`, `.by_kind`, `.cache_hits`, plus the raw server block |
| `InvestigationReport` | `.target`, `.kind`, `.results` (per-kind `LookupResult` envelopes), `.entities`, `.links`, `.summary()` |
| `ToolboxResult` | dict-backed tool output with `.get(key)` and `.raw`; shape depends on the tool |
| `AlertEntry` | one event-log row: event type, timestamp, payload, delivery status |
| `AlertConfig` | `.webhook_url`, `.events` whitelist, `.enabled` / `.is_enabled()`, `.event_types`, `.log` (recent `AlertEntry` rows) |
| `PatternFinding` / `PatternReport` | hour/weekday histograms, 7x24 activity matrix, cadence statistics, bursts, verdict lines; `.peak_hour` and friends |

The rest (`KindInfo`, `ServiceKey`, `HistoryItem`/`HistoryResult`,
`BatchEntry`/`BatchProgress`, `IntelVerdict`, `DiffReport`,
`SourceStatus`, `Provenance`/`ProvenanceEntry`, `CaseItem`, `CaseNote`,
`CorrelationCluster`, `TimelineEvent`) follow the same construction
rules. Models are plain dataclasses -- no ORM, no validation framework;
junk in the payload becomes `None`/default attributes, never exceptions.

## Custom transports and `StaticTransport`

Every request flows through a `Transport` with two methods,
`request(method, url, headers, params, json_body, body, timeout)` and
`close()`. Subclass it to route SDK calls through your own stack
(connection pooling, SOCKS proxies, logging, a mock):

```python
from obscuralens.sdk import ObscuraLensClient
from obscuralens.sdk.transport import Transport, Response

class LoggingTransport(Transport):
    def __init__(self):
        self.inner = None
    def request(self, method, url, **kwargs):
        print(f"{method} {url}")
        # ... delegate to UrllibTransport or your own HTTP stack
    def close(self):
        pass

client = ObscuraLensClient(transport=LoggingTransport())
```

For testing your scripts *offline*, the bundled `StaticTransport` is a
programmable fake server:

```python
from obscuralens.sdk import ObscuraLensClient
from obscuralens.sdk.transport import StaticTransport, Response
from obscuralens.sdk.exceptions import TransportError

transport = StaticTransport([
    Response.from_json(200, {'status': 'ok', 'version': '5.1.0'}),
    TransportError('simulated outage'),                 # raised, then retried
    Response.from_json(200, {
        'ip': '8.8.8.8', 'info': {'country': 'United States'},
        'field_sources': {'country': ['ipwhois.app']},
        'sources_ok': 5, 'sources_failed': 1, 'field_count': 14,
        'success': True, 'errors': [],
    }),
])
client = ObscuraLensClient(transport=transport, retries=3)

print(client.health())          # {'status': 'ok', 'version': '5.1.0'}
print(client.ip('8.8.8.8').summary())
```

`StaticTransport` records every call it receives -- `method`, `url`,
`params`, `json_body`, `body`, `headers`, `timeout` -- in `.calls`, with
`.last_call`, `.urls()`, `.methods()` and `.header_of(i, name)`
introspection helpers, so you can assert on the exact request your code
built. When the script runs dry it raises `TransportError` (a missing
expectation fails loudly) unless you construct it with
`repeat_last=True`. This is exactly how the SDK's own test suite runs
its 189 offline tests; it works for your scripts too.

## Error-handling recipe

A practical ladder for a script that must not die mid-run:

```python
from obscuralens.sdk import (
    ObscuraLensClient, SdkError, TransportError, TimeoutError,
    RateLimitError, NotFoundError, BadRequestError, ServerError,
    MalformedResponseError,
)

with ObscuraLensClient() as client:
    try:
        result = client.lookup("domain", "example.com")
        print(result.summary())

    except BadRequestError as exc:
        # our bug: invalid kind or a target the validator rejects
        print(f"bad request: {exc} (payload={exc.payload})")

    except NotFoundError as exc:
        print(f"no such resource: {exc}")

    except RateLimitError as exc:
        # the client already retried (honouring Retry-After);
        # reaching here means it stayed throttled
        print(f"still rate-limited after retries (retry_after={exc.retry_after})")

    except (TransportError, TimeoutError) as exc:
        # server down / unreachable -- retries exhausted
        print(f"server unreachable: {exc}")

    except MalformedResponseError as exc:
        # a 2xx that was not JSON -- proxy interference, wrong base_url?
        print(f"non-JSON response: {exc} (body starts {exc.body_text[:80]!r})")

    except SdkError as exc:
        # ServerError, other ApiError, or anything future
        print(f"lookup failed: {exc}")
```

Catch order matters: the specific subclasses first, `SdkError` last.
`ping()` is the cheap pre-flight when you want a boolean instead of an
exception.

## The async client

`AsyncObscuraLensClient` mirrors the sync surface as coroutines:
`ping`, `health`, `lookup` plus all 14 kind conveniences, `investigate`,
`risk`, `timeline`, `correlate`, `correlate_pair`, `intel`, `sources`,
`sources_health`, `stats`, `kinds`, `history`, `cases`, `watch`, plus a
`gather()` convenience. Constructor arguments are the sync ones (minus
`sleep_fn`) plus `executor` / `max_workers`.

Execution model, honestly: this is not a native-asyncio HTTP client.
Each coroutine submits the *synchronous* client call to a private
`ThreadPoolExecutor` via `loop.run_in_executor` and awaits it. That is
deliberate -- it keeps the whole SDK stdlib-only while still letting one
event loop drive many concurrent lookups (in parallel up to
`max_workers`, default 8). Consequences:

- it is safe to fire dozens of coroutines at one client; they queue on
  the pool;
- per-call latency is the same as the sync client; concurrency comes
  from the pool, not from non-blocking I/O;
- `aclose()` (also called by `async with ... __aexit__`) shuts the owned
  executor down; pass your own `executor=` if the pool must be shared.

```python
import asyncio
from obscuralens.sdk import AsyncObscuraLensClient

async def main():
    async with AsyncObscuraLensClient("http://127.0.0.1:8000") as client:
        if not await client.ping():
            print("server is down")
            return
        ip, domain = await client.gather([
            client.ip("8.8.8.8"),
            client.domain("example.com"),
        ])
        print(ip.summary(), domain.summary())

asyncio.run(main())
```

Errors propagate unchanged: the same `SdkError` hierarchy is raised from
the coroutines. A `StaticTransport` makes the async client fully
testable offline, exactly like the sync one.

## Limitations, honestly

- The SDK models the v5.x REST API of `obscuralens serve` -- it cannot
  talk to the CLI directly, and it cannot run lookups in-process.
- `batch()` is synchronous client-side because the server endpoint is
  synchronous; 25 targets per request is a server cap, not an SDK one.
- `sources_health()` is a documented convenience over `GET /api/stats`,
  not a dedicated endpoint (the server has none).
- The async client's concurrency is thread-pool bound, not
  selector-bound (see above). For massive fan-out, `batch()` on the
  server is the better tool.
- Two intentional divergences from the older prose in `docs/api.md`,
  where the SDK follows the actual server code: case items are added
  with `{"target"}` (not `{"value"}`), and `patterns` takes `target`
  (not `value`).

See [docs/api.md](api.md) for the server-side contract,
[docs/desktop-beta.md](desktop-beta.md) for running the server inside the
desktop executable, and [docs/v5.1.md](v5.1.md) for release notes.
