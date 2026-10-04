# obscuralens-sdk (JavaScript / TypeScript)

A **dependency-free** TypeScript/JavaScript SDK for the
[ObscuraLens](https://github.com/AceGuru-mjh/obscuralens) OSINT REST API
(v6.x). One `fetch`-based transport, the full 20-kind lookup surface, the
analyst toolbox, analytics, notifications, automation, STIX/MISP exports and
a fluent investigation session — zero npm dependencies, Node 18+ (or any
browser with `fetch`).

```js
import { ObscuraLensClient } from "obscuralens-sdk";

const client = new ObscuraLensClient({ baseUrl: "http://127.0.0.1:8000" });
const ip = await client.ip("8.8.8.8");
console.log(ip.info.country, ip.sources_ok);
client.close();
```

- **Runtime**: Node.js ≥ 18 (global `fetch`, `AbortSignal.timeout`) or modern
  browsers; TypeScript ≥ 5 with `strict` mode.
- **Server**: `obscuralens serve` (default `http://127.0.0.1:8000`). Start
  one locally with `pip install "obscuralens[web]" && obscuralens serve`.
- **Contract**: every method's JSDoc names the endpoint it calls in
  `obscuralens/web/app.py`; the response interfaces in
  [`src/types.ts`](src/types.ts) describe what the server actually returns.

---

## Installation

The package ships precompiled ESM + `.d.ts` in `dist/` — no build step
needed for consumers.

```bash
npm install obscuralens-sdk        # when published
```

From a checkout of this repository:

```bash
cd sdk-js
npm install        # no dependencies — creates node_modules only if you add dev tools
npm run build      # tsc -p tsconfig.json  → dist/
npm test           # node --test test/*.test.mjs (78 tests, fully offline + 1 real-HTTP smoke)
```

ESM only (`"type": "module"`); there is no CommonJS bundle — use dynamic
`import()` from CJS if you must.

---

## Quickstart

```js
import {
  ObscuraLensClient,
  InvestigationSession,
  BadRequestError,
  SdkError,
} from "obscuralens-sdk";

const client = new ObscuraLensClient({
  baseUrl: "http://127.0.0.1:8000",
  apiKey: process.env.OBSCURALENS_API_KEY, // optional X-API-Key (proxies)
  retries: 3,                               // attempts incl. the first
  timeoutMs: 30_000,
});

try {
  if (await client.ping()) {
    const { version } = await client.health();
    console.log("server up:", version);
  }

  // One lookup, one envelope
  const domain = await client.lookup("domain", "example.com");
  console.log(domain.field_count, "fields from", domain.sources_ok);

  // Typed per-kind shortcuts (all 20 kinds)
  const ip = await client.ip("8.8.8.8");

  // Auto-detect + pivot expansion
  const report = await client.investigate("evil.example.com", { pivot: true });

  // Explainable risk score
  const risk = await client.risk("domain", "evil.example.com");
  console.log(risk.risk.score, risk.risk.verdict, risk.risk.signals);
} catch (error) {
  if (error instanceof BadRequestError) {
    console.log("bad input:", error.detail); // server's {"detail": ...}
  } else if (error instanceof SdkError) {
    console.log(error.status, error.message);
  }
} finally {
  client.close();
}
```

On Node 20+ you can use explicit resource management instead of the
`finally` block:

```js
await using client = new ObscuraLensClient({ baseUrl: "http://127.0.0.1:8000" });
const ip = await client.ip("8.8.8.8");
// client[Symbol.asyncDispose]() closes the transport automatically
```

---

## Client options

| Option        | Default                  | Meaning                                                       |
| ------------- | ------------------------ | ------------------------------------------------------------- |
| `baseUrl`     | `http://127.0.0.1:8000` | Server root; trailing slashes trimmed, path prefixes kept. An invalid value throws a `TypeError` synchronously. |
| `apiKey`      | `null`                   | Sent as `X-API-Key` on every request (honoured by authenticating proxies; the stock server ignores it). |
| `timeoutMs`   | `30_000`                 | Per-request timeout via `AbortSignal.timeout` (`null` disables). |
| `retries`     | `3`                      | Total attempts per request *including the first*.             |
| `backoffMs`   | `500`                    | Retry backoff base — the delay is `backoffMs * 2 ** attempt`. |
| `maxBackoffMs`| `30_000`                 | Ceiling for one computed backoff sleep.                       |
| `transport`   | `FetchTransport`         | Pluggable HTTP layer (see [Testing](#testing-with-statictransport)). |
| `fetchFn`     | global `fetch`           | Injectable fetch for the default transport.                   |
| `sleepFn`     | `setTimeout`-based       | Injectable sleeper (tests record the delays).                 |

---

## Method families

### Liveness

```js
await client.ping();     // boolean — never rejects with SDK errors
await client.health();   // {status: "ok", version: "6.1.0"}
client.close();          // idempotent; further calls reject TransportError
```

### Lookups — 20 kinds

`lookup(kind, target)` plus one typed shortcut per kind:
`ip`, `phone`, `username`, `email`, `domain`, `url`, `crypto`, `hash`, `cve`,
`asn`, `mac`, `iban`, `imei`, `coords`, `vin`, `flight`, `mmsi`, `app`,
`package` (alias of `app`), `bssid`, `plate`.

```js
const vin = await client.vin("1M8GDM9AXKP042788");
const pkg = await client.package("pypi:requests"); // GET /api/lookup/app/{...}

const envelope = await client.lookup("email", "user@example.com");
envelope.info;                 // merged fields (the server's "info" block)
envelope.field_sources;        // {country: ["ipwhois.app", ...]} provenance
envelope.sources_ok;           // ["ipwhois.app"]
envelope.sources_failed;       // {ipinfo: "401"}
envelope.field_count;          // 14
envelope.confidence;           // v6.1 evidence block (when provenance exists)
```

Unknown kinds reject with a `TypeError` before any HTTP happens; invalid
targets reject with `BadRequestError` after the server validates.

### Investigations, risk, correlation, timeline, intel

```js
await client.investigate("evil.example.com");       // GET /api/investigate
await client.risk("domain", "evil.example.com");    // GET /api/risk/{kind}/{target}
await client.timeline({ target: "example.com", limit: 50 });
await client.correlate({ limit: 200 });
await client.correlatePair("a.com", "b.com");       // shared infrastructure
await client.intel("8.8.8.8");                      // Tor exits + blocklists
```

### Sources / stats / registry / history

```js
await client.sources();         // source catalogues per kind
await client.stats();           // database/cache/network/source_health
await client.sourcesHealth();   // the source_health list from /api/stats
await client.kinds();           // registry rows for the 20 kinds
await client.history({ kind: "ip", q: "8.8", limit: 50 });
```

### Cases

```js
await client.cases();                                   // GET /api/cases
await client.case(3);                                   // GET /api/cases/3
await client.createCase("acme", "phishing follow-up"); // POST /api/cases
await client.updateCase(3, "archived");                 // PATCH {status}
await client.addCaseItem(3, "example.com", { kind: "domain", note: "primary" });
await client.addCaseNote(3, "victim reported 2024-05-01");
await client.addCaseTag(3, "phish");
```

### Watchlist & diff

```js
await client.watch();                                 // GET /api/watch
await client.addWatch("example.com", { label: "corp site" }); // POST → {id}
await client.removeWatch(7);                          // by id or target string
await client.checkWatch({ identifier: "example.com" }); // POST /api/watch/check
await client.diff("domain", "example.com");           // latest two snapshots
```

### Settings & API keys

```js
await client.settings();                          // runtime view (dotted keys)
await client.updateSetting("app.cache_ttl", 300); // POST /api/settings
await client.keys();                              // configured services
await client.setKey("shodan", "…");               // POST /api/keys/{service}
await client.clearKey("shodan");                  // DELETE /api/keys/{service}
```

### Analyst toolbox

```js
await client.encode("admin:password");            // every scheme + digests
await client.decode("aGVsbG8=", "base64");       // or "auto" for rankings
await client.inspectJwt("e.y.z");                // local JWT inspection
await client.hashId("44d88612fea8a8f36de82e1278abb02f");
await client.convertCoords("48.8584, 2.2945");   // DD/DMS/UTM/MGRS/…
await client.extractEntities("contact bob@evil.example");
await client.squat("example.com");                // typosquat variants
await client.dorks("example.com", { kind: "domain" }); // ready-to-open links
await client.batch("ip", ["8.8.8.8", "1.1.1.1"], { risk: true });
```

### Analytics (v6.0 — offline, pure computation)

```js
await client.analyticsStats([1, 2, 3, 4, 100], 4);
await client.analyticsAnomalies([1, 2, 3, 4, 100], { method: "zscore", threshold: 2.5 });
await client.analyticsTimeseries([5, 6, 5, 6, 20, 21]);
await client.analyticsClusters([[52.0, 13.0], [52.1, 13.1]], { epsKm: 10, minPoints: 4 });
await client.analyticsKeywords("the quick brown fox", 2);
await client.analyticsLanguage("Le renard brun rapide");
await client.analyticsSimilarity("paypal.com", "paypa1.com");
await client.analyticsGraph([{ id: "a" }], [{ source: "a", target: "b" }]);
await client.analyticsHistory(500);
```

`threshold` is only sent when the method is `zscore` (the only detector that
honours it) — mirroring the server contract.

### Notifications (v6.0 part 4)

```js
await client.notifyChannels();                    // channels + vocabularies
await client.addNotifyChannel({
  name: "team-chat", type: "telegram", target: "bot:chat",
  events: ["lookup"], min_severity: "low",
});
await client.removeNotifyChannel("team-chat");
await client.testNotifyChannel("team-chat");      // 200 {ok:false} = data, not error
await client.notifyRecent(20);
await client.notifyBroadcast({ title: "watch diff", body: "NS changed",
                               severity: "high", eventType: "watch_diff" });
```

`undefined` keys are dropped from channel specs so the server applies its
own defaults.

### Automation (v6.0 part 4)

```js
await client.automationTasks();
await client.addAutomationTask({
  name: "daily-watch", action: "watch_check",
  schedule: "daily", at_time: "09:00",
});
await client.removeAutomationTask("daily-watch");
await client.runAutomationTask("daily-watch");   // manual run (no bookkeeping)
await client.runDueAutomation();                // what the tick loop does
await client.automationNext();                  // stored + recomputed next_run
```

### Sharing exports, patterns & the live stream

```js
await client.exportStix("domain", "example.com"); // STIX 2.1 bundle
await client.exportMisp("ip", "8.8.8.8");         // MISP core-format event
await client.exportGraph("graphml", "example.com"); // graphml/gexf/dot/jsonl/csv
await client.patterns("domain", "example.com");   // pattern-of-life report

await client.setStreamTopics("lookup, watch");   // POST /api/stream/subscribe
const url = client.streamUrl({ topics: ["lookup"] }); // GET /api/stream (SSE)
// connect with EventSource / fetch streaming; frames: connected|lookup|watch|heartbeat
```

The STIX/MISP exports describe the *newest stored* lookup — run the lookup
first, then export.

### Escape hatches

New server endpoints work without waiting for an SDK release:

```js
await client.rawGet("/api/profile/ip/8.8.8.8", { limit: 200 });
await client.rawPost("/api/alerts", { webhook_url: "https://…" });
await client.rawDelete("/api/watch/7");
```

---

## Error handling

Every failure rejects with an `SdkError` subclass — one `catch` guards a
whole session:

| Class                    | When                                                | Extras                          |
| ------------------------ | --------------------------------------------------- | ------------------------------- |
| `SdkError`               | base of everything below                            | `.status`, `.statusText`, `.body`, `.requestUrl`, `.detail` |
| `TransportError`         | DNS/refused/closed transport (no HTTP response)     | —                               |
| `TimeoutError`           | request timed out                                   | `.timeoutMs`                    |
| `ApiError`               | any non-2xx status                                  | parsed JSON `.body`             |
| `BadRequestError`        | HTTP 400 (invalid kind/target/body)                 | `.detail` from `{"detail": …}`  |
| `NotFoundError`          | HTTP 404 (unknown case/watch/channel/task…)         | —                               |
| `RateLimitError`         | HTTP 429                                            | `.retryAfterMs` (numeric `Retry-After` × 1000) |
| `ServerError`            | HTTP 5xx                                            | —                               |
| `MalformedResponseError` | 2xx body that is not JSON                           | `.bodyText` (truncated)         |

```js
try {
  await client.lookup("iban", "not-an-iban");
} catch (error) {
  if (error instanceof BadRequestError) console.log(error.detail);
}
```

`errorForResponse(response, bodyText, url)` is the exported factory the
client uses — build your own mapping on top of it if you swap transports.

---

## Retry semantics

- Retried (up to `retries` total attempts): `TransportError`, `TimeoutError`,
  `RateLimitError`.
- Never retried: `BadRequestError`, `NotFoundError`, `ServerError`, other
  `ApiError`s — they reject on the first response.
- Backoff: `backoffMs * 2 ** attempt` capped at `maxBackoffMs`
  (500 ms → 1 s → 2 s … capped at 30 s by default).
- `Retry-After` wins: a numeric header is slept *exactly*
  (`.retryAfterMs`); HTTP-date headers are ignored (normal backoff applies).
- Client-side `TypeError`s (unknown lookup kind, malformed `baseUrl`) never
  touch the network.

---

## Testing with StaticTransport

`StaticTransport` is a programmable in-memory server: preload responses (or
`Error` instances to throw), then assert on the exact method/URL/params/body
of every recorded call. This is how the SDK's own 78-test suite runs fully
offline.

```js
import {
  ObscuraLensClient, StaticTransport, jsonResponse,
} from "obscuralens-sdk";

const transport = new StaticTransport([
  jsonResponse(200, {
    ip: "8.8.8.8", info: { country: "US" },
    sources_ok: ["ipwhois.app"], sources_failed: {},
    field_count: 1, success: true,
  }),
]);
const client = new ObscuraLensClient({
  baseUrl: "http://127.0.0.1:8000",
  transport,
  retries: 1,
  sleepFn: (ms) => {}, // no real sleeping between retries
});

const ip = await client.ip("8.8.8.8");
ip.info.country;                          // "US"
transport.calls[0].method;                // "GET"
transport.calls[0].url;                   // "http://127.0.0.1:8000/api/lookup/ip/8.8.8.8"
transport.calls[0].params;                // {}
transport.calls[0].jsonBody;              // null

// Script failures: responses are returned, errors are thrown
// (rate-limit responses are retried by the client automatically).
const retrying = new StaticTransport([
  new (await import("obscuralens-sdk")).TransportError("reset"),
  jsonResponse(200, { status: "ok", version: "6.1.0" }),
]);
```

`StaticTransport` API: `script`, `enqueue(…)`, `calls`, `lastCall`,
`urls()`, `methods()`, `headerOf(i, name)`, `close()`, `repeatLast`
(constructor's second argument repeats the final script item forever).
When the script runs dry the transport throws `TransportError` so a missing
expectation fails loudly.

Custom transports implement `request(method, url, headers?, params?,
jsonBody?) → Promise<{status, statusText, headers, text}>` and optional
`close()` — axios/undici/caching proxies drop in without touching the client.

---

## InvestigationSession

The client is a thin endpoint mapper; real OSINT work is a *sequence* of
steps and the interesting artefact is the trail. `InvestigationSession`
wraps a client and records every step (success or failure) as data:

```js
import { ObscuraLensClient, InvestigationSession } from "obscuralens-sdk";

const client = new ObscuraLensClient();
const session = new InvestigationSession(client, {
  label: "phishing-2024",
  strict: false, // true = failing steps re-throw after being recorded
});

await session.lookup("ip", "1.2.3.4");
await session.investigate("evil.example.com");
await session.risk("domain", "evil.example.com");
await session.dorks("evil.example.com");
session.note("victim reported 2024-05-01");

session.stepCount;          // 5
session.okCount;            // 5
session.failedCount;        // 0
session.targets();          // ["1.2.3.4", "evil.example.com"] (first-seen order)
session.notesTaken;         // ["victim reported 2024-05-01"]
console.log(session.summary()); // multi-line report with step headlines

console.log(session.toJSON());  // portable JSON receipt
session.close();                // blocks further actions (client untouched)
```

- **Errors are data** — a failing step records `"ErrorType: message"` and
  resolves `undefined`; `strict: true` records *then* re-throws.
- **Receipts are portable** — `toObject()` / `toJSON(indent)` emit the
  `obscuralens-session-js/1` format: counts, targets, notes and every step.
- **Composition over HTTP** — the session only calls public client methods,
  so `StaticTransport` under the client tests the whole session offline.
- Async disposal: `await using session = new InvestigationSession(client)`
  on runtimes with `Symbol.asyncDispose`.

---

## TypeScript notes

- Everything is exported from the package root: the `ObscuraLensClient`,
  `InvestigationSession`, `StaticTransport`/`FetchTransport`, the `SdkError`
  hierarchy, and the payload interfaces
  (`LookupEnvelope`, `RiskReport`, `Timeline`, `Case`, `WatchEntry`,
  `DorkReport`, `NotifyChannels`, `AutomationTasks`, `StixBundle`,
  `MispEvent`, …) plus `KINDS`/`TARGET_KEYS` and the `LookupKind` union.
- The server is the contract: interfaces use optional fields and index
  signatures (`[key: string]: unknown`) so unknown/future keys never break
  compilation. Cast or narrow when you need a specific nested shape.
- `analytics*` methods resolve the generic `AnalyticsResult`
  (`Record<string, unknown>`-style) — each endpoint's block differs; see the
  method JSDoc for the keys the server returns.
- Source is compiled with `strict`, `noUnusedLocals`,
  `module: NodeNext`, `target: ES2022`; declaration files ship in `dist/`.

```ts
import { ObscuraLensClient, LookupEnvelope } from "obscuralens-sdk";

const client = new ObscuraLensClient({ baseUrl: "http://127.0.0.1:8000" });
const ip: LookupEnvelope = await client.ip("8.8.8.8");
const country = ip.info["country"]; // unknown — narrow as needed
```

---

## Comparison to the Python SDK

| Aspect | Python (`obscuralens.sdk`) | JavaScript (`obscuralens-sdk`) |
| --- | --- | --- |
| Language | Python 3.9+ | TypeScript 5 / Node 18+ (ESM only) |
| Dependencies | stdlib only (`urllib`) | none (global `fetch`) |
| Transport | `UrllibTransport` | `FetchTransport` (+ injectable `fetchFn`) |
| Test double | `StaticTransport` (script queue + `.calls`) | `StaticTransport` (same design, `jsonResponse()` factory) |
| Errors | `SdkError` → `ApiError`/`TransportError`/… | identical hierarchy, `retryAfterMs` in ms (Python uses seconds) |
| Retries | 3 × 0.5 s doubling, `Retry-After` honoured | identical (500 ms doubling, 30 s cap) |
| Lookups | 20 kinds + `lookup()` | identical incl. `package` alias |
| Model layer | rich dataclasses (`LookupResult`, `RiskReport`, …) | typed interfaces (the raw payloads, no wrappers) |
| Sessions | `InvestigationSession` (dump/load receipts, `to_case`) | `InvestigationSession` (toObject/toJSON receipts; simpler by design) |
| Async | `AsyncObscuraLensClient` (mirror) | the only client — every method is a `Promise` |
| Multipart uploads | `exif()`/`stego()` helpers | use `rawPost` with your own body (server: `/api/tools/file/*`) |
| `ping()` | hits `GET /api/stats` | hits `GET /api/health` (cheaper probe) |
| Version | 6.1.0 | 6.1.0 |

## License

MIT — same as the ObscuraLens project.
