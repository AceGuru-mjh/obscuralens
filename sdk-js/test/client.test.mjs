/**
 * Offline + smoke test suite for the ObscuraLens JS SDK client.
 *
 * Every endpoint assertion runs against `StaticTransport` (a programmable
 * in-memory server — no network, no FastAPI, no database) and asserts the
 * exact method/URL/params/body the client sent. One final test exercises
 * `FetchTransport` against a real `node:http` server on an ephemeral port.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";

import {
  ObscuraLensClient,
  StaticTransport,
  jsonResponse,
  buildUrl,
  KINDS,
  TARGET_KEYS,
  SDK_VERSION,
  BadRequestError,
  NotFoundError,
  RateLimitError,
  ServerError,
  ApiError,
  TransportError,
  TimeoutError,
  MalformedResponseError,
} from "../dist/index.js";

const BASE = "http://127.0.0.1:8000";

/** Build a client on a StaticTransport with a recording sleeper. */
function makeClient(script = [], overrides = {}) {
  const { retries, backoffMs = 0, ...rest } = overrides;
  const transport = new StaticTransport(script);
  const sleeps = [];
  const client = new ObscuraLensClient({
    baseUrl: BASE,
    transport,
    retries: retries ?? 1,
    backoffMs,
    sleepFn: (ms) => {
      sleeps.push(ms);
    },
    ...rest,
  });
  return { client, transport, sleeps };
}

/** Canned JSON success response. */
function ok(payload, status = 200) {
  return jsonResponse(status, payload);
}

/** Canned `{"detail": ...}` error response. */
function err(status, detail = "boom", headers = {}) {
  return jsonResponse(status, { detail }, headers);
}

const IP_PAYLOAD = {
  ip: "8.8.8.8",
  info: { ip: "8.8.8.8", country: "United States", asn: "AS15169" },
  field_sources: { country: ["ipwhois.app"], asn: ["ipwhois.app"] },
  sources_ok: ["ipwhois.app"],
  sources_failed: { ipinfo: "401" },
  field_count: 3,
  success: true,
  errors: ["1 source(s) unavailable"],
  elapsed: 0.42,
};

// ---------------------------------------------------------------------------
// Constructor / defaults / lifecycle
// ---------------------------------------------------------------------------

test("constructor rejects invalid baseUrl synchronously", () => {
  assert.throws(() => new ObscuraLensClient({ baseUrl: "not-a-url" }), TypeError);
  assert.throws(() => new ObscuraLensClient({ baseUrl: "ftp://host" }), TypeError);
  assert.throws(() => new ObscuraLensClient({ baseUrl: "" }), TypeError);
});

test("constructor normalises trailing slashes and keeps defaults", () => {
  const { client } = makeClient();
  assert.equal(client.baseUrl, BASE);
  assert.equal(client.retries, 1); // overridden by makeClient
  const defaults = new ObscuraLensClient({ transport: new StaticTransport() });
  assert.equal(defaults.baseUrl, "http://127.0.0.1:8000");
  assert.equal(defaults.retries, 3);
  assert.equal(defaults.timeoutMs, 30_000);
  assert.equal(defaults.backoffMs, 500);
  assert.equal(defaults.maxBackoffMs, 30_000);
  assert.equal(defaults.apiKey, null);
});

test("client sends Accept/User-Agent and optional X-API-Key headers", async () => {
  const { client, transport } = makeClient([ok({ status: "ok" })]);
  await client.health();
  const headers = transport.calls[0].headers;
  assert.equal(headers.Accept, "application/json");
  assert.equal(headers["User-Agent"], `obscuralens-sdk/${SDK_VERSION}`);
  assert.equal(headers["X-API-Key"], undefined);

  const keyed = makeClient([ok({ status: "ok" })], { apiKey: "sekret" });
  await keyed.client.health();
  assert.equal(keyed.transport.calls[0].headers["X-API-Key"], "sekret");
});

test("close is idempotent and blocks further requests", async () => {
  const { client, transport } = makeClient([ok({ status: "ok" })]);
  await client.health();
  client.close();
  client.close();
  await assert.rejects(() => client.health(), TransportError);
  assert.equal(transport.calls.length, 1);
});

test("ping resolves true on success and false on SDK errors", async () => {
  const good = makeClient([ok({ status: "ok", version: "6.1.0" })]);
  assert.equal(await good.client.ping(), true);
  assert.equal(good.transport.calls[0].url, `${BASE}/api/health`);

  const bad = makeClient([err(500, "nope")]);
  assert.equal(await bad.client.ping(), false);

  const dead = makeClient([new TransportError("connection refused")]);
  assert.equal(await dead.client.ping(), false);
});

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

test("lookup(ip) hits GET /api/lookup/ip/{target} with no params", async () => {
  const { client, transport } = makeClient([ok(IP_PAYLOAD)]);
  const result = await client.lookup("ip", "8.8.8.8");
  assert.equal(result.info.country, "United States");
  assert.deepEqual(result.sources_ok, ["ipwhois.app"]);
  const call = transport.calls[0];
  assert.equal(call.method, "GET");
  assert.equal(call.url, `${BASE}/api/lookup/ip/8.8.8.8`);
  assert.deepEqual(call.params, {});
  assert.equal(call.jsonBody, null);
});

test("kind shortcuts hit their endpoints and unknown kinds reject", async () => {
  const { client, transport } = makeClient([
    ok(IP_PAYLOAD),
    ok({ vin: "1M8GDM9AXKP042788", info: { wmi: "1M8" }, sources_ok: ["nhtsa"] }),
    ok({ app: "pypi:requests", info: { version: "2.31.0" }, sources_ok: ["pypi"] }),
  ]);
  await client.ip("8.8.8.8");
  await client.vin("1M8GDM9AXKP042788");
  await client.package("pypi:requests"); // alias of app
  assert.deepEqual(
    transport.urls(),
    [
      `${BASE}/api/lookup/ip/8.8.8.8`,
      `${BASE}/api/lookup/vin/1M8GDM9AXKP042788`,
      `${BASE}/api/lookup/app/pypi%3Arequests`,
    ],
  );
  await assert.rejects(() => client.lookup("nope", "x"), TypeError);
  // kind is normalised case-insensitively before the path is built
  const lower = makeClient([ok(IP_PAYLOAD)]);
  await lower.client.lookup("IP", "8.8.8.8");
  assert.equal(lower.transport.calls[0].url, `${BASE}/api/lookup/ip/8.8.8.8`);
});

test("KINDS carries the 20 kinds and TARGET_KEYS mirrors the server map", () => {
  assert.equal(KINDS.length, 20);
  assert.deepEqual([...KINDS].slice(0, 5), ["ip", "phone", "username", "email", "domain"]);
  for (const kind of KINDS) assert.ok(typeof TARGET_KEYS[kind] === "string");
  assert.equal(TARGET_KEYS.phone, "phone_number");
  assert.equal(TARGET_KEYS.crypto, "address");
  assert.equal(TARGET_KEYS.app, "app");
});

test("targets are percent-encoded in path segments", async () => {
  const { client, transport } = makeClient([
    ok({ coords: "48.8584, 2.2945", info: {}, sources_ok: [] }),
    ok({ plate: "DE:B-AB 1234", info: {}, sources_ok: [] }),
  ]);
  await client.coords("48.8584, 2.2945");
  await client.plate("DE:B-AB 1234");
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/lookup/coords/48.8584%2C%202.2945`,
    `${BASE}/api/lookup/plate/DE%3AB-AB%201234`,
  ]);
});

// ---------------------------------------------------------------------------
// Investigations / risk / correlation / timeline
// ---------------------------------------------------------------------------

test("investigate sends target and pivot as query params", async () => {
  const { client, transport } = makeClient([
    ok({ target: "evil.example.com", kind: "domain", entities: [], links: [] }),
    ok({ target: "evil.example.com", kind: "domain", entities: [], links: [] }),
  ]);
  await client.investigate("evil.example.com");
  await client.investigate("evil.example.com", { pivot: false });
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/investigate?target=evil.example.com&pivot=true`,
    `${BASE}/api/investigate?target=evil.example.com&pivot=false`,
  ]);
  assert.deepEqual(transport.calls[0].params, {
    target: "evil.example.com",
    pivot: true,
  });
});

test("risk hits GET /api/risk/{kind}/{target}", async () => {
  const { client, transport } = makeClient([
    ok({ ...IP_PAYLOAD, risk: { score: 42, verdict: "medium", signals: [], summary: "s" } }),
  ]);
  const report = await client.risk("domain", "example.com");
  assert.equal(report.risk.verdict, "medium");
  assert.equal(transport.calls[0].url, `${BASE}/api/risk/domain/example.com`);
  await assert.rejects(() => client.risk("nope", "x"), TypeError);
});

test("timeline sends limit always and target only when given", async () => {
  const { client, transport } = makeClient([
    ok({ events: [], count: 0, first: null, last: null }),
    ok({ events: [], count: 0, first: null, last: null }),
  ]);
  await client.timeline();
  await client.timeline({ target: "example.com", limit: 5 });
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/timeline?limit=100`,
    `${BASE}/api/timeline?limit=5&target=example.com`,
  ]);
});

test("correlate and correlatePair build the right queries", async () => {
  const { client, transport } = makeClient([
    ok({ entities: [], links: [], clusters: [], stats: {} }),
    ok({ entities: [], links: [], clusters: [], stats: {} }),
    ok({ targets: ["a.com", "b.com"], shared: [], connections: 0, related: false }),
  ]);
  await client.correlate();
  await client.correlate({ limit: 200 });
  await client.correlatePair("a.com", "b.com");
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/correlate`,
    `${BASE}/api/correlate?limit=200`,
    `${BASE}/api/correlate/pair?a=a.com&b=b.com`,
  ]);
});

test("intel hits GET /api/intel/{target}", async () => {
  const { client, transport } = makeClient([
    ok({ ip: "8.8.8.8", feeds: {}, tor_exit: false, relay: null }),
  ]);
  const verdict = await client.intel("8.8.8.8");
  assert.equal(verdict.tor_exit, false);
  assert.equal(transport.calls[0].url, `${BASE}/api/intel/8.8.8.8`);
});

// ---------------------------------------------------------------------------
// Sources / stats / registry / history
// ---------------------------------------------------------------------------

test("sources, stats and sourcesHealth hit GET /api/stats and /api/sources", async () => {
  const statsPayload = {
    database: { queries: 10 },
    cache: { hits: 5 },
    network: { requests: 7 },
    source_health: [{ source: "ipwhois.app", success_rate: 0.9 }],
  };
  const { client, transport } = makeClient([
    ok({ ip: { "ipwhois.app": "geo" } }),
    ok(statsPayload),
    ok(statsPayload),
  ]);
  await client.sources();
  await client.stats();
  const health = await client.sourcesHealth();
  assert.deepEqual(health, [{ source: "ipwhois.app", success_rate: 0.9 }]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/sources`,
    `${BASE}/api/stats`,
    `${BASE}/api/stats`,
  ]);
});

test("kinds and history hit their endpoints with the right params", async () => {
  const { client, transport } = makeClient([
    ok([{ kind: "ip", label: "IP address", sources: [], source_count: 0 }]),
    ok({ items: [], count: 0, limit: 50, kind: "ip", q: "8.8" }),
  ]);
  const kinds = await client.kinds();
  assert.equal(kinds.length, 1);
  assert.equal(kinds[0].kind, "ip");
  const history = await client.history({ kind: "ip", q: "8.8", limit: 50 });
  assert.equal(history.count, 0);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/kinds`,
    `${BASE}/api/history?limit=50&kind=ip&q=8.8`,
  ]);
  assert.deepEqual(transport.calls[1].params, { limit: 50, kind: "ip", q: "8.8" });
});

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

test("createCase posts {name, description} to /api/cases", async () => {
  const { client, transport } = makeClient([
    ok({ id: 1, name: "acme", description: "", status: "open" }, 201),
  ]);
  const created = await client.createCase("acme");
  assert.equal(created.id, 1);
  const call = transport.calls[0];
  assert.equal(call.method, "POST");
  assert.equal(call.url, `${BASE}/api/cases`);
  assert.deepEqual(call.jsonBody, { name: "acme", description: "" });
});

test("addCaseItem posts kind/target/note to /api/cases/{id}/items", async () => {
  const { client, transport } = makeClient([
    ok({ id: 9, case_id: 5, kind: "domain", target: "example.com" }, 201),
  ]);
  await client.addCaseItem(5, "example.com", { kind: "domain", note: "primary" });
  const call = transport.calls[0];
  assert.equal(call.method, "POST");
  assert.equal(call.url, `${BASE}/api/cases/5/items`);
  assert.deepEqual(call.jsonBody, {
    kind: "domain",
    target: "example.com",
    note: "primary",
  });
});

test("case CRUD verbs and bodies", async () => {
  const { client, transport } = makeClient([
    ok([{ id: 1, name: "acme" }]),
    ok({ id: 3, name: "acme", items: [] }),
    ok({ id: 3, name: "acme", status: "archived" }),
    ok({ id: 3, note: "done" }, 201),
    ok({ id: 3, tag: "phish" }, 201),
  ]);
  await client.cases();
  await client.case(3);
  await client.updateCase(3, "archived");
  await client.addCaseNote(3, "done");
  await client.addCaseTag(3, "phish");
  assert.deepEqual(transport.methods(), ["GET", "GET", "PATCH", "POST", "POST"]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/cases`,
    `${BASE}/api/cases/3`,
    `${BASE}/api/cases/3`,
    `${BASE}/api/cases/3/notes`,
    `${BASE}/api/cases/3/tags`,
  ]);
  assert.deepEqual(transport.calls[2].jsonBody, { status: "archived" });
  assert.deepEqual(transport.calls[3].jsonBody, { note: "done" });
  assert.deepEqual(transport.calls[4].jsonBody, { tag: "phish" });
});

// ---------------------------------------------------------------------------
// Watchlist / diff
// ---------------------------------------------------------------------------

test("addWatch posts target+label (and optional kind) to /api/watch", async () => {
  const { client, transport } = makeClient([
    ok({ id: 7 }, 201),
    ok({ id: 8 }, 201),
    ok({ id: 9 }, 201),
  ]);
  await client.addWatch("example.com", { label: "corp site" });
  await client.addWatch("8.8.8.8");
  await client.addWatch("a.com", { kind: "domain" });
  assert.deepEqual(transport.calls[0].jsonBody, {
    target: "example.com",
    label: "corp site",
  });
  assert.deepEqual(transport.calls[1].jsonBody, { target: "8.8.8.8", label: "" });
  assert.deepEqual(transport.calls[2].jsonBody, {
    target: "a.com",
    label: "",
    kind: "domain",
  });
});

test("removeWatch and checkWatch use the right verbs and params", async () => {
  const { client, transport } = makeClient([
    ok({ removed: 7 }),
    ok({ removed: "example.com" }),
    ok([{ watch_id: 1, changed_any: false }]),
    ok([{ watch_id: 2, changed_any: true }]),
  ]);
  await client.removeWatch(7);
  await client.removeWatch("example.com");
  await client.checkWatch();
  await client.checkWatch({ identifier: "example.com" });
  assert.deepEqual(transport.methods(), ["DELETE", "DELETE", "POST", "POST"]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/watch/7`,
    `${BASE}/api/watch/example.com`,
    `${BASE}/api/watch/check`,
    `${BASE}/api/watch/check?identifier=example.com`,
  ]);
  assert.deepEqual(transport.calls[2].params, {});
  assert.deepEqual(transport.calls[3].params, { identifier: "example.com" });
});

test("watch list and diff hit their endpoints", async () => {
  const { client, transport } = makeClient([
    ok([{ id: 1, target: "example.com", kind: "domain" }]),
    ok({ target: "example.com", kind: "domain", changed_any: false, added: {}, removed: {}, changed: {} }),
  ]);
  const entries = await client.watch();
  assert.equal(entries[0].target, "example.com");
  await client.diff("domain", "example.com");
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/watch`,
    `${BASE}/api/diff/domain/example.com`,
  ]);
});

// ---------------------------------------------------------------------------
// Settings / keys
// ---------------------------------------------------------------------------

test("settings, updateSetting, keys, setKey, clearKey", async () => {
  const { client, transport } = makeClient([
    ok({ settings: { "app.cache_ttl": 300 }, version: "6.1.0", note: "" }),
    ok({ ok: true, path: "app.cache_ttl", value: 300 }),
    ok([{ service: "shodan", configured: false, description: "" }]),
    ok({ ok: true, service: "shodan", configured: true }),
    ok({ ok: true, service: "shodan", configured: false }),
  ]);
  await client.settings();
  await client.updateSetting("app.cache_ttl", 300);
  await client.keys();
  await client.setKey("shodan", "abc123");
  await client.clearKey("shodan");
  assert.deepEqual(transport.methods(), ["GET", "POST", "GET", "POST", "DELETE"]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/settings`,
    `${BASE}/api/settings`,
    `${BASE}/api/keys`,
    `${BASE}/api/keys/shodan`,
    `${BASE}/api/keys/shodan`,
  ]);
  assert.deepEqual(transport.calls[1].jsonBody, { path: "app.cache_ttl", value: 300 });
  assert.deepEqual(transport.calls[3].jsonBody, { key: "abc123" });
});

// ---------------------------------------------------------------------------
// Toolbox
// ---------------------------------------------------------------------------

test("toolbox GET endpoints carry their query params", async () => {
  const { client, transport } = makeClient([
    ok({ text: "admin:password", encodings: {}, hashes: {} }),
    ok({ scheme: "auto", candidates: [] }),
    ok({ header: { alg: "HS256" }, payload: {} }),
    ok({ value: "44d88612fea8a8f36de82e1278abb02f", candidates: [] }),
  ]);
  await client.encode("admin:password");
  await client.decode("aGVsbG8=");
  await client.inspectJwt("e.y.z");
  await client.hashId("44d88612fea8a8f36de82e1278abb02f");
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/tools/encodings?text=admin%3Apassword`,
    `${BASE}/api/tools/decode`,
    `${BASE}/api/tools/jwt?token=e.y.z`,
    `${BASE}/api/tools/hash-id?value=44d88612fea8a8f36de82e1278abb02f`,
  ]);
  assert.deepEqual(transport.calls[1].jsonBody, { scheme: "auto", value: "aGVsbG8=" });
});

test("toolbox POST endpoints carry their bodies", async () => {
  const { client, transport } = makeClient([
    ok({ input: "48.8584, 2.2945", latitude: 48.8584, longitude: 2.2945 }),
    ok({ entities: { emails: [] }, summary: {} }),
    ok({ domain: "example.com", count: 0, variants: [] }),
  ]);
  await client.convertCoords("48.8584, 2.2945");
  await client.extractEntities("contact bob@evil.example");
  await client.squat("example.com");
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/tools/coords`,
    `${BASE}/api/tools/extract`,
    `${BASE}/api/tools/squat`,
  ]);
  assert.deepEqual(transport.calls[0].jsonBody, { value: "48.8584, 2.2945" });
  assert.deepEqual(transport.calls[1].jsonBody, {
    text: "contact bob@evil.example",
  });
  assert.deepEqual(transport.calls[2].jsonBody, { domain: "example.com" });
});

test("dorks sends target and optional kind query params", async () => {
  const { client, transport } = makeClient([
    ok({ target: "example.com", detected_kind: "domain", count: 2, dorks: [], dork_kinds: [] }),
    ok({ target: "example.com", detected_kind: null, count: 0, dorks: [], dork_kinds: [] }),
  ]);
  const report = await client.dorks("example.com", { kind: "domain" });
  assert.equal(report.detected_kind, "domain");
  await client.dorks("example.com");
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/tools/dorks?target=example.com&kind=domain`,
    `${BASE}/api/tools/dorks?target=example.com`,
  ]);
});

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------

test("analyticsStats posts values and bins", async () => {
  const { client, transport } = makeClient([
    ok({ count: 3, summary: {}, histogram: {} }),
  ]);
  await client.analyticsStats([1, 2, 3]);
  const call = transport.calls[0];
  assert.equal(call.method, "POST");
  assert.equal(call.url, `${BASE}/api/analytics/stats`);
  assert.deepEqual(call.jsonBody, { values: [1, 2, 3], bins: 10 });
});

test("analyticsAnomalies only sends threshold for the zscore method", async () => {
  const { client, transport } = makeClient([
    ok({ count: 3, method: "zscore", anomaly_count: 0, anomalies: [] }),
    ok({ count: 3, method: "mad", anomaly_count: 0, anomalies: [] }),
    ok({ count: 3, method: "ensemble", anomaly_count: 0, anomalies: [] }),
    ok({ count: 3, method: "ensemble", anomaly_count: 0, anomalies: [] }),
  ]);
  await client.analyticsAnomalies([1, 2, 100], { method: "zscore", threshold: 2.5 });
  await client.analyticsAnomalies([1, 2, 100], { method: "mad", threshold: 9 });
  await client.analyticsAnomalies([1, 2, 100], { threshold: 2 });
  await client.analyticsAnomalies([1, 2, 100]);
  assert.deepEqual(transport.calls[0].jsonBody, {
    values: [1, 2, 100],
    method: "zscore",
    threshold: 2.5,
  });
  assert.deepEqual(transport.calls[1].jsonBody, { values: [1, 2, 100], method: "mad" });
  assert.deepEqual(transport.calls[2].jsonBody, {
    values: [1, 2, 100],
    method: "ensemble",
  });
  assert.deepEqual(transport.calls[3].jsonBody, {
    values: [1, 2, 100],
    method: "ensemble",
  });
});

test("analyticsClusters posts points, eps_km and min_points", async () => {
  const { client, transport } = makeClient([
    ok({ point_count: 2, eps_km: 25, min_points: 3, cluster_count: 0, clusters: [] }),
  ]);
  await client.analyticsClusters(
    [
      [52.0, 13.0],
      [52.1, 13.1],
    ],
    { epsKm: 10, minPoints: 4 },
  );
  assert.deepEqual(transport.calls[0].jsonBody, {
    points: [
      [52, 13],
      [52.1, 13.1],
    ],
    eps_km: 10,
    min_points: 4,
  });
});

test("remaining analytics endpoints post their exact bodies", async () => {
  const { client, transport } = makeClient([
    ok({ count: 2, summary: {} }),
    ok({ keyword_count: 1, keywords: [] }),
    ok({ scripts: {}, guess: {} }),
    ok({ jaro_winkler: 1, mean: 1 }),
    ok({ entity_count: 1, link_count: 1, summary: {} }),
  ]);
  await client.analyticsTimeseries([5, 6, 5, 6, 20, 21]);
  await client.analyticsKeywords("the quick brown fox", 2);
  await client.analyticsLanguage("Le renard brun rapide");
  await client.analyticsSimilarity("paypal.com", "paypa1.com");
  await client.analyticsGraph([{ id: "a" }], [{ source: "a", target: "a" }]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/analytics/timeseries`,
    `${BASE}/api/analytics/keywords`,
    `${BASE}/api/analytics/language`,
    `${BASE}/api/analytics/similarity`,
    `${BASE}/api/analytics/graph`,
  ]);
  assert.deepEqual(transport.calls[0].jsonBody, { values: [5, 6, 5, 6, 20, 21] });
  assert.deepEqual(transport.calls[1].jsonBody, { text: "the quick brown fox", top: 2 });
  assert.deepEqual(transport.calls[2].jsonBody, { text: "Le renard brun rapide" });
  assert.deepEqual(transport.calls[3].jsonBody, { a: "paypal.com", b: "paypa1.com" });
  assert.deepEqual(transport.calls[4].jsonBody, {
    entities: [{ id: "a" }],
    links: [{ source: "a", target: "a" }],
  });
});

test("analyticsHistory is a GET with limit=500 by default", async () => {
  const { client, transport } = makeClient([ok({ total_queries: 0 })]);
  await client.analyticsHistory();
  assert.equal(transport.calls[0].method, "GET");
  assert.equal(transport.calls[0].url, `${BASE}/api/analytics/history?limit=500`);
  await client.analyticsHistory(100).catch(() => {});
  assert.equal(transport.calls[1].url, `${BASE}/api/analytics/history?limit=100`);
});

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

test("notifyChannels and notifyRecent hit their GET endpoints", async () => {
  const { client, transport } = makeClient([
    ok({ count: 0, channels: [], channel_types: ["webhook"], severities: ["info"] }),
    ok({ count: 0, recent: [] }),
    ok({ count: 0, recent: [] }),
  ]);
  const channels = await client.notifyChannels();
  assert.deepEqual(channels.channel_types, ["webhook"]);
  await client.notifyRecent();
  await client.notifyRecent(5);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/notify/channels`,
    `${BASE}/api/notify/recent?limit=20`,
    `${BASE}/api/notify/recent?limit=5`,
  ]);
});

test("addNotifyChannel drops undefined keys from the spec body", async () => {
  const { client, transport } = makeClient([
    ok({ ok: true, channel: { name: "team-chat", type: "telegram" } }),
    ok({ ok: true, channel: { name: "ops", type: "webhook" } }),
  ]);
  await client.addNotifyChannel({
    name: "team-chat",
    type: "telegram",
    target: "bot:chat",
    events: ["lookup"],
    min_severity: "low",
  });
  await client.addNotifyChannel({ name: "ops", type: "webhook" });
  assert.deepEqual(transport.calls[0].jsonBody, {
    name: "team-chat",
    type: "telegram",
    target: "bot:chat",
    events: ["lookup"],
    min_severity: "low",
  });
  assert.deepEqual(transport.calls[1].jsonBody, { name: "ops", type: "webhook" });
});

test("removeNotifyChannel percent-encodes the name; test posts to /test", async () => {
  const { client, transport } = makeClient([
    ok({ ok: true, removed: "team chat" }),
    ok({ ok: true, channel: "team-chat" }),
  ]);
  await client.removeNotifyChannel("team chat");
  await client.testNotifyChannel("team-chat");
  assert.deepEqual(transport.methods(), ["DELETE", "POST"]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/notify/channels/team%20chat`,
    `${BASE}/api/notify/channels/team-chat/test`,
  ]);
});

test("notifyBroadcast posts title/body/severity/event_type", async () => {
  const { client, transport } = makeClient([
    ok({ ok: true, sent: 2, skipped: 0, failed: 0, total: 2 }),
    ok({ ok: true, sent: 0, skipped: 1, failed: 0, total: 1 }),
  ]);
  const delivery = await client.notifyBroadcast({
    title: "watch diff",
    body: "example.com changed NS",
    severity: "high",
    eventType: "watch_diff",
  });
  assert.equal(delivery.sent, 2);
  await client.notifyBroadcast({ title: "t", body: "b" });
  assert.deepEqual(transport.calls[0].jsonBody, {
    title: "watch diff",
    body: "example.com changed NS",
    severity: "high",
    event_type: "watch_diff",
  });
  assert.deepEqual(transport.calls[1].jsonBody, {
    title: "t",
    body: "b",
    severity: "info",
    event_type: "manual",
  });
});

// ---------------------------------------------------------------------------
// Automation
// ---------------------------------------------------------------------------

test("automationTasks and automationNext are plain GETs", async () => {
  const { client, transport } = makeClient([
    ok({ count: 0, tasks: [], actions: ["watch_check"], schedule_types: ["interval"] }),
    ok({ count: 0, tasks: [] }),
  ]);
  const tasks = await client.automationTasks();
  assert.deepEqual(tasks.actions, ["watch_check"]);
  await client.automationNext();
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/automation/tasks`,
    `${BASE}/api/automation/next`,
  ]);
});

test("addAutomationTask drops undefined keys from the spec body", async () => {
  const { client, transport } = makeClient([
    ok({ ok: true, task: { name: "daily-watch", next_run: "2024-06-02T09:00:00" } }),
    ok({ ok: true, task: { name: "hourly", next_run: "" } }),
  ]);
  await client.addAutomationTask({
    name: "daily-watch",
    action: "watch_check",
    schedule: "daily",
    at_time: "09:00",
  });
  await client.addAutomationTask({ name: "hourly", action: "watch_check" });
  assert.deepEqual(transport.calls[0].jsonBody, {
    name: "daily-watch",
    action: "watch_check",
    schedule: "daily",
    at_time: "09:00",
  });
  assert.deepEqual(transport.calls[1].jsonBody, {
    name: "hourly",
    action: "watch_check",
  });
});

test("remove/run/run-due automation verbs and paths", async () => {
  const { client, transport } = makeClient([
    ok({ ok: true, removed: "daily-watch" }),
    ok({ ok: true, started: "t0", finished: "t1", error: "", summary: "checked 4" }),
    ok({ ran: 1, results: [{ task: "daily-watch", ok: true }] }),
  ]);
  await client.removeAutomationTask("daily-watch");
  const run = await client.runAutomationTask("daily-watch");
  assert.equal(run.summary, "checked 4");
  await client.runDueAutomation();
  assert.deepEqual(transport.methods(), ["DELETE", "POST", "POST"]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/automation/tasks/daily-watch`,
    `${BASE}/api/automation/tasks/daily-watch/run`,
    `${BASE}/api/automation/run-due`,
  ]);
});

// ---------------------------------------------------------------------------
// Sharing exports / patterns / batch / stream
// ---------------------------------------------------------------------------

test("exportStix and exportMisp hit their paths and validate kinds", async () => {
  const { client, transport } = makeClient([
    ok({ type: "bundle", id: "x", objects: [{ type: "indicator" }] }),
    ok({ Event: { info: "example.com", Attribute: [] } }),
  ]);
  const bundle = await client.exportStix("domain", "example.com");
  assert.equal(bundle.type, "bundle");
  const event = await client.exportMisp("ip", "8.8.8.8");
  assert.ok(event.Event);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/export/stix/domain/example.com`,
    `${BASE}/api/export/misp/ip/8.8.8.8`,
  ]);
  await assert.rejects(() => client.exportStix("nope", "x"), TypeError);
  await assert.rejects(() => client.exportMisp("nope", "x"), TypeError);
});

test("exportGraph, patterns and batch hit their endpoints", async () => {
  const { client, transport } = makeClient([
    ok({ target: "example.com", format: "graphml", graph: "<graphml/>", entities: 2, links: 1 }),
    ok({ kind: "domain", target: "example.com" }),
    ok({ kind: "ip", total: 1, ok: 1, failed: 0, results: [] }),
  ]);
  await client.exportGraph("graphml", "example.com");
  await client.patterns("domain", "example.com");
  await client.batch("ip", ["8.8.8.8"], { risk: true });
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/export/graphml/example.com?pivot=true`,
    `${BASE}/api/patterns?kind=domain&target=example.com`,
    `${BASE}/api/tools/batch`,
  ]);
  assert.deepEqual(transport.calls[2].jsonBody, {
    kind: "ip",
    targets: ["8.8.8.8"],
    risk: true,
  });
});

test("setStreamTopics normalises and posts the topic list", async () => {
  const { client, transport } = makeClient([
    ok({ topics: ["lookup", "watch"], count: 2, subscriber_count: 0 }),
    ok({ topics: ["lookup"], count: 1, subscriber_count: 0 }),
  ]);
  await client.setStreamTopics("lookup, watch");
  await client.setStreamTopics(["lookup"]);
  assert.deepEqual(transport.calls[0].jsonBody, { topics: ["lookup", "watch"] });
  assert.deepEqual(transport.calls[1].jsonBody, { topics: ["lookup"] });
  assert.equal(
    client.streamUrl({ topics: ["lookup", "watch"], maxEvents: 3 }),
    `${BASE}/api/stream?topics=lookup%2Cwatch&max_events=3`,
  );
  assert.equal(client.streamUrl(), `${BASE}/api/stream`);
});

// ---------------------------------------------------------------------------
// Escape hatches
// ---------------------------------------------------------------------------

test("rawGet/rawPost/rawDelete hit arbitrary paths", async () => {
  const { client, transport } = makeClient([
    ok({ found: false }),
    ok({ ok: true }),
    ok({ ok: true }),
    ok({ ok: true }),
  ]);
  await client.rawGet("/api/profile/ip/8.8.8.8", { limit: 200 });
  await client.rawPost("/api/alerts", { webhook_url: "http://x" });
  await client.rawDelete("/api/watch/7");
  await client.rawPost("api/alerts/test"); // leading slash added
  assert.deepEqual(transport.methods(), ["GET", "POST", "DELETE", "POST"]);
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/profile/ip/8.8.8.8?limit=200`,
    `${BASE}/api/alerts`,
    `${BASE}/api/watch/7`,
    `${BASE}/api/alerts/test`,
  ]);
  assert.deepEqual(transport.calls[1].jsonBody, { webhook_url: "http://x" });
});

// ---------------------------------------------------------------------------
// Retry / backoff / error mapping
// ---------------------------------------------------------------------------

test("TransportError is retried and then succeeds (2 calls, 1 sleep)", async () => {
  const { client, transport, sleeps } = makeClient(
    [new TransportError("connection reset"), ok(IP_PAYLOAD)],
    { retries: 2, backoffMs: 500 },
  );
  const result = await client.lookup("ip", "8.8.8.8");
  assert.equal(result.info.country, "United States");
  assert.equal(transport.calls.length, 2);
  assert.deepEqual(sleeps, [500]);
});

test("TimeoutError is retried with doubling backoff", async () => {
  const { client, transport, sleeps } = makeClient(
    [new TimeoutError("t1"), new TimeoutError("t2"), ok(IP_PAYLOAD)],
    { retries: 3, backoffMs: 100 },
  );
  await client.lookup("ip", "8.8.8.8");
  assert.equal(transport.calls.length, 3);
  assert.deepEqual(sleeps, [100, 200]);
});

test("RateLimitError with Retry-After sleeps the header value, not the backoff", async () => {
  const { client, transport, sleeps } = makeClient(
    [err(429, "slow down", { "Retry-After": "2" }), ok(IP_PAYLOAD)],
    { retries: 2, backoffMs: 500 },
  );
  const result = await client.lookup("ip", "8.8.8.8");
  assert.equal(result.success, true);
  assert.equal(transport.calls.length, 2);
  assert.deepEqual(sleeps, [2000]);
});

test("RateLimitError without Retry-After falls back to the backoff", async () => {
  const { client, sleeps } = makeClient(
    [err(429, "slow down"), ok(IP_PAYLOAD)],
    { retries: 2, backoffMs: 250 },
  );
  await client.lookup("ip", "8.8.8.8");
  assert.deepEqual(sleeps, [250]);
});

test("transport errors exhaust the retry budget and reject the last error", async () => {
  const { client, transport, sleeps } = makeClient(
    [new TransportError("e1"), new TransportError("e2"), new TransportError("e3")],
    { retries: 3, backoffMs: 500 },
  );
  await assert.rejects(() => client.lookup("ip", "8.8.8.8"), TransportError);
  assert.equal(transport.calls.length, 3);
  assert.deepEqual(sleeps, [500, 1000]); // no sleep before the final throw
});

test("HTTP 400 is not retried and rejects with BadRequestError + detail", async () => {
  const { client, transport, sleeps } = makeClient([err(400, "unknown kind")], {
    retries: 3,
    backoffMs: 500,
  });
  await assert.rejects(
    () => client.lookup("iban", "not-an-iban"),
    (error) => {
      assert.ok(error instanceof BadRequestError);
      assert.ok(error instanceof ApiError);
      assert.equal(error.message, "unknown kind");
      assert.equal(error.status, 400);
      assert.equal(error.detail, "unknown kind");
      assert.deepEqual(error.body, { detail: "unknown kind" });
      return true;
    },
  );
  assert.equal(transport.calls.length, 1);
  assert.deepEqual(sleeps, []);
});

test("HTTP 404 maps to NotFoundError and is not retried", async () => {
  const { client, transport } = makeClient([err(404, "not found")], { retries: 3 });
  await assert.rejects(() => client.case(999), NotFoundError);
  assert.equal(transport.calls.length, 1);
});

test("HTTP 500 maps to ServerError and is not retried", async () => {
  const { client, transport } = makeClient([err(500, "report failed")], { retries: 3 });
  await assert.rejects(() => client.diff("domain", "x"), ServerError);
  assert.equal(transport.calls.length, 1);
});

test("odd statuses map to the generic ApiError", async () => {
  const { client } = makeClient([err(418, "teapot")]);
  await assert.rejects(
    () => client.stats(),
    (error) => error instanceof ApiError && !(error instanceof BadRequestError),
  );
});

test("non-JSON 2xx bodies reject with MalformedResponseError", async () => {
  const { client } = makeClient([
    { status: 200, statusText: "OK", headers: {}, text: "<html>not json</html>" },
  ]);
  await assert.rejects(
    () => client.stats(),
    (error) => {
      assert.ok(error instanceof MalformedResponseError);
      assert.equal(error.status, 200);
      assert.ok(error.bodyText.includes("<html>"));
      return true;
    },
  );
});

test("StaticTransport script exhaustion fails loudly", async () => {
  const { client } = makeClient([], { retries: 1 });
  await assert.rejects(() => client.health(), TransportError);
});

test("buildUrl joins base, path and params like the client does", () => {
  assert.equal(buildUrl("http://x:1/", "/api/stats"), "http://x:1/api/stats");
  assert.equal(
    buildUrl("http://x:1", "/api/lookup/ip/8.8.8.8", { pivot: true }),
    "http://x:1/api/lookup/ip/8.8.8.8?pivot=true",
  );
  assert.equal(
    buildUrl("http://x:1", "/a", { q: "a b", skip: null }),
    "http://x:1/a?q=a%20b",
  );
});

// ---------------------------------------------------------------------------
// End-to-end smoke: FetchTransport against a REAL local HTTP server
// ---------------------------------------------------------------------------

test("end-to-end smoke against a real node:http server", async () => {
  const seenRequests = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seenRequests.push({
        method: req.method,
        url: req.url,
        body: body ? JSON.parse(body) : null,
        accept: req.headers.accept,
        userAgent: req.headers["user-agent"],
      });
      res.setHeader("Content-Type", "application/json");
      if (req.method === "GET" && req.url === "/api/health") {
        res.end(JSON.stringify({ status: "ok", version: "6.1.0-test" }));
      } else if (req.method === "GET" && req.url === "/api/lookup/ip/8.8.8.8") {
        res.end(JSON.stringify(IP_PAYLOAD));
      } else if (req.method === "GET" && req.url === "/api/notify/channels") {
        res.end(
          JSON.stringify({
            count: 1,
            channels: [{ name: "ops", type: "webhook" }],
            channel_types: ["webhook"],
            severities: ["info", "low"],
          }),
        );
      } else if (req.method === "POST" && req.url === "/api/notify/broadcast") {
        res.end(
          JSON.stringify({ ok: true, sent: 1, skipped: 0, failed: 0, total: 1 }),
        );
      } else {
        res.statusCode = 404;
        res.end(JSON.stringify({ detail: "no such route" }));
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const client = new ObscuraLensClient({
    baseUrl: `http://127.0.0.1:${port}/`,
    retries: 2,
    timeoutMs: 5000,
  });
  try {
    const health = await client.health();
    assert.equal(health.status, "ok");
    assert.equal(health.version, "6.1.0-test");

    const ip = await client.ip("8.8.8.8");
    assert.equal(ip.info.asn, "AS15169");
    assert.deepEqual(ip.sources_failed, { ipinfo: "401" });

    const channels = await client.notifyChannels();
    assert.equal(channels.count, 1);
    assert.equal(channels.channels[0].name, "ops");

    const delivery = await client.notifyBroadcast({
      title: "smoke",
      body: "hello",
      severity: "high",
    });
    assert.equal(delivery.sent, 1);

    await assert.rejects(() => client.case(999), NotFoundError);

    const broadcast = seenRequests.find((r) => r.url === "/api/notify/broadcast");
    assert.deepEqual(broadcast.body, {
      title: "smoke",
      body: "hello",
      severity: "high",
      event_type: "manual",
    });
    const lookup = seenRequests.find((r) => r.url === "/api/lookup/ip/8.8.8.8");
    assert.equal(lookup.accept, "application/json");
    assert.ok(lookup.userAgent.startsWith("obscuralens-sdk/"));
    assert.equal(await client.ping(), true);
  } finally {
    client.close();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("FetchTransport maps real timeouts to TimeoutError", async () => {
  const server = createServer((req, res) => {
    setTimeout(() => res.end("{}"), 500); // slower than the client timeout
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const client = new ObscuraLensClient({
    baseUrl: `http://127.0.0.1:${port}`,
    retries: 1,
    timeoutMs: 60,
  });
  try {
    await assert.rejects(() => client.health(), TimeoutError);
  } finally {
    client.close();
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
});
