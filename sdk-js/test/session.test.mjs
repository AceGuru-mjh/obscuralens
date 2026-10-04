/**
 * InvestigationSession tests — step recording, error capture, strict mode,
 * summaries and the JSON receipt round-trip, all offline via
 * StaticTransport.
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  ObscuraLensClient,
  StaticTransport,
  jsonResponse,
  InvestigationSession,
  SessionStep,
  RECEIPT_FORMAT,
  BadRequestError,
} from "../dist/index.js";

const BASE = "http://127.0.0.1:8000";

function ok(payload, status = 200) {
  return jsonResponse(status, payload);
}

function err(status, detail = "boom") {
  return jsonResponse(status, { detail });
}

const IP_PAYLOAD = {
  ip: "8.8.8.8",
  info: { country: "United States" },
  field_sources: {},
  sources_ok: ["ipwhois.app", "ipwho.is"],
  sources_failed: {},
  field_count: 5,
  success: true,
};

function makeClient(script = []) {
  const transport = new StaticTransport(script);
  const client = new ObscuraLensClient({ baseUrl: BASE, transport, retries: 1 });
  return { client, transport };
}

test("session records a step for every recorded action", async () => {
  const { client } = makeClient([
    ok(IP_PAYLOAD),
    ok({ target: "evil.example.com", kind: "domain", entities: [{ id: "a" }], links: [] }),
    ok({ ...IP_PAYLOAD, risk: { score: 42, verdict: "medium", signals: [], summary: "" } }),
    ok({ target: "evil.example.com", detected_kind: "domain", count: 3, dorks: [], dork_kinds: [] }),
  ]);
  const session = new InvestigationSession(client, { label: "phishing-2024" });

  const ip = await session.lookup("ip", "8.8.8.8");
  assert.equal(ip.info.country, "United States");
  await session.investigate("evil.example.com");
  await session.risk("domain", "evil.example.com");
  await session.dorks("evil.example.com");
  session.note("victim reported 2024-05-01");

  assert.equal(session.stepCount, 5);
  assert.equal(session.okCount, 5);
  assert.equal(session.failedCount, 0);
  const actions = session.allSteps.map((step) => step.action);
  assert.deepEqual(actions, ["lookup", "investigate", "risk", "dorks", "note"]);
  assert.equal(session.step(0).target, "8.8.8.8");
  assert.equal(session.step(0).ok, true);
  assert.equal(session.step(0).durationMs >= 0, true);
  assert.equal(session.step(1).detail, "1 entit(ies), 0 link(s)");
  assert.equal(session.step(2).detail, "score 42 (medium)");
  assert.equal(session.step(3).detail, "3 dork(s) for domain");
  assert.equal(session.step(4).target, "");
  assert.ok(session.step(4).detail.includes("victim reported"));
});

test("session records lookup details with field and source counts", async () => {
  const { client } = makeClient([ok(IP_PAYLOAD)]);
  const session = new InvestigationSession(client);
  await session.lookup("ip", "8.8.8.8");
  assert.equal(session.step(0).detail, "ip: 5 field(s) from 2 source(s)");
});

test("targets() keeps first-seen order without duplicates (notes excluded)", async () => {
  const { client } = makeClient([
    ok(IP_PAYLOAD),
    ok({ target: "evil.example.com", kind: "domain", entities: [], links: [] }),
    ok(IP_PAYLOAD),
  ]);
  const session = new InvestigationSession(client);
  await session.lookup("ip", "8.8.8.8");
  await session.investigate("evil.example.com");
  session.note("no target here");
  await session.lookup("ip", "8.8.8.8"); // duplicate
  assert.deepEqual(session.targets(), ["8.8.8.8", "evil.example.com"]);
  assert.deepEqual(session.notesTaken, ["no target here"]);
});

test("non-strict sessions capture errors as data and continue", async () => {
  const { client } = makeClient([
    ok(IP_PAYLOAD),
    err(400, "invalid domain"),
    ok({ target: "example.com", detected_kind: "domain", count: 0, dorks: [], dork_kinds: [] }),
  ]);
  const session = new InvestigationSession(client);
  const good = await session.lookup("ip", "8.8.8.8");
  assert.equal(good.success, true);
  const failed = await session.lookup("domain", "!!!bad");
  assert.equal(failed, undefined); // captured, not thrown
  await session.dorks("example.com"); // the investigation continues

  assert.equal(session.stepCount, 3);
  assert.equal(session.okCount, 2);
  assert.equal(session.failedCount, 1);
  const failedStep = session.step(1);
  assert.equal(failedStep.ok, false);
  assert.equal(failedStep.error, "BadRequestError: invalid domain");
  assert.equal(failedStep.target, "!!!bad");
  // failed lookups still count as touched targets
  assert.deepEqual(session.targets(), ["8.8.8.8", "!!!bad", "example.com"]);
});

test("strict sessions record the failing step and then re-throw", async () => {
  const { client } = makeClient([err(400, "unknown kind")]);
  const session = new InvestigationSession(client, { strict: true });
  await assert.rejects(() => session.lookup("domain", "!!!bad"), BadRequestError);
  assert.equal(session.stepCount, 1);
  assert.equal(session.step(0).ok, false);
  assert.equal(session.step(0).error, "BadRequestError: unknown kind");
  assert.equal(session.step(0).target, "!!!bad");
});

test("summary() reports counts, targets and step headlines", async () => {
  const { client } = makeClient([
    ok(IP_PAYLOAD),
    err(400, "invalid domain"),
  ]);
  const session = new InvestigationSession(client, { label: "demo" });
  await session.lookup("ip", "8.8.8.8");
  await session.lookup("domain", "!!!bad").catch(() => {});
  session.note("checked twice");
  const text = session.summary();
  assert.ok(text.includes("session demo: 3 step(s), 2 ok, 1 failed, 2 target(s)"));
  assert.ok(text.includes("targets: 8.8.8.8, !!!bad"));
  assert.ok(text.includes("ok   lookup 8.8.8.8"));
  assert.ok(text.includes("FAIL lookup !!!bad"));
  assert.ok(text.includes("notes (1):"));
  assert.ok(text.includes("- checked twice"));
});

test("toObject/toJSON round-trip is stable", async () => {
  const { client } = makeClient([ok(IP_PAYLOAD), err(400, "invalid domain")]);
  const session = new InvestigationSession(client, { label: "rt" });
  await session.lookup("ip", "8.8.8.8");
  await session.lookup("domain", "!!!bad").catch(() => {});
  session.note("round trip");

  const receipt = session.toObject();
  assert.equal(receipt.format, RECEIPT_FORMAT);
  assert.equal(receipt.label, "rt");
  assert.deepEqual(receipt.counts, { steps: 3, ok: 2, failed: 1, targets: 2 });
  assert.deepEqual(receipt.targets, ["8.8.8.8", "!!!bad"]);
  assert.deepEqual(receipt.notes, ["round trip"]);
  assert.equal(receipt.steps.length, 3);
  assert.equal(receipt.steps[1].ok, false);

  const parsed = JSON.parse(session.toJSON());
  assert.deepEqual(parsed, receipt);

  const compact = session.toJSON(0);
  assert.ok(!compact.includes("\n"));
  assert.deepEqual(JSON.parse(compact), receipt);

  const wide = session.toJSON(4);
  assert.ok(wide.includes("\n    "));
  assert.deepEqual(JSON.parse(wide), receipt);
});

test("SessionStep.fromRecord rebuilds a step from its receipt record", () => {
  const step = new SessionStep("lookup", "8.8.8.8", true, "", 12.5, "ip: 5 field(s)");
  const record = step.toRecord();
  assert.deepEqual(record, {
    action: "lookup",
    target: "8.8.8.8",
    ok: true,
    error: "",
    durationMs: 12.5,
    detail: "ip: 5 field(s)",
    at: step.at,
  });
  const rebuilt = SessionStep.fromRecord(record);
  assert.equal(rebuilt.action, "lookup");
  assert.equal(rebuilt.target, "8.8.8.8");
  assert.equal(rebuilt.ok, true);
  assert.equal(rebuilt.durationMs, 12.5);
  // junk input yields defaults instead of throwing
  const junk = SessionStep.fromRecord({});
  assert.equal(junk.action, "");
  assert.equal(junk.ok, false);
});

test("session close blocks further actions; toString is debuggable", async () => {
  const { client } = makeClient([ok(IP_PAYLOAD)]);
  const session = new InvestigationSession(client);
  await session.lookup("ip", "8.8.8.8");
  session.close();
  assert.throws(() => session.note("too late"), /session is closed/);
  await assert.rejects(() => session.lookup("ip", "8.8.8.8"), /session is closed/);
  assert.ok(session.toString().includes("steps=1"));
  assert.ok(session.toString().includes("closed"));
  // closing the session never closes the client
  assert.equal(client.transport.closed, false);
});

test("session only calls public client methods (composition, no transport)", async () => {
  const { client, transport } = makeClient([
    ok(IP_PAYLOAD),
    ok({ target: "evil.example.com", kind: "domain", entities: [], links: [] }),
  ]);
  const session = new InvestigationSession(client, { label: "comp" });
  await session.lookup("ip", "8.8.8.8");
  await session.investigate("evil.example.com");
  assert.deepEqual(transport.urls(), [
    `${BASE}/api/lookup/ip/8.8.8.8`,
    `${BASE}/api/investigate?target=evil.example.com&pivot=true`,
  ]);
});
