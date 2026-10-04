/**
 * Error hierarchy tests: construction defaults, the `detail` getter,
 * `errorForResponse` status mapping and `Retry-After` parsing — mirroring
 * the Python SDK's exceptions contract.
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  SdkError,
  TransportError,
  TimeoutError,
  ApiError,
  BadRequestError,
  NotFoundError,
  RateLimitError,
  ServerError,
  MalformedResponseError,
  errorForResponse,
  parseRetryAfterMs,
} from "../dist/index.js";

test("SdkError carries message, status, statusText, body and requestUrl", () => {
  const error = new SdkError("boom", {
    status: 503,
    statusText: "Service Unavailable",
    body: { detail: "maintenance" },
    requestUrl: "http://x/api/stats",
  });
  assert.equal(error.message, "boom");
  assert.equal(error.status, 503);
  assert.equal(error.statusText, "Service Unavailable");
  assert.deepEqual(error.body, { detail: "maintenance" });
  assert.equal(error.requestUrl, "http://x/api/stats");
  assert.equal(error.detail, "maintenance");
  assert.equal(error.toString(), "SdkError: boom (HTTP 503)");
  assert.ok(error instanceof Error);
});

test("SdkError defaults are partial-information safe", () => {
  const error = new SdkError("boom");
  assert.equal(error.status, undefined);
  assert.equal(error.statusText, "");
  assert.equal(error.body, null);
  assert.equal(error.requestUrl, undefined);
  assert.equal(error.detail, null);
  assert.equal(error.toString(), "SdkError: boom");
});

test("the hierarchy maps where a failure happens", () => {
  assert.ok(new TransportError("x") instanceof SdkError);
  assert.ok(new TimeoutError("x") instanceof SdkError);
  assert.ok(new ApiError("x", { status: 418 }) instanceof SdkError);
  assert.ok(new BadRequestError("x") instanceof ApiError);
  assert.ok(new NotFoundError("x") instanceof ApiError);
  assert.ok(new RateLimitError("x") instanceof ApiError);
  assert.ok(new ServerError("x") instanceof ApiError);
  assert.ok(new MalformedResponseError("x") instanceof SdkError);
  assert.equal(new BadRequestError("x").status, 400);
  assert.equal(new NotFoundError("x").status, 404);
  assert.equal(new RateLimitError("x").status, 429);
  assert.equal(new ServerError("x").status, 500);
});

test("TimeoutError carries the timeout in milliseconds", () => {
  const error = new TimeoutError("timed out", { timeoutMs: 2500 });
  assert.equal(error.timeoutMs, 2500);
  assert.equal(error.status, undefined);
});

test("RateLimitError defaults retryAfterMs to null", () => {
  const error = new RateLimitError("slow down");
  assert.equal(error.retryAfterMs, null);
  const withRetry = new RateLimitError("slow down", { retryAfterMs: 2000 });
  assert.equal(withRetry.retryAfterMs, 2000);
});

test("MalformedResponseError keeps the raw body text", () => {
  const error = new MalformedResponseError("non-JSON response", {
    status: 200,
    bodyText: "<html>",
  });
  assert.equal(error.bodyText, "<html>");
  assert.equal(error.status, 200);
});

test("errorForResponse maps 400 to BadRequestError with the body detail", () => {
  const error = errorForResponse(
    { status: 400, statusText: "Bad Request", headers: {} },
    '{"detail": "unknown kind"}',
    "http://x/api/lookup/nope/1",
  );
  assert.ok(error instanceof BadRequestError);
  assert.equal(error.message, "unknown kind");
  assert.equal(error.status, 400);
  assert.equal(error.statusText, "Bad Request");
  assert.deepEqual(error.body, { detail: "unknown kind" });
  assert.equal(error.requestUrl, "http://x/api/lookup/nope/1");
});

test("errorForResponse maps 404 and 5xx to their classes", () => {
  const missing = errorForResponse({ status: 404, headers: {} }, '{"detail": "not found"}');
  assert.ok(missing instanceof NotFoundError);
  assert.equal(missing.message, "not found");

  const server = errorForResponse({ status: 502, headers: {} }, '{"detail": "bad gateway"}');
  assert.ok(server instanceof ServerError);
  assert.equal(server.status, 502);

  const teapot = errorForResponse({ status: 418, headers: {} }, '{"detail": "teapot"}');
  assert.ok(teapot instanceof ApiError);
  assert.ok(!(teapot instanceof BadRequestError));
  assert.ok(!(teapot instanceof NotFoundError));
  assert.ok(!(teapot instanceof RateLimitError));
  assert.ok(!(teapot instanceof ServerError));
});

test("errorForResponse parses Retry-After (case-insensitive) into milliseconds", () => {
  const error = errorForResponse(
    { status: 429, headers: { "retry-after": "2" } },
    '{"detail": "slow down"}',
  );
  assert.ok(error instanceof RateLimitError);
  assert.equal(error.retryAfterMs, 2000);

  const none = errorForResponse({ status: 429, headers: {} }, '{"detail": "slow"}');
  assert.equal(none.retryAfterMs, null);

  const httpDate = errorForResponse(
    { status: 429, headers: { "Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT" } },
    '{"detail": "slow"}',
  );
  assert.equal(httpDate.retryAfterMs, null);
});

test("errorForResponse falls back to HTTP status text without JSON detail", () => {
  const noBody = errorForResponse({ status: 404, statusText: "Not Found", headers: {} }, "");
  assert.equal(noBody.message, "HTTP 404 Not Found");
  assert.equal(noBody.body, null);

  const nonJson = errorForResponse({ status: 400, headers: {} }, "plain text");
  assert.ok(nonJson instanceof BadRequestError);
  assert.equal(nonJson.body, null);
  assert.equal(nonJson.message, "HTTP 400");

  const nonStringDetail = errorForResponse({ status: 400, headers: {} }, '{"detail": 42}');
  assert.equal(nonStringDetail.message, "42");

  const listBody = errorForResponse({ status: 400, headers: {} }, "[1, 2]");
  assert.equal(listBody.body, null);
});

test("parseRetryAfterMs handles numeric, junk, negative and missing values", () => {
  assert.equal(parseRetryAfterMs({ "Retry-After": "5" }), 5000);
  assert.equal(parseRetryAfterMs({ "retry-after": " 1.5 " }), 1500);
  assert.equal(parseRetryAfterMs({ "Retry-After": "soon" }), null);
  assert.equal(parseRetryAfterMs({ "Retry-After": "-3" }), null);
  assert.equal(parseRetryAfterMs({}), null);
  assert.equal(parseRetryAfterMs(null), null);
  assert.equal(parseRetryAfterMs(undefined), null);
});

test("error names survive subclassing for instanceof checks", () => {
  const errors = [
    new TransportError("x"),
    new TimeoutError("x"),
    new ApiError("x", { status: 418 }),
    new BadRequestError("x"),
    new NotFoundError("x"),
    new RateLimitError("x"),
    new ServerError("x"),
    new MalformedResponseError("x"),
  ];
  for (const error of errors) {
    assert.ok(error instanceof SdkError, `${error.name} should be an SdkError`);
    assert.ok(error instanceof Error, `${error.name} should be an Error`);
  }
  assert.equal(new TransportError("x").name, "TransportError");
  assert.equal(new TimeoutError("x").name, "TimeoutError");
  assert.equal(new BadRequestError("x").name, "BadRequestError");
});
