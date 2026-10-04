/**
 * HTTP transports for the ObscuraLens JavaScript SDK.
 *
 * The SDK never talks to the network directly — every call goes through a
 * {@link Transport} object that turns `(method, url, headers, params,
 * jsonBody)` into an {@link HttpResponse}. Two implementations ship:
 *
 * - {@link FetchTransport} — the production transport, built on the global
 *   `fetch` (Node 18+/browsers/deno) with `AbortSignal.timeout` timeouts.
 *   A custom `fetchFn` can be injected for tests or proxies.
 * - {@link StaticTransport} — an in-memory test double. Load it with a queue
 *   of canned {@link HttpResponse} objects (or `Error` instances to throw),
 *   and it records every call it receives in `.calls` so tests can assert on
 *   the exact method/URL/params/body.
 *
 * Custom transports (axios, undici, a caching proxy...) only need to
 * implement `request()` and (optionally) `close()`.
 *
 * @module obscuralens-sdk/transport
 */
import { TimeoutError, TransportError, } from "./errors.js";
/** SDK version stamped into the default `User-Agent` header. */
export const SDK_VERSION = "6.1.0";
/** Default `User-Agent` sent with every SDK request. */
export const SDK_USER_AGENT = `obscuralens-sdk/${SDK_VERSION}`;
/** Header name for the optional session API key (`X-API-Key`). */
export const API_KEY_HEADER = "X-API-Key";
/**
 * Build a canned JSON success/error response (the `Response.from_json`
 * equivalent from the Python SDK).
 *
 * @param status - HTTP status code (200/201/400/404...).
 * @param payload - any JSON-serialisable value.
 * @param headers - optional response headers.
 * @param statusText - optional reason phrase (default "OK").
 *
 * @example
 * ```js
 * const response = jsonResponse(200, { status: "ok" });
 * response.text; // '{"status":"ok"}'
 * ```
 */
export function jsonResponse(status, payload, headers = {}, statusText = status >= 200 && status < 300 ? "OK" : "") {
    return { status, statusText, headers, text: JSON.stringify(payload) };
}
/**
 * Case-insensitive header lookup.
 *
 * @param headers - the response headers record.
 * @param name - header name to find (case-insensitive).
 * @returns The header value, or `null` when absent.
 */
export function headerValue(headers, name) {
    if (!headers)
        return null;
    const lowered = name.toLowerCase();
    for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === lowered)
            return headers[key];
    }
    return null;
}
/**
 * Encode query parameters into a query string (without `?`).
 *
 * `null`/`undefined` values are skipped, arrays repeat the key and booleans
 * are emitted as lowercase `true`/`false` (FastAPI-friendly). Spaces are
 * percent-encoded (`%20`) and unicode values are UTF-8 encoded —
 * `user@example.com` and `48.8584, 2.2945` survive the round trip.
 *
 * @param params - query parameter names to values.
 * @returns The encoded query string (`""` when empty).
 */
export function buildQuery(params) {
    if (!params)
        return "";
    const pairs = [];
    for (const [rawKey, value] of Object.entries(params)) {
        if (value === null || value === undefined)
            continue;
        const key = encodeURIComponent(String(rawKey));
        if (Array.isArray(value)) {
            for (const item of value) {
                if (item === null || item === undefined)
                    continue;
                pairs.push([key, encodeValue(item)]);
            }
        }
        else {
            pairs.push([key, encodeValue(value)]);
        }
    }
    return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}
/** Encode one scalar query value (booleans lowercase). */
function encodeValue(value) {
    if (typeof value === "boolean")
        return value ? "true" : "false";
    return encodeURIComponent(String(value));
}
/**
 * Join a base URL, a path and query parameters into one URL.
 *
 * @param baseUrl - server root, with or without a trailing slash (a path
 *   prefix such as `http://host/obscuralens` is kept).
 * @param path - absolute path starting with `/`.
 * @param params - optional query parameters.
 * @returns The fully-joined URL (query string appended when non-empty).
 *
 * @example
 * ```js
 * buildUrl("http://x:1/", "/api/stats"); // "http://x:1/api/stats"
 * ```
 */
export function buildUrl(baseUrl, path, params) {
    const base = String(baseUrl || "").replace(/\/+$/, "");
    let suffix = String(path || "");
    if (!suffix.startsWith("/"))
        suffix = `/${suffix}`;
    const url = `${base}${suffix}`;
    const query = buildQuery(params);
    return query ? `${url}?${query}` : url;
}
/**
 * Production transport built on the global `fetch` (Node 18+, browsers).
 *
 * Timeouts use `AbortSignal.timeout` when available; a fetch rejection with
 * a `TimeoutError`/`AbortError` DOMException maps to
 * {@link import("./errors.js").TimeoutError} and network `TypeError`s map to
 * {@link import("./errors.js").TransportError}.
 *
 * @example
 * ```js
 * const transport = new FetchTransport({ timeoutMs: 10_000 });
 * const client = new ObscuraLensClient({ transport });
 * ```
 */
export class FetchTransport {
    /** Default per-request timeout in milliseconds (`null` = no timeout). */
    timeoutMs;
    /** The `fetch`-like function used for every request. */
    fetchFn;
    /** Headers merged into every request. */
    defaultHeaders;
    closed = false;
    constructor(options = {}) {
        this.timeoutMs =
            options.timeoutMs === undefined ? 30_000 : options.timeoutMs;
        this.fetchFn =
            options.fetchFn ??
                ((url, init) => fetch(url, init));
        this.defaultHeaders = { ...(options.defaultHeaders ?? {}) };
    }
    async request(method, url, headers, _params, jsonBody) {
        if (this.closed) {
            throw new TransportError("transport is closed", { requestUrl: url });
        }
        const merged = {
            Accept: "application/json",
            ...this.defaultHeaders,
            ...(headers ?? {}),
        };
        const init = { method: String(method || "GET").toUpperCase(), headers: merged };
        if (jsonBody !== undefined && jsonBody !== null) {
            init.body = JSON.stringify(jsonBody);
        }
        if (this.timeoutMs !== null && this.timeoutMs > 0) {
            init.signal = makeTimeoutSignal(this.timeoutMs);
        }
        let response;
        try {
            response = await this.fetchFn(url, init);
        }
        catch (error) {
            throw transportErrorOf(error, this.timeoutMs ?? undefined, url);
        }
        return {
            status: response.status,
            statusText: response.statusText ?? "",
            headers: flattenHeaders(response.headers),
            text: await response.text(),
        };
    }
    /** Mark the transport closed; further requests throw TransportError. */
    close() {
        this.closed = true;
    }
}
/** Build an abort signal that fires after `ms` milliseconds, when supported. */
function makeTimeoutSignal(ms) {
    const candidate = AbortSignal;
    if (typeof candidate.timeout === "function") {
        return candidate.timeout(ms);
    }
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms);
    return controller.signal;
}
/** Flatten a `Headers`-like object into a plain record. */
function flattenHeaders(headers) {
    const flat = {};
    headers.forEach((value, key) => {
        const lower = key.toLowerCase();
        flat[lower] = flat[lower] === undefined ? value : `${flat[lower]}, ${value}`;
    });
    return flat;
}
/** Map one fetch rejection onto the right SDK transport error. */
function transportErrorOf(error, timeoutMs, url) {
    if (error instanceof TransportError || error instanceof TimeoutError) {
        return error;
    }
    const name = error !== null && typeof error === "object" && "name" in error
        ? String(error.name)
        : "";
    const message = error instanceof Error ? error.message : String(error ?? "unknown error");
    if (name === "TimeoutError" || name === "AbortError") {
        return new TimeoutError(`request timed out after ${timeoutMs ?? "?"}ms: ${url}`, { timeoutMs, requestUrl: url });
    }
    return new TransportError(`connection failed: ${message}`, {
        requestUrl: url,
    });
}
/**
 * In-memory transport for tests — a programmable fake server.
 *
 * Preload a list of {@link HttpResponse} objects and/or `Error` instances;
 * each `request` pops the next item (responses resolve, errors reject).
 * Every call is recorded in {@link StaticTransport.calls} so tests can
 * assert on the exact endpoint a client method hit.
 *
 * When the script runs dry the transport throws
 * {@link import("./errors.js").TransportError} so a missing expectation
 * fails loudly instead of silently repeating.
 *
 * @example
 * ```js
 * const transport = new StaticTransport([jsonResponse(200, { ok: 1 })]);
 * const client = new ObscuraLensClient({ transport });
 * await client.health();
 * transport.calls[0].url; // "http://127.0.0.1:8000/api/health"
 * ```
 */
export class StaticTransport {
    /** The scripted outcomes, consumed in order. */
    script;
    /** When `true`, the final script item repeats forever once reached. */
    repeatLast;
    /** Every call received, in order. */
    calls = [];
    /** Flipped by {@link StaticTransport.close} (recorded calls are kept). */
    closed = false;
    constructor(script = [], repeatLast = false) {
        this.script = [...script];
        this.repeatLast = repeatLast;
    }
    /** Append more scripted outcomes (responses or errors); chainable. */
    enqueue(...items) {
        this.script.push(...items);
        return this;
    }
    /** Pop the next scripted item without recording a call. */
    nextItem() {
        if (this.script.length === 0)
            return null;
        if (this.script.length === 1 && this.repeatLast)
            return this.script[0];
        return this.script.shift() ?? null;
    }
    async request(method, url, headers, params, jsonBody) {
        this.calls.push({
            method: String(method || "GET").toUpperCase(),
            url: String(url),
            params: { ...(params ?? {}) },
            jsonBody: jsonBody === undefined ? null : jsonBody,
            headers: { ...(headers ?? {}) },
        });
        if (this.closed) {
            throw new TransportError("transport is closed", { requestUrl: url });
        }
        const item = this.nextItem();
        if (item === null) {
            throw new TransportError(`StaticTransport script exhausted — no response queued for ${method} ${url}`, { requestUrl: url });
        }
        if (item instanceof Error)
            throw item;
        return item;
    }
    /** Flip the closed flag (recorded calls are kept for asserts). */
    close() {
        this.closed = true;
    }
    /** The most recent recorded call, or `null` when none yet. */
    get lastCall() {
        return this.calls.length ? this.calls[this.calls.length - 1] : null;
    }
    /** The recorded URLs in call order. */
    urls() {
        return this.calls.map((call) => call.url);
    }
    /** The recorded HTTP verbs in call order. */
    methods() {
        return this.calls.map((call) => call.method);
    }
    /** Case-insensitive header lookup on one recorded call. */
    headerOf(callIndex, name) {
        const call = this.calls[callIndex];
        if (!call)
            return null;
        return headerValue(call.headers, name);
    }
}
