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
/** SDK version stamped into the default `User-Agent` header. */
export declare const SDK_VERSION = "6.1.0";
/** Default `User-Agent` sent with every SDK request. */
export declare const SDK_USER_AGENT = "obscuralens-sdk/6.1.0";
/** Header name for the optional session API key (`X-API-Key`). */
export declare const API_KEY_HEADER = "X-API-Key";
/**
 * One immutable HTTP response.
 *
 * Non-2xx statuses are *returned*, not thrown — the client maps them onto
 * SDK errors (see `errorForResponse`).
 */
export interface HttpResponse {
    /** The HTTP status code. */
    status: number;
    /** The HTTP reason phrase ("OK", "Created", "Not Found"). */
    statusText: string;
    /** Response headers as a plain string record (repeats comma-joined). */
    headers: Record<string, string>;
    /** The raw response body as text. */
    text: string;
}
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
export declare function jsonResponse(status: number, payload: unknown, headers?: Record<string, string>, statusText?: string): HttpResponse;
/**
 * Case-insensitive header lookup.
 *
 * @param headers - the response headers record.
 * @param name - header name to find (case-insensitive).
 * @returns The header value, or `null` when absent.
 */
export declare function headerValue(headers: Record<string, string> | null | undefined, name: string): string | null;
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
export declare function buildQuery(params?: Record<string, unknown> | null): string;
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
export declare function buildUrl(baseUrl: string, path: string, params?: Record<string, unknown> | null): string;
/**
 * Minimal structural type for a `fetch`-like function — the global `fetch`
 * satisfies it, and tests can supply their own.
 */
export type FetchLike = (url: string, init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
}) => Promise<{
    status: number;
    statusText: string;
    headers: {
        forEach(callback: (value: string, key: string) => void): void;
    };
    text(): Promise<string>;
}>;
/** The transport contract every SDK client sends requests through. */
export interface Transport {
    /**
     * Perform one HTTP request.
     *
     * @param method - HTTP verb (GET/POST/PATCH/DELETE...).
     * @param url - absolute URL, query string already appended.
     * @param headers - request headers to send (never `undefined`).
     * @param params - the query parameters before encoding (supplied for
     *   logging/recording; the URL already contains the encoded form).
     * @param jsonBody - a JSON-serialisable request body, or `null`.
     * @returns A response for *every* HTTP status — non-2xx statuses are
     *   returned, not rejected; the client maps them to SDK errors.
     * @throws {@link import("./errors.js").TransportError} when no HTTP
     *   response could be obtained.
     * @throws {@link import("./errors.js").TimeoutError} when the attempt
     *   timed out.
     */
    request(method: string, url: string, headers?: Record<string, string>, params?: Record<string, unknown> | null, jsonBody?: unknown): Promise<HttpResponse>;
    /** Release any underlying resources (default: nothing to release). */
    close(): void;
}
/** Options for {@link FetchTransport}. */
export interface FetchTransportOptions {
    /** Default per-request timeout in milliseconds (default 30,000). */
    timeoutMs?: number | null;
    /** Injectable `fetch` implementation (defaults to the global `fetch`). */
    fetchFn?: FetchLike;
    /** Headers merged into every request (caller headers win on conflict). */
    defaultHeaders?: Record<string, string>;
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
export declare class FetchTransport implements Transport {
    /** Default per-request timeout in milliseconds (`null` = no timeout). */
    readonly timeoutMs: number | null;
    /** The `fetch`-like function used for every request. */
    readonly fetchFn: FetchLike;
    /** Headers merged into every request. */
    readonly defaultHeaders: Record<string, string>;
    private closed;
    constructor(options?: FetchTransportOptions);
    request(method: string, url: string, headers?: Record<string, string>, _params?: Record<string, unknown> | null, jsonBody?: unknown): Promise<HttpResponse>;
    /** Mark the transport closed; further requests throw TransportError. */
    close(): void;
}
/** A queued {@link StaticTransport} item: a canned response or an error to throw. */
export type TransportScriptItem = HttpResponse | Error;
/** One recorded {@link StaticTransport} call. */
export interface RecordedCall {
    /** HTTP verb the client asked for (uppercase). */
    method: string;
    /** Absolute URL the client built (query string included). */
    url: string;
    /** Pre-encoded query parameters (recorded verbatim; `{}` when none). */
    params: Record<string, unknown>;
    /** The JSON body the client serialised, or `null`. */
    jsonBody: unknown;
    /** The request headers the client merged. */
    headers: Record<string, string>;
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
export declare class StaticTransport implements Transport {
    /** The scripted outcomes, consumed in order. */
    script: TransportScriptItem[];
    /** When `true`, the final script item repeats forever once reached. */
    repeatLast: boolean;
    /** Every call received, in order. */
    calls: RecordedCall[];
    /** Flipped by {@link StaticTransport.close} (recorded calls are kept). */
    closed: boolean;
    constructor(script?: TransportScriptItem[], repeatLast?: boolean);
    /** Append more scripted outcomes (responses or errors); chainable. */
    enqueue(...items: TransportScriptItem[]): this;
    /** Pop the next scripted item without recording a call. */
    nextItem(): TransportScriptItem | null;
    request(method: string, url: string, headers?: Record<string, string>, params?: Record<string, unknown> | null, jsonBody?: unknown): Promise<HttpResponse>;
    /** Flip the closed flag (recorded calls are kept for asserts). */
    close(): void;
    /** The most recent recorded call, or `null` when none yet. */
    get lastCall(): RecordedCall | null;
    /** The recorded URLs in call order. */
    urls(): string[];
    /** The recorded HTTP verbs in call order. */
    methods(): string[];
    /** Case-insensitive header lookup on one recorded call. */
    headerOf(callIndex: number, name: string): string | null;
}
