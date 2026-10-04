/**
 * Error hierarchy for the ObscuraLens JavaScript/TypeScript SDK.
 *
 * Every error raised (rejected) by {@link import("./client.js").ObscuraLensClient}
 * derives from {@link SdkError}, so callers can guard a whole session with a
 * single `catch`:
 *
 * ```js
 * import { ObscuraLensClient, SdkError } from "obscuralens-sdk";
 *
 * const client = new ObscuraLensClient({ baseUrl: "http://127.0.0.1:8000" });
 * try {
 *   const result = await client.ip("8.8.8.8");
 * } catch (error) {
 *   if (error instanceof SdkError) {
 *     console.log(`lookup failed: ${error.message} (status=${error.status})`);
 *   }
 * }
 * ```
 *
 * The hierarchy mirrors where a failure happens (and mirrors the Python SDK's
 * `obscuralens.sdk.exceptions` module):
 *
 * - {@link TransportError} / {@link TimeoutError} — the request never produced
 *   an HTTP response (DNS failure, refused connection, aborted fetch). These
 *   are the errors the client retries.
 * - {@link ApiError} plus {@link BadRequestError}, {@link NotFoundError},
 *   {@link RateLimitError}, {@link ServerError} — the server answered with a
 *   non-2xx status. The parsed JSON body is preserved on `.body`.
 * - {@link MalformedResponseError} — a 2xx response whose body was not the
 *   JSON the SDK expected.
 *
 * All errors are safe to construct with partial information: `.status` is
 * `undefined` for connection-level failures and `.body` is `null` when the
 * response body could not be parsed as JSON.
 *
 * @module obscuralens-sdk/errors
 */
/** Options bag accepted by every SDK error constructor. */
export interface SdkErrorOptions {
    /** HTTP status code when a response was received, else `undefined`. */
    status?: number;
    /** HTTP reason phrase ("OK", "Not Found") when a response was received. */
    statusText?: string;
    /** Parsed JSON body of the error response when available. */
    body?: Record<string, unknown> | null;
    /** The URL the failing request was sent to (diagnostics). */
    requestUrl?: string;
}
/**
 * Base class for every error raised by the ObscuraLens SDK.
 *
 * @example
 * ```js
 * try {
 *   await client.lookup("ip", "8.8.8.8");
 * } catch (error) {
 *   if (error instanceof SdkError) console.log(error.status, error.body);
 * }
 * ```
 */
export declare class SdkError extends Error {
    /** HTTP status code when a response was received, else `undefined`. */
    readonly status?: number;
    /** HTTP reason phrase when a response was received, else `""`. */
    readonly statusText: string;
    /** Parsed JSON body when the response was JSON, else `null`. */
    readonly body: Record<string, unknown> | null;
    /** The URL the request was sent to, when known. */
    readonly requestUrl?: string;
    constructor(message: string, options?: SdkErrorOptions);
    /**
     * The server's `detail` string from a JSON error body, or `null`.
     *
     * ObscuraLens error bodies are `{"detail": "..."}` — this getter surfaces
     * that string without poking at `.body` manually.
     */
    get detail(): string | null;
    /** Debug representation: `SdkError: message (HTTP 404)`. */
    toString(): string;
}
/**
 * The request could not be delivered or no response arrived.
 *
 * Raised for DNS failures, refused connections and any other connection-level
 * problem reported by the transport. The client retries requests that fail
 * with this error (up to `retries` attempts) before letting it propagate.
 */
export declare class TransportError extends SdkError {
    constructor(message: string, options?: SdkErrorOptions);
}
/**
 * The request timed out before a response arrived.
 *
 * A connection-level failure with no HTTP status; the client retries it with
 * exponential backoff. `.timeoutMs` carries the timeout that was in effect.
 */
export declare class TimeoutError extends SdkError {
    /** The timeout value (milliseconds) that was in effect, when known. */
    readonly timeoutMs?: number;
    constructor(message: string, options?: SdkErrorOptions & {
        timeoutMs?: number;
    });
}
/**
 * The server answered with a non-2xx HTTP status.
 *
 * The body is parsed as JSON when possible and stored on `.body`; the
 * `detail` string is used as the error message.
 */
export declare class ApiError extends SdkError {
    constructor(message: string, options: SdkErrorOptions & {
        status: number;
    });
}
/**
 * HTTP 400 — invalid kind, failed target validation or a bad body.
 *
 * Endpoint: every `/api` route that validates its input.
 */
export declare class BadRequestError extends ApiError {
    constructor(message: string, options?: SdkErrorOptions);
}
/**
 * HTTP 404 — unknown resource id (case, watch entry, channel, task...).
 *
 * Endpoints: `/api/cases/{id}`, `/api/watch/{id}`, `/api/notify/channels/{name}`,
 * `/api/automation/tasks/{name}`, `/api/export/stix|fisp/{kind}/{target}`...
 */
export declare class NotFoundError extends ApiError {
    constructor(message: string, options?: SdkErrorOptions);
}
/**
 * HTTP 429 — the server (or a proxy in front of it) applied rate limiting.
 *
 * `.retryAfterMs` carries the server's `Retry-After` header in milliseconds
 * when the header was numeric; the client honours it before retrying
 * (sleeping exactly that long instead of the computed backoff). Non-numeric
 * `Retry-After` values (HTTP dates) are not computed — the normal backoff
 * applies instead.
 */
export declare class RateLimitError extends ApiError {
    /** Milliseconds to wait before the next attempt, or `null`. */
    readonly retryAfterMs: number | null;
    constructor(message: string, options?: SdkErrorOptions & {
        retryAfterMs?: number | null;
    });
}
/**
 * HTTP 5xx — the server itself failed (report build, corrupt snapshot data...).
 *
 * Endpoints: `/api/diff/{kind}/{target}` (corrupt snapshots),
 * `/api/report/{kind}/{target}` (report build failure), `/api/keys/{service}`
 * (unwritable secrets file)...
 */
export declare class ServerError extends ApiError {
    constructor(message: string, options?: SdkErrorOptions);
}
/**
 * A 2xx response whose body could not be parsed as JSON.
 *
 * The SDK expects JSON from every endpoint it models, so a non-JSON success
 * body rejects with this error instead of returning garbage. The raw body
 * text (truncated) is kept on `.bodyText` for diagnostics.
 */
export declare class MalformedResponseError extends SdkError {
    /** The raw response body as text (truncated to 2,000 characters). */
    readonly bodyText: string;
    constructor(message: string, options?: SdkErrorOptions & {
        bodyText?: string;
    });
}
/**
 * The minimal response shape the error factory needs (the SDK's
 * {@link import("./transport.js").HttpResponse} satisfies it).
 */
export interface ErrorResponseLike {
    /** HTTP status code. */
    status: number;
    /** HTTP reason phrase, when available. */
    statusText?: string;
    /** Response headers as a plain string record (case varies). */
    headers?: Record<string, string>;
}
/**
 * Parse a numeric `Retry-After` header (case-insensitive).
 *
 * @param headers - response headers as a plain record.
 * @returns Milliseconds to wait, or `null` when absent/non-numeric (an
 *   HTTP-date value is not computed — the normal backoff applies instead).
 */
export declare function parseRetryAfterMs(headers: Record<string, string> | undefined | null): number | null;
/**
 * Map one non-2xx response onto the right SDK error — the factory the
 * client's retry pipeline uses, mirroring the Python SDK's hierarchy.
 *
 * @param response - the offending response (status, headers, reason phrase).
 * @param bodyText - the raw response body text (parsed as JSON best-effort).
 * @param url - the request URL, recorded on the error for diagnostics.
 * @returns The error instance to reject with (never thrown here):
 *   400 → {@link BadRequestError}, 404 → {@link NotFoundError},
 *   429 → {@link RateLimitError} (with `retryAfterMs` from `Retry-After`),
 *   5xx → {@link ServerError}, anything else → {@link ApiError}.
 *
 * @example
 * ```js
 * const error = errorForResponse(
 *   { status: 400, headers: {} },
 *   '{"detail": "unknown kind"}',
 *   "http://127.0.0.1:8000/api/lookup/nope/1",
 * );
 * error instanceof BadRequestError; // true
 * error.message;                    // "unknown kind"
 * ```
 */
export declare function errorForResponse(response: ErrorResponseLike, bodyText: string, url?: string): ApiError;
