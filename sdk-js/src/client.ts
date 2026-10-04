/**
 * ObscuraLensClient — the asynchronous JavaScript/TypeScript client for the
 * ObscuraLens REST API (v6.x).
 *
 * Every method maps one endpoint from `obscuralens/web/app.py`; the JSDoc on
 * each method names that endpoint. Responses come back as parsed JSON typed
 * with the interfaces from {@link module:obscuralens-sdk/types} — the server
 * is the contract, so unknown keys simply pass through.
 *
 * ```js
 * import { ObscuraLensClient } from "obscuralens-sdk";
 *
 * const client = new ObscuraLensClient({
 *   baseUrl: "http://127.0.0.1:8000",
 *   retries: 3,
 * });
 * const ip = await client.ip("8.8.8.8");
 * console.log(ip.info.country, ip.sources_ok);
 * await client.close();
 * ```
 *
 * Requests failing with `TransportError`, `TimeoutError` or `RateLimitError`
 * are retried with exponential backoff (500 ms doubling, capped at 30 s);
 * `Retry-After` headers are honoured exactly. Other HTTP errors reject
 * immediately with the mapped SDK error.
 *
 * @module obscuralens-sdk/client
 */

import {
  MalformedResponseError,
  RateLimitError,
  SdkError,
  TimeoutError,
  TransportError,
  errorForResponse,
} from "./errors.js";
import {
  API_KEY_HEADER,
  FetchTransport,
  SDK_VERSION,
  Transport,
  buildUrl,
  type FetchLike,
} from "./transport.js";
import {
  KINDS,
  type AnalyticsResult,
  type AutomationAddResult,
  type AutomationNext,
  type AutomationRunDue,
  type AutomationRunResult,
  type AutomationTaskSpec,
  type AutomationTasks,
  type BatchProgress,
  type Case,
  type CorrelationResult,
  type DiffReport,
  type DorkReport,
  type GraphExport,
  type HistoryResult,
  type IntelVerdict,
  type InvestigationReport,
  type KeyMutationResult,
  type KindInfo,
  type LookupEnvelope,
  type LookupKind,
  type NotifyAddResult,
  type NotifyBroadcastSpec,
  type NotifyChannelSpec,
  type NotifyChannels,
  type NotifyDelivery,
  type NotifyRecent,
  type PairComparison,
  type PatternReport,
  type RemoveResult,
  type RiskReport,
  type ServiceKey,
  type SettingsUpdateResult,
  type SettingsView,
  type SourceHealthEntry,
  type SourceInfo,
  type StatsSummary,
  type StixBundle,
  type StreamTopicsResult,
  type MispEvent,
  type Timeline,
  type ToolboxResult,
  type WatchAddResult,
  type WatchDiff,
  type WatchEntry,
} from "./types.js";

/** Default server address (matches `obscuralens serve` defaults). */
export const DEFAULT_BASE_URL = "http://127.0.0.1:8000";

/** Default per-request timeout (milliseconds). */
export const DEFAULT_TIMEOUT_MS = 30_000;

/** Default total attempts per request (one try plus up to two retries). */
export const DEFAULT_RETRIES = 3;

/** Default retry backoff base (milliseconds); doubles per attempt. */
export const DEFAULT_BACKOFF_MS = 500;

/** Upper bound for any single computed backoff sleep (milliseconds). */
export const DEFAULT_MAX_BACKOFF_MS = 30_000;

/** Export formats accepted by `GET /api/export/{fmt}/{target}`. */
export const EXPORT_FORMATS: readonly string[] = [
  "graphml", "gexf", "dot", "jsonl", "csv",
];

/** Valid case statuses for `updateCase` (PATCH /api/cases/{id}). */
export const CASE_STATUSES: readonly string[] = ["open", "closed", "archived"];

/** Constructor options for {@link ObscuraLensClient}. */
export interface ClientOptions {
  /**
   * Scheme + host + port of the server, with or without a trailing slash.
   * A path prefix such as `http://host/obscuralens` is preserved.
   * @default "http://127.0.0.1:8000"
   */
  baseUrl?: string;
  /**
   * Optional session API key sent as an `X-API-Key` header on every request.
   * The stock server ignores it (no built-in auth), but authenticating
   * reverse proxies and the `OBSCURALENS_API_KEY` deployment pattern honour
   * it. Leave `undefined` for a plain local server.
   */
  apiKey?: string;
  /**
   * Per-request timeout in milliseconds (`null` disables the timeout).
   * @default 30000
   */
  timeoutMs?: number | null;
  /**
   * Maximum number of attempts per request *including the first*. Requests
   * failing with `TransportError`, `TimeoutError` or `RateLimitError` are
   * retried; other HTTP errors reject immediately.
   * @default 3
   */
  retries?: number;
  /**
   * Base sleep between retries in milliseconds — the delay is
   * `backoffMs * 2 ** attempt`, capped at `maxBackoffMs`.
   * @default 500
   */
  backoffMs?: number;
  /** Ceiling for the exponential backoff sleep. @default 30000 */
  maxBackoffMs?: number;
  /** Custom transport; when omitted a {@link FetchTransport} is built. */
  transport?: Transport;
  /** Injectable `fetch` for the default {@link FetchTransport} (tests). */
  fetchFn?: FetchLike;
  /** Injectable sleeper used between retries (tests record the delays). */
  sleepFn?: (ms: number) => void | Promise<void>;
}

/** Per-request options used by the private request pipeline. */
interface RequestOptions {
  params?: Record<string, unknown> | null;
  jsonBody?: unknown;
}

/** Verify `kind` is one of the 20 known kinds, else throw a TypeError. */
function requireKind(kind: string): LookupKind {
  const normalized = String(kind ?? "")
    .trim()
    .toLowerCase();
  if ((KINDS as readonly string[]).includes(normalized)) {
    return normalized as LookupKind;
  }
  throw new TypeError(
    `unknown kind ${JSON.stringify(kind)} — expected one of ${KINDS.join(", ")}`,
  );
}

/**
 * The asynchronous client for the ObscuraLens REST API.
 *
 * All methods reject with {@link module:obscuralens-sdk/errors.SdkError}
 * subclasses; see each method's JSDoc for the endpoint it calls.
 */
export class ObscuraLensClient {
  /** Normalised server root (no trailing slash). */
  public readonly baseUrl: string;
  /** Session API key (or `null`) — sent as `X-API-Key`. */
  public readonly apiKey: string | null;
  /** Per-request timeout in milliseconds (`null` = no timeout). */
  public readonly timeoutMs: number | null;
  /** Total attempts per request including the first. */
  public readonly retries: number;
  /** Retry backoff base in milliseconds (doubles per attempt). */
  public readonly backoffMs: number;
  /** Ceiling for one computed backoff sleep in milliseconds. */
  public readonly maxBackoffMs: number;
  /** The transport this client sends requests through. */
  public readonly transport: Transport;
  private readonly sleepFn: (ms: number) => void | Promise<void>;
  private closed = false;

  constructor(options: ClientOptions = {}) {
    const base = String(options.baseUrl ?? DEFAULT_BASE_URL)
      .trim()
      .replace(/\/+$/, "");
    let parsed: URL;
    try {
      parsed = new URL(base);
    } catch {
      throw new TypeError(
        `baseUrl must look like http://host:port — got ${JSON.stringify(options.baseUrl)}`,
      );
    }
    if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname) {
      throw new TypeError(
        `baseUrl must look like http://host:port — got ${JSON.stringify(options.baseUrl)}`,
      );
    }
    this.baseUrl = base;
    this.apiKey = options.apiKey ?? null;
    this.timeoutMs =
      options.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : options.timeoutMs;
    this.retries = Math.max(1, Math.floor(options.retries ?? DEFAULT_RETRIES));
    this.backoffMs = Math.max(0, options.backoffMs ?? DEFAULT_BACKOFF_MS);
    this.maxBackoffMs = Math.max(
      0,
      options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS,
    );
    this.sleepFn =
      options.sleepFn ??
      ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    this.transport =
      options.transport ??
      new FetchTransport({
        timeoutMs: this.timeoutMs,
        fetchFn: options.fetchFn,
      });
  }

  // ------------------------------------------------------------------
  // Lifecycle
  // ------------------------------------------------------------------

  /**
   * Close the underlying transport and mark the client closed.
   *
   * Idempotent; further requests reject with `TransportError`. `await
   * client.close()` in a `finally` block, or use `Symbol.asyncDispose`
   * (`await using`) on runtimes that provide it (Node 20+).
   */
  close(): void {
    this.closed = true;
    this.transport.close();
  }

  /** Debug representation with base URL, SDK version and state. */
  toString(): string {
    const state = this.closed ? "closed" : "open";
    return `<ObscuraLensClient ${this.baseUrl} sdk=${SDK_VERSION} ${state}>`;
  }

  // ------------------------------------------------------------------
  // Request plumbing (retry / backoff / error mapping)
  // ------------------------------------------------------------------

  private baseHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": `obscuralens-sdk/${SDK_VERSION}`,
    };
    if (this.apiKey) headers[API_KEY_HEADER] = this.apiKey;
    return headers;
  }

  /** Exponential backoff for one attempt index (0-based), capped. */
  private backoffDelay(attempt: number): number {
    return Math.min(this.backoffMs * 2 ** attempt, this.maxBackoffMs);
  }

  /** The retry delay for one attempt: backoff, unless Retry-After wins. */
  private delayFor(attempt: number, error: SdkError): number {
    if (error instanceof RateLimitError && error.retryAfterMs !== null) {
      return error.retryAfterMs;
    }
    return this.backoffDelay(attempt);
  }

  private sleep(ms: number): Promise<void> {
    if (!(ms > 0)) return Promise.resolve();
    return Promise.resolve(this.sleepFn(ms)).then(() => undefined);
  }

  /** Percent-encode one path segment (slashes, colons, commas...). */
  private static encodeSegment(value: unknown): string {
    return encodeURIComponent(String(value));
  }

  /** Build an API path from a `{0}`/`{1}` template and encoded segments. */
  private path(template: string, ...segments: unknown[]): string {
    return template.replace(/\{(\d+)\}/g, (_match, index: string) =>
      ObscuraLensClient.encodeSegment(segments[Number(index)]),
    );
  }

  /**
   * Perform one request with retries; resolve with the raw 2xx response.
   *
   * Retries `TransportError`, `TimeoutError` and `RateLimitError` (sleeping
   * `Retry-After` milliseconds when the server sent one, else the
   * exponential backoff) up to `retries` total attempts. Non-2xx statuses
   * reject with the mapped SDK error on the final attempt.
   */
  private async send(
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<import("./transport.js").HttpResponse> {
    if (this.closed) {
      throw new TransportError("client is closed", { requestUrl: this.baseUrl });
    }
    const url = buildUrl(this.baseUrl, path, options.params ?? null);
    const headers = this.baseHeaders();
    for (let attempt = 0; attempt < this.retries; attempt += 1) {
      const final = attempt + 1 >= this.retries;
      let response: import("./transport.js").HttpResponse;
      try {
        response = await this.transport.request(
          method,
          url,
          headers,
          options.params ?? null,
          options.jsonBody ?? null,
        );
      } catch (error) {
        if (
          error instanceof RateLimitError ||
          error instanceof TransportError ||
          error instanceof TimeoutError
        ) {
          if (final) throw error;
          await this.sleep(this.delayFor(attempt, error));
          continue;
        }
        throw error;
      }
      if (response.status >= 200 && response.status < 300) return response;
      const error = errorForResponse(response, response.text, url);
      if (error instanceof RateLimitError && !final) {
        await this.sleep(this.delayFor(attempt, error));
        continue;
      }
      throw error;
    }
    throw new TransportError(
      `${method} ${path}: no response after ${this.retries} attempt(s)`,
      { requestUrl: url },
    );
  }

  /**
   * Perform one request and resolve with the parsed JSON.
   *
   * @throws {@link module:obscuralens-sdk/errors.MalformedResponseError}
   *   when a 2xx body is not valid JSON.
   */
  private async requestJson(
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<unknown> {
    const response = await this.send(method, path, options);
    try {
      return JSON.parse(response.text);
    } catch {
      const excerpt = response.text.slice(0, 200);
      throw new MalformedResponseError(
        `non-JSON response from ${method} ${path}: ${JSON.stringify(excerpt)}`,
        {
          status: response.status,
          statusText: response.statusText,
          bodyText: response.text.slice(0, 2000),
          requestUrl: buildUrl(this.baseUrl, path, options.params ?? null),
        },
      );
    }
  }

  /** Coerce a JSON payload into a list (junk → empty array). */
  private static asList(payload: unknown): unknown[] {
    return Array.isArray(payload) ? payload : [];
  }

  // ------------------------------------------------------------------
  // Liveness
  // ------------------------------------------------------------------

  /**
   * Check that the server is reachable and answering.
   *
   * Endpoint: `GET /api/health` — any successful response means `true`.
   * Never rejects with SDK errors — connection failures, timeouts and HTTP
   * errors resolve `false`. A dead server still burns the retry budget (use
   * a small `retries` value when pinging aggressively).
   */
  async ping(): Promise<boolean> {
    try {
      await this.requestJson("GET", "/api/health");
      return true;
    } catch (error) {
      if (error instanceof SdkError) return false;
      throw error;
    }
  }

  /**
   * Liveness probe with the server's package version.
   *
   * Endpoint: `GET /api/health` → `{status: "ok", version: "6.1.0"}`.
   */
  async health(): Promise<{ status: string; version: string }> {
    const payload = await this.requestJson("GET", "/api/health");
    return (payload && typeof payload === "object"
      ? payload
      : {}) as { status: string; version: string };
  }

  // ------------------------------------------------------------------
  // Lookups (20 kinds)
  // ------------------------------------------------------------------

  /**
   * Run the tracker for one kind — the core lookup endpoint.
   *
   * Endpoint: `GET /api/lookup/{kind}/{target}` — returns the standard
   * envelope: `info` (merged fields), `field_sources` (per-field provenance),
   * `sources_ok` / `sources_failed`, `field_count`, `confidence` (v6.1).
   *
   * @throws TypeError when `kind` is not one of the 20 kinds.
   * @throws BadRequestError when the target fails server-side validation.
   */
  async lookup(kind: LookupKind | string, target: string): Promise<LookupEnvelope> {
    const safeKind = requireKind(kind);
    const path = this.path("/api/lookup/{0}/{1}", safeKind, target);
    const payload = await this.requestJson("GET", path);
    return payload as LookupEnvelope;
  }

  /** `GET /api/lookup/ip/{target}` — geo, ASN, reverse DNS, threat intel. */
  async ip(target: string): Promise<LookupEnvelope> {
    return this.lookup("ip", target);
  }

  /** `GET /api/lookup/phone/{target}` — E.164, carrier hints, geo. */
  async phone(target: string): Promise<LookupEnvelope> {
    return this.lookup("phone", target);
  }

  /** `GET /api/lookup/username/{target}` — 45 platforms, 3-state verdicts. */
  async username(target: string): Promise<LookupEnvelope> {
    return this.lookup("username", target);
  }

  /** `GET /api/lookup/email/{target}` — breaches, reputation, profiles. */
  async email(target: string): Promise<LookupEnvelope> {
    return this.lookup("email", target);
  }

  /** `GET /api/lookup/domain/{target}` — registration, DNS, CT logs. */
  async domain(target: string): Promise<LookupEnvelope> {
    return this.lookup("domain", target);
  }

  /** `GET /api/lookup/url/{target}` — redirects, urlscan, safety verdicts. */
  async url(target: string): Promise<LookupEnvelope> {
    return this.lookup("url", target);
  }

  /** `GET /api/lookup/crypto/{target}` — BTC/ETH/LTC/DOGE balances. */
  async crypto(target: string): Promise<LookupEnvelope> {
    return this.lookup("crypto", target);
  }

  /** `GET /api/lookup/hash/{target}` — malware family, detections. */
  async hash(target: string): Promise<LookupEnvelope> {
    return this.lookup("hash", target);
  }

  /** `GET /api/lookup/cve/{target}` — CVSS, products, EPSS. */
  async cve(target: string): Promise<LookupEnvelope> {
    return this.lookup("cve", target);
  }

  /** `GET /api/lookup/asn/{target}` — holder, prefixes, peers. */
  async asn(target: string): Promise<LookupEnvelope> {
    return this.lookup("asn", target);
  }

  /** `GET /api/lookup/mac/{target}` — IEEE OUI vendor lookup. */
  async mac(target: string): Promise<LookupEnvelope> {
    return this.lookup("mac", target);
  }

  /** `GET /api/lookup/iban/{target}` — checksum, bank, country. */
  async iban(target: string): Promise<LookupEnvelope> {
    return this.lookup("iban", target);
  }

  /** `GET /api/lookup/imei/{target}` — TAC, manufacturer, Luhn. */
  async imei(target: string): Promise<LookupEnvelope> {
    return this.lookup("imei", target);
  }

  /** `GET /api/lookup/coords/{target}` — every format + reverse geocode. */
  async coords(target: string): Promise<LookupEnvelope> {
    return this.lookup("coords", target);
  }

  /** `GET /api/lookup/vin/{target}` — ISO 3779 decode, NHTSA vPIC. */
  async vin(target: string): Promise<LookupEnvelope> {
    return this.lookup("vin", target);
  }

  /** `GET /api/lookup/flight/{target}` — airline pack, live status. */
  async flight(target: string): Promise<LookupEnvelope> {
    return this.lookup("flight", target);
  }

  /** `GET /api/lookup/mmsi/{target}` — ITU class, MID flag state. */
  async mmsi(target: string): Promise<LookupEnvelope> {
    return this.lookup("mmsi", target);
  }

  /**
   * `GET /api/lookup/app/{target}` — registry records + OSV CVEs for
   * pypi/npm/crate/docker/github packages (e.g. `pypi:requests`).
   */
  async app(target: string): Promise<LookupEnvelope> {
    return this.lookup("app", target);
  }

  /**
   * `GET /api/lookup/app/{target}` — alias of {@link app}: "package" is a
   * friendly name for the app/package registry kind.
   */
  async package(target: string): Promise<LookupEnvelope> {
    return this.lookup("app", target);
  }

  /** `GET /api/lookup/bssid/{target}` — OUI vendor, geolocation. */
  async bssid(target: string): Promise<LookupEnvelope> {
    return this.lookup("bssid", target);
  }

  /** `GET /api/lookup/plate/{target}` — country formats, city codes. */
  async plate(target: string): Promise<LookupEnvelope> {
    return this.lookup("plate", target);
  }

  // ------------------------------------------------------------------
  // Investigations / risk / correlation
  // ------------------------------------------------------------------

  /**
   * Auto-detect a target and (optionally) follow related pivots.
   *
   * Endpoint: `GET /api/investigate?target=...&pivot=...` — `{target, kind,
   * entities, links, ...}`.
   *
   * @param target - the value to investigate (kind auto-detected).
   * @param options.pivot - follow pivot entities (default `true`).
   */
  async investigate(
    target: string,
    options: { pivot?: boolean } = {},
  ): Promise<InvestigationReport> {
    const payload = await this.requestJson("GET", "/api/investigate", {
      params: { target, pivot: options.pivot ?? true },
    });
    return payload as InvestigationReport;
  }

  /**
   * Run a lookup and attach explainable heuristic risk scoring.
   *
   * Endpoint: `GET /api/risk/{kind}/{target}` — a full lookup envelope with
   * the `risk` block (`score`, `verdict`, `signals`, `summary`) attached.
   *
   * @throws TypeError when `kind` is unknown.
   */
  async risk(kind: LookupKind | string, target: string): Promise<RiskReport> {
    const safeKind = requireKind(kind);
    const path = this.path("/api/risk/{0}/{1}", safeKind, target);
    const payload = await this.requestJson("GET", path);
    return payload as RiskReport;
  }

  /**
   * Chronological event timeline across stored lookup history.
   *
   * Endpoint: `GET /api/timeline?target=...&limit=100` — events sorted
   * oldest → newest, optionally filtered by a target substring.
   */
  async timeline(
    options: { target?: string; limit?: number } = {},
  ): Promise<Timeline> {
    const params: Record<string, unknown> = {
      limit: options.limit ?? 100,
    };
    if (options.target !== undefined) params.target = options.target;
    const payload = await this.requestJson("GET", "/api/timeline", { params });
    return payload as Timeline;
  }

  /**
   * Correlation graph, clusters and bridge entities from history.
   *
   * Endpoint: `GET /api/correlate?limit=...` — an empty history yields empty
   * lists and `{}` stats.
   */
  async correlate(options: { limit?: number } = {}): Promise<CorrelationResult> {
    const params: Record<string, unknown> = {};
    if (options.limit !== undefined) params.limit = options.limit;
    const payload = await this.requestJson("GET", "/api/correlate", { params });
    return payload as CorrelationResult;
  }

  /**
   * Shared-infrastructure comparison between two targets.
   *
   * Endpoint: `GET /api/correlate/pair?a=...&b=...`.
   */
  async correlatePair(a: string, b: string): Promise<PairComparison> {
    const payload = await this.requestJson("GET", "/api/correlate/pair", {
      params: { a, b },
    });
    return payload as PairComparison;
  }

  /**
   * Threat-intel verdict for an IP: Tor exit status, blocklist feeds.
   *
   * Endpoint: `GET /api/intel/{target}`.
   *
   * @throws BadRequestError when the target is not a valid IP.
   */
  async intel(target: string): Promise<IntelVerdict> {
    const path = this.path("/api/intel/{0}", target);
    const payload = await this.requestJson("GET", path);
    return payload as IntelVerdict;
  }

  // ------------------------------------------------------------------
  // Sources / stats / registry / history
  // ------------------------------------------------------------------

  /** Endpoint: `GET /api/sources` — source catalogues for every kind. */
  async sources(): Promise<SourceInfo> {
    const payload = await this.requestJson("GET", "/api/sources");
    return payload as SourceInfo;
  }

  /**
   * Source health roll-up.
   *
   * Endpoint: `GET /api/stats` (the `source_health` block is extracted) —
   * rolling success rates and consecutive failures per source.
   */
  async sourcesHealth(): Promise<SourceHealthEntry[]> {
    const payload = await this.requestJson("GET", "/api/stats");
    const stats = (payload && typeof payload === "object"
      ? payload
      : {}) as StatsSummary;
    return Array.isArray(stats.source_health) ? stats.source_health : [];
  }

  /**
   * Database, cache, network and source-health statistics.
   *
   * Endpoint: `GET /api/stats`.
   */
  async stats(): Promise<StatsSummary> {
    const payload = await this.requestJson("GET", "/api/stats");
    return payload as StatsSummary;
  }

  /** Endpoint: `GET /api/kinds` — registry rows for the 20 kinds. */
  async kinds(): Promise<KindInfo[]> {
    const payload = await this.requestJson("GET", "/api/kinds");
    return ObscuraLensClient.asList(payload) as KindInfo[];
  }

  /**
   * Search stored lookup history.
   *
   * Endpoint: `GET /api/history?kind=...&q=...&limit=100` — `kind` filters
   * by target kind, `q` is a case-insensitive substring match on the stored
   * value, `limit` caps rows (server clamps to 1..500).
   */
  async history(
    options: { kind?: string; q?: string; limit?: number } = {},
  ): Promise<HistoryResult> {
    const params: Record<string, unknown> = {
      limit: options.limit ?? 100,
    };
    if (options.kind !== undefined) params.kind = options.kind;
    if (options.q !== undefined) params.q = options.q;
    const payload = await this.requestJson("GET", "/api/history", { params });
    return payload as HistoryResult;
  }

  // ------------------------------------------------------------------
  // Cases
  // ------------------------------------------------------------------

  /** Endpoint: `GET /api/cases` — every case with item/note/tag counts. */
  async cases(): Promise<Case[]> {
    const payload = await this.requestJson("GET", "/api/cases");
    return ObscuraLensClient.asList(payload) as Case[];
  }

  /**
   * One case with items, notes and tags.
   *
   * Endpoint: `GET /api/cases/{case_id}`.
   *
   * @throws NotFoundError when the id is unknown.
   */
  async case(caseId: number): Promise<Case> {
    const path = this.path("/api/cases/{0}", caseId);
    const payload = await this.requestJson("GET", path);
    return payload as Case;
  }

  /**
   * Create a case.
   *
   * Endpoint: `POST /api/cases` with body `{name, description}` (201).
   *
   * @throws BadRequestError when the name is blank.
   */
  async createCase(name: string, description = ""): Promise<Case> {
    const payload = await this.requestJson("POST", "/api/cases", {
      jsonBody: { name, description },
    });
    return payload as Case;
  }

  /**
   * Update case status.
   *
   * Endpoint: `PATCH /api/cases/{case_id}` with body
   * `{status: "open"|"closed"|"archived"}`.
   *
   * @throws BadRequestError for an unknown status.
   * @throws NotFoundError when the id is unknown.
   */
  async updateCase(caseId: number, status: string): Promise<Case> {
    const path = this.path("/api/cases/{0}", caseId);
    const payload = await this.requestJson("PATCH", path, {
      jsonBody: { status },
    });
    return payload as Case;
  }

  /**
   * Add an item to a case.
   *
   * Endpoint: `POST /api/cases/{case_id}/items` with body
   * `{kind: "auto", target, note?}` (201) — `note` is only sent when given.
   *
   * @throws BadRequestError when the target is blank.
   */
  async addCaseItem(
    caseId: number,
    target: string,
    options: { kind?: string; note?: string } = {},
  ): Promise<Case> {
    const path = this.path("/api/cases/{0}/items", caseId);
    const body: Record<string, unknown> = {
      kind: options.kind ?? "auto",
      target,
    };
    if (options.note !== undefined && options.note !== null) {
      body.note = options.note;
    }
    const payload = await this.requestJson("POST", path, { jsonBody: body });
    return payload as Case;
  }

  /**
   * Append a note to a case.
   *
   * Endpoint: `POST /api/cases/{case_id}/notes` with body `{note}` (201).
   *
   * @throws BadRequestError when the note is blank.
   */
  async addCaseNote(caseId: number, body: string): Promise<Case> {
    const path = this.path("/api/cases/{0}/notes", caseId);
    const payload = await this.requestJson("POST", path, {
      jsonBody: { note: body },
    });
    return payload as Case;
  }

  /**
   * Add a tag to a case.
   *
   * Endpoint: `POST /api/cases/{case_id}/tags` with body `{tag}` (201).
   *
   * @throws BadRequestError when the tag is blank.
   */
  async addCaseTag(caseId: number, tag: string): Promise<Case> {
    const path = this.path("/api/cases/{0}/tags", caseId);
    const payload = await this.requestJson("POST", path, {
      jsonBody: { tag },
    });
    return payload as Case;
  }

  // ------------------------------------------------------------------
  // Watchlist / diff
  // ------------------------------------------------------------------

  /** Endpoint: `GET /api/watch` — every watched target. */
  async watch(): Promise<WatchEntry[]> {
    const payload = await this.requestJson("GET", "/api/watch");
    return ObscuraLensClient.asList(payload) as WatchEntry[];
  }

  /**
   * Add a target to the watchlist.
   *
   * Endpoint: `POST /api/watch` with body `{target, label}` (201) — returns
   * `{id: <watch id>}`. `label` defaults to `""`; an optional `kind` is
   * forwarded when given (the stock server auto-detects and ignores it).
   *
   * @throws BadRequestError for an invalid or duplicate target.
   */
  async addWatch(
    target: string,
    options: { label?: string; kind?: string } = {},
  ): Promise<WatchAddResult> {
    const body: Record<string, unknown> = {
      target,
      label: options.label ?? "",
    };
    if (options.kind !== undefined && options.kind !== null) {
      body.kind = options.kind;
    }
    const payload = await this.requestJson("POST", "/api/watch", {
      jsonBody: body,
    });
    return payload as WatchAddResult;
  }

  /**
   * Remove a watch by numeric id or target string.
   *
   * Endpoint: `DELETE /api/watch/{identifier}`.
   *
   * @throws NotFoundError when no matching watch exists.
   */
  async removeWatch(idOrTarget: number | string): Promise<RemoveResult> {
    const path = this.path("/api/watch/{0}", idOrTarget);
    const payload = await this.requestJson("DELETE", path);
    return payload as RemoveResult;
  }

  /**
   * Run and diff one watch (id or target) or every watch.
   *
   * Endpoint: `POST /api/watch/check?identifier=...` — one change record
   * per checked watch (`added`/`removed`/`changed`, `is_first`).
   */
  async checkWatch(
    options: { identifier?: string } = {},
  ): Promise<WatchDiff[]> {
    const params: Record<string, unknown> = {};
    if (options.identifier !== undefined) {
      params.identifier = options.identifier;
    }
    const payload = await this.requestJson("POST", "/api/watch/check", {
      params,
    });
    return ObscuraLensClient.asList(payload) as WatchDiff[];
  }

  /**
   * Snapshot diff for one watched target (latest two snapshots).
   *
   * Endpoint: `GET /api/diff/{kind}/{target}` — `changed_any` plus
   * `added`/`removed`/`changed` field maps; a single-snapshot target
   * answers with `changed_any: false` and a `note`.
   *
   * @throws NotFoundError when the target is not on the watchlist.
   */
  async diff(kind: string, target: string): Promise<DiffReport> {
    const path = this.path("/api/diff/{0}/{1}", kind, target);
    const payload = await this.requestJson("GET", path);
    return payload as DiffReport;
  }

  // ------------------------------------------------------------------
  // Settings / API keys
  // ------------------------------------------------------------------

  /** Endpoint: `GET /api/keys` — which keyed services are configured. */
  async keys(): Promise<ServiceKey[]> {
    const payload = await this.requestJson("GET", "/api/keys");
    return ObscuraLensClient.asList(payload) as ServiceKey[];
  }

  /**
   * Store an API key for a service.
   *
   * Endpoint: `POST /api/keys/{service}` with body `{key}` — the key lands
   * in the server's git-ignored `config/secrets.yaml`.
   *
   * @throws BadRequestError for an unknown service or blank key.
   */
  async setKey(service: string, key: string): Promise<KeyMutationResult> {
    const path = this.path("/api/keys/{0}", service);
    const payload = await this.requestJson("POST", path, {
      jsonBody: { key },
    });
    return payload as KeyMutationResult;
  }

  /**
   * Remove a stored API key.
   *
   * Endpoint: `DELETE /api/keys/{service}`.
   *
   * @throws BadRequestError for an unknown service.
   */
  async clearKey(service: string): Promise<KeyMutationResult> {
    const path = this.path("/api/keys/{0}", service);
    const payload = await this.requestJson("DELETE", path);
    return payload as KeyMutationResult;
  }

  /**
   * Runtime application settings as dotted-path keys.
   *
   * Endpoint: `GET /api/settings` — the *live* runtime configuration (env
   * overrides included); secret and filesystem paths are never exposed.
   */
  async settings(): Promise<SettingsView> {
    const payload = await this.requestJson("GET", "/api/settings");
    return payload as SettingsView;
  }

  /**
   * Update one runtime setting (in-memory only, not persisted).
   *
   * Endpoint: `POST /api/settings` with body
   * `{path: "app.cache_ttl", value: 300}` — only non-blocklisted `app.*`
   * keys are accepted; values are coerced to the current field type.
   *
   * @throws BadRequestError for unknown/protected paths or bad values.
   */
  async updateSetting(
    path: string,
    value: unknown,
  ): Promise<SettingsUpdateResult> {
    const payload = await this.requestJson("POST", "/api/settings", {
      jsonBody: { path, value },
    });
    return payload as SettingsUpdateResult;
  }

  // ------------------------------------------------------------------
  // Analyst toolbox
  // ------------------------------------------------------------------

  /**
   * Encode one input into every scheme plus a full digest panel.
   *
   * Endpoint: `GET /api/tools/encodings?text=...` — `encodings`
   * (hex/base32/base64/base85/url/html/rot13/binary/morse/...) and `hashes`
   * (MD5 → SHA-3/BLAKE2, CRC32). All local computation.
   */
  async encode(text: string): Promise<ToolboxResult> {
    const payload = await this.requestJson("GET", "/api/tools/encodings", {
      params: { text },
    });
    return payload as ToolboxResult;
  }

  /**
   * Decode a value with one scheme, or rank every scheme's attempt.
   *
   * Endpoint: `POST /api/tools/decode` with body `{scheme, value}` — use
   * `scheme: "auto"` (default) for the ranked candidate list.
   *
   * @throws BadRequestError for a blank value or unknown scheme.
   */
  async decode(value: string, scheme = "auto"): Promise<ToolboxResult> {
    const payload = await this.requestJson("POST", "/api/tools/decode", {
      jsonBody: { scheme, value },
    });
    return payload as ToolboxResult;
  }

  /**
   * Decode and inspect a JWT (no signature verification — local).
   *
   * Endpoint: `GET /api/tools/jwt?token=...` — `header`, `payload`,
   * `claims`, `identifiers`, `key_info`, `token_stats`, `notes`.
   *
   * @throws BadRequestError for a malformed token.
   */
  async inspectJwt(token: string): Promise<ToolboxResult> {
    const payload = await this.requestJson("GET", "/api/tools/jwt", {
      params: { token },
    });
    return payload as ToolboxResult;
  }

  /**
   * Identify candidate hash formats for a digest-shaped string.
   *
   * Endpoint: `GET /api/tools/hash-id?value=...` — `candidates` ranked by
   * confidence (`{name, confidence, length, charset, note}`).
   */
  async hashId(value: string): Promise<ToolboxResult> {
    const payload = await this.requestJson("GET", "/api/tools/hash-id", {
      params: { value },
    });
    return payload as ToolboxResult;
  }

  /**
   * Parse coordinates (DD/DMS/DDM/UTM/MGRS) and convert to every format.
   *
   * Endpoint: `POST /api/tools/coords` with body `{value}` — `latitude`,
   * `longitude`, `decimal`, `dms`, `ddm`, `utm`, `mgrs`, `geohash`,
   * `maidenhead`.
   *
   * @throws BadRequestError for an unrecognised coordinate format.
   */
  async convertCoords(value: string): Promise<ToolboxResult> {
    const payload = await this.requestJson("POST", "/api/tools/coords", {
      jsonBody: { value },
    });
    return payload as ToolboxResult;
  }

  /**
   * Extract entities from free text (emails, IPs, domains, URLs, phones,
   * hashes, CVEs, crypto addresses, MACs, IBANs, IMEIs, coords, handles,
   * tracking IDs).
   *
   * Endpoint: `POST /api/tools/extract` with body `{text}` — all local
   * regex + validator work.
   *
   * @throws BadRequestError for blank text.
   */
  async extractEntities(text: string): Promise<ToolboxResult> {
    const payload = await this.requestJson("POST", "/api/tools/extract", {
      jsonBody: { text },
    });
    return payload as ToolboxResult;
  }

  /**
   * Generate and score typosquatting variants for a domain.
   *
   * Endpoint: `POST /api/tools/squat` with body `{domain}` — omission,
   * insertion, transposition, homoglyphs, bitsquatting, combo-squatting,
   * TLD swaps... Local generation only.
   *
   * @throws BadRequestError for an invalid domain.
   */
  async squat(domain: string): Promise<ToolboxResult> {
    const payload = await this.requestJson("POST", "/api/tools/squat", {
      jsonBody: { domain },
    });
    return payload as ToolboxResult;
  }

  /**
   * Ready-to-open search-engine dorks for a target (v6.1).
   *
   * Endpoint: `GET /api/tools/dorks?target=...&kind=...` — the kind is
   * auto-detected unless overridden via `options.kind`; links are generated
   * locally (Google, Bing, DuckDuckGo, Yandex, GitHub code search).
   *
   * @throws BadRequestError for a blank target.
   */
  async dorks(
    target: string,
    options: { kind?: string } = {},
  ): Promise<DorkReport> {
    const params: Record<string, unknown> = { target };
    if (options.kind !== undefined) params.kind = options.kind;
    const payload = await this.requestJson("GET", "/api/tools/dorks", {
      params,
    });
    return payload as DorkReport;
  }

  // ------------------------------------------------------------------
  // Analytics (v6.0 part 2)
  // ------------------------------------------------------------------

  /**
   * Descriptive statistics plus a histogram for a numeric list.
   *
   * Endpoint: `POST /api/analytics/stats` with body `{values, bins}` —
   * non-numeric items are dropped server-side; `bins` clamps to 1..100.
   *
   * @throws BadRequestError when `values` has no usable numbers.
   */
  async analyticsStats(
    values: Array<number>,
    bins = 10,
  ): Promise<AnalyticsResult> {
    const payload = await this.requestJson("POST", "/api/analytics/stats", {
      jsonBody: { values: [...values], bins },
    });
    return payload as AnalyticsResult;
  }

  /**
   * Outlier detection over a numeric list.
   *
   * Endpoint: `POST /api/analytics/anomalies` with body
   * `{values, method, threshold?}` — `method` is one of zscore/iqr/mad/
   * grubbs/ensemble/threshold (default ensemble). `threshold` is only sent
   * when given *and* the method is `zscore` (the only detector that
   * honours it).
   *
   * @throws BadRequestError when `values` has no usable numbers.
   */
  async analyticsAnomalies(
    values: Array<number>,
    options: { method?: string; threshold?: number } = {},
  ): Promise<AnalyticsResult> {
    const body: Record<string, unknown> = {
      values: [...values],
      method: options.method ?? "ensemble",
    };
    if (
      options.threshold !== undefined &&
      (options.method ?? "ensemble") === "zscore"
    ) {
      body.threshold = options.threshold;
    }
    const payload = await this.requestJson(
      "POST",
      "/api/analytics/anomalies",
      { jsonBody: body },
    );
    return payload as AnalyticsResult;
  }

  /**
   * Trend / changepoint summary for a value sequence.
   *
   * Endpoint: `POST /api/analytics/timeseries` with body `{values}` —
   * values are indexed as consecutive days.
   *
   * @throws BadRequestError when `values` has no usable numbers.
   */
  async analyticsTimeseries(
    values: Array<number>,
  ): Promise<AnalyticsResult> {
    const payload = await this.requestJson("POST", "/api/analytics/timeseries", {
      jsonBody: { values: [...values] },
    });
    return payload as AnalyticsResult;
  }

  /**
   * Kilometre-space clustering of `[lat, lon]` coordinate pairs.
   *
   * Endpoint: `POST /api/analytics/clusters` with body
   * `{points, eps_km, min_points}` — great-circle DBSCAN; `epsKm` defaults
   * to 25, `minPoints` to 3.
   *
   * @throws BadRequestError when `points` has no usable rows.
   */
  async analyticsClusters(
    points: Array<[number, number]>,
    options: { epsKm?: number; minPoints?: number } = {},
  ): Promise<AnalyticsResult> {
    const payload = await this.requestJson("POST", "/api/analytics/clusters", {
      jsonBody: {
        points: points.map(([lat, lon]) => [lat, lon]),
        eps_km: options.epsKm ?? 25,
        min_points: options.minPoints ?? 3,
      },
    });
    return payload as AnalyticsResult;
  }

  /**
   * Stopword-filtered keyword mining for a text.
   *
   * Endpoint: `POST /api/analytics/keywords` with body `{text, top}` —
   * `term`/`count`/`weight` records sorted by weight (`top` default 10).
   *
   * @throws BadRequestError for blank text.
   */
  async analyticsKeywords(
    text: string,
    top = 10,
  ): Promise<AnalyticsResult> {
    const payload = await this.requestJson("POST", "/api/analytics/keywords", {
      jsonBody: { text, top },
    });
    return payload as AnalyticsResult;
  }

  /**
   * Script and language fingerprint for a text.
   *
   * Endpoint: `POST /api/analytics/language` with body `{text}` — dominant
   * script, per-script character counts, a language guess with confidence
   * and a human-readable hint.
   *
   * @throws BadRequestError for blank text.
   */
  async analyticsLanguage(text: string): Promise<AnalyticsResult> {
    const payload = await this.requestJson("POST", "/api/analytics/language", {
      jsonBody: { text },
    });
    return payload as AnalyticsResult;
  }

  /**
   * Four-metric similarity between two texts.
   *
   * Endpoint: `POST /api/analytics/similarity` with body `{a, b}` —
   * Jaro-Winkler, Levenshtein ratio, bigram similarity, sparse cosine,
   * their mean and both lengths.
   *
   * @throws BadRequestError when either text is blank.
   */
  async analyticsSimilarity(a: string, b: string): Promise<AnalyticsResult> {
    const payload = await this.requestJson("POST", "/api/analytics/similarity", {
      jsonBody: { a, b },
    });
    return payload as AnalyticsResult;
  }

  /**
   * Graph metrics over an `entities`/`links` payload.
   *
   * Endpoint: `POST /api/analytics/graph` with body `{entities, links}` —
   * node/edge counts, density, components, communities, top entities by
   * degree/PageRank/betweenness, bridges and isolated nodes.
   *
   * @throws BadRequestError when neither list is present.
   */
  async analyticsGraph(
    entities: Array<Record<string, unknown>>,
    links: Array<Record<string, unknown>>,
  ): Promise<AnalyticsResult> {
    const payload = await this.requestJson("POST", "/api/analytics/graph", {
      jsonBody: { entities: [...entities], links: [...links] },
    });
    return payload as AnalyticsResult;
  }

  /**
   * Enrichment report over stored query history.
   *
   * Endpoint: `GET /api/analytics/history?limit=500` — kind frequency,
   * hour/weekday activity profiles, per-kind success rates, source
   * reliability, day-volume anomalies and the most re-queried targets.
   */
  async analyticsHistory(limit = 500): Promise<AnalyticsResult> {
    const payload = await this.requestJson("GET", "/api/analytics/history", {
      params: { limit },
    });
    return payload as AnalyticsResult;
  }

  // ------------------------------------------------------------------
  // Notifications (v6.0 part 4)
  // ------------------------------------------------------------------

  /**
   * Every configured notification channel plus the protocol vocabularies.
   *
   * Endpoint: `GET /api/notify/channels`.
   */
  async notifyChannels(): Promise<NotifyChannels> {
    const payload = await this.requestJson("GET", "/api/notify/channels");
    return payload as NotifyChannels;
  }

  /**
   * Register one notification channel.
   *
   * Endpoint: `POST /api/notify/channels` with the spec as the body —
   * `undefined` keys are dropped (the server applies its own defaults), so
   * a minimal registration is just `{name, type}`.
   *
   * @throws BadRequestError when the spec is rejected (unknown type,
   *   missing target, duplicate name...).
   */
  async addNotifyChannel(spec: NotifyChannelSpec): Promise<NotifyAddResult> {
    const body: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(spec)) {
      if (value !== undefined) body[key] = value;
    }
    const payload = await this.requestJson("POST", "/api/notify/channels", {
      jsonBody: body,
    });
    return payload as NotifyAddResult;
  }

  /**
   * Delete one channel by name (delivery history stays behind).
   *
   * Endpoint: `DELETE /api/notify/channels/{name}`.
   *
   * @throws NotFoundError for an unknown channel name.
   */
  async removeNotifyChannel(name: string): Promise<RemoveResult> {
    const path = this.path("/api/notify/channels/{0}", name);
    const payload = await this.requestJson("DELETE", path);
    return payload as RemoveResult;
  }

  /**
   * Probe one channel with a one-off test message.
   *
   * Endpoint: `POST /api/notify/channels/{name}/test` — subscription/
   * severity/quiet-hours/dedup filters are bypassed. A delivery failure is
   * a `200` with `{ok: false, error}` (data, not an HTTP error).
   *
   * @throws NotFoundError for an unknown channel name.
   */
  async testNotifyChannel(name: string): Promise<NotifyDelivery> {
    const path = this.path("/api/notify/channels/{0}/test", name);
    const payload = await this.requestJson("POST", path);
    return payload as NotifyDelivery;
  }

  /**
   * Recent notification history, newest first.
   *
   * Endpoint: `GET /api/notify/recent?limit=20` — sends, failures and
   * skips alike.
   */
  async notifyRecent(limit = 20): Promise<NotifyRecent> {
    const payload = await this.requestJson("GET", "/api/notify/recent", {
      params: { limit },
    });
    return payload as NotifyRecent;
  }

  /**
   * Fan one event out to every configured channel.
   *
   * Endpoint: `POST /api/notify/broadcast` with body `{title, body,
   * severity, event_type}` — per-channel filters (event subscriptions,
   * severity floors, quiet hours, dedup) apply server-side; failures never
   * abort the loop. `severity` defaults to `"info"`, `eventType` to
   * `"manual"`.
   *
   * @throws BadRequestError for blank `title` or `body`.
   */
  async notifyBroadcast(
    spec: NotifyBroadcastSpec,
  ): Promise<NotifyDelivery> {
    const payload = await this.requestJson("POST", "/api/notify/broadcast", {
      jsonBody: {
        title: spec.title,
        body: spec.body,
        severity: spec.severity ?? "info",
        event_type: spec.eventType ?? "manual",
      },
    });
    return payload as NotifyDelivery;
  }

  // ------------------------------------------------------------------
  // Automation (v6.0 part 4)
  // ------------------------------------------------------------------

  /**
   * Every scheduled task (schedules, bookkeeping fields, health).
   *
   * Endpoint: `GET /api/automation/tasks`.
   */
  async automationTasks(): Promise<AutomationTasks> {
    const payload = await this.requestJson("GET", "/api/automation/tasks");
    return payload as AutomationTasks;
  }

  /**
   * Register one scheduled task.
   *
   * Endpoint: `POST /api/automation/tasks` with the spec as the body —
   * `undefined` keys are dropped; the stored task comes back with a
   * freshly computed `next_run`.
   *
   * @throws BadRequestError when the spec is rejected (unknown action/
   *   schedule, bad `at_time`, duplicate name...).
   */
  async addAutomationTask(
    spec: AutomationTaskSpec,
  ): Promise<AutomationAddResult> {
    const body: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(spec)) {
      if (value !== undefined) body[key] = value;
    }
    const payload = await this.requestJson("POST", "/api/automation/tasks", {
      jsonBody: body,
    });
    return payload as AutomationAddResult;
  }

  /**
   * Delete one scheduled task by name.
   *
   * Endpoint: `DELETE /api/automation/tasks/{name}`.
   *
   * @throws NotFoundError for an unknown task name.
   */
  async removeAutomationTask(name: string): Promise<RemoveResult> {
    const path = this.path("/api/automation/tasks/{0}", name);
    const payload = await this.requestJson("DELETE", path);
    return payload as RemoveResult;
  }

  /**
   * Execute one task now, regardless of its schedule.
   *
   * Endpoint: `POST /api/automation/tasks/{name}/run` — a failing executor
   * is a `200` with `{ok: false, error}` (the run outcome, not an HTTP
   * error). Bookkeeping is left to `runDueAutomation`.
   *
   * @throws NotFoundError for an unknown task name.
   */
  async runAutomationTask(name: string): Promise<AutomationRunResult> {
    const path = this.path("/api/automation/tasks/{0}/run", name);
    const payload = await this.requestJson("POST", path);
    return payload as AutomationRunResult;
  }

  /**
   * Run every task whose schedule has arrived, then persist the
   * bookkeeping (`last_run`, `run_count`, `error_count`, `next_run`).
   *
   * Endpoint: `POST /api/automation/run-due` — exactly what the background
   * tick loop does every 30 seconds.
   */
  async runDueAutomation(): Promise<AutomationRunDue> {
    const payload = await this.requestJson("POST", "/api/automation/run-due");
    return payload as AutomationRunDue;
  }

  /**
   * When every task runs next: the stored `next_run` plus a fresh
   * recomputation from *now*.
   *
   * Endpoint: `GET /api/automation/next`.
   */
  async automationNext(): Promise<AutomationNext> {
    const payload = await this.requestJson("GET", "/api/automation/next");
    return payload as AutomationNext;
  }

  // ------------------------------------------------------------------
  // Intelligence-sharing exports
  // ------------------------------------------------------------------

  /**
   * A STIX 2.1 bundle for the newest stored lookup of one target.
   *
   * Endpoint: `GET /api/export/stix/{kind}/{target}` — identity +
   * indicator (or vulnerability for CVEs) + observed data + provenance
   * note, deterministic UUIDv5 ids throughout. Run the lookup first, then
   * export.
   *
   * @throws TypeError when `kind` is unknown (client-side check).
   * @throws NotFoundError when no stored lookup matches the target.
   */
  async exportStix(
    kind: LookupKind | string,
    target: string,
  ): Promise<StixBundle> {
    const safeKind = requireKind(kind);
    const path = this.path("/api/export/stix/{0}/{1}", safeKind, target);
    const payload = await this.requestJson("GET", path);
    return payload as StixBundle;
  }

  /**
   * A MISP core-format event for the newest stored lookup of one target.
   *
   * Endpoint: `GET /api/export/misp/{kind}/{target}` — fixed ObscuraLens
   * `orgc`, the target attribute, one text attribute per `info` field and
   * a threat level derived from source health.
   *
   * @throws TypeError when `kind` is unknown (client-side check).
   * @throws NotFoundError when no stored lookup matches the target.
   */
  async exportMisp(
    kind: LookupKind | string,
    target: string,
  ): Promise<MispEvent> {
    const safeKind = requireKind(kind);
    const path = this.path("/api/export/misp/{0}/{1}", safeKind, target);
    const payload = await this.requestJson("GET", path);
    return payload as MispEvent;
  }

  /**
   * Export an investigation entity graph as text.
   *
   * Endpoint: `GET /api/export/{fmt}/{target}?pivot=...` — `{target,
   * format, graph, entities, links}` with `graph` being graphml/gexf/dot/
   * jsonl/csv text; `pivot` defaults to `true`.
   *
   * @throws BadRequestError for an unknown format or undetectable target.
   */
  async exportGraph(
    fmt: string,
    target: string,
    options: { pivot?: boolean } = {},
  ): Promise<GraphExport> {
    const path = this.path("/api/export/{0}/{1}", fmt, target);
    const payload = await this.requestJson("GET", path, {
      params: { pivot: options.pivot ?? true },
    });
    return payload as GraphExport;
  }

  /**
   * Pattern-of-life analysis for one target across stored history.
   *
   * Endpoint: `GET /api/patterns?kind=...&target=...` — hour/weekday
   * histograms, 7×24 activity matrix, cadence, bursts.
   */
  async patterns(kind: string, target: string): Promise<PatternReport> {
    const payload = await this.requestJson("GET", "/api/patterns", {
      params: { kind, target },
    });
    return payload as PatternReport;
  }

  /**
   * Batch lookup up to 25 targets of one kind.
   *
   * Endpoint: `POST /api/tools/batch` with body `{kind, targets, risk}`.
   *
   * @throws BadRequestError for an unknown kind or empty targets.
   */
  async batch(
    kind: string,
    targets: string[],
    options: { risk?: boolean } = {},
  ): Promise<BatchProgress> {
    const payload = await this.requestJson("POST", "/api/tools/batch", {
      jsonBody: {
        kind,
        targets: [...targets],
        risk: options.risk ?? false,
      },
    });
    return payload as BatchProgress;
  }

  // ------------------------------------------------------------------
  // Live stream (v6.0 part 3)
  // ------------------------------------------------------------------

  /**
   * Declare the event topics the live stream should carry.
   *
   * Endpoint: `POST /api/stream/subscribe` with body `{topics}` — a list
   * or a single comma-separated string works; blank names are dropped.
   * Every `GET /api/stream` connection without its own `?topics=` filters
   * through the declared set.
   *
   * @throws BadRequestError for missing/empty topics.
   */
  async setStreamTopics(
    topics: string[] | string,
  ): Promise<StreamTopicsResult> {
    const names = typeof topics === "string"
      ? topics.split(",").map((item) => item.trim()).filter(Boolean)
      : topics.map((item) => String(item).trim()).filter(Boolean);
    const payload = await this.requestJson("POST", "/api/stream/subscribe", {
      jsonBody: { topics: names },
    });
    return payload as StreamTopicsResult;
  }

  /**
   * The absolute URL for the server-sent-events feed — connect with the
   * runtime's `EventSource`/`fetch` streaming.
   *
   * Endpoint: `GET /api/stream` (`?topics=a,b&max_events=...` optional) —
   * `connected`, `lookup`, `watch` and `heartbeat` frames.
   */
  streamUrl(options: { topics?: string[] | string; maxEvents?: number } = {}): string {
    const params: Record<string, unknown> = {};
    if (options.topics !== undefined) {
      params.topics = Array.isArray(options.topics)
        ? options.topics.join(",")
        : options.topics;
    }
    if (options.maxEvents !== undefined) params.max_events = options.maxEvents;
    return buildUrl(this.baseUrl, "/api/stream", params);
  }

  // ------------------------------------------------------------------
  // Escape hatches
  // ------------------------------------------------------------------

  /**
   * GET any API path and resolve with the parsed JSON.
   *
   * The escape hatch for endpoints this SDK version does not model — new
   * server endpoints work without waiting for an SDK release.
   *
   * @param path - absolute path starting with `/` (a leading slash is
   *   added when missing).
   * @param params - optional query parameters.
   */
  async rawGet(
    path: string,
    params?: Record<string, unknown>,
  ): Promise<unknown> {
    return this.requestJson("GET", normalizePath(path), { params });
  }

  /**
   * POST any API path and resolve with the parsed JSON.
   *
   * @param path - absolute path starting with `/`.
   * @param jsonBody - the JSON body to send (`undefined` = empty body).
   */
  async rawPost(path: string, jsonBody?: unknown): Promise<unknown> {
    return this.requestJson("POST", normalizePath(path), { jsonBody });
  }

  /**
   * DELETE any API path and resolve with the parsed JSON.
   *
   * @param path - absolute path starting with `/`.
   */
  async rawDelete(path: string): Promise<unknown> {
    return this.requestJson("DELETE", normalizePath(path));
  }
}

/** Ensure a raw path starts with `/`. */
function normalizePath(path: string): string {
  const text = String(path ?? "");
  return text.startsWith("/") ? text : `/${text}`;
}

/**
 * Attach `Symbol.asyncDispose` (Node 20+, `await using`) when the runtime
 * provides the symbol — closes the client's transport.
 */
const asyncDisposeSymbol = (Symbol as unknown as { asyncDispose?: symbol })
  .asyncDispose;
if (asyncDisposeSymbol !== undefined) {
  const proto = ObscuraLensClient.prototype as unknown as Record<
    symbol,
    () => Promise<void>
  >;
  proto[asyncDisposeSymbol] = function asyncDispose(
    this: ObscuraLensClient,
  ): Promise<void> {
    this.close();
    return Promise.resolve();
  };
}
