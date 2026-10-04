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
import { Transport, type FetchLike } from "./transport.js";
import { type AnalyticsResult, type AutomationAddResult, type AutomationNext, type AutomationRunDue, type AutomationRunResult, type AutomationTaskSpec, type AutomationTasks, type BatchProgress, type Case, type CorrelationResult, type DiffReport, type DorkReport, type GraphExport, type HistoryResult, type IntelVerdict, type InvestigationReport, type KeyMutationResult, type KindInfo, type LookupEnvelope, type LookupKind, type NotifyAddResult, type NotifyBroadcastSpec, type NotifyChannelSpec, type NotifyChannels, type NotifyDelivery, type NotifyRecent, type PairComparison, type PatternReport, type RemoveResult, type RiskReport, type ServiceKey, type SettingsUpdateResult, type SettingsView, type SourceHealthEntry, type SourceInfo, type StatsSummary, type StixBundle, type StreamTopicsResult, type MispEvent, type Timeline, type ToolboxResult, type WatchAddResult, type WatchDiff, type WatchEntry } from "./types.js";
/** Default server address (matches `obscuralens serve` defaults). */
export declare const DEFAULT_BASE_URL = "http://127.0.0.1:8000";
/** Default per-request timeout (milliseconds). */
export declare const DEFAULT_TIMEOUT_MS = 30000;
/** Default total attempts per request (one try plus up to two retries). */
export declare const DEFAULT_RETRIES = 3;
/** Default retry backoff base (milliseconds); doubles per attempt. */
export declare const DEFAULT_BACKOFF_MS = 500;
/** Upper bound for any single computed backoff sleep (milliseconds). */
export declare const DEFAULT_MAX_BACKOFF_MS = 30000;
/** Export formats accepted by `GET /api/export/{fmt}/{target}`. */
export declare const EXPORT_FORMATS: readonly string[];
/** Valid case statuses for `updateCase` (PATCH /api/cases/{id}). */
export declare const CASE_STATUSES: readonly string[];
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
/**
 * The asynchronous client for the ObscuraLens REST API.
 *
 * All methods reject with {@link module:obscuralens-sdk/errors.SdkError}
 * subclasses; see each method's JSDoc for the endpoint it calls.
 */
export declare class ObscuraLensClient {
    /** Normalised server root (no trailing slash). */
    readonly baseUrl: string;
    /** Session API key (or `null`) — sent as `X-API-Key`. */
    readonly apiKey: string | null;
    /** Per-request timeout in milliseconds (`null` = no timeout). */
    readonly timeoutMs: number | null;
    /** Total attempts per request including the first. */
    readonly retries: number;
    /** Retry backoff base in milliseconds (doubles per attempt). */
    readonly backoffMs: number;
    /** Ceiling for one computed backoff sleep in milliseconds. */
    readonly maxBackoffMs: number;
    /** The transport this client sends requests through. */
    readonly transport: Transport;
    private readonly sleepFn;
    private closed;
    constructor(options?: ClientOptions);
    /**
     * Close the underlying transport and mark the client closed.
     *
     * Idempotent; further requests reject with `TransportError`. `await
     * client.close()` in a `finally` block, or use `Symbol.asyncDispose`
     * (`await using`) on runtimes that provide it (Node 20+).
     */
    close(): void;
    /** Debug representation with base URL, SDK version and state. */
    toString(): string;
    private baseHeaders;
    /** Exponential backoff for one attempt index (0-based), capped. */
    private backoffDelay;
    /** The retry delay for one attempt: backoff, unless Retry-After wins. */
    private delayFor;
    private sleep;
    /** Percent-encode one path segment (slashes, colons, commas...). */
    private static encodeSegment;
    /** Build an API path from a `{0}`/`{1}` template and encoded segments. */
    private path;
    /**
     * Perform one request with retries; resolve with the raw 2xx response.
     *
     * Retries `TransportError`, `TimeoutError` and `RateLimitError` (sleeping
     * `Retry-After` milliseconds when the server sent one, else the
     * exponential backoff) up to `retries` total attempts. Non-2xx statuses
     * reject with the mapped SDK error on the final attempt.
     */
    private send;
    /**
     * Perform one request and resolve with the parsed JSON.
     *
     * @throws {@link module:obscuralens-sdk/errors.MalformedResponseError}
     *   when a 2xx body is not valid JSON.
     */
    private requestJson;
    /** Coerce a JSON payload into a list (junk → empty array). */
    private static asList;
    /**
     * Check that the server is reachable and answering.
     *
     * Endpoint: `GET /api/health` — any successful response means `true`.
     * Never rejects with SDK errors — connection failures, timeouts and HTTP
     * errors resolve `false`. A dead server still burns the retry budget (use
     * a small `retries` value when pinging aggressively).
     */
    ping(): Promise<boolean>;
    /**
     * Liveness probe with the server's package version.
     *
     * Endpoint: `GET /api/health` → `{status: "ok", version: "6.1.0"}`.
     */
    health(): Promise<{
        status: string;
        version: string;
    }>;
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
    lookup(kind: LookupKind | string, target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/ip/{target}` — geo, ASN, reverse DNS, threat intel. */
    ip(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/phone/{target}` — E.164, carrier hints, geo. */
    phone(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/username/{target}` — 45 platforms, 3-state verdicts. */
    username(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/email/{target}` — breaches, reputation, profiles. */
    email(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/domain/{target}` — registration, DNS, CT logs. */
    domain(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/url/{target}` — redirects, urlscan, safety verdicts. */
    url(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/crypto/{target}` — BTC/ETH/LTC/DOGE balances. */
    crypto(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/hash/{target}` — malware family, detections. */
    hash(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/cve/{target}` — CVSS, products, EPSS. */
    cve(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/asn/{target}` — holder, prefixes, peers. */
    asn(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/mac/{target}` — IEEE OUI vendor lookup. */
    mac(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/iban/{target}` — checksum, bank, country. */
    iban(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/imei/{target}` — TAC, manufacturer, Luhn. */
    imei(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/coords/{target}` — every format + reverse geocode. */
    coords(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/vin/{target}` — ISO 3779 decode, NHTSA vPIC. */
    vin(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/flight/{target}` — airline pack, live status. */
    flight(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/mmsi/{target}` — ITU class, MID flag state. */
    mmsi(target: string): Promise<LookupEnvelope>;
    /**
     * `GET /api/lookup/app/{target}` — registry records + OSV CVEs for
     * pypi/npm/crate/docker/github packages (e.g. `pypi:requests`).
     */
    app(target: string): Promise<LookupEnvelope>;
    /**
     * `GET /api/lookup/app/{target}` — alias of {@link app}: "package" is a
     * friendly name for the app/package registry kind.
     */
    package(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/bssid/{target}` — OUI vendor, geolocation. */
    bssid(target: string): Promise<LookupEnvelope>;
    /** `GET /api/lookup/plate/{target}` — country formats, city codes. */
    plate(target: string): Promise<LookupEnvelope>;
    /**
     * Auto-detect a target and (optionally) follow related pivots.
     *
     * Endpoint: `GET /api/investigate?target=...&pivot=...` — `{target, kind,
     * entities, links, ...}`.
     *
     * @param target - the value to investigate (kind auto-detected).
     * @param options.pivot - follow pivot entities (default `true`).
     */
    investigate(target: string, options?: {
        pivot?: boolean;
    }): Promise<InvestigationReport>;
    /**
     * Run a lookup and attach explainable heuristic risk scoring.
     *
     * Endpoint: `GET /api/risk/{kind}/{target}` — a full lookup envelope with
     * the `risk` block (`score`, `verdict`, `signals`, `summary`) attached.
     *
     * @throws TypeError when `kind` is unknown.
     */
    risk(kind: LookupKind | string, target: string): Promise<RiskReport>;
    /**
     * Chronological event timeline across stored lookup history.
     *
     * Endpoint: `GET /api/timeline?target=...&limit=100` — events sorted
     * oldest → newest, optionally filtered by a target substring.
     */
    timeline(options?: {
        target?: string;
        limit?: number;
    }): Promise<Timeline>;
    /**
     * Correlation graph, clusters and bridge entities from history.
     *
     * Endpoint: `GET /api/correlate?limit=...` — an empty history yields empty
     * lists and `{}` stats.
     */
    correlate(options?: {
        limit?: number;
    }): Promise<CorrelationResult>;
    /**
     * Shared-infrastructure comparison between two targets.
     *
     * Endpoint: `GET /api/correlate/pair?a=...&b=...`.
     */
    correlatePair(a: string, b: string): Promise<PairComparison>;
    /**
     * Threat-intel verdict for an IP: Tor exit status, blocklist feeds.
     *
     * Endpoint: `GET /api/intel/{target}`.
     *
     * @throws BadRequestError when the target is not a valid IP.
     */
    intel(target: string): Promise<IntelVerdict>;
    /** Endpoint: `GET /api/sources` — source catalogues for every kind. */
    sources(): Promise<SourceInfo>;
    /**
     * Source health roll-up.
     *
     * Endpoint: `GET /api/stats` (the `source_health` block is extracted) —
     * rolling success rates and consecutive failures per source.
     */
    sourcesHealth(): Promise<SourceHealthEntry[]>;
    /**
     * Database, cache, network and source-health statistics.
     *
     * Endpoint: `GET /api/stats`.
     */
    stats(): Promise<StatsSummary>;
    /** Endpoint: `GET /api/kinds` — registry rows for the 20 kinds. */
    kinds(): Promise<KindInfo[]>;
    /**
     * Search stored lookup history.
     *
     * Endpoint: `GET /api/history?kind=...&q=...&limit=100` — `kind` filters
     * by target kind, `q` is a case-insensitive substring match on the stored
     * value, `limit` caps rows (server clamps to 1..500).
     */
    history(options?: {
        kind?: string;
        q?: string;
        limit?: number;
    }): Promise<HistoryResult>;
    /** Endpoint: `GET /api/cases` — every case with item/note/tag counts. */
    cases(): Promise<Case[]>;
    /**
     * One case with items, notes and tags.
     *
     * Endpoint: `GET /api/cases/{case_id}`.
     *
     * @throws NotFoundError when the id is unknown.
     */
    case(caseId: number): Promise<Case>;
    /**
     * Create a case.
     *
     * Endpoint: `POST /api/cases` with body `{name, description}` (201).
     *
     * @throws BadRequestError when the name is blank.
     */
    createCase(name: string, description?: string): Promise<Case>;
    /**
     * Update case status.
     *
     * Endpoint: `PATCH /api/cases/{case_id}` with body
     * `{status: "open"|"closed"|"archived"}`.
     *
     * @throws BadRequestError for an unknown status.
     * @throws NotFoundError when the id is unknown.
     */
    updateCase(caseId: number, status: string): Promise<Case>;
    /**
     * Add an item to a case.
     *
     * Endpoint: `POST /api/cases/{case_id}/items` with body
     * `{kind: "auto", target, note?}` (201) — `note` is only sent when given.
     *
     * @throws BadRequestError when the target is blank.
     */
    addCaseItem(caseId: number, target: string, options?: {
        kind?: string;
        note?: string;
    }): Promise<Case>;
    /**
     * Append a note to a case.
     *
     * Endpoint: `POST /api/cases/{case_id}/notes` with body `{note}` (201).
     *
     * @throws BadRequestError when the note is blank.
     */
    addCaseNote(caseId: number, body: string): Promise<Case>;
    /**
     * Add a tag to a case.
     *
     * Endpoint: `POST /api/cases/{case_id}/tags` with body `{tag}` (201).
     *
     * @throws BadRequestError when the tag is blank.
     */
    addCaseTag(caseId: number, tag: string): Promise<Case>;
    /** Endpoint: `GET /api/watch` — every watched target. */
    watch(): Promise<WatchEntry[]>;
    /**
     * Add a target to the watchlist.
     *
     * Endpoint: `POST /api/watch` with body `{target, label}` (201) — returns
     * `{id: <watch id>}`. `label` defaults to `""`; an optional `kind` is
     * forwarded when given (the stock server auto-detects and ignores it).
     *
     * @throws BadRequestError for an invalid or duplicate target.
     */
    addWatch(target: string, options?: {
        label?: string;
        kind?: string;
    }): Promise<WatchAddResult>;
    /**
     * Remove a watch by numeric id or target string.
     *
     * Endpoint: `DELETE /api/watch/{identifier}`.
     *
     * @throws NotFoundError when no matching watch exists.
     */
    removeWatch(idOrTarget: number | string): Promise<RemoveResult>;
    /**
     * Run and diff one watch (id or target) or every watch.
     *
     * Endpoint: `POST /api/watch/check?identifier=...` — one change record
     * per checked watch (`added`/`removed`/`changed`, `is_first`).
     */
    checkWatch(options?: {
        identifier?: string;
    }): Promise<WatchDiff[]>;
    /**
     * Snapshot diff for one watched target (latest two snapshots).
     *
     * Endpoint: `GET /api/diff/{kind}/{target}` — `changed_any` plus
     * `added`/`removed`/`changed` field maps; a single-snapshot target
     * answers with `changed_any: false` and a `note`.
     *
     * @throws NotFoundError when the target is not on the watchlist.
     */
    diff(kind: string, target: string): Promise<DiffReport>;
    /** Endpoint: `GET /api/keys` — which keyed services are configured. */
    keys(): Promise<ServiceKey[]>;
    /**
     * Store an API key for a service.
     *
     * Endpoint: `POST /api/keys/{service}` with body `{key}` — the key lands
     * in the server's git-ignored `config/secrets.yaml`.
     *
     * @throws BadRequestError for an unknown service or blank key.
     */
    setKey(service: string, key: string): Promise<KeyMutationResult>;
    /**
     * Remove a stored API key.
     *
     * Endpoint: `DELETE /api/keys/{service}`.
     *
     * @throws BadRequestError for an unknown service.
     */
    clearKey(service: string): Promise<KeyMutationResult>;
    /**
     * Runtime application settings as dotted-path keys.
     *
     * Endpoint: `GET /api/settings` — the *live* runtime configuration (env
     * overrides included); secret and filesystem paths are never exposed.
     */
    settings(): Promise<SettingsView>;
    /**
     * Update one runtime setting (in-memory only, not persisted).
     *
     * Endpoint: `POST /api/settings` with body
     * `{path: "app.cache_ttl", value: 300}` — only non-blocklisted `app.*`
     * keys are accepted; values are coerced to the current field type.
     *
     * @throws BadRequestError for unknown/protected paths or bad values.
     */
    updateSetting(path: string, value: unknown): Promise<SettingsUpdateResult>;
    /**
     * Encode one input into every scheme plus a full digest panel.
     *
     * Endpoint: `GET /api/tools/encodings?text=...` — `encodings`
     * (hex/base32/base64/base85/url/html/rot13/binary/morse/...) and `hashes`
     * (MD5 → SHA-3/BLAKE2, CRC32). All local computation.
     */
    encode(text: string): Promise<ToolboxResult>;
    /**
     * Decode a value with one scheme, or rank every scheme's attempt.
     *
     * Endpoint: `POST /api/tools/decode` with body `{scheme, value}` — use
     * `scheme: "auto"` (default) for the ranked candidate list.
     *
     * @throws BadRequestError for a blank value or unknown scheme.
     */
    decode(value: string, scheme?: string): Promise<ToolboxResult>;
    /**
     * Decode and inspect a JWT (no signature verification — local).
     *
     * Endpoint: `GET /api/tools/jwt?token=...` — `header`, `payload`,
     * `claims`, `identifiers`, `key_info`, `token_stats`, `notes`.
     *
     * @throws BadRequestError for a malformed token.
     */
    inspectJwt(token: string): Promise<ToolboxResult>;
    /**
     * Identify candidate hash formats for a digest-shaped string.
     *
     * Endpoint: `GET /api/tools/hash-id?value=...` — `candidates` ranked by
     * confidence (`{name, confidence, length, charset, note}`).
     */
    hashId(value: string): Promise<ToolboxResult>;
    /**
     * Parse coordinates (DD/DMS/DDM/UTM/MGRS) and convert to every format.
     *
     * Endpoint: `POST /api/tools/coords` with body `{value}` — `latitude`,
     * `longitude`, `decimal`, `dms`, `ddm`, `utm`, `mgrs`, `geohash`,
     * `maidenhead`.
     *
     * @throws BadRequestError for an unrecognised coordinate format.
     */
    convertCoords(value: string): Promise<ToolboxResult>;
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
    extractEntities(text: string): Promise<ToolboxResult>;
    /**
     * Generate and score typosquatting variants for a domain.
     *
     * Endpoint: `POST /api/tools/squat` with body `{domain}` — omission,
     * insertion, transposition, homoglyphs, bitsquatting, combo-squatting,
     * TLD swaps... Local generation only.
     *
     * @throws BadRequestError for an invalid domain.
     */
    squat(domain: string): Promise<ToolboxResult>;
    /**
     * Ready-to-open search-engine dorks for a target (v6.1).
     *
     * Endpoint: `GET /api/tools/dorks?target=...&kind=...` — the kind is
     * auto-detected unless overridden via `options.kind`; links are generated
     * locally (Google, Bing, DuckDuckGo, Yandex, GitHub code search).
     *
     * @throws BadRequestError for a blank target.
     */
    dorks(target: string, options?: {
        kind?: string;
    }): Promise<DorkReport>;
    /**
     * Descriptive statistics plus a histogram for a numeric list.
     *
     * Endpoint: `POST /api/analytics/stats` with body `{values, bins}` —
     * non-numeric items are dropped server-side; `bins` clamps to 1..100.
     *
     * @throws BadRequestError when `values` has no usable numbers.
     */
    analyticsStats(values: Array<number>, bins?: number): Promise<AnalyticsResult>;
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
    analyticsAnomalies(values: Array<number>, options?: {
        method?: string;
        threshold?: number;
    }): Promise<AnalyticsResult>;
    /**
     * Trend / changepoint summary for a value sequence.
     *
     * Endpoint: `POST /api/analytics/timeseries` with body `{values}` —
     * values are indexed as consecutive days.
     *
     * @throws BadRequestError when `values` has no usable numbers.
     */
    analyticsTimeseries(values: Array<number>): Promise<AnalyticsResult>;
    /**
     * Kilometre-space clustering of `[lat, lon]` coordinate pairs.
     *
     * Endpoint: `POST /api/analytics/clusters` with body
     * `{points, eps_km, min_points}` — great-circle DBSCAN; `epsKm` defaults
     * to 25, `minPoints` to 3.
     *
     * @throws BadRequestError when `points` has no usable rows.
     */
    analyticsClusters(points: Array<[number, number]>, options?: {
        epsKm?: number;
        minPoints?: number;
    }): Promise<AnalyticsResult>;
    /**
     * Stopword-filtered keyword mining for a text.
     *
     * Endpoint: `POST /api/analytics/keywords` with body `{text, top}` —
     * `term`/`count`/`weight` records sorted by weight (`top` default 10).
     *
     * @throws BadRequestError for blank text.
     */
    analyticsKeywords(text: string, top?: number): Promise<AnalyticsResult>;
    /**
     * Script and language fingerprint for a text.
     *
     * Endpoint: `POST /api/analytics/language` with body `{text}` — dominant
     * script, per-script character counts, a language guess with confidence
     * and a human-readable hint.
     *
     * @throws BadRequestError for blank text.
     */
    analyticsLanguage(text: string): Promise<AnalyticsResult>;
    /**
     * Four-metric similarity between two texts.
     *
     * Endpoint: `POST /api/analytics/similarity` with body `{a, b}` —
     * Jaro-Winkler, Levenshtein ratio, bigram similarity, sparse cosine,
     * their mean and both lengths.
     *
     * @throws BadRequestError when either text is blank.
     */
    analyticsSimilarity(a: string, b: string): Promise<AnalyticsResult>;
    /**
     * Graph metrics over an `entities`/`links` payload.
     *
     * Endpoint: `POST /api/analytics/graph` with body `{entities, links}` —
     * node/edge counts, density, components, communities, top entities by
     * degree/PageRank/betweenness, bridges and isolated nodes.
     *
     * @throws BadRequestError when neither list is present.
     */
    analyticsGraph(entities: Array<Record<string, unknown>>, links: Array<Record<string, unknown>>): Promise<AnalyticsResult>;
    /**
     * Enrichment report over stored query history.
     *
     * Endpoint: `GET /api/analytics/history?limit=500` — kind frequency,
     * hour/weekday activity profiles, per-kind success rates, source
     * reliability, day-volume anomalies and the most re-queried targets.
     */
    analyticsHistory(limit?: number): Promise<AnalyticsResult>;
    /**
     * Every configured notification channel plus the protocol vocabularies.
     *
     * Endpoint: `GET /api/notify/channels`.
     */
    notifyChannels(): Promise<NotifyChannels>;
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
    addNotifyChannel(spec: NotifyChannelSpec): Promise<NotifyAddResult>;
    /**
     * Delete one channel by name (delivery history stays behind).
     *
     * Endpoint: `DELETE /api/notify/channels/{name}`.
     *
     * @throws NotFoundError for an unknown channel name.
     */
    removeNotifyChannel(name: string): Promise<RemoveResult>;
    /**
     * Probe one channel with a one-off test message.
     *
     * Endpoint: `POST /api/notify/channels/{name}/test` — subscription/
     * severity/quiet-hours/dedup filters are bypassed. A delivery failure is
     * a `200` with `{ok: false, error}` (data, not an HTTP error).
     *
     * @throws NotFoundError for an unknown channel name.
     */
    testNotifyChannel(name: string): Promise<NotifyDelivery>;
    /**
     * Recent notification history, newest first.
     *
     * Endpoint: `GET /api/notify/recent?limit=20` — sends, failures and
     * skips alike.
     */
    notifyRecent(limit?: number): Promise<NotifyRecent>;
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
    notifyBroadcast(spec: NotifyBroadcastSpec): Promise<NotifyDelivery>;
    /**
     * Every scheduled task (schedules, bookkeeping fields, health).
     *
     * Endpoint: `GET /api/automation/tasks`.
     */
    automationTasks(): Promise<AutomationTasks>;
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
    addAutomationTask(spec: AutomationTaskSpec): Promise<AutomationAddResult>;
    /**
     * Delete one scheduled task by name.
     *
     * Endpoint: `DELETE /api/automation/tasks/{name}`.
     *
     * @throws NotFoundError for an unknown task name.
     */
    removeAutomationTask(name: string): Promise<RemoveResult>;
    /**
     * Execute one task now, regardless of its schedule.
     *
     * Endpoint: `POST /api/automation/tasks/{name}/run` — a failing executor
     * is a `200` with `{ok: false, error}` (the run outcome, not an HTTP
     * error). Bookkeeping is left to `runDueAutomation`.
     *
     * @throws NotFoundError for an unknown task name.
     */
    runAutomationTask(name: string): Promise<AutomationRunResult>;
    /**
     * Run every task whose schedule has arrived, then persist the
     * bookkeeping (`last_run`, `run_count`, `error_count`, `next_run`).
     *
     * Endpoint: `POST /api/automation/run-due` — exactly what the background
     * tick loop does every 30 seconds.
     */
    runDueAutomation(): Promise<AutomationRunDue>;
    /**
     * When every task runs next: the stored `next_run` plus a fresh
     * recomputation from *now*.
     *
     * Endpoint: `GET /api/automation/next`.
     */
    automationNext(): Promise<AutomationNext>;
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
    exportStix(kind: LookupKind | string, target: string): Promise<StixBundle>;
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
    exportMisp(kind: LookupKind | string, target: string): Promise<MispEvent>;
    /**
     * Export an investigation entity graph as text.
     *
     * Endpoint: `GET /api/export/{fmt}/{target}?pivot=...` — `{target,
     * format, graph, entities, links}` with `graph` being graphml/gexf/dot/
     * jsonl/csv text; `pivot` defaults to `true`.
     *
     * @throws BadRequestError for an unknown format or undetectable target.
     */
    exportGraph(fmt: string, target: string, options?: {
        pivot?: boolean;
    }): Promise<GraphExport>;
    /**
     * Pattern-of-life analysis for one target across stored history.
     *
     * Endpoint: `GET /api/patterns?kind=...&target=...` — hour/weekday
     * histograms, 7×24 activity matrix, cadence, bursts.
     */
    patterns(kind: string, target: string): Promise<PatternReport>;
    /**
     * Batch lookup up to 25 targets of one kind.
     *
     * Endpoint: `POST /api/tools/batch` with body `{kind, targets, risk}`.
     *
     * @throws BadRequestError for an unknown kind or empty targets.
     */
    batch(kind: string, targets: string[], options?: {
        risk?: boolean;
    }): Promise<BatchProgress>;
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
    setStreamTopics(topics: string[] | string): Promise<StreamTopicsResult>;
    /**
     * The absolute URL for the server-sent-events feed — connect with the
     * runtime's `EventSource`/`fetch` streaming.
     *
     * Endpoint: `GET /api/stream` (`?topics=a,b&max_events=...` optional) —
     * `connected`, `lookup`, `watch` and `heartbeat` frames.
     */
    streamUrl(options?: {
        topics?: string[] | string;
        maxEvents?: number;
    }): string;
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
    rawGet(path: string, params?: Record<string, unknown>): Promise<unknown>;
    /**
     * POST any API path and resolve with the parsed JSON.
     *
     * @param path - absolute path starting with `/`.
     * @param jsonBody - the JSON body to send (`undefined` = empty body).
     */
    rawPost(path: string, jsonBody?: unknown): Promise<unknown>;
    /**
     * DELETE any API path and resolve with the parsed JSON.
     *
     * @param path - absolute path starting with `/`.
     */
    rawDelete(path: string): Promise<unknown>;
}
