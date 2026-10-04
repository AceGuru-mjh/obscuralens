/**
 * obscuralens-sdk — the dependency-free TypeScript/JavaScript SDK for the
 * ObscuraLens OSINT REST API (v6.x).
 *
 * ```js
 * import { ObscuraLensClient, InvestigationSession, SdkError } from "obscuralens-sdk";
 *
 * const client = new ObscuraLensClient({ baseUrl: "http://127.0.0.1:8000" });
 * try {
 *   const ip = await client.ip("8.8.8.8");
 *   console.log(ip.info.country, ip.sources_ok);
 * } catch (error) {
 *   if (error instanceof SdkError) console.log(error.status, error.message);
 * } finally {
 *   client.close();
 * }
 * ```
 *
 * Module map:
 *
 * - `client` — {@link import("./client.js").ObscuraLensClient} (all endpoints)
 * - `session` — {@link import("./session.js").InvestigationSession} (fluent wrapper)
 * - `transport` — {@link import("./transport.js").FetchTransport} /
 *   {@link import("./transport.js").StaticTransport} (pluggable HTTP layer)
 * - `errors` — the {@link import("./errors.js").SdkError} hierarchy
 * - `types` — response payload interfaces (the server is the contract)
 *
 * @module obscuralens-sdk
 */
export { ObscuraLensClient, DEFAULT_BASE_URL, DEFAULT_TIMEOUT_MS, DEFAULT_RETRIES, DEFAULT_BACKOFF_MS, DEFAULT_MAX_BACKOFF_MS, EXPORT_FORMATS, CASE_STATUSES, } from "./client.js";
export type { ClientOptions } from "./client.js";
export { InvestigationSession, SessionStep, RECEIPT_FORMAT, } from "./session.js";
export type { SessionOptions, SessionReceipt } from "./session.js";
export { FetchTransport, StaticTransport, jsonResponse, headerValue, buildQuery, buildUrl, SDK_VERSION, SDK_USER_AGENT, API_KEY_HEADER, } from "./transport.js";
export type { HttpResponse, Transport, FetchLike, FetchTransportOptions, TransportScriptItem, RecordedCall, } from "./transport.js";
export { SdkError, TransportError, TimeoutError, ApiError, BadRequestError, NotFoundError, RateLimitError, ServerError, MalformedResponseError, errorForResponse, parseRetryAfterMs, } from "./errors.js";
export type { SdkErrorOptions, ErrorResponseLike } from "./errors.js";
export { KINDS, TARGET_KEYS, } from "./types.js";
export type { LookupKind, FieldConfidenceEntry, ConfidenceBlock, FieldProvenance, LookupEnvelope, RiskSignal, RiskBlock, RiskReport, GraphEntity, GraphLink, InvestigationReport, TimelineEvent, Timeline, CorrelationCluster, CorrelationResult, PairComparison, IntelVerdict, SourceInfo, SourceHealthEntry, StatsSummary, KindInfo, HistoryItem, HistoryResult, Case, CaseItem, CaseNote, WatchEntry, WatchDiff, DiffReport, ServiceKey, SettingsView, SettingsUpdateResult, KeyMutationResult, MutationOk, WatchAddResult, RemoveResult, ToolboxResult, DorkLink, DorkReport, AnalyticsResult, NotifyChannel, NotifyChannels, NotifyDelivery, NotifyChannelSpec, NotifyAddResult, NotifyRecent, NotifyBroadcastSpec, AutomationTaskSpec, AutomationTask, AutomationTasks, AutomationAddResult, AutomationRunResult, AutomationRunDue, AutomationNextTask, AutomationNext, StixBundle, StixObject, MispAttribute, MispEvent, GraphExport, AlertConfig, PatternReport, BatchEntry, BatchProgress, BatchResult, StreamEvent, StreamTopicsResult, } from "./types.js";
