/**
 * Response payload types for the ObscuraLens REST API (v6.x).
 *
 * These interfaces describe what the server *actually returns* — they are the
 * source of truth being `obscuralens/web/app.py`. The server is the contract:
 * every type is deliberately tolerant (optional fields, index signatures via
 * `Record<string, unknown>` bases) so unknown or future keys never break
 * compilation. Each interface's JSDoc names the endpoint it models.
 *
 * Numeric IDs are `number`, ISO timestamps are `string`, and "loose" nested
 * blocks stay `Record<string, unknown>`.
 *
 * @module obscuralens-sdk/types
 */
/**
 * The 20 target kinds supported by the v6.x API — mirrors the `KINDS` tuple
 * in `obscuralens/web/app.py` and `obscuralens/sdk/models.py`.
 *
 * The five core kinds, nine v4/v5 additions and the six v6.0 sensor kinds
 * (vin, flight, mmsi, app, bssid, plate).
 */
export type LookupKind = "ip" | "phone" | "username" | "email" | "domain" | "url" | "crypto" | "hash" | "cve" | "asn" | "mac" | "iban" | "imei" | "coords" | "vin" | "flight" | "mmsi" | "app" | "bssid" | "plate";
/** Readonly tuple of every {@link LookupKind} (order matches the server). */
export declare const KINDS: readonly LookupKind[];
/**
 * Field each tracker uses to echo back the queried target — mirrors
 * `_TARGET_KEY` in `obscuralens/web/app.py` (e.g. `phone` → `phone_number`,
 * `crypto` → `address`).
 */
export declare const TARGET_KEYS: Readonly<Record<LookupKind, string>>;
/**
 * Evidence-confidence line for one field (v6.1).
 *
 * Endpoint: attached to every `GET /api/lookup/{kind}/{target}` envelope
 * under the `confidence.per_field` map by `correlation/confidence.py`.
 */
export interface FieldConfidenceEntry {
    /** 0..1 corroboration score for the field. */
    score: number;
    /** How many sources supplied the field. */
    sources: number;
    /** Human band for the score ("strong", "moderate"...). */
    band?: string;
    /** Supplying source names, in trust order. */
    names?: string[];
    [key: string]: unknown;
}
/** The `confidence` block attached to lookup envelopes (v6.1). */
export interface ConfidenceBlock {
    /** Mean of the per-field scores, 0..1. */
    overall: number;
    /** Human band for the overall score. */
    band: string;
    /** How many fields were scored. */
    fields_scored: number;
    /** Fields supplied by two or more sources. */
    corroborated: number;
    /** Field name → {@link FieldConfidenceEntry}. */
    per_field: Record<string, FieldConfidenceEntry>;
}
/** One named source's contribution to a field (provenance entry). */
export interface FieldProvenance {
    /** Field name the entry documents (e.g. `country`). */
    field: string;
    /** Source names that supplied the field, in confidence order. */
    sources: string[];
    [key: string]: unknown;
}
/**
 * The standard lookup envelope — the response of
 * `GET /api/lookup/{kind}/{target}` (and the base of `/api/risk/...`).
 *
 * The echoed target sits under the kind's {@link TARGET_KEYS} field (`ip`,
 * `phone_number`, `address`...), `info` carries the merged fields, and
 * `field_sources` maps each field to the sources that supplied it.
 */
export interface LookupEnvelope {
    /** True when at least one source answered. */
    success: boolean;
    /** Merged field values (the envelope's `info` block). */
    info: Record<string, unknown>;
    /** Field name → supplying source names (per-field provenance). */
    field_sources?: Record<string, string[]>;
    /** Sources that answered successfully. */
    sources_ok: string[];
    /** Source name → error message for sources that failed. */
    sources_failed: Record<string, string>;
    /** How many fields carry a value. */
    field_count: number;
    /** Server-side error strings (present when sources failed). */
    errors?: string[];
    /** Single error string on a total tracker failure. */
    error?: string;
    /** Wall-clock seconds the server took, when reported. */
    elapsed?: number;
    /** Evidence-confidence annotation (v6.1, when provenance exists). */
    confidence?: ConfidenceBlock;
    /** Risk annotation when this envelope came from `/api/risk/...`. */
    risk?: RiskBlock;
    /** The echoed target value under its kind-specific key. */
    [key: string]: unknown;
}
/** One weighted heuristic signal inside a {@link RiskReport}. */
export interface RiskSignal {
    /** Signal id (e.g. `risky_service_tags`). */
    id: string;
    /** Points contributed to the score. */
    weight: number;
    /** Human-readable explanation. */
    detail: string;
    [key: string]: unknown;
}
/** The bare `risk` block attached to a risk envelope. */
export interface RiskBlock {
    /** 0-100 weighted signal sum. */
    score: number;
    /** Verdict band: clean / low / medium / high / critical / unknown. */
    verdict: string;
    /** Why the score is what it is. */
    signals: RiskSignal[];
    /** Server-generated one-liner. */
    summary?: string;
    [key: string]: unknown;
}
/**
 * Explainable heuristic risk score for one target.
 *
 * Endpoint: `GET /api/risk/{kind}/{target}` — a full lookup envelope with the
 * {@link RiskBlock} attached under `risk`.
 */
export interface RiskReport extends LookupEnvelope {
    risk: RiskBlock;
}
/** One entity in an investigation/correlation graph. */
export interface GraphEntity {
    /** Stable entity id (hash of type + value). */
    id: string;
    /** Entity type (`ip`, `domain`, `email`...). */
    type: string;
    /** Entity value. */
    value: string;
    /** Role in the investigation (`target`, `pivot`...). */
    role?: string;
    [key: string]: unknown;
}
/** One relationship edge in an investigation/correlation graph. */
export interface GraphLink {
    /** Source entity id. */
    source: string;
    /** Target entity id. */
    target: string;
    /** Relationship label (`resolves_to`, `registered_by`...). */
    relation?: string;
    [key: string]: unknown;
}
/**
 * The auto-detect investigation dossier.
 *
 * Endpoint: `GET /api/investigate?target=...&pivot=...` — `{target, kind,
 * entities, links, ...}` with pivot expansion.
 */
export interface InvestigationReport {
    /** The investigated value. */
    target: string;
    /** Auto-detected kind (`ip`, `domain`...). */
    kind: string;
    /** Discovered entities (the target plus pivots). */
    entities: GraphEntity[];
    /** Entity relationships. */
    links: GraphLink[];
    [key: string]: unknown;
}
/** One dated event on the history timeline. */
export interface TimelineEvent {
    /** Human-readable event date. */
    date: string;
    /** Sortable date key. */
    sort_key: string;
    /** Event source kind. */
    kind: string;
    /** Event target value. */
    target: string;
    /** Event label (e.g. `first seen`). */
    label?: string;
    [key: string]: unknown;
}
/**
 * Chronological event timeline across stored lookup history.
 *
 * Endpoint: `GET /api/timeline?target=...&limit=...` — events sorted oldest →
 * newest.
 */
export interface Timeline {
    events: TimelineEvent[];
    /** Number of events kept. */
    count: number;
    /** Oldest event date, or `null`. */
    first: string | null;
    /** Newest event date, or `null`. */
    last: string | null;
}
/** One entity cluster in a correlation graph. */
export interface CorrelationCluster {
    /** Cluster index. */
    cluster: number;
    /** Entity ids in the cluster. */
    entities: string[];
    [key: string]: unknown;
}
/**
 * Correlation graph, clusters and bridge entities from history.
 *
 * Endpoint: `GET /api/correlate?limit=...` — `{entities, links, clusters,
 * stats, degree}` (an empty history yields empty lists and `{}` stats).
 */
export interface CorrelationResult {
    entities: GraphEntity[];
    links: GraphLink[];
    clusters: CorrelationCluster[];
    stats: Record<string, unknown>;
    [key: string]: unknown;
}
/**
 * Shared-infrastructure comparison between two targets.
 *
 * Endpoint: `GET /api/correlate/pair?a=...&b=...` — `{targets, shared,
 * connections, related}` plus per-bridge detail.
 */
export interface PairComparison {
    /** The two compared values `[a, b]`. */
    targets: string[];
    /** Shared infrastructure entities. */
    shared: Record<string, unknown>[];
    /** Number of shared connections. */
    connections: number;
    /** True when the targets are related. */
    related: boolean;
    [key: string]: unknown;
}
/**
 * Threat-intel verdict for an IP.
 *
 * Endpoint: `GET /api/intel/{target}` — Tor exit status, blocklist feeds and
 * relay details.
 */
export interface IntelVerdict {
    /** The checked IP. */
    ip: string;
    /** Blocklist feed hits (`{feed: hit}`-shaped record). */
    feeds: Record<string, unknown>;
    /** True when the IP is a known Tor exit node. */
    tor_exit: boolean;
    /** Tor relay details when it is one, else `null`. */
    relay: Record<string, unknown> | null;
}
/**
 * Source catalogues for every kind.
 *
 * Endpoint: `GET /api/sources` — kind → {source name → description}.
 */
export type SourceInfo = Record<string, Record<string, string>>;
/** One source's health entry inside `/api/stats`' `source_health` list. */
export interface SourceHealthEntry {
    /** Source name. */
    source: string;
    /** Rolling success ratio 0..1. */
    success_rate: number;
    /** Consecutive failures. */
    consecutive_failures?: number;
    /** Window size. */
    window?: number;
    /** Deconfigured at ISO timestamp, or `null`. */
    disabled_until?: string | null;
    [key: string]: unknown;
}
/**
 * Database, cache, network and source-health statistics.
 *
 * Endpoint: `GET /api/stats`.
 */
export interface StatsSummary {
    database: Record<string, unknown>;
    cache: Record<string, unknown>;
    network: Record<string, unknown>;
    source_health: SourceHealthEntry[];
    [key: string]: unknown;
}
/** One kind's registry row. Endpoint: `GET /api/kinds` (a JSON array). */
export interface KindInfo {
    /** The kind slug (`ip`, `vin`...). */
    kind: string;
    /** Human label ("IP address"). */
    label: string;
    /** Example target value. */
    example: string;
    /** One-line blurb. */
    blurb: string;
    /** Sorted source names backing the kind. */
    sources: string[];
    /** How many sources back the kind. */
    source_count: number;
    [key: string]: unknown;
}
/** One stored lookup row. Endpoint: inside `GET /api/history`'s `items`. */
export interface HistoryItem {
    id: number;
    kind: string;
    value: string;
    timestamp: string;
    success: boolean;
    field_count: number;
    error: string;
    [key: string]: unknown;
}
/**
 * Search result over stored lookup history.
 *
 * Endpoint: `GET /api/history?kind=...&q=...&limit=...`.
 */
export interface HistoryResult {
    items: HistoryItem[];
    count: number;
    limit: number;
    kind: string;
    q: string;
}
/** One evidence item inside a case. */
export interface CaseItem {
    id: number;
    case_id: number;
    kind: string;
    target: string;
    note?: string | null;
    created_at: string;
    [key: string]: unknown;
}
/** One analyst note inside a case. */
export interface CaseNote {
    id: number;
    case_id: number;
    note: string;
    created_at: string;
    [key: string]: unknown;
}
/**
 * One investigation case with items, notes and tags.
 *
 * Endpoints: `GET /api/cases`, `GET /api/cases/{id}`, `POST /api/cases`,
 * `PATCH /api/cases/{id}` (status open/closed/archived),
 * `POST /api/cases/{id}/items|notes|tags`.
 */
export interface Case {
    id: number;
    name: string;
    description: string;
    status: string;
    created_at: string;
    updated_at?: string;
    items?: CaseItem[];
    notes?: CaseNote[];
    tags?: string[];
    item_count?: number;
    note_count?: number;
    tag_count?: number;
    [key: string]: unknown;
}
/**
 * One watched target.
 *
 * Endpoints: `GET /api/watch`, `POST /api/watch` (returns `{'id': n}`).
 */
export interface WatchEntry {
    id: number;
    target: string;
    kind: string;
    label: string;
    snapshot_count: number;
    last_checked: string | null;
    created_at?: string;
    [key: string]: unknown;
}
/** One watchlist check diff (POST /api/watch/check response rows). */
export interface WatchDiff {
    watch_id: number;
    target: string;
    kind: string;
    is_first: boolean;
    changed_any: boolean;
    added: Record<string, string>;
    removed: Record<string, string>;
    changed: Record<string, string>;
    checked_at?: string;
    [key: string]: unknown;
}
/**
 * Snapshot diff for one watched target (latest two snapshots).
 *
 * Endpoint: `GET /api/diff/{kind}/{target}` — `changed: false` plus a `note`
 * when fewer than two snapshots exist.
 */
export interface DiffReport {
    target: string;
    kind: string;
    changed_any: boolean;
    added: Record<string, string>;
    removed: Record<string, string>;
    changed: Record<string, string>;
    note?: string;
    previous?: string;
    current?: string;
}
/** One keyed service's configuration state. Endpoint: `GET /api/keys`. */
export interface ServiceKey {
    /** Service slug (`shodan`, `virustotal`...). */
    service: string;
    /** True when a key is stored (values are never returned). */
    configured: boolean;
    /** Friendly description. */
    description: string;
    [key: string]: unknown;
}
/** Runtime application settings view. Endpoint: `GET /api/settings`. */
export interface SettingsView {
    /** Dotted-path keys → live values (`app.cache_ttl`...). */
    settings: Record<string, unknown>;
    version: string;
    note: string;
    [key: string]: unknown;
}
/** Result of `POST /api/settings` / `POST /api/keys/{service}` mutations. */
export interface MutationOk {
    ok: boolean;
    [key: string]: unknown;
}
/** Result of a settings update. Endpoint: `POST /api/settings`. */
export interface SettingsUpdateResult {
    ok: boolean;
    /** The dotted setting path that was changed. */
    path: string;
    /** The coerced value now in effect. */
    value: unknown;
}
/** Result of storing or clearing an API key. Endpoint: `POST|DELETE /api/keys/{service}`. */
export interface KeyMutationResult {
    ok: boolean;
    service: string;
    configured: boolean;
}
/** Result of adding a watch. Endpoint: `POST /api/watch` (201). */
export interface WatchAddResult {
    id: number;
    [key: string]: unknown;
}
/** Generic `{'ok': true, 'removed': ...}` payload (watch/channel/task removals). */
export interface RemoveResult {
    ok?: boolean;
    removed?: string | number;
    [key: string]: unknown;
}
/** Result of registering a channel. Endpoint: `POST /api/notify/channels`. */
export interface NotifyAddResult {
    ok: boolean;
    channel: NotifyChannel;
    [key: string]: unknown;
}
/** Result of registering a task. Endpoint: `POST /api/automation/tasks`. */
export interface AutomationAddResult {
    ok: boolean;
    task: AutomationTask;
    [key: string]: unknown;
}
/** Result of declaring stream topics. Endpoint: `POST /api/stream/subscribe`. */
export interface StreamTopicsResult {
    topics: string[];
    count: number;
    subscriber_count: number;
}
/**
 * Generic analyst-toolbox result.
 *
 * Endpoints: `GET /api/tools/encodings`, `POST /api/tools/decode`,
 * `GET /api/tools/jwt`, `GET /api/tools/hash-id`, `POST /api/tools/coords`,
 * `POST /api/tools/extract`, `POST /api/tools/squat` — the payload varies by
 * tool; typed accessors live in the docs of each client method.
 */
export interface ToolboxResult {
    /** The input the tool worked on (`text` / `value` / `domain`...). */
    [key: string]: unknown;
}
/** One ready-to-open search-engine dork link (v6.1). */
export interface DorkLink {
    /** Search engine (`google`, `bing`, `duckduckgo`, `yandex`, `github`). */
    engine: string;
    /** Human label ("Exact match"). */
    label: string;
    /** The dork query string. */
    query: string;
    /** Ready-to-open URL. */
    url: string;
    [key: string]: unknown;
}
/**
 * Dork report for a target.
 *
 * Endpoint: `GET /api/tools/dorks?target=...&kind=...` — links are generated
 * locally; the analyst stays in control of every active query.
 */
export interface DorkReport {
    target: string;
    /** Server-detected kind, or `null` when detection failed. */
    detected_kind: string | null;
    count: number;
    dorks: DorkLink[];
    /** Kinds that carry dork templates. */
    dork_kinds: string[];
}
/**
 * Generic analytics response envelope (v6.0 part 2 — offline, pure
 * computation).
 *
 * Endpoints: `POST /api/analytics/stats|anomalies|timeseries|clusters|
 * keywords|language|similarity|graph` and `GET /api/analytics/history`.
 * Each endpoint's block differs — see the client method docs; unknown keys
 * pass through untouched.
 */
export interface AnalyticsResult {
    [key: string]: unknown;
}
/** One configured notification channel. */
export interface NotifyChannel {
    /** Unique human label. */
    name: string;
    /** Channel type (webhook/telegram/discord/slack/smtp). */
    type: string;
    /** Where messages go (URL, `bot_token:chat_id`, SMTP spec). */
    target?: string;
    /** Subscribed event types (empty = everything). */
    events?: string[];
    /** Weakest severity rung worth waking the channel. */
    min_severity?: string;
    /** Local-hour quiet window `[start, end]` (wraps past midnight). */
    quiet_hours?: [number, number];
    /** Master switch. */
    enabled?: boolean;
    [key: string]: unknown;
}
/**
 * Every configured notification channel plus the protocol vocabularies.
 *
 * Endpoint: `GET /api/notify/channels`.
 */
export interface NotifyChannels {
    count: number;
    channels: NotifyChannel[];
    /** Valid channel types. */
    channel_types: string[];
    /** Severity ladder (info → critical). */
    severities: string[];
}
/** Delivery outcome for a channel test or a broadcast. */
export interface NotifyDelivery {
    /** True when the pipe worked / at least one channel accepted. */
    ok: boolean;
    /** Failure description, or `""`. */
    error?: string;
    /** The probed channel (test shape). */
    channel?: string;
    /** Per-channel results (broadcast shape). */
    results?: Record<string, unknown>[];
    /** Broadcast aggregate: channels that accepted the event. */
    sent?: number;
    /** Broadcast aggregate: channels whose filters skipped it. */
    skipped?: number;
    /** Broadcast aggregate: channels that failed. */
    failed?: number;
    /** Broadcast aggregate: total channels tried. */
    total?: number;
    [key: string]: unknown;
}
/** Spec accepted by {@link import("./client.js").ObscuraLensClient.addNotifyChannel}. */
export interface NotifyChannelSpec {
    name: string;
    type: string;
    target?: string;
    events?: string[];
    min_severity?: string;
    quiet_hours?: [number, number];
    [key: string]: unknown;
}
/** Recent notification log. Endpoint: `GET /api/notify/recent?limit=...`. */
export interface NotifyRecent {
    count: number;
    recent: Array<Record<string, unknown>>;
    [key: string]: unknown;
}
/** Broadcast request body (POST /api/notify/broadcast). */
export interface NotifyBroadcastSpec {
    title: string;
    body: string;
    severity?: string;
    eventType?: string;
}
/** Spec accepted by {@link import("./client.js").ObscuraLensClient.addAutomationTask}. */
export interface AutomationTaskSpec {
    /** Unique human label (max 80 chars). */
    name: string;
    /** One of watch_check / pipeline / report / feed_refresh / notify_test. */
    action: string;
    /** `interval` (default) / `daily` / `weekly`. */
    schedule?: string;
    /** Period for the interval schedule (default 3600). */
    interval_seconds?: number;
    /** `'HH:MM'` local time for daily/weekly schedules. */
    at_time?: string;
    /** 0 = Monday … 6 = Sunday (weekly schedule). */
    weekday?: number;
    /** The executor's payload. */
    params?: Record<string, unknown>;
    /** Master switch — disabled tasks are never due. */
    enabled?: boolean;
    [key: string]: unknown;
}
/** One scheduled task with bookkeeping and health (GET /api/automation/tasks rows). */
export interface AutomationTask {
    name: string;
    action: string;
    schedule: string;
    enabled: boolean;
    interval_seconds?: number;
    at_time?: string | null;
    weekday?: number | null;
    params?: Record<string, unknown> | null;
    last_run?: string | null;
    next_run?: string | null;
    run_count?: number;
    error_count?: number;
    last_error?: string | null;
    created_at?: string;
    [key: string]: unknown;
}
/**
 * Every scheduled task plus the action/schedule vocabularies.
 *
 * Endpoint: `GET /api/automation/tasks`.
 */
export interface AutomationTasks {
    count: number;
    tasks: AutomationTask[];
    /** Valid task actions. */
    actions: string[];
    /** Valid schedule types. */
    schedule_types: string[];
}
/** One manual run outcome (POST /api/automation/tasks/{name}/run). */
export interface AutomationRunResult {
    ok: boolean;
    started?: string;
    finished?: string;
    error?: string;
    summary?: string;
    [key: string]: unknown;
}
/** Run-due aggregate (POST /api/automation/run-due). */
export interface AutomationRunDue {
    ran: number;
    results: AutomationRunResult[];
}
/** One row of the next-run snapshot (GET /api/automation/next). */
export interface AutomationNextTask {
    name: string;
    action: string;
    schedule: string;
    enabled: boolean;
    stored_next_run: string | null;
    recomputed_next_run: string | null;
}
/** Next-run snapshot for every task. Endpoint: `GET /api/automation/next`. */
export interface AutomationNext {
    count: number;
    tasks: AutomationNextTask[];
}
/** One object inside a STIX bundle. */
export interface StixObject {
    /** STIX object type (`identity`, `indicator`, `observed-data`...). */
    type: string;
    id?: string;
    [key: string]: unknown;
}
/**
 * A STIX 2.1 bundle for the newest stored lookup of one target.
 *
 * Endpoint: `GET /api/export/stix/{kind}/{target}` — deterministic UUIDv5 ids
 * throughout so re-imports merge. Run the lookup first.
 */
export interface StixBundle {
    type: "bundle";
    id?: string;
    objects: StixObject[];
    [key: string]: unknown;
}
/** One MISP attribute inside an event. */
export interface MispAttribute {
    category?: string;
    type?: string;
    value?: string;
    to_ids?: boolean;
    comment?: string;
    uuid?: string;
    timestamp?: string;
    [key: string]: unknown;
}
/** One MISP core-format event (bare-event shape accepted too). */
export interface MispEvent {
    Event?: {
        uuid?: string;
        info?: string;
        threat_level_id?: string;
        analysis?: string;
        timestamp?: string;
        Attribute?: MispAttribute[];
        Tag?: Array<Record<string, unknown>>;
        [key: string]: unknown;
    };
    [key: string]: unknown;
}
/**
 * Graph export as text.
 *
 * Endpoint: `GET /api/export/{fmt}/{target}?pivot=...` — `{target, format,
 * graph, entities, links}` with `graph` being graphml/gexf/dot/jsonl/csv text.
 */
export interface GraphExport {
    target: string;
    format: string;
    graph: string;
    entities: number;
    links: number;
    [key: string]: unknown;
}
/** Webhook alert configuration plus the recent event log (GET /api/alerts). */
export interface AlertConfig {
    webhook_url?: string;
    events?: string[];
    recent?: Array<Record<string, unknown>>;
    event_types?: string[];
    [key: string]: unknown;
}
/** Pattern-of-life analysis report. Endpoint: `GET /api/patterns?kind=&target=`. */
export interface PatternReport {
    kind: string;
    target: string;
    [key: string]: unknown;
}
/** One batch entry (success or failure row). */
export interface BatchEntry {
    target: string;
    ok: boolean;
    [key: string]: unknown;
}
/** Batch lookup progress/result (POST /api/tools/batch, up to 25 targets). */
export interface BatchProgress {
    kind: string;
    total: number;
    ok: number;
    failed: number;
    results: BatchEntry[];
    [key: string]: unknown;
}
/** Alias: batch responses share the progress shape. */
export type BatchResult = BatchProgress;
/** One server-sent-event frame from `GET /api/stream`. */
export interface StreamEvent {
    /** Event topic (`connected`, `lookup`, `watch`, `heartbeat`). */
    event: string;
    /** Parsed JSON data of the frame. */
    data: Record<string, unknown>;
}
