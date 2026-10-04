/**
 * InvestigationSession — a fluent, receipt-keeping investigation wrapper.
 *
 * The {@link import("./client.js").ObscuraLensClient} is a thin endpoint
 * mapper; real OSINT work is a *sequence* of steps — look up the IP, pivot
 * to the domain, score the risk, build dorks, jot a note — and the
 * interesting artefact is the **trail**, not any single response.
 * `InvestigationSession` wraps a client and records every step it performs
 * so the analyst can summarise and export the whole investigation at the
 * end:
 *
 * ```js
 * import { ObscuraLensClient, InvestigationSession } from "obscuralens-sdk";
 *
 * const client = new ObscuraLensClient({ baseUrl: "http://127.0.0.1:8000" });
 * const session = new InvestigationSession(client, { label: "phishing-2024" });
 *
 * await session.lookup("ip", "1.2.3.4");          // records a step
 * await session.investigate("evil.example.com");  // records a step
 * await session.risk("domain", "evil.example.com");
 * session.note("victim reported 2024-05-01");
 * await session.dorks("evil.example.com");
 *
 * console.log(session.summary());   // multi-step report
 * console.log(session.toJSON());    // JSON receipt
 * ```
 *
 * Design notes (independently designed, mirroring the Python SDK's session
 * in spirit):
 *
 * - **Composition over HTTP** — the session never touches a transport; it
 *   only calls public client methods, so a `StaticTransport` under the
 *   client makes the whole session testable offline.
 * - **Errors are data** — a failing step records the exception (type and
 *   message) and the investigation *continues*, resolving `undefined`;
 *   `strict: true` flips the behaviour to reject instead, for pipelines
 *   that want fail-fast (the step is still recorded first).
 * - **Receipts are portable** — `toObject()`/`toJSON()` produce a
 *   plain-JSON receipt of every step, target and count.
 *
 * @module obscuralens-sdk/session
 */
import type { ObscuraLensClient } from "./client.js";
import type { DorkReport, InvestigationReport, LookupEnvelope, LookupKind, RiskReport } from "./types.js";
/** Receipt format written by {@link InvestigationSession.toJSON}. */
export declare const RECEIPT_FORMAT = "obscuralens-session-js/1";
/** One recorded investigation step. */
export declare class SessionStep {
    readonly action: string;
    readonly target: string;
    readonly ok: boolean;
    readonly error: string;
    readonly durationMs: number;
    readonly detail: string;
    readonly at: string;
    /**
     * @param action - the session action that ran (`lookup`, `investigate`,
     *   `risk`, `dorks`, `note`).
     * @param target - the step's target value (`""` for notes).
     * @param ok - `true` when the step completed without rejecting.
     * @param error - `"ErrorType: message"` for failed steps, `""` otherwise.
     * @param durationMs - wall-clock milliseconds the step took.
     * @param detail - one-line human summary of the result.
     * @param at - ISO timestamp recorded when the step finished.
     */
    constructor(action: string, target: string, ok: boolean, error: string, durationMs: number, detail: string, at?: string);
    /** One-line headline: `ok   lookup ip 1.2.3.4 (12 fields...)`. */
    get headline(): string;
    /** The JSON-ready step record (receipts embed a list of these). */
    toRecord(): Record<string, unknown>;
    /** Rebuild one step from its receipt record (junk-tolerant). */
    static fromRecord(record: Record<string, unknown>): SessionStep;
}
/** Constructor options for {@link InvestigationSession}. */
export interface SessionOptions {
    /** Human label for the receipt ("phishing-2024"). */
    label?: string;
    /**
     * Fail-fast mode: a failing step is *still recorded* and then re-thrown.
     * When `false` (default) failures are captured as step data and the
     * method resolves `undefined`.
     */
    strict?: boolean;
}
/** Shape returned by {@link InvestigationSession.toObject}. */
export interface SessionReceipt {
    format: string;
    label: string;
    startedAt: string;
    closed: boolean;
    counts: {
        steps: number;
        ok: number;
        failed: number;
        targets: number;
    };
    targets: string[];
    notes: string[];
    steps: Array<Record<string, unknown>>;
}
/**
 * The fluent investigation wrapper — see the module docs.
 */
export declare class InvestigationSession {
    /** The wrapped client (the session never closes it). */
    readonly client: ObscuraLensClient;
    /** Human label for the receipt. */
    readonly label: string;
    /** Fail-fast mode — see {@link SessionOptions.strict}. */
    readonly strict: boolean;
    /** ISO timestamp captured when the session was created. */
    readonly startedAt: string;
    private readonly steps;
    private readonly notes;
    private readonly seenTargets;
    private closed;
    constructor(client: ObscuraLensClient, options?: SessionOptions);
    /**
     * Run a lookup and record the step. `GET /api/lookup/{kind}/{target}`.
     *
     * @throws (strict mode only) whatever the client rejected with, after
     *   recording the step.
     */
    lookup(kind: LookupKind | string, target: string): Promise<LookupEnvelope | undefined>;
    /**
     * Run an investigation and record the step.
     * `GET /api/investigate?target=...`.
     */
    investigate(target: string, options?: {
        pivot?: boolean;
    }): Promise<InvestigationReport | undefined>;
    /**
     * Run a risk score and record the step.
     * `GET /api/risk/{kind}/{target}`.
     */
    risk(kind: LookupKind | string, target: string): Promise<RiskReport | undefined>;
    /**
     * Build search-engine dorks and record the step.
     * `GET /api/tools/dorks?target=...`.
     */
    dorks(target: string, options?: {
        kind?: string;
    }): Promise<DorkReport | undefined>;
    /**
     * Jot a free-form analyst note (no HTTP; recorded as a step).
     *
     * @returns The note text, for chaining.
     */
    note(text: string): string;
    /** A copy of every recorded step, in order. */
    get allSteps(): SessionStep[];
    /** One recorded step by index (0-based), or `undefined`. */
    step(index: number): SessionStep | undefined;
    /** How many steps were recorded. */
    get stepCount(): number;
    /** How many steps succeeded. */
    get okCount(): number;
    /** How many steps failed. */
    get failedCount(): number;
    /** The analyst notes, in order. */
    get notesTaken(): string[];
    /**
     * Every distinct target the session touched, first-seen order (failed
     * lookups included, notes excluded).
     */
    targets(): string[];
    /**
     * Multi-line human summary of the whole session:
     * counts, targets, per-step headlines and notes.
     */
    summary(): string;
    /** The portable receipt object (see {@link SessionReceipt}). */
    toObject(): SessionReceipt;
    /**
     * The receipt as a JSON string.
     *
     * @param indent - indentation passed to `JSON.stringify` (default 2;
     *   pass `0` for compact output).
     */
    toJSON(indent?: number): string;
    /** Marks the session closed — further recorded actions throw. */
    close(): void;
    /** Debug representation. */
    toString(): string;
    private assertOpen;
    private rememberTarget;
    private runStep;
}
