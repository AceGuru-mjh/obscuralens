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
import type {
  DorkReport,
  InvestigationReport,
  LookupEnvelope,
  LookupKind,
  RiskReport,
} from "./types.js";

/** Receipt format written by {@link InvestigationSession.toJSON}. */
export const RECEIPT_FORMAT = "obscuralens-session-js/1";

/** One recorded investigation step. */
export class SessionStep {
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
  constructor(
    public readonly action: string,
    public readonly target: string,
    public readonly ok: boolean,
    public readonly error: string,
    public readonly durationMs: number,
    public readonly detail: string,
    public readonly at: string = new Date().toISOString(),
  ) {}

  /** One-line headline: `ok   lookup ip 1.2.3.4 (12 fields...)`. */
  get headline(): string {
    const status = this.ok ? "ok  " : "FAIL";
    const target = this.target ? ` ${this.target}` : "";
    const detail = this.detail ? ` — ${this.detail}` : "";
    const error = this.error ? ` — ${this.error}` : "";
    return `${status} ${this.action}${target}${detail}${error}`;
  }

  /** The JSON-ready step record (receipts embed a list of these). */
  toRecord(): Record<string, unknown> {
    return {
      action: this.action,
      target: this.target,
      ok: this.ok,
      error: this.error,
      durationMs: Math.round(this.durationMs * 1000) / 1000,
      detail: this.detail,
      at: this.at,
    };
  }

  /** Rebuild one step from its receipt record (junk-tolerant). */
  static fromRecord(record: Record<string, unknown>): SessionStep {
    const pick = (key: string, fallback: unknown): unknown =>
      record[key] === undefined ? fallback : record[key];
    return new SessionStep(
      String(pick("action", "")),
      String(pick("target", "")),
      Boolean(pick("ok", false)),
      String(pick("error", "")),
      Number(pick("durationMs", 0) || 0),
      String(pick("detail", "")),
      String(pick("at", "")),
    );
  }
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
  counts: { steps: number; ok: number; failed: number; targets: number };
  targets: string[];
  notes: string[];
  steps: Array<Record<string, unknown>>;
}

/**
 * The fluent investigation wrapper — see the module docs.
 */
export class InvestigationSession {
  /** The wrapped client (the session never closes it). */
  public readonly client: ObscuraLensClient;
  /** Human label for the receipt. */
  public readonly label: string;
  /** Fail-fast mode — see {@link SessionOptions.strict}. */
  public readonly strict: boolean;
  /** ISO timestamp captured when the session was created. */
  public readonly startedAt: string = new Date().toISOString();
  private readonly steps: SessionStep[] = [];
  private readonly notes: string[] = [];
  private readonly seenTargets: string[] = [];
  private closed = false;

  constructor(client: ObscuraLensClient, options: SessionOptions = {}) {
    this.client = client;
    this.label = options.label ?? "";
    this.strict = options.strict ?? false;
  }

  // ------------------------------------------------------------------
  // Recorded actions
  // ------------------------------------------------------------------

  /**
   * Run a lookup and record the step. `GET /api/lookup/{kind}/{target}`.
   *
   * @throws (strict mode only) whatever the client rejected with, after
   *   recording the step.
   */
  async lookup(
    kind: LookupKind | string,
    target: string,
  ): Promise<LookupEnvelope | undefined> {
    this.assertOpen();
    const kindLabel = String(kind ?? "").trim().toLowerCase();
    return this.runStep("lookup", target, () => this.client.lookup(kind, target),
      (result) => {
        const fields = Number(result.field_count ?? 0);
        const okSources = Array.isArray(result.sources_ok)
          ? result.sources_ok.length
          : 0;
        return `${kindLabel}: ${fields} field(s) from ${okSources} source(s)`;
      });
  }

  /**
   * Run an investigation and record the step.
   * `GET /api/investigate?target=...`.
   */
  async investigate(
    target: string,
    options: { pivot?: boolean } = {},
  ): Promise<InvestigationReport | undefined> {
    this.assertOpen();
    return this.runStep("investigate", target, () =>
      this.client.investigate(target, options),
      (result) => {
        const entities = Array.isArray(result.entities)
          ? result.entities.length
          : 0;
        const links = Array.isArray(result.links) ? result.links.length : 0;
        return `${entities} entit(ies), ${links} link(s)`;
      });
  }

  /**
   * Run a risk score and record the step.
   * `GET /api/risk/{kind}/{target}`.
   */
  async risk(
    kind: LookupKind | string,
    target: string,
  ): Promise<RiskReport | undefined> {
    this.assertOpen();
    return this.runStep("risk", target, () => this.client.risk(kind, target),
      (result) => {
        const risk = result.risk as Record<string, unknown> | undefined;
        const score = risk ? Number(risk.score ?? 0) : 0;
        const verdict = risk ? String(risk.verdict ?? "unknown") : "unknown";
        return `score ${score} (${verdict})`;
      });
  }

  /**
   * Build search-engine dorks and record the step.
   * `GET /api/tools/dorks?target=...`.
   */
  async dorks(
    target: string,
    options: { kind?: string } = {},
  ): Promise<DorkReport | undefined> {
    this.assertOpen();
    return this.runStep("dorks", target, () => this.client.dorks(target, options),
      (result) => {
        const count = Number(result.count ?? 0);
        const detected = String(result.detected_kind ?? "?");
        return `${count} dork(s) for ${detected}`;
      });
  }

  /**
   * Jot a free-form analyst note (no HTTP; recorded as a step).
   *
   * @returns The note text, for chaining.
   */
  note(text: string): string {
    this.assertOpen();
    const value = String(text ?? "");
    this.notes.push(value);
    this.steps.push(
      new SessionStep(
        "note",
        "",
        true,
        "",
        0,
        value.length > 60 ? `${value.slice(0, 57)}...` : value,
      ),
    );
    return value;
  }

  // ------------------------------------------------------------------
  // Introspection
  // ------------------------------------------------------------------

  /** A copy of every recorded step, in order. */
  get allSteps(): SessionStep[] {
    return [...this.steps];
  }

  /** One recorded step by index (0-based), or `undefined`. */
  step(index: number): SessionStep | undefined {
    return this.steps[index];
  }

  /** How many steps were recorded. */
  get stepCount(): number {
    return this.steps.length;
  }

  /** How many steps succeeded. */
  get okCount(): number {
    return this.steps.filter((step) => step.ok).length;
  }

  /** How many steps failed. */
  get failedCount(): number {
    return this.steps.filter((step) => !step.ok).length;
  }

  /** The analyst notes, in order. */
  get notesTaken(): string[] {
    return [...this.notes];
  }

  /**
   * Every distinct target the session touched, first-seen order (failed
   * lookups included, notes excluded).
   */
  targets(): string[] {
    return [...this.seenTargets];
  }

  /**
   * Multi-line human summary of the whole session:
   * counts, targets, per-step headlines and notes.
   */
  summary(): string {
    const lines: string[] = [];
    const head = this.label ? `session ${this.label}` : "session";
    lines.push(
      `${head}: ${this.stepCount} step(s), ${this.okCount} ok, ` +
        `${this.failedCount} failed, ${this.seenTargets.length} target(s)`,
    );
    if (this.seenTargets.length) {
      lines.push(`targets: ${this.seenTargets.join(", ")}`);
    }
    for (const step of this.steps) {
      lines.push(`  ${step.headline}`);
    }
    if (this.notes.length) {
      lines.push(`notes (${this.notes.length}):`);
      for (const note of this.notes) {
        lines.push(`  - ${note}`);
      }
    }
    return lines.join("\n");
  }

  /** The portable receipt object (see {@link SessionReceipt}). */
  toObject(): SessionReceipt {
    return {
      format: RECEIPT_FORMAT,
      label: this.label,
      startedAt: this.startedAt,
      closed: this.closed,
      counts: {
        steps: this.stepCount,
        ok: this.okCount,
        failed: this.failedCount,
        targets: this.seenTargets.length,
      },
      targets: [...this.seenTargets],
      notes: [...this.notes],
      steps: this.steps.map((step) => step.toRecord()),
    };
  }

  /**
   * The receipt as a JSON string.
   *
   * @param indent - indentation passed to `JSON.stringify` (default 2;
   *   pass `0` for compact output).
   */
  toJSON(indent: number = 2): string {
    return JSON.stringify(this.toObject(), null, indent > 0 ? indent : undefined);
  }

  /** Marks the session closed — further recorded actions throw. */
  close(): void {
    this.closed = true;
  }

  /** Debug representation. */
  toString(): string {
    const state = this.closed ? "closed" : "open";
    return `<InvestigationSession ${this.label || "(unlabelled)"} steps=${this.stepCount} ${state}>`;
  }

  // ------------------------------------------------------------------
  // Internals
  // ------------------------------------------------------------------

  private assertOpen(): void {
    if (this.closed) {
      throw new Error("session is closed");
    }
  }

  private rememberTarget(target: string): void {
    const value = String(target ?? "");
    if (value && !this.seenTargets.includes(value)) {
      this.seenTargets.push(value);
    }
  }

  private async runStep<T>(
    action: string,
    target: string,
    run: () => Promise<T>,
    describe: (result: T) => string = () => "",
  ): Promise<T | undefined> {
    this.rememberTarget(target);
    const started = Date.now();
    try {
      const result = await run();
      this.steps.push(
        new SessionStep(
          action,
          String(target ?? ""),
          true,
          "",
          Date.now() - started,
          describe(result),
        ),
      );
      return result;
    } catch (error) {
      const message =
        error instanceof Error
          ? `${error.name}: ${error.message}`
          : String(error);
      this.steps.push(
        new SessionStep(
          action,
          String(target ?? ""),
          false,
          message,
          Date.now() - started,
          "",
        ),
      );
      if (this.strict) throw error;
      return undefined;
    }
  }
}
