/**
 * ObscuraLens web UI — live event client (v6.0 part 3).
 *
 * A thin, defensive wrapper around the native `EventSource` API talking to
 * the backend's `GET /api/stream` server-sent-events feed. What it adds
 * over a raw EventSource:
 *
 *   - named-topic subscriptions (`on('lookup', cb)` etc.) with JSON
 *     auto-parsing and unsubscribe handles,
 *   - exponential-backoff reconnection (capped, with a retry budget and a
 *     `disconnect` event every time the wire drops),
 *   - an online/offline state machine views can poll (`sse.state`),
 *   - graceful degradation: browsers without `EventSource` fall back to a
 *     polling loop built from `fetch` (`fallbackPoll`),
 *   - `subscribeEvents(topics)` — declares the topics the server should
 *     carry via `POST /api/stream/subscribe`.
 *
 * The singleton `sse` instance is pre-pointed at `/api/stream` but stays
 * dormant (zero sockets, zero timers) until a view calls `connect()`.
 */

/** Event topics the backend is known to emit. */
export const TOPICS = ['connected', 'lookup', 'watch', 'alert',
  'analytics', 'heartbeat', 'disconnect'];

/** Default reconnect base delay (ms) — doubled on every failed attempt. */
const DEFAULT_RECONNECT_MS = 5000;

/** Default retry budget before the client gives up (state 'closed'). */
const DEFAULT_MAX_RETRY = 10;

/** Hard cap for the backoff delay so a long-lived tab does not go idle forever. */
const MAX_BACKOFF_MS = 60000;

/**
 * Parse one SSE `data:` payload: JSON when possible, raw string otherwise.
 *
 * @param {string} raw
 * @returns {*}
 */
function parseData(raw) {
  if (typeof raw !== 'string' || !raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

/**
 * The live event client. One instance per stream path; the exported
 * `sse` singleton covers the standard backend feed.
 */
export class SseClient {
  /**
   * @param {string} path Stream endpoint (default-style '/api/stream').
   * @param {{reconnectMs?: number, maxRetry?: number,
   *          pollFn?: function(): Promise<*>|null,
   *          pollMs?: number}} [options]
   *   `reconnectMs` is the *base* backoff delay; `maxRetry` the attempt
   *   budget; `pollFn`/`pollMs` configure the EventSource-less fallback
   *   (the default pollFn pings `/api/health` and re-emits the result as
   *   `heartbeat` events so liveness badges keep working).
   */
  constructor(path = '/api/stream', options = {}) {
    this.path = path;
    this.reconnectMs = Number.isFinite(+options.reconnectMs)
      ? Math.max(250, +options.reconnectMs) : DEFAULT_RECONNECT_MS;
    this.maxRetry = Number.isFinite(+options.maxRetry)
      ? Math.max(0, Math.round(+options.maxRetry)) : DEFAULT_MAX_RETRY;
    this.pollMs = Number.isFinite(+options.pollMs)
      ? Math.max(500, +options.pollMs) : 15000;
    this.pollFn = typeof options.pollFn === 'function'
      ? options.pollFn : null;

    /** @type {Map<string, Set<function(*, Object): void>>} */
    this._handlers = new Map();
    /** @type {EventSource|null} */
    this._source = null;
    /** @type {number|null} reconnect timer id */
    this._timer = null;
    /** @type {number|null} fallback poll timer id */
    this._pollTimer = null;
    this._retries = 0;
    this._state = 'idle';

    // pre-register the known topics so on() can be called before connect()
    for (const topic of TOPICS) this._handlers.set(topic, new Set());
  }

  /**
   * Current connection state: 'idle' | 'connecting' | 'open' |
   * 'reconnecting' | 'polling' | 'closed'.
   *
   * @returns {string}
   */
  get state() {
    return this._state;
  }

  /**
   * Whether the feed is delivering events right now (open or polling).
   *
   * @returns {boolean}
   */
  get online() {
    return this._state === 'open' || this._state === 'polling';
  }

  /**
   * Open the stream (idempotent — a no-op when already live).
   *
   * Falls back to polling when `EventSource` is unavailable.
   *
   * @returns {SseClient} this — chainable.
   */
  connect() {
    if (this._state === 'open' || this._state === 'connecting'
      || this._state === 'polling') return this;
    if (typeof globalThis.EventSource !== 'function') {
      this._startPolling();
      return this;
    }
    this._clearTimer();
    this._state = 'connecting';
    let source;
    try {
      source = new EventSource(this.path);
    } catch {
      this._scheduleReconnect();
      return this;
    }
    this._source = source;

    source.onopen = () => {
      this._state = 'open';
      this._retries = 0;
      this._emit('connected', { path: this.path }, { type: 'connected' });
    };

    // every named topic the server may send gets its own listener; unknown
    // topics still arrive through this registry because listeners are added
    // lazily in on()
    for (const topic of this._handlers.keys()) {
      source.addEventListener(topic, (ev) => {
        if (this._state !== 'open') this._state = 'open';
        this._retries = 0;
        this._emit(topic, parseData(ev.data || null), ev);
      });
    }

    source.onerror = () => {
      // EventSource auto-retries on its own; we take over instead so the
      // retry budget and backoff are ours.
      this._teardownSource();
      this._emit('disconnect', { retries: this._retries }, { type: 'error' });
      this._scheduleReconnect();
    };
    return this;
  }

  /**
   * Subscribe to one event topic. The callback receives
   * `(data, event)` where `data` is the parsed JSON payload.
   *
   * Known topics: 'connected' | 'lookup' | 'watch' | 'alert' |
   * 'analytics' | 'heartbeat' | 'disconnect' — any other name works too
   * (the listener is attached lazily on the live connection).
   *
   * @param {string} event Topic name.
   * @param {function(*, Object): void} cb
   * @returns {function(): void} Unsubscribe function.
   */
  on(event, cb) {
    if (typeof cb !== 'function') return () => {};
    const topic = String(event || '');
    if (!this._handlers.has(topic)) {
      this._handlers.set(topic, new Set());
      // attach to a live connection created before this topic was known
      if (this._source && typeof this._source.addEventListener === 'function') {
        this._source.addEventListener(topic, (ev) => {
          this._emit(topic, parseData(ev.data || null), ev);
        });
      }
    }
    this._handlers.get(topic).add(cb);
    return () => {
      const set = this._handlers.get(topic);
      if (set) set.delete(cb);
    };
  }

  /**
   * Remove one callback (or every callback for a topic).
   *
   * @param {string} event
   * @param {function(*, Object): void} [cb] Omit to clear the whole topic.
   */
  off(event, cb) {
    const set = this._handlers.get(String(event || ''));
    if (!set) return;
    if (cb) set.delete(cb);
    else set.clear();
  }

  /**
   * Declare the topics this deployment's stream should carry
   * (`POST /api/stream/subscribe`, body `{'topics': [...]}`).
   *
   * @param {string[]|string} topics List or comma-separated string.
   * @returns {Promise<*>} The parsed server confirmation.
   */
  async subscribeEvents(topics) {
    const list = Array.isArray(topics)
      ? topics.map((t) => String(t ?? '').trim())
      : String(topics ?? '').split(',').map((t) => t.trim());
    const clean = [...new Set(list.filter(Boolean))];
    if (!clean.length) {
      throw new Error('subscribeEvents: at least one topic is required');
    }
    const response = await fetch('/api/stream/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ topics: clean }),
    });
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!response.ok) {
      const detail = data && typeof data === 'object' ? data.detail : data;
      throw new Error(typeof detail === 'string' && detail
        ? detail : `HTTP ${response.status} ${response.statusText}`);
    }
    return data;
  }

  /**
   * Run a polling loop when EventSource is unavailable.
   *
   * Usable standalone too: `SseClient.fallbackPoll(fn, 5000)` — the
   * returned stop function cancels the timer and awaits the in-flight
   * poll. The loop stops on its own when `fn` returns `false`.
   *
   * @param {function(): Promise<*>|*} fn Async or sync poll body.
   * @param {number} [intervalMs] Interval (default this.pollMs).
   * @returns {function(): void} Stop function.
   */
  fallbackPoll(fn, intervalMs) {
    const interval = Math.max(250, Number.isFinite(+intervalMs)
      ? +intervalMs : this.pollMs);
    const body = typeof fn === 'function' ? fn : this.pollFn;
    if (!body) return () => {};
    let stopped = false;
    let timer = null;
    const tick = async () => {
      if (stopped) return;
      try {
        const result = await body();
        if (result === false) { stop(); return; }
      } catch { /* a failed poll is retried on the next tick */ }
      if (!stopped) timer = setTimeout(tick, interval);
    };
    const stop = () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
    timer = setTimeout(tick, interval);
    return stop;
  }

  /**
   * Start the degraded polling mode (no EventSource in this browser).
   *
   * @private
   */
  _startPolling() {
    this._state = 'polling';
    this._emit('connected', { mode: 'polling', interval: this.pollMs },
      { type: 'connected' });
    const defaultPoll = async () => {
      try {
        const response = await fetch('/api/health');
        const data = await response.json();
        this._emit('heartbeat', data, { type: 'heartbeat' });
        return response.ok;
      } catch {
        this._emit('disconnect', { mode: 'polling' }, { type: 'error' });
        return true; // keep polling — the server may come back
      }
    };
    this._pollTimer = this.fallbackPoll(this.pollFn || defaultPoll,
      this.pollMs);
  }

  /**
   * Tear the current EventSource down without emitting anything.
   *
   * @private
   */
  _teardownSource() {
    if (this._source) {
      // silence the native auto-reconnect before closing
      this._source.onopen = null;
      this._source.onerror = null;
      try { this._source.close(); } catch { /* already closed */ }
      this._source = null;
    }
  }

  /**
   * Clear any pending reconnect timer.
   *
   * @private
   */
  _clearTimer() {
    if (this._timer !== null) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }

  /**
   * Schedule the next reconnect attempt with exponential backoff.
   *
   * @private
   */
  _scheduleReconnect() {
    this._clearTimer();
    if (this._retries >= this.maxRetry) {
      this._state = 'closed';
      this._emit('disconnect', { given_up: true, retries: this._retries },
        { type: 'closed' });
      return;
    }
    this._state = 'reconnecting';
    const delay = Math.min(MAX_BACKOFF_MS,
      this.reconnectMs * Math.pow(2, this._retries));
    this._retries += 1;
    this._timer = setTimeout(() => {
      this._timer = null;
      this.connect();
    }, delay);
  }

  /**
   * Dispatch one event to its subscribers. A throwing callback is skipped,
   * never propagated — one broken view must not kill the live feed.
   *
   * @param {string} topic
   * @param {*} data
   * @param {Object} ev Raw event-ish object.
   * @private
   */
  _emit(topic, data, ev) {
    const set = this._handlers.get(topic);
    if (!set || !set.size) return;
    for (const cb of set) {
      try { cb(data, ev); } catch { /* a broken listener is skipped */ }
    }
  }

  /**
   * Close the stream and stop every timer. Safe to call repeatedly; a
   * later `connect()` starts fresh (retry budget resets).
   *
   * @returns {SseClient} this — chainable.
   */
  close() {
    this._clearTimer();
    this._teardownSource();
    if (typeof this._pollTimer === 'function') {
      this._pollTimer(); // fallbackPoll's stop function
      this._pollTimer = null;
    }
    this._state = 'closed';
    this._retries = 0;
    return this;
  }
}

/** Pre-configured singleton for the standard backend feed. */
export const sse = new SseClient('/api/stream');

export default sse;
