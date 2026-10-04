/**
 * ObscuraLens web UI — REST API client.
 *
 * Wraps every backend endpoint behind typed, error-normalised helpers.
 * All functions reject with an `ApiError` carrying `.status` and `.detail`
 * so views can render actionable messages instead of parsing strings.
 *
 * The base URL is same-origin; the SPA is served by the same FastAPI app.
 */

/** Error type raised for any non-2xx API response. */
export class ApiError extends Error {
  /**
   * @param {string} message Human-readable error text.
   * @param {number} status HTTP status code (0 for network failures).
   * @param {*} detail Optional structured detail from the response body.
   */
  constructor(message, status = 0, detail = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

/** Default request timeout in milliseconds. */
const DEFAULT_TIMEOUT = 90000;

/** Kinds the backend understands (mirrors obscuralens web app KINDS). */
export const KINDS = [
  'ip', 'domain', 'email', 'username', 'phone', 'url',
  'crypto', 'hash', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords',
  // v6.0 kinds
  'vin', 'flight', 'mmsi', 'app', 'bssid', 'plate',
];

/** Friendly metadata for each kind, used by selects and the palette. */
export const KIND_META = {
  ip:       { label: 'IP address',     hint: '8.8.8.8 or 2001:db8::1' },
  domain:   { label: 'Domain',         hint: 'example.com' },
  email:    { label: 'Email',          hint: 'user@example.com' },
  username: { label: 'Username',       hint: 'a handle, e.g. johndoe' },
  phone:    { label: 'Phone',          hint: '+14155552671' },
  url:      { label: 'URL',            hint: 'https://example.com/page' },
  crypto:   { label: 'Crypto address', hint: 'BTC / ETH / LTC / DOGE / XMR…' },
  hash:     { label: 'File hash',      hint: 'MD5/SHA1/SHA256 hex digest' },
  cve:      { label: 'CVE',            hint: 'CVE-2021-44228' },
  asn:      { label: 'AS number',      hint: 'AS15169' },
  mac:      { label: 'MAC address',    hint: 'b8:27:eb:aa:bb:cc' },
  iban:     { label: 'IBAN',           hint: 'DE89 3704 0044 0532 0130 00' },
  imei:     { label: 'IMEI',           hint: '356938035643809' },
  coords:   { label: 'Coordinates',    hint: '48.8584, 2.2945 or UTM/MGRS' },
  // v6.0 kinds
  vin:      { label: 'VIN',            hint: '1M8GDM9AXKP042788 (17 chars)' },
  flight:   { label: 'Flight number',  hint: 'BA2490, UA1 or DLH400A' },
  mmsi:     { label: 'MMSI',           hint: '366910000 (9 digits)' },
  app:      { label: 'Software package', hint: 'pypi:requests or npm:lodash' },
  bssid:    { label: 'WiFi BSSID',      hint: '00:1A:2B:3C:4D:5E' },
  plate:    { label: 'License plate',   hint: 'DE:B-AB 1234 or GB:AB12 CDE' },
};

/* ---------------------------------------------------------------------- */
/* Core transport                                                          */
/* ---------------------------------------------------------------------- */

/**
 * Perform a JSON request against the backend.
 *
 * @param {string} path Request path beginning with '/'.
 * @param {{method?: string, body?: *, timeout?: number, form?: FormData}} opts
 * @returns {Promise<*>} Parsed JSON body.
 */
export async function request(path, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(),
    opts.timeout ?? DEFAULT_TIMEOUT);
  /** @type {RequestInit} */
  const init = {
    method: opts.method ?? 'GET',
    signal: controller.signal,
    headers: {},
  };
  if (opts.form) {
    init.body = opts.form; // browser sets multipart boundary headers
  } else if (opts.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw new ApiError(`Request timed out after ${Math.round((opts.timeout ?? DEFAULT_TIMEOUT) / 1000)}s`, 0);
    }
    throw new ApiError('Network error — is the ObscuraLens server running?', 0);
  } finally {
    clearTimeout(timer);
  }

  let data = null;
  const text = await response.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }

  if (!response.ok) {
    const detail = data && typeof data === 'object' ? data.detail : data;
    const message = typeof detail === 'string' && detail
      ? detail
      : `HTTP ${response.status} ${response.statusText}`;
    throw new ApiError(message, response.status, detail);
  }
  return data;
}

/** URL-encode a path segment (targets can contain '/', ':' etc.). */
export function enc(value) {
  return encodeURIComponent(String(value ?? ''));
}

/* ---------------------------------------------------------------------- */
/* Endpoint helpers                                                        */
/* ---------------------------------------------------------------------- */

export const api = {
  /* ---- health / meta ---- */

  /** Backend liveness + version. */
  health() { return request('/api/health'); },

  /** Registry of every target kind with labels and source lists. */
  kinds() { return request('/api/kinds'); },

  /* ---- lookups ---- */

  /**
   * Run a tracker lookup.
   * @param {string} kind One of KINDS.
   * @param {string} target Raw target value.
   */
  lookup(kind, target) { return request(`/api/lookup/${kind}/${enc(target)}`); },

  /**
   * Lookup with the explainable risk score attached.
   * @param {string} kind
   * @param {string} target
   */
  risk(kind, target) { return request(`/api/risk/${kind}/${enc(target)}`); },

  /**
   * Auto-detect a target and (optionally) follow pivots.
   * @param {string} target
   * @param {{pivot?: boolean}} [opts]
   */
  investigate(target, opts = {}) {
    const params = new URLSearchParams({ target, pivot: String(opts.pivot ?? true) });
    return request(`/api/investigate?${params}`);
  },

  /**
   * Threat-intel verdict for an IP (Tor exit, blocklist feeds).
   * @param {string} ip
   */
  intel(ip) { return request(`/api/intel/${enc(ip)}`); },

  /* ---- history / correlation ---- */

  /**
   * Search stored lookup history.
   * @param {{kind?: string, q?: string, limit?: number}} [opts]
   */
  history(opts = {}) {
    const params = new URLSearchParams();
    if (opts.kind) params.set('kind', opts.kind);
    if (opts.q) params.set('q', opts.q);
    params.set('limit', String(opts.limit ?? 100));
    return request(`/api/history?${params}`);
  },

  /**
   * Chronological event timeline across history.
   * @param {{target?: string, limit?: number}} [opts]
   */
  timeline(opts = {}) {
    const params = new URLSearchParams();
    if (opts.target) params.set('target', opts.target);
    params.set('limit', String(opts.limit ?? 100));
    return request(`/api/timeline?${params}`);
  },

  /**
   * Correlation graph, clusters and bridge entities.
   * @param {{limit?: number}} [opts]
   */
  correlate(opts = {}) {
    const params = new URLSearchParams();
    if (opts.limit) params.set('limit', String(opts.limit));
    return request(`/api/correlate?${params}`);
  },

  /**
   * Shared-infrastructure comparison between two targets.
   * @param {string} a
   * @param {string} b
   */
  correlatePair(a, b) {
    const params = new URLSearchParams({ a, b });
    return request(`/api/correlate/pair?${params}`);
  },

  /**
   * Pattern-of-life analysis for one target.
   * @param {string} kind
   * @param {string} target
   */
  patterns(kind, target) {
    const params = new URLSearchParams({ kind, target });
    return request(`/api/patterns?${params}`);
  },

  /* ---- cases ---- */

  cases() { return request('/api/cases'); },
  caseGet(id) { return request(`/api/cases/${id}`); },
  caseCreate(body) { return request('/api/cases', { method: 'POST', body }); },
  caseUpdate(id, body) { return request(`/api/cases/${id}`, { method: 'PATCH', body }); },
  caseAddItem(id, body) { return request(`/api/cases/${id}/items`, { method: 'POST', body }); },
  caseAddNote(id, body) { return request(`/api/cases/${id}/notes`, { method: 'POST', body }); },
  caseAddTag(id, body) { return request(`/api/cases/${id}/tags`, { method: 'POST', body }); },

  /* ---- watchlist ---- */

  watchList() { return request('/api/watch'); },
  watchAdd(body) { return request('/api/watch', { method: 'POST', body }); },
  watchRemove(identifier) { return request(`/api/watch/${enc(identifier)}`, { method: 'DELETE' }); },
  watchCheck(identifier) {
    const params = identifier ? new URLSearchParams({ identifier }) : null;
    return request(`/api/watch/check${params ? '?' + params : ''}`, { method: 'POST' });
  },

  /**
   * Snapshot diff for one watched target.
   * @param {string} kind
   * @param {string} target
   */
  diff(kind, target) { return request(`/api/diff/${kind}/${enc(target)}`); },

  /* ---- sources / stats ---- */

  sources() { return request('/api/sources'); },
  stats() { return request('/api/stats'); },

  /* ---- settings / keys ---- */

  settings() { return request('/api/settings'); },
  settingsUpdate(body) { return request('/api/settings', { method: 'POST', body }); },
  keys() { return request('/api/keys'); },
  keySet(service, key) { return request(`/api/keys/${enc(service)}`, { method: 'POST', body: { key } }); },
  keyClear(service) { return request(`/api/keys/${enc(service)}`, { method: 'DELETE' }); },

  /* ---- toolbox ---- */

  /**
   * Encode one input into every scheme at once.
   * @param {string} text
   */
  encodings(text) {
    const params = new URLSearchParams({ text });
    return request(`/api/tools/encodings?${params}`);
  },

  /**
   * Decode a value with a chosen scheme.
   * @param {{scheme: string, value: string}} body
   */
  decode(body) { return request('/api/tools/decode', { method: 'POST', body }); },

  /**
   * Decode + inspect a JWT.
   * @param {string} token
   */
  jwt(token) {
    const params = new URLSearchParams({ token });
    return request(`/api/tools/jwt?${params}`);
  },

  /**
   * Identify candidate hash formats.
   * @param {string} value
   */
  hashId(value) {
    const params = new URLSearchParams({ value });
    return request(`/api/tools/hash-id?${params}`);
  },

  /**
   * Parse coordinates and convert to every format.
   * @param {{value: string}} body
   */
  coordsConvert(body) { return request('/api/tools/coords', { method: 'POST', body }); },

  /**
   * Extract entities (emails, IPs, hashes…) from free text.
   * @param {{text: string}} body
   */
  extract(body) { return request('/api/tools/extract', { method: 'POST', body }); },

  /**
   * Generate typosquatting variants for a domain.
   * @param {{domain: string}} body
   */
  squat(body) { return request('/api/tools/squat', { method: 'POST', body }); },

  /**
   * Ready-to-open search-engine dorks for a target (v6.1). The kind is
   * auto-detected server-side unless overridden.
   * @param {string} target
   * @param {string|null} kind
   */
  dorks(target, kind = null) {
    const params = new URLSearchParams({ target });
    if (kind) params.set('kind', kind);
    return request(`/api/tools/dorks?${params.toString()}`);
  },

  /**
   * EXIF / metadata analysis of an uploaded file (runs locally).
   * @param {File} file
   */
  exif(file) {
    const form = new FormData();
    form.append('file', file);
    return request('/api/tools/file/exif', { method: 'POST', form });
  },

  /**
   * Steganography / entropy analysis of an uploaded file (runs locally).
   * @param {File} file
   */
  stego(file) {
    const form = new FormData();
    form.append('file', file);
    return request('/api/tools/file/stego', { method: 'POST', form });
  },

  /**
   * Batch lookup multiple targets of one kind (cap 25).
   * @param {{kind: string, targets: string[], risk?: boolean}} body
   */
  batch(body) { return request('/api/tools/batch', { method: 'POST', body }); },

  /* ---- analytics (v6.0 part 2/3) ---- */

  /**
   * Descriptive statistics + histogram for a numeric list.
   * @param {number[]|string[]} values Raw numbers (non-numbers are dropped
   *        server-side).
   * @param {{bins?: number}} [opts]
   */
  analyticsStats(values, opts = {}) {
    return request('/api/analytics/stats', {
      method: 'POST',
      body: { values, bins: opts.bins },
    });
  },

  /**
   * Outlier detection over a numeric list.
   * @param {number[]} values
   * @param {string} [method] ensemble|zscore|iqr|mad|grubbs|threshold.
   * @param {number} [threshold] Z-score cut-off (zscore method only).
   */
  analyticsAnomalies(values, method = 'ensemble', threshold = null) {
    const body = { values, method };
    if (Number.isFinite(Number(threshold))) body.threshold = Number(threshold);
    return request('/api/analytics/anomalies', { method: 'POST', body });
  },

  /**
   * Stopword-filtered keyword mining for one text.
   * @param {string} text
   * @param {number} [top] Maximum keywords returned.
   */
  analyticsKeywords(text, top = 10) {
    return request('/api/analytics/keywords', {
      method: 'POST',
      body: { text, top },
    });
  },

  /**
   * Script + language fingerprint for one text.
   * @param {string} text
   */
  analyticsLanguage(text) {
    return request('/api/analytics/language', {
      method: 'POST',
      body: { text },
    });
  },

  /**
   * Enrichment report over stored query history.
   * @param {number} [limit] Newest rows considered (default 500).
   */
  analyticsHistory(limit = 500) {
    const params = new URLSearchParams({ limit: String(limit) });
    return request(`/api/analytics/history?${params}`);
  },

  /* ---- live stream aggregation views (v6.0 part 3) ---- */

  /**
   * Geographic points distilled from stored lookup history.
   * @param {number} [limit] Newest rows scanned (default 500).
   */
  mapPoints(limit = 500) {
    const params = new URLSearchParams({ limit: String(limit) });
    return request(`/api/map/points?${params}`);
  },

  /**
   * Aggregated activity profile for one target across stored history.
   * @param {string} kind One of KINDS.
   * @param {string} target Raw target value.
   * @param {number} [limit] Newest rows considered (default 200).
   */
  profile(kind, target, limit = 200) {
    const params = new URLSearchParams({ limit: String(limit) });
    return request(`/api/profile/${enc(kind)}/${enc(target)}?${params}`);
  },

  /**
   * Field-level diff between two live lookups (A versus B).
   * @param {string} kindA
   * @param {string} targetA
   * @param {string} kindB
   * @param {string} targetB
   */
  compare(kindA, targetA, kindB, targetB) {
    const params = new URLSearchParams({
      kind_a: kindA, target_a: targetA,
      kind_b: kindB, target_b: targetB,
    });
    return request(`/api/compare?${params}`);
  },

  /* ---- reports / alerts ---- */

  /**
   * Self-contained HTML investigation report.
   * @param {string} kind
   * @param {string} target
   */
  report(kind, target) { return request(`/api/report/${kind}/${enc(target)}`); },

  alerts() { return request('/api/alerts'); },
  alertsConfigure(body) { return request('/api/alerts', { method: 'POST', body }); },
  alertsTest() { return request('/api/alerts/test', { method: 'POST' }); },

  /* ---- export ---- */

  /**
   * Export an investigation graph as text (graphml/gexf/dot/jsonl/csv).
   * @param {string} fmt
   * @param {string} target
   */
  graphExport(fmt, target) { return request(`/api/export/${fmt}/${enc(target)}`); },
};

export default api;
