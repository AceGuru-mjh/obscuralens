/**
 * ObscuraLens web UI — advanced canvas chart library (v6.0 part 3).
 *
 * A second chart engine beside `charts.js` covering the analytics-view
 * primitives the first one does not: box plots, radar charts, heatmaps,
 * squarified treemaps, gauges, stacked bars, kind-coloured scatters,
 * simplified violins and table sparklines. The conventions are identical
 * to `charts.js` so views can mix both freely:
 *
 *   - raw `<canvas>` 2D rendering, devicePixelRatio-aware (`fitCanvas`),
 *   - automatic redraw when the canvas' parent resizes (ResizeObserver,
 *     cleanup handle stored on `canvas.__olResize`),
 *   - colours read from the CSS custom-property palette on every draw, so
 *     theme switches recolour charts without re-instantiating anything,
 *   - optional hover tooltips (`.chart-tip`) with per-chart hit testing,
 *   - `aria-label` summaries on every canvas (role `img`),
 *   - empty-data and NaN-safe guards everywhere (no NaN axes, no explosions),
 *   - `{update(nextSpec)}` handles returned by every chart.
 *
 * Every chart also sets `canvas.__olDraw` so the shared theme observer in
 * `charts.js` (which watches `data-theme` and redraws live canvases) picks
 * these up automatically. The module never touches the DOM at import time.
 */

/* ---------------------------------------------------------------------- */
/* Theme / colour utilities                                                */
/* ---------------------------------------------------------------------- */

/** Fallbacks mirroring base.css dark-theme tokens (used when CSS is absent). */
const FALLBACK = {
  palette: ['#2dd4a7', '#f5a524', '#b58cff', '#4cc3ff',
    '#f2637a', '#8fd15f', '#e8965a', '#5fb0c9'],
  grid: 'rgba(139, 149, 167, 0.14)',
  axis: '#5d6879',
  panel2: '#151d2a',
  panel3: '#1a2331',
  accent: '#2dd4a7',
  bg: '#0a0e14',
  ok: '#3ec98f',
  warn: '#f0b429',
  danger: '#f2637a',
};

/**
 * Read one CSS custom property from :root, trimmed.
 *
 * @param {string} name Custom property name including leading `--`.
 * @param {string} fallback Value used when the property is empty.
 * @returns {string}
 */
function cssVar(name, fallback) {
  try {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
    return value || fallback;
  } catch {
    return fallback;
  }
}

/**
 * Snapshot of the chart-relevant design tokens. Re-read on every draw so
 * `[data-theme=light]` switches recolour existing charts.
 *
 * @returns {{palette: string[], grid: string, axis: string, panel2: string,
 *   panel3: string, accent: string, bg: string, ok: string,
 *   warn: string, danger: string}}
 */
function theme() {
  const palette = [];
  for (let i = 1; i <= 8; i += 1) {
    palette.push(cssVar(`--chart-${i}`, FALLBACK.palette[i - 1]));
  }
  return {
    palette,
    grid: cssVar('--chart-grid', FALLBACK.grid),
    axis: cssVar('--chart-axis', FALLBACK.axis),
    panel2: cssVar('--panel-2', FALLBACK.panel2),
    panel3: cssVar('--panel-3', FALLBACK.panel3),
    accent: cssVar('--accent', FALLBACK.accent),
    bg: cssVar('--bg', FALLBACK.bg),
    ok: cssVar('--ok', FALLBACK.ok),
    warn: cssVar('--warn', FALLBACK.warn),
    danger: cssVar('--danger', FALLBACK.danger),
  };
}

/** Lazy 1×1 canvas used to normalise arbitrary CSS colour strings. */
let normalizeCanvas = null;

/**
 * Normalise any CSS colour to `#rrggbb` or `rgba(...)` via canvas fillStyle.
 *
 * @param {string} color
 * @returns {string}
 */
function normalizeColor(color) {
  if (!normalizeCanvas) {
    normalizeCanvas = document.createElement('canvas');
    normalizeCanvas.width = 1;
    normalizeCanvas.height = 1;
  }
  const ctx = normalizeCanvas.getContext('2d');
  ctx.fillStyle = '#000000';
  ctx.fillStyle = String(color);
  return ctx.fillStyle;
}

/**
 * Parse a CSS colour into [r, g, b, a]; returns null when unparseable.
 *
 * @param {string} color
 * @returns {[number, number, number, number]|null}
 */
function parseColor(color) {
  if (color === null || color === undefined) return null;
  const s = String(color).trim();
  if (!s) return null;
  let m = s.match(/^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i);
  if (m) {
    const hex = m[1];
    const byte = (i) => parseInt(hex.slice(i, i + 2), 16);
    if (hex.length === 3) {
      return [parseInt(hex[0] + hex[0], 16), parseInt(hex[1] + hex[1], 16),
        parseInt(hex[2] + hex[2], 16), 1];
    }
    if (hex.length === 6) return [byte(0), byte(2), byte(4), 1];
    return [byte(0), byte(2), byte(4), byte(6) / 255];
  }
  m = s.match(/^rgba?\(([^)]+)\)$/i);
  if (m) {
    const parts = m[1].split(/[,/\s]+/).filter(Boolean).map(Number);
    if (parts.length >= 3 && parts.slice(0, 3).every(Number.isFinite)) {
      const a = parts.length >= 4 && Number.isFinite(parts[3])
        ? Math.max(0, Math.min(1, parts[3])) : 1;
      return [parts[0], parts[1], parts[2], a];
    }
  }
  try {
    const norm = normalizeColor(s);
    if (norm !== s) return parseColor(norm);
  } catch { /* canvas unavailable — give up gracefully */ }
  return null;
}

/**
 * Apply an alpha to any CSS colour.
 *
 * @param {string} color
 * @param {number} alpha
 * @returns {string}
 */
function withAlpha(color, alpha) {
  const p = parseColor(color);
  if (!p) return color;
  return `rgba(${Math.round(p[0])}, ${Math.round(p[1])}, ${Math.round(p[2])}, ${alpha})`;
}

/**
 * Linear interpolation between two colours (in 0..1 space).
 *
 * @param {string} a
 * @param {string} b
 * @param {number} t
 * @returns {string} `rgba(...)` string.
 */
function interpolate(a, b, t) {
  const pa = parseColor(a) ?? [21, 29, 42, 1];
  const pb = parseColor(b) ?? [45, 212, 167, 1];
  const mix = (i) => Math.round(pa[i] + (pb[i] - pa[i]) * t);
  return `rgba(${mix(0)}, ${mix(1)}, ${mix(2)}, ${pa[3] + (pb[3] - pa[3]) * t})`;
}

/** Kinds in registry order — the fallback palette slot for `colorFor`. */
const KNOWN_KINDS = ['ip', 'domain', 'email', 'username', 'phone', 'url',
  'crypto', 'hash', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords',
  'vin', 'flight', 'mmsi', 'app', 'bssid', 'plate'];

/**
 * Colour for one target kind: the `--kind-*` token when the theme defines
 * one, else a deterministic palette slot (v6.0 kinds have no token yet).
 *
 * @param {string|null|undefined} kind
 * @returns {string}
 */
export function colorFor(kind) {
  const palette = theme().palette;
  if (kind && KNOWN_KINDS.includes(kind)) {
    const token = cssVar(`--kind-${kind}`, '');
    if (token) return token;
  }
  const index = kind ? KNOWN_KINDS.indexOf(kind) : -1;
  return palette[(index >= 0 ? index : KNOWN_KINDS.length) % palette.length];
}

/* ---------------------------------------------------------------------- */
/* Ticks / formatters                                                      */
/* ---------------------------------------------------------------------- */

/**
 * Human-friendly axis ticks: steps are 1/2/5 × 10^n, the domain is padded to
 * whole steps and degenerate ranges are widened (division-by-zero guard).
 *
 * @param {number} min
 * @param {number} max
 * @param {number} count Desired tick count.
 * @returns {{lo: number, hi: number, ticks: number[]}}
 */
function niceTicks(min, max, count = 5) {
  if (!Number.isFinite(min) || !Number.isFinite(max)) return { lo: 0, hi: 1, ticks: [0, 1] };
  let lo = Math.min(min, max);
  let hi = Math.max(min, max);
  if (hi === lo) { hi += 1; lo -= 1; }
  const span = hi - lo;
  const raw = span / Math.max(1, count);
  const magnitude = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / magnitude;
  let step;
  if (norm <= 1) step = 1;
  else if (norm <= 2) step = 2;
  else if (norm <= 5) step = 5;
  else step = 10;
  step *= magnitude;
  const start = Math.floor(lo / step) * step;
  const end = Math.ceil(hi / step) * step;
  const ticks = [];
  const eps = step * 1e-6;
  for (let v = start; v <= end + eps; v += step) {
    ticks.push(Math.abs(v) < eps ? 0 : Math.round(v / step) * step);
  }
  return { lo: start, hi: end, ticks };
}

/**
 * Compact number formatting: 1234 → "1.2k", 5.2e6 → "5.2M", 4.1e9 → "4.1B".
 *
 * @param {number} value
 * @returns {string}
 */
function fmtCompact(value) {
  const v = Number(value);
  if (!Number.isFinite(v)) return '—';
  const abs = Math.abs(v);
  const trim = (n) => n.toFixed(abs >= 100 || Number.isInteger(n) ? 0 : 1)
    .replace(/\.0$/, '');
  if (abs >= 1e9) return `${trim(v / 1e9)}B`;
  if (abs >= 1e6) return `${trim(v / 1e6)}M`;
  if (abs >= 1e3) return `${trim(v / 1e3)}k`;
  return String(Math.round(v * 100) / 100);
}

/**
 * Linear-interpolated percentile (numpy default, same as analytics.stats).
 *
 * @param {number[]} sorted Ascending values.
 * @param {number} p Percentile 0..1.
 * @returns {number}
 */
function percentile(sorted, p) {
  if (!sorted.length) return NaN;
  if (sorted.length === 1) return sorted[0];
  const idx = p * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

/**
 * Five-number summary plus 1.5-IQR whiskers and outlier indexes.
 *
 * @param {number[]} rawValues
 * @returns {{n: number, min: number, q1: number, median: number,
 *   q3: number, max: number, lo: number, hi: number,
 *   outliers: number[]}|null} null when no usable numbers.
 */
function boxStats(rawValues) {
  const sorted = (Array.isArray(rawValues) ? rawValues : [])
    .map(Number).filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const q1 = percentile(sorted, 0.25);
  const median = percentile(sorted, 0.5);
  const q3 = percentile(sorted, 0.75);
  const iqr = q3 - q1;
  const lo = Math.max(sorted[0], q1 - 1.5 * iqr);
  const hi = Math.min(sorted[sorted.length - 1], q3 + 1.5 * iqr);
  const outliers = sorted.filter((v) => v < lo || v > hi);
  return { n: sorted.length, min: sorted[0], q1, median, q3,
    max: sorted[sorted.length - 1], lo, hi, outliers };
}

/* ---------------------------------------------------------------------- */
/* Canvas plumbing: DPR setup, resize observation, events, tooltip         */
/* ---------------------------------------------------------------------- */

/** Font shorthand used for all chart text (11px UI sans by default). */
const AXIS_FONT = '10.5px var(--font-ui, sans-serif)';
const MONO_FONT = '10.5px var(--font-mono, monospace)';

/**
 * Size a canvas for device pixels and return a DPR-scaled context —
 * the exported `fitCanvas` twin of `charts.js`' internal `setup`.
 *
 * @param {HTMLCanvasElement} canvas
 * @returns {{ctx: CanvasRenderingContext2D, w: number, h: number, dpr: number}}
 */
export function fitCanvas(canvas) {
  const dpr = Math.max(1, Math.min(3, window.devicePixelRatio || 1));
  const parent = canvas.parentElement;
  const w = Math.max(1, Math.round(
    canvas.clientWidth || parent?.clientWidth || 300));
  const h = Math.max(1, Math.round(
    canvas.clientHeight || parent?.clientHeight || 200));
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h, dpr };
}

/** Compatibility alias so code written against charts.js keeps working. */
const setup = fitCanvas;

/** Canvases with a live `__olDraw` (for theme-change redraws). */
const liveCanvases = new Set();

/** Lazily-created observer that redraws charts when the theme flips. */
let themeObserver = null;

/** Attach the theme observer once (never at import time). */
function ensureThemeObserver() {
  if (themeObserver || typeof MutationObserver === 'undefined') return;
  const root = typeof document !== 'undefined' ? document.documentElement : null;
  if (!root) return;
  themeObserver = new MutationObserver(() => {
    for (const canvas of liveCanvases) {
      if (canvas.isConnected) canvas.__olDraw?.();
      else liveCanvases.delete(canvas); // lazy GC of detached canvases
    }
  });
  themeObserver.observe(root, { attributes: true, attributeFilter: ['data-theme'] });
}

/**
 * Watch the canvas' parent for size changes and re-run the last draw fn
 * (stored as `canvas.__olDraw` by each chart). Idempotent per canvas.
 *
 * @param {HTMLCanvasElement} canvas
 */
function observeResize(canvas) {
  liveCanvases.add(canvas);
  ensureThemeObserver();
  if (canvas.__olResize || typeof ResizeObserver === 'undefined') return;
  const target = canvas.parentElement ?? canvas;
  const ro = new ResizeObserver(() => canvas.__olDraw?.());
  ro.observe(target);
  canvas.__olResize = ro;
}

/**
 * (Re)bind the hover handlers for a canvas, removing any previous pair.
 *
 * @param {HTMLCanvasElement} canvas
 * @param {function(MouseEvent): void} [move]
 * @param {function(MouseEvent): void} [leave]
 */
function bindEvents(canvas, move, leave) {
  unbindEvents(canvas);
  if (!move) return;
  canvas.__olEvents = { move, leave };
  canvas.addEventListener('mousemove', move);
  if (leave) canvas.addEventListener('mouseleave', leave);
}

/**
 * Remove handlers installed by {@link bindEvents}.
 *
 * @param {HTMLCanvasElement} canvas
 */
function unbindEvents(canvas) {
  const ev = canvas.__olEvents;
  if (!ev) return;
  canvas.removeEventListener('mousemove', ev.move);
  if (ev.leave) canvas.removeEventListener('mouseleave', ev.leave);
  canvas.__olEvents = null;
}

/**
 * Shared hover tooltip: one `.chart-tip` div per canvas parent, shown with
 * label/value rows at (x, y). Exported because the map view and custom
 * widgets want the identical look for free.
 */
export class Tooltip {
  /**
   * @param {HTMLCanvasElement} canvas The canvas the tooltip tracks.
   */
  constructor(canvas) {
    this.canvas = canvas;
    /** @type {HTMLElement|null} */
    this.node = null;
    const parent = canvas?.parentElement;
    if (!parent) return;
    if (getComputedStyle(parent).position === 'static') {
      parent.style.position = 'relative';
    }
    for (const child of parent.children) {
      if (child.classList?.contains('chart-tip')) this.node = child;
    }
    if (!this.node) {
      this.node = document.createElement('div');
      this.node.className = 'chart-tip';
      parent.append(this.node);
    }
  }

  /**
   * Show the tooltip at CSS-pixel coordinates with label/value rows.
   *
   * @param {number} x
   * @param {number} y
   * @param {Array<[string, string]>} rows
   * @param {number} [w] Canvas CSS width (for clamping).
   */
  show(x, y, rows, w = 300) {
    const tip = this.node;
    if (!tip) return;
    tip.replaceChildren(...rows.map(([label, value]) => {
      const row = document.createElement('div');
      row.className = 'tip-row';
      if (label !== null && label !== undefined && label !== '') {
        const lab = document.createElement('span');
        lab.className = 'tip-label';
        lab.textContent = String(label);
        row.append(lab);
      }
      const val = document.createElement('span');
      val.className = 'tip-val';
      val.textContent = String(value);
      row.append(val);
      return row;
    }));
    const cx = Math.max(56, Math.min(w - 56, x));
    tip.style.left = `${Math.round(cx)}px`;
    tip.style.top = `${Math.max(44, Math.round(y))}px`;
    tip.classList.add('visible');
  }

  /** Hide the tooltip. */
  hide() {
    this.node?.classList.remove('visible');
  }
}

/**
 * Draw the optional small muted title in the top-left corner.
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {string} title
 */
function drawTitle(ctx, title) {
  if (!title) return;
  ctx.save();
  ctx.font = `600 ${AXIS_FONT}`;
  ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
  ctx.textAlign = 'left';
  ctx.textBaseline = 'alphabetic';
  ctx.fillText(String(title), 2, 12);
  ctx.restore();
}

/**
 * Clear and draw the centered muted "no data" placeholder.
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {number} w
 * @param {number} h
 * @param {string} [text]
 */
function drawEmpty(ctx, w, h, text = 'no data') {
  ctx.clearRect(0, 0, w, h);
  ctx.save();
  ctx.font = '500 12px var(--font-ui, sans-serif)';
  ctx.fillStyle = cssVar('--text-faint', '#5d6879');
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, Math.round(w / 2), Math.round(h / 2));
  ctx.restore();
}

/**
 * Set the accessibility summary on the canvas (role img + label).
 *
 * @param {HTMLCanvasElement} canvas
 * @param {string} label
 */
function setAria(canvas, label) {
  try {
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', String(label));
  } catch { /* detached canvas — aria is best-effort */ }
}

/**
 * Draw an in-canvas legend (swatch + label rows) in the top-right corner.
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {Array<{label: string, color: string}>} items
 * @param {number} w
 * @param {number} y Top of the legend block.
 */
function drawLegend(ctx, items, w, y) {
  if (!items.length) return;
  ctx.save();
  ctx.font = `500 ${AXIS_FONT}`;
  ctx.textAlign = 'left';
  ctx.textBaseline = 'middle';
  const rowH = 15;
  const width = Math.max(...items.map(
    (i) => ctx.measureText(String(i.label)).width)) + 22;
  items.forEach((item, i) => {
    const ly = y + i * rowH;
    ctx.fillStyle = item.color;
    ctx.fillRect(w - width - 6, ly - 4, 9, 9);
    ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
    ctx.fillText(String(item.label), w - width + 7, ly + 0.5);
  });
  ctx.restore();
}

/**
 * Boilerplate shared by every chart draw: DPI setup, clear, title, and the
 * `__olDraw`/resize registration done once by the caller.
 *
 * @param {HTMLCanvasElement} canvas
 * @param {string} [title]
 * @returns {{ctx: CanvasRenderingContext2D, w: number, h: number}|null}
 *          null when the canvas has a zero-sized parent (headless).
 */
function beginDraw(canvas, title) {
  const { ctx, w, h } = setup(canvas);
  ctx.clearRect(0, 0, w, h);
  drawTitle(ctx, title);
  return { ctx, w, h };
}

/* ---------------------------------------------------------------------- */
/* Box plot                                                                */
/* ---------------------------------------------------------------------- */

/**
 * Draw a five-number box plot (Q1/Q2/Q3, 1.5-IQR whiskers, hollow outlier
 * circles), vertical by default.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   groups: [{label?: string, values: number[]}],
 *   orient?: 'v'|'h',             // default 'v'
 *   valueFormat?: (n) => string,  // default compact
 *   interactive?: boolean,        // hover tooltip with the summary
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function boxplot(canvas, spec = {}) {
  let hover = -1;
  let geom = null;
  const valueFormat = (v) => (typeof spec.valueFormat === 'function'
    ? spec.valueFormat(v) : fmtCompact(v));

  const groups = () => (Array.isArray(spec.groups) ? spec.groups : [])
    .map((g, i) => ({
      label: g?.label ?? `group ${i + 1}`,
      stats: boxStats(Array.isArray(g?.values) ? g.values : []),
    }))
    .filter((g) => g.stats);

  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const items = groups();
    if (!items.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }
    setAria(canvas, `Box plot of ${items.length} groups`);

    const horizontal = spec.orient === 'h';
    const all = items.flatMap((g) => [g.stats.min, g.stats.max]);
    const ticks = niceTicks(Math.min(...all), Math.max(...all), 5);
    const n = items.length;
    const padL = horizontal ? 46 : Math.min(120,
      Math.max(...items.map((g) => g.label.length)) * 6.2 + 10);
    const padR = horizontal ? 14 : 46;
    const padT = spec.title ? 28 : 12;
    const padB = horizontal ? 26 : 34;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const sv = (v) => (horizontal
      ? padL + ((v - ticks.lo) / (ticks.hi - ticks.lo)) * pw
      : padT + ph - ((v - ticks.lo) / (ticks.hi - ticks.lo)) * ph);
    const slot = (i) => (horizontal
      ? padT + (i + 0.5) * (ph / n)
      : padL + (i + 0.5) * (pw / n));
    const boxSpan = Math.min(horizontal ? ph / n * 0.55 : pw / n * 0.55, 84);
    geom = { items, horizontal, padL, padT, pw, ph, sv, slot, boxSpan, w, h };

    // grid + tick labels along the value axis
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.strokeStyle = T.grid;
    ctx.setLineDash([4, 4]);
    ctx.lineWidth = 1;
    ctx.fillStyle = T.axis;
    for (const t of ticks.ticks) {
      const pos = Math.round(sv(t)) + 0.5;
      ctx.beginPath();
      if (horizontal) {
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.moveTo(pos, padT);
        ctx.lineTo(pos, padT + ph);
        ctx.stroke();
        ctx.fillText(fmtCompact(t), pos, padT + ph + 6);
      } else {
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.moveTo(padL, pos);
        ctx.lineTo(padL + pw, pos);
        ctx.stroke();
        ctx.fillText(fmtCompact(t), padL - 8, pos);
      }
    }
    ctx.restore();

    // one box per group
    items.forEach((g, i) => {
      const color = T.palette[i % T.palette.length];
      const center = slot(i);
      const lo = sv(g.stats.lo);
      const hi = sv(g.stats.hi);
      const q1 = sv(g.stats.q1);
      const q2 = sv(g.stats.median);
      const q3 = sv(g.stats.q3);
      const hovered = i === hover;
      ctx.save();
      if (hovered) {
        ctx.shadowColor = withAlpha(color, 0.5);
        ctx.shadowBlur = 8;
      }
      // whisker line + caps
      ctx.strokeStyle = T.axis;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      if (horizontal) {
        ctx.moveTo(center, lo);
        ctx.lineTo(center, hi);
        ctx.moveTo(lo, center - boxSpan / 2 + 6);
        ctx.lineTo(lo, center + boxSpan / 2 - 6);
        ctx.moveTo(hi, center - boxSpan / 2 + 6);
        ctx.lineTo(hi, center + boxSpan / 2 - 6);
      } else {
        ctx.moveTo(center, lo);
        ctx.lineTo(center, hi);
        ctx.moveTo(center - boxSpan / 2 + 6, lo);
        ctx.lineTo(center + boxSpan / 2 - 6, lo);
        ctx.moveTo(center - boxSpan / 2 + 6, hi);
        ctx.lineTo(center + boxSpan / 2 - 6, hi);
      }
      ctx.stroke();
      // box + median
      if (horizontal) {
        ctx.fillStyle = withAlpha(color, 0.22);
        ctx.fillRect(q1, center - boxSpan / 2, q3 - q1, boxSpan);
        ctx.strokeStyle = color;
        ctx.strokeRect(q1, center - boxSpan / 2, q3 - q1, boxSpan);
        ctx.beginPath();
        ctx.moveTo(q2, center - boxSpan / 2);
        ctx.lineTo(q2, center + boxSpan / 2);
        ctx.stroke();
      } else {
        ctx.fillStyle = withAlpha(color, 0.22);
        ctx.fillRect(center - boxSpan / 2, q3, boxSpan, q1 - q3);
        ctx.strokeStyle = color;
        ctx.strokeRect(center - boxSpan / 2, q3, boxSpan, q1 - q3);
        ctx.beginPath();
        ctx.moveTo(center - boxSpan / 2, q2);
        ctx.lineTo(center + boxSpan / 2, q2);
        ctx.stroke();
      }
      // outliers: hollow circles
      ctx.fillStyle = T.bg;
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.2;
      for (const v of g.stats.outliers) {
        const pos = sv(v);
        ctx.beginPath();
        if (horizontal) ctx.arc(pos, center, 3, 0, Math.PI * 2);
        else ctx.arc(center, pos, 3, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
      }
      ctx.restore();
    });

    // group labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    items.forEach((g, i) => {
      const center = slot(i);
      if (horizontal) {
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(g.label, padL - 8, center);
      } else {
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(g.label, center, padT + ph + 8);
      }
    });
    ctx.restore();
    void valueFormat;
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = new Tooltip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      let idx = -1;
      geom.items.forEach((g, i) => {
        const center = geom.slot(i);
        if (geom.horizontal
          ? Math.abs(my - center) < geom.boxSpan
          : Math.abs(mx - center) < geom.boxSpan) idx = i;
      });
      if (idx !== hover) { hover = idx; draw(); }
      if (idx >= 0) {
        const s = geom.items[idx].stats;
        const x = geom.horizontal ? mx : geom.slot(idx);
        const y = geom.horizontal ? geom.slot(idx) : my;
        tip.show(x, y, [
          [geom.items[idx].label, `n = ${s.n}`],
          ['max', valueFormat(s.max)],
          ['q3', valueFormat(s.q3)],
          ['median', valueFormat(s.median)],
          ['q1', valueFormat(s.q1)],
          ['min', valueFormat(s.min)],
          ['outliers', String(s.outliers.length)],
        ], geom.w);
      } else {
        tip.hide();
      }
    }, () => {
      hover = -1;
      tip.hide();
      draw();
    });
  } else {
    unbindEvents(canvas);
  }

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Radar chart                                                             */
/* ---------------------------------------------------------------------- */

/**
 * Draw a radar (spider) chart with polygon grid, semi-transparent filled
 * series and an in-canvas legend.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   axes: [{label: string, max?: number}],
 *   series: [{label?: string, values: number[], color?: string}],
 *   levels?: number,               // grid rings (default 4)
 *   interactive?: boolean,         // hover a series → tooltip
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function radar(canvas, spec = {}) {
  let hover = -1;
  let geom = null;

  const cleanAxes = () => (Array.isArray(spec.axes) ? spec.axes : [])
    .map((a, i) => ({ label: a?.label ?? `axis ${i + 1}`, max: Number(a?.max) }));
  const cleanSeries = () => (Array.isArray(spec.series) ? spec.series : [])
    .map((s, i) => ({
      label: s?.label ?? `series ${i + 1}`,
      color: s?.color,
      values: (Array.isArray(s?.values) ? s.values : []).map(Number),
    }));

  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const axes = cleanAxes();
    const series = cleanSeries();
    const usable = axes.filter((a) => Number.isFinite(a.max) && a.max > 0);
    if (!series.length || !axes.length || usable.length !== axes.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }
    setAria(canvas, `Radar chart, ${axes.length} axes, ${series.length} series`);

    const levels = Math.max(2, Math.round(spec.levels) || 4);
    const legendH = series.length * 15 + 8;
    const cx = w / 2;
    const cy = (h - (spec.title ? 10 : 0)) / 2 + 6;
    const radius = Math.max(30, Math.min(w, h) / 2
      - (spec.title ? 34 : 18) - 26);
    const angle = (i) => -Math.PI / 2 + (i / axes.length) * Math.PI * 2;
    const pt = (i, frac) => [
      cx + Math.cos(angle(i)) * radius * frac,
      cy + Math.sin(angle(i)) * radius * frac,
    ];
    geom = { axes, series, cx, cy, radius, angle, pt, w, h, legendH };

    // grid rings + spokes
    ctx.save();
    ctx.strokeStyle = T.grid;
    ctx.lineWidth = 1;
    for (let lvl = 1; lvl <= levels; lvl += 1) {
      ctx.beginPath();
      for (let i = 0; i <= axes.length; i += 1) {
        const [x, y] = pt(i % axes.length, lvl / levels);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
    }
    for (let i = 0; i < axes.length; i += 1) {
      const [x, y] = pt(i, 1);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(x, y);
      ctx.stroke();
    }
    ctx.restore();

    // axis labels
    ctx.save();
    ctx.font = `500 ${AXIS_FONT}`;
    ctx.fillStyle = T.axis;
    ctx.textBaseline = 'middle';
    axes.forEach((a, i) => {
      const [x, y] = pt(i, 1.14);
      ctx.textAlign = Math.abs(x - cx) < 6 ? 'center'
        : x > cx ? 'left' : 'right';
      ctx.fillText(a.label, x, y);
    });
    ctx.restore();

    // series polygons (fill first at low alpha, stroke on top)
    series.forEach((s, si) => {
      const color = s.color ?? T.palette[si % T.palette.length];
      const fracs = s.values.map((v, i) => {
        const max = axes[i] ? axes[i].max : 1;
        return Number.isFinite(v) ? Math.max(0, Math.min(1, v / (max || 1))) : 0;
      });
      if (fracs.length !== axes.length) return;
      ctx.save();
      if (si === hover) {
        ctx.shadowColor = withAlpha(color, 0.55);
        ctx.shadowBlur = 10;
      }
      ctx.beginPath();
      for (let i = 0; i <= axes.length; i += 1) {
        const [x, y] = pt(i % axes.length, fracs[i % axes.length] || 0);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.fillStyle = withAlpha(color, si === hover ? 0.26 : 0.16);
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = si === hover ? 2.2 : 1.6;
      ctx.stroke();
      // vertex dots
      for (let i = 0; i < axes.length; i += 1) {
        const [x, y] = pt(i, fracs[i] || 0);
        ctx.beginPath();
        ctx.arc(x, y, si === hover ? 3.4 : 2.4, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
      }
      ctx.restore();
    });

    drawLegend(ctx, series.map((s, i) => ({
      label: s.label,
      color: s.color ?? T.palette[i % T.palette.length],
    })), w, (spec.title ? 30 : 10) + legendH - 15 * series.length + 15);
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = new Tooltip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      // point-in-polygon test per series (ray casting)
      let idx = -1;
      geom.series.forEach((s, si) => {
        const fracs = s.values.map((v, i) => {
          const max = geom.axes[i] ? geom.axes[i].max : 1;
          return Number.isFinite(v) ? Math.max(0, Math.min(1, v / (max || 1))) : 0;
        });
        if (fracs.length !== geom.axes.length) return;
        const verts = geom.axes.map((_, i) => geom.pt(i, fracs[i] || 0));
        let inside = false;
        for (let i = 0, j = verts.length - 1; i < verts.length; j = i++) {
          const [xi, yi] = verts[i];
          const [xj, yj] = verts[j];
          if ((yi > my) !== (yj > my)
            && mx < ((xj - xi) * (my - yi)) / (yj - yi) + xi) {
            inside = !inside;
          }
        }
        if (inside) idx = si;
      });
      if (idx !== hover) { hover = idx; draw(); }
      if (idx >= 0) {
        const s = geom.series[idx];
        tip.show(mx, my, [
          [s.label, `${geom.axes.length} axes`],
          ...geom.axes.map((a, i) => [a.label,
            Number.isFinite(s.values[i]) ? fmtCompact(s.values[i]) : '—']),
        ], geom.w);
      } else {
        tip.hide();
      }
    }, () => {
      hover = -1;
      tip.hide();
      draw();
    });
  } else {
    unbindEvents(canvas);
  }

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Heatmap                                                                 */
/* ---------------------------------------------------------------------- */

/**
 * Draw a matrix heatmap with a `--chart-*` colour ramp, per-cell values and
 * row/column labels.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   rows: string[], cols: string[],
 *   values: number[][],           // values[r][c]
 *   xlabel?: string, ylabel?: string,
 *   format?: (n) => string,       // cell + tooltip value format
 *   interactive?: boolean,        // hover cell → tooltip
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function heatmap(canvas, spec = {}) {
  let hover = null; // {r, c}
  let geom = null;
  const format = (v) => (typeof spec.format === 'function'
    ? spec.format(v) : fmtCompact(v));

  const matrix = () => (Array.isArray(spec.values) ? spec.values : [])
    .map((row) => (Array.isArray(row) ? row : []).map(Number));

  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const rows = Array.isArray(spec.rows) ? spec.rows.map(String) : [];
    const cols = Array.isArray(spec.cols) ? spec.cols.map(String) : [];
    const values = matrix();
    const numbers = values.flat().filter(Number.isFinite);
    if (!rows.length || !cols.length || !numbers.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }
    setAria(canvas, `Heatmap, ${rows.length} rows × ${cols.length} columns`);

    const min = Math.min(...numbers);
    const max = Math.max(...numbers);
    const span = max - min || 1;
    // 4-stop sequential ramp: panel → chart-1 → chart-2 → chart-5 (danger)
    const ramp = (t) => {
      const stops = [T.panel2, T.palette[0], T.palette[1], T.palette[4]];
      const scaled = Math.max(0, Math.min(1, t)) * (stops.length - 1);
      const i = Math.min(stops.length - 2, Math.floor(scaled));
      return interpolate(stops[i], stops[i + 1], scaled - i);
    };

    const rotateCols = cols.length > 8;
    const padL = Math.min(140, Math.max(...rows.map((r) => r.length)) * 6.2 + 10);
    const padR = 14;
    const padT = spec.title ? 28 : 14;
    const padB = rotateCols ? 58 : 30 + (spec.xlabel ? 14 : 0);
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const cw = pw / cols.length;
    const ch = ph / rows.length;
    geom = { rows, cols, values, padL, padT, cw, ch, w, h };

    // cells
    rows.forEach((_, r) => {
      cols.forEach((__, c) => {
        const v = values[r] ? values[r][c] : NaN;
        const t = Number.isFinite(v) ? (v - min) / span : 0;
        const x = padL + c * cw;
        const y = padT + r * ch;
        const hovered = hover && hover.r === r && hover.c === c;
        ctx.fillStyle = Number.isFinite(v) ? ramp(t) : T.panel2;
        ctx.fillRect(x + 0.5, y + 0.5, Math.max(1, cw - 1), Math.max(1, ch - 1));
        if (hovered) {
          ctx.strokeStyle = T.accent;
          ctx.lineWidth = 2;
          ctx.strokeRect(x + 1, y + 1, Math.max(1, cw - 2), Math.max(1, ch - 2));
        }
        // in-cell value when there is room; contrast flips mid-ramp
        if (Number.isFinite(v) && cw > 26 && ch > 15) {
          ctx.save();
          ctx.font = `500 ${MONO_FONT}`;
          ctx.fillStyle = t > 0.55 ? T.bg : cssVar('--text-strong', '#f2f6fa');
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(format(v), x + cw / 2, y + ch / 2);
          ctx.restore();
        }
      });
    });

    // labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    rows.forEach((label, r) => {
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(label, padL - 6, padT + (r + 0.5) * ch);
    });
    cols.forEach((label, c) => {
      ctx.textAlign = 'center';
      if (rotateCols) {
        ctx.save();
        ctx.translate(padL + (c + 0.5) * cw, padT + ph + 8);
        ctx.rotate(-Math.PI / 4);
        ctx.textBaseline = 'top';
        ctx.fillText(label, 0, 0);
        ctx.restore();
      } else {
        ctx.textBaseline = 'top';
        ctx.fillText(label, padL + (c + 0.5) * cw, padT + ph + 8);
      }
    });
    if (spec.xlabel) {
      ctx.font = `600 ${AXIS_FONT}`;
      ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
      ctx.textAlign = 'center';
      ctx.fillText(String(spec.xlabel), padL + pw / 2, h - 6);
    }
    if (spec.ylabel) {
      ctx.save();
      ctx.translate(10, padT + ph / 2);
      ctx.rotate(-Math.PI / 2);
      ctx.fillText(String(spec.ylabel), 0, 0);
      ctx.restore();
    }
    ctx.restore();
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = new Tooltip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      const c = Math.floor((mx - geom.padL) / geom.cw);
      const r = Math.floor((my - geom.padT) / geom.ch);
      if (r >= 0 && r < geom.rows.length && c >= 0 && c < geom.cols.length) {
        hover = { r, c };
        draw();
        const v = geom.values[r] ? geom.values[r][c] : NaN;
        tip.show(mx, my, [
          [`${geom.rows[r]} · ${geom.cols[c]}`,
            Number.isFinite(v) ? format(v) : '—'],
        ], geom.w);
      } else if (hover) {
        hover = null;
        tip.hide();
        draw();
      } else {
        tip.hide();
      }
    }, () => {
      hover = null;
      tip.hide();
      draw();
    });
  } else {
    unbindEvents(canvas);
  }

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Treemap (squarified)                                                    */
/* ---------------------------------------------------------------------- */

/**
 * Worst aspect ratio of one laid-out row (Bruls et al. 2000).
 *
 * @param {Array<{area: number}>} row Cells placed side by side.
 * @param {number} stripLength Length of the side the row runs along.
 * @returns {number}
 */
function worstRatio(row, stripLength) {
  const area = row.reduce((acc, cell) => acc + cell.area, 0);
  if (area <= 0 || stripLength <= 0) return Infinity;
  const thickness = area / stripLength;
  let worst = 0;
  for (const cell of row) {
    const length = cell.area / thickness;
    worst = Math.max(worst, length / thickness, thickness / length);
  }
  return worst;
}

/**
 * Classic squarified-treemap layout (greedy rows along the longer side).
 *
 * @param {Array<{value: number}>} items Descending by value, all > 0.
 * @param {number} x
 * @param {number} y
 * @param {number} w
 * @param {number} h
 * @returns {Array<{x: number, y: number, w: number, h: number,
 *   value: number}>}
 */
function squarify(items, x, y, w, h) {
  const out = [];
  let rest = items.slice();
  let rect = { x, y, w, h };
  let guard = 0;
  while (rest.length && guard < 10000) {
    guard += 1;
    if (rect.w <= 0 || rect.h <= 0) break;
    const total = rest.reduce((acc, item) => acc + item.value, 0);
    if (total <= 0) break;
    const scale = (rect.w * rect.h) / total;
    // longer side = the direction the row runs along
    const horizontalRow = rect.w >= rect.h;
    const stripLength = horizontalRow ? rect.w : rect.h;

    let row = [rest[0]];
    let i = 1;
    while (i < rest.length) {
      const candidate = rest.slice(0, i + 1).map((item) => ({
        ...item, area: item.value * scale }));
      const current = row.map((item) => ({ ...item, area: item.value * scale }));
      if (worstRatio(candidate, stripLength)
        <= worstRatio(current, stripLength)) {
        row = rest.slice(0, i + 1);
        i += 1;
      } else {
        break;
      }
    }
    const rowArea = row.reduce((acc, item) => acc + item.value * scale, 0);
    const thickness = rowArea / stripLength;
    if (!(thickness > 0)) break;
    let offset = 0;
    for (const item of row) {
      const length = (item.value * scale) / thickness;
      const cell = {
        x: horizontalRow ? rect.x + offset : rect.x,
        y: horizontalRow ? rect.y : rect.y + offset,
        w: horizontalRow ? length : thickness,
        h: horizontalRow ? thickness : length,
        value: item.value,
        label: item.label,
        kind: item.kind,
      };
      if (cell.w > 0 && cell.h > 0) out.push(cell);
      offset += length;
    }
    if (horizontalRow) {
      rect = { x: rect.x, y: rect.y + thickness, w: rect.w, h: rect.h - thickness };
    } else {
      rect = { x: rect.x + thickness, y: rect.y, w: rect.w - thickness, h: rect.h };
    }
    rest = rest.slice(row.length);
  }
  return out;
}

/**
 * Draw a squarified treemap: cells sized by value, coloured per kind.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   items: [{label: string, value: number, kind?: string}],
 *   format?: (n) => string,       // default compact
 *   interactive?: boolean,        // hover cell → tooltip
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function treemap(canvas, spec = {}) {
  let hover = -1;
  let geom = null;
  const format = (v) => (typeof spec.format === 'function'
    ? spec.format(v) : fmtCompact(v));

  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const items = (Array.isArray(spec.items) ? spec.items : [])
      .filter((i) => i && Number.isFinite(+i.value) && +i.value > 0)
      .sort((a, b) => b.value - a.value);
    if (!items.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }
    setAria(canvas, `Treemap of ${items.length} items`);
    const total = items.reduce((acc, i) => acc + i.value, 0);

    const padT = spec.title ? 30 : 8;
    const pad = 6;
    const cells = squarify(items, pad, padT, w - pad * 2, h - padT - pad);
    geom = { cells, total, w, h };

    cells.forEach((cell, i) => {
      const color = cell.kind ? colorFor(cell.kind) : T.palette[i % 8];
      const hovered = i === hover;
      ctx.save();
      if (hovered) {
        ctx.shadowColor = withAlpha(color, 0.6);
        ctx.shadowBlur = 10;
      }
      ctx.fillStyle = withAlpha(color, hovered ? 0.5 : 0.32);
      ctx.fillRect(cell.x + 1, cell.y + 1, cell.w - 2, cell.h - 2);
      ctx.strokeStyle = T.bg;
      ctx.lineWidth = 2;
      ctx.strokeRect(cell.x + 1, cell.y + 1, cell.w - 2, cell.h - 2);
      ctx.restore();
      // label + value when the cell can host them
      ctx.save();
      ctx.font = `500 ${AXIS_FONT}`;
      ctx.fillStyle = cssVar('--text-strong', '#f2f6fa');
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      if (cell.w > 34 && cell.h > 16) {
        const label = String(cell.label ?? '');
        const maxChars = Math.floor((cell.w - 10) / 6.2);
        ctx.fillText(label.length > maxChars && maxChars > 1
          ? `${label.slice(0, maxChars - 1)}…` : label,
        cell.x + 5, cell.y + 4);
      }
      if (cell.w > 40 && cell.h > 32) {
        ctx.font = `600 ${MONO_FONT}`;
        ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
        ctx.textBaseline = 'bottom';
        ctx.fillText(format(cell.value), cell.x + 5, cell.y + cell.h - 4);
      }
      ctx.restore();
    });
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = new Tooltip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      let idx = -1;
      geom.cells.forEach((cell, i) => {
        if (mx >= cell.x && mx <= cell.x + cell.w
          && my >= cell.y && my <= cell.y + cell.h) idx = i;
      });
      if (idx !== hover) { hover = idx; draw(); }
      if (idx >= 0) {
        const cell = geom.cells[idx];
        const pct = geom.total
          ? Math.round((cell.value / geom.total) * 1000) / 10 : 0;
        tip.show(mx, my, [
          [cell.label ?? 'cell', format(cell.value)],
          ['share', `${pct}%`],
          ['kind', cell.kind || '—'],
        ], geom.w);
      } else {
        tip.hide();
      }
    }, () => {
      hover = -1;
      tip.hide();
      draw();
    });
  } else {
    unbindEvents(canvas);
  }

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Sparkline                                                               */
/* ---------------------------------------------------------------------- */

/**
 * Draw a mini trend line (for embedding in history tables). Unlike
 * `charts.sparkline` this one is kind-coloured and honours explicit
 * `width`/`height` specs by sizing the canvas element itself.
 *
 * Spec:
 * ```
 * {
 *   values: number[],
 *   width?: number, height?: number,  // CSS px, applied to the canvas
 *   kind?: string,                    // --kind-* colour source
 *   fill?: boolean,                   // soft area fill (default true)
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function sparkline(canvas, spec = {}) {
  function draw() {
    const T = theme();
    const values = (Array.isArray(spec.values) ? spec.values : [])
      .map(Number).filter(Number.isFinite);
    if (spec.width) canvas.style.width = `${Math.round(spec.width)}px`;
    if (spec.height) canvas.style.height = `${Math.round(spec.height)}px`;
    const { ctx, w, h } = setup(canvas);
    ctx.clearRect(0, 0, w, h);
    if (!values.length) {
      drawEmpty(ctx, w, h);
      return;
    }
    setAria(canvas, `Sparkline of ${values.length} values`);
    const color = spec.kind ? colorFor(spec.kind) : T.accent;
    let lo = Math.min(...values);
    let hi = Math.max(...values);
    if (hi === lo) { hi += 0.5; lo -= 0.5; }
    const sx = (i) => (values.length === 1 ? w / 2 : (i / (values.length - 1)) * w);
    const sy = (v) => 3 + (h - 6) * (1 - (v - lo) / (hi - lo));

    if (spec.fill !== false) {
      ctx.save();
      ctx.beginPath();
      values.forEach((v, i) => {
        if (i === 0) ctx.moveTo(sx(i), sy(v));
        else ctx.lineTo(sx(i), sy(v));
      });
      ctx.lineTo(sx(values.length - 1), h);
      ctx.lineTo(sx(0), h);
      ctx.closePath();
      ctx.fillStyle = withAlpha(color, 0.14);
      ctx.fill();
      ctx.restore();
    }
    ctx.save();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.6;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.beginPath();
    values.forEach((v, i) => {
      if (i === 0) ctx.moveTo(sx(i), sy(v));
      else ctx.lineTo(sx(i), sy(v));
    });
    ctx.stroke();
    ctx.restore();
    // last-point marker
    ctx.save();
    ctx.fillStyle = color;
    ctx.strokeStyle = T.bg;
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    ctx.arc(sx(values.length - 1), sy(values[values.length - 1]), 2.6, 0,
      Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    ctx.restore();
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);
  unbindEvents(canvas);

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Gauge                                                                   */
/* ---------------------------------------------------------------------- */

/**
 * Draw a semicircular gauge (risk scores and other 0..N verdicts).
 *
 * Spec:
 * ```
 * {
 *   value: number, min?: number, max?: number,   // default 0..100
 *   label?: string,
 *   format?: (n) => string,                      // big centre value
 *   bands?: [{to: number, color?: string}],      // thresholds, ascending
 *   // default bands colour the thirds ok/warn/danger
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function gauge(canvas, spec = {}) {
  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const min = Number.isFinite(+spec.min) ? +spec.min : 0;
    const max = Number.isFinite(+spec.max) ? +spec.max : 100;
    const span = max - min || 1;
    const raw = Number(spec.value);
    const value = Number.isFinite(raw) ? Math.max(min, Math.min(max, raw)) : min;
    const frac = (value - min) / span;
    const format = (v) => (typeof spec.format === 'function'
      ? spec.format(v) : fmtCompact(v));
    setAria(canvas, `Gauge: ${format(value)} of ${format(min)}–${format(max)}`
      + (spec.label ? ` (${spec.label})` : ''));

    const bands = (Array.isArray(spec.bands) && spec.bands.length
      ? spec.bands : [
        { to: min + span * 0.5, color: T.ok },
        { to: min + span * 0.8, color: T.warn },
        { to: max, color: T.danger },
      ]).map((b) => ({
        to: Number.isFinite(+b.to) ? +b.to : max,
        color: b.color,
      })).sort((a, b) => a.to - b.to);

    const cx = w / 2;
    const cy = h - Math.max(34, h * 0.22);
    const radius = Math.max(30, Math.min(w / 2 - 24, cy - 26));
    const START = Math.PI;         // left
    const SWEEP = Math.PI;         // over the top to the right
    const angleAt = (f) => START + SWEEP * Math.max(0, Math.min(1, f));

    // track + threshold bands
    ctx.save();
    ctx.lineWidth = 13;
    ctx.lineCap = 'butt';
    ctx.strokeStyle = T.panel3;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, START, START + SWEEP);
    ctx.stroke();
    let bandStart = 0;
    for (const band of bands) {
      const bandFrac = Math.max(0, Math.min(1, (band.to - min) / span));
      if (bandFrac <= bandStart) continue;
      ctx.strokeStyle = withAlpha(band.color ?? T.axis, 0.30);
      ctx.beginPath();
      ctx.arc(cx, cy, radius, angleAt(bandStart), angleAt(bandFrac));
      ctx.stroke();
      bandStart = bandFrac;
    }
    // value arc — coloured by the band the value lands in
    const activeBand = [...bands].reverse()
      .find((b) => value <= b.to) ?? bands[bands.length - 1];
    ctx.strokeStyle = activeBand?.color ?? T.accent;
    ctx.lineWidth = 13;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, START, angleAt(frac));
    ctx.stroke();
    ctx.restore();

    // ticks along the arc
    const ticks = niceTicks(min, max, 5);
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    for (const t of ticks.ticks) {
      const f = (t - min) / span;
      if (f < 0 || f > 1) continue;
      const a = angleAt(f);
      const x1 = cx + Math.cos(a) * (radius - 10);
      const y1 = cy + Math.sin(a) * (radius - 10);
      const x2 = cx + Math.cos(a) * (radius - 16);
      const y2 = cy + Math.sin(a) * (radius - 16);
      ctx.strokeStyle = T.axis;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.stroke();
      const tx = cx + Math.cos(a) * (radius - 28);
      const ty = cy + Math.sin(a) * (radius - 28);
      ctx.fillText(fmtCompact(t), tx, ty);
    }
    ctx.restore();

    // needle + hub
    const na = angleAt(frac);
    ctx.save();
    ctx.strokeStyle = cssVar('--text-strong', '#f2f6fa');
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(na) * (radius - 20), cy + Math.sin(na) * (radius - 20));
    ctx.stroke();
    ctx.fillStyle = cssVar('--text-strong', '#f2f6fa');
    ctx.beginPath();
    ctx.arc(cx, cy, 4, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();

    // big value + label under the pivot
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = activeBand?.color ?? T.accent;
    ctx.font = `700 21px var(--font-mono, monospace)`;
    ctx.fillText(format(value), cx, cy + 26);
    if (spec.label) {
      ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
      ctx.font = `600 ${AXIS_FONT}`;
      ctx.fillText(String(spec.label).toUpperCase(), cx, cy + 42);
    }
    ctx.restore();
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);
  unbindEvents(canvas);

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Stacked bar chart                                                       */
/* ---------------------------------------------------------------------- */

/**
 * Draw a stacked bar chart, vertical by default.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   groups: string[],
 *   series: [{label?: string, values: number[], color?: string}],
 *   orient?: 'v'|'h',             // default 'v'
 *   valueFormat?: (n) => string,  // default compact
 *   interactive?: boolean,        // hover bar → breakdown tooltip
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function stackedBar(canvas, spec = {}) {
  let hover = -1;
  let geom = null;
  const valueFormat = (v) => (typeof spec.valueFormat === 'function'
    ? spec.valueFormat(v) : fmtCompact(v));

  const clean = () => {
    const groups = (Array.isArray(spec.groups) ? spec.groups : [])
      .map((g, i) => String(g ?? `group ${i + 1}`));
    const series = (Array.isArray(spec.series) ? spec.series : [])
      .map((s, i) => ({
        label: s?.label ?? `series ${i + 1}`,
        color: s?.color,
        values: (Array.isArray(s?.values) ? s.values : [])
          .map((v) => (Number.isFinite(+v) ? Math.max(0, +v) : 0)),
      }))
      .map((s) => ({ ...s, values: s.values.slice(0, groups.length) }));
    return { groups, series };
  };

  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const { groups, series } = clean();
    if (!groups.length || !series.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }
    setAria(canvas, `Stacked bar chart, ${groups.length} groups × `
      + `${series.length} series`);
    const totals = groups.map((_, gi) =>
      series.reduce((acc, s) => acc + (s.values[gi] || 0), 0));
    const maxTotal = Math.max(...totals, 0);

    const horizontal = spec.orient === 'h';
    const ticks = niceTicks(0, maxTotal, 5);
    const n = groups.length;
    const legendRows = series.length * 15 + 6;
    const padL = horizontal ? Math.min(150, Math.max(
      ...groups.map((g) => g.length)) * 6.2 + 10) : 48;
    const padR = horizontal ? 46 : Math.max(14, legendRows > 40 ? 14 : 14);
    const padT = (spec.title ? 28 : 12) + (horizontal ? 0 : 0);
    const padB = horizontal ? 26 : 34;
    const pw = w - padL - padR;
    const ph = h - padT - padB - (horizontal ? legendRows : 0);
    const sv = (v) => (horizontal
      ? padL + ((v - ticks.lo) / (ticks.hi - ticks.lo)) * pw
      : padT + ph - ((v - ticks.lo) / (ticks.hi - ticks.lo)) * ph);
    const slot = (i) => (horizontal
      ? padT + (i + 0.5) * (ph / n)
      : padL + (i + 0.5) * (pw / n));
    const barSpan = Math.min(
      (horizontal ? ph / n : pw / n) * 0.6, 90);
    geom = { groups, series, totals, horizontal, padL, padT, pw, ph,
      sv, slot, barSpan, w, h };

    // grid + value-axis labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.strokeStyle = T.grid;
    ctx.setLineDash([4, 4]);
    ctx.lineWidth = 1;
    ctx.fillStyle = T.axis;
    for (const t of ticks.ticks) {
      const pos = Math.round(sv(t)) + 0.5;
      ctx.beginPath();
      if (horizontal) {
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.moveTo(pos, padT);
        ctx.lineTo(pos, padT + ph);
        ctx.stroke();
        ctx.fillText(fmtCompact(t), pos, padT + ph + 6);
      } else {
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.moveTo(padL, pos);
        ctx.lineTo(padL + pw, pos);
        ctx.stroke();
        ctx.fillText(fmtCompact(t), padL - 8, pos);
      }
    }
    ctx.restore();

    // stacked bars
    groups.forEach((_, gi) => {
      const center = slot(gi);
      let acc = 0;
      series.forEach((s, si) => {
        const v = s.values[gi] || 0;
        if (v <= 0) return;
        const from = sv(acc);
        acc += v;
        const to = sv(acc);
        const color = s.color ?? T.palette[si % T.palette.length];
        const hovered = gi === hover;
        ctx.save();
        if (hovered) {
          ctx.shadowColor = withAlpha(color, 0.45);
          ctx.shadowBlur = 7;
        }
        ctx.fillStyle = withAlpha(color, hovered ? 0.85 : 0.62);
        if (horizontal) {
          ctx.fillRect(from, center - barSpan / 2, to - from, barSpan);
          ctx.strokeStyle = T.bg;
          ctx.lineWidth = 1;
          ctx.strokeRect(from, center - barSpan / 2, to - from, barSpan);
        } else {
          ctx.fillRect(center - barSpan / 2, to, barSpan, from - to);
          ctx.strokeStyle = T.bg;
          ctx.lineWidth = 1;
          ctx.strokeRect(center - barSpan / 2, to, barSpan, from - to);
        }
        ctx.restore();
      });
      // total caption on top of each bar
      if (totals[gi] > 0) {
        ctx.save();
        ctx.font = `600 ${MONO_FONT}`;
        ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
        if (horizontal) {
          ctx.textAlign = 'left';
          ctx.textBaseline = 'middle';
          ctx.fillText(fmtCompact(totals[gi]), sv(totals[gi]) + 6, center);
        } else {
          ctx.textAlign = 'center';
          ctx.textBaseline = 'bottom';
          ctx.fillText(fmtCompact(totals[gi]), center, sv(totals[gi]) - 4);
        }
        ctx.restore();
      }
    });

    // group labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    groups.forEach((label, gi) => {
      const center = slot(gi);
      if (horizontal) {
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(label, padL - 8, center);
      } else {
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(label, center, padT + ph + 8);
      }
    });
    ctx.restore();

    // in-canvas legend
    drawLegend(ctx, series.map((s, i) => ({
      label: s.label,
      color: s.color ?? T.palette[i % T.palette.length],
    })), w, padT + 2);
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = new Tooltip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      let idx = -1;
      geom.groups.forEach((_, gi) => {
        const center = geom.slot(gi);
        if (geom.horizontal
          ? Math.abs(my - center) < geom.barSpan / 2 + 3
          : Math.abs(mx - center) < geom.barSpan / 2 + 3) idx = gi;
      });
      if (idx !== hover) { hover = idx; draw(); }
      if (idx >= 0) {
        const rows = geom.series
          .filter((s) => (s.values[idx] || 0) > 0)
          .map((s, si) => [s.label, valueFormat(s.values[idx])]);
        rows.unshift([geom.groups[idx],
          `total ${valueFormat(geom.totals[idx])}`]);
        const x = geom.horizontal ? mx : geom.slot(idx);
        const y = geom.horizontal ? geom.slot(idx) : my;
        tip.show(x, y, rows, geom.w);
      } else {
        tip.hide();
      }
    }, () => {
      hover = -1;
      tip.hide();
      draw();
    });
  } else {
    unbindEvents(canvas);
  }

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Scatter plot (kind-coloured)                                            */
/* ---------------------------------------------------------------------- */

/**
 * Draw a kind-coloured scatter plot with auto-scaled axes.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   points: [{x: number, y: number, label?: string, kind?: string,
 *             size?: number}],
 *   xLabel?: string, yLabel?: string,
 *   interactive?: boolean,        // hover point → tooltip
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function scatter(canvas, spec = {}) {
  let hover = -1;
  let geom = null;

  const points = () => (Array.isArray(spec.points) ? spec.points : [])
    .filter((p) => p && Number.isFinite(+p.x) && Number.isFinite(+p.y))
    .map((p) => ({
      x: +p.x, y: +p.y,
      label: p.label ?? '',
      kind: p.kind ?? '',
      size: Number.isFinite(+p.size) ? Math.max(2, +p.size) : 3.4,
    }));

  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const pts = points();
    if (!pts.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }
    const kinds = new Set(pts.map((p) => p.kind).filter(Boolean));
    setAria(canvas, `Scatter plot of ${pts.length} points`
      + (kinds.size ? ` across ${kinds.size} kinds` : ''));

    let xmin = Infinity; let xmax = -Infinity;
    let ymin = Infinity; let ymax = -Infinity;
    for (const p of pts) {
      if (p.x < xmin) xmin = p.x;
      if (p.x > xmax) xmax = p.x;
      if (p.y < ymin) ymin = p.y;
      if (p.y > ymax) ymax = p.y;
    }
    if (xmax === xmin) xmax = xmin + 1;
    if (ymax === ymin) ymax = ymin + 1;

    const padL = 52;
    const padR = 18;
    const padT = spec.title ? 30 : 14;
    const padB = 44;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const xt = niceTicks(xmin, xmax, 5);
    const yt = niceTicks(ymin, ymax, 5);
    const sx = (v) => padL + ((v - xt.lo) / (xt.hi - xt.lo)) * pw;
    const sy = (v) => padT + ph - ((v - yt.lo) / (yt.hi - yt.lo)) * ph;
    geom = { pts, sx, sy, padL, padT, pw, ph, w, h };

    // gridlines + tick labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    ctx.strokeStyle = T.grid;
    ctx.setLineDash([4, 4]);
    ctx.lineWidth = 1;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (const t of yt.ticks) {
      const y = Math.round(sy(t)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();
      ctx.fillText(fmtCompact(t), padL - 8, y);
    }
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (const t of xt.ticks) {
      const x = Math.round(sx(t)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(x, padT);
      ctx.lineTo(x, padT + ph);
      ctx.stroke();
      ctx.fillText(fmtCompact(t), x, padT + ph + 6);
    }
    ctx.restore();

    // axis captions
    ctx.save();
    ctx.font = `600 ${AXIS_FONT}`;
    ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
    if (spec.xLabel) {
      ctx.textAlign = 'center';
      ctx.fillText(String(spec.xLabel), padL + pw / 2, h - 8);
    }
    if (spec.yLabel) {
      ctx.save();
      ctx.translate(12, padT + ph / 2);
      ctx.rotate(-Math.PI / 2);
      ctx.textAlign = 'center';
      ctx.fillText(String(spec.yLabel), 0, 0);
      ctx.restore();
    }
    ctx.restore();

    // points (kind-coloured)
    pts.forEach((p, i) => {
      const color = p.kind ? colorFor(p.kind) : T.palette[0];
      ctx.save();
      if (i === hover) {
        ctx.shadowColor = color;
        ctx.shadowBlur = 9;
      }
      ctx.fillStyle = withAlpha(color, i === hover ? 1 : 0.85);
      ctx.beginPath();
      ctx.arc(sx(p.x), sy(p.y), i === hover ? p.size + 2 : p.size, 0,
        Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = T.bg;
      ctx.lineWidth = 1.2;
      ctx.stroke();
      ctx.restore();
    });
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = new Tooltip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      let best = -1;
      let bestD2 = 14 * 14;
      geom.pts.forEach((p, i) => {
        const dx = geom.sx(p.x) - mx;
        const dy = geom.sy(p.y) - my;
        const d2 = dx * dx + dy * dy;
        if (d2 <= bestD2) { bestD2 = d2; best = i; }
      });
      if (best !== hover) { hover = best; draw(); }
      if (hover >= 0) {
        const p = geom.pts[hover];
        tip.show(geom.sx(p.x), geom.sy(p.y), [
          [p.label || p.kind || 'point',
            `${fmtCompact(p.x)} , ${fmtCompact(p.y)}`],
        ], geom.w);
      } else {
        tip.hide();
      }
    }, () => {
      hover = -1;
      tip.hide();
      draw();
    });
  } else {
    unbindEvents(canvas);
  }

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Violin plot (simplified)                                                */
/* ---------------------------------------------------------------------- */

/**
 * Draw simplified violins: one mirrored histogram blob per group with an
 * inner median/quartile marker.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   groups: [{label?: string, values: number[]}],
 *   bins?: number,                // histogram resolution (default 16)
 *   interactive?: boolean,        // hover violin → summary tooltip
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function violin(canvas, spec = {}) {
  let hover = -1;
  let geom = null;

  const groups = () => (Array.isArray(spec.groups) ? spec.groups : [])
    .map((g, i) => {
      const sorted = (Array.isArray(g?.values) ? g.values : [])
        .map(Number).filter(Number.isFinite).sort((a, b) => a - b);
      return { label: g?.label ?? `group ${i + 1}`, sorted };
    })
    .filter((g) => g.sorted.length >= 2);

  function draw() {
    const begin = beginDraw(canvas, spec.title);
    if (!begin) return;
    const { ctx, w, h } = begin;
    const T = theme();
    const items = groups();
    if (!items.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }
    setAria(canvas, `Violin plot of ${items.length} groups`);
    const bins = Math.max(4, Math.round(spec.bins) || 16);

    const all = items.flatMap((g) => g.sorted);
    const ticks = niceTicks(Math.min(...all), Math.max(...all), 5);
    const n = items.length;
    const padL = 46;
    const padR = 14;
    const padT = spec.title ? 28 : 12;
    const padB = 34;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const sy = (v) => padT + ph - ((v - ticks.lo) / (ticks.hi - ticks.lo)) * ph;
    const slot = (i) => padL + (i + 0.5) * (pw / n);
    const maxBlob = (pw / n) * 0.42;

    // histograms (shared bin edges across groups for honest comparison)
    const lo = ticks.lo;
    const hi = ticks.hi;
    const step = (hi - lo) / bins || 1;
    let maxCount = 1;
    const hists = items.map((g) => {
      const counts = new Array(bins).fill(0);
      for (const v of g.sorted) {
        let idx = Math.floor((v - lo) / step);
        if (idx < 0) idx = 0;
        if (idx >= bins) idx = bins - 1;
        counts[idx] += 1;
      }
      maxCount = Math.max(maxCount, ...counts);
      // smooth: average with neighbours so the blob has no saw teeth
      return counts.map((c, i) => {
        const prev = counts[Math.max(0, i - 1)];
        const next = counts[Math.min(bins - 1, i + 1)];
        return (prev + 2 * c + next) / 4;
      });
    });
    geom = { items, hists, sy, slot, maxBlob, maxCount, padL, padT, pw, ph, w, h };

    // gridlines + labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    ctx.strokeStyle = T.grid;
    ctx.setLineDash([4, 4]);
    ctx.lineWidth = 1;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (const t of ticks.ticks) {
      const y = Math.round(sy(t)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + pw, y);
      ctx.stroke();
      ctx.fillText(fmtCompact(t), padL - 8, y);
    }
    ctx.restore();

    // mirrored density blobs
    items.forEach((g, i) => {
      const color = T.palette[i % T.palette.length];
      const center = slot(i);
      const hist = hists[i];
      const halfAt = (bin) => (hist[bin] / maxCount) * maxBlob;
      const hovered = i === hover;
      ctx.save();
      if (hovered) {
        ctx.shadowColor = withAlpha(color, 0.5);
        ctx.shadowBlur = 9;
      }
      ctx.beginPath();
      // right side down, left side up (mirrored outline)
      for (let bin = 0; bin < bins; bin += 1) {
        const yTop = sy(lo + bin * step);
        const yBot = sy(lo + (bin + 1) * step);
        const mid = (yTop + yBot) / 2;
        const half = halfAt(bin);
        if (bin === 0) ctx.moveTo(center + half, mid);
        else ctx.lineTo(center + half, mid);
        void yBot;
      }
      for (let bin = bins - 1; bin >= 0; bin -= 1) {
        const yTop = sy(lo + bin * step);
        const yBot = sy(lo + (bin + 1) * step);
        const mid = (yTop + yBot) / 2;
        ctx.lineTo(center - halfAt(bin), mid);
      }
      ctx.closePath();
      ctx.fillStyle = withAlpha(color, hovered ? 0.30 : 0.18);
      ctx.fill();
      ctx.strokeStyle = withAlpha(color, 0.8);
      ctx.lineWidth = 1.4;
      ctx.stroke();
      // inner quartile marker: q1—median—q3 dashes
      const q1 = percentile(g.sorted, 0.25);
      const q2 = percentile(g.sorted, 0.5);
      const q3 = percentile(g.sorted, 0.75);
      ctx.strokeStyle = cssVar('--text-strong', '#f2f6fa');
      ctx.lineWidth = 1.4;
      ctx.setLineDash([3, 2]);
      ctx.beginPath();
      ctx.moveTo(center - maxBlob * 0.34, sy(q1));
      ctx.lineTo(center + maxBlob * 0.34, sy(q1));
      ctx.moveTo(center - maxBlob * 0.34, sy(q3));
      ctx.lineTo(center + maxBlob * 0.34, sy(q3));
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.moveTo(center - maxBlob * 0.44, sy(q2));
      ctx.lineTo(center + maxBlob * 0.44, sy(q2));
      ctx.stroke();
      ctx.restore();
    });

    // group labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    items.forEach((g, i) => ctx.fillText(g.label, slot(i), padT + ph + 8));
    ctx.restore();
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = new Tooltip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      let idx = -1;
      geom.items.forEach((_, i) => {
        if (Math.abs(mx - geom.slot(i)) < geom.maxBlob + 8) idx = i;
      });
      if (idx !== hover) { hover = idx; draw(); }
      if (idx >= 0) {
        const sorted = geom.items[idx].sorted;
        const mean = sorted.reduce((a, b) => a + b, 0) / sorted.length;
        tip.show(geom.slot(idx), my, [
          [geom.items[idx].label, `n = ${sorted.length}`],
          ['max', fmtCompact(sorted[sorted.length - 1])],
          ['q3', fmtCompact(percentile(sorted, 0.75))],
          ['median', fmtCompact(percentile(sorted, 0.5))],
          ['mean', fmtCompact(Math.round(mean * 100) / 100)],
          ['q1', fmtCompact(percentile(sorted, 0.25))],
          ['min', fmtCompact(sorted[0])],
        ], geom.w);
      } else {
        tip.hide();
      }
    }, () => {
      hover = -1;
      tip.hide();
      draw();
    });
  } else {
    unbindEvents(canvas);
  }

  return {
    /** Merge new spec fields and redraw. */
    update(next = {}) {
      spec = { ...spec, ...next };
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Public API                                                              */
/* ---------------------------------------------------------------------- */

/** Advanced chart facade — see the module docstring for behaviours. */
export const charts2 = {
  boxplot,
  radar,
  heatmap,
  treemap,
  sparkline,
  gauge,
  stackedBar,
  scatter,
  violin,
};

export default charts2;
