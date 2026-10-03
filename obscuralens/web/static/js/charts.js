/**
 * ObscuraLens web UI — zero-dependency canvas chart library.
 *
 * Six chart primitives (line, donut, bars, sparkline, heatmap, scatter) plus
 * a DOM legend builder, all rendered on raw <canvas> elements with:
 *
 *   - devicePixelRatio-aware output (crisp on retina displays),
 *   - automatic redraw when the canvas' parent resizes (ResizeObserver,
 *     cleanup handle stored on `canvas.__olResize`),
 *   - colours read from the CSS custom-property palette on every draw, so
 *     theme switches recolour charts without re-instantiating anything,
 *   - optional hover tooltips (`.chart-tip`) with per-chart-type hit testing,
 *   - empty-data and NaN-safe guards everywhere (no NaN axes, no explosions).
 *
 * The module never touches the DOM at import time — every bit of DOM work
 * happens inside the chart functions, so it imports cleanly headlessly.
 *
 * Specs are plain objects; see each chart function below for the exact shape.
 */

/* ---------------------------------------------------------------------- */
/* Theme / colour utilities                                                */
/* ---------------------------------------------------------------------- */

/** Fallbacks mirroring base.css dark-theme tokens (used when CSS is missing). */
const FALLBACK = {
  palette: ['#2dd4a7', '#f5a524', '#b58cff', '#4cc3ff',
    '#f2637a', '#8fd15f', '#e8965a', '#5fb0c9'],
  grid: 'rgba(139, 149, 167, 0.14)',
  axis: '#5d6879',
  panel2: '#151d2a',
  accent: '#2dd4a7',
  bg: '#0a0e14',
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
 * @returns {{palette: string[], grid: string, axis: string,
 *            panel2: string, accent: string, bg: string}}
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
    accent: cssVar('--accent', FALLBACK.accent),
    bg: cssVar('--bg', FALLBACK.bg),
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
 * Understands #rgb/#rrggbb/#rrggbbaa, rgb(), rgba() and (through canvas
 * normalisation) named colours.
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
 * Convert a hex colour to an `rgba(...)` string with the given alpha.
 *
 * @param {string} hex `#rgb`, `#rrggbb` or `#rrggbbaa`.
 * @param {number} alpha Replacement alpha (0..1).
 * @returns {string}
 */
function hexToRgba(hex, alpha) {
  const p = parseColor(hex);
  if (!p) return `rgba(45, 212, 167, ${alpha})`;
  return `rgba(${Math.round(p[0])}, ${Math.round(p[1])}, ${Math.round(p[2])}, ${alpha})`;
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
    // kill float dust like 0.30000000000000004
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

/* ---------------------------------------------------------------------- */
/* Canvas plumbing: DPR setup, resize observation, events, tooltip         */
/* ---------------------------------------------------------------------- */

/**
 * Size a canvas for device pixels and return a DPR-scaled context.
 * Legitimate CSS sizes are honoured at any height (sparklines are 28 px);
 * degenerate/unsized canvases fall back to sane defaults.
 *
 * @param {HTMLCanvasElement} canvas
 * @returns {{ctx: CanvasRenderingContext2D, w: number, h: number, dpr: number}}
 */
function setup(canvas) {
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
 * Ensure a `.chart-tip` tooltip div exists inside the canvas' parent
 * (made `position: relative` when static).
 *
 * @param {HTMLCanvasElement} canvas
 * @returns {HTMLElement|null}
 */
function ensureTip(canvas) {
  const parent = canvas.parentElement;
  if (!parent) return null;
  if (getComputedStyle(parent).position === 'static') {
    parent.style.position = 'relative';
  }
  for (const child of parent.children) {
    if (child.classList?.contains('chart-tip')) return child;
  }
  const tip = document.createElement('div');
  tip.className = 'chart-tip';
  parent.append(tip);
  return tip;
}

/**
 * Show the tooltip at CSS-pixel coordinates with label/value rows.
 *
 * @param {HTMLElement} tip
 * @param {number} x
 * @param {number} y
 * @param {Array<[string, string]>} rows
 * @param {number} w Canvas CSS width (for clamping).
 */
function showTip(tip, x, y, rows, w) {
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

/**
 * Hide the tooltip.
 *
 * @param {HTMLElement} tip
 */
function hideTip(tip) {
  tip?.classList.remove('visible');
}

/* ---------------------------------------------------------------------- */
/* Shared drawing helpers                                                  */
/* ---------------------------------------------------------------------- */

/** Font shorthand used for all chart text (11px UI sans by default). */
const AXIS_FONT = '10.5px var(--font-ui, sans-serif)';
const MONO_FONT = '10.5px var(--font-mono, monospace)';

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
  ctx.font = `500 12px var(--font-ui, sans-serif)`;
  ctx.fillStyle = cssVar('--text-faint', '#5d6879');
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, Math.round(w / 2), Math.round(h / 2));
  ctx.restore();
}

/**
 * Path a rounded rectangle (all corners).
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {number} x
 * @param {number} y
 * @param {number} w
 * @param {number} h
 * @param {number} r Corner radius.
 */
function roundRect(ctx, x, y, w, h, r) {
  const rad = Math.max(0, Math.min(r, w / 2, h / 2));
  ctx.beginPath();
  ctx.moveTo(x + rad, y);
  ctx.arcTo(x + w, y, x + w, y + h, rad);
  ctx.arcTo(x + w, y + h, x, y + h, rad);
  ctx.arcTo(x, y + h, x, y, rad);
  ctx.arcTo(x, y, x + w, y, rad);
  ctx.closePath();
}

/**
 * Path a rectangle with only the top corners rounded (bar tops).
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {number} x
 * @param {number} y
 * @param {number} w
 * @param {number} h  Positive height; the flat edge sits at `y + h`.
 * @param {number} r
 */
function roundTopRect(ctx, x, y, w, h, r) {
  const rad = Math.max(0, Math.min(r, w / 2, Math.abs(h) / 2));
  ctx.beginPath();
  ctx.moveTo(x, y + h);
  ctx.lineTo(x, y + rad);
  ctx.arcTo(x, y, x + rad, y, rad);
  ctx.lineTo(x + w - rad, y);
  ctx.arcTo(x + w, y, x + w, y + rad, rad);
  ctx.lineTo(x + w, y + h);
  ctx.closePath();
}

/* ---------------------------------------------------------------------- */
/* Line chart                                                              */
/* ---------------------------------------------------------------------- */

/**
 * Draw a multi-series line chart with auto-scaled axes.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   series: [{label?: string, color?: string, points: [[x, y], ...]}],
 *   yTicks?: number,             // desired tick count (default 5)
 *   xLabels?: string[],          // labels spread evenly over the x domain
 *   yFormat?: (n) => string,     // default compact (1.2k style)
 *   fill?: boolean,              // soft area fill under lines (alpha 0.12)
 *   interactive?: boolean,       // hover tooltip + nearest-point marker
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function line(canvas, spec = {}) {
  let hover = null; // {si: number, pi: number}
  let geom = null;  // scales + cleaned series for hit testing

  const cleaned = () => (Array.isArray(spec.series) ? spec.series : [])
    .map((s, i) => ({
      label: s?.label ?? `series ${i + 1}`,
      color: s?.color,
      pts: (Array.isArray(s?.points) ? s.points : []).filter(
        (p) => Array.isArray(p) && Number.isFinite(+p[0]) && Number.isFinite(+p[1])),
    }));

  function draw() {
    const { ctx, w, h } = setup(canvas);
    const T = theme();
    ctx.clearRect(0, 0, w, h);
    drawTitle(ctx, spec.title);
    const series = cleaned();
    const all = series.flatMap((s) => s.pts);
    if (!all.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }

    let xmin = Infinity; let xmax = -Infinity;
    let ymin = Infinity; let ymax = -Infinity;
    for (const [x, y] of all) {
      if (x < xmin) xmin = x;
      if (x > xmax) xmax = x;
      if (y < ymin) ymin = y;
      if (y > ymax) ymax = y;
    }
    if (xmax === xmin) xmax = xmin + 1;
    if (ymax === ymin) { ymax += 0.5; ymin -= 0.5; }

    const padL = 48;
    const padR = 14;
    const padT = spec.title ? 28 : 12;
    const padB = 34;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const yticks = niceTicks(ymin, ymax, spec.yTicks ?? 5);
    const yFormat = typeof spec.yFormat === 'function' ? spec.yFormat : fmtCompact;
    const sx = (v) => padL + ((v - xmin) / (xmax - xmin)) * pw;
    const sy = (v) => padT + ph - ((v - yticks.lo) / (yticks.hi - yticks.lo)) * ph;
    geom = { series, sx, sy, padL, padT, pw, ph, w, h, xmin, xmax };

    // dashed gridlines + y tick labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (const t of yticks.ticks) {
      const y = Math.round(sy(t)) + 0.5;
      ctx.strokeStyle = T.grid;
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();
      ctx.fillStyle = T.axis;
      ctx.fillText(yFormat(t), padL - 8, y);
    }
    ctx.restore();

    // x labels (rotated -30° when more than six)
    const xLabels = Array.isArray(spec.xLabels) ? spec.xLabels.map(String) : null;
    const labelCount = xLabels ? xLabels.length : Math.min(6, Math.max(2, Math.floor(pw / 60)));
    const rotate = labelCount > 6;
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.fillStyle = T.axis;
    ctx.textBaseline = 'top';
    for (let i = 0; i < labelCount; i += 1) {
      const frac = labelCount === 1 ? 0.5 : i / (labelCount - 1);
      const lx = padL + frac * pw;
      const ly = padT + ph + 8;
      let text;
      if (xLabels) text = xLabels[Math.round(frac * (xLabels.length - 1))] ?? '';
      else text = yFormat(xmin + frac * (xmax - xmin));
      if (!text) continue;
      ctx.save();
      ctx.translate(lx, ly);
      if (rotate) {
        ctx.rotate(-Math.PI / 6);
        ctx.textAlign = 'right';
        ctx.fillText(text, 0, 0);
      } else {
        ctx.textAlign = 'center';
        ctx.fillText(text, 0, 0);
      }
      ctx.restore();
    }
    ctx.restore();

    // x baseline
    ctx.save();
    ctx.strokeStyle = cssVar('--line-strong', '#2b3648');
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padL, padT + ph + 0.5);
    ctx.lineTo(w - padR, padT + ph + 0.5);
    ctx.stroke();
    ctx.restore();

    // series (area fill first, then the stroke on top)
    series.forEach((s, si) => {
      if (!s.pts.length) return;
      const color = s.color ?? T.palette[si % T.palette.length];
      if (spec.fill === true) {
        ctx.save();
        ctx.beginPath();
        s.pts.forEach(([x, y], i) => {
          const px = sx(x); const py = sy(y);
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        });
        ctx.lineTo(sx(s.pts[s.pts.length - 1][0]), padT + ph);
        ctx.lineTo(sx(s.pts[0][0]), padT + ph);
        ctx.closePath();
        ctx.fillStyle = withAlpha(color, 0.12);
        ctx.fill();
        ctx.restore();
      }
      ctx.save();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.beginPath();
      s.pts.forEach(([x, y], i) => {
        const px = sx(x); const py = sy(y);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      });
      ctx.stroke();
      ctx.restore();
    });

    // hover marker
    if (hover && geom) {
      const s = geom.series[hover.si];
      const p = s?.pts[hover.pi];
      if (p) {
        const px = geom.sx(p[0]);
        const py = geom.sy(p[1]);
        ctx.save();
        ctx.fillStyle = T.bg;
        ctx.strokeStyle = s.color ?? T.palette[0];
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(px, py, 4.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.restore();
      }
    }
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = ensureTip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      let best = null;
      geom.series.forEach((s, si) => {
        s.pts.forEach((p, pi) => {
          const dx = geom.sx(p[0]) - mx;
          const dy = geom.sy(p[1]) - my;
          const d2 = dx * dx + dy * dy;
          if (d2 <= 22 * 22 && (!best || d2 < best.d2)) best = { si, pi, d2, p, s };
        });
      });
      if (!best) {
        if (hover) { hover = null; draw(); }
        hideTip(tip);
        return;
      }
      hover = { si: best.si, pi: best.pi };
      draw();
      const xLabels = Array.isArray(spec.xLabels) ? spec.xLabels : null;
      const xText = xLabels
        ? (xLabels[Math.round(best.p[0] - geom.xmin)] ?? fmtCompact(best.p[0]))
        : fmtCompact(best.p[0]);
      showTip(tip, geom.sx(best.p[0]), geom.sy(best.p[1]), [
        [best.s.label, `${xText} · ${fmtCompact(best.p[1])}`],
      ], geom.w);
    }, () => {
      hover = null;
      hideTip(tip);
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
/* Donut chart                                                             */
/* ---------------------------------------------------------------------- */

/**
 * Draw a donut/ring chart.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   slices: [{label: string, value: number, color?: string}],
 *   center?: {label?: string, value?: string|number},
 *   thickness?: number,          // ring thickness in px (default 22)
 *   interactive?: boolean,       // hover expands slice + tooltip
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function donut(canvas, spec = {}) {
  let hover = -1;
  let geom = null;
  const thickness = Math.max(6, Number(spec.thickness) || 22);

  const slices = () => (Array.isArray(spec.slices) ? spec.slices : [])
    .map((s) => ({ ...s, value: Number(s?.value) || 0 }))
    .filter((s) => s.value > 0);

  function draw() {
    const { ctx, w, h } = setup(canvas);
    const T = theme();
    ctx.clearRect(0, 0, w, h);
    drawTitle(ctx, spec.title);
    const data = slices();
    const total = data.reduce((acc, s) => acc + s.value, 0);
    if (!data.length || total <= 0) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }

    const cx = w / 2;
    const cy = h / 2 + (spec.title ? 6 : 0);
    const outer = Math.max(24, Math.min(w, h) / 2 - (spec.title ? 26 : 10));
    const r = Math.max(8, outer - thickness / 2 - 2);
    const gap = r > 24 ? 2 / r : 0; // ~2px angular gap between slices

    const TAU = Math.PI * 2;
    const norm = (x) => ((x % TAU) + TAU) % TAU;
    let ang = -Math.PI / 2;
    const spans = [];
    data.forEach((s, i) => {
      const span = (s.value / total) * TAU;
      spans.push({ start: norm(ang), end: norm(ang + span) });
      const rr = r + (i === hover ? 4 : 0);
      ctx.save();
      ctx.strokeStyle = s.color ?? T.palette[i % T.palette.length];
      ctx.lineWidth = thickness;
      ctx.lineCap = 'butt';
      ctx.beginPath();
      ctx.arc(cx, cy, rr, ang + gap / 2, ang + span - gap / 2);
      ctx.stroke();
      ctx.restore();
      ang += span;
    });
    geom = { cx, cy, r, thickness, spans, total, w, h };

    // center text: big value + small label
    const center = spec.center ?? {};
    const bigValue = center.value !== undefined && center.value !== null
      ? String(center.value) : fmtCompact(total);
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = cssVar('--text-strong', '#f2f6fa');
    ctx.font = '700 21px var(--font-mono, monospace)';
    ctx.fillText(bigValue, cx, cy - 5);
    if (center.label) {
      ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
      ctx.font = `600 ${AXIS_FONT}`;
      ctx.fillText(String(center.label).toUpperCase(), cx, cy + 13);
    }
    ctx.restore();
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = ensureTip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      const dx = mx - geom.cx;
      const dy = my - geom.cy;
      const dist = Math.hypot(dx, dy);
      let idx = -1;
      if (Math.abs(dist - geom.r) <= geom.thickness / 2 + 6) {
        const a = norm(Math.atan2(dy, dx));
        idx = geom.spans.findIndex((s) => (s.start <= s.end
          ? a >= s.start && a < s.end
          : a >= s.start || a < s.end));
      }
      if (idx !== hover) { hover = idx; draw(); }
      if (idx >= 0) {
        const s = slices()[idx];
        const pct = geom.total ? Math.round((s.value / geom.total) * 1000) / 10 : 0;
        showTip(tip, mx, my, [[s.label, `${fmtCompact(s.value)} · ${pct}%`]], geom.w);
      } else {
        hideTip(tip);
      }
    }, () => {
      hover = -1;
      hideTip(tip);
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
/* Bar chart (vertical + horizontal)                                       */
/* ---------------------------------------------------------------------- */

/**
 * Draw a bar chart, vertical by default.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   bars: [{label: string, value: number, color?: string}],
 *   horizontal?: boolean,
 *   valueFormat?: (n) => string,   // default compact
 *   interactive?: boolean,
 * }
 * ```
 *
 * @param {HTMLCanvasElement} canvas
 * @param {object} spec
 * @returns {{update: (next: object) => void}}
 */
function bars(canvas, spec = {}) {
  let hover = -1;
  let geom = null;
  const valueFormat = (v) => (typeof spec.valueFormat === 'function'
    ? spec.valueFormat(v) : fmtCompact(v));

  const data = () => (Array.isArray(spec.bars) ? spec.bars : [])
    .map((b) => ({ ...b, value: Number(b?.value) || 0 }))
    .filter((b) => Number.isFinite(b.value));

  function draw() {
    const { ctx, w, h } = setup(canvas);
    const T = theme();
    ctx.clearRect(0, 0, w, h);
    drawTitle(ctx, spec.title);
    const items = data();
    if (!items.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }

    const horizontal = spec.horizontal === true;
    const n = items.length;
    const minV = Math.min(0, ...items.map((b) => b.value));
    const maxV = Math.max(0, ...items.map((b) => b.value));
    const ticks = niceTicks(minV, maxV, 5);

    if (horizontal) {
      const labelW = Math.min(150, Math.max(...items.map(
        (b) => String(b.label ?? '').length)) * 6.2 + 8);
      const padL = labelW + 10;
      const padR = 46;
      const padT = spec.title ? 26 : 10;
      const padB = 26;
      const pw = w - padL - padR;
      const ph = h - padT - padB;
      const rowH = ph / n;
      const barH = Math.max(4, rowH * 0.62);
      const sv = (v) => padL + ((v - ticks.lo) / (ticks.hi - ticks.lo)) * pw;
      geom = { horizontal: true, items, padL, padT, rowH, ph, pw, sv, w, h, n };

      // vertical gridlines + bottom tick labels
      ctx.save();
      ctx.font = AXIS_FONT;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.strokeStyle = T.grid;
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1;
      ctx.fillStyle = T.axis;
      for (const t of ticks.ticks) {
        const x = Math.round(sv(t)) + 0.5;
        ctx.beginPath();
        ctx.moveTo(x, padT);
        ctx.lineTo(x, padT + ph);
        ctx.stroke();
        ctx.fillText(fmtCompact(t), x, padT + ph + 6);
      }
      ctx.restore();

      // baseline
      ctx.save();
      ctx.strokeStyle = cssVar('--line-strong', '#2b3648');
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(Math.round(sv(0)) + 0.5, padT);
      ctx.lineTo(Math.round(sv(0)) + 0.5, padT + ph);
      ctx.stroke();
      ctx.restore();

      items.forEach((b, i) => {
        const y = padT + rowH * (i + 0.5) - barH / 2;
        const x0 = Math.min(sv(0), sv(b.value));
        const x1 = Math.max(sv(0), sv(b.value));
        const bw = Math.max(1, x1 - x0);
        const color = b.color ?? T.palette[i % T.palette.length];
        ctx.save();
        ctx.fillStyle = i === hover ? withAlpha(color, 1) : withAlpha(color, 0.82);
        roundRect(ctx, x0, y, bw, barH, 3);
        ctx.fill();
        if (i === hover) {
          ctx.strokeStyle = color;
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }
        ctx.restore();
        // row label
        ctx.save();
        ctx.font = AXIS_FONT;
        ctx.fillStyle = i === hover ? cssVar('--text-strong', '#f2f6fa') : T.axis;
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        let label = String(b.label ?? '');
        if (label.length > 18) label = `${label.slice(0, 16)}…`;
        ctx.fillText(label, padL - 12, y + barH / 2);
        // value at the end of the bar
        ctx.textAlign = 'left';
        ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
        ctx.fillText(valueFormat(b.value), x1 + 6, y + barH / 2);
        ctx.restore();
      });
      return;
    }

    // ---- vertical ----
    const padL = 48;
    const padR = 12;
    const padT = spec.title ? 28 : 14;
    const padB = 34;
    const pw = w - padL - padR;
    const ph = h - padT - padB;
    const colW = pw / n;
    const barW = Math.max(2, colW * 0.68);
    const sv = (v) => padT + ph - ((v - ticks.lo) / (ticks.hi - ticks.lo)) * ph;
    geom = { horizontal: false, items, padL, padT, colW, pw, ph, sv, w, h, n };

    // horizontal gridlines + y labels
    ctx.save();
    ctx.font = AXIS_FONT;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (const t of ticks.ticks) {
      const y = Math.round(sv(t)) + 0.5;
      ctx.strokeStyle = T.grid;
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(w - padR, y);
      ctx.stroke();
      ctx.fillStyle = T.axis;
      ctx.fillText(fmtCompact(t), padL - 8, y);
    }
    ctx.restore();

    // baseline at zero
    ctx.save();
    ctx.strokeStyle = cssVar('--line-strong', '#2b3648');
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padL, Math.round(sv(0)) + 0.5);
    ctx.lineTo(w - padR, Math.round(sv(0)) + 0.5);
    ctx.stroke();
    ctx.restore();

    const rotateLabels = n > 8;
    items.forEach((b, i) => {
      const cxBar = padL + colW * (i + 0.5);
      const y0 = Math.min(sv(0), sv(b.value));
      const y1 = Math.max(sv(0), sv(b.value));
      const bh = Math.max(1, y1 - y0);
      const color = b.color ?? T.palette[i % T.palette.length];
      ctx.save();
      ctx.fillStyle = i === hover ? withAlpha(color, 1) : withAlpha(color, 0.82);
      roundTopRect(ctx, cxBar - barW / 2, y0, barW, bh, 3);
      ctx.fill();
      if (i === hover) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
      ctx.restore();

      // value label above the bar (≤12 bars)
      if (n <= 12) {
        ctx.save();
        ctx.font = `600 ${AXIS_FONT}`;
        ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(valueFormat(b.value), cxBar, y0 - 3);
        ctx.restore();
      }

      // x label
      ctx.save();
      ctx.font = AXIS_FONT;
      ctx.fillStyle = i === hover ? cssVar('--text-strong', '#f2f6fa') : T.axis;
      let label = String(b.label ?? '');
      const maxChars = rotateLabels ? 12 : 16;
      if (label.length > maxChars) label = `${label.slice(0, maxChars - 1)}…`;
      ctx.translate(cxBar, padT + ph + 8);
      if (rotateLabels) {
        ctx.rotate(-Math.PI / 6);
        ctx.textAlign = 'right';
        ctx.textBaseline = 'top';
      } else {
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
      }
      ctx.fillText(label, 0, 0);
      ctx.restore();
    });
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = ensureTip(canvas);
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      let idx = -1;
      if (geom.horizontal) {
        idx = Math.floor((my - geom.padT) / geom.rowH);
      } else {
        idx = Math.floor((mx - geom.padL) / geom.colW);
      }
      if (idx < 0 || idx >= geom.n) idx = -1;
      if (idx !== hover) { hover = idx; draw(); }
      if (idx >= 0) {
        const b = geom.items[idx];
        showTip(tip, mx, my, [[b.label, valueFormat(b.value)]], geom.w);
      } else {
        hideTip(tip);
      }
    }, () => {
      hover = -1;
      hideTip(tip);
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
 * Draw a tiny trend line — no axes, optional area fill, glowing last dot.
 *
 * @param {HTMLCanvasElement} canvas
 * @param {Array<number>} values
 * @param {{color?: string, fill?: boolean, height?: number}} [opts]
 * @returns {{update: (values: number[]) => void}}
 */
function sparkline(canvas, values, opts = {}) {
  if (opts.height) canvas.style.height = `${Number(opts.height) || 28}px`;

  function draw() {
    const { ctx, w, h } = setup(canvas);
    const T = theme();
    ctx.clearRect(0, 0, w, h);
    const vals = (Array.isArray(values) ? values : [])
      .map(Number).filter(Number.isFinite);
    if (vals.length < 2) {
      drawEmpty(ctx, w, h, vals.length ? '—' : 'no data');
      return;
    }
    const color = opts.color ?? T.palette[0];
    const pad = 3;
    let vmin = Math.min(...vals);
    let vmax = Math.max(...vals);
    if (vmax === vmin) { vmax += 0.5; vmin -= 0.5; }
    const sx = (i) => pad + (i / (vals.length - 1)) * (w - pad * 2);
    const sy = (v) => pad + (1 - (v - vmin) / (vmax - vmin)) * (h - pad * 2);

    if (opts.fill !== false) {
      ctx.save();
      ctx.beginPath();
      vals.forEach((v, i) => {
        if (i === 0) ctx.moveTo(sx(i), sy(v));
        else ctx.lineTo(sx(i), sy(v));
      });
      ctx.lineTo(sx(vals.length - 1), h - pad);
      ctx.lineTo(sx(0), h - pad);
      ctx.closePath();
      ctx.fillStyle = withAlpha(color, 0.12);
      ctx.fill();
      ctx.restore();
    }

    ctx.save();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.beginPath();
    vals.forEach((v, i) => {
      if (i === 0) ctx.moveTo(sx(i), sy(v));
      else ctx.lineTo(sx(i), sy(v));
    });
    ctx.stroke();
    ctx.restore();

    // last point: dot + soft glow
    const lx = sx(vals.length - 1);
    const ly = sy(vals[vals.length - 1]);
    ctx.save();
    ctx.shadowColor = color;
    ctx.shadowBlur = 7;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(lx, ly, 2.4, 0, Math.PI * 2);
    ctx.fill();
    ctx.fill(); // double fill intensifies the glow core
    ctx.restore();
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  return {
    /** Replace the values and redraw. */
    update(next) {
      values = next;
      draw();
    },
  };
}

/* ---------------------------------------------------------------------- */
/* Heatmap                                                                 */
/* ---------------------------------------------------------------------- */

/**
 * Draw a labelled heatmap (rounded cells, interpolated colours).
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   matrix: number[][],                  // rows × cols
 *   rowLabels?: string[], colLabels?: string[],
 *   colorLow?: string, colorHigh?: string,   // defaults --panel-2 → --accent
 *   format?: (n) => string,
 *   interactive?: boolean,
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

  const matrix = () => {
    const m = Array.isArray(spec.matrix) ? spec.matrix : [];
    return m.map((row) => (Array.isArray(row) ? row.map(Number) : [])).filter(
      (row) => row.length);
  };

  function draw() {
    const { ctx, w, h } = setup(canvas);
    const T = theme();
    ctx.clearRect(0, 0, w, h);
    drawTitle(ctx, spec.title);
    const m = matrix();
    if (!m.length || !m[0].length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }

    const rows = m.length;
    const cols = m[0].length;
    const rowLabels = (Array.isArray(spec.rowLabels) ? spec.rowLabels : [])
      .map(String).slice(0, rows);
    const colLabels = (Array.isArray(spec.colLabels) ? spec.colLabels : [])
      .map(String).slice(0, cols);
    const low = spec.colorLow ?? T.panel2;
    const high = spec.colorHigh ?? T.accent;

    let vmin = Infinity; let vmax = -Infinity;
    for (const row of m) {
      for (const v of row) {
        if (!Number.isFinite(v)) continue;
        if (v < vmin) vmin = v;
        if (v > vmax) vmax = v;
      }
    }
    if (!Number.isFinite(vmin)) { vmin = 0; vmax = 1; }
    if (vmax === vmin) vmax = vmin + 1;

    const rotateCols = colLabels.length > 10;
    const rowLabW = Math.min(96, Math.max(24,
      ...(rowLabels.length ? rowLabels.map((l) => l.length * 6.4 + 8) : [24])));
    const colLabH = rotateCols ? 52 : 22;
    const padT = (spec.title ? 26 : 8) + colLabH;
    const padB = 6;
    const padL = rowLabW + 6;
    const padR = 6;
    const gw = Math.max(10, w - padL - padR);
    const gh = Math.max(10, h - padT - padB);
    const cw = gw / cols;
    const ch = gh / rows;
    geom = { m, rows, cols, padL, padT, cw, ch, rowLabels, colLabels, w, h };

    // cells
    const gap = Math.min(2, cw * 0.18, ch * 0.18);
    for (let r = 0; r < rows; r += 1) {
      for (let c = 0; c < cols; c += 1) {
        const v = m[r][c];
        const x = padL + c * cw;
        const y = padT + r * ch;
        const t = Number.isFinite(v) ? (v - vmin) / (vmax - vmin) : 0;
        ctx.fillStyle = interpolate(low, high, Math.max(0, Math.min(1, t)));
        roundRect(ctx, x + gap / 2, y + gap / 2, Math.max(1, cw - gap),
          Math.max(1, ch - gap), 3);
        ctx.fill();
        if (hover && hover.r === r && hover.c === c) {
          ctx.strokeStyle = cssVar('--text-strong', '#f2f6fa');
          ctx.lineWidth = 1.4;
          ctx.stroke();
        }
      }
    }

    // row labels (left gutter, right aligned)
    ctx.save();
    ctx.font = `10px var(--font-mono, monospace)`;
    ctx.fillStyle = T.axis;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let r = 0; r < rows; r += 1) {
      if (!rowLabels[r]) continue;
      let label = rowLabels[r];
      if (label.length > 12) label = `${label.slice(0, 11)}…`;
      ctx.fillText(label, padL - 10, padT + r * ch + ch / 2);
    }
    ctx.restore();

    // column labels (top gutter; rotated when crowded)
    ctx.save();
    ctx.font = `10px var(--font-mono, monospace)`;
    ctx.fillStyle = T.axis;
    for (let c = 0; c < cols; c += 1) {
      if (!colLabels[c]) continue;
      const x = padL + c * cw + cw / 2;
      if (rotateCols) {
        ctx.save();
        ctx.translate(x, padT - 6);
        ctx.rotate(-Math.PI / 3.2);
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText(colLabels[c], 0, 0);
        ctx.restore();
      } else {
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(colLabels[c], x, padT - 5);
      }
    }
    ctx.restore();
  }

  draw();
  canvas.__olDraw = draw;
  observeResize(canvas);

  if (spec.interactive === true) {
    const tip = ensureTip(canvas);
    const format = typeof spec.format === 'function' ? spec.format : fmtCompact;
    bindEvents(canvas, (ev) => {
      if (!geom) return;
      const rect = canvas.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;
      const c = Math.floor((mx - geom.padL) / geom.cw);
      const r = Math.floor((my - geom.padT) / geom.ch);
      const inside = c >= 0 && c < geom.cols && r >= 0 && r < geom.rows;
      const next = inside ? { r, c } : null;
      if ((next?.r !== hover?.r) || (next?.c !== hover?.c)
        || (!next && hover)) {
        hover = next;
        draw();
      }
      if (hover) {
        const value = geom.m[hover.r][hover.c];
        showTip(tip, mx, my, [
          [geom.rowLabels[hover.r] ?? `row ${hover.r}`,
            `${geom.colLabels[hover.c] ?? `col ${hover.c}`} · ${format(Number.isFinite(value) ? value : 0)}`],
        ], geom.w);
      } else {
        hideTip(tip);
      }
    }, () => {
      hover = null;
      hideTip(tip);
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
/* Scatter                                                                 */
/* ---------------------------------------------------------------------- */

/**
 * Draw a labelled scatter plot with auto-scaled axes.
 *
 * Spec:
 * ```
 * {
 *   title?: string,
 *   points: [{x: number, y: number, label?: string, color?: string, size?: number}],
 *   xLabel?: string, yLabel?: string,
 *   interactive?: boolean,
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
    .map((p, i) => ({
      x: +p.x, y: +p.y,
      label: p.label ? String(p.label) : `#${i + 1}`,
      color: p.color,
      size: Math.max(2, Number(p.size) || 4),
    }));

  function draw() {
    const { ctx, w, h } = setup(canvas);
    const T = theme();
    ctx.clearRect(0, 0, w, h);
    drawTitle(ctx, spec.title);
    const pts = points();
    if (!pts.length) {
      geom = null;
      drawEmpty(ctx, w, h);
      return;
    }

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

    // points
    pts.forEach((p, i) => {
      const px = sx(p.x);
      const py = sy(p.y);
      const color = p.color ?? T.palette[i % T.palette.length];
      ctx.save();
      if (i === hover) {
        ctx.shadowColor = color;
        ctx.shadowBlur = 9;
      }
      ctx.fillStyle = withAlpha(color, i === hover ? 1 : 0.85);
      ctx.beginPath();
      ctx.arc(px, py, i === hover ? p.size + 2 : p.size, 0, Math.PI * 2);
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
    const tip = ensureTip(canvas);
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
        showTip(tip, geom.sx(p.x), geom.sy(p.y), [
          [p.label, `${fmtCompact(p.x)} , ${fmtCompact(p.y)}`],
        ], geom.w);
      } else {
        hideTip(tip);
      }
    }, () => {
      hover = -1;
      hideTip(tip);
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
/* DOM legend                                                              */
/* ---------------------------------------------------------------------- */

/**
 * Build a `.chart-legend` DOM list inside `container` (previous legends we
 * created there are removed first).
 *
 * @param {HTMLElement} container
 * @param {Array<{label: string, color?: string, value?: number|string,
 *   pct?: number}>} items
 * @returns {HTMLElement|null}
 */
function legend(container, items) {
  if (!container || typeof container.append !== 'function') return null;
  for (const child of [...container.querySelectorAll(':scope > .chart-legend')]) {
    child.remove();
  }
  const data = (Array.isArray(items) ? items : []).filter(
    (i) => i && i.label !== undefined);
  const total = data.reduce((acc, i) => acc + (Number(i.value) || 0), 0);
  const node = document.createElement('div');
  node.className = 'chart-legend';
  const T = theme();
  data.forEach((item, i) => {
    const row = document.createElement('span');
    row.className = 'chart-legend-item';
    const swatch = document.createElement('span');
    swatch.className = 'chart-legend-swatch';
    swatch.style.background = item.color ?? T.palette[i % T.palette.length];
    const label = document.createElement('span');
    label.textContent = String(item.label);
    row.append(swatch, label);
    if (item.value !== undefined && item.value !== null) {
      const value = document.createElement('span');
      value.className = 'chart-legend-value';
      const v = Number(item.value);
      const pct = item.pct ?? (total > 0 && Number.isFinite(v)
        ? Math.round((v / total) * 100) : null);
      value.textContent = `${fmtCompact(v)}${pct !== null ? ` · ${pct}%` : ''}`;
      row.append(value);
    }
    node.append(row);
  });
  if (!data.length) {
    const empty = document.createElement('span');
    empty.className = 'chart-legend-item';
    empty.textContent = 'no data';
    node.append(empty);
  }
  container.append(node);
  return node;
}

/* ---------------------------------------------------------------------- */
/* Public API                                                              */
/* ---------------------------------------------------------------------- */

/** Chart library facade — see module docstring for behaviours. */
export const charts = {
  line,
  donut,
  bars,
  sparkline,
  heatmap,
  scatter,
  legend,
};

export default charts;
