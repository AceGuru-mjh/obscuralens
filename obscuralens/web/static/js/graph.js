/**
 * ObscuraLens web UI — force-directed entity graph engine (canvas, no libs).
 *
 * `createGraph(container)` mounts an interactive investigation graph inside
 * a `.graph-wrap` element and returns a small controller:
 *
 * ```js
 * const g = createGraph(wrapEl);
 * g.setData({ nodes: [{id, label, kind, size?, meta?}],
 *             links: [{source, target, label?}] });
 * g.onSelect(node => …).ondblclick(node => …);
 * g.focus(id); g.reset(); g.exportPNG(); g.destroy();
 * ```
 *
 * Physics (plain O(n²), fine for ≤ 400 nodes):
 *   - pairwise repulsion with distance cutoff and force clamping,
 *   - spring attraction along links (rest length ~110 px, stiffness 1/degree),
 *   - weak gravity toward the world origin,
 *   - velocity damping 0.85, clamped speeds — nodes never explode,
 *   - d3-style `alpha` cooling (1 → 0.02 over ~300 ticks, reheated by drags
 *     and data changes); the rAF loop stops when the system settles.
 *
 * Rendering: kind-coloured circles (--kind-<kind> tokens), labels shown when
 * zoomed in / hovered / dragged, link label chips when zoom > 1.2, accent
 * halo + ring on the selected node, viewport culling for labels.
 *
 * Interactions: pan (drag background), zoom toward cursor (wheel, 0.25–4×),
 * node drag (pinned while held, keeps velocity on release), click →
 * onSelect, double-click → ondblclick, hover tooltip (.graph-node-tip).
 * A toolbar (zoom in/out, reset, PNG export) and a HUD (counts + zoom %)
 * are built into the container.
 *
 * The module touches no DOM at import time.
 */

/* ---------------------------------------------------------------------- */
/* Tunables                                                                */
/* ---------------------------------------------------------------------- */

/** Hard cap on simulated nodes; extras are dropped (noted in the HUD). */
const MAX_NODES = 400;
/** Repulsion strength (k in F = k / d²). */
const REPULSION = 3400;
/** Above this pixel distance, pair repulsion is skipped (perf cutoff). */
const REPULSION_CUTOFF = 800;
/** Single-pair force clamp. */
const MAX_PAIR_FORCE = 14;
/** Link rest length in world px. */
const SPRING_LENGTH = 110;
/** Base spring stiffness (scaled by 1/degree). */
const SPRING_K = 0.055;
/** Minimum spring stiffness (hubs). */
const MIN_SPRING_STRENGTH = 0.12;
/** Centering gravity factor. */
const GRAVITY = 0.035;
/** Velocity damping per tick. */
const DAMPING = 0.85;
/** Speed clamp per tick (px). */
const MAX_SPEED = 26;
/** Below this alpha the simulation freezes. */
const ALPHA_MIN = 0.02;
/** Alpha decay per tick (~300 ticks from 1 to 0). */
const ALPHA_DECAY = 0.014;
/** Alpha set by setData (full reheat). */
const ALPHA_START = 1;
/** Zoom bounds. */
const ZOOM_MIN = 0.25;
const ZOOM_MAX = 4;
/** Physics ticks per animation frame. */
const TICKS_PER_FRAME = 2;
/** Max label characters under a node. */
const LABEL_MAX = 18;
/** Skip link-label chips beyond this many links. */
const CHIP_LINK_LIMIT = 80;

/* ---------------------------------------------------------------------- */
/* Small helpers                                                           */
/* ---------------------------------------------------------------------- */

/**
 * Read a CSS custom property from :root.
 *
 * @param {string} name
 * @param {string} fallback
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
 * Build a small inline stroke SVG icon (24×24 viewBox).
 *
 * @param {string} inner SVG inner markup.
 * @param {number} size
 * @returns {SVGSVGElement}
 */
function svgIcon(inner, size = 16) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', 'icon');
  svg.innerHTML = inner;
  return svg;
}

/** Toolbar icon paths (lucide-style). */
const TOOLBAR_ICONS = {
  plus: '<path d="M12 5v14M5 12h14"/>',
  minus: '<path d="M5 12h14"/>',
  reset: '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
};

/**
 * Create a toolbar icon button.
 *
 * @param {string} iconName
 * @param {string} title
 * @param {function(): void} onClick
 * @returns {HTMLButtonElement}
 */
function toolButton(iconName, title, onClick) {
  const btn = document.createElement('button');
  btn.className = 'icon-btn';
  btn.type = 'button';
  btn.title = title;
  btn.setAttribute('aria-label', title);
  btn.append(svgIcon(TOOLBAR_ICONS[iconName]));
  btn.addEventListener('click', onClick);
  return btn;
}

/**
 * Clamp a number into [lo, hi].
 *
 * @param {number} v
 * @param {number} lo
 * @param {number} hi
 * @returns {number}
 */
function clamp(v, lo, hi) {
  return v < lo ? lo : v > hi ? hi : v;
}

/**
 * Truncate a label for display.
 *
 * @param {string} text
 * @param {number} max
 * @returns {string}
 */
function trunc(text, max = LABEL_MAX) {
  const s = String(text ?? '');
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/* ---------------------------------------------------------------------- */
/* Engine                                                                  */
/* ---------------------------------------------------------------------- */

/**
 * Instantiate a graph inside `container` (a `.graph-wrap` element).
 *
 * @param {HTMLElement} container
 * @param {{onSelect?: function, ondblclick?: function}} [opts]
 * @returns {{setData: function, focus: function, reset: function,
 *   exportPNG: function, destroy: function, onSelect: function,
 *   ondblclick: function}}
 */
export function createGraph(container, opts = {}) {
  if (!container || typeof container.append !== 'function') {
    throw new Error('createGraph: container element required');
  }

  /* ---- DOM scaffold ------------------------------------------------- */

  const canvas = document.createElement('canvas');
  canvas.style.position = 'absolute';
  canvas.style.inset = '0';
  canvas.style.touchAction = 'none';
  container.append(canvas);

  const toolbar = document.createElement('div');
  toolbar.className = 'graph-toolbar';
  container.append(toolbar);

  const hud = document.createElement('div');
  hud.className = 'graph-hud';
  container.append(hud);

  const tip = document.createElement('div');
  tip.className = 'graph-node-tip';
  container.append(tip);

  /* ---- state ---------------------------------------------------------- */

  const state = {
    nodes: [],
    links: [],
    byId: new Map(),
    dropped: 0,
    transform: { x: 0, y: 0, k: 1 },
    alpha: 0,
    running: false,
    raf: 0,
    hovered: null,
    selected: null,
    pointer: null, // {x, y, node|null, moved, lastWorld, pwx, pwy}
    lastSize: { w: 0, h: 0 },
  };
  const callbacks = {
    select: typeof opts.onSelect === 'function' ? [opts.onSelect] : [],
    dblclick: typeof opts.ondblclick === 'function' ? [opts.ondblclick] : [],
  };

  /* ---- sizing ---------------------------------------------------------- */

  /**
   * Resize the backing store to the container (DPR aware) when needed.
   *
   * @returns {{ctx: CanvasRenderingContext2D, w: number, h: number}}
   */
  function resizeCanvas() {
    const dpr = Math.max(1, Math.min(3, window.devicePixelRatio || 1));
    const w = Math.max(40, Math.round(container.clientWidth || 640));
    const h = Math.max(40, Math.round(container.clientHeight || 480));
    const pw = Math.round(w * dpr);
    const ph = Math.round(h * dpr);
    if (canvas.width !== pw || canvas.height !== ph) {
      canvas.width = pw;
      canvas.height = ph;
    }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, w, h };
  }

  /* ---- transform helpers ----------------------------------------------- */

  /**
   * World → screen coordinates.
   *
   * @param {number} x
   * @param {number} y
   * @returns {[number, number]}
   */
  function toScreen(x, y) {
    const t = state.transform;
    return [x * t.k + t.x, y * t.k + t.y];
  }

  /**
   * Screen → world coordinates.
   *
   * @param {number} x
   * @param {number} y
   * @returns {[number, number]}
   */
  function toWorld(x, y) {
    const t = state.transform;
    return [(x - t.x) / t.k, (y - t.y) / t.k];
  }

  /* ---- physics --------------------------------------------------------- */

  /**
   * Advance the simulation by one tick (all forces clamped — no blow-ups).
   */
  function tick() {
    const nodes = state.nodes;
    const n = nodes.length;
    if (!n) return;
    const a = state.alpha;

    // pairwise repulsion (O(n²), distance-cutoff for perf)
    for (let i = 0; i < n; i += 1) {
      const ni = nodes[i];
      for (let j = i + 1; j < n; j += 1) {
        const nj = nodes[j];
        let dx = nj.x - ni.x;
        let dy = nj.y - ni.y;
        let d2 = dx * dx + dy * dy;
        if (d2 > REPULSION_CUTOFF * REPULSION_CUTOFF) continue;
        if (d2 < 0.01) {
          // coincident nodes: deterministic-ish nudge apart
          dx = ((i % 7) - 3) * 0.9 + 0.05;
          dy = ((j % 5) - 2) * 0.9 + 0.05;
          d2 = dx * dx + dy * dy;
        }
        const d = Math.sqrt(d2);
        let f = REPULSION / d2;
        if (f > MAX_PAIR_FORCE) f = MAX_PAIR_FORCE;
        f *= a;
        const ux = dx / d;
        const uy = dy / d;
        ni.vx -= ux * f;
        ni.vy -= uy * f;
        nj.vx += ux * f;
        nj.vy += uy * f;
      }
    }

    // spring attraction along links
    for (const link of state.links) {
      const s = link.source;
      const t = link.target;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const d = Math.hypot(dx, dy) || 0.01;
      const f = (d - SPRING_LENGTH) * SPRING_K * link.strength * a;
      const ux = dx / d;
      const uy = dy / d;
      s.vx += ux * f;
      s.vy += uy * f;
      t.vx -= ux * f;
      t.vy -= uy * f;
    }

    // weak gravity toward the origin + damped integration
    const g = GRAVITY * a;
    for (const node of nodes) {
      node.vx -= node.x * g;
      node.vy -= node.y * g;
      if (node.fixed) {
        node.vx = 0;
        node.vy = 0;
        continue;
      }
      node.vx *= DAMPING;
      node.vy *= DAMPING;
      const speed = Math.hypot(node.vx, node.vy);
      if (speed > MAX_SPEED) {
        node.vx = (node.vx / speed) * MAX_SPEED;
        node.vy = (node.vy / speed) * MAX_SPEED;
      }
      node.x = clamp(node.x + node.vx, -20000, 20000);
      node.y = clamp(node.y + node.vy, -20000, 20000);
    }

    // alpha cooling
    state.alpha += (0 - state.alpha) * ALPHA_DECAY;
    if (state.alpha < ALPHA_MIN) state.alpha = 0;
  }

  /**
   * (Re)start the animation loop.
   *
   * @param {number} [alpha] Minimum alpha to reheat to.
   */
  function reheat(alpha = 0.3) {
    state.alpha = Math.max(state.alpha, alpha);
    if (!state.running) {
      state.running = true;
      state.raf = requestAnimationFrame(loop);
    }
  }

  /** rAF driver: physics ticks + render; halts when settled or detached. */
  function loop() {
    if (!state.running) return;
    if (!canvas.isConnected) {
      state.running = false;
      return;
    }
    if (state.alpha <= 0) {
      state.running = false;
      render();
      updateHud();
      return;
    }
    for (let i = 0; i < TICKS_PER_FRAME; i += 1) tick();
    render();
    state.raf = requestAnimationFrame(loop);
  }

  /* ---- rendering --------------------------------------------------------- */

  /**
   * Node fill colour: --kind-<kind> with --chart-1 fallback.
   *
   * @param {object} node
   * @param {Map<string, string>} cache Per-render colour cache.
   * @returns {string}
   */
  function nodeColor(node, cache) {
    if (cache.has(node.kind)) return cache.get(node.kind);
    const color = cssVar(`--kind-${node.kind}`, '') || cssVar('--chart-1', '#2dd4a7');
    cache.set(node.kind, color);
    return color;
  }

  /** Render the current scene (nodes, links, chips, labels, HUD). */
  function render() {
    const { ctx, w, h } = resizeCanvas();
    state.lastSize = { w, h };
    ctx.clearRect(0, 0, w, h);
    const t = state.transform;
    const k = t.k;
    const colorCache = new Map();

    // ---- links ----
    ctx.save();
    ctx.lineWidth = 1.2;
    ctx.strokeStyle = cssVar('--line-strong', '#2b3648');
    ctx.beginPath();
    for (const link of state.links) {
      const [ax, ay] = toScreen(link.source.x, link.source.y);
      const [bx, by] = toScreen(link.target.x, link.target.y);
      // viewport culling (generous margin)
      if ((ax < -60 && bx < -60) || (ax > w + 60 && bx > w + 60)) continue;
      if ((ay < -60 && by < -60) || (ay > h + 60 && by > h + 60)) continue;
      ctx.moveTo(ax, ay);
      ctx.lineTo(bx, by);
    }
    ctx.stroke();
    ctx.restore();

    // ---- link label chips (only when zoomed in and graph is small) ----
    if (k > 1.2 && state.links.length <= CHIP_LINK_LIMIT) {
      ctx.save();
      ctx.font = '9.5px var(--font-mono, monospace)';
      ctx.textBaseline = 'middle';
      for (const link of state.links) {
        if (!link.label) continue;
        const [ax, ay] = toScreen(link.source.x, link.source.y);
        const [bx, by] = toScreen(link.target.x, link.target.y);
        const cx = (ax + bx) / 2;
        const cy = (ay + by) / 2;
        if (cx < -40 || cx > w + 40 || cy < -20 || cy > h + 20) continue;
        const text = trunc(link.label, 22);
        const tw = ctx.measureText(text).width;
        const padX = 4;
        const boxW = tw + padX * 2;
        const boxH = 13;
        ctx.fillStyle = cssVar('--panel', '#111722');
        ctx.strokeStyle = cssVar('--line', '#1f2937');
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect
          ? ctx.roundRect(cx - boxW / 2, cy - boxH / 2, boxW, boxH, 4)
          : ctx.rect(cx - boxW / 2, cy - boxH / 2, boxW, boxH);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = cssVar('--text-muted', '#8b95a7');
        ctx.textAlign = 'center';
        ctx.fillText(text, cx, cy);
      }
      ctx.restore();
    }

    // ---- nodes ----
    for (const node of state.nodes) {
      const [sx, sy] = toScreen(node.x, node.y);
      const r = clamp((8 + (node.size ?? 0)) * k, 2.5, 42);
      if (sx < -r - 90 || sx > w + r + 90 || sy < -r - 90 || sy > h + r + 90) {
        continue; // culled (label margin included)
      }
      const color = nodeColor(node, colorCache);

      // selection halo + ring
      if (node === state.selected) {
        const halo = ctx.createRadialGradient(sx, sy, r * 0.6, sx, sy, r * 2.4);
        halo.addColorStop(0, 'rgba(45, 212, 167, 0.28)');
        halo.addColorStop(1, 'rgba(45, 212, 167, 0)');
        ctx.fillStyle = halo;
        ctx.beginPath();
        ctx.arc(sx, sy, r * 2.4, 0, Math.PI * 2);
        ctx.fill();
      }

      ctx.save();
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(sx, sy, r, 0, Math.PI * 2);
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = cssVar('--bg', '#0a0e14');
      ctx.stroke();
      if (node === state.selected) {
        ctx.strokeStyle = cssVar('--accent', '#2dd4a7');
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(sx, sy, r + 3.5, 0, Math.PI * 2);
        ctx.stroke();
      } else if (node === state.hovered) {
        ctx.strokeStyle = cssVar('--text-muted', '#8b95a7');
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(sx, sy, r + 2.5, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.restore();

      // label below the node
      const showLabel = k > 0.8 || node === state.hovered
        || node === state.selected || node.fixed;
      if (showLabel) {
        ctx.save();
        ctx.font = '11px var(--font-mono, monospace)';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = node === state.selected
          ? cssVar('--text-strong', '#f2f6fa')
          : cssVar('--text-muted', '#8b95a7');
        ctx.fillText(trunc(node.label || node.id), sx, sy + r + 4);
        ctx.restore();
      }
    }
  }

  /** Refresh the HUD counters (nodes / links / zoom / dropped note). */
  function updateHud() {
    const t = state.transform;
    const parts = [
      `${state.nodes.length} nodes`,
      `${state.links.length} links`,
      `${Math.round(t.k * 100)}%`,
    ];
    if (state.dropped > 0) parts.push(`+${state.dropped} dropped`);
    const text = parts.join('  ·  ');
    if (hud.textContent !== text) hud.textContent = text;
  }

  /* ---- view fitting ------------------------------------------------------ */

  /** Fit all nodes into the viewport (used by setData/reset). */
  function fitView() {
    const w = container.clientWidth || 640;
    const h = container.clientHeight || 480;
    const t = state.transform;
    if (!state.nodes.length) {
      t.k = 1;
      t.x = w / 2;
      t.y = h / 2;
      render();
      updateHud();
      return;
    }
    let minX = Infinity; let maxX = -Infinity;
    let minY = Infinity; let maxY = -Infinity;
    for (const node of state.nodes) {
      if (node.x < minX) minX = node.x;
      if (node.x > maxX) maxX = node.x;
      if (node.y < minY) minY = node.y;
      if (node.y > maxY) maxY = node.y;
    }
    const bw = Math.max(1, maxX - minX);
    const bh = Math.max(1, maxY - minY);
    const k = clamp(Math.min((w - 130) / bw, (h - 130) / bh), ZOOM_MIN, 2.5);
    t.k = k;
    t.x = w / 2 - k * ((minX + maxX) / 2);
    t.y = h / 2 - k * ((minY + maxY) / 2);
    render();
    updateHud();
  }

  /* ---- data --------------------------------------------------------------- */

  /**
   * Replace the dataset (positions of known node ids are preserved so
   * incremental expansions don't explode the layout).
   *
   * @param {{nodes?: Array<{id, label?, kind?, size?, meta?}>,
   *          links?: Array<{source, target, label?}>}} data
   */
  function setData(data = {}) {
    const rawNodes = Array.isArray(data.nodes) ? data.nodes : [];
    const rawLinks = Array.isArray(data.links) ? data.links : [];
    const kept = rawNodes.slice(0, MAX_NODES);
    state.dropped = rawNodes.length - kept.length;

    const prev = state.byId;
    const nodes = kept.map((raw, i) => {
      const id = String(raw?.id ?? `node-${i}`);
      const old = prev.get(id);
      const angle = i * 2.399963229728653; // golden angle spread
      const radius = 30 + 11 * Math.sqrt(i + 1);
      return {
        id,
        label: String(raw?.label ?? id),
        kind: String(raw?.kind ?? 'entity'),
        value: raw?.value ?? raw?.label ?? id,
        meta: raw?.meta ?? null,
        size: Number(raw?.size) || 0,
        degree: 0,
        fixed: false,
        x: old ? old.x : Math.cos(angle) * radius,
        y: old ? old.y : Math.sin(angle) * radius,
        vx: old ? old.vx * 0.4 : 0,
        vy: old ? old.vy * 0.4 : 0,
      };
    });
    state.nodes = nodes;
    state.byId = new Map(nodes.map((node) => [node.id, node]));

    // resolve links (ids or node refs), dedupe, drop dangling
    const links = [];
    const seen = new Set();
    for (const raw of rawLinks) {
      const sid = String(raw?.source ?? '');
      const tid = String(raw?.target ?? '');
      const s = state.byId.get(sid);
      const t = state.byId.get(tid);
      if (!s || !t || s === t) continue;
      const key = `${s.id}\u0000${t.id}\u0000${raw?.label ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      links.push({ source: s, target: t, label: raw?.label ?? '', strength: 1 });
    }
    state.links = links;

    // degrees → spring strength (hubs get weaker springs)
    for (const link of state.links) {
      link.source.degree += 1;
      link.target.degree += 1;
    }
    for (const link of state.links) {
      const d = Math.max(link.source.degree, link.target.degree, 1);
      link.strength = clamp(1 / d, MIN_SPRING_STRENGTH, 1);
    }

    // stale selection/hover refs
    if (state.selected && !state.byId.has(state.selected.id)) state.selected = null;
    if (state.hovered && !state.byId.has(state.hovered.id)) state.hovered = null;

    reheat(ALPHA_START);
    fitView();
  }

  /* ---- selection / callbacks ----------------------------------------------- */

  /**
   * Public copy of an internal node (no physics fields).
   *
   * @param {object} node
   * @returns {object}
   */
  function publicNode(node) {
    if (!node) return null;
    return {
      id: node.id,
      label: node.label,
      kind: node.kind,
      value: node.value,
      meta: node.meta,
    };
  }

  /**
   * Select a node (or null) and notify listeners.
   *
   * @param {object|null} node
   */
  function select(node) {
    state.selected = node;
    render();
    for (const cb of callbacks.select) {
      try {
        cb(publicNode(node));
      } catch (err) {
        console.error('[obscuralens] graph onSelect handler failed:', err);
      }
    }
  }

  /* ---- pointer interactions ----------------------------------------------- */

  /**
   * Local canvas coordinates for a pointer/mouse event.
   *
   * @param {MouseEvent|PointerEvent} ev
   * @returns {[number, number]}
   */
  function localPoint(ev) {
    const rect = canvas.getBoundingClientRect();
    return [ev.clientX - rect.left, ev.clientY - rect.top];
  }

  /**
   * Topmost node under the given screen point (or null).
   *
   * @param {number} mx
   * @param {number} my
   * @returns {object|null}
   */
  function pickNode(mx, my) {
    const [wx, wy] = toWorld(mx, my);
    const slack = 6 / state.transform.k;
    let best = null;
    let bestD2 = Infinity;
    for (const node of state.nodes) {
      const r = 8 + (node.size ?? 0) + slack;
      const dx = node.x - wx;
      const dy = node.y - wy;
      const d2 = dx * dx + dy * dy;
      if (d2 <= r * r && d2 < bestD2) {
        bestD2 = d2;
        best = node;
      }
    }
    return best;
  }

  /**
   * Position and fill the hover tooltip for a node.
   *
   * @param {PointerEvent} ev
   * @param {object|null} node
   */
  function updateTip(ev, node) {
    if (!node) {
      tip.classList.remove('visible');
      return;
    }
    const rect = container.getBoundingClientRect();
    const meta = node.meta && typeof node.meta === 'object' ? node.meta : {};
    const role = meta.role ? String(meta.role) : '';
    const extra = meta.label && meta.label !== node.label
      ? String(meta.label) : '';
    tip.replaceChildren(
      (() => {
        const k = document.createElement('div');
        k.className = 'tip-kind';
        k.textContent = node.kind;
        return k;
      })(),
      (() => {
        const v = document.createElement('div');
        v.className = 'tip-value';
        v.textContent = node.label || node.id;
        return v;
      })(),
      (() => {
        const m = document.createElement('div');
        m.className = 'tip-meta';
        m.textContent = [role, extra].filter(Boolean).join(' · ')
          || `${node.degree} link${node.degree === 1 ? '' : 's'}`;
        return m;
      })(),
    );
    const x = clamp(ev.clientX - rect.left + 16, 8,
      Math.max(8, rect.width - 240));
    const y = clamp(ev.clientY - rect.top + 14, 8,
      Math.max(8, rect.height - 90));
    tip.style.left = `${Math.round(x)}px`;
    tip.style.top = `${Math.round(y)}px`;
    tip.classList.add('visible');
  }

  canvas.addEventListener('pointerdown', (ev) => {
    const [mx, my] = localPoint(ev);
    const node = pickNode(mx, my);
    state.pointer = { x: mx, y: my, node, moved: 0, lwx: null, lwy: null };
    if (node) {
      node.fixed = true;
      reheat(0.35);
    }
    try {
      canvas.setPointerCapture(ev.pointerId);
    } catch { /* older browsers */ }
  });

  canvas.addEventListener('pointermove', (ev) => {
    const [mx, my] = localPoint(ev);
    const p = state.pointer;
    if (p) {
      const dx = mx - p.x;
      const dy = my - p.y;
      p.moved += Math.abs(dx) + Math.abs(dy);
      p.x = mx;
      p.y = my;
      if (p.node) {
        const [wx, wy] = toWorld(mx, my);
        // remember motion so release keeps a natural velocity
        if (p.lwx !== null) {
          p.node.vx = clamp((wx - p.lwx) * 0.35, -10, 10);
          p.node.vy = clamp((wy - p.lwy) * 0.35, -10, 10);
        }
        p.node.x = wx;
        p.node.y = wy;
        p.lwx = wx;
        p.lwy = wy;
        reheat(0.3);
        render();
        updateTip(ev, p.node);
      } else {
        state.transform.x += dx;
        state.transform.y += dy;
        render();
        updateHud();
      }
      return;
    }
    // hover
    const node = pickNode(mx, my);
    if (node !== state.hovered) {
      state.hovered = node;
      render();
    }
    updateTip(ev, node);
  });

  const endPointer = (ev) => {
    const p = state.pointer;
    if (!p) return;
    state.pointer = null;
    if (p.node) {
      p.node.fixed = false; // release keeps its velocity
      reheat(0.3);
      if (p.moved < 6) select(p.node);
    } else if (p.moved < 6) {
      select(null);
    }
    render();
    updateHud();
    try {
      canvas.releasePointerCapture?.(ev.pointerId);
    } catch { /* ignore */ }
  };
  canvas.addEventListener('pointerup', endPointer);
  canvas.addEventListener('pointercancel', endPointer);
  canvas.addEventListener('pointerleave', (ev) => {
    if (!state.pointer) {
      state.hovered = null;
      tip.classList.remove('visible');
      render();
    }
    ev.preventDefault?.();
  });

  canvas.addEventListener('dblclick', (ev) => {
    const [mx, my] = localPoint(ev);
    const node = pickNode(mx, my);
    if (!node) return;
    for (const cb of callbacks.dblclick) {
      try {
        cb(publicNode(node));
      } catch (err) {
        console.error('[obscuralens] graph ondblclick handler failed:', err);
      }
    }
  });

  canvas.addEventListener('wheel', (ev) => {
    ev.preventDefault();
    const [mx, my] = localPoint(ev);
    const t = state.transform;
    const factor = Math.exp(-ev.deltaY * 0.0016);
    const k = clamp(t.k * factor, ZOOM_MIN, ZOOM_MAX);
    t.x = mx - (mx - t.x) * (k / t.k);
    t.y = my - (my - t.y) * (k / t.k);
    t.k = k;
    render();
    updateHud();
  }, { passive: false });

  /* ---- toolbar ----------------------------------------------------------- */

  toolbar.append(
    toolButton('plus', 'Zoom in', () => {
      zoomStep(1.35);
    }),
    toolButton('minus', 'Zoom out', () => {
      zoomStep(1 / 1.35);
    }),
    toolButton('reset', 'Reset view', () => {
      reset();
    }),
    toolButton('download', 'Export PNG', () => {
      const url = exportPNG();
      if (!url) return;
      const a = document.createElement('a');
      a.href = url;
      a.download = 'obscuralens-graph.png';
      document.body.append(a);
      a.click();
      a.remove();
    }),
  );

  /**
   * Zoom by a multiplicative step around the viewport centre.
   *
   * @param {number} factor
   */
  function zoomStep(factor) {
    const w = container.clientWidth || 640;
    const h = container.clientHeight || 480;
    const t = state.transform;
    const k = clamp(t.k * factor, ZOOM_MIN, ZOOM_MAX);
    t.x = w / 2 - (w / 2 - t.x) * (k / t.k);
    t.y = h / 2 - (h / 2 - t.y) * (k / t.k);
    t.k = k;
    render();
    updateHud();
  }

  /* ---- observers ----------------------------------------------------------- */

  /** ResizeObserver: keep the world centred when the box changes size. */
  const ro = typeof ResizeObserver !== 'undefined'
    ? new ResizeObserver(() => {
      const w = container.clientWidth || 640;
      const h = container.clientHeight || 480;
      const t = state.transform;
      t.x += (w - state.lastSize.w) / 2; // gentle re-center
      t.y += (h - state.lastSize.h) / 2;
      state.lastSize = { w, h };
      render();
      updateHud();
    })
    : null;
  ro?.observe(container);

  /** Re-render when the theme attribute flips (palette is read per draw). */
  const themeObserver = typeof MutationObserver !== 'undefined'
    ? new MutationObserver(() => render())
    : null;
  themeObserver?.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme'],
  });

  /* ---- public API ----------------------------------------------------------- */

  /**
   * Center the view on one node (by id) and highlight it.
   *
   * @param {string} id
   */
  function focus(id) {
    const node = state.byId.get(String(id));
    if (!node) return;
    const w = container.clientWidth || 640;
    const h = container.clientHeight || 480;
    const t = state.transform;
    t.k = clamp(Math.max(t.k, 1.25), ZOOM_MIN, ZOOM_MAX);
    t.x = w / 2 - t.k * node.x;
    t.y = h / 2 - t.k * node.y;
    state.selected = node;
    reheat(0.25);
    render();
    updateHud();
  }

  /** Refit the whole graph into the viewport and clear the selection. */
  function reset() {
    state.selected = null;
    reheat(0.2);
    fitView();
  }

  /**
   * Composite the current canvas over a --bg background.
   *
   * @returns {string|null} PNG dataURL.
   */
  function exportPNG() {
    try {
      const off = document.createElement('canvas');
      off.width = canvas.width;
      off.height = canvas.height;
      const ctx = off.getContext('2d');
      ctx.fillStyle = cssVar('--bg', '#0a0e14');
      ctx.fillRect(0, 0, off.width, off.height);
      ctx.drawImage(canvas, 0, 0);
      return off.toDataURL('image/png');
    } catch (err) {
      console.error('[obscuralens] graph PNG export failed:', err);
      return null;
    }
  }

  /** Tear everything down (listeners, observers, DOM). */
  function destroy() {
    state.running = false;
    cancelAnimationFrame(state.raf);
    ro?.disconnect();
    themeObserver?.disconnect();
    canvas.remove();
    toolbar.remove();
    hud.remove();
    tip.remove();
    state.nodes = [];
    state.links = [];
    state.byId = new Map();
    callbacks.select.length = 0;
    callbacks.dblclick.length = 0;
  }

  /**
   * Register a selection listener (fires with a public node or null).
   *
   * @param {function} cb
   */
  function onSelect(cb) {
    if (typeof cb === 'function') callbacks.select.push(cb);
    return api;
  }

  /**
   * Register a double-click listener (fires with a public node).
   *
   * @param {function} cb
   */
  function ondblclick(cb) {
    if (typeof cb === 'function') callbacks.dblclick.push(cb);
    return api;
  }

  const api = {
    setData,
    focus,
    reset,
    exportPNG,
    destroy,
    onSelect,
    ondblclick,
  };

  render();
  updateHud();
  return api;
}

export default { createGraph };
