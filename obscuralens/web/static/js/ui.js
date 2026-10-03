/**
 * ObscuraLens web UI — component toolkit.
 *
 * Tiny DOM-builder (`el`), the inline icon set, and factories for toasts,
 * modals, tabs, sortable tables, key-value grids, badges and skeletons.
 * No framework; every helper returns real DOM nodes.
 */

/* ---------------------------------------------------------------------- */
/* DOM builder                                                             */
/* ---------------------------------------------------------------------- */

/**
 * Build an element.
 *
 * @param {string} tag Element tag.
 * @param {object} [props] Attributes/props. `class`, `dataset`, `style`
 *   (object), `on*` event handlers and `html` (trusted innerHTML) special.
 * @param {Array<Node|string|null|undefined|false>} [children]
 * @returns {HTMLElement}
 */
export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key === 'style' && typeof value === 'object') Object.assign(node.style, value);
    else if (key === 'html') node.innerHTML = value;
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key in node && key !== 'list' && typeof value !== 'string') {
      node[key] = value;
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** Empty a container and append children in one call. */
export function mount(container, ...children) {
  container.replaceChildren(...children.flat(Infinity).filter(Boolean));
  return container;
}

/** Escape a string for safe HTML interpolation. */
export function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/* ---------------------------------------------------------------------- */
/* Icon set — inline 24×24 stroke SVG paths (lucide-style)                 */
/* ---------------------------------------------------------------------- */

/**
 * Inline icon paths. Keys are referenced by views via `ui.icon(name)`.
 * Each value is the inner SVG markup (paths/circles).
 */
export const ICONS = {
  gauge:        '<path d="M12 14l4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0" fill="none"/>',
  search:       '<path d="M21 21l-4.35-4.35"/><circle cx="11" cy="11" r="7" fill="none"/>',
  network:      '<circle cx="12" cy="5" r="2.5" fill="none"/><circle cx="5" cy="19" r="2.5" fill="none"/><circle cx="19" cy="19" r="2.5" fill="none"/><path d="M12 7.5v4M12 11.5L6.5 17M12 11.5l5.5 5.5"/>',
  clock:        '<circle cx="12" cy="12" r="9" fill="none"/><path d="M12 7v5l3.5 2"/>',
  folder:       '<path d="M3 7a2 2 0 0 1 2-2h4l2.5 3H19a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="none"/>',
  eye:          '<path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12z" fill="none"/><circle cx="12" cy="12" r="3" fill="none"/>',
  radio:        '<circle cx="12" cy="12" r="2" fill="currentColor"/><path d="M7.8 16.2a6 6 0 0 1 0-8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.9 19.1a10 10 0 0 1 0-14.2M19.1 4.9a10 10 0 0 1 0 14.2" fill="none"/>',
  database:     '<ellipse cx="12" cy="5.5" rx="8" ry="3" fill="none"/><path d="M4 5.5v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6M4 11.5v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" fill="none"/>',
  wrench:       '<path d="M14.7 6.3a4.5 4.5 0 0 0-6 5.6L3 17.6V21h3.4l5.7-5.7a4.5 4.5 0 0 0 5.6-6l-2.8 2.8-2.1-.7-.7-2.1z" fill="none"/>',
  history:      '<path d="M3 12a9 9 0 1 0 2.6-6.4L3 8"/><path d="M3 3v5h5" fill="none"/><path d="M12 7v5l3.5 2" fill="none"/>',
  settings:     '<circle cx="12" cy="12" r="3" fill="none"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" fill="none"/>',
  check:        '<path d="M20 6L9 17l-5-5" fill="none"/>',
  x:            '<path d="M18 6L6 18M6 6l12 12" fill="none"/>',
  alert:        '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" fill="none"/><path d="M12 9v4M12 17h.01"/>',
  info:         '<circle cx="12" cy="12" r="9" fill="none"/><path d="M12 16v-4M12 8h.01"/>',
  copy:         '<rect x="9" y="9" width="12" height="12" rx="2" fill="none"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" fill="none"/>',
  download:     '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" fill="none"/>',
  refresh:      '<path d="M23 4v6h-6M1 20v-6h6" fill="none"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15" fill="none"/>',
  plus:         '<path d="M12 5v14M5 12h14" fill="none"/>',
  trash:        '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" fill="none"/>',
  external:     '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3" fill="none"/>',
  sun:          '<circle cx="12" cy="12" r="4" fill="none"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4l1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" fill="none"/>',
  moon:         '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" fill="none"/>',
  file:         '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" fill="none"/><path d="M14 2v6h6M9 13h6M9 17h6"/>',
  shield:       '<path d="M12 22s8-3.6 8-10V5l-8-3-8 3v7c0 6.4 8 10 8 10z" fill="none"/>',
  zap:          '<path d="M13 2L3 14h9l-1 8 10-12h-9z" fill="none"/>',
  map:          '<path d="M9 18l-6 3V6l6-3 6 3 6-3v15l-6 3z" fill="none"/><path d="M9 3v15M15 6v15"/>',
  tag:          '<path d="M20.6 13.4L12 22l-9-9V3h10l7.6 7.6a2 2 0 0 1 0 2.8z" fill="none"/><circle cx="7.5" cy="7.5" r="1.2" fill="none"/>',
  globe:        '<circle cx="12" cy="12" r="9" fill="none"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z" fill="none"/>',
  cpu:          '<rect x="5" y="5" width="14" height="14" rx="2" fill="none"/><rect x="9" y="9" width="6" height="6" fill="none"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3" fill="none"/>',
  layers:       '<path d="M12 2L2 7l10 5 10-5z" fill="none"/><path d="M2 12l10 5 10-5M2 17l10 5 10-5" fill="none"/>',
  link:         '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7" fill="none"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7" fill="none"/>',
  mail:         '<rect x="2" y="4" width="20" height="16" rx="2" fill="none"/><path d="M22 7l-10 6L2 7"/>',
  key:          '<circle cx="7.5" cy="15.5" r="4.5" fill="none"/><path d="M11 12L21 2M15 8l3 3M18 5l3 3" fill="none"/>',
  flask:        '<path d="M9 3h6M10 3v6l-6 9a2 2 0 0 0 1.7 3h12.6A2 2 0 0 0 20 18l-6-9V3" fill="none"/><path d="M7.5 14h9"/>',
  lock:         '<rect x="4" y="11" width="16" height="10" rx="2" fill="none"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  unlock:       '<rect x="4" y="11" width="16" height="10" rx="2" fill="none"/><path d="M8 11V7a4 4 0 0 1 7.8-1.3"/>',
  play:         '<path d="M6 4l14 8-14 8z" fill="none"/>',
  stop:         '<rect x="6" y="6" width="12" height="12" rx="1" fill="none"/>',
  chevronDown:  '<path d="M6 9l6 6 6-6" fill="none"/>',
  chevronRight: '<path d="M9 6l6 6-6 6" fill="none"/>',
  arrowUpRight: '<path d="M7 17L17 7M8 7h9v9" fill="none"/>',
  bug:          '<rect x="8" y="6" width="8" height="14" rx="4" fill="none"/><path d="M12 6V3M8 9L4 8M8 13H3M8 17l-3 3M16 9l4-1M16 13h5M16 17l3 3" fill="none"/>',
  finger:       '<path d="M12 2a5 5 0 0 0-5 5v6a7 7 0 0 0 14 0V7a5 5 0 0 0-5-5z" fill="none"/><path d="M12 2v14"/>',
  git:          '<circle cx="18" cy="6" r="3" fill="none"/><circle cx="6" cy="18" r="3" fill="none"/><path d="M18 9a9 9 0 0 1-9 9" fill="none"/>',
  book:         '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20V2H6.5A2.5 2.5 0 0 0 4 4.5z" fill="none"/><path d="M4 19.5A2.5 2.5 0 0 0 6.5 22H20v-5"/>',
};

/**
 * Build an inline `<svg class="icon …">` from the icon set.
 *
 * @param {string} name Key in ICONS.
 * @param {{size?: number, cls?: string, stroke?: number}} [opts]
 * @returns {SVGSVGElement}
 */
export function icon(name, opts = {}) {
  const size = opts.size ?? 16;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', String(opts.stroke ?? 2));
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  if (opts.cls) svg.setAttribute('class', opts.cls);
  svg.innerHTML = ICONS[name] ?? ICONS.info;
  return svg;
}

/* ---------------------------------------------------------------------- */
/* Formatters                                                              */
/* ---------------------------------------------------------------------- */

/** Format an integer with thin thousands separators. */
export function fmtInt(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  return n.toLocaleString('en-US');
}

/** Format bytes human-readable. */
export function fmtBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

/** Shorten long hex/monospace values for display. */
export function fmtShort(value, max = 48) {
  const s = String(value ?? '');
  if (s.length <= max) return s;
  return `${s.slice(0, Math.ceil(max / 2) - 4)}…${s.slice(-Math.floor(max / 2) + 4)}`;
}

/**
 * Format a timestamp (ISO string / epoch seconds / epoch ms / Date).
 * Returns '—' for nullish/unparseable input.
 */
export function fmtWhen(value, withTime = true) {
  if (value === null || value === undefined || value === '') return '—';
  let date;
  if (value instanceof Date) date = value;
  else if (typeof value === 'number') {
    date = new Date(value < 1e12 ? value * 1000 : value);
  } else {
    const s = String(value);
    if (/^\d+$/.test(s)) {
      const n = Number(s);
      date = new Date(n < 1e12 ? n * 1000 : n);
    } else {
      date = new Date(s);
    }
  }
  if (Number.isNaN(date.getTime())) return '—';
  const dateOpts = { year: 'numeric', month: 'short', day: '2-digit' };
  const timeOpts = { hour: '2-digit', minute: '2-digit' };
  return date.toLocaleString('en-GB', withTime ? { ...dateOpts, ...timeOpts } : dateOpts);
}

/** Relative "3 min ago" style description. */
export function fmtAgo(value) {
  const t = typeof value === 'number' ? (value < 1e12 ? value * 1000 : value)
    : Date.parse(String(value ?? ''));
  if (!Number.isFinite(t)) return '—';
  const seconds = Math.round((Date.now() - t) / 1000);
  if (Math.abs(seconds) < 45) return 'just now';
  const units = [
    [31536000, 'year'], [2592000, 'month'], [86400, 'day'],
    [3600, 'hour'], [60, 'minute'],
  ];
  for (const [secs, label] of units) {
    const n = Math.round(Math.abs(seconds) / secs);
    if (n >= 1) return `${n} ${label}${n > 1 ? 's' : ''} ${seconds > 0 ? 'ago' : 'from now'}`;
  }
  return 'just now';
}

/** Format a risk score 0-100 as a labeled badge level. */
export function riskLevel(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return { label: 'unknown', cls: 'badge-muted', pct: 0 };
  if (n >= 70) return { label: 'high', cls: 'badge-danger', pct: n };
  if (n >= 40) return { label: 'elevated', cls: 'badge-warn', pct: n };
  if (n >= 20) return { label: 'moderate', cls: 'badge-info', pct: n };
  return { label: 'low', cls: 'badge-ok', pct: n };
}

/** Truthey → ok/cross icon badge helper for verdict-ish values. */
export function truthyBadge(value, okLabel = 'yes', noLabel = 'no') {
  return value ? badge(okLabel, 'ok') : badge(noLabel, 'muted');
}

/* ---------------------------------------------------------------------- */
/* Badges / chips                                                          */
/* ---------------------------------------------------------------------- */

/**
 * Build a badge element.
 *
 * @param {string} text
 * @param {'ok'|'warn'|'danger'|'info'|'accent'|'muted'} [variant]
 * @param {{icon?: string, dot?: boolean}} [opts]
 */
export function badge(text, variant = 'muted', opts = {}) {
  const node = el('span', { class: `badge badge-${variant}` });
  if (opts.dot) node.append(el('span', { class: 'dot' }));
  if (opts.icon) node.append(icon(opts.icon, { size: 11, stroke: 2.4 }));
  node.append(String(text));
  return node;
}

/** Kind badge with per-kind hue (data-kind drives CSS color). */
export function kindBadge(kind) {
  return el('span', { class: 'badge badge-kind', 'data-kind': String(kind) },
    [String(kind)]);
}

/** Source provenance chip. `failed` renders the danger variant. */
export function srcChip(name, failed = false) {
  return el('span', { class: `chip ${failed ? 'chip-fail' : 'chip-src'}` },
    [failed ? icon('x', { size: 10, stroke: 2.6 }) : null, String(name)]);
}

/* ---------------------------------------------------------------------- */
/* Toasts                                                                  */
/* ---------------------------------------------------------------------- */

const TOAST_ICONS = { ok: 'check', warn: 'alert', danger: 'alert', info: 'info' };

/**
 * Show a toast notification.
 *
 * @param {string} message Body text (plain text).
 * @param {{title?: string, variant?: 'ok'|'warn'|'danger'|'info',
 *          timeout?: number}} [opts]
 */
export function toast(message, opts = {}) {
  const stack = document.getElementById('toast-stack');
  if (!stack) return;
  const variant = opts.variant ?? 'info';
  const node = el('div', { class: `toast ${variant}`, role: 'status' }, [
    el('span', { class: 'toast-icon' }, [icon(TOAST_ICONS[variant] ?? 'info', { size: 15 })]),
    el('div', { class: 'toast-msg' }, [
      opts.title ? el('strong', {}, [opts.title]) : null,
      el('span', {}, [String(message)]),
    ]),
    el('button', {
      class: 'toast-close', 'aria-label': 'Dismiss',
      onclick: () => dismiss(),
    }, [icon('x', { size: 12 })]),
  ]);
  stack.append(node);

  let timer = null;
  function dismiss() {
    if (timer) clearTimeout(timer);
    if (!node.isConnected) return;
    node.classList.add('leaving');
    node.addEventListener('animationend', () => node.remove(), { once: true });
  }
  if (opts.timeout !== 0) timer = setTimeout(dismiss, opts.timeout ?? 4200);
  return dismiss;
}

/** Convenience wrappers. */
export const toastOk = (msg, opts) => toast(msg, { ...opts, variant: 'ok' });
export const toastWarn = (msg, opts) => toast(msg, { ...opts, variant: 'warn' });
export const toastErr = (msg, opts) => toast(msg, { ...opts, variant: 'danger', timeout: 6500 });
export const toastInfo = (msg, opts) => toast(msg, { ...opts, variant: 'info' });

/* ---------------------------------------------------------------------- */
/* Modal                                                                   */
/* ---------------------------------------------------------------------- */

/**
 * Open a modal dialog. Returns a close() function.
 *
 * @param {{title?: string, body?: Node|Node[], foot?: Node|Node[],
 *          wide?: boolean, onClose?: () => void}} opts
 */
export function modal(opts = {}) {
  const root = document.getElementById('modal-root');
  if (!root) return () => {};
  let previouslyFocused = document.activeElement;

  const closeBtn = el('button', {
    class: 'icon-btn', 'aria-label': 'Close dialog',
    onclick: () => close(),
  }, [icon('x')]);

  const node = el('div', { class: 'modal-backdrop', onclick: (e) => {
    if (e.target === node) close();
  } }, [
    el('div', {
      class: `modal${opts.wide ? ' modal-wide' : ''}`,
      role: 'dialog', 'aria-modal': 'true', 'aria-label': opts.title ?? 'Dialog',
    }, [
      el('div', { class: 'modal-head' }, [
        el('span', { class: 'modal-title' }, [opts.title ?? '']),
        el('span', { class: 'grow' }),
        closeBtn,
      ]),
      opts.body ? el('div', { class: 'modal-body' }, [].concat(opts.body)) : null,
      opts.foot ? el('div', { class: 'modal-foot' }, [].concat(opts.foot)) : null,
    ]),
  ]);

  function close() {
    node.remove();
    document.removeEventListener('keydown', onKey, true);
    if (previouslyFocused && previouslyFocused.isConnected) previouslyFocused.focus();
    opts.onClose?.();
  }
  function onKey(e) {
    if (e.key === 'Escape') { e.stopPropagation(); close(); }
  }
  document.addEventListener('keydown', onKey, true);

  root.append(node);
  const focusable = node.querySelector('input, textarea, select, button:not(.icon-btn)');
  if (focusable) focusable.focus();
  return close;
}

/**
 * Confirmation dialog (async).
 *
 * @param {string} title
 * @param {string} message
 * @param {{confirmLabel?: string, danger?: boolean}} [opts]
 * @returns {Promise<boolean>}
 */
export function confirmDialog(title, message, opts = {}) {
  return new Promise((resolve) => {
    let closeRef = null;
    const confirmBtn = el('button', {
      class: `btn ${opts.danger ? 'btn-danger' : 'btn-primary'}`,
      onclick: () => { closeRef?.(); resolve(true); },
    }, [opts.confirmLabel ?? 'Confirm']);
    const cancelBtn = el('button', {
      class: 'btn btn-ghost', onclick: () => { closeRef?.(); resolve(false); },
    }, ['Cancel']);
    closeRef = modal({
      title,
      body: el('p', { class: 'muted' }, [message]),
      foot: [cancelBtn, confirmBtn],
      onClose: () => resolve(false),
    });
  });
}

/* ---------------------------------------------------------------------- */
/* Tabs                                                                    */
/* ---------------------------------------------------------------------- */

/**
 * Build a tab strip + panel container.
 *
 * The active tab's key is stored in the returned state; panels render via
 * the provided render functions lazily and are cached unless `cache:false`.
 *
 * @param {Array<{key: string, label: string, icon?: string,
 *   badge?: Node|string, render: () => Node|Node[]}>} tabsSpec
 * @param {{active?: string, cache?: boolean}} [opts]
 * @returns {{root: Node, select: (key: string) => void}}
 */
export function tabs(tabsSpec, opts = {}) {
  const strip = el('div', { class: 'tabs', role: 'tablist' });
  const panels = el('div', { class: 'tab-panels' });
  const cache = opts.cache !== false;
  const panelCache = new Map();
  let active = opts.active ?? tabsSpec[0]?.key;

  function select(key) {
    active = key;
    for (const btn of strip.children) {
      btn.setAttribute('aria-selected', String(btn.dataset.key === key));
    }
    let panel = cache ? panelCache.get(key) : null;
    if (!panel) {
      const spec = tabsSpec.find((t) => t.key === key);
      panel = el('div', { class: 'tab-panel' }, spec ? [].concat(spec.render()) : []);
      if (cache) panelCache.set(key, panel);
    }
    panels.replaceChildren(panel);
  }

  for (const spec of tabsSpec) {
    strip.append(el('button', {
      class: 'tab', role: 'tab', 'data-key': spec.key,
      'aria-selected': String(spec.key === active),
      onclick: () => select(spec.key),
    }, [
      spec.icon ? icon(spec.icon, { size: 13 }) : null,
      spec.label,
      spec.badge !== undefined ? spec.badge : null,
    ]));
  }
  select(active);

  return { root: el('div', {}, [strip, panels]), select };
}

/* ---------------------------------------------------------------------- */
/* Tables                                                                  */
/* ---------------------------------------------------------------------- */

/**
 * Build a sortable data table.
 *
 * @param {{columns: Array<{key: string, label: string, sortable?: boolean,
 *   render?: (row: *, rowIdx: number) => Node|string,
 *   value?: (row: *) => *}>,
 *   rows: Array<*>, rowClass?: (row: *) => string,
 *   empty?: string}} spec
 */
export function dataTable(spec) {
  const { columns, rows } = spec;
  let sortKey = null;
  let sortDir = 1;

  const thead = el('thead');
  const tbody = el('tbody');
  const wrap = el('div', { class: 'table-wrap' }, [
    el('table', { role: 'table' }, [thead, tbody]),
  ]);

  function renderHead() {
    thead.replaceChildren(el('tr', {}, columns.map((col) => {
      const th = el('th', {
        class: col.sortable === false ? '' : 'sortable',
        scope: 'col',
        onclick: col.sortable === false ? null : () => {
          if (sortKey === col.key) sortDir = -sortDir;
          else { sortKey = col.key; sortDir = 1; }
          renderHead();
          renderBody();
        },
      }, [
        col.label,
        sortKey === col.key
          ? el('span', { class: 'sort-arrow' }, [sortDir > 0 ? '↑' : '↓']) : null,
      ]);
      return th;
    })));
  }

  function sortedRows() {
    if (!sortKey) return rows;
    const col = columns.find((c) => c.key === sortKey);
    const getter = col?.value ?? ((row) => row?.[sortKey]);
    const out = [...rows];
    out.sort((a, b) => {
      const va = getter(a), vb = getter(b);
      if (va === vb) return 0;
      if (va === null || va === undefined) return 1;
      if (vb === null || vb === undefined) return -1;
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * sortDir;
      return String(va).localeCompare(String(vb), undefined, { numeric: true }) * sortDir;
    });
    return sortDir > 0 ? out : out.reverse();
  }

  function renderBody() {
    const data = sortedRows();
    if (!data.length) {
      tbody.replaceChildren();
      wrap.dataset.empty = '1';
      return;
    }
    delete wrap.dataset.empty;
    tbody.replaceChildren(...data.map((row, idx) => el('tr', {
      class: spec.rowClass?.(row) ?? '',
    }, columns.map((col) => el('td', {}, [
      col.render ? col.render(row, idx)
        : (row?.[col.key] === null || row?.[col.key] === undefined ? '—'
          : String(row[col.key])),
    ])))));
  }

  renderHead();
  renderBody();

  if (!rows.length) {
    return el('div', {}, [
      wrap,
      emptyState({ title: spec.empty ?? 'No data', icon: 'database' }),
    ]);
  }
  return wrap;
}

/* ---------------------------------------------------------------------- */
/* Key-value grid                                                          */
/* ---------------------------------------------------------------------- */

/**
 * Build a definition-list style key/value grid.
 *
 * @param {Array<[string, *]>|Map<string, *>} entries Key/value pairs.
 *   Values may be strings, numbers, Nodes or {text, title} objects.
 * @param {{mono?: boolean}} [opts]
 */
export function kvGrid(entries, opts = {}) {
  const dl = el('dl', { class: 'kv' });
  const pairs = entries instanceof Map ? [...entries] : [...(entries ?? [])];
  for (const [key, raw] of pairs) {
    if (raw === null || raw === undefined || raw === '') continue;
    const item = (typeof raw === 'object' && raw !== null && !('nodeType' in raw))
      ? raw : { text: raw };
    const valueNode = item.node ?? item.text;
    dl.append(
      el('dt', {}, [String(key)]),
      el('dd', { title: item.title ?? undefined, class: opts.mono === false ? '' : undefined },
        [valueNode instanceof Node ? valueNode : String(valueNode)]),
    );
  }
  return dl;
}

/* ---------------------------------------------------------------------- */
/* Skeletons / empty state / misc                                          */
/* ---------------------------------------------------------------------- */

/** Skeleton lines block. */
export function skeleton(lines = 4, blockFirst = false) {
  return el('div', { class: 'card', 'aria-hidden': 'true' }, [
    el('div', { class: 'card-body' }, Array.from({ length: lines }, (_, i) =>
      el('div', {
        class: `skeleton ${i === 0 && blockFirst ? 'skeleton-block' : 'skeleton-text'}`,
        style: { width: `${88 - i * 13}%` },
      }))),
  ]);
}

/** Centered inline spinner with label. */
export function loading(label = 'Loading…') {
  return el('div', { class: 'loading-inline', role: 'status' }, [
    el('span', { class: 'spinner' }), label,
  ]);
}

/**
 * Empty state block.
 * @param {{title: string, hint?: string, icon?: string, action?: Node}} spec
 */
export function emptyState(spec) {
  return el('div', { class: 'empty' }, [
    icon(spec.icon ?? 'search', { size: 34 }),
    el('div', { class: 'empty-title' }, [spec.title]),
    spec.hint ? el('p', { class: 'empty-hint' }, [spec.hint]) : null,
    spec.action ?? null,
  ]);
}

/**
 * A value with an inline copy button.
 * @param {string} value Text to copy.
 * @param {{short?: number, full?: string}} [opts]
 */
export function copyable(value, opts = {}) {
  const shown = opts.short ? fmtShort(value, opts.short) : String(value ?? '');
  return el('span', { class: 'copyable' }, [
    el('span', { title: opts.full ?? value }, [shown]),
    el('button', {
      class: 'copy-btn', 'aria-label': 'Copy value', title: 'Copy',
      onclick: async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(String(value));
          toastOk('Copied to clipboard');
        } catch {
          toastErr('Clipboard unavailable');
        }
      },
    }, [icon('copy')]),
  ]);
}

/** Trigger a client-side file download of text content. */
export function download(name, content, mime = 'text/plain') {
  const blob = content instanceof Blob ? content : new Blob([String(content)], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/** Render a JSON payload into a pretty, collapsible code block. */
export function jsonBlock(data, title = 'Raw JSON') {
  const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  return el('div', { class: 'code-block' }, [
    el('div', { class: 'code-block-head' }, [
      icon('code', { size: 12 }),
      el('span', { class: 'grow' }, [title]),
      copyable(text, { short: 0 }),
    ]),
    el('pre', { class: 'mono xs' }, [escapeHtml(text)]),
  ]);
}

/** Debounce helper for search inputs. */
export function debounce(fn, ms = 300) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

/** Sleep helper. */
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------------------------------------------------------------------- */
/* Bundled namespace for convenient `import { ui } from '../ui.js'`        */
/* ---------------------------------------------------------------------- */

export const ui = {
  el, mount, icon, ICONS, escapeHtml,
  fmtInt, fmtBytes, fmtShort, fmtWhen, fmtAgo, riskLevel,
  badge, kindBadge, srcChip, truthyBadge,
  toast, toastOk, toastWarn, toastErr, toastInfo,
  modal, confirmDialog, tabs, dataTable, kvGrid,
  skeleton, loading, emptyState, copyable, download, jsonBlock,
  debounce, sleep,
};

export default ui;
