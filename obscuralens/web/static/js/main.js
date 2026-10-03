/**
 * ObscuraLens web UI — application bootstrap.
 *
 * Owns: hash router, sidebar navigation, theme persistence, the command
 * palette (⌘K), global keyboard shortcuts and backend status polling.
 *
 * Views are ES modules under /static/js/views/<name>.js, each exporting:
 *
 *   export const view = {
 *     id: 'lookup',          // unique, matches the hash route
 *     title: 'Lookup',       // sidebar + topbar label
 *     subtitle: '…',         // topbar description
 *     icon: 'search',        // key in ui.ICONS
 *     section: 'workspace',  // sidebar section: workspace|investigation|platform
 *     order: 10,             // sort inside section
 *     render(root, params) {} // mount into the #view container
 *   };
 *
 * Missing modules degrade to a placeholder so the shell always boots.
 */

import { api, KINDS, KIND_META, ApiError } from './api.js';
import { ui } from './ui.js';

const { el, icon, toast, toastErr } = ui;

/* ---------------------------------------------------------------------- */
/* View registry                                                           */
/* ---------------------------------------------------------------------- */

/** View ids in load order — each maps to /static/js/views/<id>.js. */
const VIEW_IDS = [
  'dashboard', 'lookup', 'history',
  'investigate', 'timeline', 'cases', 'watchlist',
  'sources', 'tools', 'settings',
];

/** @type {Map<string, object>} id → view module export. */
const registry = new Map();

async function loadViews() {
  await Promise.all(VIEW_IDS.map(async (id) => {
    try {
      const mod = await import(`/static/js/views/${id}.js`);
      const view = mod.view ?? mod.default;
      if (view && view.id) registry.set(view.id, view);
    } catch (err) {
      console.warn(`[obscuralens] view module "${id}" unavailable:`, err?.message ?? err);
    }
  }));
}

function placeholderView(id) {
  return {
    id,
    title: id.charAt(0).toUpperCase() + id.slice(1),
    subtitle: 'module not loaded',
    icon: 'alert',
    section: 'platform',
    order: 999,
    render(root) {
      root.replaceChildren(ui.emptyState({
        title: 'View unavailable',
        hint: `The "${id}" view module could not be loaded. Check the server logs.`,
        icon: 'alert',
      }));
    },
  };
}

function getView(id) {
  return registry.get(id) ?? placeholderView(id);
}

/* ---------------------------------------------------------------------- */
/* Router                                                                  */
/* ---------------------------------------------------------------------- */

/** Parse location.hash → { view, params }. */
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  if (!raw) return { view: 'dashboard', params: new URLSearchParams() };
  const qIndex = raw.indexOf('?');
  const id = (qIndex === -1 ? raw : raw.slice(0, qIndex)).split('/')[0] || 'dashboard';
  const params = new URLSearchParams(qIndex === -1 ? '' : raw.slice(qIndex + 1));
  return { view: id, params };
}

let activeViewId = null;
let renderToken = 0;

async function route() {
  const { view: id, params } = parseHash();
  const view = getView(id);
  activeViewId = id;

  // Update nav highlight
  for (const link of document.querySelectorAll('.nav-link')) {
    link.classList.toggle('active', link.dataset.view === id);
    if (link.dataset.view === id) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }

  // Update topbar
  document.getElementById('view-title').textContent = view.title ?? id;
  document.getElementById('view-subtitle').textContent =
    view.subtitle ?? params.get('target') ?? '';

  const root = document.getElementById('view');
  const token = ++renderToken;
  root.replaceChildren(ui.loading('Loading view…'));
  document.getElementById('app').removeAttribute('data-booting');

  try {
    await view.render?.(root, params);
  } catch (err) {
    if (token !== renderToken) return; // a newer route superseded us
    const message = err instanceof ApiError ? err.message
      : `${err?.name ?? 'Error'}: ${err?.message ?? err}`;
    root.replaceChildren(ui.emptyState({
      title: 'View failed to load',
      hint: message,
      icon: 'alert',
    }));
    console.error('[obscuralens] view render failed:', err);
  }
}

/** Navigate programmatically. */
export function navigate(viewId, params) {
  const qs = params instanceof URLSearchParams ? params.toString()
    : params ? new URLSearchParams(params).toString() : '';
  location.hash = `#/${viewId}${qs ? '?' + qs : ''}`;
}

/* ---------------------------------------------------------------------- */
/* Sidebar                                                                 */
/* ---------------------------------------------------------------------- */

const SECTION_LABELS = new Map([
  ['workspace', 'Workspace'],
  ['investigation', 'Investigation'],
  ['platform', 'Platform'],
]);

function buildNav() {
  const sections = new Map();
  for (const id of VIEW_IDS) {
    const view = getView(id);
    const section = view.section ?? 'platform';
    if (!sections.has(section)) sections.set(section, []);
    sections.get(section).push(view);
  }
  for (const [section, views] of sections) {
    views.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
    const list = document.getElementById(`nav-${section}`);
    if (!list) continue;
    list.replaceChildren(...views.map((view) => el('li', {}, [
      el('a', {
        class: 'nav-link', href: `#/${view.id}`, 'data-view': view.id,
      }, [
        icon(view.icon ?? 'info', { size: 17 }),
        el('span', { class: 'nav-label' }, [view.title ?? view.id]),
      ]),
    ])));
  }
}

/* ---------------------------------------------------------------------- */
/* Theme                                                                   */
/* ---------------------------------------------------------------------- */

const THEME_KEY = 'ol-theme';

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* private mode */ }
}

function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* ignore */ }
  applyTheme(saved === 'light' || saved === 'dark' ? saved : 'dark');
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });
}

/* ---------------------------------------------------------------------- */
/* Backend status                                                          */
/* ---------------------------------------------------------------------- */

let statusTimer = null;

async function pollStatus() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const health = await api.health();
    dot?.classList.add('ok');
    dot?.classList.remove('err');
    if (text) text.textContent = `online · ${health.version ?? 'v?'}`;
    const version = health.version;
    if (version) {
      document.getElementById('brand-version').textContent = version;
      document.getElementById('footer-version').textContent = version;
    }
  } catch {
    dot?.classList.add('err');
    dot?.classList.remove('ok');
    if (text) text.textContent = 'backend offline';
  }
}

function startStatusPolling() {
  pollStatus();
  statusTimer = setInterval(pollStatus, 30000);
}

/* ---------------------------------------------------------------------- */
/* Command palette                                                         */
/* ---------------------------------------------------------------------- */

const paletteEl = () => document.getElementById('palette');
const paletteInput = () => document.getElementById('palette-input');
const paletteList = () => document.getElementById('palette-list');
let paletteOpen = false;
let paletteIndex = 0;
let paletteItems = [];

/** Fuzzy subsequence match; returns score (higher = better) or -1. */
function fuzzyScore(needle, haystack) {
  const n = needle.toLowerCase();
  const h = haystack.toLowerCase();
  if (!n) return 0;
  let score = 0, hi = 0, streak = 0;
  for (const ch of n) {
    const found = h.indexOf(ch, hi);
    if (found === -1) return -1;
    streak = found === hi ? streak + 1 : 0;
    score += 1 + streak * 2 + (found === 0 ? 3 : 0);
    hi = found + 1;
  }
  return score;
}

/** Build the palette command list for the current input. */
function buildCommands(query) {
  const commands = [];

  // Navigation commands
  for (const id of VIEW_IDS) {
    const view = getView(id);
    commands.push({
      key: `go-${id}`,
      label: `Go to ${view.title ?? id}`,
      hint: 'navigate',
      icon: view.icon ?? 'info',
      score: fuzzyScore(query, `${view.title ?? id} ${id}`),
      run: () => navigate(id),
    });
  }

  // Theme + misc
  commands.push({
    key: 'toggle-theme',
    label: 'Toggle light / dark theme',
    hint: 'theme',
    icon: 'moon',
    score: fuzzyScore(query, 'toggle theme dark light'),
    run: () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'),
  });
  commands.push({
    key: 'open-docs',
    label: 'Open REST API documentation',
    hint: 'external',
    icon: 'book',
    score: fuzzyScore(query, 'api docs openapi rest'),
    run: () => window.open('/docs', '_blank', 'noopener'),
  });

  // When the query looks like a target, offer investigations
  const trimmed = query.trim();
  if (trimmed.length >= 2 && !trimmed.startsWith('>')) {
    commands.push({
      key: 'investigate-query',
      label: `Investigate “${trimmed}”`,
      hint: 'auto-detect',
      icon: 'network',
      score: 60,
      run: () => navigate('investigate', { target: trimmed }),
    });
    for (const kind of KINDS) {
      commands.push({
        key: `lookup-${kind}`,
        label: `Look up as ${KIND_META[kind]?.label ?? kind}`,
        hint: kind,
        icon: 'search',
        score: 40,
        run: () => navigate('lookup', { kind, target: trimmed }),
      });
    }
  }

  return commands.filter((c) => c.score >= 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 14);
}

function renderPalette(query) {
  paletteItems = buildCommands(query);
  paletteIndex = Math.min(paletteIndex, Math.max(0, paletteItems.length - 1));
  const list = paletteList();
  list.replaceChildren(...paletteItems.map((cmd, idx) => el('li', {
    class: `palette-item${idx === paletteIndex ? ' selected' : ''}`,
    role: 'option', 'aria-selected': String(idx === paletteIndex),
    onclick: () => runPaletteCommand(idx),
    onmousemove: () => { if (paletteIndex !== idx) { paletteIndex = idx; renderPalette(query); } },
  }, [
    icon(cmd.icon, { size: 15 }),
    el('span', { class: 'palette-item-label' }, [cmd.label]),
    el('span', { class: 'palette-item-hint' }, [cmd.hint]),
  ])));
}

function runPaletteCommand(idx) {
  const cmd = paletteItems[idx];
  if (!cmd) return;
  closePalette();
  try {
    cmd.run();
  } catch (err) {
    toastErr(`Command failed: ${err?.message ?? err}`);
  }
}

function openPalette(prefill = '') {
  const node = paletteEl();
  if (!node) return;
  paletteOpen = true;
  node.hidden = false;
  paletteIndex = 0;
  const input = paletteInput();
  input.value = prefill;
  renderPalette(prefill);
  input.focus();
  input.select?.();
}

function closePalette() {
  const node = paletteEl();
  if (!node) return;
  paletteOpen = false;
  node.hidden = true;
  paletteInput().value = '';
}

function initPalette() {
  document.getElementById('palette-open')?.addEventListener('click', () => openPalette());
  const input = paletteInput();
  input.addEventListener('input', () => renderPalette(input.value));
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!paletteItems.length) return;
      paletteIndex = (paletteIndex + (e.key === 'ArrowDown' ? 1 : -1) + paletteItems.length) % paletteItems.length;
      renderPalette(input.value);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      runPaletteCommand(paletteIndex);
    } else if (e.key === 'Tab') {
      e.preventDefault();
      // autocomplete "kind:" prefixes for lookup commands
      const cmd = paletteItems[paletteIndex];
      if (cmd?.key?.startsWith('lookup-')) {
        const kind = cmd.key.slice('lookup-'.length);
        input.value = `${kind}: ${input.value.replace(/^[a-z]+:\s*/, '')}`;
        renderPalette(input.value);
      }
    }
  });
  paletteEl()?.addEventListener('mousedown', (e) => {
    if (e.target === paletteEl()) closePalette();
  });
}

/* ---------------------------------------------------------------------- */
/* Global shortcuts + quick search                                         */
/* ---------------------------------------------------------------------- */

function initShortcuts() {
  document.addEventListener('keydown', (e) => {
    const inField = /^(input|textarea|select)$/i.test(e.target.tagName)
      || e.target.isContentEditable;

    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      paletteOpen ? closePalette() : openPalette();
      return;
    }
    if (e.key === 'Escape' && paletteOpen) {
      closePalette();
      return;
    }
    if (inField) return;

    if (e.key === '/') {
      e.preventDefault();
      const qs = document.getElementById('quick-search');
      if (window.matchMedia('(max-width: 1024px)').matches) {
        openPalette();
      } else {
        qs?.focus();
      }
      return;
    }
    if (e.key.toLowerCase() === 't' && !e.metaKey && !e.ctrlKey && !e.altKey) {
      applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
      return;
    }
    if (e.key.toLowerCase() === 'g') {
      // "g then key" navigation
      const once = (ev) => {
        document.removeEventListener('keydown', once, true);
        const map = { d: 'dashboard', l: 'lookup', i: 'investigate',
          t: 'timeline', c: 'cases', w: 'watchlist', s: 'sources',
          o: 'tools', h: 'history', p: 'settings' };
        const dest = map[ev.key.toLowerCase()];
        if (dest) { ev.preventDefault(); navigate(dest); }
      };
      document.addEventListener('keydown', once, true);
      setTimeout(() => document.removeEventListener('keydown', once, true), 900);
    }
  });

  // Quick target search → investigate view
  const quick = document.getElementById('quick-search');
  quick?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const value = quick.value.trim();
      if (value) navigate('investigate', { target: value });
    }
  });

  // Mobile off-canvas nav
  const toggle = document.getElementById('nav-toggle');
  const app = document.getElementById('app');
  const backdrop = document.getElementById('sidebar-backdrop');
  toggle?.addEventListener('click', () => {
    const open = app.classList.toggle('nav-open');
    toggle.setAttribute('aria-expanded', String(open));
    if (backdrop) backdrop.hidden = !open;
  });
  backdrop?.addEventListener('click', () => {
    app.classList.remove('nav-open');
    toggle?.setAttribute('aria-expanded', 'false');
    backdrop.hidden = true;
  });
  // Close the drawer after navigating on mobile
  window.addEventListener('hashchange', () => {
    if (window.matchMedia('(max-width: 640px)').matches) {
      app.classList.remove('nav-open');
      if (backdrop) backdrop.hidden = true;
    }
  });
}

/* ---------------------------------------------------------------------- */
/* Global helpers exposed to views                                         */
/* ---------------------------------------------------------------------- */

/** Shared app context passed to views that ask for it via export. */
export const app = {
  navigate,
  views: registry,
  getView,
  refreshNav: buildNav,
};

/** Re-render the current route (used after mutations). */
export function refresh() {
  route();
}

/* ---------------------------------------------------------------------- */
/* Boot                                                                    */
/* ---------------------------------------------------------------------- */

async function boot() {
  initTheme();
  initPalette();
  initShortcuts();

  window.addEventListener('hashchange', route);

  await loadViews();
  buildNav();

  if (!location.hash) {
    history.replaceState(null, '', '#/dashboard');
  }
  await route();
  startStatusPolling();
}

boot().catch((err) => {
  console.error('[obscuralens] boot failed:', err);
  const root = document.getElementById('view');
  root?.replaceChildren(ui.emptyState({
    title: 'Failed to start ObscuraLens',
    hint: String(err?.message ?? err),
    icon: 'alert',
  }));
});
