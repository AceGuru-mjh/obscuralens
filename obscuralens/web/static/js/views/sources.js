/**
 * ObscuraLens web UI — Sources view.
 *
 * Data source catalog & health. Two tabs:
 *   Catalog — every known source per target kind (from /api/kinds when
 *             available, falling back to /api/sources), searchable.
 *   Health  — per-source success/failure counters and circuit-breaker state
 *             from /api/stats → .source_health (list *or* map shape).
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';

const {
  el, icon, badge, kindBadge, toastErr, dataTable, emptyState, skeleton,
  fmtInt, fmtWhen, debounce,
} = ui;

/* ---------------------------------------------------------------------- */
/* Small helpers                                                           */
/* ---------------------------------------------------------------------- */

/** Human-readable error text for callouts and toasts. */
function errText(err) {
  return err instanceof Error ? err.message : String(err ?? 'unknown error');
}

/** Inline danger callout with an optional retry button. */
function errorCallout(message, onRetry, what = 'Sources') {
  return el('div', { class: 'callout danger', role: 'alert' }, [
    icon('alert'),
    el('div', { class: 'grow' }, [
      el('strong', {}, [`${what} could not be loaded`]),
      el('div', { class: 'muted sm' }, [message]),
    ]),
    onRetry ? el('button', { class: 'btn btn-sm', onclick: onRetry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]) : null,
  ]);
}

/** Coerce to a finite non-negative integer. */
const num = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : 0;
};

/** Source entries may be strings or {name, description} objects. */
function normalizeSourceEntry(entry, index) {
  if (typeof entry === 'string') return { name: entry, desc: '' };
  if (entry && typeof entry === 'object') {
    const name = String(entry.name ?? entry.source ?? entry.id ?? `source-${index}`);
    const desc = String(entry.description ?? entry.desc ?? entry.doc ?? '');
    return { name, desc };
  }
  return { name: `source-${index}`, desc: '' };
}

/* ---------------------------------------------------------------------- */
/* Health payload normalisation                                            */
/* ---------------------------------------------------------------------- */

/**
 * Normalise `.source_health` from /api/stats.
 * Accepts a list of rows (backend v4 shape) or a map keyed by source name.
 * @returns {Array<{source, kind, ok, fail, state, rate, cooldown, lastError}>}
 */
function normalizeHealth(payload) {
  const raw = [];
  if (Array.isArray(payload)) {
    for (const item of payload) if (item && typeof item === 'object') raw.push(item);
  } else if (payload && typeof payload === 'object') {
    for (const [name, info] of Object.entries(payload)) {
      raw.push(info && typeof info === 'object' ? { source: name, ...info } : { source: name });
    }
  }
  const rows = [];
  for (const row of raw) {
    const ok = num(row.ok ?? row.successes ?? row.ok_count ?? row.success_count ?? 0);
    const fail = num(row.fail ?? row.failures ?? row.fail_count ?? row.failure_count ?? 0);
    let state = String(row.state ?? row.status ?? '').toLowerCase();
    if (!state) state = ok + fail === 0 ? 'untested' : 'healthy';
    if (['tripped', 'open', 'down', 'cooldown'].includes(state)) state = 'tripped';
    else if (['healthy', 'ok', 'up', 'alive'].includes(state)) state = 'healthy';
    else if (state !== 'untested') state = state || 'unknown';
    rows.push({
      source: String(row.source ?? row.name ?? '—'),
      kind: row.kind ?? null,
      ok,
      fail,
      state,
      rate: ok + fail > 0 ? Math.round((ok / (ok + fail)) * 1000) / 10 : null,
      cooldown: row.cooldown_until ?? row.cooldown ?? null,
      lastError: row.last_error ?? null,
    });
  }
  return rows.filter((r) => r.source && r.source !== '—');
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'sources',
  title: 'Sources',
  subtitle: 'Data source catalog & health',
  icon: 'radio',
  section: 'platform',
  order: 10,

  /**
   * Mount the sources view (tabbed).
   * @param {HTMLElement} root
   */
  async render(root) {
    const tabsUi = ui.tabs([
      { key: 'catalog', label: 'Catalog', icon: 'radio', render: () => catalogPanel() },
      { key: 'health', label: 'Health', icon: 'shield', render: () => healthPanel() },
    ]);
    root.replaceChildren(tabsUi.root);
  },
};

/* ---------------------------------------------------------------------- */
/* Catalog tab                                                             */
/* ---------------------------------------------------------------------- */

/**
 * Build the catalog panel: search box + per-kind source grids.
 * Prefers /api/kinds (rich metadata); falls back to /api/sources.
 */
function catalogPanel() {
  const search = el('input', {
    class: 'input', type: 'search',
    placeholder: 'Filter sources by name or description…',
    'aria-label': 'Filter sources', spellcheck: 'false',
    style: { minWidth: '260px' },
  });
  const countChip = el('span', { class: 'muted sm' });
  const listEl = el('div', { class: 'stack-lg' });
  const state = { sections: [] };

  search.addEventListener('input', debounce(render, 200));

  async function load() {
    listEl.replaceChildren(skeleton(6));
    let sections = null;
    try {
      sections = await fromKinds();
    } catch { /* endpoint missing on older backends — fall back below */ }
    if (!sections) {
      try {
        sections = await fromSources();
      } catch (err) {
        listEl.replaceChildren(errorCallout(errText(err), load));
        return;
      }
    }
    if (!listEl.isConnected) return;
    state.sections = sections;
    render();
  }

  /** /api/kinds → [{kind, label, description, example, sources: [...]}] */
  async function fromKinds() {
    const kinds = await api.kinds();
    const arr = Array.isArray(kinds) ? kinds : kinds?.kinds ?? null;
    if (!Array.isArray(arr) || !arr.length) return null;
    const sections = [];
    for (const entry of arr) {
      if (!entry || typeof entry !== 'object') continue;
      const kind = String(entry.kind ?? '').toLowerCase();
      const rawSources = Array.isArray(entry.sources) ? entry.sources : [];
      if (!kind || !rawSources.length) continue;
      sections.push({
        kind,
        label: String(entry.label ?? KIND_META[kind]?.label ?? kind),
        hint: String(entry.description ?? ''),
        sources: rawSources.map(normalizeSourceEntry).filter((s) => s.name),
      });
    }
    return sections.length ? sections : null;
  }

  /** /api/sources → {kind: {source_name: description}} */
  async function fromSources() {
    const catalog = await api.sources();
    if (!catalog || typeof catalog !== 'object') return [];
    const sections = [];
    for (const [kind, entries] of Object.entries(catalog)) {
      if (!entries || typeof entries !== 'object') continue;
      const sources = Object.entries(entries).map(([name, desc]) =>
        ({ name, desc: String(desc ?? '') }));
      if (!sources.length) continue;
      sections.push({
        kind: String(kind).toLowerCase(),
        label: KIND_META[kind]?.label ?? String(kind),
        hint: '',
        sources,
      });
    }
    return sections;
  }

  /** Client-side search across names + descriptions. */
  function render() {
    const q = search.value.trim().toLowerCase();
    const sections = state.sections
      .map((s) => ({
        ...s,
        sources: q
          ? s.sources.filter((src) => src.name.toLowerCase().includes(q)
            || src.desc.toLowerCase().includes(q))
          : s.sources,
      }))
      .filter((s) => s.sources.length);

    const total = sections.reduce((acc, s) => acc + s.sources.length, 0);
    countChip.textContent = q
      ? `${total} matching source${total === 1 ? '' : 's'}`
      : `${total} source${total === 1 ? '' : 's'} across ${sections.length} kind${sections.length === 1 ? '' : 's'}`;

    if (!sections.length) {
      listEl.replaceChildren(emptyState({
        title: state.sections.length ? 'No sources match this filter' : 'No source catalog available',
        hint: state.sections.length
          ? 'Try a different search term — the filter matches source names and descriptions.'
          : 'The backend did not return a source catalog. Run a lookup first, then reload.',
        icon: 'radio',
      }));
      return;
    }
    listEl.replaceChildren(...sections.map(sectionEl));
  }

  /** One kind section: header + grid of source cards. */
  function sectionEl(section) {
    return el('section', { class: 'src-section' }, [
      el('div', { class: 'section-head' }, [
        kindBadge(section.kind),
        el('span', { class: 'section-title' }, [section.label]),
        section.hint ? el('span', { class: 'faint xs truncate', style: { maxWidth: '42ch' } }, [section.hint]) : null,
        el('span', { class: 'grow' }),
        badge(`${section.sources.length}`, 'accent'),
      ]),
      el('div', { class: 'src-grid' }, section.sources.map((src) =>
        el('div', { class: 'src-card', title: src.desc || src.name }, [
          el('div', { class: 'src-name mono' }, [src.name]),
          src.desc ? el('div', { class: 'src-desc muted xs' }, [src.desc]) : null,
        ]))),
    ]);
  }

  load();
  return el('div', { class: 'stack' }, [
    el('div', { class: 'filter-bar' }, [search, el('span', { class: 'spacer' }), countChip]),
    listEl,
  ]);
}

/* ---------------------------------------------------------------------- */
/* Health tab                                                              */
/* ---------------------------------------------------------------------- */

/** Build the health panel: summary chips + reliability table. */
function healthPanel() {
  const chips = el('div', { class: 'filter-bar', role: 'status' });
  const tableEl = el('div', { class: 'stack' });

  async function load() {
    tableEl.replaceChildren(skeleton(6));
    chips.replaceChildren();
    try {
      const stats = await api.stats();
      if (!tableEl.isConnected) return;
      const rows = normalizeHealth(stats?.source_health ?? stats?.health ?? stats?.sources_health);
      if (!rows.length) {
        tableEl.replaceChildren(emptyState({
          title: 'No source health recorded yet',
          hint: 'Health counters and circuit-breaker state appear after the first tracker lookups run.',
          icon: 'shield',
        }));
        return;
      }
      render(rows);
    } catch (err) {
      tableEl.replaceChildren(errorCallout(errText(err), load, 'Source health'));
    }
  }

  /** Summary chips + the failure-sorted table. */
  function render(rows) {
    const healthy = rows.filter((r) => r.state === 'healthy').length;
    const tripped = rows.filter((r) => r.state === 'tripped').length;
    chips.replaceChildren(
      badge(`${rows.length} sources tracked`, 'accent', { icon: 'radio' }),
      badge(`${healthy} healthy`, 'ok', { dot: true }),
      tripped ? badge(`${tripped} tripped`, 'danger', { icon: 'zap' })
        : badge('0 tripped', 'muted'),
    );

    const sorted = [...rows].sort((a, b) => b.fail - a.fail
      || a.ok - b.ok || a.source.localeCompare(b.source));

    tableEl.replaceChildren(dataTable({
      columns: [
        { key: 'source', label: 'Source', render: (row) => el('span', { class: 'mono sm strong' }, [row.source]) },
        { key: 'kind', label: 'Kind', render: kindCell },
        { key: 'ok', label: 'Successes', value: (row) => row.ok, render: (row) => el('span', { class: 'mono sm' }, [fmtInt(row.ok)]) },
        { key: 'fail', label: 'Failures', value: (row) => row.fail, render: failCell },
        { key: 'rate', label: 'OK rate', sortable: false, render: rateCell },
        { key: 'state', label: 'State', render: stateCell },
      ],
      rows: sorted,
      rowClass: (row) => (row.state === 'tripped' ? 'row-err'
        : row.state === 'healthy' ? 'row-ok' : ''),
      empty: 'No source health rows',
    }));
  }

  function kindCell(row) {
    const kind = String(row.kind ?? '').toLowerCase();
    return kind ? (KINDS.includes(kind) ? kindBadge(kind)
      : el('span', { class: 'muted xs mono' }, [kind]))
      : el('span', { class: 'faint' }, ['—']);
  }

  function failCell(row) {
    return row.fail > 0
      ? el('span', { class: 'mono sm strong', style: { color: 'var(--danger)' } }, [fmtInt(row.fail)])
      : el('span', { class: 'mono sm muted' }, ['0']);
  }

  function rateCell(row) {
    if (row.rate === null) return el('span', { class: 'faint sm' }, ['untested']);
    const cls = row.rate < 50 ? 'danger' : row.rate < 80 ? 'warn' : '';
    return el('div', { class: 'src-rate' }, [
      el('div', { class: 'progress', role: 'progressbar', 'aria-valuenow': String(row.rate), 'aria-valuemin': '0', 'aria-valuemax': '100' }, [
        el('div', { class: `progress-bar ${cls}`, style: { width: `${Math.min(100, row.rate)}%` } }),
      ]),
      el('span', { class: 'src-rate-label mono xs' }, [`${row.rate}%`]),
    ]);
  }

  function stateCell(row) {
    const title = row.cooldown
      ? `cooldown until ${fmtWhen(row.cooldown)}${row.lastError ? ` · ${row.lastError}` : ''}`
      : row.lastError || undefined;
    if (row.state === 'tripped') return el('span', { title }, [badge('tripped', 'danger', { icon: 'zap' })]);
    if (row.state === 'healthy') return el('span', { title }, [badge('healthy', 'ok', { dot: true })]);
    return el('span', { title }, [badge(row.state || 'unknown', 'muted')]);
  }

  load();
  return el('div', { class: 'stack-lg' }, [chips, tableEl]);
}

export default view;
