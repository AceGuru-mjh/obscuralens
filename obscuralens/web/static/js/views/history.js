/**
 * ObscuraLens web UI — history view.
 *
 * Browse every lookup the backend has stored: filter by kind, free-text
 * search across targets (debounced), page deeper with growing limits,
 * jump straight back into the workbench, and export the current view to
 * CSV. Rows are clickable and targets are copyable.
 */
import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';
import { navigate } from '../main.js';

const {
  el, icon, badge, kindBadge,
  dataTable, emptyState, skeleton, download,
  toastOk, toastWarn, toastErr,
  fmtWhen, fmtAgo, debounce,
} = ui;

/** Page sizes offered by the "Load more" control (the endpoint takes `limit`). */
const LIMIT_STEPS = [50, 100, 250, 500, 1000];

/** Column order of the CSV export. */
const CSV_COLUMNS = ['when', 'kind', 'target', 'success', 'field_count', 'error'];

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/**
 * Human-readable message for any thrown error.
 *
 * @param {*} err
 * @returns {string}
 */
function errText(err) {
  if (err && typeof err === 'object' && typeof err.message === 'string' && err.message) {
    return err.message;
  }
  return String(err ?? 'unknown error');
}

/**
 * Normalise a timestamp to epoch milliseconds (accepts ISO strings, epoch
 * seconds and epoch milliseconds).
 *
 * @param {*} value
 * @returns {?number}
 */
function toMs(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
  const raw = String(value);
  if (/^\d+$/.test(raw)) {
    const n = Number(raw);
    return n < 1e12 ? n * 1000 : n;
  }
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Normalise one history row across the shapes the API has produced
 * (`{kind, value, timestamp, ...}` and the raw DB `{query_type,
 * query_value, created_at, success, error_message, ...}`).
 *
 * @param {*} item
 * @returns {?object}
 */
function normRow(item) {
  if (!item || typeof item !== 'object') return null;
  const kind = item.kind ?? item.query_type ?? item.type;
  const value = item.value ?? item.query_value ?? item.target;
  if (kind === undefined && value === undefined) return null;
  let fieldCount = Number(item.field_count);
  if (!Number.isFinite(fieldCount) && typeof item.result_data === 'string' && item.result_data) {
    // Defensive: derive the count from the stored payload when present.
    try {
      const parsed = JSON.parse(item.result_data);
      fieldCount = Number(parsed?.field_count);
      if (!Number.isFinite(fieldCount) && parsed && typeof parsed.info === 'object') {
        fieldCount = Object.keys(parsed.info).length;
      }
    } catch { /* not JSON — ignore */ }
  }
  return {
    kind: String(kind ?? 'unknown'),
    value: String(value ?? ''),
    ts: toMs(item.timestamp ?? item.created_at ?? item.when ?? item.at),
    success: typeof item.success === 'boolean' ? item.success : null,
    fieldCount: Number.isFinite(fieldCount) ? fieldCount : null,
    error: item.error ?? item.error_message ?? null,
  };
}

/**
 * CSV-escape one cell.
 *
 * @param {*} value
 * @returns {string}
 */
function csvCell(value) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

/**
 * Danger callout + retry button used when the history endpoint fails.
 *
 * @param {*} err
 * @param {() => void} retry
 * @returns {Node}
 */
function errRetryBlock(err, retry) {
  return el('div', { class: 'stack' }, [
    el('div', { class: 'callout danger', role: 'alert' }, [
      icon('alert'),
      el('div', {}, [
        el('strong', {}, ['Could not load history']),
        el('div', { class: 'sm' }, [errText(err)]),
      ]),
    ]),
    el('div', {}, [
      el('button', { class: 'btn btn-sm', type: 'button', onclick: retry }, [
        icon('refresh', { size: 13 }), 'Retry',
      ]),
    ]),
  ]);
}

/**
 * A small standalone copy button (the copyable() helper renders its own
 * text, which would duplicate the target link).
 *
 * @param {string} value
 * @returns {HTMLElement}
 */
function copyButton(value) {
  return el('button', {
    class: 'copy-btn', type: 'button',
    'aria-label': 'Copy target', title: 'Copy target',
    onclick: async (e) => {
      e.stopPropagation();
      try {
        await navigator.clipboard.writeText(value);
        toastOk('Target copied to clipboard');
      } catch { toastErr('Clipboard unavailable'); }
    },
  }, [icon('copy')]);
}

/* ------------------------------------------------------------------ */
/* View                                                                 */
/* ------------------------------------------------------------------ */

export const view = {
  id: 'history',
  title: 'History',
  subtitle: 'Query history browser',
  icon: 'history',
  section: 'workspace',
  order: 20,

  /**
   * Mount the history browser.
   *
   * @param {HTMLElement} root Empty <main> container.
   * @param {URLSearchParams} [params] Hash route params (kind/q/limit).
   */
  async render(root, params = new URLSearchParams()) {
    if (!root) return;

    /* ---- state ---------------------------------------------------- */
    const paramKind = params.get('kind');
    const state = {
      kind: paramKind && KINDS.includes(paramKind) ? paramKind : 'all',
      q: (params.get('q') ?? '').trim(),
      limitIdx: Math.max(0, LIMIT_STEPS.indexOf(Number(params.get('limit')))),
    };
    /** @type {Array<object>} normalised rows currently rendered */
    let rows = [];
    let total = null;

    /* ---- filter bar ----------------------------------------------- */
    const kindSelect = el('select', {
      class: 'select', 'aria-label': 'Filter by kind',
    }, [
      el('option', { value: 'all' }, ['All kinds']),
      ...KINDS.map((k) => el('option', { value: k }, [KIND_META[k]?.label ?? k])),
    ]);
    kindSelect.value = state.kind;
    kindSelect.addEventListener('change', () => {
      state.kind = kindSelect.value;
      state.limitIdx = 0;
      load();
    });

    const searchInput = el('input', {
      class: 'input', type: 'search',
      placeholder: 'Search targets…', 'aria-label': 'Search history',
      autocomplete: 'off', spellcheck: 'false',
      value: state.q,
    });
    searchInput.addEventListener('input', debounce(() => {
      state.q = searchInput.value.trim();
      state.limitIdx = 0;
      load();
    }, 300));

    const limitSelect = el('select', {
      class: 'select', 'aria-label': 'Page size',
      title: 'How many rows to fetch',
    }, LIMIT_STEPS.map((n) => el('option', { value: String(n) }, [`${n} rows`])));
    limitSelect.value = String(LIMIT_STEPS[state.limitIdx]);
    limitSelect.addEventListener('change', () => {
      state.limitIdx = Math.max(0, LIMIT_STEPS.indexOf(Number(limitSelect.value)));
      load();
    });

    const exportBtn = el('button', { class: 'btn', type: 'button' }, [
      icon('download', { size: 14 }), 'Export CSV',
    ]);
    exportBtn.addEventListener('click', exportCSV);

    /* ---- table + footer ------------------------------------------- */
    const countLine = el('span', { class: 'xs faint' }, ['']);
    const moreBtn = el('button', { class: 'btn', type: 'button', hidden: true }, [
      icon('chevronDown', { size: 14 }), 'Load more',
    ]);
    moreBtn.addEventListener('click', () => {
      if (state.limitIdx < LIMIT_STEPS.length - 1) {
        state.limitIdx += 1;
        limitSelect.value = String(LIMIT_STEPS[state.limitIdx]);
        load();
      }
    });

    const tableSlot = el('div', {}, [skeleton(6)]);
    const tableCard = el('section', { class: 'card', 'aria-label': 'Query history' }, [
      el('div', { class: 'card-head' }, [
        icon('database'),
        el('span', { class: 'card-title' }, ['Stored lookups']),
        el('span', { class: 'grow' }),
        countLine,
      ]),
      el('div', { class: 'card-body history-table' }, [tableSlot]),
      el('div', { class: 'card-foot history-foot' }, [moreBtn]),
    ]);

    root.append(el('div', { class: 'view-history' }, [
      el('div', { class: 'filter-bar' }, [
        kindSelect,
        searchInput,
        limitSelect,
        el('span', { class: 'spacer' }),
        exportBtn,
      ]),
      tableCard,
    ]));

    // Row clicks navigate to the workbench using the target link inside
    // the row (works after column sorting too, since the link moves with
    // its row). Links and buttons keep their native behaviour.
    tableCard.addEventListener('click', (e) => {
      if (e.target.closest('a, button')) return;
      const tr = e.target.closest('tbody tr');
      const link = tr?.querySelector('a.history-target');
      if (link) location.hash = link.getAttribute('href') ?? '';
    });

    /* ---- data loading --------------------------------------------- */

    /** Fetch history from the API and render the table. */
    async function load() {
      tableSlot.replaceChildren(skeleton(6));
      countLine.textContent = 'loading…';
      moreBtn.hidden = true;
      try {
        const res = await api.history({
          kind: state.kind === 'all' ? undefined : state.kind,
          q: state.q || undefined,
          limit: LIMIT_STEPS[state.limitIdx],
        });
        if (!tableSlot.isConnected) return;
        const items = Array.isArray(res) ? res : (res?.items ?? []);
        total = Number.isFinite(Number(res?.total)) ? Number(res.total) : null;
        rows = items.map(normRow).filter(Boolean);
        renderTable();
      } catch (err) {
        if (!tableSlot.isConnected) return;
        countLine.textContent = '';
        tableSlot.replaceChildren(errRetryBlock(err, load));
      }
    }

    /** Render the rows (or the empty state). */
    function renderTable() {
      const filtered = Boolean(state.q) || state.kind !== 'all';
      if (!rows.length) {
        tableSlot.replaceChildren(emptyState({
          title: filtered ? 'No matching lookups' : 'No history yet',
          hint: filtered
            ? 'Nothing matches the current filters — try another kind or search term.'
            : 'Run lookups from the workbench and every result is stored here '
              + 'with its provenance and field counts.',
          icon: 'history',
          action: el('button', {
            class: 'btn btn-primary', type: 'button',
            onclick: () => navigate('lookup'),
          }, [icon('search', { size: 14 }), 'Open the workbench']),
        }));
        countLine.textContent = '';
        moreBtn.hidden = true;
        return;
      }

      const known = total ?? rows.length;
      countLine.textContent = `showing ${ui.fmtInt(rows.length)} of ${ui.fmtInt(known)}`
        + (total === null ? '+' : '');
      moreBtn.hidden = rows.length >= known
        || state.limitIdx >= LIMIT_STEPS.length - 1;

      tableSlot.replaceChildren(dataTable({
        columns: [
          {
            key: 'when', label: 'When',
            value: (row) => row.ts ?? Number.MAX_SAFE_INTEGER,
            render: (row) => el('span', {
              class: 'nowrap',
              title: row.ts ? `${fmtWhen(row.ts)} (${fmtAgo(row.ts)})` : undefined,
            }, [
              row.ts ? fmtWhen(row.ts) : '—',
              el('span', { class: 'faint xs' }, [`  ·  ${row.ts ? fmtAgo(row.ts) : ''}`]),
            ]),
          },
          {
            key: 'kind', label: 'Kind',
            value: (row) => row.kind,
            render: (row) => kindBadge(row.kind),
          },
          {
            key: 'value', label: 'Target', sortable: false,
            render: (row) => (row.value
              ? el('span', { class: 'history-target-cell' }, [
                el('a', {
                  class: 'history-target mono',
                  href: `#/lookup?kind=${encodeURIComponent(row.kind)}`
                    + `&target=${encodeURIComponent(row.value)}`,
                  title: 'Open in the lookup workbench',
                }, [ui.fmtShort(row.value, 48)]),
                copyButton(row.value),
              ])
              : el('span', { class: 'faint' }, ['—'])),
          },
          {
            key: 'result', label: 'Result', sortable: false,
            render: (row) => {
              const parts = [];
              if (row.success === true) parts.push(badge('success', 'ok'));
              else if (row.success === false) parts.push(badge('failed', 'danger'));
              else parts.push(badge('stored', 'muted'));
              if (row.fieldCount !== null) {
                parts.push(el('span', { class: 'xs muted mono nowrap' },
                  [`${row.fieldCount} fields`]));
              }
              if (row.error) {
                parts.push(el('span', {
                  class: 'xs err truncate', title: String(row.error),
                }, [ui.fmtShort(String(row.error), 56)]));
              }
              return el('span', { class: 'result-cell' }, parts);
            },
          },
        ],
        rows,
        empty: 'No lookups stored',
      }));
    }

    /** Export the currently loaded rows to CSV (client-side). */
    function exportCSV() {
      if (!rows.length) {
        toastWarn('Nothing to export yet');
        return;
      }
      const lines = [CSV_COLUMNS.join(',')];
      for (const row of rows) {
        const cells = {
          when: row.ts ? fmtWhen(row.ts) : '',
          kind: row.kind,
          target: row.value,
          success: row.success === null ? '' : String(row.success),
          field_count: row.fieldCount ?? '',
          error: row.error ?? '',
        };
        lines.push(CSV_COLUMNS.map((col) => csvCell(cells[col])).join(','));
      }
      const stamp = new Date().toISOString().slice(0, 10);
      download(`obscuralens-history-${stamp}.csv`, lines.join('\n'), 'text/csv');
      toastOk(`Exported ${rows.length} rows to CSV`);
    }

    load();
  },
};

export default view;
