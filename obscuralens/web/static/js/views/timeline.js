/**
 * ObscuraLens web UI — Timeline view.
 *
 * Chronological event reconstruction across stored lookup history: dated
 * fields harvested from past tracker results (registrations, breaches,
 * certificate lifetimes, first/last seen…) rendered as a vertical rail of
 * day-grouped event cards with a summary strip and CSV/JSON export.
 *
 * The `/api/timeline` payload is read defensively — events may carry
 * `date|timestamp|ts`, `target|value`, `label|description|field` and an
 * optional `source`, wrapped as `{events, count, first, last}` (older or
 * newer backend shapes all normalise to the same internal event).
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';

const {
  el, icon, badge, kindBadge, srcChip, toastErr,
  fmtWhen, fmtAgo, debounce, emptyState, skeleton, download,
} = ui;

/* ---------------------------------------------------------------------- */
/* Navigation                                                              */
/* ---------------------------------------------------------------------- */
/*
 * main.js boots the app shell at module scope, so a static import would run
 * DOM code whenever this module is evaluated outside a browser (node syntax
 * checks). The shell module is therefore imported lazily on first use; until
 * it resolves, navigation falls back to a plain hash change — behaviourally
 * identical to navigate(). Swap back to a static
 * `import { navigate } from '../main.js'` once main.js guards its boot().
 */

let navigateFn = null;
let navigateStarted = false;

function loadNavigate() {
  if (navigateStarted) return;
  navigateStarted = true;
  import('../main.js')
    .then((mod) => { navigateFn = mod?.navigate ?? null; })
    .catch(() => { navigateFn = null; });
}

/** Navigate to a view with a hash-based fallback. */
function nav(viewId, params) {
  loadNavigate();
  if (typeof navigateFn === 'function') { navigateFn(viewId, params); return; }
  const qs = params ? new URLSearchParams(params).toString() : '';
  location.hash = `#/${viewId}${qs ? '?' + qs : ''}`;
}

/* ---------------------------------------------------------------------- */
/* Small helpers                                                           */
/* ---------------------------------------------------------------------- */

/** Human-readable error text for callouts and toasts. */
function errText(err) {
  return err instanceof Error ? err.message : String(err ?? 'unknown error');
}

/** Inline danger callout with an optional retry button. */
function errorCallout(message, onRetry) {
  return el('div', { class: 'callout danger', role: 'alert' }, [
    icon('alert'),
    el('div', { class: 'grow' }, [
      el('strong', {}, ['Timeline could not be loaded']),
      el('div', { class: 'muted sm' }, [message]),
    ]),
    onRetry ? el('button', { class: 'btn btn-sm', onclick: onRetry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]) : null,
  ]);
}

/** Parse anything timestamp-ish into epoch milliseconds (null if hopeless). */
function toTimeMs(value) {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Date) {
    const t = value.getTime();
    return Number.isFinite(t) ? t : null;
  }
  let t;
  if (typeof value === 'number') {
    t = value < 1e12 ? value * 1000 : value;
  } else {
    const s = String(value);
    if (/^\d+$/.test(s)) {
      const n = Number(s);
      t = n < 1e12 ? n * 1000 : n;
    } else {
      t = Date.parse(s);
    }
  }
  return Number.isFinite(t) ? t : null;
}

/** First non-empty string among the arguments ('' when none match). */
function firstStr(...values) {
  for (const v of values) {
    if (v === null || v === undefined) continue;
    const s = String(v);
    if (s.trim() !== '') return s;
  }
  return '';
}

/** Allowed limit values: 50 / 100 / 200 / 400. */
function toLimit(value, fallback) {
  const n = Number(value);
  return [50, 100, 200, 400].includes(n) ? n : fallback;
}

/** Quote one CSV cell per RFC 4180. */
function csvCell(value) {
  const s = String(value ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

/* ---------------------------------------------------------------------- */
/* Event normalisation                                                     */
/* ---------------------------------------------------------------------- */

/**
 * Normalise any supported timeline payload into a sorted event list.
 * @param {*} payload API response (array or `{events: [...]}`).
 * @returns {Array<{when: number|null, kind: string, value: string,
 *            label: string, source: string}>} oldest → newest.
 */
function normalizeEvents(payload) {
  const raw = Array.isArray(payload) ? payload
    : (payload && Array.isArray(payload.events)) ? payload.events : [];
  const out = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    out.push({
      when: toTimeMs(item.timestamp ?? item.ts ?? item.date ?? item.when ?? item.time),
      kind: String(item.kind ?? '').trim().toLowerCase(),
      value: firstStr(item.value, item.target),
      label: firstStr(item.label, item.description, item.field),
      source: firstStr(item.source, item.source_name),
    });
  }
  out.sort((a, b) => (a.when ?? Number.NEGATIVE_INFINITY)
    - (b.when ?? Number.NEGATIVE_INFINITY));
  return out;
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'timeline',
  title: 'Timeline',
  subtitle: 'Chronological event reconstruction',
  icon: 'clock',
  section: 'investigation',
  order: 20,

  /**
   * Mount the timeline into the view root.
   * @param {HTMLElement} root
   * @param {URLSearchParams} params `target` and `limit` query params.
   */
  async render(root, params) {
    loadNavigate();

    const state = {
      target: params.get('target') ?? '',
      limit: toLimit(params.get('limit'), 100),
      events: [],
    };

    /* -- filter / action row ------------------------------------------ */
    const targetInput = el('input', {
      class: 'input input-mono', type: 'search', value: state.target,
      placeholder: 'Filter by target substring…',
      'aria-label': 'Filter events by target', spellcheck: 'false',
      style: { minWidth: '220px' },
    });
    const limitSelect = el('select', { class: 'select', 'aria-label': 'Event limit' },
      [50, 100, 200, 400].map((n) =>
        el('option', { value: String(n) }, [`${n} events`])));
    limitSelect.value = String(state.limit);

    targetInput.addEventListener('input', debounce(() => {
      state.target = targetInput.value.trim();
      load();
    }, 400));
    limitSelect.addEventListener('change', () => {
      state.limit = toLimit(limitSelect.value, 100);
      load();
    });

    const exportCsvBtn = el('button', {
      class: 'btn btn-sm', title: 'Download the loaded events as CSV',
      onclick: () => exportCsv(state.events),
    }, [icon('download', { size: 13 }), 'CSV']);
    const exportJsonBtn = el('button', {
      class: 'btn btn-sm', title: 'Download the loaded events as JSON',
      onclick: () => exportJson(state.events),
    }, [icon('download', { size: 13 }), 'JSON']);

    const summary = el('div', { class: 'filter-bar tl-summary', role: 'status' });
    const container = el('div', { class: 'tl-wrap' });

    root.replaceChildren(el('div', { class: 'stack-lg' }, [
      el('div', { class: 'filter-bar' }, [
        targetInput,
        limitSelect,
        el('span', { class: 'spacer' }),
        el('span', { class: 'faint xs nowrap' }, ['export:']),
        exportCsvBtn,
        exportJsonBtn,
      ]),
      summary,
      container,
    ]));

    let token = 0;

    async function load() {
      const my = ++token;
      container.replaceChildren(skeleton(7));
      summary.replaceChildren();
      try {
        const payload = await api.timeline({
          target: state.target || undefined,
          limit: state.limit,
        });
        if (my !== token || !container.isConnected) return;
        state.events = normalizeEvents(payload);
        renderSummary();
        renderTimeline();
      } catch (err) {
        if (my !== token || !container.isConnected) return;
        container.replaceChildren(errorCallout(errText(err), load));
      }
    }

    /** Summary strip: totals, distinct targets and the covered span. */
    function renderSummary() {
      const events = state.events;
      const targets = new Set(events.map((e) => e.value).filter(Boolean));
      const dated = events.filter((e) => e.when !== null);
      const first = dated.length ? Math.min(...dated.map((e) => e.when)) : null;
      const last = dated.length ? Math.max(...dated.map((e) => e.when)) : null;
      summary.replaceChildren(
        badge(`${events.length} event${events.length === 1 ? '' : 's'}`, 'accent', { icon: 'clock' }),
        badge(`${targets.size} target${targets.size === 1 ? '' : 's'}`, 'info', { icon: 'tag' }),
        first !== null && last !== null
          ? el('span', { class: 'muted sm' }, [
              `${fmtWhen(first)} → ${fmtWhen(last)} `,
              el('span', { class: 'faint' }, [`(${fmtAgo(last)})`]),
            ])
          : el('span', { class: 'faint sm' }, ['no dated events in this set']),
      );
    }

    /** Group events by calendar day and render the vertical rail. */
    function renderTimeline() {
      if (!state.events.length) {
        container.replaceChildren(emptyState({
          title: state.target ? 'No events match this target' : 'No timeline events yet',
          hint: state.target
            ? 'Nothing in the stored history matches that filter. Clear it or run a lookup for the target first.'
            : 'Run a few lookups — dated evidence (registrations, breaches, certificates, first/last seen) is reconstructed here in order.',
          icon: 'clock',
        }));
        return;
      }

      const groups = new Map(); // dayKey(null for undated) → [events]
      for (const event of state.events) {
        const key = event.when === null ? null : new Date(event.when).toDateString();
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(event);
      }
      const orderedKeys = [...groups.keys()].sort((a, b) => {
        if (a === null) return 1;
        if (b === null) return -1;
        return Date.parse(a) - Date.parse(b);
      });

      container.replaceChildren(...orderedKeys.map((key) => {
        const events = groups.get(key);
        const dayDate = key ? new Date(key) : null;
        return el('section', { class: 'tl-day' }, [
          el('div', { class: 'tl-day-head' }, [
            el('span', { class: 'tl-day-label' }, [
              dayDate ? fmtWhen(dayDate, false) : 'Undated',
            ]),
            el('span', { class: 'tl-day-count mono' }, [
              `${events.length} event${events.length === 1 ? '' : 's'}`,
            ]),
          ]),
          el('div', { class: 'tl-items' }, events.map(eventCard)),
        ]);
      }));
    }

    /** One rail card for a single event. */
    function eventCard(event) {
      const lookupable = event.value && KINDS.includes(event.kind);
      const valueNode = event.value
        ? (lookupable
          ? el('button', {
              class: 'tl-value mono', type: 'button',
              title: `Look up as ${KIND_META[event.kind]?.label ?? event.kind}`,
              onclick: () => nav('lookup', { kind: event.kind, target: event.value }),
            }, [event.value])
          : el('span', { class: 'mono strong break-all' }, [event.value]))
        : el('span', { class: 'faint' }, ['(no target)']);

      return el('article', { class: 'tl-item' }, [
        el('div', { class: 'tl-card' }, [
          el('div', { class: 'tl-head' }, [
            event.kind ? kindBadge(event.kind) : null,
            valueNode,
            el('span', { class: 'spacer' }),
            event.when !== null
              ? el('span', { class: 'tl-time muted xs nowrap', title: fmtAgo(event.when) },
                [fmtWhen(event.when)])
              : null,
          ]),
          event.label
            ? el('div', { class: 'tl-desc muted sm' }, [event.label])
            : null,
          event.source
            ? el('div', { class: 'tl-src' }, [srcChip(event.source)])
            : null,
        ]),
      ]);
    }

    await load();
  },
};

/* ---------------------------------------------------------------------- */
/* Export helpers (client-side, from the currently loaded events)          */
/* ---------------------------------------------------------------------- */

/** Download the loaded events as a CSV file. */
function exportCsv(events) {
  if (!events.length) { toastErr('Nothing to export — load some events first'); return; }
  const lines = ['timestamp,kind,target,description,source'];
  for (const e of events) {
    lines.push([
      e.when !== null ? new Date(e.when).toISOString() : '',
      e.kind, e.value, e.label, e.source,
    ].map(csvCell).join(','));
  }
  download(`obscuralens-timeline-${Date.now()}.csv`, lines.join('\r\n'), 'text/csv');
}

/** Download the loaded events as a JSON document. */
function exportJson(events) {
  if (!events.length) { toastErr('Nothing to export — load some events first'); return; }
  download(`obscuralens-timeline-${Date.now()}.json`,
    JSON.stringify({
      exported_at: new Date().toISOString(),
      count: events.length,
      events: events.map((e) => ({
        timestamp: e.when !== null ? new Date(e.when).toISOString() : null,
        kind: e.kind, target: e.value, description: e.label, source: e.source,
      })),
    }, null, 2),
    'application/json');
}

export default view;
