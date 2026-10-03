/**
 * ObscuraLens web UI — dashboard view.
 *
 * Workspace overview: stat cards (database / cache / network / source-health
 * statistics), a lookups-over-time line chart with per-kind sparklines, a
 * kind-distribution donut, a source-health bar card and a recent-activity
 * list. Every section loads independently — one failing endpoint degrades
 * to a compact retry callout instead of breaking the page.
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';
import { navigate } from '../main.js';
import { charts } from '../charts.js';

const { el, icon, kindBadge, fmtInt, fmtBytes, fmtAgo } = ui;

/**
 * Headless import guard: main.js boots against the DOM at import time; under
 * Node (module smoke tests) that rejection is expected and harmless — keep
 * the module graph importable by absorbing it.
 */
if (typeof window === 'undefined' && typeof process !== 'undefined'
  && process.on && !process.__olImportGuard) {
  process.__olImportGuard = true;
  process.on('unhandledRejection', () => {});
}

/* ---------------------------------------------------------------------- */
/* Helpers                                                                 */
/* ---------------------------------------------------------------------- */

/**
 * Read the per-kind colour token.
 *
 * @param {string} kind
 * @returns {string}
 */
function kindColor(kind) {
  try {
    return getComputedStyle(document.documentElement)
      .getPropertyValue(`--kind-${kind}`).trim() || '#2dd4a7';
  } catch {
    return '#2dd4a7';
  }
}

/**
 * Normalise a history timestamp (ISO, epoch s/ms or sqlite "Y-m-d H:M:S").
 *
 * @param {*} value
 * @returns {Date|null}
 */
function parseTs(value) {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Date) return value;
  if (typeof value === 'number') {
    return new Date(value < 1e12 ? value * 1000 : value);
  }
  const s = String(value);
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return new Date(n < 1e12 ? n * 1000 : n);
  }
  const d = new Date(s.includes(' ') && !s.includes('T') ? s.replace(' ', 'T') : s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Extract a flat item list from a /api/history payload (defensive: accepts
 * {items: [...]}, a bare array, or nullish).
 *
 * @param {*} payload
 * @returns {Array<{kind: string, value: string, when: Date|null}>}
 */
function historyItems(payload) {
  const raw = Array.isArray(payload) ? payload
    : Array.isArray(payload?.items) ? payload.items : [];
  return raw.map((row) => ({
    kind: String(row?.kind ?? row?.query_type ?? '').toLowerCase(),
    value: String(row?.value ?? row?.query_value ?? row?.target ?? ''),
    when: parseTs(row?.timestamp ?? row?.created_at ?? row?.time),
  })).filter((row) => row.kind && row.value);
}

/**
 * Local "YYYY-MM-DD" day key.
 *
 * @param {Date} d
 * @returns {string}
 */
function dayKey(d) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/**
 * Build a card with head + body.
 *
 * @param {{icon?: string, title: string, extra?: Node}} spec
 * @param {Node} body
 * @returns {HTMLElement}
 */
function card(spec, body) {
  return el('div', { class: 'card' }, [
    el('div', { class: 'card-head' }, [
      icon(spec.icon ?? 'layers', { size: 16 }),
      el('span', { class: 'card-title' }, [spec.title]),
      el('span', { class: 'grow' }),
      spec.extra ?? null,
    ]),
    el('div', { class: 'card-body' }, [body]),
  ]);
}

/**
 * Compact failure callout with a retry button.
 *
 * @param {string} message
 * @param {function(): void} retry
 * @returns {HTMLElement}
 */
function failCallout(message, retry) {
  return el('div', { class: 'callout danger' }, [
    icon('alert', { size: 16 }),
    el('div', { class: 'grow' }, [
      el('div', { class: 'strong sm' }, ['Could not load this section']),
      el('div', { class: 'muted xs' }, [String(message ?? 'unknown error')]),
    ]),
    el('button', { class: 'btn btn-sm', onclick: retry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]),
  ]);
}

/**
 * Body-placeholder skeletons while a section loads.
 *
 * @param {number} [lines]
 * @returns {HTMLElement}
 */
function cardSkeleton(lines = 5) {
  return el('div', { 'aria-hidden': 'true' }, Array.from({ length: lines }, (_, i) =>
    el('div', {
      class: `skeleton ${i === 0 ? 'skeleton-block' : 'skeleton-text'}`,
      style: { width: `${88 - i * 11}%`, marginBottom: '8px' },
    })));
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'dashboard',
  title: 'Dashboard',
  subtitle: 'Workspace overview',
  icon: 'gauge',
  section: 'workspace',
  order: 0,

  /**
   * Render the dashboard.
   *
   * @param {HTMLElement} root #view container.
   * @param {URLSearchParams} params Route params (unused).
   */
  async render(root, params) {
    void params;

    /* ---- stat card slots ------------------------------------------- */

    const statDefs = [
      { key: 'lookups', label: 'total lookups', hint: 'query history, all time', icon: 'database' },
      { key: 'success', label: 'success rate', hint: 'of stored lookups', icon: 'check' },
      { key: 'distinct', label: 'distinct targets', hint: 'in recent history', icon: 'finger' },
      { key: 'cache', label: 'cache hit ratio', hint: 'network lookups', icon: 'zap' },
      { key: 'requests', label: 'http requests', hint: 'this session', icon: 'globe' },
      { key: 'bytes', label: 'bytes received', hint: 'network transfer', icon: 'download' },
      { key: 'sources', label: 'sources healthy', hint: 'circuit breakers', icon: 'radio' },
    ];
    const statSlots = {};
    const statCards = statDefs.map((def) => {
      const value = el('div', { class: 'stat-value' }, ['…']);
      const hint = el('div', { class: 'stat-hint' }, [def.hint]);
      statSlots[def.key] = { value, hint };
      return el('div', { class: 'card stat-card' }, [
        el('div', { class: 'flex between' }, [
          el('span', { class: 'stat-label' }, [def.label]),
          icon(def.icon, { size: 14 }),
        ]),
        value,
        hint,
      ]);
    });

    /* ---- chart card bodies ----------------------------------------- */

    const trendBody = el('div', { class: 'dash-trend' }, [cardSkeleton(6)]);
    const kindBody = el('div', {}, [cardSkeleton(6)]);
    const sourceBody = el('div', {}, [cardSkeleton(5)]);
    const recentBody = el('div', { class: 'dash-recent' }, [cardSkeleton(6)]);

    const updatedEl = el('span', { class: 'dash-updated faint' }, ['']);

    root.replaceChildren(el('div', { class: 'view-dashboard' }, [
      el('div', { class: 'page-head' }, [
        el('div', { class: 'titles' }, [
          el('h1', { class: 'page-title' }, ['Dashboard']),
          el('p', { class: 'page-desc' }, [
            'Workspace overview — lookup activity, kind mix, source health and recent investigations.',
          ]),
        ]),
        el('div', { class: 'actions' }, [
          updatedEl,
          el('button', {
            class: 'btn btn-sm',
            onclick: () => {
              loadStats();
              loadHistory();
            },
          }, [icon('refresh', { size: 14 }), 'Refresh']),
        ]),
      ]),

      el('div', { class: 'dash-stats' }, statCards),

      el('div', { class: 'dash-charts' }, [
        card({ icon: 'history', title: 'Lookups over time' }, trendBody),
        card({ icon: 'layers', title: 'Kind distribution' }, kindBody),
        card({ icon: 'radio', title: 'Source health — top sources by call volume' }, sourceBody),
        card({ icon: 'clock', title: 'Recent activity' }, recentBody),
      ]),
    ]));

    const touchUpdated = () => {
      updatedEl.textContent = `updated ${new Date().toLocaleTimeString('en-GB')}`;
    };

    /* ---- loader: /api/stats ---------------------------------------- */

    async function loadStats() {
      // stat cards + source-health card
      for (const slot of Object.values(statSlots)) {
        slot.value.textContent = '…';
        slot.value.classList.remove('accent');
      }
      sourceBody.replaceChildren(cardSkeleton(5));
      try {
        const stats = await api.stats();
        const db = stats?.database ?? {};
        const net = stats?.network ?? {};
        const cache = stats?.cache ?? {};
        const healthRows = Array.isArray(stats?.source_health)
          ? stats.source_health : [];

        // total lookups (total_queries, else the sum of queries_by_type)
        const byType = db.queries_by_type ?? {};
        const totalLookups = Number.isFinite(Number(db.total_queries))
          ? Number(db.total_queries)
          : Object.values(byType).reduce((acc, n) => acc + (Number(n) || 0), 0);
        statSlots.lookups.value.textContent = fmtInt(totalLookups) || '—';
        statSlots.lookups.hint.textContent = `${fmtInt(db.recent_queries_7d ?? 0)} in the last 7 days`;

        // success rate
        const successRate = Number(db.success_rate);
        statSlots.success.value.textContent = Number.isFinite(successRate)
          ? `${Math.round(successRate * 10) / 10}%` : '—';

        // cache hit ratio (network counters, else the cache table)
        let hitRate = Number(net.cache_hit_rate);
        if (!Number.isFinite(hitRate)) {
          const total = Number(cache.total) || 0;
          const fresh = Number(cache.fresh) || 0;
          hitRate = total > 0 ? Math.round((fresh / total) * 1000) / 10 : NaN;
        }
        statSlots.cache.value.textContent = Number.isFinite(hitRate)
          ? `${hitRate}%` : '—';
        statSlots.cache.value.classList.add('accent');
        statSlots.cache.hint.textContent = Number.isFinite(Number(net.cache_hits))
          ? `${fmtInt(net.cache_hits)} hits · ${fmtInt(net.cache_misses)} misses` : 'http cache table';

        // requests + bytes
        const requests = Number(net.requests ?? net.total_requests);
        statSlots.requests.value.textContent = Number.isFinite(requests)
          ? fmtInt(requests) : '—';
        statSlots.requests.hint.textContent = [
          Number.isFinite(Number(net.failures)) ? `${fmtInt(net.failures)} failures` : null,
          Number.isFinite(Number(net.timeouts)) ? `${fmtInt(net.timeouts)} timeouts` : null,
        ].filter(Boolean).join(' · ') || 'this session';

        statSlots.bytes.value.textContent = fmtBytes(net.bytes_received);

        // source health summary
        const healthy = healthRows.filter((r) => r?.state === 'healthy').length;
        const tripped = healthRows.filter((r) => r?.state === 'tripped').length;
        const untested = healthRows.filter((r) => r?.state === 'untested').length;
        statSlots.sources.value.textContent = Number.isFinite(healthy)
          ? `${fmtInt(healthy)}/${fmtInt(healthRows.length)}` : '—';
        statSlots.sources.hint.textContent = [
          tripped ? `${tripped} tripped` : null,
          untested ? `${untested} untested` : null,
        ].filter(Boolean).join(' · ') || 'no source failures';

        renderSourceHealth(healthRows);
        touchUpdated();
      } catch (err) {
        for (const slot of Object.values(statSlots)) slot.value.textContent = '—';
        sourceBody.replaceChildren(failCallout(err?.message ?? err, loadStats));
      }
    }

    /**
     * Render the source-health horizontal bars (ok-rate coloured).
     *
     * @param {Array<object>} rows Health rows with ok_count/fail_count/reliability.
     */
    function renderSourceHealth(rows) {
      const top = [...rows]
        .map((r) => ({
          label: String(r.source ?? r.name ?? '?'),
          calls: (Number(r.ok_count) || 0) + (Number(r.fail_count) || 0),
          reliability: Number.isFinite(Number(r.reliability))
            ? Number(r.reliability) : 0,
        }))
        .filter((r) => r.calls > 0)
        .sort((a, b) => b.calls - a.calls)
        .slice(0, 8);
      if (!top.length) {
        sourceBody.replaceChildren(ui.emptyState({
          title: 'No source traffic yet',
          hint: 'Run a few lookups — per-source reliability appears here.',
          icon: 'radio',
        }));
        return;
      }
      const box = el('div', { class: 'chart-box chart-box--bars' },
        [el('canvas')]);
      sourceBody.replaceChildren(box);
      const okColor = css('--ok', '#3ec98f');
      const warnColor = css('--warn', '#f0b429');
      const dangerColor = css('--danger', '#f2637a');
      charts.bars(box.querySelector('canvas'), {
        bars: top.map((r) => ({
          label: r.label,
          value: r.reliability,
          color: r.reliability > 90 ? okColor
            : r.reliability > 60 ? warnColor : dangerColor,
        })),
        horizontal: true,
        valueFormat: (v) => `${Math.round(v)}%`,
        interactive: true,
      });
    }

    /** Minimal cssVar helper scoped to this view. */
    function css(name, fallback) {
      try {
        return getComputedStyle(document.documentElement)
          .getPropertyValue(name).trim() || fallback;
      } catch {
        return fallback;
      }
    }

    /* ---- loader: /api/history ---------------------------------------- */

    async function loadHistory() {
      trendBody.replaceChildren(cardSkeleton(6));
      kindBody.replaceChildren(cardSkeleton(6));
      recentBody.replaceChildren(cardSkeleton(6));
      try {
        const payload = await api.history({ limit: 500 });
        const items = historyItems(payload);

        // ---- stat: distinct targets ----
        statSlots.distinct.value.textContent = fmtInt(
          new Set(items.map((it) => `${it.kind}\u0000${it.value.toLowerCase()}`)).size) || '—';
        statSlots.distinct.hint.textContent = `across ${fmtInt(items.length)} recent records`;

        renderTrend(items);
        renderKindMix(items);
        renderRecent(items);
        touchUpdated();
      } catch (err) {
        statSlots.distinct.value.textContent = '—';
        const callout = failCallout(err?.message ?? err, loadHistory);
        trendBody.replaceChildren(callout);
        kindBody.replaceChildren(cardSkeleton(1));
        recentBody.replaceChildren(cardSkeleton(1));
      }
    }

    /**
     * Lookups-per-day line chart (14d) + per-kind sparkline row (7d).
     *
     * @param {Array<object>} items
     */
    function renderTrend(items) {
      const days = [];
      const keys = new Set();
      for (let i = 13; i >= 0; i -= 1) {
        const d = new Date();
        d.setHours(12, 0, 0, 0);
        d.setDate(d.getDate() - i);
        const key = dayKey(d);
        days.push({ key, label: d.toLocaleDateString('en-GB',
          { weekday: 'short', day: '2-digit' }), count: 0 });
        keys.add(key);
      }
      const byDay = new Map(days.map((d) => [d.key, d]));
      const kindByDay = new Map(); // kind -> Map(dayKey -> count)
      for (const it of items) {
        const d = it.when ?? new Date();
        const key = dayKey(d);
        if (!keys.has(key)) continue;
        byDay.get(key).count += 1;
        if (!kindByDay.has(it.kind)) kindByDay.set(it.kind, new Map());
        const m = kindByDay.get(it.kind);
        m.set(key, (m.get(key) ?? 0) + 1);
      }

      // ---- line chart ----
      const lineBox = el('div', { class: 'chart-box chart-box--line' },
        [el('canvas')]);
      const sparkRow = el('div', { class: 'spark-row' });
      trendBody.replaceChildren(lineBox, el('div', { class: 'mt-3' }, [sparkRow]));

      if (!items.length) {
        charts.line(lineBox.querySelector('canvas'), {
          series: [{ label: 'lookups', points: days.map((d, i) => [i, 0]) }],
          xLabels: days.map((d) => d.label),
          fill: true,
        });
        sparkRow.replaceChildren(el('span', { class: 'muted xs' },
          ['No history yet — run lookups to populate the dashboard.']));
        return;
      }

      charts.line(lineBox.querySelector('canvas'), {
        series: [{ label: 'lookups', points: days.map((d, i) => [i, d.count]) }],
        xLabels: days.map((d) => d.label),
        yTicks: 4,
        fill: true,
        interactive: true,
      });

      // ---- top-5 kind sparklines (7 days) ----
      const kindTotals = new Map();
      for (const [kind, m] of kindByDay) {
        kindTotals.set(kind, [...m.values()].reduce((a, b) => a + b, 0));
      }
      const topKinds = [...kindTotals.entries()]
        .sort((a, b) => b[1] - a[1]).slice(0, 5).map(([kind]) => kind);
      const last7 = days.slice(-7);
      sparkRow.replaceChildren(...topKinds.map((kind) => {
        const m = kindByDay.get(kind);
        const values = last7.map((d) => m.get(d.key) ?? 0);
        const canvasEl = el('canvas');
        const item = el('div', { class: 'spark-item' }, [
          el('div', { class: 'spark-head' }, [
            kindBadge(kind),
            el('span', { class: 'faint mono xs' },
              [String(kindTotals.get(kind))]),
          ]),
          canvasEl,
        ]);
        charts.sparkline(canvasEl, values, { color: kindColor(kind), height: 28 });
        return item;
      }));
    }

    /**
     * Donut of lookups by kind + legend.
     *
     * @param {Array<object>} items
     */
    function renderKindMix(items) {
      const counts = new Map();
      for (const it of items) counts.set(it.kind, (counts.get(it.kind) ?? 0) + 1);
      const entries = [...counts.entries()].sort((a, b) => b[1] - a[1]);
      const box = el('div', { class: 'chart-box chart-box--donut' }, [el('canvas')]);
      const legendBox = el('div', {});
      kindBody.replaceChildren(box, legendBox);
      if (!entries.length) {
        charts.donut(box.querySelector('canvas'), {
          slices: [],
          center: { label: 'lookups', value: 0 },
        });
        charts.legend(legendBox, []);
        return;
      }
      const known = entries.filter(([kind]) => KINDS.includes(kind));
      const other = entries.filter(([kind]) => !KINDS.includes(kind))
        .reduce((acc, [, n]) => acc + n, 0);
      const slices = known.slice(0, 8).map(([kind, n]) => ({
        label: KIND_META[kind]?.label ?? kind,
        value: n,
        color: kindColor(kind),
      }));
      if (other > 0 || known.length > 8) {
        slices.push({
          label: 'other',
          value: other + known.slice(8).reduce((acc, [, n]) => acc + n, 0),
          color: css('--panel-3', '#1a2331'),
        });
      }
      const total = entries.reduce((acc, [, n]) => acc + n, 0);
      charts.donut(box.querySelector('canvas'), {
        slices,
        center: { label: 'lookups', value: ui.fmtInt(total) },
        thickness: 22,
        interactive: true,
      });
      charts.legend(legendBox, slices);
    }

    /**
     * Recent activity list (last 10 history rows).
     *
     * @param {Array<object>} items
     */
    function renderRecent(items) {
      const recent = items.slice(0, 10);
      if (!recent.length) {
        recentBody.replaceChildren(ui.emptyState({
          title: 'No recent lookups',
          hint: 'Investigated targets will appear here as activity.',
          icon: 'clock',
        }));
        return;
      }
      recentBody.replaceChildren(...recent.map((it) => el('button', {
        class: 'dash-recent-item',
        title: `Open ${it.kind} lookup`,
        onclick: () => navigate('lookup', { kind: it.kind, target: it.value }),
      }, [
        el('span', { class: 'dash-recent-when' }, [fmtAgo(it.when)]),
        kindBadge(it.kind),
        el('span', { class: 'dash-recent-target mono' }, [ui.fmtShort(it.value, 42)]),
      ])));
    }

    /* ---- kick off both sections independently ------------------------ */

    await Promise.allSettled([loadStats(), loadHistory()]);
  },
};

export default view;
