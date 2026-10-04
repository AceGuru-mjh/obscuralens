/**
 * ObscuraLens web UI — Profile view (v6.0 part 3).
 *
 * Entity dossier "360": one target's entire stored history aggregated by
 * `GET /api/profile/{kind}/{target}` — first/last seen, query count,
 * success rate, a field-frequency census (what the sources keep saying
 * about this target), a source-count risk trend sparkline and the ten most
 * recent lookups as a timeline.
 *
 * Deep-linkable (`#/profile?kind=ip&target=8.8.8.8`), searchable through
 * the inline kind/target form, and with side actions: re-query now (runs
 * the live tracker and refreshes the dossier), add to the watchlist, and
 * export the raw JSON payload. A target with no history gets a guiding
 * empty state that jumps straight into the lookup workbench.
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';
import { navigate } from '../main.js';
import { charts } from '../charts.js';
import { charts2 } from '../charts2.js';

const {
  el, icon, badge, kindBadge, fmtInt, fmtWhen, fmtAgo, emptyState, download,
  toastOk, toastErr, toastInfo,
} = ui;

/** Field-frequency rows rendered. */
const FIELD_TOP = 15;

/* ---------------------------------------------------------------------- */
/* Helpers                                                                 */
/* ---------------------------------------------------------------------- */

/** Human-readable error text. */
function errText(err) {
  return err instanceof Error ? err.message : String(err ?? 'unknown error');
}

/** Compact failure callout with a retry button. */
function failCallout(message, retry) {
  return el('div', { class: 'callout danger' }, [
    icon('alert', { size: 16 }),
    el('div', { class: 'grow' }, [
      el('div', { class: 'strong sm' }, ['Profile could not be loaded']),
      el('div', { class: 'muted xs' }, [errText(message)]),
    ]),
    el('button', { class: 'btn btn-sm', type: 'button', onclick: retry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]),
  ]);
}

/** Build a kind <select> (defaults to a sensible first kind). */
function kindSelect(selected) {
  const initial = KINDS.includes(selected) ? selected : 'ip';
  return el('select', { class: 'select', 'aria-label': 'Target kind' },
    KINDS.map((k) => el('option', {
      value: k, selected: k === initial,
    }, [KIND_META[k]?.label ?? k])));
}

/** Percent formatter that tolerates junk. */
function fmtPct(value) {
  const n = Number(value);
  return Number.isFinite(n) ? `${Math.round(n * 10) / 10}%` : '—';
}

/** Parse a timestamp-ish value to a Date (null when unparseable). */
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

/** Safe count list out of a risk_trend array. */
function trendValues(trend, key) {
  return (Array.isArray(trend) ? trend : [])
    .map((point) => Number(point?.[key]))
    .filter(Number.isFinite);
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'profile',
  title: 'Profile',
  subtitle: 'Entity dossier',
  icon: 'finger',
  section: 'investigation',
  order: 45,

  /**
   * Mount the profile view.
   *
   * @param {HTMLElement} root #view container.
   * @param {URLSearchParams} params Route params (kind/target).
   */
  async render(root, params = new URLSearchParams()) {
    /* ---- search form ---------------------------------------------------- */

    const paramKind = (params.get('kind') ?? '').toLowerCase();
    const paramTarget = (params.get('target') ?? '').trim();

    const kindSel = kindSelect(paramKind);
    const targetInput = el('input', {
      class: 'input input-mono', type: 'text',
      placeholder: KIND_META[kindSel.value]?.hint ?? 'e.g. 8.8.8.8',
      autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false',
      'aria-label': 'Profile target',
    });
    if (paramTarget) targetInput.value = paramTarget;

    const loadBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('finger', { size: 14 }), 'Load profile',
    ]);

    kindSel.addEventListener('change', () => {
      targetInput.placeholder = KIND_META[kindSel.value]?.hint ?? '';
    });

    targetInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        loadBtn.click();
      }
    });

    /* ---- layout slots ---------------------------------------------------- */

    const resultSlot = el('div', { class: 'stack-lg' }, [emptyState({
      title: 'No profile loaded',
      hint: 'Pick a kind and enter a target — its full stored history is '
        + 'aggregated into a dossier: activity stats, field frequency, risk '
        + 'trend and the most recent lookups.',
      icon: 'finger',
    })]);

    root.replaceChildren(el('div', { class: 'view-profile stack-lg' }, [
      el('div', { class: 'page-head' }, [
        el('div', { class: 'titles' }, [
          el('h1', { class: 'page-title' }, ['Profile']),
          el('p', { class: 'page-desc' }, [
            'Entity dossier — everything ObscuraLens has ever stored about one '
            + 'target, aggregated from the local history database. Nothing is '
            + 're-fetched unless you ask for it.',
          ]),
        ]),
      ]),
      el('div', { class: 'card profile-search-card' }, [
        el('div', { class: 'card-body profile-search' }, [
          el('div', { class: 'field' }, [
            el('label', { class: 'field-label' }, ['Kind']),
            kindSel,
          ]),
          el('div', { class: 'field grow' }, [
            el('label', { class: 'field-label' }, ['Target']),
            targetInput,
          ]),
          loadBtn,
        ]),
      ]),
      resultSlot,
    ]));

    /** The last payload, kept for the JSON export action. */
    let lastPayload = null;
    let lastKind = '';
    let lastTarget = '';

    /* ---- loader ----------------------------------------------------------- */

    loadBtn.addEventListener('click', () => {
      const target = targetInput.value.trim();
      if (!target) {
        toastErr('Enter a target value first');
        targetInput.focus();
        return;
      }
      loadProfile(kindSel.value, target);
    });

    /**
     * Fetch + render one profile; syncs the deep link.
     *
     * @param {string} kind
     * @param {string} target
     */
    async function loadProfile(kind, target) {
      lastKind = kind;
      lastTarget = target;
      loadBtn.disabled = true;
      resultSlot.replaceChildren(ui.loading('Aggregating stored history…'));
      try {
        const payload = await api.profile(kind, target);
        if (!resultSlot.isConnected) return;
        lastPayload = payload;
        try {
          const qs = new URLSearchParams({ kind, target }).toString();
          history.replaceState(null, '', `#/profile?${qs}`);
        } catch { /* hash sync is best-effort */ }
        renderProfile(payload, kind, target);
      } catch (err) {
        lastPayload = null;
        resultSlot.replaceChildren(failCallout(err, () => loadProfile(kind, target)));
      } finally {
        loadBtn.disabled = false;
      }
    }

    /**
     * Render a profile dossier (or its not-found empty state).
     *
     * @param {*} payload /api/profile/{kind}/{target} body.
     * @param {string} kind
     * @param {string} target
     */
    function renderProfile(payload, kind, target) {
      if (!payload || payload.found === false) {
        resultSlot.replaceChildren(emptyState({
          title: 'No stored history for this target',
          hint: `${target} has never been looked up as ${kind} (or nothing was `
            + 'stored). Run a live lookup first — the profile builds itself '
            + 'from every stored result.',
          icon: 'finger',
          action: el('button', {
            class: 'btn btn-primary', type: 'button',
            onclick: () => navigate('lookup', { kind, target }),
          }, [icon('search', { size: 14 }), `Look up ${target} now`]),
        }));
        return;
      }

      /* ---- header + stat cards ---------------------------------- */

      const firstSeen = parseTs(payload.first_seen);
      const lastSeen = parseTs(payload.last_seen);
      const stat = (label, valueNode, hint) => el('div', { class: 'card profile-stat' }, [
        el('div', { class: 'flex between' }, [
          el('span', { class: 'stat-label' }, [label]),
          el('span', { class: 'faint xs' }, [hint]),
        ]),
        valueNode,
      ]);

      const header = el('div', { class: 'card profile-header' }, [
        el('div', { class: 'card-body' }, [
          el('div', { class: 'profile-header-top' }, [
            kindBadge(kind),
            el('span', { class: 'profile-target mono' },
              [ui.fmtShort(target, 90)]),
            el('span', { class: 'grow' }),
            el('button', {
              class: 'btn btn-sm', type: 'button',
              title: 'Copy the target value',
              onclick: async () => {
                try {
                  await navigator.clipboard.writeText(target);
                  toastOk('Target copied');
                } catch {
                  toastErr('Clipboard unavailable');
                }
              },
            }, [icon('copy', { size: 13 }), 'Copy']),
          ]),
          el('div', { class: 'profile-stats' }, [
            stat('first seen',
              el('div', { class: 'stat-value', title: firstSeen?.toISOString() ?? '' },
                [fmtWhen(firstSeen)]),
              fmtAgo(firstSeen)),
            stat('last seen',
              el('div', { class: 'stat-value', title: lastSeen?.toISOString() ?? '' },
                [fmtWhen(lastSeen)]),
              fmtAgo(lastSeen)),
            stat('queries',
              el('div', { class: 'stat-value' }, [fmtInt(payload.query_count)]),
              `${fmtInt(payload.failure_count ?? 0)} failed`),
            stat('success rate',
              el('div', { class: 'stat-value accent' }, [fmtPct(payload.success_rate)]),
              `${fmtInt(payload.success_count ?? 0)} succeeded`),
          ]),
        ]),
      ]);

      /* ---- field frequency ---------------------------------------- */

      const frequency = (Array.isArray(payload.field_frequency)
        ? payload.field_frequency : []).slice(0, FIELD_TOP);
      const freqBox = el('div', { class: 'chart-box chart-box--bars' }, [el('canvas')]);
      const freqCard = el('div', { class: 'card' }, [
        el('div', { class: 'card-head' }, [
          icon('layers', { size: 16 }),
          el('span', { class: 'card-title' },
            [`Field frequency — top ${frequency.length}`]),
          el('span', { class: 'grow' }),
          el('span', { class: 'faint xs' },
            ['how often each field is present across stored results']),
        ]),
        el('div', { class: 'card-body' }, [freqBox]),
      ]);
      charts.bars(freqBox.querySelector('canvas'), {
        bars: frequency.map((row) => ({
          label: String(row?.field ?? '?'),
          value: Number(row?.count) || 0,
          color: freqColor(),
        })),
        horizontal: true,
        valueFormat: (v) => fmtInt(Math.round(v)),
        interactive: true,
      });
      if (!frequency.length) {
        freqBox.replaceChildren(el('span', { class: 'muted xs' },
          ['No field data stored for this target yet.']));
      }

      /* ---- risk trend sparkline ------------------------------------ */

      const okCounts = trendValues(payload.risk_trend, 'sources_ok');
      const failCounts = trendValues(payload.risk_trend, 'sources_failed');
      const trendCanvas = el('canvas');
      if (okCounts.length) {
        charts2.sparkline(trendCanvas, {
          values: okCounts, height: 60, kind, fill: true,
        });
      }
      const trendCard = el('div', { class: 'card' }, [
        el('div', { class: 'card-head' }, [
          icon('shield', { size: 16 }),
          el('span', { class: 'card-title' }, ['Source-count trend']),
          el('span', { class: 'grow' }),
          el('span', { class: 'faint xs' },
            [okCounts.length ? `${okCounts.length} successful lookups` : 'no data']),
        ]),
        el('div', { class: 'card-body profile-trend-body' }, [
          okCounts.length
            ? el('div', { class: 'stack' }, [
              trendCanvas,
              el('span', { class: 'faint xs' }, [
                `sources answering per successful lookup · latest `
                + `${okCounts[okCounts.length - 1]} ok`
                + (failCounts.length ? `, ${failCounts[failCounts.length - 1]} failed` : ''),
              ]),
            ])
            : el('span', { class: 'muted xs' },
              ['No successful lookups with source counts yet.']),
        ]),
      ]);

      /* ---- recent lookups timeline ---------------------------------- */

      const recent = Array.isArray(payload.recent) ? payload.recent : [];
      const recentList = el('div', { class: 'profile-recent' }, recent.length
        ? recent.map((row) => {
          const when = parseTs(row?.timestamp);
          return el('div', { class: 'profile-recent-item' }, [
            el('span', { class: 'profile-recent-when mono xs', title: fmtWhen(when) },
              [fmtWhen(when)]),
            row?.success === true ? badge('ok', 'ok')
              : row?.success === false ? badge('failed', 'danger')
                : badge('unknown', 'muted'),
            el('span', { class: 'faint xs' },
              [`${fmtInt(row?.field_count)} fields`]),
            row?.error ? el('span', {
              class: 'mono xs profile-recent-error', title: String(row.error),
            }, [ui.fmtShort(String(row.error), 64)]) : null,
            el('span', { class: 'grow' }),
            el('button', {
              class: 'btn btn-sm btn-ghost', type: 'button',
              title: 'Open this target in the lookup workbench',
              onclick: () => navigate('lookup', { kind, target }),
            }, [icon('search', { size: 11 }), 're-run']),
          ]);
        })
        : [el('span', { class: 'muted xs' }, ['No recent lookups recorded.'])]);
      const recentCard = el('div', { class: 'card' }, [
        el('div', { class: 'card-head' }, [
          icon('history', { size: 16 }),
          el('span', { class: 'card-title' }, ['Recent lookups']),
          el('span', { class: 'grow' }),
          el('span', { class: 'faint xs' }, ['newest first']),
        ]),
        el('div', { class: 'card-body' }, [recentList]),
      ]);

      /* ---- side actions ---------------------------------------------- */

      const requeryBtn = el('button', { class: 'btn', type: 'button' }, [
        icon('refresh', { size: 14 }), 'Re-query now',
      ]);
      requeryBtn.addEventListener('click', async () => {
        requeryBtn.disabled = true;
        requeryBtn.replaceChildren(ui.loading('Running lookup…'));
        try {
          await api.lookup(kind, target);
          toastOk(`Live lookup for ${ui.fmtShort(target, 32)} stored`);
          loadProfile(kind, target);
        } catch (err) {
          toastErr(`Lookup failed: ${errText(err)}`);
        } finally {
          requeryBtn.disabled = false;
          requeryBtn.replaceChildren(icon('refresh', { size: 14 }), 'Re-query now');
        }
      });

      const watchBtn = el('button', { class: 'btn', type: 'button' }, [
        icon('eye', { size: 14 }), 'Add to watch',
      ]);
      watchBtn.addEventListener('click', async () => {
        watchBtn.disabled = true;
        try {
          const resp = await api.watchAdd({ target, label: kind });
          if (resp && typeof resp === 'object' && resp.error) {
            toastErr(String(resp.error));
          } else {
            toastOk(`${ui.fmtShort(target, 32)} added to the watchlist`);
          }
        } catch (err) {
          toastErr(`Could not watch: ${errText(err)}`);
        } finally {
          watchBtn.disabled = false;
        }
      });

      const exportBtn = el('button', { class: 'btn', type: 'button' }, [
        icon('download', { size: 14 }), 'Export JSON',
      ]);
      exportBtn.addEventListener('click', () => {
        if (!lastPayload) {
          toastInfo('Load a profile first');
          return;
        }
        const name = `profile-${kind}-${target.replace(/[^a-z0-9._-]+/gi, '_')}.json`;
        download(name, JSON.stringify(lastPayload, null, 2), 'application/json');
        toastOk(`Exported ${name}`);
      });

      const actionsCard = el('div', { class: 'card' }, [
        el('div', { class: 'card-head' }, [
          icon('wrench', { size: 16 }),
          el('span', { class: 'card-title' }, ['Actions']),
        ]),
        el('div', { class: 'card-body profile-actions' }, [
          requeryBtn,
          watchBtn,
          exportBtn,
          el('button', {
            class: 'btn btn-ghost', type: 'button',
            onclick: () => navigate('timeline', { target }),
          }, [icon('clock', { size: 14 }), 'Timeline for target']),
          el('button', {
            class: 'btn btn-ghost', type: 'button',
            onclick: () => navigate('lookup', { kind, target }),
          }, [icon('search', { size: 14 }), 'Open in workbench']),
        ]),
      ]);

      /* ---- assemble ---------------------------------------------------- */

      resultSlot.replaceChildren(
        header,
        el('div', { class: 'profile-grid' }, [
          el('div', { class: 'stack-lg' }, [freqCard, trendCard, recentCard]),
          el('div', { class: 'profile-side' }, [actionsCard]),
        ]),
      );
    }

    /** Bar colour for the frequency chart (accent, theme-aware at draw time). */
    function freqColor() {
      try {
        return getComputedStyle(document.documentElement)
          .getPropertyValue('--accent').trim() || '#2dd4a7';
      } catch {
        return '#2dd4a7';
      }
    }

    /* ---- deep-link auto-load --------------------------------------------- */

    if (KINDS.includes(paramKind) && paramTarget) {
      loadProfile(paramKind, paramTarget);
    }
  },
};

export default view;
