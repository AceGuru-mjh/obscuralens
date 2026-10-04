/**
 * ObscuraLens web UI — Analytics view (v6.0 part 3).
 *
 * The analytics workbench: every section consumes one of the Part-2
 * `/api/analytics/*` endpoints and renders it with the charts2 engine:
 *
 *   - 数值分析  — paste comma/space separated numbers → descriptive
 *     statistics card grid (mean/median/stdev/min/max/quartiles/skew),
 *     a box plot and the histogram as a labelled bins table.
 *   - 异常检测  — the same numbers through the anomaly detectors
 *     (ensemble/z-score/IQR/MAD) as a scored table.
 *   - 历史画像  — the enrichment report over stored query history:
 *     kind-frequency treemap, 24-hour activity heatmap, per-source
 *     reliability stacked bars and day-volume anomaly table.
 *   - 文本洞察  — keyword mining table plus script/language fingerprint
 *     cards for a free-text blob.
 *
 * Each section loads and fails independently — a failing endpoint degrades
 * to a retry callout, never a broken page.
 */

import { api } from '../api.js';
import { ui } from '../ui.js';
import { charts2 } from '../charts2.js';

const { el, icon, badge, fmtInt, emptyState } = ui;

/* ---------------------------------------------------------------------- */
/* Helpers                                                                 */
/* ---------------------------------------------------------------------- */

/** Human-readable error text. */
function errText(err) {
  return err instanceof Error ? err.message : String(err ?? 'unknown error');
}

/** Read one CSS custom property. */
function cssVar(name, fallback) {
  try {
    return getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim() || fallback;
  } catch {
    return fallback;
  }
}

/**
 * Parse a free-form numeric blob: commas, spaces, semicolons and newlines
 * all separate values; junk tokens are dropped.
 *
 * @param {string} text
 * @returns {number[]}
 */
function parseValues(text) {
  return String(text ?? '')
    .split(/[\s,;]+/)
    .map((token) => token.trim())
    .filter(Boolean)
    .map(Number)
    .filter((n) => Number.isFinite(n));
}

/**
 * Adaptive number formatting for stat cards (ints stay ints, tiny/huge
 * values go exponential, everything else keeps 3 decimals).
 *
 * @param {*} value
 * @returns {string}
 */
function fmtNum(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '—';
  if (Number.isInteger(n)) return n.toLocaleString('en-US');
  const abs = Math.abs(n);
  if (abs !== 0 && (abs >= 1e6 || abs < 1e-3)) return n.toExponential(2);
  return String(Math.round(n * 1000) / 1000);
}

/** Build a card with head + body (dashboard-style). */
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

/** Compact failure callout with a retry button. */
function failCallout(message, retry) {
  return el('div', { class: 'callout danger' }, [
    icon('alert', { size: 16 }),
    el('div', { class: 'grow' }, [
      el('div', { class: 'strong sm' }, ['Could not load this section']),
      el('div', { class: 'muted xs' }, [errText(message)]),
    ]),
    el('button', { class: 'btn btn-sm', type: 'button', onclick: retry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]),
  ]);
}

/** Inline danger note for form validation feedback. */
function dangerNote(text) {
  return el('div', { class: 'callout danger' }, [
    icon('alert', { size: 14 }),
    el('div', { class: 'grow sm' }, [text]),
  ]);
}

/** Skeleton placeholder while a section loads. */
function cardSkeleton(lines = 5) {
  return el('div', { 'aria-hidden': 'true' }, Array.from({ length: lines }, (_, i) =>
    el('div', {
      class: `skeleton ${i === 0 ? 'skeleton-block' : 'skeleton-text'}`,
      style: { width: `${88 - i * 11}%`, marginBottom: '8px' },
    })));
}

/** Build a <select> with a pre-selected option. */
function selectEl(entries, selected) {
  return el('select', { class: 'select' }, entries.map(([value, label]) =>
    el('option', { value, selected: value === selected }, [label])));
}

/** Label + control + optional hint, stacked. */
function fieldEl(labelText, control, hint) {
  return el('div', { class: 'field' }, [
    el('label', { class: 'field-label' }, [labelText]),
    control,
    hint ? el('span', { class: 'field-hint' }, [hint]) : null,
  ]);
}

/**
 * Compact `key=value` rendering of an anomaly detail dict.
 *
 * @param {*} detail
 * @returns {string}
 */
function detailText(detail) {
  if (detail === null || detail === undefined || detail === '') return '—';
  if (typeof detail !== 'object') return String(detail);
  return Object.entries(detail)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
    .join(' ');
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'analytics',
  title: 'Analytics',
  subtitle: 'Numeric, history & text analysis',
  icon: 'flask',
  section: 'workspace',
  order: 25,

  /**
   * Mount the analytics workbench.
   *
   * @param {HTMLElement} root #view container.
   * @param {URLSearchParams} params Route params (unused).
   */
  async render(root, params) {
    void params;

    /* ---- section 1: numeric analysis --------------------------------- */

    const valuesInput = el('textarea', {
      class: 'textarea analytics-values-input',
      rows: 3, spellcheck: 'false', autocomplete: 'off',
      placeholder: 'e.g. 12, 14, 15, 15, 16, 18, 42  —  commas, spaces or newlines',
      'aria-label': 'Numeric values',
    });
    const binsSelect = selectEl([
      ['6', '6 bins'], ['8', '8 bins'], ['10', '10 bins (default)'],
      ['16', '16 bins'], ['24', '24 bins'],
    ], '10');
    const statsBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('flask', { size: 14 }), 'Analyze',
    ]);
    const statsBody = el('div', { class: 'stack' }, [
      el('div', { class: 'muted sm' }, [
        'Paste numbers above and press Analyze — summary cards, a box plot ',
        'and the histogram bins appear here.',
      ]),
    ]);

    const numericCard = card({ icon: 'flask', title: '数值分析 — numeric analysis' }, el('div', { class: 'stack' }, [
      fieldEl('Values *', valuesInput,
        'Non-numeric tokens are dropped server-side; at least one number is required.'),
      el('div', { class: 'filter-bar' }, [
        el('label', { class: 'monitor-filter analytics-inline-field' }, [
          binsSelect,
        ]),
        el('span', { class: 'spacer' }),
        statsBtn,
      ]),
      statsBody,
    ]));

    statsBtn.addEventListener('click', () => runStats());

    valuesInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        runStats();
      }
    });

    async function runStats() {
      const values = parseValues(valuesInput.value);
      if (!values.length) {
        statsBody.replaceChildren(dangerNote(
          'Enter at least one number (comma, space or newline separated).'));
        return;
      }
      statsBtn.disabled = true;
      statsBody.replaceChildren(ui.loading('Computing summary…'));
      try {
        const payload = await api.analyticsStats(values, {
          bins: Number(binsSelect.value) || 10,
        });
        if (!statsBody.isConnected) return;
        renderStats(payload, values);
      } catch (err) {
        statsBody.replaceChildren(failCallout(err, runStats));
      } finally {
        statsBtn.disabled = false;
      }
    }

    /**
     * Render the stats result: card grid + box plot + bins table.
     *
     * @param {*} payload /api/analytics/stats body.
     * @param {number[]} values The parsed inputs (box plot source).
     */
    function renderStats(payload, values) {
      const summary = payload?.summary ?? {};
      const defs = [
        ['count', 'count', 'plain'],
        ['mean', 'mean', 'plain'],
        ['median', 'median', 'plain'],
        ['stdev', 'stdev', 'plain'],
        ['min', 'min', 'plain'],
        ['max', 'max', 'plain'],
        ['q1', 'Q1', 'plain'],
        ['q3', 'Q3', 'plain'],
        ['skew', 'skew', 'plain'],
      ];
      const statCards = defs.map(([key, label]) => el('div', { class: 'card analytics-stat' }, [
        el('div', { class: 'flex between' }, [
          el('span', { class: 'stat-label' }, [label]),
          icon('cpu', { size: 12 }),
        ]),
        el('div', { class: 'stat-value' }, [fmtNum(summary[key])]),
        el('div', { class: 'stat-hint' }, [key]),
      ]));

      // box plot over the raw values (one group)
      const boxBox = el('div', { class: 'chart-box analytics-box-plot' }, [el('canvas')]);
      charts2.boxplot(boxBox.querySelector('canvas'), {
        groups: [{ label: 'values', values }],
        interactive: true,
      });

      // histogram bins table with proportional bars
      const hist = payload?.histogram ?? {};
      const labels = Array.isArray(hist.bin_labels) ? hist.bin_labels : [];
      const counts = Array.isArray(hist.bin_counts) ? hist.bin_counts : [];
      const maxCount = counts.length ? Math.max(...counts, 1) : 1;
      const binsTable = counts.length
        ? el('div', { class: 'table-wrap analytics-bins' }, [
          el('table', { role: 'table' }, [
            el('thead', {}, [el('tr', {}, [
              el('th', { scope: 'col' }, ['bin']),
              el('th', { scope: 'col' }, ['count']),
              el('th', { scope: 'col', class: 'sortable-false' }, ['distribution']),
            ])]),
            el('tbody', {}, counts.map((count, i) => el('tr', {}, [
              el('td', { class: 'mono xs' }, [labels[i] ?? `bin ${i}`]),
              el('td', { class: 'mono sm' }, [String(count)]),
              el('td', {}, [
                el('div', { class: 'analytics-binbar' }, [
                  el('div', {
                    class: 'analytics-binbar-fill',
                    style: { width: `${Math.max(2, Math.round((count / maxCount) * 100))}%` },
                  }),
                ]),
              ]),
            ]))),
          ]),
        ])
        : el('div', { class: 'muted sm' }, ['No histogram available for this input.']);

      statsBody.replaceChildren(
        el('div', { class: 'analytics-stats' }, statCards),
        el('div', { class: 'analytics-split' }, [
          el('div', { class: 'stack' }, [
            el('div', { class: 'strong sm' }, ['Five-number box plot']),
            boxBox,
          ]),
          el('div', { class: 'stack' }, [
            el('div', { class: 'strong sm' }, [`Histogram — ${counts.length} bins`]),
            binsTable,
          ]),
        ]),
      );
    }

    /* ---- section 2: anomaly detection -------------------------------- */

    const methodSelect = selectEl([
      ['ensemble', 'ensemble (default)'],
      ['zscore', 'z-score'],
      ['iqr', 'IQR fence'],
      ['mad', 'MAD'],
    ], 'ensemble');
    const thresholdInput = el('input', {
      class: 'input', type: 'number', min: '0.5', max: '10', step: '0.5',
      value: '3', 'aria-label': 'Z-score threshold',
      title: 'Cut-off used by the z-score method only',
    });
    const anomalyBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('bug', { size: 14 }), 'Detect anomalies',
    ]);
    const anomalyBody = el('div', { class: 'stack' }, [
      el('div', { class: 'muted sm' }, [
        'Outlier scores for the numbers entered in 数值分析 above — the same ',
        'values, a different lens. z-score is blinded by the very outliers ',
        'it hunts (the mean drags along); MAD stays robust.',
      ]),
    ]);

    const anomalyCard = card({ icon: 'bug', title: '异常检测 — anomaly detection' }, el('div', { class: 'stack' }, [
      el('div', { class: 'filter-bar' }, [
        el('label', { class: 'monitor-filter' }, [methodSelect]),
        el('label', { class: 'monitor-filter' }, [
          thresholdInput, el('span', { class: 'faint xs' }, ['z cut-off']),
        ]),
        el('span', { class: 'spacer' }),
        anomalyBtn,
      ]),
      anomalyBody,
    ]));

    anomalyBtn.addEventListener('click', () => runAnomalies());

    async function runAnomalies() {
      const values = parseValues(valuesInput.value);
      if (!values.length) {
        anomalyBody.replaceChildren(dangerNote(
          'Enter numbers in the 数值分析 box first — both sections share it.'));
        return;
      }
      anomalyBtn.disabled = true;
      anomalyBody.replaceChildren(ui.loading('Scoring outliers…'));
      try {
        const payload = await api.analyticsAnomalies(
          values, methodSelect.value, Number(thresholdInput.value));
        if (!anomalyBody.isConnected) return;
        renderAnomalies(payload);
      } catch (err) {
        anomalyBody.replaceChildren(failCallout(err, runAnomalies));
      } finally {
        anomalyBtn.disabled = false;
      }
    }

    /**
     * Render the anomaly result table.
     *
     * @param {*} payload /api/analytics/anomalies body.
     */
    function renderAnomalies(payload) {
      const rows = Array.isArray(payload?.anomalies) ? payload.anomalies : [];
      const head = el('div', { class: 'flex between' }, [
        el('span', {}, [
          badge(`${payload?.method ?? 'ensemble'}`, 'accent'),
          el('span', { class: 'muted sm' }, [
            ` — ${fmtInt(payload?.anomaly_count ?? rows.length)} of `
            + `${fmtInt(payload?.count ?? '—')} values flagged`,
          ]),
        ]),
      ]);
      if (!rows.length) {
        anomalyBody.replaceChildren(head, emptyState({
          title: 'No anomalies detected',
          hint: 'Every value sits inside this method’s fences — try another '
            + 'detector or looser threshold.',
          icon: 'check',
        }));
        return;
      }
      const table = ui.dataTable({
        columns: [
          { key: 'value', label: 'Value', render: (r) => el('span', { class: 'mono sm' }, [fmtNum(r.value)]) },
          { key: 'score', label: 'Score', render: (r) => el('span', { class: 'mono sm' }, [fmtNum(r.score)]) },
          { key: 'method', label: 'Method', render: (r) => badge(String(r.method ?? ''), 'muted') },
          {
            key: 'detail', label: 'Detail', sortable: false,
            render: (r) => el('span', {
              class: 'mono xs analytics-detail', title: detailText(r.detail),
            }, [detailText(r.detail)]),
          },
        ],
        rows,
        empty: 'No anomalies',
      });
      anomalyBody.replaceChildren(head, table);
    }

    /* ---- section 3: history profile ----------------------------------- */

    const histHeadExtra = el('span', { class: 'muted xs' }, ['']);
    const kindBody = el('div', {}, [cardSkeleton(5)]);
    const hoursBody = el('div', {}, [cardSkeleton(5)]);
    const sourcesBody = el('div', {}, [cardSkeleton(5)]);
    const anomaliesBody = el('div', {}, [cardSkeleton(5)]);

    const historyGrid = el('div', { class: 'analytics-history-grid' }, [
      card({ icon: 'layers', title: 'Kind frequency' }, kindBody),
      card({ icon: 'clock', title: 'Activity by hour (UTC)' }, hoursBody),
      card({ icon: 'radio', title: 'Source reliability — top 10' }, sourcesBody),
      card({ icon: 'alert', title: 'Day-volume anomalies' }, anomaliesBody),
    ]);
    const historyCard = card({ icon: 'history', title: '历史画像 — history profile', extra: histHeadExtra }, historyGrid);

    async function loadHistory() {
      kindBody.replaceChildren(cardSkeleton(4));
      hoursBody.replaceChildren(cardSkeleton(4));
      sourcesBody.replaceChildren(cardSkeleton(4));
      anomaliesBody.replaceChildren(cardSkeleton(4));
      histHeadExtra.textContent = '';
      try {
        const report = await api.analyticsHistory(500);
        const total = Number(report?.total_queries);
        histHeadExtra.textContent = Number.isFinite(total)
          ? `${fmtInt(total)} queries · ${fmtNum(report?.span_days)}d span` : '';
        renderKindFrequency(report?.kind_frequency);
        renderHours(report?.hour_profile);
        renderSources(report?.source_reliability);
        renderHistoryAnomalies(report?.anomalies, report?.hour_profile);
      } catch (err) {
        const callout = failCallout(err, loadHistory);
        kindBody.replaceChildren(callout);
        hoursBody.replaceChildren(cardSkeleton(1));
        sourcesBody.replaceChildren(cardSkeleton(1));
        anomaliesBody.replaceChildren(cardSkeleton(1));
      }
    }

    /** Kind-frequency treemap (kind-coloured cells). */
    function renderKindFrequency(rows) {
      const items = (Array.isArray(rows) ? rows : [])
        .map((r) => ({
          label: String(r?.kind ?? '?'),
          value: Number(r?.count),
          kind: String(r?.kind ?? ''),
        }))
        .filter((i) => Number.isFinite(i.value) && i.value > 0);
      if (!items.length) {
        kindBody.replaceChildren(emptyState({
          title: 'No history yet',
          hint: 'Run a few lookups — the kind mix of your workspace lands here.',
          icon: 'layers',
        }));
        return;
      }
      const box = el('div', { class: 'chart-box analytics-box-treemap' }, [el('canvas')]);
      kindBody.replaceChildren(box);
      charts2.treemap(box.querySelector('canvas'), {
        items, interactive: true,
      });
    }

    /** 24-hour activity profile as a 1×24 heatmap. */
    function renderHours(rows) {
      const counts = (Array.isArray(rows) ? rows : [])
        .map((r) => Number(r?.count))
        .map((n) => (Number.isFinite(n) ? n : 0));
      if (!counts.length) {
        hoursBody.replaceChildren(emptyState({
          title: 'No activity yet',
          hint: 'The UTC hour histogram of your lookups appears here.',
          icon: 'clock',
        }));
        return;
      }
      const cols = counts.map((_, i) => String(i).padStart(2, '0'));
      const box = el('div', { class: 'chart-box analytics-box-heat' }, [el('canvas')]);
      hoursBody.replaceChildren(box);
      charts2.heatmap(box.querySelector('canvas'), {
        rows: ['lookups'],
        cols,
        values: [counts],
        xlabel: 'hour of day (UTC)',
        format: (n) => String(Math.round(n)),
        interactive: true,
      });
    }

    /** Per-source reliability as horizontal ok/failed stacked bars. */
    function renderSources(rows) {
      const top = (Array.isArray(rows) ? rows : [])
        .map((r) => ({
          source: String(r?.source ?? '?'),
          ok: Number(r?.ok) || 0,
          failed: Number(r?.failed) || 0,
        }))
        .filter((r) => r.ok + r.failed > 0)
        .sort((a, b) => (b.ok + b.failed) - (a.ok + a.failed))
        .slice(0, 10);
      if (!top.length) {
        sourcesBody.replaceChildren(emptyState({
          title: 'No source traffic yet',
          hint: 'Reliability per source appears once lookups touch the network.',
          icon: 'radio',
        }));
        return;
      }
      const box = el('div', { class: 'chart-box analytics-box-bars' }, [el('canvas')]);
      sourcesBody.replaceChildren(box);
      charts2.stackedBar(box.querySelector('canvas'), {
        groups: top.map((r) => r.source),
        series: [
          {
            label: 'ok',
            values: top.map((r) => r.ok),
            color: cssVar('--ok', '#3ec98f'),
          },
          {
            label: 'failed',
            values: top.map((r) => r.failed),
            color: cssVar('--danger', '#f2637a'),
          },
        ],
        orient: 'h',
        interactive: true,
      });
    }

    /** Day-volume anomaly table + intraday activity sparkline. */
    function renderHistoryAnomalies(rows, hourProfile) {
      const hits = Array.isArray(rows) ? rows : [];
      const counts = (Array.isArray(hourProfile) ? hourProfile : [])
        .map((r) => Number(r?.count)).filter(Number.isFinite);

      const sparkWrap = el('div', { class: 'stack' }, [
        el('div', { class: 'strong sm' }, ['Intraday rhythm']),
        counts.length
          ? (() => {
            const canvasEl = el('canvas');
            charts2.sparkline(canvasEl, {
              values: counts, height: 34, fill: true,
            });
            return canvasEl;
          })()
          : el('span', { class: 'muted xs' }, ['no activity yet']),
      ]);

      if (!hits.length) {
        anomaliesBody.replaceChildren(el('div', { class: 'stack' }, [
          emptyState({
            title: 'No anomalous days',
            hint: 'Days whose lookup volume breaks the ensemble fences will be flagged here.',
            icon: 'check',
          }),
          sparkWrap,
        ]));
        return;
      }
      const table = ui.dataTable({
        columns: [
          { key: 'value', label: 'Volume', render: (r) => el('span', { class: 'mono sm' }, [fmtNum(r.value)]) },
          { key: 'score', label: 'Score', render: (r) => el('span', { class: 'mono sm' }, [fmtNum(r.score)]) },
          { key: 'method', label: 'Method', render: (r) => badge(String(r.method ?? ''), 'muted') },
          {
            key: 'day', label: 'Day', sortable: false,
            value: (r) => String(r?.detail?.day ?? ''),
            render: (r) => el('span', { class: 'mono xs' }, [String(r?.detail?.day ?? '—')]),
          },
        ],
        rows: hits,
        empty: 'No anomalies',
      });
      anomaliesBody.replaceChildren(el('div', { class: 'stack' }, [table, sparkWrap]));
    }

    /* ---- section 4: text insights ------------------------------------- */

    const textInput = el('textarea', {
      class: 'textarea analytics-text-input',
      rows: 4, spellcheck: 'false', autocomplete: 'off',
      placeholder: 'Paste any text — a note, a paste dump, a ransom message…',
      'aria-label': 'Text to analyse',
    });
    const topSelect = selectEl([
      ['5', 'top 5'], ['10', 'top 10 (default)'], ['15', 'top 15'], ['25', 'top 25'],
    ], '10');
    const textBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('book', { size: 14 }), 'Analyse text',
    ]);
    const keywordsBody = el('div', { class: 'stack' }, [
      el('div', { class: 'muted sm' }, [
        'Stopword-filtered keyword frequencies land here — terms ranked by ',
        'how much of the meaningful text they carry.',
      ]),
    ]);
    const languageBody = el('div', { class: 'stack' }, [
      el('div', { class: 'muted sm' }, [
        'Script census and a stopword-ratio language guess appear here — ',
        'a fingerprint hint, not an identification.',
      ]),
    ]);

    const textCard = card({ icon: 'book', title: '文本洞察 — text insights' }, el('div', { class: 'stack' }, [
      fieldEl('Text *', textInput, 'Minimum one non-space character; both analyses run in parallel.'),
      el('div', { class: 'filter-bar' }, [
        el('label', { class: 'monitor-filter' }, [topSelect]),
        el('span', { class: 'spacer' }),
        textBtn,
      ]),
      el('div', { class: 'analytics-text-grid' }, [
        card({ icon: 'tag', title: 'Keywords' }, keywordsBody),
        card({ icon: 'globe', title: 'Script & language' }, languageBody),
      ]),
    ]));

    textBtn.addEventListener('click', () => runText());

    async function runText() {
      const text = String(textInput.value ?? '');
      if (!text.trim()) {
        keywordsBody.replaceChildren(dangerNote('Enter some text to analyse.'));
        languageBody.replaceChildren(cardSkeleton(2));
        return;
      }
      const top = Number(topSelect.value) || 10;
      textBtn.disabled = true;
      keywordsBody.replaceChildren(ui.loading('Mining keywords…'));
      languageBody.replaceChildren(ui.loading('Fingerprinting scripts…'));
      const results = await Promise.allSettled([
        api.analyticsKeywords(text, top),
        api.analyticsLanguage(text),
      ]);
      if (results[0].status === 'fulfilled') renderKeywords(results[0].value);
      else keywordsBody.replaceChildren(failCallout(results[0].reason, runText));
      if (results[1].status === 'fulfilled') renderLanguage(results[1].value);
      else languageBody.replaceChildren(failCallout(results[1].reason, runText));
      textBtn.disabled = false;
    }

    /** Keyword table with weight bars. */
    function renderKeywords(payload) {
      const rows = Array.isArray(payload?.keywords) ? payload.keywords : [];
      if (!rows.length) {
        keywordsBody.replaceChildren(emptyState({
          title: 'No meaningful terms',
          hint: 'Only stopwords and bare numbers in this text.',
          icon: 'tag',
        }));
        return;
      }
      const maxCount = Math.max(...rows.map((r) => Number(r.count) || 0), 1);
      keywordsBody.replaceChildren(ui.dataTable({
        columns: [
          { key: 'term', label: 'Term', render: (r) => el('span', { class: 'mono sm' }, [String(r.term ?? '')]) },
          { key: 'count', label: 'Count', render: (r) => el('span', { class: 'mono sm' }, [String(r.count ?? 0)]) },
          {
            key: 'weight', label: 'Weight', sortable: false,
            render: (r) => el('div', { class: 'analytics-binbar' }, [
              el('div', {
                class: 'analytics-binbar-fill',
                style: {
                  width: `${Math.max(3, Math.round(((Number(r.count) || 0) / maxCount) * 100))}%`,
                },
              }),
              el('span', { class: 'mono xs analytics-weight' },
                [`${Math.round((Number(r.weight) || 0) * 100)}%`]),
            ]),
          },
        ],
        rows,
        empty: 'No keywords',
      }));
    }

    /** Script + language fingerprint cards. */
    function renderLanguage(payload) {
      const scriptCounts = payload && typeof payload === 'object'
        && payload.script_counts && typeof payload.script_counts === 'object'
        ? Object.entries(payload.script_counts)
          .map(([script, n]) => [script, Number(n) || 0])
          .filter(([, n]) => n > 0)
          .sort((a, b) => b[1] - a[1])
        : [];
      const confidence = Number(payload?.confidence);
      const cards = el('div', { class: 'analytics-lang-cards' }, [
        el('div', { class: 'card analytics-stat' }, [
          el('div', { class: 'flex between' }, [
            el('span', { class: 'stat-label' }, ['dominant script']),
            icon('globe', { size: 12 }),
          ]),
          el('div', { class: 'stat-value' }, [String(payload?.dominant_script ?? '—')]),
          el('div', { class: 'stat-hint' }, ['most characters']),
        ]),
        el('div', { class: 'card analytics-stat' }, [
          el('div', { class: 'flex between' }, [
            el('span', { class: 'stat-label' }, ['language guess']),
            icon('book', { size: 12 }),
          ]),
          el('div', { class: 'stat-value' }, [String(payload?.language_guess ?? 'none')]),
          el('div', { class: 'stat-hint' }, [
            Number.isFinite(confidence)
              ? `${Math.round(confidence * 100)}% stopword ratio` : 'stopword ratio',
          ]),
        ]),
      ]);
      const census = scriptCounts.length
        ? el('div', { class: 'analytics-script-chips' }, scriptCounts.map(([script, n]) =>
          el('span', { class: 'chip chip-src mono xs' }, [`${script} ${fmtInt(n)}`])))
        : el('span', { class: 'muted xs' }, ['no tracked script characters']);
      const hint = payload?.hint
        ? el('div', { class: 'muted xs analytics-lang-hint' }, [String(payload.hint)])
        : null;
      languageBody.replaceChildren(el('div', { class: 'stack' }, [cards, census, hint]));
    }

    /* ---- layout + kick off --------------------------------------------- */

    root.replaceChildren(el('div', { class: 'view-analytics stack-lg' }, [
      el('div', { class: 'page-head' }, [
        el('div', { class: 'titles' }, [
          el('h1', { class: 'page-title' }, ['Analytics']),
          el('p', { class: 'page-desc' }, [
            'Offline statistics, anomaly detection, history profiling and text ',
            'metrics — the same engines the CLI exposes as ',
            'obscuralens analytics, served to the browser. Nothing here leaves ',
            'your machine.',
          ]),
        ]),
        el('div', { class: 'actions' }, [
          el('button', { class: 'btn btn-sm', type: 'button', onclick: loadHistory }, [
            icon('refresh', { size: 14 }), 'Refresh history',
          ]),
        ]),
      ]),
      numericCard,
      anomalyCard,
      historyCard,
      textCard,
    ]));

    await Promise.allSettled([loadHistory()]);
  },
};

export default view;
