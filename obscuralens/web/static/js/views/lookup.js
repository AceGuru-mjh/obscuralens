/**
 * ObscuraLens web UI — lookup view (the flagship intelligence workbench).
 *
 * One command bar does everything: pick a kind (or let the workbench
 * auto-detect it), paste a target, optionally attach the explainable risk
 * score, and fan the query out to every enabled source. Results render as
 * a provenance-tracked fields table, a source health panel, risk signals,
 * threat-intel verdicts (IPs) and the raw JSON. Every lookup is
 * deep-linkable (`#/lookup?kind=ip&target=8.8.8.8`), recorded in a local
 * "recent" strip and shareable as a URL.
 */
import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';
import { navigate } from '../main.js';

const {
  el, icon, badge, kindBadge, srcChip, truthyBadge, copyable,
  dataTable, emptyState, skeleton, jsonBlock, download,
  toastOk, toastWarn, toastErr,
  fmtShort, fmtWhen, fmtAgo, fmtInt, riskLevel,
} = ui;

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

/** localStorage keys (all prefixed "ol-" like the theme key in main.js). */
const KIND_STORE = 'ol-kind';
const RISK_STORE = 'ol-risk';
const RECENT_STORE = 'ol-recent';

/** How many recent lookups the strip keeps. */
const RECENT_MAX = 8;

/** Graph export formats offered by the backend /api/export endpoint. */
const EXPORT_FORMATS = [
  ['graphml', 'GraphML'],
  ['gexf', 'GEXF'],
  ['dot', 'DOT'],
  ['jsonl', 'JSONL'],
  ['csv', 'CSV'],
];

/** MIME types used when downloading exported graphs. */
const EXPORT_MIME = {
  graphml: 'application/xml',
  gexf: 'application/xml',
  dot: 'text/vnd.graphviz',
  jsonl: 'application/x-ndjson',
  csv: 'text/csv',
};

/** Strings longer than this many characters collapse into copyable chips. */
const LONG_VALUE = 90;

/* ------------------------------------------------------------------ */
/* Small helpers                                                        */
/* ------------------------------------------------------------------ */

/**
 * Read a raw value from localStorage (private-mode safe).
 *
 * @param {string} key
 * @param {string} fallback
 * @returns {string}
 */
function readStore(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? fallback : raw;
  } catch { return fallback; }
}

/**
 * Write a raw value to localStorage (private-mode safe).
 *
 * @param {string} key
 * @param {string} value
 */
function writeStore(key, value) {
  try { localStorage.setItem(key, value); } catch { /* ignore */ }
}

/**
 * Read + JSON.parse from localStorage with a type-checked fallback.
 *
 * @param {string} key
 * @param {*} fallback
 * @returns {*}
 */
function readJSON(key, fallback) {
  try {
    const parsed = JSON.parse(localStorage.getItem(key));
    return parsed === null || parsed === undefined ? fallback : parsed;
  } catch { return fallback; }
}

/**
 * JSON.stringify + write to localStorage.
 *
 * @param {string} key
 * @param {*} value
 */
function writeJSON(key, value) {
  writeStore(key, JSON.stringify(value));
}

/**
 * Normalise a kind coming from a URL param or localStorage.
 *
 * @param {*} value
 * @returns {?string} 'auto', a KINDS entry, or null when unknown.
 */
function normalizeKind(value) {
  if (value === 'auto') return 'auto';
  return typeof value === 'string' && KINDS.includes(value) ? value : null;
}

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
 * HTTP status of an ApiError (null when the error is not an ApiError).
 *
 * @param {*} err
 * @returns {?number}
 */
function errStatus(err) {
  return err && typeof err === 'object' && err.name === 'ApiError'
    ? Number(err.status) || 0 : null;
}

/**
 * Filesystem-friendly slug for download filenames.
 *
 * @param {string} target
 * @returns {string}
 */
function slug(target) {
  const s = String(target ?? '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  return s || 'target';
}

/**
 * Turn a snake_case identifier into a readable label ("spamhaus_drop" →
 * "Spamhaus drop").
 *
 * @param {*} value
 * @returns {string}
 */
function prettifyId(value) {
  const s = String(value ?? '').replace(/[_-]+/g, ' ').trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '—';
}

/**
 * Set a button into / out of a busy state and swap its trailing label.
 *
 * @param {HTMLButtonElement} btn
 * @param {boolean} on
 * @param {string} [label] Replacement label while busy.
 */
function busy(btn, on, label) {
  if (!btn || !btn.isConnected) return;
  btn.disabled = on;
  if (on && label) {
    const last = btn.lastChild;
    if (last && last.nodeType === Node.TEXT_NODE) last.textContent = label;
  }
}

/* ------------------------------------------------------------------ */
/* Recent lookups (localStorage strip)                                  */
/* ------------------------------------------------------------------ */

/**
 * Load the recent-lookup list, defensively filtered to valid entries.
 *
 * @returns {Array<{kind: string, target: string, ts: number}>}
 */
function loadRecent() {
  const list = readJSON(RECENT_STORE, []);
  if (!Array.isArray(list)) return [];
  return list.filter((item) => item && typeof item === 'object'
    && typeof item.kind === 'string' && typeof item.target === 'string');
}

/**
 * Record one lookup at the head of the recent list (deduplicated, capped).
 *
 * @param {string} kind
 * @param {string} target
 */
function pushRecent(kind, target) {
  const entry = { kind: String(kind), target: String(target), ts: Date.now() };
  const list = loadRecent()
    .filter((item) => !(item.kind === entry.kind && item.target === entry.target));
  list.unshift(entry);
  writeJSON(RECENT_STORE, list.slice(0, RECENT_MAX));
}

/* ------------------------------------------------------------------ */
/* Client-side target detection (informational hints only)              */
/* ------------------------------------------------------------------ */

/**
 * Lightweight recognisers used for the "auto" hint text. Purely cosmetic —
 * the backend always has the final word on validation.
 */
const DETECT_PATTERNS = [
  ['cve',    /^CVE-\d{4}-\d{4,8}$/i],
  ['hash',   /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i],
  ['mac',    /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$|^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$|^([0-9a-f]{2}){6}$/i],
  ['imei',   /^\d{15}(?:\d{2})?$/],
  ['iban',   /^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/i],
  ['ip',     /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$/i],
  ['email',  /^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$/],
  ['url',    /^[a-z][a-z0-9+.-]*:\/\//i],
  ['crypto', /^(?:(?:bc1|[13])[a-hj-np-z0-9]{25,62}|0x[a-f0-9]{40}|[48][1-9A-HJ-NP-Za-km-z]{51})$/i],
  ['phone',  /^\+?\d[\d\s().-]{6,}$/],
  ['asn',    /^AS\d{1,10}$/i],
  ['coords', /^-?\d{1,3}(?:\.\d+)?\s*,\s*-?\d{1,3}(?:\.\d+)?$/],
  ['domain', /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i],
];

/**
 * Best-effort local kind detection.
 *
 * @param {string} value
 * @returns {?string}
 */
function detectKindLocal(value) {
  const v = String(value ?? '').trim();
  if (!v) return null;
  for (const [kind, pattern] of DETECT_PATTERNS) {
    if (pattern.test(v)) return kind;
  }
  return null;
}

/**
 * Hint line shown under the target input for "auto" mode.
 *
 * @param {string} value
 * @returns {string}
 */
function detectHint(value) {
  const kind = detectKindLocal(value);
  if (!kind) return 'Auto-detect — start typing a target and the workbench will classify it';
  return `Auto-detect — looks like ${KIND_META[kind]?.label ?? kind}`;
}

/* ------------------------------------------------------------------ */
/* Field value rendering                                                */
/* ------------------------------------------------------------------ */

/**
 * Render one `result.info` value following the workbench rules:
 * booleans → verdict badges, nullish → em dash, long strings → copyable
 * chips, arrays → comma-joined (long items copyable), objects → compact
 * monospace JSON.
 *
 * @param {*} value
 * @returns {Node}
 */
function renderFieldValue(value) {
  if (value === null || value === undefined) {
    return el('span', { class: 'faint' }, ['—']);
  }
  if (typeof value === 'boolean') {
    return truthyBadge(value);
  }
  if (typeof value === 'number') {
    return el('span', { class: 'mono field-value' }, [fmtInt(value)]);
  }
  if (typeof value === 'string') {
    if (!value) return el('span', { class: 'faint' }, ['—']);
    if (value.length > LONG_VALUE) return copyable(value, { short: 64 });
    return el('span', { class: 'mono field-value', title: value }, [value]);
  }
  if (Array.isArray(value)) {
    if (!value.length) return el('span', { class: 'faint' }, ['—']);
    const wrap = el('span', { class: 'field-array' }, []);
    value.forEach((item, idx) => {
      if (idx) wrap.append(document.createTextNode(', '));
      if (typeof item === 'string') {
        wrap.append(item.length > LONG_VALUE ? copyable(item, { short: 48 })
          : el('span', { class: 'mono field-value', title: item }, [item]));
      } else if (item !== null && item !== undefined && typeof item === 'object') {
        const text = JSON.stringify(item);
        wrap.append(text.length > LONG_VALUE ? copyable(text, { short: 48 })
          : el('span', { class: 'mono xs', title: text }, [text]));
      } else {
        wrap.append(document.createTextNode(String(item)));
      }
    });
    return wrap;
  }
  // Plain object → compact JSON
  const text = JSON.stringify(value) ?? '—';
  if (text.length > LONG_VALUE) return copyable(text, { short: 64 });
  return el('span', { class: 'mono xs', title: text }, [text]);
}

/* ------------------------------------------------------------------ */
/* Result panels                                                        */
/* ------------------------------------------------------------------ */

/**
 * The provenance-tracked fields table (Field | Value | Sources).
 *
 * @param {object} result Tracker result dict.
 * @returns {Node}
 */
function fieldsCard(result) {
  const info = (result && typeof result.info === 'object' && result.info !== null
    && !Array.isArray(result.info)) ? result.info : {};
  const fieldSources = (result && typeof result.field_sources === 'object'
    && result.field_sources !== null && !Array.isArray(result.field_sources))
    ? result.field_sources : {};

  const rows = Object.entries(info)
    .filter(([, value]) => value !== undefined)
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
    .map(([key, value]) => {
      let sources = fieldSources[key];
      if (typeof sources === 'string') sources = [sources];
      if (!Array.isArray(sources)) sources = [];
      return { key, value, sources };
    });

  const table = dataTable({
    columns: [
      {
        key: 'key', label: 'Field',
        value: (row) => row.key,
        render: (row) => el('span', { class: 'field-key', title: row.key }, [row.key]),
      },
      {
        key: 'value', label: 'Value', sortable: false,
        render: (row) => renderFieldValue(row.value),
      },
      {
        key: 'sources', label: 'Sources', sortable: false,
        render: (row) => (row.sources.length
          ? el('span', { class: 'src-chip-row' },
            row.sources.map((s) => srcChip(String(s))))
          : el('span', { class: 'faint' }, ['—'])),
      },
    ],
    rows,
    empty: 'No fields were returned for this target',
  });

  return el('section', { class: 'card fields-card', 'aria-label': 'Fields' }, [
    el('div', { class: 'card-head' }, [
      icon('layers'),
      el('span', { class: 'card-title' }, ['Fields']),
      el('span', { class: 'grow' }),
      el('span', { class: 'badge badge-muted' }, [`${rows.length}`]),
    ]),
    el('div', { class: 'card-body fields-table' }, [table]),
  ]);
}

/**
 * Source health panel: chips for every source that answered or failed.
 *
 * @param {object} result
 * @returns {Node}
 */
function sourcesCard(result) {
  const rawOk = result?.sources_ok;
  const okList = Array.isArray(rawOk) ? rawOk
    : (rawOk && typeof rawOk === 'object' ? Object.keys(rawOk) : []);
  const failed = (result?.sources_failed && typeof result.sources_failed === 'object'
    && !Array.isArray(result.sources_failed)) ? result.sources_failed : {};

  const chipRow = (items) => el('span', { class: 'src-chip-row wrap' }, items);

  const okChips = okList.map((name) => srcChip(String(name)));
  const failChips = Object.entries(failed).map(([name, reason]) => {
    const chip = srcChip(String(name), true);
    chip.title = typeof reason === 'string' && reason ? reason : 'source failed';
    return chip;
  });

  const body = el('div', { class: 'card-body stack' }, []);
  if (!okChips.length && !failChips.length) {
    body.append(el('p', { class: 'muted sm' }, ['No source health data in this response.']));
  } else {
    body.append(
      el('div', { class: 'field' }, [
        el('span', { class: 'field-label' }, [`Answered · ${okChips.length}`]),
        chipRow(okChips),
      ]),
      failChips.length ? el('div', { class: 'field' }, [
        el('span', { class: 'field-label' }, [`Failed · ${failChips.length}`]),
        chipRow(failChips),
      ]) : null,
    );
  }

  return el('section', { class: 'card', 'aria-label': 'Sources' }, [
    el('div', { class: 'card-head' }, [
      icon('radio'),
      el('span', { class: 'card-title' }, ['Sources']),
      el('span', { class: 'grow' }),
      el('span', { class: 'badge badge-ok' }, [`${okChips.length}`]),
      failChips.length ? el('span', { class: 'badge badge-danger' }, [`${failChips.length}`]) : null,
    ]),
    body,
  ]);
}

/**
 * Explainable risk panel — big score, level badge, progress bar and the
 * signal table. Renders defensively whatever the backend attached.
 *
 * @param {*} risk The `result.risk` block.
 * @returns {?Node} Null when there is nothing to render.
 */
function riskCard(risk) {
  if (!risk || typeof risk !== 'object' || Array.isArray(risk)) return null;

  const scoreNum = Number(risk.score);
  const lvl = riskLevel(Number.isFinite(scoreNum) ? scoreNum : null);
  const variant = (lvl.cls || '').replace('badge-', '') || 'muted';
  const levelText = risk.level ?? risk.verdict ?? lvl.label ?? 'unknown';
  const progressCls = {
    danger: 'lv-danger', warn: 'lv-warn', info: 'lv-info', ok: 'lv-ok',
  }[variant] ?? '';

  const signals = Array.isArray(risk.signals)
    ? risk.signals.filter((s) => s && typeof s === 'object') : [];

  const body = el('div', { class: 'card-body stack' }, [
    el('div', { class: 'risk-score' }, [
      el('span', {
        class: 'risk-score-num',
        title: 'Heuristic risk score, 0 (clean) to 100 (high risk)',
      }, [Number.isFinite(scoreNum) ? String(Math.round(scoreNum)) : '—']),
      badge(levelText, variant),
      el('span', { class: 'progress', role: 'progressbar',
        'aria-valuemin': '0', 'aria-valuemax': '100',
        'aria-valuenow': String(Math.round(lvl.pct ?? 0)),
        'aria-label': 'Risk score' }, [
        el('span', {
          class: `progress-bar ${progressCls}`,
          style: { width: `${Math.max(0, Math.min(100, lvl.pct ?? 0))}%` },
        }),
      ]),
    ]),
    typeof risk.summary === 'string' && risk.summary
      ? el('p', { class: 'muted sm' }, [risk.summary]) : null,
  ]);

  if (signals.length) {
    body.append(dataTable({
      columns: [
        {
          key: 'name', label: 'Signal',
          value: (row) => row.name,
          render: (row) => el('span', { class: 'strong sm' }, [row.name]),
        },
        {
          key: 'weight', label: 'Score',
          value: (row) => row.weight,
          render: (row) => el('span', { class: 'mono sm' }, [
            row.weight === null ? '—' : `+${row.weight}`,
          ]),
        },
        {
          key: 'detail', label: 'Detail', sortable: false,
          render: (row) => el('span', { class: 'muted sm', title: row.detail }, [row.detail]),
        },
      ],
      rows: signals.map((signal, idx) => ({
        name: typeof signal.label === 'string' && signal.label
          ? signal.label : prettifyId(signal.id ?? `signal ${idx + 1}`),
        weight: Number.isFinite(Number(signal.weight))
          ? Number(signal.weight)
          : (Number.isFinite(Number(signal.score)) ? Number(signal.score) : null),
        detail: typeof signal.detail === 'string' ? signal.detail
          : (signal.detail === null || signal.detail === undefined ? '—' : String(signal.detail)),
      })),
      empty: 'No risk signals',
    }));
  } else {
    body.append(el('p', { class: 'faint xs' }, ['No individual signals contributed to this score.']));
  }

  return el('section', { class: 'card', 'aria-label': 'Risk assessment' }, [
    el('div', { class: 'card-head' }, [
      icon('gauge'),
      el('span', { class: 'card-title' }, ['Risk']),
      el('span', { class: 'grow' }),
      el('span', { class: `badge ${lvl.cls}` }, ['0–100']),
    ]),
    body,
  ]);
}

/**
 * Inline error block with a retry button (used inside async panels).
 *
 * @param {*} err
 * @param {() => void} retry
 * @param {string} [title]
 * @returns {Node}
 */
function errRetryBlock(err, retry, title = 'Request failed') {
  return el('div', { class: 'stack' }, [
    el('div', { class: 'callout danger', role: 'alert' }, [
      icon('alert'),
      el('div', {}, [
        el('strong', {}, [title]),
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
 * Threat-intel panel for IP targets: Tor exit status, relay metadata and
 * blocklist feed verdicts. Loads lazily and retries inline on failure.
 *
 * @param {string} target
 * @returns {Node}
 */
function intelCard(target) {
  const body = el('div', { class: 'card-body stack' }, [
    el('div', { 'aria-hidden': 'true' }, [1, 2, 3].map(() =>
      el('div', { class: 'skeleton skeleton-text', style: { width: '82%' } }))),
  ]);

  const card = el('section', { class: 'card', 'aria-label': 'Threat intelligence' }, [
    el('div', { class: 'card-head' }, [
      icon('shield'),
      el('span', { class: 'card-title' }, ['Threat intel']),
    ]),
    body,
  ]);

  let token = 0;
  async function load() {
    const my = ++token;
    try {
      const data = await api.intel(target);
      if (my !== token || !body.isConnected) return;
      body.replaceChildren(...intelContent(data));
    } catch (err) {
      if (my !== token || !body.isConnected) return;
      body.replaceChildren(errRetryBlock(err, load, 'Could not load threat intel'));
    }
  }
  load();
  return card;
}

/**
 * Content builder for the threat-intel panel (defensive against every
 * payload shape the /api/intel endpoint has produced).
 *
 * @param {*} data
 * @returns {Node[]}
 */
function intelContent(data) {
  const nodes = [];
  const feeds = (data && typeof data.feeds === 'object' && !Array.isArray(data.feeds))
    ? data.feeds : {};

  if (feeds.disabled) {
    nodes.push(el('div', { class: 'callout warn' }, [
      icon('alert'),
      el('div', { class: 'sm' }, ['Threat-intel feeds are disabled in the runtime settings '
        + '(\u200bapp.feeds_enabled = false).']),
    ]));
    return nodes;
  }

  const torExit = data?.tor_exit === true;
  const listed = Number(feeds.listed_count);
  nodes.push(el('div', { class: 'flex gap-2 wrap' }, [
    torExit
      ? badge('Tor exit node', 'danger', { icon: 'shield' })
      : badge('not a Tor exit', 'ok'),
    Number.isFinite(listed) && listed > 0
      ? badge(`listed on ${listed} feed${listed === 1 ? '' : 's'}`, 'danger', { icon: 'alert' })
      : badge('not on blocklists', 'ok'),
  ]));

  const feedEntries = Object.entries(feeds)
    .filter(([name, value]) => !['relay', 'listed_count', 'disabled', 'tor'].includes(name)
      && typeof value === 'boolean');
  if (feedEntries.length) {
    nodes.push(el('div', {}, feedEntries.map(([name, listedNow]) =>
      el('div', { class: 'intel-feed-row' }, [
        el('span', { class: 'intel-feed-name' }, [prettifyId(name)]),
        listedNow ? badge('listed', 'danger') : badge('clean', 'ok'),
      ]))));
  }

  const relay = data?.relay;
  if (relay && typeof relay === 'object' && relay.is_relay) {
    nodes.push(ui.kvGrid([
      ['Relay nickname', relay.nickname ?? '—'],
      ['Fingerprint', relay.fingerprint
        ? { node: copyable(String(relay.fingerprint), { short: 20 }) } : '—'],
      ['Flags', Array.isArray(relay.flags) && relay.flags.length
        ? relay.flags.join(', ') : '—'],
      ['Bandwidth', relay.bandwidth ?? '—'],
      ['First seen', relay.first_seen ? fmtWhen(relay.first_seen) : '—'],
      ['Last seen', relay.last_seen ? fmtWhen(relay.last_seen) : '—'],
    ]));
  }
  return nodes;
}

/* ------------------------------------------------------------------ */
/* Case picker modal                                                    */
/* ------------------------------------------------------------------ */

/**
 * Open the "Add to case" modal: choose an existing case or create one,
 * then POST the indicator via api.caseAddItem.
 *
 * @param {string} kind Effective kind of the target.
 * @param {string} target
 */
async function openCaseModal(kind, target) {
  let caseList = [];
  try {
    const res = await api.cases();
    const list = Array.isArray(res) ? res : (res?.cases ?? []);
    caseList = list.filter((c) => c && typeof c === 'object' && c.id !== undefined
      && (c.status ?? 'active') !== 'archived');
  } catch (err) {
    toastErr(`Could not load cases: ${errText(err)}`);
    return;
  }

  const select = el('select', { class: 'select', 'aria-label': 'Destination case' });
  for (const c of caseList) {
    const label = `${c.name ?? `case #${c.id}`}`
      + (Number.isFinite(Number(c.item_count)) ? ` · ${c.item_count} items` : '');
    select.append(el('option', { value: String(c.id) }, [label]));
  }
  select.append(el('option', { value: '__new__' }, ['Create a new case…']));
  if (!caseList.length) select.value = '__new__';

  const nameInput = el('input', {
    class: 'input', type: 'text', 'aria-label': 'New case name',
    placeholder: 'Case name, e.g. Phishing campaign Q3',
  });
  const descInput = el('input', {
    class: 'input', type: 'text', 'aria-label': 'New case description',
    placeholder: 'Short description (optional)',
  });
  const newBlock = el('div', { class: `stack${select.value === '__new__' ? '' : ' hidden'}` }, [
    el('div', { class: 'field' }, [el('span', { class: 'field-label' }, ['Name']), nameInput]),
    el('div', { class: 'field' }, [el('span', { class: 'field-label' }, ['Description']), descInput]),
  ]);
  select.addEventListener('change', () => {
    newBlock.classList.toggle('hidden', select.value !== '__new__');
  });

  const noteInput = el('input', {
    class: 'input', type: 'text', 'aria-label': 'Item note',
    placeholder: 'Optional note attached to the item',
  });

  const saveBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('check'), 'Add to case',
  ]);
  saveBtn.addEventListener('click', async () => {
    try {
      busy(saveBtn, true, 'Adding…');
      let caseId;
      let caseName;
      if (select.value === '__new__') {
        const name = nameInput.value.trim();
        if (!name) {
          busy(saveBtn, false);
          toastWarn('Give the new case a name first');
          nameInput.focus();
          return;
        }
        const created = await api.caseCreate({ name, description: descInput.value.trim() });
        caseId = Number(created?.id ?? created?.case?.id);
        caseName = created?.name ?? name;
      } else {
        caseId = Number(select.value);
        caseName = caseList.find((c) => Number(c.id) === caseId)?.name ?? `case #${caseId}`;
      }
      if (!Number.isFinite(caseId)) throw new Error('invalid case id');

      const resp = await api.caseAddItem(caseId, {
        kind, value: target, note: noteInput.value.trim(),
      });
      if (resp && typeof resp === 'object' && resp.error) {
        toastErr(String(resp.error));
        busy(saveBtn, false);
        return;
      }
      toastOk(`Added to ${caseName}`, { title: 'Case updated' });
      closeRef?.();
    } catch (err) {
      toastErr(errText(err));
      busy(saveBtn, false);
    }
  });

  let closeRef = null;
  closeRef = ui.modal({
    title: 'Add to case',
    body: el('div', { class: 'stack' }, [
      el('div', { class: 'flex gap-2 wrap' }, [
        el('span', { class: 'muted sm' }, ['Indicator:']),
        kindBadge(kind),
        el('span', { class: 'mono sm strong', title: target }, [fmtShort(target, 56)]),
      ]),
      el('div', { class: 'field' }, [el('span', { class: 'field-label' }, ['Case']), select]),
      newBlock,
      el('div', { class: 'field' }, [el('span', { class: 'field-label' }, ['Note']), noteInput]),
    ]),
    foot: [
      el('button', {
        class: 'btn btn-ghost', type: 'button',
        onclick: () => closeRef?.(),
      }, ['Cancel']),
      saveBtn,
    ],
  });
}

/* ------------------------------------------------------------------ */
/* Result hero                                                          */
/* ------------------------------------------------------------------ */

/**
 * The result header card: identity, stats and the full action row
 * (re-run, copy/download JSON, graph export, watchlist, case).
 *
 * @param {object} opts
 * @param {string} opts.kind Effective (detected) kind.
 * @param {string} opts.target
 * @param {object} opts.result
 * @param {boolean} opts.autoDetected True when the kind came from auto-detect.
 * @param {number} opts.tookMs Round-trip duration in milliseconds.
 * @param {() => void} opts.onRerun Re-run handler.
 * @returns {Node}
 */
function resultHeroCard({ kind, target, result, autoDetected, tookMs, onRerun }) {
  const info = (result && typeof result.info === 'object' && result.info !== null
    && !Array.isArray(result.info)) ? result.info : {};
  const rawOk = result?.sources_ok;
  const okCount = Array.isArray(rawOk) ? rawOk.length
    : (rawOk && typeof rawOk === 'object' ? Object.keys(rawOk).length : 0);
  const failCount = (result?.sources_failed && typeof result.sources_failed === 'object'
    && !Array.isArray(result.sources_failed)) ? Object.keys(result.sources_failed).length : 0;
  const fieldCount = Number.isFinite(Number(result?.field_count))
    ? Number(result.field_count) : Object.keys(info).length;
  const success = result?.success;

  const stat = (value, label) => el('div', { class: 'hero-stat' }, [
    el('span', { class: 'hero-stat-value' }, [value]),
    el('span', { class: 'hero-stat-label' }, [label]),
  ]);

  /* ---- actions ---- */
  const jsonText = () => JSON.stringify(result, null, 2);

  const rerunBtn = el('button', { class: 'btn btn-sm', type: 'button', onclick: onRerun }, [
    icon('refresh', { size: 13 }), 'Re-run',
  ]);

  const copyBtn = el('button', {
    class: 'btn btn-sm', type: 'button',
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(jsonText());
        toastOk('Response JSON copied to clipboard');
      } catch { toastErr('Clipboard unavailable'); }
    },
  }, [icon('copy', { size: 13 }), 'Copy JSON']);

  const downloadBtn = el('button', {
    class: 'btn btn-sm', type: 'button',
    onclick: () => {
      download(`${slug(target)}-${kind}.json`, jsonText(), 'application/json');
      toastOk('Response JSON downloaded');
    },
  }, [icon('download', { size: 13 }), 'Download JSON']);

  const exportSelect = el('select', {
    class: 'select', 'aria-label': 'Graph export format',
    title: 'Investigation graph export format',
  }, EXPORT_FORMATS.map(([value, label]) =>
    el('option', { value }, [label])));
  const exportBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
    icon('external', { size: 13 }), 'Export graph',
  ]);
  exportBtn.addEventListener('click', async () => {
    const fmt = exportSelect.value;
    busy(exportBtn, true, 'Exporting…');
    try {
      const resp = await api.graphExport(fmt, target);
      const text = resp && typeof resp.graph === 'string' && resp.graph
        ? resp.graph : JSON.stringify(resp, null, 2);
      download(`${slug(target)}.${fmt}`, text, EXPORT_MIME[fmt] ?? 'text/plain');
      const entities = Number(resp?.entities);
      const suffix = Number.isFinite(entities)
        ? ` · ${entities} entities, ${Number(resp?.links)} links` : '';
      toastOk(`Graph exported as ${fmt}${suffix}`);
    } catch (err) {
      toastErr(errText(err));
    } finally {
      busy(exportBtn, false);
    }
  });

  const watchBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
    icon('eye', { size: 13 }), 'Watch',
  ]);
  watchBtn.addEventListener('click', async () => {
    busy(watchBtn, true, 'Adding…');
    try {
      const resp = await api.watchAdd({ target, label: kind });
      if (resp && typeof resp === 'object' && resp.error) {
        toastErr(String(resp.error));
      } else {
        toastOk(`${fmtShort(target, 32)} added to the watchlist`);
      }
    } catch (err) {
      toastErr(errText(err));
    } finally {
      busy(watchBtn, false);
    }
  });

  const caseBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
    icon('folder', { size: 13 }), 'Add to case',
  ]);
  caseBtn.addEventListener('click', () => openCaseModal(kind, target));

  return el('section', { class: 'card lookup-hero-card', 'aria-label': 'Result summary' }, [
    el('div', { class: 'card-body' }, [
      el('div', { class: 'lookup-hero-top' }, [
        kindBadge(kind),
        autoDetected ? badge('auto-detected', 'accent', { icon: 'zap' }) : null,
        success === true ? badge('success', 'ok')
          : success === false ? badge('failed', 'danger')
            : badge('unknown', 'muted'),
        el('span', { class: 'grow' }),
        el('span', { class: 'lookup-hero-target' }, [copyable(target, { short: 120 })]),
      ]),
      el('div', { class: 'lookup-hero-stats' }, [
        stat(String(fieldCount), 'fields'),
        stat(String(okCount), 'sources ok'),
        stat(String(failCount), 'sources failed'),
        Number.isFinite(tookMs) && tookMs >= 0
          ? stat(`${(tookMs / 1000).toFixed(1)}s`, 'round trip') : null,
      ]),
      el('div', { class: 'lookup-hero-actions' }, [
        rerunBtn, copyBtn, downloadBtn,
        el('span', { class: 'export-group' }, [exportSelect, exportBtn]),
        watchBtn, caseBtn,
      ]),
    ]),
  ]);
}

/* ------------------------------------------------------------------ */
/* View                                                                 */
/* ------------------------------------------------------------------ */

export const view = {
  id: 'lookup',
  title: 'Lookup',
  subtitle: 'Multi-source intelligence workbench',
  icon: 'search',
  section: 'workspace',
  order: 10,

  /**
   * Mount the workbench.
   *
   * @param {HTMLElement} root Empty <main> container.
   * @param {URLSearchParams} [params] Hash route params (kind/target/risk).
   */
  async render(root, params = new URLSearchParams()) {
    if (!root) return;

    /* ---- persisted + deep-linked state ---------------------------- */
    const paramKind = normalizeKind(params.get('kind'));
    const storedKind = normalizeKind(readStore(KIND_STORE, 'auto'));
    let currentKind = paramKind ?? storedKind ?? 'auto';

    const paramTarget = (params.get('target') ?? '').trim();
    const riskParam = params.get('risk');
    const riskOn = riskParam === null
      ? readStore(RISK_STORE, '0') === '1'
      : ['1', 'true', 'yes', 'on'].includes(String(riskParam).toLowerCase());

    /* ---- command bar ---------------------------------------------- */
    const pillsRow = el('div', {
      class: 'kind-pills', role: 'group', 'aria-label': 'Target kind',
    }, ['auto', ...KINDS].map((k) => el('button', {
      class: 'btn', type: 'button', 'data-kind': k,
      'aria-pressed': 'false',
      onclick: () => setKind(k),
    }, [k === 'auto' ? 'Auto-detect' : (KIND_META[k]?.label ?? k)])));

    const targetInput = el('input', {
      class: 'input input-mono', type: 'text', id: 'lookup-target',
      autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false',
      'aria-label': 'Lookup target',
      placeholder: currentKind === 'auto'
        ? 'Any target — paste an IP, domain, email, handle, hash…'
        : `e.g. ${KIND_META[currentKind]?.hint ?? currentKind}`,
      onkeydown: (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          runLookup();
        } else if (e.key === 'Escape' && targetInput.value) {
          targetInput.value = '';
          updateHint();
        }
      },
      oninput: () => updateHint(),
    });

    const hintEl = el('div', { class: 'command-hint', id: 'lookup-hint' }, ['']);
    targetInput.setAttribute('aria-describedby', 'lookup-hint');

    const lookupBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('search'), 'Look up',
    ]);
    lookupBtn.addEventListener('click', () => runLookup());

    const investigateBtn = el('button', { class: 'btn btn-ghost', type: 'button' }, [
      icon('network'), 'Investigate pivots',
    ]);
    investigateBtn.addEventListener('click', () => {
      const value = targetInput.value.trim();
      if (!value) {
        toastWarn('Enter a target to investigate');
        targetInput.focus();
        return;
      }
      navigate('investigate', { target: value });
    });

    const riskCheck = el('input', {
      class: 'check-input', type: 'checkbox', checked: riskOn,
      'aria-label': 'Attach risk score to the lookup',
    });
    riskCheck.addEventListener('change', () => {
      writeStore(RISK_STORE, riskCheck.checked ? '1' : '0');
    });

    const commandCard = el('section', {
      class: 'card lookup-command', 'aria-label': 'Lookup command bar',
    }, [
      el('div', { class: 'card-body' }, [
        pillsRow,
        el('div', { class: 'command-row' }, [
          el('div', { class: 'field grow' }, [
            el('label', { class: 'field-label', for: 'lookup-target' }, ['Target']),
            targetInput,
          ]),
          lookupBtn,
        ]),
        el('div', { class: 'command-aux' }, [
          hintEl,
          el('label', { class: 'check' }, [riskCheck, 'With risk score']),
          el('span', { class: 'grow' }),
          investigateBtn,
        ]),
      ]),
    ]);

    /* ---- error + result slots ------------------------------------- */
    const errorSlot = el('div', { hidden: true }, []);
    const recentSlot = el('div', {}, []);
    const resultArea = el('div', {
      class: 'lookup-result', role: 'region', 'aria-label': 'Lookup result',
    }, []);

    root.append(el('div', { class: 'view-lookup stack-lg' }, [
      commandCard,
      errorSlot,
      recentSlot,
      resultArea,
    ]));

    /* ---- inline feedback helpers ---------------------------------- */

    /**
     * Show an inline callout in the error slot.
     *
     * @param {string} message
     * @param {{variant?: string, status?: ?number}} [opts]
     */
    function showError(message, opts = {}) {
      const variant = opts.variant ?? 'danger';
      errorSlot.replaceChildren(el('div', {
        class: `callout ${variant}`,
        role: variant === 'danger' ? 'alert' : 'status',
      }, [
        icon('alert'),
        el('div', {}, [
          el('strong', {}, [variant === 'warn' ? 'Heads up' : 'Lookup failed']),
          el('div', { class: 'sm' }, [message]),
          opts.status ? el('div', { class: 'xs faint' }, [`HTTP ${opts.status}`]) : null,
        ]),
      ]));
      errorSlot.hidden = false;
    }

    /** Clear the inline error callout. */
    function clearError() {
      errorSlot.replaceChildren();
      errorSlot.hidden = true;
    }

    /** Refresh the hint line under the command bar. */
    function updateHint() {
      const value = targetInput.value.trim();
      hintEl.textContent = currentKind === 'auto'
        ? detectHint(value)
        : `Validated as ${KIND_META[currentKind]?.label ?? currentKind} by the backend on submit`;
    }

    /**
     * Select a kind: pill styling, placeholder, hint and persistence.
     *
     * @param {string} kind
     */
    function setKind(kind) {
      currentKind = normalizeKind(kind) ?? 'auto';
      for (const pill of pillsRow.children) {
        const active = pill.dataset.kind === currentKind;
        pill.classList.toggle('active', active);
        pill.setAttribute('aria-pressed', String(active));
      }
      targetInput.placeholder = currentKind === 'auto'
        ? 'Any target — paste an IP, domain, email, handle, hash…'
        : `e.g. ${KIND_META[currentKind]?.hint ?? currentKind}`;
      writeStore(KIND_STORE, currentKind);
      updateHint();
    }

    /* ---- recent strip --------------------------------------------- */

    /** Re-render the recent-lookups strip from localStorage. */
    function renderRecent() {
      const list = loadRecent();
      if (!list.length) {
        recentSlot.replaceChildren();
        return;
      }
      const chips = list.map((item) => el('button', {
        class: 'recent-chip', type: 'button',
        title: `${item.kind} · ${item.target} · ${fmtAgo(item.ts)}`,
        onclick: () => {
          targetInput.value = item.target;
          setKind(item.kind);
          runLookup(item.kind, item.target);
        },
      }, [
        kindBadge(item.kind),
        el('span', { class: 'mono truncate' }, [fmtShort(item.target, 24)]),
        el('span', { class: 'faint xs nowrap' }, [fmtAgo(item.ts)]),
      ]));
      recentSlot.replaceChildren(el('div', { class: 'recent-strip', 'aria-label': 'Recent lookups' }, [
        el('span', { class: 'recent-strip-label' }, [icon('history', { size: 13 }), 'Recent']),
        ...chips,
        el('span', { class: 'grow' }),
        el('button', {
          class: 'btn btn-ghost btn-sm', type: 'button',
          title: 'Clear the recent-lookup history',
          onclick: () => {
            writeJSON(RECENT_STORE, []);
            renderRecent();
            toastOk('Recent lookups cleared');
          },
        }, [icon('trash', { size: 12 }), 'Clear']),
      ]));
    }

    /* ---- result rendering ----------------------------------------- */

    /**
     * Build the full result layout (hero + grid with fields/sources side
     * panels + raw JSON).
     *
     * @param {object} opts
     */
    function renderResult({ kind, requestedKind, target, result, autoDetected, withRisk, tookMs }) {
      const res = result && typeof result === 'object' && !Array.isArray(result)
        ? result : {};

      const mainCol = el('div', { class: 'stack' }, [fieldsCard(res)]);
      const sideCol = el('div', { class: 'stack' }, [sourcesCard(res)]);

      const riskNode = riskCard(res.risk);
      if (riskNode) sideCol.append(riskNode);
      if (kind === 'ip') sideCol.append(intelCard(target));

      mainCol.append(el('details', { class: 'raw-json' }, [
        el('summary', {}, [icon('chevronDown', { size: 14 }), 'Raw JSON response']),
        el('div', { class: 'raw-json-body' }, [
          jsonBlock(res, withRisk ? `GET /api/risk · ${target}` : `GET response · ${target}`),
        ]),
      ]));

      const layout = el('div', { class: 'stack' }, [
        resultHeroCard({
          kind, target, result: res, autoDetected, tookMs,
          // Re-run replays the query that produced THIS result (auto stays
          // auto even when the pill row has since changed).
          onRerun: () => runLookup(requestedKind ?? currentKind, target, {
            withRisk: riskCheck.checked,
          }),
        }),
      ]);

      if (res.success === false) {
        const errors = [];
        if (Array.isArray(res.errors)) {
          errors.push(...res.errors.map((e) => String(e ?? '')).filter(Boolean));
        } else if (typeof res.error === 'string' && res.error) {
          errors.push(res.error);
        }
        layout.append(el('div', { class: 'callout danger', role: 'alert' }, [
          icon('alert'),
          el('div', {}, [
            el('strong', {}, ['The tracker reported a failure']),
            errors.length
              ? el('ul', { class: 'stack sm' }, errors.slice(0, 5).map((e) =>
                el('li', { class: 'mono xs' }, [e])))
              : el('div', { class: 'sm' }, ['No error detail was returned.']),
          ]),
        ]));
      }

      layout.append(el('div', { class: 'result-grid' }, [mainCol, sideCol]));
      resultArea.replaceChildren(layout);
    }

    /** Skeleton layout shown while a lookup is in flight. */
    function skeletonResult() {
      return el('div', { class: 'result-grid', 'aria-hidden': 'true' }, [
        el('div', { class: 'stack' }, [skeleton(2, true), skeleton(7)]),
        el('div', { class: 'stack' }, [skeleton(3), skeleton(4)]),
      ]);
    }

    /* ---- the lookup runner ---------------------------------------- */
    let runToken = 0;

    /**
     * Execute a lookup and render the outcome. Guards against stale
     * responses with a token so rapid re-submits never race.
     *
     * @param {string} [kindOverride]
     * @param {string} [targetOverride]
     * @param {{withRisk?: boolean}} [opts]
     */
    async function runLookup(kindOverride, targetOverride, opts = {}) {
      const kind = normalizeKind(kindOverride) ?? currentKind;
      const target = String(targetOverride ?? targetInput.value ?? '').trim();
      const withRisk = opts.withRisk ?? riskCheck.checked;

      if (!target) {
        showError('Enter a target to look up — IPs, domains, emails, usernames, phones, '
          + 'URLs, crypto, hashes, CVEs, AS numbers, MACs, IBANs, IMEIs or coordinates.', {
          variant: 'warn',
        });
        targetInput.focus();
        return;
      }

      const token = ++runToken;
      clearError();
      busy(lookupBtn, true, 'Looking up…');
      resultArea.replaceChildren(skeletonResult());
      const startedAt = performance.now();

      try {
        let effectiveKind = kind;
        let result;
        let autoDetected = false;

        if (kind === 'auto') {
          // Auto-detect via /api/investigate (no pivots), then optionally
          // re-run as an explicit /api/risk call for the scored variant.
          const investigation = await api.investigate(target, { pivot: false });
          if (token !== runToken || !root.isConnected) return;
          autoDetected = true;
          effectiveKind = normalizeKind(investigation?.kind) ?? detectKindLocal(target) ?? 'auto';
          result = investigation?.results?.[effectiveKind]
            ?? investigation?.results?.[investigation?.kind]
            ?? investigation;
          if (withRisk && normalizeKind(effectiveKind)) {
            result = await api.risk(effectiveKind, target);
          }
        } else {
          result = withRisk
            ? await api.risk(kind, target)
            : await api.lookup(kind, target);
        }

        if (token !== runToken || !root.isConnected) return;
        const tookMs = performance.now() - startedAt;

        pushRecent(effectiveKind, target);
        writeStore(KIND_STORE, kind);
        renderRecent();

        // Silent URL update so the view is shareable / reloadable.
        const qs = new URLSearchParams({ kind, target });
        if (withRisk) qs.set('risk', '1');
        try { history.replaceState(null, '', `#/lookup?${qs}`); } catch { /* exotic contexts */ }

        renderResult({
          kind: effectiveKind, requestedKind: kind, target, result,
          autoDetected, withRisk, tookMs,
        });
      } catch (err) {
        if (token !== runToken || !root.isConnected) return;
        const status = errStatus(err);
        showError(errText(err), { status });
        resultArea.replaceChildren(emptyState({
          title: 'Lookup failed',
          hint: 'The request did not complete. Check the message above — validation '
            + 'problems are usually a malformed target for the selected kind.',
          icon: 'alert',
        }));
        if (status === null || status === 0 || status >= 500) {
          toastErr(errText(err));
        }
      } finally {
        if (token === runToken) busy(lookupBtn, false);
      }
    }

    /* ---- initial paint -------------------------------------------- */
    setKind(currentKind);
    renderRecent();

    if (paramTarget) {
      targetInput.value = paramTarget;
      updateHint();
      runLookup(currentKind, paramTarget, { withRisk: riskOn });
    } else {
      resultArea.replaceChildren(emptyState({
        title: 'Enter a target',
        hint: 'IPs, domains, emails, usernames, phones, URLs, crypto, hashes, CVEs, '
          + 'AS numbers, MACs, IBANs, IMEIs or coordinates — every lookup fans out to '
          + 'all enabled sources with full provenance.',
        icon: 'search',
      }));
      targetInput.focus({ preventScroll: true });
    }
  },
};

export default view;
