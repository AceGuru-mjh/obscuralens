/**
 * ObscuraLens web UI — investigate view (entity graph & pivot engine).
 *
 * The workbench: type any target (kind auto-detected by the backend), the
 * force-directed graph maps the primary result plus every pivot entity;
 * double-click nodes to expand them into the running investigation, inspect
 * entities in the side panel (lookup / risk / case actions), browse the
 * per-kind result tabs and export the graph in five text formats plus PNG.
 *
 * Defensive by design: the backend payload may key entities by `kind` or
 * `type` and links by `source/target` or `from/to` — both are normalised.
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';
import { navigate } from '../main.js';
import { createGraph } from '../graph.js';

const { el, icon, badge, kindBadge, toastOk, toastWarn, toastErr } = ui;

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
/* Payload normalisation                                                   */
/* ---------------------------------------------------------------------- */

/** Per-kind result target key (best-effort for tab back-links). */
const TARGET_KEYS = {
  ip: 'ip', domain: 'domain', email: 'email', username: 'username',
  phone: 'phone', url: 'url', crypto: 'address', hash: 'hash',
  cve: 'cve', asn: 'asn', mac: 'mac', iban: 'iban', imei: 'imei',
  coords: 'coords',
};

/**
 * Normalise one entity (accepts `kind` or `type` keys).
 *
 * @param {*} raw
 * @returns {{id: string, kind: string, value: string, label: string,
 *   role: string}|null}
 */
function normEntity(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const kind = String(raw.kind ?? raw.type ?? '').trim().toLowerCase();
  const value = raw.value ?? raw.label ?? raw.id;
  if (!kind || value === null || value === undefined || value === '') return null;
  const valueStr = String(value);
  return {
    id: String(raw.id ?? `${kind}:${valueStr}`),
    kind,
    value: valueStr,
    label: String(raw.label ?? valueStr),
    role: String(raw.role ?? ''),
  };
}

/**
 * Normalise one link (accepts `source/target` or `from/to` keys).
 *
 * @param {*} raw
 * @returns {{source: string, target: string, label: string}|null}
 */
function normLink(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const source = raw.source ?? raw.from;
  const target = raw.target ?? raw.to;
  if (source === null || source === undefined
    || target === null || target === undefined) return null;
  return {
    source: String(source),
    target: String(target),
    label: String(raw.label ?? ''),
  };
}

/**
 * Filesystem-safe slug for export names.
 *
 * @param {string} target
 * @returns {string}
 */
function slug(target) {
  return String(target).replace(/[^a-z0-9.-]+/gi, '_').replace(/^_+|_+$/g, '')
    .slice(0, 60) || 'target';
}

/**
 * Best-effort value for a tracker result (used for "open full result").
 *
 * @param {string} kind
 * @param {object} result
 * @param {string} fallback
 * @returns {string}
 */
function resultValue(kind, result, fallback) {
  const key = TARGET_KEYS[kind];
  if (key) {
    const direct = result?.[key] ?? result?.info?.[key] ?? result?.target;
    if (direct !== undefined && direct !== null && direct !== '') {
      return String(direct);
    }
  }
  return fallback;
}

/** Meta keys that are never rendered as result fields. */
const RESULT_META_KEYS = new Set(['info', 'field_sources', 'sources_ok',
  'sources_failed', 'field_count', 'success', 'errors', 'risk', 'error',
  'domain', 'target']);

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'investigate',
  title: 'Investigate',
  subtitle: 'Entity graph & pivot engine',
  icon: 'network',
  section: 'investigation',
  order: 10,

  /**
   * Render the investigation workbench.
   *
   * @param {HTMLElement} root #view container.
   * @param {URLSearchParams} params Route params (`target` auto-runs).
   */
  async render(root, params) {
    /* ---- shared state ------------------------------------------------ */

    const nodesMap = new Map(); // id → normalised entity
    const linksMap = new Map(); // link key → normalised link
    const resultsMap = new Map(); // tab key → {kind, value, result}
    const expanded = new Set(); // lowercased values already expanded
    const claimedValues = new Set(); // values already bound to a tab

    let currentTarget = '';
    let lastPayload = null;
    let selectedNode = null;

    const NODE_CAP = 400;

    /* ---- command row -------------------------------------------------- */

    const input = el('input', {
      class: 'input input-mono',
      type: 'text',
      spellcheck: 'false',
      autocomplete: 'off',
      placeholder: 'any target — IP, domain, email, username, phone, URL, crypto, hash, CVE, ASN, MAC, IBAN, IMEI, coords…',
    });
    const depthSelect = el('select', { class: 'select', title: 'Pivot depth' }, [
      el('option', { value: '1' }, ['Depth 1 · target only']),
      el('option', { value: '2', selected: true }, ['Depth 2 · + auto pivots']),
      el('option', { value: '3' }, ['Depth 3 · + pivots of pivots']),
    ]);
    const runBtn = el('button', { class: 'btn btn-primary' }, [
      icon('network', { size: 15 }), 'Investigate',
    ]);
    const hintChip = el('span', { class: 'chip' }, ['auto-detect runs server-side']);

    input.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') run(input.value);
    });
    runBtn.addEventListener('click', () => run(input.value));

    /* ---- graph card ---------------------------------------------------- */

    const graphWrap = el('div', { class: 'graph-wrap graph-wrap-lg' });
    const overlayLabel = el('div', { class: 'muted sm' }, ['Following pivots…']);
    const overlay = el('div', { class: 'graph-overlay', hidden: true }, [
      el('span', { class: 'spinner spinner-lg' }),
      overlayLabel,
    ]);
    const intro = el('div', { class: 'graph-intro' }, [
      icon('network', { size: 30 }),
      el('div', { class: 'empty-title' }, ['No investigation running']),
      el('p', { class: 'empty-hint' }, [
        'Enter a target above — ObscuraLens auto-detects its type, queries every source and maps related entities here. Double-click a node to pivot deeper.',
      ]),
    ]);
    graphWrap.append(overlay, intro);

    const exportRow = el('div', { class: 'inv-export' }, [
      el('span', { class: 'stat-label' }, ['export']),
      ...['graphml', 'gexf', 'dot', 'jsonl', 'csv'].map((fmt) =>
        el('button', {
          class: 'btn btn-sm',
          dataset: { fmt },
          onclick: () => exportGraph(fmt),
        }, [fmt.toUpperCase()])),
      el('button', {
        class: 'btn btn-sm',
        onclick: () => exportPNGFile(),
      }, [icon('download', { size: 12 }), 'PNG']),
      pngNote(),
    ]);
    const mermaidBtn = el('button', {
      class: 'btn btn-sm',
      disabled: true,
      title: 'Copy the Mermaid flowchart of this investigation',
      onclick: () => copyMermaid(),
    }, [icon('link', { size: 12}), 'Mermaid']);
    exportRow.append(mermaidBtn);

    /** Tiny "also copies" note; keeps the export row self-explaining. */
    function pngNote() {
      return el('span', { class: 'faint xs nowrap' }, ['· graph snapshot']);
    }

    /* ---- side panel ----------------------------------------------------- */

    const sideBody = el('div', { class: 'inv-side-body' }, []);

    /* ---- results card ---------------------------------------------------- */

    const resultsBody = el('div', {}, []);

    /* ---- layout ----------------------------------------------------------- */

    root.replaceChildren(el('div', { class: 'view-investigate' }, [
      el('div', { class: 'inv-cmd' }, [
        el('span', { class: 'flex gap-2' }, [
          icon('search', { size: 15 }),
        ]),
        input,
        depthSelect,
        runBtn,
        hintChip,
      ]),
      el('div', { class: 'inv-layout' }, [
        el('div', { class: 'card inv-graph-card' }, [
          el('div', { class: 'card-head' }, [
            icon('network', { size: 16 }),
            el('span', { class: 'card-title' }, ['Entity graph']),
            el('span', { class: 'grow' }),
            el('span', { class: 'faint xs' }, ['drag · scroll to zoom · double-click to pivot']),
          ]),
          graphWrap,
          el('div', { class: 'card-foot' }, [exportRow]),
        ]),
        el('div', { class: 'card inv-side' }, [
          el('div', { class: 'card-head' }, [
            icon('finger', { size: 16 }),
            el('span', { class: 'card-title' }, ['Inspector']),
          ]),
          sideBody,
        ]),
      ]),
      el('div', { class: 'card inv-results' }, [
        el('div', { class: 'card-head' }, [
          icon('layers', { size: 16 }),
          el('span', { class: 'card-title' }, ['Entity results']),
          el('span', { class: 'grow' }),
        ]),
        el('div', { class: 'card-body' }, [resultsBody]),
      ]),
    ]));

    /* ---- graph engine ------------------------------------------------------ */

    const graph = createGraph(graphWrap);
    graph
      .onSelect((node) => {
        selectedNode = node;
        renderSidePanel(node);
      })
      .ondblclick((node) => {
        if (node?.value) expandEntity(node.value);
      });

    /**
     * Current graph dataset from the merged maps.
     *
     * @returns {{nodes: Array<object>, links: Array<object>}}
     */
    function graphData() {
      return {
        nodes: [...nodesMap.values()].map((e) => ({
          id: e.id,
          label: e.label,
          kind: e.kind,
          size: e.role === 'target' ? 6 : 0,
          meta: { role: e.role, value: e.value },
        })),
        links: [...linksMap.values()].map((l) => ({
          source: l.source,
          target: l.target,
          label: l.label,
        })),
      };
    }

    /* ---- payload ingestion --------------------------------------------------- */

    /**
     * Merge an investigate payload into the running maps.
     *
     * @param {object} payload
     * @param {{reset?: boolean}} [opts]
     * @returns {{entities: number, links: number}} newly added counts.
     */
    function ingest(payload, opts = {}) {
      if (opts.reset) {
        nodesMap.clear();
        linksMap.clear();
        resultsMap.clear();
        claimedValues.clear();
      }
      const rawEntities = Array.isArray(payload?.entities) ? payload.entities : [];
      const rawLinks = Array.isArray(payload?.links) ? payload.links : [];

      let addedEntities = 0;
      for (const raw of rawEntities) {
        const e = normEntity(raw);
        if (!e || nodesMap.has(e.id)) continue;
        if (nodesMap.size >= NODE_CAP) break; // engine caps at 400 too
        nodesMap.set(e.id, e);
        addedEntities += 1;
      }
      let addedLinks = 0;
      for (const raw of rawLinks) {
        const l = normLink(raw);
        if (!l) continue;
        if (!nodesMap.has(l.source) || !nodesMap.has(l.target)) continue;
        const key = `${l.source}\u0000${l.target}\u0000${l.label}`;
        if (linksMap.has(key)) continue;
        linksMap.set(key, l);
        addedLinks += 1;
      }

      // merge per-kind results into tabs
      const results = payload?.results ?? {};
      if (results && typeof results === 'object') {
        for (const [kind, result] of Object.entries(results)) {
          if (!result || typeof result !== 'object') continue;
          const kindLc = String(kind).toLowerCase();
          const fallback = String(payload?.target ?? currentTarget ?? '');
          let value = kindLc === String(payload?.kind ?? '').toLowerCase()
            ? fallback : '';
          if (!value) {
            // first unclaimed entity of this kind
            for (const e of nodesMap.values()) {
              if (e.kind === kindLc && !claimedValues.has(e.value.toLowerCase())) {
                value = e.value;
                break;
              }
            }
          }
          if (!value) value = resultValue(kindLc, result, fallback);
          claimedValues.add(value.toLowerCase());
          resultsMap.set(`${kindLc}:${value.toLowerCase()}`, {
            kind: kindLc, value, result,
          });
        }
      }
      return { entities: addedEntities, links: addedLinks };
    }

    /* ---- loading ---------------------------------------------------------- */

    /**
     * Toggle the graph loading overlay.
     *
     * @param {boolean} on
     * @param {string} [label]
     */
    function setLoading(on, label) {
      overlay.hidden = !on;
      if (label) overlayLabel.textContent = label;
      runBtn.disabled = on;
      intro.hidden = nodesMap.size > 0 || on;
    }

    /* ---- run / expand --------------------------------------------------------- */

    /**
     * Run a fresh investigation for `target`.
     *
     * @param {string} target
     */
    async function run(target) {
      const value = String(target ?? '').trim();
      if (!value) {
        toastWarn('Enter a target first');
        return;
      }
      // deep-linkable hash without re-triggering the router
      try {
        history.replaceState(null, '',
          `#/investigate?target=${encodeURIComponent(value)}`);
      } catch { /* file:// or similar */ }
      input.value = value;
      currentTarget = value;
      selectedNode = null;
      setLoading(true, 'Investigating…');
      try {
        const payload = await api.investigate(value, { pivot: true });
        lastPayload = payload;
        expanded.clear();
        expanded.add(value.toLowerCase());
        const { entities } = ingest(payload, { reset: true });
        graph.setData(graphData());
        renderSidePanel(null);
        buildTabs();
        updateHint(payload);
        const depth = Number(depthSelect.value) || 1;
        if (depth >= 2 && entities > 1) await autoExpand(depth);
        renderSidePanel(selectedNode); // refresh pivot summary post-expansion
        toastOk(`Mapped ${nodesMap.size} entities · ${linksMap.size} links`);
      } catch (err) {
        toastErr(err?.message ?? String(err));
        if (nodesMap.size === 0) {
          renderSidePanel(null);
          resultsBody.replaceChildren(ui.emptyState({
            title: 'Investigation failed',
            hint: String(err?.message ?? err),
            icon: 'alert',
          }));
        }
      } finally {
        setLoading(false);
      }
    }

    /**
     * Auto-expand pivot entities for depth ≥ 2.
     *
     * @param {number} depth
     */
    async function autoExpand(depth) {
      const limit = Math.min((depth - 1) * 2, 6);
      const candidates = [...nodesMap.values()]
        .filter((e) => e.role !== 'target' && !expanded.has(e.value.toLowerCase()))
        .slice(0, limit)
        .map((e) => e.value);
      if (!candidates.length) return;
      setLoading(true, 'Following pivots…');
      await Promise.allSettled(candidates.map((v) => expandEntity(v, true)));
    }

    /**
     * Pivot on one entity value and merge it into the graph.
     *
     * @param {string} value
     * @param {boolean} [quiet] Suppress the toast (auto-expansion).
     */
    async function expandEntity(value, quiet = false) {
      const key = String(value ?? '').toLowerCase();
      if (!key || expanded.has(key)) return;
      expanded.add(key);
      setLoading(true, 'Following pivots…');
      try {
        const payload = await api.investigate(String(value), { pivot: true });
        lastPayload = lastPayload ?? payload;
        const { entities } = ingest(payload);
        graph.setData(graphData());
        buildTabs();
        if (!quiet) {
          toastOk(entities > 0
            ? `Expanded ${entities} new entities`
            : 'No new entities for this pivot');
        }
      } catch (err) {
        toastErr(`Pivot failed: ${err?.message ?? err}`);
      } finally {
        setLoading(false);
      }
    }

    /**
     * Refresh the hint chip after a successful run.
     *
     * @param {object} payload
     */
    function updateHint(payload) {
      const kind = String(payload?.kind ?? '').toLowerCase();
      hintChip.replaceChildren(
        kind ? kindBadge(kind) : el('span', {}, ['unknown']),
        el('span', { class: 'mono truncate', title: currentTarget },
          [ui.fmtShort(currentTarget, 26)]),
      );
      mermaidBtn.disabled = !payload?.mermaid;
    }

    /* ---- side panel --------------------------------------------------------- */

    /**
     * Render the inspector: entity details or pivot summary.
     *
     * @param {object|null} node Public node from the graph engine.
     */
    function renderSidePanel(node) {
      if (!node) {
        selectedNode = null;
        sideBody.replaceChildren(pivotSummary());
        return;
      }
      const entity = nodesMap.get(node.id);
      const kind = entity?.kind ?? node.kind ?? 'entity';
      const value = entity?.value ?? node.value ?? node.label ?? '';
      const role = entity?.role ?? node.meta?.role ?? '';

      const riskBox = el('div', { class: 'inv-risk-box' }, []);

      sideBody.replaceChildren(
        el('div', { class: 'flex gap-2 wrap' }, [
          kindBadge(kind),
          role ? badge(role, role === 'target' ? 'accent' : 'muted') : null,
        ]),
        el('div', { class: 'inv-side-value mt-2' }, [
          ui.copyable(value, { short: 34 }),
        ]),
        KIND_META[kind]?.hint
          ? el('div', { class: 'faint xs mt-1' }, [KIND_META[kind].hint])
          : null,
        el('div', { class: 'inv-quick mt-3' }, [
          el('button', {
            class: 'btn btn-sm',
            onclick: () => navigate('lookup', { kind, target: value }),
          }, [icon('search', { size: 12 }), 'Open in Lookup']),
          el('button', {
            class: 'btn btn-sm',
            onclick: () => runRisk(kind, value, riskBox),
          }, [icon('shield', { size: 12 }), 'Run risk']),
          el('button', {
            class: 'btn btn-sm',
            onclick: () => addToCase(kind, value),
          }, [icon('folder', { size: 12 }), 'Add to case']),
        ]),
        riskBox,
      );
    }

    /**
     * Default inspector content: pivot summary + payload stats.
     *
     * @returns {HTMLElement}
     */
    function pivotSummary() {
      if (!lastPayload && nodesMap.size === 0) {
        return el('div', { class: 'empty inv-side-empty' }, [
          icon('finger', { size: 26 }),
          el('div', { class: 'empty-title' }, ['Nothing selected']),
          el('p', { class: 'empty-hint' }, [
            'Click a node to inspect it. The pivot summary appears once an investigation runs.',
          ]),
        ]);
      }
      const byKind = new Map();
      for (const e of nodesMap.values()) {
        byKind.set(e.kind, (byKind.get(e.kind) ?? 0) + 1);
      }
      const kindRows = [...byKind.entries()].sort((a, b) => b[1] - a[1])
        .map(([kind, n]) => el('span', { class: 'inv-kind-chip' }, [
          kindBadge(kind),
          el('b', {}, [String(n)]),
        ]));
      const errors = Array.isArray(lastPayload?.errors)
        ? lastPayload.errors.slice(0, 3) : [];
      return el('div', {}, [
        el('div', { class: 'stat-label mb-2' }, ['pivot summary']),
        el('div', { class: 'inv-kind-row' }, kindRows.length ? kindRows
          : [el('span', { class: 'faint xs' }, ['no entities'])]),
        el('div', { class: 'mt-3' }, [ui.kvGrid([
          ['target', currentTarget || '—'],
          ['entities', String(nodesMap.size)],
          ['links', String(linksMap.size)],
          ['result sets', String(resultsMap.size)],
          ['expanded', String(expanded.size)],
        ])]),
        errors.length ? el('div', { class: 'callout warn mt-3' }, [
          icon('alert', { size: 14 }),
          el('div', { class: 'grow xs' }, errors.map((e) =>
            el('div', { class: 'mono truncate' }, [String(e)]))),
        ]) : null,
      ]);
    }

    /**
     * Fetch and render the risk block for an entity.
     *
     * @param {string} kind
     * @param {string} value
     * @param {HTMLElement} box Target container.
     */
    async function runRisk(kind, value, box) {
      box.replaceChildren(ui.loading('Scoring…'));
      try {
        const result = await api.risk(kind, value);
        const risk = result?.risk && typeof result.risk === 'object'
          ? result.risk : null;
        if (!risk) {
          box.replaceChildren(el('div', { class: 'callout info mt-3' }, [
            icon('info', { size: 14 }),
            el('div', { class: 'grow xs' }, [
              'No risk block attached — scoring may be disabled in settings.',
            ]),
          ]));
          return;
        }
        const level = ui.riskLevel(Number(risk.score));
        const signals = Array.isArray(risk.signals) ? risk.signals : [];
        box.replaceChildren(
          el('div', { class: 'mt-3 flex gap-2' }, [
            el('div', { class: 'stat-value' }, [String(risk.score ?? 0)]),
            el('div', {}, [
              badge(`${level.label} risk`, level.label === 'high'
                ? 'danger' : level.label === 'elevated' ? 'warn'
                : level.label === 'moderate' ? 'info' : 'ok'),
              el('div', { class: 'faint xs' }, [
                `${signals.length} signal${signals.length === 1 ? '' : 's'}`,
              ]),
            ]),
          ]),
          risk.summary ? el('p', { class: 'muted xs mt-1' }, [String(risk.summary)]) : null,
          el('ul', { class: 'inv-risk-list mt-2' }, signals.slice(0, 8).map((s) =>
            el('li', {}, [
              el('span', { class: 'mono xs' }, [String(s?.id ?? '?')]),
              el('span', {
                class: `inv-risk-w ${Number(s?.weight) > 0 ? 'up' : 'down'}`,
              }, [`${Number(s?.weight) > 0 ? '+' : ''}${Number(s?.weight) ?? 0}`]),
              el('span', { class: 'xs muted' }, [String(s?.detail ?? '')]),
            ]))),
        );
      } catch (err) {
        box.replaceChildren(el('div', { class: 'callout danger mt-3' }, [
          icon('alert', { size: 14 }),
          el('div', { class: 'grow xs' }, [String(err?.message ?? err)]),
        ]));
      }
    }

    /**
     * "Add to case" modal (existing case select or create + optional note).
     *
     * @param {string} kind
     * @param {string} value
     */
    async function addToCase(kind, value) {
      let closeRef = null;
      const select = el('select', { class: 'select' }, []);
      const nameInput = el('input', {
        class: 'input', placeholder: 'New case name (e.g. ACME phishing)',
      });
      const note = el('textarea', {
        class: 'textarea', rows: 2,
        placeholder: 'item note (optional)',
      });
      const status = el('div', { class: 'muted xs' }, ['Loading cases…']);
      let caseList = [];

      const body = el('div', { class: 'flex-col gap-3' }, [
        el('div', { class: 'field' }, [
          el('label', { class: 'field-label' }, ['Entity']),
          el('div', { class: 'mono sm' }, [`${kind} · ${ui.fmtShort(value, 40)}`]),
        ]),
        el('div', { class: 'field' }, [
          el('label', { class: 'field-label' }, ['Case']),
          select,
          nameInput,
          status,
        ]),
        el('div', { class: 'field' }, [
          el('label', { class: 'field-label' }, ['Note']),
          note,
        ]),
      ]);

      const submit = el('button', { class: 'btn btn-primary', disabled: true }, [
        icon('plus', { size: 13 }), 'Add to case',
      ]);
      const cancel = el('button', { class: 'btn btn-ghost' }, ['Cancel']);

      closeRef = ui.modal({
        title: 'Add to case',
        body,
        foot: [cancel, submit],
      });
      cancel.addEventListener('click', () => closeRef?.());
      submit.addEventListener('click', async () => {
        submit.disabled = true;
        status.textContent = 'Adding…';
        try {
          const newMode = select.value === '__new__';
          let caseId = newMode ? null : Number(select.value);
          if (newMode) {
            const created = await api.caseCreate({ name: nameInput.value.trim() });
            caseId = Number(created?.id);
          }
          if (!caseId) throw new Error('no case selected');
          await api.caseAddItem(caseId, {
            kind, value, note: note.value.trim(),
          });
          toastOk(`Added to case #${caseId}`);
          closeRef?.();
        } catch (err) {
          submit.disabled = false;
          status.textContent = String(err?.message ?? err);
        }
      });

      // populate the case select
      try {
        caseList = await api.cases();
        const open = (Array.isArray(caseList) ? caseList : [])
          .filter((c) => c && c.status !== 'closed' && c.status !== 'archived');
        select.replaceChildren(
          ...open.map((c) => el('option', { value: String(c.id) }, [
            `#${c.id} · ${String(c.name ?? 'case').slice(0, 40)}` +
              (c.item_count ? ` (${c.item_count})` : ''),
          ])),
          el('option', { value: '__new__' }, ['＋ create new case…']),
        );
        if (!open.length) select.value = '__new__';
        nameInput.hidden = select.value !== '__new__';
        select.addEventListener('change', () => {
          nameInput.hidden = select.value !== '__new__';
        });
        submit.disabled = false;
        status.textContent = open.length
          ? `${open.length} open case(s)` : 'no open cases — create one';
      } catch (err) {
        select.replaceChildren(el('option', { value: '__new__' }, ['＋ create new case…']));
        select.value = '__new__';
        nameInput.hidden = false;
        submit.disabled = false;
        status.textContent = String(err?.message ?? err);
      }
    }

    /* ---- result tabs --------------------------------------------------------- */

    /**
     * Rebuild the per-kind result tabs (cap 10).
     */
    function buildTabs() {
      const entries = [...resultsMap.entries()].slice(0, 10);
      if (!entries.length) {
        resultsBody.replaceChildren(ui.emptyState({
          title: 'No result sets yet',
          hint: 'Per-kind tracker results appear here after an investigation runs.',
          icon: 'layers',
        }));
        return;
      }
      const specs = entries.map(([key, entry]) => {
        const info = entry.result?.info
          && typeof entry.result.info === 'object' ? entry.result.info : null;
        const count = info ? Object.keys(info).length
          : Number(entry.result?.field_count) || 0;
        const label = KIND_META[entry.kind]?.label ?? entry.kind;
        return {
          key,
          label: entry.value && resultsMap.size > 1
            ? `${label} · ${ui.fmtShort(entry.value, 14)}` : label,
          badge: badge(String(count), 'muted'),
          render: () => renderResultPanel(entry.kind, entry.value, entry.result),
        };
      });
      resultsBody.replaceChildren(ui.tabs(specs).root);
    }

    /**
     * One result tab: compact field table + provenance + full-result link.
     *
     * @param {string} kind
     * @param {string} value
     * @param {object} result Tracker result payload.
     * @returns {HTMLElement}
     */
    function renderResultPanel(kind, value, result) {
      const info = result?.info && typeof result.info === 'object'
        ? result.info : null;
      const fieldSources = result?.field_sources
        && typeof result.field_sources === 'object' ? result.field_sources : {};
      const failed = result?.sources_failed ?? {};
      const failedMap = failed && typeof failed === 'object' && !Array.isArray(failed)
        ? failed : {};

      let fields = info ? Object.entries(info)
        : Object.entries(result ?? {}).filter(([k]) => !RESULT_META_KEYS.has(k));
      const totalFields = fields.length;
      fields = fields.slice(0, 12);

      const headRow = el('div', { class: 'flex gap-2 wrap mb-3' }, [
        result?.success === false ? badge('failed', 'danger') : badge('success', 'ok'),
        badge(`${Number(result?.field_count) || totalFields} fields`, 'muted'),
        Array.isArray(result?.sources_ok)
          ? badge(`${result.sources_ok.length} sources ok`, 'info') : null,
        Object.keys(failedMap).length
          ? badge(`${Object.keys(failedMap).length} failed`, 'warn') : null,
      ]);

      const openFull = el('button', {
        class: 'btn btn-sm btn-outline',
        onclick: () => navigate('lookup', { kind, target: value }),
      }, ['Open full result', icon('arrowUpRight', { size: 12 })]);

      if (!fields.length) {
        return el('div', {}, [
          headRow,
          el('p', { class: 'muted sm' }, [
            'No fields collected for this result set.',
            Array.isArray(result?.errors) && result.errors.length
              ? ` ${String(result.errors[0])}` : '',
          ]),
          el('div', { class: 'mt-3' }, [openFull]),
        ]);
      }

      const table = ui.dataTable({
        columns: [
          {
            key: 'field', label: 'Field', sortable: false,
            render: (row) => el('span', { class: 'mono xs' }, [row.field]),
          },
          {
            key: 'value', label: 'Value', sortable: false,
            render: (row) => el('span', {
              class: 'mono xs inv-cell', title: row.full,
            }, [row.short]),
          },
          {
            key: 'sources', label: 'Sources', sortable: false,
            render: (row) => el('span', { class: 'tag-list' }, row.chips),
          },
        ],
        rows: fields.map(([field, raw]) => {
          const shown = formatFieldValue(raw);
          const sources = Array.isArray(fieldSources[field])
            ? fieldSources[field].map(String) : [];
          const chips = sources.slice(0, 4).map((s) =>
            ui.srcChip(s, Boolean(failedMap[s])));
          if (sources.length > 4) {
            chips.push(el('span', { class: 'chip' }, [`+${sources.length - 4}`]));
          }
          return {
            field: String(field),
            short: shown.short,
            full: shown.full,
            chips,
          };
        }),
      });

      return el('div', {}, [
        headRow,
        table,
        totalFields > 12
          ? el('p', { class: 'faint xs mt-2' }, [
            `showing 12 of ${totalFields} fields — open the full result for everything`,
          ]) : null,
        el('div', { class: 'mt-3' }, [openFull]),
      ]);
    }

    /**
     * Human-friendly cell text for a tracker field value.
     *
     * @param {*} raw
     * @returns {{short: string, full: string}}
     */
    function formatFieldValue(raw) {
      if (raw === null || raw === undefined || raw === '') return { short: '—', full: '—' };
      let full;
      if (Array.isArray(raw)) full = raw.map((x) => String(x)).join(', ');
      else if (typeof raw === 'object') {
        try { full = JSON.stringify(raw); } catch { full = String(raw); }
      } else full = String(raw);
      return { short: ui.fmtShort(full, 96), full };
    }

    /* ---- exports --------------------------------------------------------------- */

    /** Download extension per export format. */
    const EXPORT_EXT = {
      graphml: 'graphml', gexf: 'gexf', dot: 'dot', jsonl: 'jsonl', csv: 'csv',
    };

    /**
     * Export the current investigation in a text graph format.
     *
     * @param {string} fmt
     */
    async function exportGraph(fmt) {
      if (!currentTarget) {
        toastWarn('Run an investigation first');
        return;
      }
      try {
        const payload = await api.graphExport(fmt, currentTarget);
        const text = payload?.graph ?? '';
        if (!text) {
          toastWarn(`Empty ${fmt.toUpperCase()} export`);
          return;
        }
        ui.download(
          `obscuralens-${slug(currentTarget)}.${EXPORT_EXT[fmt] ?? fmt}`,
          text, 'text/plain; charset=utf-8');
        toastOk(`${fmt.toUpperCase()} exported — `
          + `${payload?.entities ?? '?'} entities, ${payload?.links ?? '?'} links`);
      } catch (err) {
        toastErr(String(err?.message ?? err));
      }
    }

    /** Download the current graph canvas as a PNG. */
    function exportPNGFile() {
      if (!nodesMap.size) {
        toastWarn('Nothing to export yet');
        return;
      }
      const url = graph.exportPNG();
      if (!url) {
        toastErr('PNG export failed');
        return;
      }
      const a = el('a', {
        href: url,
        download: `obscuralens-${slug(currentTarget || 'graph')}.png`,
      });
      document.body.append(a);
      a.click();
      a.remove();
    }

    /** Copy the Mermaid diagram of the latest payload. */
    async function copyMermaid() {
      const text = lastPayload?.mermaid;
      if (!text) {
        toastWarn('No Mermaid diagram in this payload');
        return;
      }
      try {
        await navigator.clipboard.writeText(String(text));
        toastOk('Mermaid diagram copied to clipboard');
      } catch {
        toastErr('Clipboard unavailable');
      }
    }

    /* ---- deep-link auto-run ------------------------------------------------------ */

    const prefill = params?.get?.('target');
    if (prefill) {
      input.value = prefill;
      run(prefill);
    } else {
      renderSidePanel(null);
      buildTabs();
    }
  },
};

export default view;
