/**
 * ObscuraLens web UI — Compare view (v6.0 part 3).
 *
 * Side-by-side entity comparison over `GET /api/compare`: pick a kind and
 * a target for side A and side B, press Compare and both trackers run live
 * (through the same cache/rate-limits as any lookup). The response is
 * rendered as three columns — the fields each side returned, and a central
 * diff column with **added** (B only, green), **removed** (A only, red) and
 * **differing** (both, unequal — amber) groups.
 *
 * Validation happens before any request fires: both kinds must be selected
 * and both targets non-empty. A swap button mirrors A ⇄ B in one click.
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';

const { el, icon, badge, kindBadge, fmtInt, copyable, emptyState } = ui;

/** Truncation width for diff values (matches the backend's 80-char cap). */
const VALUE_SHORT = 80;

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
      el('div', { class: 'strong sm' }, ['Comparison failed']),
      el('div', { class: 'muted xs' }, [errText(message)]),
    ]),
    el('button', { class: 'btn btn-sm', type: 'button', onclick: retry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]),
  ]);
}

/** Inline danger note for validation feedback. */
function dangerNote(text) {
  return el('div', { class: 'callout danger' }, [
    icon('alert', { size: 14 }),
    el('div', { class: 'grow sm' }, [text]),
  ]);
}

/** Build a kind <select> (with a required placeholder option). */
function kindSelect(selected) {
  return el('select', { class: 'select', 'aria-label': 'Target kind' }, [
    el('option', { value: '', selected: !selected }, ['— select kind —']),
    ...KINDS.map((k) => el('option', {
      value: k, selected: k === selected,
    }, [KIND_META[k]?.label ?? k])),
  ]);
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
 * One side of the form.
 *
 * @param {'A'|'B'} sideLabel
 * @returns {{kind: HTMLSelectElement, target: HTMLInputElement,
 *            errorSlot: HTMLElement, root: HTMLElement}}
 */
function sideForm(sideLabel) {
  const kind = kindSelect('');
  const target = el('input', {
    class: 'input input-mono', type: 'text',
    placeholder: sideLabel === 'A' ? 'e.g. 8.8.8.8' : 'e.g. 1.1.1.1',
    autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false',
    'aria-label': `Side ${sideLabel} target`,
  });
  const errorSlot = el('div', {});
  return {
    kind,
    target,
    errorSlot,
    root: el('div', { class: 'compare-side' }, [
      el('div', { class: 'compare-side-head' }, [
        badge(`side ${sideLabel}`, 'accent'),
      ]),
      fieldEl(`Kind ${sideLabel} *`, kind),
      fieldEl(`Target ${sideLabel} *`, target,
        'The backend validates the target against its kind before running.'),
      errorSlot,
    ]),
  };
}

/**
 * Shortened, title-carrying mono value cell.
 *
 * @param {*} value
 * @returns {HTMLElement}
 */
function valueCell(value) {
  const text = value === null || value === undefined ? '' : String(value);
  if (!text) return el('span', { class: 'faint sm' }, ['—']);
  return el('span', { class: 'mono sm compare-value', title: text }, [
    text.length > VALUE_SHORT ? `${text.slice(0, VALUE_SHORT - 1)}…` : text,
  ]);
}

/**
 * The side summary header card (kind badge, target, success, field count,
 * error line).
 *
 * @param {*} side {kind, target, success, field_count, error}
 * @param {'A'|'B'} label
 * @returns {HTMLElement}
 */
function sideHeader(side, label) {
  const kind = String(side?.kind ?? '').toLowerCase();
  const target = String(side?.target ?? '');
  const success = side?.success;
  return el('div', { class: 'card compare-side-card' }, [
    el('div', { class: 'card-head' }, [
      kind ? kindBadge(kind) : badge(`side ${label}`, 'accent'),
      el('span', { class: 'grow' }),
      success === true ? badge('success', 'ok')
        : success === false ? badge('failed', 'danger')
          : badge('unknown', 'muted'),
    ]),
    el('div', { class: 'card-body' }, [
      el('div', { class: 'compare-side-target mono' }, [copyable(target, { short: 60 })]),
      el('div', { class: 'compare-side-stats' }, [
        el('span', { class: 'muted sm' }, [`${fmtInt(side?.field_count)} fields`]),
      ]),
      side?.error ? el('div', { class: 'callout danger compare-side-error' }, [
        icon('alert', { size: 12 }),
        el('span', { class: 'mono xs grow' }, [String(side.error)]),
      ]) : null,
    ]),
  ]);
}

/**
 * One field row for the A/B field tables.
 *
 * @param {string} field
 * @param {*} value
 * @param {string} tone 'plain'|'add'|'del'|'chg'
 * @returns {HTMLElement}
 */
function fieldRow(field, value, tone = 'plain') {
  return el('div', { class: `compare-field-row${tone !== 'plain' ? ` compare-${tone}` : ''}` }, [
    el('span', { class: 'compare-field-name mono xs' }, [field]),
    valueCell(value),
  ]);
}

/**
 * A group block for the central diff column.
 *
 * @param {string} title
 * @param {'add'|'del'|'chg'} tone
 * @param {Array<HTMLElement>} rows
 * @returns {HTMLElement}
 */
function diffGroup(title, tone, rows) {
  return el('div', { class: `compare-diff-group compare-diff-${tone}` }, [
    el('div', { class: 'compare-diff-label' }, [
      badge(title, tone === 'add' ? 'ok' : tone === 'del' ? 'danger' : 'warn'),
    ]),
    rows.length
      ? el('div', { class: 'compare-diff-rows' }, rows)
      : el('div', { class: 'faint xs compare-diff-empty' }, ['none']),
  ]);
}

/**
 * Differing-field row: field name with A→B values.
 *
 * @param {*} row {field, a, b}
 * @returns {HTMLElement}
 */
function changedRow(row) {
  return el('div', { class: 'compare-field-row compare-chg' }, [
    el('span', { class: 'compare-field-name mono xs' }, [String(row?.field ?? '')]),
    el('span', { class: 'compare-chg-values' }, [
      el('span', { class: 'compare-chg-a mono xs', title: String(row?.a ?? '') },
        [String(row?.a ?? '')]),
      el('span', { class: 'compare-chg-arrow faint xs' }, ['→']),
      el('span', { class: 'compare-chg-b mono xs', title: String(row?.b ?? '') },
        [String(row?.b ?? '')]),
    ]),
  ]);
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'compare',
  title: 'Compare',
  subtitle: 'A/B entity diff',
  icon: 'layers',
  section: 'investigation',
  order: 40,

  /**
   * Mount the compare workbench.
   *
   * @param {HTMLElement} root #view container.
   * @param {URLSearchParams} params Route params (kindA/targetA/kindB/targetB
   *        prefill the form when present).
   */
  async render(root, params = new URLSearchParams()) {
    const a = sideForm('A');
    const b = sideForm('B');

    // deep-link prefill (e.g. #/compare?kindA=ip&targetA=8.8.8.8&kindB=ip&targetB=1.1.1.1)
    const preA = (params.get('kindA') ?? params.get('kind_a') ?? '').toLowerCase();
    const preB = (params.get('kindB') ?? params.get('kind_b') ?? '').toLowerCase();
    if (KINDS.includes(preA)) a.kind.value = preA;
    if (KINDS.includes(preB)) b.kind.value = preB;
    a.target.value = params.get('targetA') ?? params.get('target_a') ?? '';
    b.target.value = params.get('targetB') ?? params.get('target_b') ?? '';

    const compareBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('layers', { size: 14 }), 'Compare',
    ]);
    const swapBtn = el('button', { class: 'btn', type: 'button',
      title: 'Swap sides A and B' }, [
      icon('refresh', { size: 14 }), 'Swap A ⇄ B',
    ]);
    const clearBtn = el('button', { class: 'btn btn-ghost', type: 'button' }, [
      icon('x', { size: 14 }), 'Clear',
    ]);

    const resultSlot = el('div', { class: 'compare-result' }, [
      emptyState({
        title: 'Nothing compared yet',
        hint: 'Pick a kind and target for each side, then press Compare — both '
          + 'lookups run live and their fields are diffed field by field. '
          + 'Comparing a target against itself is the empty-diff case.',
        icon: 'layers',
      }),
    ]);

    root.replaceChildren(el('div', { class: 'view-compare stack-lg' }, [
      el('div', { class: 'page-head' }, [
        el('div', { class: 'titles' }, [
          el('h1', { class: 'page-title' }, ['Compare']),
          el('p', { class: 'page-desc' }, [
            'Field-level diff between two live lookups — shared infrastructure, '
            + 'copy-paste fraud, infrastructure reuse: see exactly which fields '
            + 'match, which differ and which only one side has.',
          ]),
        ]),
      ]),
      el('div', { class: 'card compare-form-card' }, [
        el('div', { class: 'card-body' }, [
          el('div', { class: 'compare-form' }, [
            a.root,
            el('div', { class: 'compare-form-middle' }, [
              compareBtn,
              swapBtn,
              clearBtn,
            ]),
            b.root,
          ]),
        ]),
      ]),
      resultSlot,
    ]));

    /* ---- wiring --------------------------------------------------------- */

    for (const input of [a.target, b.target]) {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          runCompare();
        }
      });
    }

    compareBtn.addEventListener('click', () => runCompare());
    swapBtn.addEventListener('click', () => {
      const kindA = a.kind.value;
      const targetA = a.target.value;
      a.kind.value = b.kind.value;
      a.target.value = b.target.value;
      b.kind.value = kindA;
      b.target.value = targetA;
      a.errorSlot.replaceChildren();
      b.errorSlot.replaceChildren();
    });
    clearBtn.addEventListener('click', () => {
      a.kind.value = '';
      a.target.value = '';
      b.kind.value = '';
      b.target.value = '';
      a.errorSlot.replaceChildren();
      b.errorSlot.replaceChildren();
      resultSlot.replaceChildren(emptyState({
        title: 'Nothing compared yet',
        hint: 'Pick a kind and target for each side, then press Compare.',
        icon: 'layers',
      }));
    });

    /**
     * Validate both sides; inline notes mark the offending fields.
     *
     * @returns {boolean}
     */
    function validate() {
      let ok = true;
      if (!a.kind.value) {
        a.errorSlot.replaceChildren(dangerNote('Select a kind for side A.'));
        ok = false;
      } else a.errorSlot.replaceChildren();
      if (!a.target.value.trim()) {
        a.errorSlot.replaceChildren(dangerNote('Enter a target for side A.'));
        ok = false;
      } else if (a.kind.value) a.errorSlot.replaceChildren();
      if (!b.kind.value) {
        b.errorSlot.replaceChildren(dangerNote('Select a kind for side B.'));
        ok = false;
      } else b.errorSlot.replaceChildren();
      if (!b.target.value.trim()) {
        b.errorSlot.replaceChildren(dangerNote('Enter a target for side B.'));
        ok = false;
      } else if (b.kind.value) b.errorSlot.replaceChildren();
      return ok;
    }

    async function runCompare() {
      if (!validate()) return;
      const kindA = a.kind.value;
      const targetA = a.target.value.trim();
      const kindB = b.kind.value;
      const targetB = b.target.value.trim();
      compareBtn.disabled = true;
      resultSlot.replaceChildren(ui.loading(
        `Comparing ${targetA} against ${targetB} — both lookups run live…`));
      try {
        const payload = await api.compare(kindA, targetA, kindB, targetB);
        if (!resultSlot.isConnected) return;
        renderResult(payload);
      } catch (err) {
        resultSlot.replaceChildren(failCallout(err, runCompare));
      } finally {
        compareBtn.disabled = false;
      }
    }

    /**
     * Render the three-column comparison result.
     *
     * @param {*} payload /api/compare body.
     */
    function renderResult(payload) {
      const added = Array.isArray(payload?.added) ? payload.added : [];
      const removed = Array.isArray(payload?.removed) ? payload.removed : [];
      const differing = Array.isArray(payload?.differing) ? payload.differing : [];
      const counts = payload?.counts ?? {};

      const countsRow = el('div', { class: 'compare-counts' }, [
        el('div', { class: 'card compare-count' }, [
          el('div', { class: 'compare-count-value' }, [fmtInt(counts.common)]),
          el('div', { class: 'compare-count-label' }, ['common fields']),
        ]),
        el('div', { class: 'card compare-count compare-count--add' }, [
          el('div', { class: 'compare-count-value' }, [fmtInt(counts.added)]),
          el('div', { class: 'compare-count-label' }, ['B only (+)']),
        ]),
        el('div', { class: 'card compare-count compare-count--del' }, [
          el('div', { class: 'compare-count-value' }, [fmtInt(counts.removed)]),
          el('div', { class: 'compare-count-label' }, ['A only (−)']),
        ]),
        el('div', { class: 'card compare-count compare-count--chg' }, [
          el('div', { class: 'compare-count-value' }, [fmtInt(counts.differing)]),
          el('div', { class: 'compare-count-label' }, ['differing']),
        ]),
      ]);

      // A-side field table: fields A carries that B lacks or disagrees with
      const aRows = el('div', { class: 'compare-field-rows' }, [
        ...removed.map((r) => fieldRow(String(r.field), r.value, 'del')),
        ...differing.map((r) => fieldRow(String(r.field), r.a, 'chg')),
      ]);
      // B-side field table: fields B carries that A lacks or disagrees with
      const bRows = el('div', { class: 'compare-field-rows' }, [
        ...added.map((r) => fieldRow(String(r.field), r.value, 'add')),
        ...differing.map((r) => fieldRow(String(r.field), r.b, 'chg')),
      ]);

      const identical = !added.length && !removed.length && !differing.length;
      const centerDiff = identical
        ? el('div', { class: 'callout ok' }, [
          icon('check', { size: 16 }),
          el('div', { class: 'grow sm' }, [
            'No field differences — the two lookups returned the same flattened '
            + 'field set with equal values.',
          ]),
        ])
        : el('div', { class: 'stack' }, [
          diffGroup(`+ ${added.length} added on B`, 'add',
            added.map((r) => fieldRow(String(r.field), r.value, 'add'))),
          diffGroup(`− ${removed.length} removed from A`, 'del',
            removed.map((r) => fieldRow(String(r.field), r.value, 'del'))),
          diffGroup(`± ${differing.length} differing`, 'chg',
            differing.map(changedRow)),
        ]);

      resultSlot.replaceChildren(el('div', { class: 'stack-lg' }, [
        countsRow,
        el('div', { class: 'compare-grid' }, [
          el('div', { class: 'compare-col' }, [
            sideHeader(payload?.a, 'A'),
            el('div', { class: 'card compare-fields-card' }, [
              el('div', { class: 'card-head' }, [
                icon('layers', { size: 14 }),
                el('span', { class: 'card-title' }, ['Fields on A']),
              ]),
              el('div', { class: 'card-body' }, [aRows.children.length
                ? aRows
                : el('span', { class: 'muted xs' },
                  ['No fields unique to A and no differing values.'])]),
            ]),
          ]),
          el('div', { class: 'compare-col compare-col--diff' }, [
            el('div', { class: 'card' }, [
              el('div', { class: 'card-head' }, [
                icon('git', { size: 14 }),
                el('span', { class: 'card-title' }, ['Diff — A versus B']),
              ]),
              el('div', { class: 'card-body' }, [centerDiff]),
            ]),
          ]),
          el('div', { class: 'compare-col' }, [
            sideHeader(payload?.b, 'B'),
            el('div', { class: 'card compare-fields-card' }, [
              el('div', { class: 'card-head' }, [
                icon('layers', { size: 14 }),
                el('span', { class: 'card-title' }, ['Fields on B']),
              ]),
              el('div', { class: 'card-body' }, [bRows.children.length
                ? bRows
                : el('span', { class: 'muted xs' },
                  ['No fields unique to B and no differing values.'])]),
            ]),
          ]),
        ]),
      ]));
    }

    /* auto-run when the deep link carried a full query */
    if (KINDS.includes(preA) && a.target.value.trim()
      && KINDS.includes(preB) && b.target.value.trim()) {
      runCompare();
    }
  },
};

export default view;
