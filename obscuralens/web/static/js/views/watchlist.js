/**
 * ObscuraLens web UI — Watchlist view.
 *
 * Monitored targets and change detection: add targets (auto-kind), check
 * one or all watches, view snapshot diffs (added / removed / changed
 * fields) and remove entries.
 *
 * API shapes are consumed defensively:
 *   list  → [{id, target, kind, label, created_at|added_at, last_checked,
 *             snapshots?}]
 *   check → [{watch_id|id, target, kind, checked_at, is_first?, added?,
 *             removed?, changed?|changes?|changed_fields?, success?, error?}]
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';

const {
  el, icon, badge, kindBadge, toastOk, toastErr, toastWarn, toastInfo,
  modal, confirmDialog, dataTable, emptyState, skeleton,
  fmtWhen, fmtAgo, copyable, jsonBlock,
} = ui;

/* ---------------------------------------------------------------------- */
/* Navigation (lazy — see timeline.js for the rationale)                   */
/* ---------------------------------------------------------------------- */

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
      el('strong', {}, ['Watchlist could not be loaded']),
      el('div', { class: 'muted sm' }, [message]),
    ]),
    onRetry ? el('button', { class: 'btn btn-sm', onclick: onRetry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]) : null,
  ]);
}

/** Compact danger note for inline form feedback inside modals. */
function dangerNote(text) {
  return el('div', { class: 'callout danger' }, [
    icon('alert', { size: 14 }),
    el('div', { class: 'grow sm' }, [text]),
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

/** Epoch-ms for a timestamp-ish value (0 when unparseable). */
function timeOf(value) {
  if (value === null || value === undefined || value === '') return 0;
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
  const t = Date.parse(String(value));
  return Number.isFinite(t) ? t : 0;
}

/** Coerce a value to a plain string ('' for nullish). */
const str = (v) => (v === null || v === undefined ? '' : String(v));

/** Object-only view of a value (null for arrays/scalars). */
function asDict(value) {
  return (value && typeof value === 'object' && !Array.isArray(value)) ? value : null;
}

/* ---------------------------------------------------------------------- */
/* Diff rendering (tolerates every known diff payload shape)               */
/* ---------------------------------------------------------------------- */

/**
 * Build the body content describing one diff result.
 * Handles WatchDiff ({added, removed, changed}) as well as
 * {changes|changed_fields: [...]} and {fields: {...}} shapes.
 */
function diffBody(diff) {
  const parts = [];

  if (diff.error) {
    parts.push(el('div', { class: 'callout danger' }, [
      icon('alert', { size: 14 }),
      el('div', { class: 'grow sm' }, [`Check failed: ${diff.error}`]),
    ]));
  }
  if (diff.is_first) {
    parts.push(el('div', { class: 'callout info' }, [
      icon('info', { size: 14 }),
      el('div', { class: 'grow sm' }, [
        'First snapshot recorded — a baseline was stored. Future checks will diff against it.',
      ]),
    ]));
  }

  const added = asDict(diff.added ?? diff.added_fields);
  if (added && Object.keys(added).length) {
    parts.push(el('div', { class: 'watch-diff-group' }, [
      el('div', { class: 'watch-diff-label' }, [
        badge(`+ ${Object.keys(added).length} new`, 'ok'),
      ]),
      el('div', { class: 'watch-diff-rows' }, Object.entries(added).map(([field, value]) =>
        el('div', { class: 'watch-diff-row watch-diff-add' }, [
          el('span', { class: 'watch-diff-field mono xs' }, [field]),
          el('span', { class: 'watch-diff-val mono sm break-all' }, [str(value)]),
        ]))),
    ]));
  }

  const removed = asDict(diff.removed ?? diff.removed_fields);
  if (removed && Object.keys(removed).length) {
    parts.push(el('div', { class: 'watch-diff-group' }, [
      el('div', { class: 'watch-diff-label' }, [
        badge(`− ${Object.keys(removed).length} gone`, 'danger'),
      ]),
      el('div', { class: 'watch-diff-rows' }, Object.entries(removed).map(([field, value]) =>
        el('div', { class: 'watch-diff-row watch-diff-del' }, [
          el('span', { class: 'watch-diff-field mono xs' }, [field]),
          el('span', { class: 'watch-diff-val mono sm' }, [str(value)]),
        ]))),
    ]));
  }

  /* Changed fields: dict {field: {from,to}|{old,new}|[old,new]} or a list. */
  const changedRows = [];
  const changed = asDict(diff.changed ?? diff.changed_fields);
  if (changed) {
    for (const [field, raw] of Object.entries(changed)) {
      let from = ''; let to = '';
      const d = asDict(raw);
      if (d) { from = str(d.from ?? d.old ?? d.before ?? ''); to = str(d.to ?? d.new ?? d.after ?? ''); }
      else if (Array.isArray(raw) && raw.length >= 2) { from = str(raw[0]); to = str(raw[1]); }
      else { from = '—'; to = str(raw); }
      changedRows.push([field, from, to]);
    }
  }
  const changeList = Array.isArray(diff.changes) ? diff.changes : [];
  for (const change of changeList) {
    const d = asDict(change);
    if (!d) continue;
    changedRows.push([
      str(d.field ?? d.name ?? d.key ?? ''),
      str(d.from ?? d.old ?? d.before ?? ''),
      str(d.to ?? d.new ?? d.after ?? d.value ?? ''),
    ]);
  }
  if (changedRows.length) {
    parts.push(el('div', { class: 'watch-diff-group' }, [
      el('div', { class: 'watch-diff-label' }, [
        badge(`~ ${changedRows.length} changed`, 'warn'),
      ]),
      el('div', { class: 'watch-diff-rows' }, changedRows.map(([field, from, to]) =>
        el('div', { class: 'watch-diff-row' }, [
          el('span', { class: 'watch-diff-field mono xs' }, [field]),
          el('span', { class: 'watch-diff-val mono sm' }, [
            el('span', { class: 'watch-diff-old muted' }, [from || '—']),
            ' → ',
            el('span', { class: 'strong break-all' }, [to || '—']),
          ]),
        ]))),
    ]));
  }

  /* Nothing recognisable — surface raw scalars, then the raw JSON. */
  if (!parts.length) {
    const scalars = Object.entries(diff)
      .filter(([k, v]) => !['added', 'removed', 'changed', 'changes', 'changed_fields'].includes(k)
        && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'))
      .slice(0, 8);
    if (scalars.length) {
      parts.push(el('div', { class: 'watch-diff-rows' }, scalars.map(([k, v]) =>
        el('div', { class: 'watch-diff-row' }, [
          el('span', { class: 'watch-diff-field mono xs' }, [k]),
          el('span', { class: 'watch-diff-val mono sm' }, [str(v)]),
        ]))));
    }
    parts.push(jsonBlock(diff, 'Raw diff payload'));
  }
  return parts;
}

/**
 * Open a modal listing diffs for one or more targets.
 * @param {string} title
 * @param {Array<object>} diffs
 */
function openDiffsModal(title, diffs) {
  const meaningful = diffs.filter((d) =>
    d && (d.error || d.is_first
      || Object.keys(asDict(d.added ?? d.added_fields) ?? {}).length
      || Object.keys(asDict(d.removed ?? d.removed_fields) ?? {}).length
      || Object.keys(asDict(d.changed ?? d.changed_fields) ?? {}).length
      || Array.isArray(d.changes)));
  if (!meaningful.length) {
    toastInfo('No changes detected since the last check');
    return;
  }
  modal({
    title,
    wide: true,
    body: el('div', { class: 'stack' }, meaningful.map((diff) => {
      const target = str(diff.target ?? diff.watch_id ?? diff.id ?? 'unknown');
      const kind = str(diff.kind).toLowerCase();
      const checkedAt = timeOf(diff.checked_at);
      return el('div', { class: 'card watch-diff' }, [
        el('div', { class: 'card-head' }, [
          icon('eye', { size: 15 }),
          el('span', { class: 'card-title mono' }, [target]),
          kind ? kindBadge(kind) : null,
          el('span', { class: 'grow' }),
          checkedAt
            ? el('span', { class: 'muted xs nowrap', title: fmtAgo(checkedAt) },
              [fmtWhen(checkedAt)])
            : null,
        ]),
        el('div', { class: 'card-body-tight stack' }, diffBody(diff)),
      ]);
    })),
    foot: [el('button', { class: 'btn', type: 'button', onclick: () => undefined }, ['Close'])],
  });
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'watchlist',
  title: 'Watchlist',
  subtitle: 'Monitored targets & change detection',
  icon: 'eye',
  section: 'investigation',
  order: 40,

  /**
   * Mount the watchlist.
   * @param {HTMLElement} root
   */
  async render(root) {
    loadNavigate();

    const countChipEl = el('span', { class: 'muted sm' });
    const container = el('div');
    const checkAllBtn = el('button', { class: 'btn', type: 'button' }, [
      icon('refresh', { size: 14 }), 'Check all now',
    ]);

    checkAllBtn.addEventListener('click', () => checkAll());

    root.replaceChildren(el('div', { class: 'stack-lg' }, [
      el('div', { class: 'filter-bar' }, [
        countChipEl,
        el('span', { class: 'spacer' }),
        checkAllBtn,
        el('button', {
          class: 'btn btn-primary', type: 'button',
          onclick: () => addWatchModal(reload),
        }, [icon('plus', { size: 14 }), 'Add target']),
      ]),
      container,
    ]));

    let token = 0;

    async function reload() {
      const my = ++token;
      container.replaceChildren(skeleton(4));
      countChipEl.textContent = '';
      try {
        const payload = await api.watchList();
        if (my !== token || !container.isConnected) return;
        const rows = (Array.isArray(payload) ? payload : payload?.watches ?? [])
          .filter((w) => w && typeof w === 'object' && (w.target || w.id !== undefined));
        render(rows);
      } catch (err) {
        if (my !== token || !container.isConnected) return;
        container.replaceChildren(errorCallout(errText(err), reload));
      }
    }

    /** Render the watch table. */
    function render(rows) {
      countChipEl.textContent = `${rows.length} target${rows.length === 1 ? '' : 's'} monitored`;
      if (!rows.length) {
        container.replaceChildren(emptyState({
          title: 'Nothing is being monitored yet',
          hint: 'Add a target to the watchlist and ObscuraLens stores periodic snapshots of its lookup results — then tells you exactly which fields changed between checks (new DNS records, changed WHOIS, new breach appearances…).',
          icon: 'eye',
          action: el('button', { class: 'btn btn-primary', type: 'button', onclick: () => addWatchModal(reload) }, [
            icon('plus', { size: 14 }), 'Add target',
          ]),
        }));
        return;
      }

      container.replaceChildren(dataTable({
        columns: [
          { key: 'target', label: 'Target', render: targetCell },
          { key: 'label', label: 'Label', render: labelCell },
          {
            key: 'added', label: 'Added',
            value: (row) => timeOf(row.added_at ?? row.created_at),
            render: (row) => whenCell(row.added_at ?? row.created_at),
          },
          {
            key: 'checked', label: 'Last checked',
            value: (row) => timeOf(row.last_checked),
            render: (row) => whenCell(row.last_checked),
          },
          { key: 'actions', label: 'Actions', sortable: false, render: actionsCell },
        ],
        rows,
        empty: 'No watched targets',
      }));
    }

    /** Target cell: mono copyable, opens the lookup when the kind is known. */
    function targetCell(row) {
      const target = str(row.target);
      const kind = str(row.kind).toLowerCase();
      const inner = el('span', { class: 'watch-target' }, [
        copyable(target, { short: 40 }),
        Number(row.snapshots) > 0
          ? el('span', { class: 'watch-snaps faint xs', title: 'Stored snapshots' },
            [`${Number(row.snapshots)} snaps`])
          : null,
      ]);
      if (target && KINDS.includes(kind)) {
        inner.classList.add('watch-target-link');
        inner.title = `Look up as ${KIND_META[kind]?.label ?? kind}`;
        inner.setAttribute('role', 'button');
        inner.setAttribute('tabindex', '0');
        inner.addEventListener('click', () => nav('lookup', { kind, target }));
        inner.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            nav('lookup', { kind, target });
          }
        });
      }
      return inner;
    }

    function labelCell(row) {
      const label = str(row.label);
      return label
        ? el('span', { class: 'sm' }, [label])
        : el('span', { class: 'faint' }, ['—']);
    }

    function whenCell(value) {
      const t = timeOf(value);
      return t
        ? el('span', { class: 'muted sm nowrap', title: fmtAgo(t) }, [fmtWhen(t)])
        : el('span', { class: 'faint sm' }, ['never']);
    }

    /** Per-row action buttons. */
    function actionsCell(row) {
      const id = row.id ?? row.target;
      const target = str(row.target);
      const kind = str(row.kind).toLowerCase();

      const checkBtn = el('button', {
        class: 'btn btn-sm', type: 'button', title: 'Re-check this target now',
        onclick: () => checkOne(id, row),
      }, [icon('refresh', { size: 12 }), 'Check']);

      const diffBtn = el('button', {
        class: 'btn btn-sm btn-ghost', type: 'button',
        title: 'Diff the two most recent stored snapshots',
        onclick: () => openDiffView(kind, target),
      }, [icon('layers', { size: 12 }), 'Diff']);

      const removeBtn = el('button', {
        class: 'btn btn-sm btn-ghost icon-btn-danger watch-remove', type: 'button',
        title: 'Remove this watch', 'aria-label': `Remove ${target || 'watch'}`,
        onclick: () => removeWatch(id, target),
      }, [icon('trash', { size: 12 })]);

      return el('span', { class: 'watch-actions' }, [checkBtn, diffBtn, removeBtn]);
    }

    /** Check every watch and summarise the outcome. */
    async function checkAll() {
      checkAllBtn.disabled = true;
      checkAllBtn.replaceChildren(ui.loading('Checking all…'));
      try {
        const diffs = await api.watchCheck();
        if (!container.isConnected) return;
        openDiffsModal('Watchlist check — changed targets', Array.isArray(diffs) ? diffs : [diffs]);
        reload();
      } catch (err) {
        toastErr(`Check failed: ${errText(err)}`);
      } finally {
        checkAllBtn.disabled = false;
        checkAllBtn.replaceChildren(icon('refresh', { size: 14 }), 'Check all now');
      }
    }

    /** Check a single watch (by id) and show its diff. */
    async function checkOne(id, row) {
      const target = str(row.target);
      toastInfo(`Checking ${target || 'target'}…`);
      try {
        const diffs = await api.watchCheck(id);
        const list = Array.isArray(diffs) ? diffs : [diffs];
        if (!list.length) {
          toastWarn(`Watch ${target || id} not found — it may have been removed`);
          return;
        }
        openDiffsModal(`Check — ${target || `watch #${id}`}`, list);
        reload();
      } catch (err) {
        toastErr(`Check failed: ${errText(err)}`);
      }
    }

    /** Open the stored-snapshot diff view for one target (errors tolerated). */
    async function openDiffView(kind, target) {
      if (!target) { toastWarn('No target to diff'); return; }
      let close = null;
      const body = el('div', {}, [ui.loading('Diffing stored snapshots…')]);
      close = modal({ title: `Snapshot diff — ${target}`, wide: true, body });
      try {
        const res = await api.diff(kind && KINDS.includes(kind) ? kind : 'auto', target);
        body.replaceChildren(...diffBody(res && typeof res === 'object' && !Array.isArray(res)
          ? res : { changes: Array.isArray(res) ? res : [] }));
      } catch (err) {
        body.replaceChildren(el('div', { class: 'callout warn' }, [
          icon('alert', { size: 14 }),
          el('div', { class: 'grow sm' }, [
            `Diff unavailable: ${errText(err)} — at least two snapshots are needed.`,
          ]),
        ]));
      }
    }

    /** Remove a watch after confirmation. */
    async function removeWatch(id, target) {
      const confirmed = await confirmDialog(
        'Remove watched target?',
        `Stop monitoring ${target || `watch #${id}`}? Stored snapshots remain in the database for auditing.`,
        { danger: true, confirmLabel: 'Remove' },
      );
      if (!confirmed) return;
      try {
        await api.watchRemove(id);
        toastOk(`Removed ${target || `watch #${id}`}`);
        reload();
      } catch (err) {
        toastErr(`Could not remove: ${errText(err)}`);
      }
    }

    await reload();
  },
};

/* ---------------------------------------------------------------------- */
/* "Add target" modal                                                      */
/* ---------------------------------------------------------------------- */

/** Open the add-watch dialog; refreshes the list on success. */
function addWatchModal(onDone) {
  const targetInput = el('input', {
    class: 'input input-mono', placeholder: 'e.g. example.com, 8.8.8.8, user@corp.com',
    spellcheck: 'false', autocomplete: 'off',
  });
  const labelInput = el('input', {
    class: 'input', placeholder: 'e.g. CFO’s blog — monthly', maxlength: 80,
    autocomplete: 'off',
  });
  const errBox = el('div', { class: 'stack' });
  const submit = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('plus', { size: 14 }), 'Watch target',
  ]);
  let close = null;

  targetInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); submit.click(); }
  });

  submit.addEventListener('click', async () => {
    const target = targetInput.value.trim();
    if (!target) {
      errBox.replaceChildren(dangerNote('A target value is required.'));
      targetInput.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = 'Adding…';
    try {
      const res = await api.watchAdd({ target, label: labelInput.value.trim() });
      if (res && res.error) {
        errBox.replaceChildren(dangerNote(`Target not added: ${res.error}`));
        submit.disabled = false;
        submit.replaceChildren(icon('plus', { size: 14 }), 'Watch target');
        return;
      }
      toastOk(`Now watching ${target}`);
      close?.();
      onDone?.();
    } catch (err) {
      errBox.replaceChildren(dangerNote(errText(err)));
      submit.disabled = false;
      submit.replaceChildren(icon('plus', { size: 14 }), 'Watch target');
    }
  });

  close = modal({
    title: 'Watch a target',
    body: el('div', { class: 'stack' }, [
      fieldEl('Target *', targetInput, 'Kind is auto-detected (IP, domain, email, hash…).'),
      fieldEl('Label', labelInput, 'Optional note shown in the list.'),
      errBox,
    ]),
    foot: [
      el('button', { class: 'btn btn-ghost', type: 'button', onclick: () => close?.() }, ['Cancel']),
      submit,
    ],
  });
}

export default view;
