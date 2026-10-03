/**
 * ObscuraLens web UI — Cases view.
 *
 * Investigation case management: a card grid of cases (counts, tags,
 * archive toggles) and a full detail view per case with indicator items,
 * free-form notes and an inline tag input.
 *
 * API shapes are consumed defensively:
 *   list  → [{id, name, description, status, created_at, updated_at,
 *             item_count, note_count, tag_count, items_by_kind?, tags?}]
 *   detail→ {case?: {...}, items?: [...], notes?: [...], tags?: [...]}
 *           (or the same fields flat on the root object).
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';

const {
  el, icon, badge, kindBadge, toastOk, toastErr, toastWarn,
  modal, confirmDialog, dataTable, emptyState, skeleton,
  fmtWhen, fmtAgo, copyable,
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
      el('strong', {}, ['Could not load cases']),
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

const num = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : 0;
};

/** Is this case archived (status field or legacy boolean)? */
function isArchived(c) {
  return c?.status === 'archived' || c?.archived === true;
}

/** Item / note / tag counts from any of the known payload spellings. */
function countsOf(c) {
  return {
    items: c.item_count ?? c.counts?.items ?? (Array.isArray(c.items) ? c.items.length : 0),
    notes: c.note_count ?? c.counts?.notes ?? (Array.isArray(c.notes) ? c.notes.length : 0),
    tags: c.tag_count ?? c.counts?.tags ?? (Array.isArray(c.tags) ? c.tags.length : 0),
  };
}

/** Status badge: open → ok, closed → warn, archived → muted. */
function statusBadge(c) {
  const status = c?.status ?? (isArchived(c) ? 'archived' : 'open');
  if (status === 'archived') return badge('archived', 'muted', { icon: 'folder' });
  if (status === 'closed') return badge('closed', 'warn', { icon: 'lock' });
  return badge('open', 'ok', { dot: true });
}

/** Small "icon + number + label" count chip. */
function countChip(iconName, value, label) {
  return el('span', { class: 'cases-count' }, [
    icon(iconName, { size: 12 }),
    el('span', { class: 'mono xs strong' }, [String(num(value))]),
    el('span', { class: 'faint xs' }, [label]),
  ]);
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'cases',
  title: 'Cases',
  subtitle: 'Investigation case management',
  icon: 'folder',
  section: 'investigation',
  order: 30,

  /**
   * Route between list mode and detail mode.
   * @param {HTMLElement} root
   * @param {URLSearchParams} params `case=<id>` opens the detail view.
   */
  async render(root, params) {
    loadNavigate();
    const caseId = params.get('case');
    if (caseId && /^\d+$/.test(caseId)) await renderDetail(root, Number(caseId));
    else await renderList(root);
  },
};

/* ---------------------------------------------------------------------- */
/* Case list                                                               */
/* ---------------------------------------------------------------------- */

/** Render the case list (cards in a 2-column grid). */
async function renderList(root) {
  const filterSelect = el('select', { class: 'select', 'aria-label': 'Filter cases' }, [
    el('option', { value: 'all' }, ['All cases']),
    el('option', { value: 'active' }, ['Active only']),
    el('option', { value: 'archived' }, ['Archived only']),
  ]);
  const countChipEl = el('span', { class: 'muted sm' });
  const container = el('div', { class: 'stack' });

  root.replaceChildren(el('div', { class: 'stack-lg' }, [
    el('div', { class: 'filter-bar' }, [
      filterSelect,
      countChipEl,
      el('span', { class: 'spacer' }),
      el('button', {
        class: 'btn btn-primary',
        onclick: () => newCaseModal(reload),
      }, [icon('plus', { size: 14 }), 'New case']),
    ]),
    container,
    el('p', { class: 'faint xs' }, [
      'Cases hold indicators, notes and tags. Archiving hides a case from active work; ',
      'permanent deletion is currently available via the CLI only.',
    ]),
  ]));

  let token = 0;

  async function reload() {
    const my = ++token;
    container.replaceChildren(skeleton(3));
    countChipEl.textContent = '';
    try {
      const payload = await api.cases();
      if (my !== token || !container.isConnected) return;
      renderListRows(Array.isArray(payload) ? payload : payload?.cases ?? []);
    } catch (err) {
      if (my !== token || !container.isConnected) return;
      container.replaceChildren(errorCallout(errText(err), reload));
    }
  }

  /** Client-side status filter + card grid. */
  function renderListRows(cases) {
    const mode = filterSelect.value;
    const rows = cases.filter((c) => c && typeof c === 'object' && c.id !== undefined)
      .filter((c) => (mode === 'active' ? !isArchived(c)
        : mode === 'archived' ? isArchived(c) : true));
    countChipEl.textContent = `${cases.length} case${cases.length === 1 ? '' : 's'} stored`;

    if (!rows.length) {
      container.replaceChildren(emptyState({
        title: cases.length ? 'No cases match this filter' : 'No investigation cases yet',
        hint: cases.length
          ? 'Switch the filter above to see archived or active cases.'
          : 'Group indicators, notes and tags for one investigation. Create your first case to get started.',
        icon: 'folder',
        action: el('button', { class: 'btn btn-primary', onclick: () => newCaseModal(reload) }, [
          icon('plus', { size: 14 }), 'New case',
        ]),
      }));
      return;
    }

    container.replaceChildren(el('div', { class: 'grid grid-2' }, rows.map(caseCard)));
  }

  filterSelect.addEventListener('change', () => reload());

  /** One case card. */
  function caseCard(c) {
    const counts = countsOf(c);
    const archived = isArchived(c);
    const byKind = (c.items_by_kind && typeof c.items_by_kind === 'object')
      ? Object.entries(c.items_by_kind) : [];

    return el('div', {
      class: `card card-hover cases-card${archived ? ' cases-archived' : ''}`,
    }, [
      el('div', { class: 'card-head' }, [
        icon('folder', { size: 16 }),
        el('button', {
          class: 'card-title cases-name', type: 'button',
          title: 'Open this case',
          onclick: () => nav('cases', { case: String(c.id) }),
        }, [String(c.name ?? `Case #${c.id}`)]),
        el('span', { class: 'grow' }),
        statusBadge(c),
      ]),
      el('div', { class: 'card-body cases-body' }, [
        el('p', { class: `cases-desc ${c.description ? 'muted sm' : 'faint sm'}` },
          [c.description || 'No description.']),
        el('div', { class: 'cases-counts' }, [
          countChip('layers', counts.items, 'items'),
          countChip('file', counts.notes, 'notes'),
          countChip('tag', counts.tags, 'tags'),
        ]),
        byKind.length ? el('div', { class: 'cases-kinds' }, byKind.map(([kind, count]) =>
          el('span', { class: 'cases-kind' }, [kindBadge(kind), el('span', { class: 'faint xs' }, [`×${num(count)}`])]))) : null,
      ]),
      el('div', { class: 'card-foot cases-foot' }, [
        el('span', { class: 'faint xs', title: c.created_at ? fmtWhen(c.created_at) : '' },
          [`created ${fmtAgo(c.created_at)}`]),
        el('span', { class: 'spacer' }),
        el('button', {
          class: 'btn btn-sm', type: 'button',
          onclick: () => nav('cases', { case: String(c.id) }),
        }, ['Open']),
        el('button', {
          class: 'btn btn-sm btn-ghost', type: 'button',
          title: archived ? 'Return this case to active work' : 'Hide this case from active work',
          onclick: () => toggleArchive(c, archived),
        }, [archived ? 'Unarchive' : 'Archive']),
      ]),
    ]);
  }

  /** Archive / unarchive one case, then refresh. */
  async function toggleArchive(c, archived) {
    try {
      const res = await api.caseUpdate(c.id, { archived: !archived });
      if (res && res.error) {
        toastErr(`Could not ${archived ? 'unarchive' : 'archive'}: ${res.error}`);
        return;
      }
      toastOk(`“${c.name ?? `Case #${c.id}`}” ${archived ? 'unarchived' : 'archived'}`);
      reload();
    } catch (err) {
      toastErr(errText(err));
    }
  }

  await reload();
}

/* ---------------------------------------------------------------------- */
/* "New case" modal                                                        */
/* ---------------------------------------------------------------------- */

/** Open the create-case dialog; calls onDone after a successful create. */
function newCaseModal(onDone) {
  const nameInput = el('input', {
    class: 'input', placeholder: 'e.g. Phishing campaign — ACME finance',
    maxlength: 120, autocomplete: 'off',
  });
  const descInput = el('textarea', {
    class: 'textarea', rows: 4,
    placeholder: 'Scope, hypothesis, linked incidents…',
  });
  const errBox = el('div', { class: 'stack' });
  const submit = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('plus', { size: 14 }), 'Create case',
  ]);
  let close = null;

  submit.addEventListener('click', async () => {
    const name = nameInput.value.trim();
    if (!name) {
      errBox.replaceChildren(dangerNote('A case name is required.'));
      nameInput.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = 'Creating…';
    try {
      const res = await api.caseCreate({ name, description: descInput.value.trim() });
      if (res && res.error) {
        errBox.replaceChildren(dangerNote(
          `${res.error}${res.id ? ` — an existing case already uses this name (#${res.id}).` : ''}`));
        submit.disabled = false;
        submit.replaceChildren(icon('plus', { size: 14 }), 'Create case');
        return;
      }
      toastOk(`Case “${name}” created`);
      close?.();
      onDone?.();
    } catch (err) {
      errBox.replaceChildren(dangerNote(errText(err)));
      submit.disabled = false;
      submit.replaceChildren(icon('plus', { size: 14 }), 'Create case');
    }
  });

  close = modal({
    title: 'New investigation case',
    body: el('div', { class: 'stack' }, [
      fieldEl('Name *', nameInput, 'Unique across the workspace.'),
      fieldEl('Description', descInput, 'Optional — what this case covers.'),
      errBox,
    ]),
    foot: [
      el('button', { class: 'btn btn-ghost', type: 'button', onclick: () => close?.() }, ['Cancel']),
      submit,
    ],
  });
}

/* ---------------------------------------------------------------------- */
/* Case detail                                                             */
/* ---------------------------------------------------------------------- */

/**
 * Normalise the case-detail payload for both nested and flat shapes.
 * @returns {{info: object, items: Array, notes: Array, tags: Array}|null}
 */
function normalizeDetail(data) {
  if (!data || typeof data !== 'object') return null;
  const inner = (data.case && typeof data.case === 'object') ? data.case : data;
  const pick = (src, key) => (Array.isArray(src?.[key]) ? src[key] : null);
  return {
    info: { ...inner },
    items: pick(data, 'items') ?? pick(inner, 'items') ?? [],
    notes: pick(data, 'notes') ?? pick(inner, 'notes') ?? [],
    tags: pick(data, 'tags') ?? pick(inner, 'tags') ?? [],
  };
}

/** Render one case with items, notes and tags. */
async function renderDetail(root, id) {
  const container = el('div', { class: 'stack-lg' });
  root.replaceChildren(container);
  container.replaceChildren(skeleton(6));

  let token = 0;

  async function load() {
    const my = ++token;
    container.replaceChildren(skeleton(6));
    try {
      const data = await api.caseGet(id);
      if (my !== token || !container.isConnected) return;
      const norm = normalizeDetail(data);
      if (!norm || norm.info.error || norm.info.id === undefined) {
        container.replaceChildren(emptyState({
          title: norm?.info?.error ? 'Case unavailable' : 'Case not found',
          hint: norm?.info?.error ?? `No case with id ${id} exists (it may have been deleted via the CLI).`,
          icon: 'alert',
          action: el('button', { class: 'btn', type: 'button', onclick: () => nav('cases') }, [
            'All cases',
          ]),
        }));
        return;
      }
      render(norm);
    } catch (err) {
      if (my !== token || !container.isConnected) return;
      container.replaceChildren(errorCallout(errText(err), load));
    }
  }

  /** Paint the whole detail view from normalised data. */
  function render({ info, items, notes, tags }) {
    const archived = isArchived(info);
    const backIcon = icon('chevronRight', { size: 15 });
    backIcon.style.transform = 'rotate(180deg)';

    /* -- header card ------------------------------------------------- */
    const tagInput = el('input', {
      class: 'input input-mono cases-tag-input', placeholder: 'add tag…',
      maxlength: 40, 'aria-label': 'Add a tag', spellcheck: 'false',
    });
    tagInput.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      e.preventDefault();
      const tag = tagInput.value.trim().toLowerCase();
      if (!tag) return;
      addTag(tag);
    });

    async function addTag(tag) {
      tagInput.disabled = true;
      try {
        const res = await api.caseAddTag(id, { tag });
        if (res && res.error) { toastErr(`Tag not added: ${res.error}`); return; }
        toastOk(`Tag “${tag}” added`);
        load();
      } catch (err) {
        toastErr(errText(err));
      } finally {
        tagInput.disabled = false;
      }
    }

    const header = el('div', { class: 'card' }, [
      el('div', { class: 'card-body stack cases-detail' }, [
        el('div', { class: 'flex wrap gap-2' }, [
          el('button', { class: 'btn btn-sm btn-ghost', type: 'button', onclick: () => nav('cases') }, [
            backIcon, 'All cases',
          ]),
          el('span', { class: 'spacer' }),
          statusBadge(info),
        ]),
        el('h2', { class: 'cases-title' }, [String(info.name ?? `Case #${id}`)]),
        el('div', { class: 'faint xs' }, [
          `created ${fmtWhen(info.created_at)} · updated ${fmtWhen(info.updated_at)}`,
        ]),
        info.description
          ? el('p', { class: 'muted sm' }, [String(info.description)])
          : null,
        el('div', { class: 'cases-tagbar' }, [
          el('span', { class: 'tag-list' },
            tags.map((t) => el('span', { class: 'tag' }, [String(t)]))),
          tagInput,
        ]),
        el('div', { class: 'flex wrap gap-2' }, [
          el('button', {
            class: 'btn btn-primary btn-sm', type: 'button',
            onclick: () => addItemModal(id, load),
          }, [icon('plus', { size: 13 }), 'Add item']),
          el('button', {
            class: 'btn btn-sm', type: 'button',
            onclick: () => addNoteModal(id, load),
          }, [icon('file', { size: 13 }), 'Add note']),
          el('button', {
            class: 'btn btn-sm btn-ghost', type: 'button',
            onclick: () => toggleArchive(info, archived),
          }, [archived ? 'Unarchive case' : 'Archive case']),
        ]),
      ]),
    ]);

    async function toggleArchive(info2, isArch) {
      try {
        const res = await api.caseUpdate(id, { archived: !isArch });
        if (res && res.error) { toastErr(`Could not update: ${res.error}`); return; }
        toastOk(isArch ? 'Case unarchived' : 'Case archived');
        load();
      } catch (err) {
        toastErr(errText(err));
      }
    }

    /* -- items table -------------------------------------------------- */
    const itemsCard = el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        icon('layers', { size: 16 }),
        el('span', { class: 'card-title' }, ['Indicators']),
        badge(`${items.length}`, 'accent'),
      ]),
      el('div', { class: 'card-body-tight' }, [items.length
        ? dataTable({
          columns: [
            { key: 'kind', label: 'Kind', render: (row) => kindBadge(String(row.kind ?? 'other')) },
            { key: 'value', label: 'Target', render: (row) => itemTargetCell(row) },
            { key: 'added', label: 'Added', value: (row) => timeOf(row.added_at),
              render: (row) => el('span', { class: 'muted sm nowrap' }, [fmtWhen(row.added_at)]) },
          ],
          rows: items,
          rowClass: () => '',
          empty: 'No indicators yet',
        })
        : emptyState({
          title: 'No indicators in this case',
          hint: 'Add IPs, domains, hashes… you are investigating so they stay grouped and re-runnable.',
          icon: 'layers',
          action: el('button', { class: 'btn btn-sm btn-primary', type: 'button', onclick: () => addItemModal(id, load) }, [
            icon('plus', { size: 13 }), 'Add item',
          ]),
        })]),
    ]);

    function itemTargetCell(row) {
      const value = String(row.value ?? row.target ?? '');
      const kind = String(row.kind ?? '').toLowerCase();
      const hint = KINDS.includes(kind)
        ? `Look up as ${KIND_META[kind]?.label ?? kind}` : 'Indicator value';
      return el('span', {
        class: 'cases-item-target', title: hint,
        ...(KINDS.includes(kind) ? {
          role: 'button', tabindex: 0,
          onclick: () => nav('lookup', { kind, target: value }),
          onkeydown: (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              nav('lookup', { kind, target: value });
            }
          },
        } : {}),
      }, [copyable(value, { short: 42 })]);
    }

    /* -- notes list ---------------------------------------------------- */
    const sortedNotes = [...notes].sort((a, b) => timeOf(b.created_at) - timeOf(a.created_at));
    const notesCard = el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        icon('file', { size: 16 }),
        el('span', { class: 'card-title' }, ['Notes']),
        badge(`${notes.length}`, 'info'),
      ]),
      el('div', { class: 'card-body-tight stack' },
        sortedNotes.length ? sortedNotes.map(noteCard) : emptyState({
          title: 'No notes yet',
          hint: 'Record observations, hypotheses and next steps — notes become the case timeline.',
          icon: 'file',
          action: el('button', { class: 'btn btn-sm', type: 'button', onclick: () => addNoteModal(id, load) }, [
            icon('plus', { size: 13 }), 'Add note',
          ]),
        })),
    ]);

    function noteCard(n) {
      const body = String(n.body ?? n.note ?? n.text ?? '');
      return el('div', { class: 'cases-note' }, [
        el('div', { class: 'cases-note-head' }, [
          icon('clock', { size: 13 }),
          el('span', { class: 'muted xs nowrap', title: fmtAgo(n.created_at) },
            [fmtWhen(n.created_at)]),
        ]),
        el('div', { class: 'cases-note-body mono sm' }, [body || '—']),
      ]);
    }

    container.replaceChildren(header, itemsCard, notesCard);
  }

  await load();
}

/* ---------------------------------------------------------------------- */
/* Add-item / add-note modals                                              */
/* ---------------------------------------------------------------------- */

/** Open the add-indicator dialog for a case. */
function addItemModal(id, onDone) {
  const kindSelect = el('select', { class: 'select', 'aria-label': 'Indicator kind' }, [
    el('option', { value: 'auto' }, ['auto-detect']),
    ...KINDS.map((k) => el('option', { value: k }, [KIND_META[k]?.label ?? k])),
    el('option', { value: 'other' }, ['other / free-form']),
  ]);
  const targetInput = el('input', {
    class: 'input input-mono', placeholder: 'e.g. 8.8.8.8', spellcheck: 'false',
    autocomplete: 'off',
  });
  const errBox = el('div', { class: 'stack' });
  const submit = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('plus', { size: 14 }), 'Add item',
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
      const res = await api.caseAddItem(id, {
        kind: kindSelect.value, target,
      });
      if (res && res.error) {
        errBox.replaceChildren(dangerNote(`Item not added: ${res.error}`));
        submit.disabled = false;
        submit.replaceChildren(icon('plus', { size: 14 }), 'Add item');
        return;
      }
      toastOk('Indicator added to case');
      close?.();
      onDone?.();
    } catch (err) {
      errBox.replaceChildren(dangerNote(errText(err)));
      submit.disabled = false;
      submit.replaceChildren(icon('plus', { size: 14 }), 'Add item');
    }
  });

  close = modal({
    title: 'Add indicator to case',
    body: el('div', { class: 'stack' }, [
      fieldEl('Kind', kindSelect, 'Auto-detect picks the tracker matching the value.'),
      fieldEl('Target *', targetInput),
      errBox,
    ]),
    foot: [
      el('button', { class: 'btn btn-ghost', type: 'button', onclick: () => close?.() }, ['Cancel']),
      submit,
    ],
  });
}

/** Open the add-note dialog for a case. */
function addNoteModal(id, onDone) {
  const noteInput = el('textarea', {
    class: 'textarea', rows: 6,
    placeholder: 'What did you observe? Sources, timestamps, hypotheses…',
  });
  const errBox = el('div', { class: 'stack' });
  const submit = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('file', { size: 14 }), 'Add note',
  ]);
  let close = null;

  submit.addEventListener('click', async () => {
    const note = noteInput.value.trim();
    if (!note) {
      errBox.replaceChildren(dangerNote('The note body is empty.'));
      noteInput.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = 'Saving…';
    try {
      const res = await api.caseAddNote(id, { note });
      if (res && res.error) {
        errBox.replaceChildren(dangerNote(`Note not added: ${res.error}`));
        submit.disabled = false;
        submit.replaceChildren(icon('file', { size: 14 }), 'Add note');
        return;
      }
      toastOk('Note added');
      close?.();
      onDone?.();
    } catch (err) {
      errBox.replaceChildren(dangerNote(errText(err)));
      submit.disabled = false;
      submit.replaceChildren(icon('file', { size: 14 }), 'Add note');
    }
  });

  close = modal({
    title: 'Add case note',
    body: el('div', { class: 'stack' }, [fieldEl('Note *', noteInput), errBox]),
    foot: [
      el('button', { class: 'btn btn-ghost', type: 'button', onclick: () => close?.() }, ['Cancel']),
      submit,
    ],
  });
}

export default view;
