/**
 * ObscuraLens web UI — settings view.
 *
 * Three tabs over the platform endpoints:
 *   • API keys  — configure keyed sources (stored locally in
 *     config/secrets.yaml, never transmitted);
 *   • Runtime   — the flat dotted-path settings the server exposes, with
 *     switches for booleans and Set buttons for numbers/strings;
 *   • Alerts    — webhook notification configuration + test delivery +
 *     recent notification log.
 *
 * Every tab degrades gracefully: loading skeletons, inline danger
 * callouts with retry buttons, and empty states instead of dead ends.
 */
import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';
import { navigate } from '../main.js';

const {
  el, icon, badge, dataTable, emptyState, skeleton, modal, confirmDialog, tabs,
  toastOk, toastWarn, toastErr, fmtWhen, fmtAgo,
} = ui;

/** Canonical webhook event names (fallback when the backend returns none). */
const DEFAULT_EVENTS = ['lookup_failed', 'watch_diff', 'risk_high', 'source_tripped'];

/** Tab keys (deep-linkable via #/settings?tab=…). */
const TAB_KEYS = ['keys', 'runtime', 'alerts'];

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
 * Danger callout + retry button for a failed tab load.
 *
 * @param {string} title
 * @param {*} err
 * @param {() => void} retry
 * @returns {Node}
 */
function failBlock(title, err, retry) {
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
 * Set a button into / out of a busy state and swap its trailing label.
 *
 * @param {HTMLButtonElement} btn
 * @param {boolean} on
 * @param {string} [label]
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
/* Tab 1 — API keys                                                     */
/* ------------------------------------------------------------------ */

/**
 * Build the API-keys tab panel.
 *
 * @returns {HTMLElement}
 */
function keysPanel() {
  const body = el('div', { class: 'stack' }, [skeleton(5)]);
  const wrap = el('div', {}, [body]);

  /** Fetch the key registry and render the table. */
  async function load() {
    body.replaceChildren(skeleton(5));
    try {
      const res = await api.keys();
      if (!wrap.isConnected) return;
      const list = Array.isArray(res) ? res : (res?.keys ?? []);
      body.replaceChildren(...renderKeys(list));
    } catch (err) {
      if (!wrap.isConnected) return;
      body.replaceChildren(failBlock('Could not load API keys', err, load));
    }
  }

  /**
   * Render the keys table + privacy note.
   *
   * @param {Array<*>} list
   * @returns {Node[]}
   */
  function renderKeys(list) {
    const nodes = [
      el('div', { class: 'callout info' }, [
        icon('lock'),
        el('div', { class: 'sm' }, [
          'Keys are stored locally in ',
          el('code', {}, ['config/secrets.yaml']),
          ' on the machine running ObscuraLens and are never transmitted '
          + 'to any remote service.',
        ]),
      ]),
    ];
    if (!list.length) {
      nodes.push(emptyState({
        title: 'No keyed services',
        hint: 'Every free source works without keys. Keyed sources appear here '
          + 'once the backend reports them.',
        icon: 'key',
      }));
      return nodes;
    }

    nodes.push(dataTable({
      columns: [
        {
          key: 'service', label: 'Service',
          value: (row) => row.service,
          render: (row) => el('span', { class: 'flex gap-2 wrap' }, [
            el('span', { class: 'mono strong sm' }, [String(row.service ?? '—')]),
            typeof row.doc === 'string' && /^https?:\/\//.test(row.doc)
              ? el('a', {
                class: 'icon-btn', href: row.doc, target: '_blank', rel: 'noopener',
                title: 'Documentation', 'aria-label': `Documentation for ${row.service}`,
              }, [icon('external', { size: 13 })])
              : null,
          ]),
        },
        {
          key: 'status', label: 'Status',
          value: (row) => (row.configured ? 1 : 0),
          render: (row) => (row.configured
            ? badge('configured', 'ok', { icon: 'check' })
            : badge('not set', 'muted')),
        },
        {
          key: 'description', label: 'Description', sortable: false,
          render: (row) => el('span', {
            class: 'muted sm', title: row.description ?? undefined,
          }, [String(row.description ?? '—')]),
        },
        {
          key: 'actions', label: 'Actions', sortable: false,
          render: (row) => el('span', { class: 'flex gap-2' }, [
            el('button', {
              class: 'btn btn-sm', type: 'button',
              onclick: () => setKeyModal(String(row.service ?? '')),
            }, [icon('key', { size: 12 }), 'Set key']),
            row.configured ? el('button', {
              class: 'btn btn-sm btn-danger', type: 'button',
              onclick: () => clearKey(String(row.service ?? '')),
            }, [icon('trash', { size: 12 }), 'Clear']) : null,
          ]),
        },
      ],
      rows: list.filter((row) => row && typeof row === 'object'),
      empty: 'No keyed services',
    }));
    return nodes;
  }

  /**
   * Open the password modal that stores a service key.
   *
   * @param {string} service
   */
  function setKeyModal(service) {
    const input = el('input', {
      class: 'input input-mono', type: 'password',
      autocomplete: 'off', spellcheck: 'false',
      placeholder: `Paste the ${service} key`,
      'aria-label': `${service} API key`,
    });
    const saveBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('check'), 'Save key',
    ]);
    saveBtn.addEventListener('click', async () => {
      const key = input.value.trim();
      if (!key) {
        toastWarn('Paste a key first');
        input.focus();
        return;
      }
      busy(saveBtn, true, 'Saving…');
      try {
        await api.keySet(service, key);
        toastOk(`${service} key saved to config/secrets.yaml`);
        closeRef?.();
        load();
      } catch (err) {
        toastErr(errText(err));
        busy(saveBtn, false);
      }
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') saveBtn.click();
    });

    let closeRef = null;
    closeRef = modal({
      title: `Set ${service} key`,
      body: el('div', { class: 'stack' }, [
        el('div', { class: 'field' }, [
          el('label', { class: 'field-label' }, ['API key']),
          input,
          el('span', { class: 'field-hint' },
            ['Stored locally only — never sent to third parties.']),
        ]),
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

  /**
   * Confirm + clear a configured key.
   *
   * @param {string} service
   */
  async function clearKey(service) {
    const confirmed = await confirmDialog(
      `Clear the ${service} key?`,
      'The key is removed from config/secrets.yaml. Sources using it fall back '
      + 'to unauthenticated limits.',
      { danger: true, confirmLabel: 'Clear key' },
    );
    if (!confirmed) return;
    try {
      await api.keyClear(service);
      toastOk(`${service} key cleared`);
      load();
    } catch (err) {
      toastErr(errText(err));
    }
  }

  load();
  return wrap;
}

/* ------------------------------------------------------------------ */
/* Tab 2 — Runtime settings                                             */
/* ------------------------------------------------------------------ */

/**
 * Build the runtime settings tab panel.
 *
 * @returns {HTMLElement}
 */
function runtimePanel() {
  const body = el('div', { class: 'stack' }, [skeleton(6)]);
  const wrap = el('div', {}, [body]);

  /** Fetch the settings map and render one row per key. */
  async function load() {
    body.replaceChildren(skeleton(6));
    try {
      const res = await api.settings();
      if (!wrap.isConnected) return;
      const map = extractSettingsMap(res);
      if (!map) {
        body.replaceChildren(failBlock(
          'Malformed settings payload',
          { message: 'The /api/settings response did not contain a settings object.' },
          load,
        ));
        return;
      }
      body.replaceChildren(...renderSettings(map));
    } catch (err) {
      if (!wrap.isConnected) return;
      body.replaceChildren(failBlock('Could not load runtime settings', err, load));
    }
  }

  /**
   * Pull the flat dotted-path settings dict out of any response shape.
   *
   * @param {*} res
   * @returns {?object}
   */
  function extractSettingsMap(res) {
    if (!res || typeof res !== 'object' || Array.isArray(res)) return null;
    if (res.settings && typeof res.settings === 'object' && !Array.isArray(res.settings)) {
      return res.settings;
    }
    // Flat `{path: value}` response — accept it when values are primitives.
    const entries = Object.entries(res);
    return entries.length && entries.every(([, v]) => v === null
      || ['boolean', 'number', 'string', 'object'].includes(typeof v)) ? res : null;
  }

  /**
   * Render the settings rows.
   *
   * @param {object} map
   * @returns {Node[]}
   */
  function renderSettings(map) {
    const entries = Object.entries(map)
      .filter(([path, value]) => value !== null && value !== undefined
        && ['boolean', 'number', 'string'].includes(typeof value))
      .sort((a, b) => a[0].localeCompare(b[0]));

    const nodes = [
      el('div', { class: 'callout info' }, [
        icon('info'),
        el('div', { class: 'sm' }, [
          'Switches apply immediately; value rows save on ',
          el('strong', {}, ['Set']),
          '. Changes take effect on the running server and persist to '
          + 'config.yaml where supported.',
        ]),
      ]),
    ];

    if (!entries.length) {
      nodes.push(emptyState({
        title: 'No editable settings exposed',
        hint: 'The backend did not report any runtime settings.',
        icon: 'settings',
      }));
      return nodes;
    }

    nodes.push(el('div', { class: 'settings-rows' }, entries.map(([path, value]) =>
      settingRow(path, value))));

    // Non-primitive values (arrays / objects) are shown read-only.
    const readonly = Object.entries(map)
      .filter(([, value]) => value !== null && value !== undefined
        && !['boolean', 'number', 'string'].includes(typeof value));
    if (readonly.length) {
      nodes.push(el('details', { class: 'raw-json' }, [
        el('summary', {}, [icon('chevronDown', { size: 14 }),
          `Read-only values · ${readonly.length}`]),
        el('div', { class: 'raw-json-body stack' }, readonly.map(([path, value]) =>
          el('div', { class: 'flex gap-2 wrap' }, [
            el('span', { class: 'mono sm strong' }, [path]),
            el('code', { class: 'xs', title: JSON.stringify(value) },
              [JSON.stringify(value)]),
          ]))),
      ]));
    }
    return nodes;
  }

  /**
   * One label + control + (Set) row for a single setting.
   *
   * @param {string} path
   * @param {boolean|number|string} value
   * @returns {HTMLElement}
   */
  function settingRow(path, value) {
    const pathLabel = el('span', {
      class: 'settings-path mono', title: path,
    }, [path]);

    if (typeof value === 'boolean') {
      const control = el('button', {
        class: 'switch', type: 'button', role: 'switch',
        'aria-checked': String(value),
        'aria-label': `${path} toggle`,
        title: 'Applies immediately',
      });
      control.addEventListener('click', async () => {
        const next = control.getAttribute('aria-checked') !== 'true';
        control.setAttribute('aria-checked', String(next));
        try {
          await api.settingsUpdate({ path, value: next });
          toastOk(`${path} → ${next}`);
          load();
        } catch (err) {
          control.setAttribute('aria-checked', String(!next));
          toastErr(errText(err));
        }
      });
      return el('div', { class: 'switch-row' }, [
        pathLabel,
        el('span', { class: 'control' }, [control,
          el('span', { class: 'xs muted' }, [value ? 'enabled' : 'disabled']),
        ]),
        el('span', { class: 'xs faint nowrap' }, ['live']),
      ]);
    }

    // Numbers and strings share the input + Set button pattern.
    const isNumber = typeof value === 'number';
    const input = el('input', {
      class: 'input input-mono', type: isNumber ? 'number' : 'text',
      step: isNumber ? 'any' : undefined,
      value: isNumber ? String(value) : value,
      'aria-label': `Value for ${path}`,
      spellcheck: 'false',
    });
    const setBtn = el('button', { class: 'btn btn-sm', type: 'button', disabled: true }, [
      icon('check', { size: 12 }), 'Set',
    ]);
    const markDirty = () => {
      const current = isNumber ? input.value.trim() : input.value;
      setBtn.disabled = current === String(value);
    };
    input.addEventListener('input', markDirty);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !setBtn.disabled) setBtn.click();
    });

    setBtn.addEventListener('click', async () => {
      let next;
      if (isNumber) {
        next = Number(input.value);
        if (!Number.isFinite(next)) {
          toastWarn(`"${input.value}" is not a number`);
          return;
        }
      } else {
        next = input.value;
        if (!next.trim()) {
          toastWarn('Value cannot be empty');
          return;
        }
      }
      busy(setBtn, true, 'Saving…');
      try {
        await api.settingsUpdate({ path, value: next });
        toastOk(`${path} → ${isNumber ? next : ui.fmtShort(next, 24)}`);
        load();
      } catch (err) {
        toastErr(errText(err));
        busy(setBtn, false);
      }
    });

    return el('div', { class: 'switch-row' }, [
      pathLabel,
      el('span', { class: 'control' }, [input, setBtn]),
      el('span', { class: 'xs faint nowrap' }, [isNumber ? 'number' : 'text']),
    ]);
  }

  load();
  return wrap;
}

/* ------------------------------------------------------------------ */
/* Tab 3 — Alerts                                                       */
/* ------------------------------------------------------------------ */

/**
 * Build the webhook alerts tab panel.
 *
 * @returns {HTMLElement}
 */
function alertsPanel() {
  const body = el('div', { class: 'stack' }, [skeleton(5)]);
  const wrap = el('div', {}, [body]);

  /** Checkbox inputs keyed by event name (rebuilt on every load). */
  const eventBoxes = new Map();

  /** Fetch the alerts configuration and render the form + recent log. */
  async function load() {
    body.replaceChildren(skeleton(5));
    try {
      const res = await api.alerts();
      if (!wrap.isConnected) return;
      const data = res && typeof res === 'object' && !Array.isArray(res) ? res : {};
      body.replaceChildren(...renderAlerts(data));
    } catch (err) {
      if (!wrap.isConnected) return;
      body.replaceChildren(failBlock('Could not load alert configuration', err, load));
    }
  }

  /**
   * Render the webhook form, test button and recent-notification log.
   *
   * @param {object} data
   * @returns {Node[]}
   */
  function renderAlerts(data) {
    eventBoxes.clear();
    const configuredUrl = typeof data.webhook_url === 'string' ? data.webhook_url : '';
    const events = Array.isArray(data.events)
      ? data.events.map((e) => String(e)).filter(Boolean) : [];

    const urlInput = el('input', {
      class: 'input input-mono', type: 'url',
      placeholder: 'https://hooks.example.com/…',
      'aria-label': 'Webhook URL',
      value: configuredUrl,
      spellcheck: 'false',
    });

    const eventList = events.length ? events : DEFAULT_EVENTS;
    const isFallback = !events.length;
    const boxes = eventList.map((event) => {
      const box = el('input', {
        class: 'check-input', type: 'checkbox',
        checked: !isFallback, 'aria-label': `Event ${event}`,
      });
      eventBoxes.set(event, box);
      return el('label', { class: 'check' }, [
        box,
        el('span', { class: 'mono sm' }, [event]),
        KNOWN_EVENT_HINTS[event]
          ? el('span', { class: 'xs faint' }, [KNOWN_EVENT_HINTS[event]]) : null,
      ]);
    });

    const saveBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
      icon('check'), 'Save configuration',
    ]);
    saveBtn.addEventListener('click', async () => {
      const url = urlInput.value.trim();
      const selected = [...eventBoxes.entries()]
        .filter(([, box]) => box.checked).map(([event]) => event);
      if (!url) {
        toastWarn('Enter a webhook URL first');
        urlInput.focus();
        return;
      }
      if (!selected.length) {
        toastWarn('Select at least one event');
        return;
      }
      busy(saveBtn, true, 'Saving…');
      try {
        await api.alertsConfigure({ webhook_url: url, events: selected });
        toastOk('Alert configuration saved');
        load();
      } catch (err) {
        toastErr(errText(err));
        busy(saveBtn, false);
      }
    });

    const testBtn = el('button', { class: 'btn', type: 'button' }, [
      icon('zap', { size: 14 }), 'Send test',
    ]);
    testBtn.addEventListener('click', async () => {
      busy(testBtn, true, 'Sending…');
      try {
        const res = await api.alertsTest();
        const failed = res && typeof res === 'object'
          && (res.ok === false || res.error);
        if (failed) {
          toastErr(String(res.error ?? res.message ?? 'Test delivery failed'));
        } else {
          toastOk(typeof res?.message === 'string' && res.message
            ? res.message : 'Test notification delivered');
        }
        load();
      } catch (err) {
        toastErr(errText(err));
      } finally {
        busy(testBtn, false);
      }
    });

    const formCard = el('section', { class: 'card', 'aria-label': 'Webhook notifications' }, [
      el('div', { class: 'card-head' }, [
        icon('zap'),
        el('span', { class: 'card-title' }, ['Webhook notifications']),
        el('span', { class: 'grow' }),
        configuredUrl ? badge('configured', 'ok') : badge('not set', 'muted'),
      ]),
      el('div', { class: 'card-body stack' }, [
        el('div', { class: 'field' }, [
          el('label', { class: 'field-label' }, ['Webhook URL']),
          urlInput,
          el('span', { class: 'field-hint' },
            ['Receives a JSON POST for every enabled event.']),
        ]),
        el('div', { class: 'field' }, [
          el('span', { class: 'field-label' }, [
            `Events${isFallback ? ' · defaults (none configured yet)' : ''}`,
          ]),
          el('div', { class: 'alerts-events' }, boxes),
        ]),
        el('div', { class: 'alerts-actions' }, [saveBtn, testBtn]),
      ]),
    ]);

    return [formCard, recentCard(data.recent)];
  }

  /**
   * The recent-notification log card (rendered defensively).
   *
   * @param {*} recent
   * @returns {Node}
   */
  function recentCard(recent) {
    const list = Array.isArray(recent) ? recent.filter((r) => r && typeof r === 'object') : [];
    const head = el('div', { class: 'card-head' }, [
      icon('clock'),
      el('span', { class: 'card-title' }, ['Recent notifications']),
      el('span', { class: 'grow' }),
      el('span', { class: 'badge badge-muted' }, [`${list.length}`]),
    ]);
    if (!list.length) {
      return el('section', { class: 'card', 'aria-label': 'Recent notifications' }, [
        head,
        emptyState({
          title: 'No notifications sent yet',
          hint: 'Alerts fire when watched targets change, sources trip or lookups fail. '
            + 'Run a lookup to start generating events.',
          icon: 'clock',
          action: el('button', {
            class: 'btn btn-sm', type: 'button',
            onclick: () => navigate('lookup'),
          }, [icon('search', { size: 13 }), 'Open the workbench']),
        }),
      ]);
    }

    const rows = list.slice(0, 25).map((item, idx) => {
      const when = item.when ?? item.timestamp ?? item.created_at ?? item.at;
      const event = item.event ?? item.type ?? item.name ?? 'event';
      const ok = item.ok === true || item.status === 'ok' || item.delivered === true;
      const detail = typeof item.error === 'string' && item.error
        ? item.error : (typeof item.detail === 'string' ? item.detail : null);
      return { idx, when, event, ok, detail };
    });

    return el('section', { class: 'card', 'aria-label': 'Recent notifications' }, [
      head,
      el('div', { class: 'card-body' }, [dataTable({
        columns: [
          {
            key: 'when', label: 'When',
            value: (row) => (row.when ? Date.parse(String(row.when)) || 0 : 0),
            render: (row) => (row.when
              ? el('span', { class: 'nowrap' }, [
                fmtWhen(row.when),
                el('span', { class: 'faint xs' }, [`  ·  ${fmtAgo(row.when)}`]),
              ])
              : el('span', { class: 'faint' }, ['—'])),
          },
          {
            key: 'event', label: 'Event',
            value: (row) => row.event,
            render: (row) => el('span', { class: 'mono sm' }, [String(row.event)]),
          },
          {
            key: 'status', label: 'Status', sortable: false,
            render: (row) => el('span', { class: 'flex gap-2 wrap' }, [
              row.ok ? badge('delivered', 'ok') : badge('failed', 'danger'),
              row.detail ? el('span', {
                class: 'xs err truncate', title: row.detail,
              }, [ui.fmtShort(row.detail, 64)]) : null,
            ]),
          },
        ],
        rows,
        empty: 'No notifications yet',
      })]),
    ]);
  }

  load();
  return wrap;
}

/** Friendly hints for the canonical webhook events. */
const KNOWN_EVENT_HINTS = {
  lookup_failed: 'a lookup errored or returned no data',
  watch_diff: 'a watched target changed between snapshots',
  risk_high: 'a lookup scored as high risk',
  source_tripped: 'a source tripped its failure circuit breaker',
};

/* ------------------------------------------------------------------ */
/* View                                                                 */
/* ------------------------------------------------------------------ */

export const view = {
  id: 'settings',
  title: 'Settings',
  subtitle: 'Settings & integrations',
  icon: 'settings',
  section: 'platform',
  order: 30,

  /**
   * Mount the settings tabs.
   *
   * @param {HTMLElement} root Empty <main> container.
   * @param {URLSearchParams} [params] Hash route params (tab=keys|runtime|alerts).
   */
  async render(root, params = new URLSearchParams()) {
    if (!root) return;
    const wanted = params.get('tab');
    const active = TAB_KEYS.includes(wanted) ? wanted : 'keys';

    const tabbed = tabs([
      { key: 'keys', label: 'API keys', icon: 'key', render: () => keysPanel() },
      { key: 'runtime', label: 'Runtime', icon: 'wrench', render: () => runtimePanel() },
      { key: 'alerts', label: 'Alerts', icon: 'zap', render: () => alertsPanel() },
    ], { active });

    root.append(el('div', { class: 'view-settings' }, [tabbed.root]));
  },
};

export default view;
