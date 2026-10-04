/**
 * ObscuraLens web UI — Monitor view (v6.0 part 3).
 *
 * Real-time event monitor over the backend's server-sent-events feed
 * (`GET /api/stream`, wrapped by `sse.js`). Shows the connection state
 * (open / reconnecting / polling fallback), a live reverse-chronological
 * event feed of lookups, watch checks and heartbeats (capped at 100 rows,
 * new rows fade in at the top), per-topic counters and topic visibility
 * filters. A "mute" toggle freezes the visible feed without dropping the
 * connection.
 *
 * The `sse` singleton is shared with the rest of the SPA, so this view
 * never closes it — it only unsubscribes its own callbacks once its DOM
 * is detached (checked per event and on hashchange, so the view is safely
 * re-entrant: navigating away and back re-registers fresh handlers).
 */

import { ui } from '../ui.js';
import { sse } from '../sse.js';

const { el, icon, badge, kindBadge, fmtInt, toastInfo } = ui;

/** Topics this view listens to on the shared stream. */
const FEED_TOPICS = ['lookup', 'watch', 'heartbeat'];

/** Maximum feed rows kept in the DOM. */
const MAX_FEED_ROWS = 100;

/* ---------------------------------------------------------------------- */
/* Helpers                                                                 */
/* ---------------------------------------------------------------------- */

/** Human-readable error text. */
function errText(err) {
  return err instanceof Error ? err.message : String(err ?? 'unknown error');
}

/** Local wall-clock time "HH:MM:SS" for feed rows. */
function nowTime() {
  return new Date().toLocaleTimeString('en-GB');
}

/**
 * "HH:MM:SS" from a timestamp-ish value (heartbeat payloads carry `ts`).
 *
 * @param {*} value
 * @returns {string}
 */
function tsTime(value) {
  if (value === null || value === undefined || value === '') return nowTime();
  const t = typeof value === 'number' ? (value < 1e12 ? value * 1000 : value)
    : Date.parse(String(value));
  return Number.isFinite(t)
    ? new Date(t).toLocaleTimeString('en-GB') : nowTime();
}

/**
 * Extract a compact {kind, value, extra} view of a lookup event payload.
 * The backend's save hook publishes `{kind, value, success, field_count}`;
 * unknown shapes degrade to the raw value string.
 *
 * @param {*} data
 * @returns {{kind: string, value: string, success: boolean|null,
 *            fields: number|null}}
 */
function lookupInfo(data) {
  if (!data || typeof data !== 'object') {
    return { kind: '', value: String(data ?? ''), success: null, fields: null };
  }
  return {
    kind: String(data.kind ?? '').toLowerCase(),
    value: String(data.value ?? data.target ?? ''),
    success: typeof data.success === 'boolean' ? data.success : null,
    fields: Number.isFinite(Number(data.field_count))
      ? Number(data.field_count) : null,
  };
}

/**
 * Extract a compact view of a watch event payload ({changed, target, kind}).
 *
 * @param {*} data
 * @returns {{changed: boolean|null, target: string, kind: string}}
 */
function watchInfo(data) {
  if (!data || typeof data !== 'object') {
    return { changed: null, target: String(data ?? ''), kind: '' };
  }
  return {
    changed: typeof data.changed === 'boolean' ? data.changed : null,
    target: String(data.target ?? data.value ?? ''),
    kind: String(data.kind ?? '').toLowerCase(),
  };
}

/**
 * Build one feed row for a topic/payload pair.
 *
 * @param {string} topic
 * @param {*} data
 * @returns {HTMLElement}
 */
function feedRow(topic, data) {
  const time = el('span', { class: 'monitor-when mono xs' }, [tsTime(data?.ts)]);
  const body = el('span', { class: 'monitor-event-body' });

  if (topic === 'lookup') {
    const info = lookupInfo(data);
    body.replaceChildren(
      info.kind ? kindBadge(info.kind) : badge('lookup', 'accent'),
      el('span', { class: 'monitor-target mono sm' }, [info.value || '—']),
      info.success === true ? badge('ok', 'ok')
        : info.success === false ? badge('failed', 'danger') : null,
      info.fields !== null
        ? el('span', { class: 'faint xs' }, [`${info.fields} fields`]) : null,
    );
  } else if (topic === 'watch') {
    const info = watchInfo(data);
    body.replaceChildren(
      badge('watch', 'info'),
      info.changed === true ? badge('changed', 'warn')
        : info.changed === false ? badge('unchanged', 'muted') : null,
      info.kind ? kindBadge(info.kind) : null,
      el('span', { class: 'monitor-target mono sm' }, [info.target || '—']),
    );
  } else {
    body.replaceChildren(
      badge('heartbeat', 'muted'),
      el('span', { class: 'faint xs' },
        [typeof data === 'object' && data ? 'stream alive' : 'heartbeat']),
    );
  }

  return el('li', {
    class: `monitor-event monitor-event--${topic}`,
    'data-topic': topic,
  }, [time, body]);
}

/** Checkbox row for one topic filter. */
function filterToggle(topic, label, checked, onChange) {
  const box = el('input', {
    type: 'checkbox', checked, 'aria-label': `Show ${label} events`,
    onchange: () => onChange(topic, box.checked),
  });
  return el('label', { class: 'monitor-filter' }, [
    box, el('span', { class: 'sm' }, [label]),
  ]);
}

/** One counter card. */
function counterCard(label, iconName) {
  const value = el('div', { class: 'monitor-counter-value' }, ['0']);
  const root = el('div', { class: 'card monitor-counter' }, [
    el('div', { class: 'card-body' }, [
      el('div', { class: 'flex between' }, [
        el('span', { class: 'stat-label' }, [label]),
        icon(iconName, { size: 14 }),
      ]),
      value,
    ]),
  ]);
  return { root, value };
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'monitor',
  title: 'Monitor',
  subtitle: 'Live event stream',
  icon: 'zap',
  section: 'workspace',
  order: 20,

  /**
   * Mount the monitor.
   *
   * @param {HTMLElement} root #view container.
   * @param {URLSearchParams} params Route params (unused).
   */
  async render(root, params) {
    void params;

    /* ---- connection state card ------------------------------------- */

    const stateDot = el('span', { class: 'monitor-dot', 'aria-hidden': 'true' });
    const stateLabel = el('span', { class: 'strong sm' }, ['idle']);
    const stateDetail = el('div', { class: 'muted xs' }, ['not connected yet']);
    const lastBeat = el('div', { class: 'muted xs' }, ['last heartbeat: —']);

    const reconnectBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
      icon('refresh', { size: 13 }), 'Reconnect',
    ]);

    const connectionCard = el('div', { class: 'card monitor-conn' }, [
      el('div', { class: 'card-head' }, [
        icon('radio', { size: 16 }),
        el('span', { class: 'card-title' }, ['Connection']),
        el('span', { class: 'grow' }),
        reconnectBtn,
      ]),
      el('div', { class: 'card-body' }, [
        el('div', { class: 'monitor-conn-state' }, [stateDot, stateLabel]),
        stateDetail,
        lastBeat,
      ]),
    ]);

    /* ---- counters --------------------------------------------------- */

    const lookupCounter = counterCard('lookups', 'search');
    const watchCounter = counterCard('watch checks', 'eye');
    const beatCounter = counterCard('heartbeats', 'clock');
    const totalCounter = counterCard('feed events', 'zap');

    /* ---- feed + controls --------------------------------------------- */

    const feed = el('ul', { class: 'monitor-feed', role: 'log',
      'aria-live': 'polite', 'aria-label': 'Live event feed' });

    const visible = new Map(FEED_TOPICS.map((t) => [t, true]));
    const applyFilters = () => {
      for (const topic of FEED_TOPICS) {
        feed.classList.toggle(`hide-${topic}`, !visible.get(topic));
      }
    };
    const filters = FEED_TOPICS.map((topic, i) => filterToggle(
      topic,
      ['lookups', 'watches', 'heartbeats'][i],
      true,
      (t, checked) => {
        visible.set(t, checked);
        applyFilters();
      },
    ));

    let muted = false;
    const muteBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
      icon('stop', { size: 13 }), 'Mute feed',
    ]);
    muteBtn.addEventListener('click', () => {
      muted = !muted;
      muteBtn.replaceChildren(
        icon(muted ? 'play' : 'stop', { size: 13 }),
        muted ? 'Unmute feed' : 'Mute feed',
      );
      feed.classList.toggle('is-muted', muted);
      if (muted) toastInfo('Feed muted — events keep counting in the background');
    });

    const feedCard = el('div', { class: 'card monitor-feed-card' }, [
      el('div', { class: 'card-head' }, [
        icon('zap', { size: 16 }),
        el('span', { class: 'card-title' }, ['Live event feed']),
        el('span', { class: 'grow' }),
        el('span', { class: 'monitor-filter-row' }, filters),
        muteBtn,
      ]),
      el('div', { class: 'card-body monitor-feed-body' }, [feed]),
    ]);

    /* ---- degraded-mode banner ---------------------------------------- */

    const banner = typeof globalThis.EventSource !== 'function'
      ? el('div', { class: 'callout info', role: 'note' }, [
        icon('info', { size: 16 }),
        el('div', { class: 'grow sm' }, [
          'This browser has no EventSource support — the client fell back to ',
          'a polling loop against /api/health. Lookup and watch events need a ',
          'stream-capable browser; liveness still updates.',
        ]),
      ])
      : null;

    /* ---- layout ------------------------------------------------------- */

    root.replaceChildren(el('div', { class: 'view-monitor' }, [
      el('div', { class: 'page-head' }, [
        el('div', { class: 'titles' }, [
          el('h1', { class: 'page-title' }, ['Monitor']),
          el('p', { class: 'page-desc' }, [
            'Server-sent events from the live stream — lookups, watch checks ',
            'and heartbeats as they happen, straight from the database save ',
            'hook. Nothing is stored: this is a window, not a log.',
          ]),
        ]),
      ]),
      banner,
      el('div', { class: 'monitor-grid' }, [
        connectionCard,
        lookupCounter.root,
        watchCounter.root,
        beatCounter.root,
        totalCounter.root,
      ]),
      feedCard,
    ]));

    /* ---- state + subscription management ------------------------------ */

    const counters = {
      lookup: lookupCounter.value,
      watch: watchCounter.value,
      heartbeat: beatCounter.value,
      total: totalCounter.value,
    };
    const totals = { lookup: 0, watch: 0, heartbeat: 0, total: 0 };
    let feedRows = 0;

    /** Append one row at the top (unless muted) and enforce the cap. */
    function pushRow(topic, data) {
      if (muted) return;
      feed.prepend(feedRow(topic, data));
      feedRows += 1;
      while (feedRows > MAX_FEED_ROWS && feed.lastElementChild) {
        feed.lastElementChild.remove();
        feedRows -= 1;
      }
    }

    function setConnection() {
      const state = sse.state;
      stateDot.dataset.state = state;
      stateLabel.textContent = state;
      const online = sse.online;
      stateDetail.textContent = online
        ? `events arriving over ${state === 'polling'
          ? 'the polling fallback' : 'the event stream'}`
        : state === 'reconnecting'
          ? 'connection lost — retrying with backoff'
          : state === 'closed'
            ? 'gave up after too many retries — press Reconnect'
            : 'waiting for the first event…';
    }

    /** Tear this render's subscriptions down (safe to call repeatedly). */
    function detach() {
      while (offs.length) {
        const off = offs.pop();
        try { off(); } catch { /* already gone */ }
      }
      window.removeEventListener('hashchange', onHash);
    }

    /** @type {Array<function(): void>} unsubscribe handles */
    const offs = [];
    const on = (topic, cb) => offs.push(sse.on(topic, cb));

    const onHash = () => {
      // navigating away re-renders #view — our children detach; drop our
      // handlers then so a stale render never keeps receiving events
      if (!feed.isConnected) detach();
    };
    window.addEventListener('hashchange', onHash);

    on('connected', (data) => {
      if (!feed.isConnected) { detach(); return; }
      setConnection();
      const subs = Number(data?.subscribers);
      if (Number.isFinite(subs)) {
        stateDetail.textContent =
          `${stateDetail.textContent} · ${fmtInt(subs)} subscriber(s)`;
      }
    });

    on('disconnect', (data) => {
      if (!feed.isConnected) { detach(); return; }
      setConnection();
      if (!muted) {
        const row = el('li', {
          class: 'monitor-event monitor-event--heartbeat',
          'data-topic': 'heartbeat',
        }, [
          el('span', { class: 'monitor-when mono xs' }, [nowTime()]),
          el('span', { class: 'faint xs' }, [
            `connection dropped${data?.given_up ? ' — retry budget spent' : ''}`,
          ]),
        ]);
        feed.prepend(row);
      }
    });

    on('heartbeat', (data) => {
      if (!feed.isConnected) { detach(); return; }
      totals.heartbeat += 1;
      totals.total += 1;
      counters.heartbeat.textContent = fmtInt(totals.heartbeat);
      counters.total.textContent = fmtInt(totals.total);
      lastBeat.textContent = `last heartbeat: ${tsTime(data?.ts ?? Date.now())}`;
      setConnection();
      pushRow('heartbeat', data);
    });

    on('lookup', (data) => {
      if (!feed.isConnected) { detach(); return; }
      totals.lookup += 1;
      totals.total += 1;
      counters.lookup.textContent = fmtInt(totals.lookup);
      counters.total.textContent = fmtInt(totals.total);
      pushRow('lookup', data);
    });

    on('watch', (data) => {
      if (!feed.isConnected) { detach(); return; }
      totals.watch += 1;
      totals.total += 1;
      counters.watch.textContent = fmtInt(totals.watch);
      counters.total.textContent = fmtInt(totals.total);
      pushRow('watch', data);
    });

    reconnectBtn.addEventListener('click', () => {
      try {
        sse.connect();
        setConnection();
        toastInfo('Stream connection requested');
      } catch (err) {
        ui.toastErr(`Could not connect: ${errText(err)}`);
      }
    });

    /* ---- go ----------------------------------------------------------- */

    applyFilters();
    setConnection();
    sse.connect(); // idempotent — other views share this singleton
    setConnection();
  },
};

export default view;
