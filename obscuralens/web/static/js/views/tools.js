/**
 * ObscuraLens web UI — Tools view (the analyst toolbox).
 *
 * Eight tabs of local-first analysis utilities:
 *   Encode/Decode · JWT · Hash ID · Coordinates · Extract · Typosquats ·
 *   File analysis (EXIF / steganography with drag & drop) · Batch lookup.
 *
 * Every call is defensive: fetches are wrapped, failures render inline
 * callouts with retry actions, and unknown payload keys degrade to a raw
 * JSON block instead of breaking the view. No dynamic value is ever placed
 * via innerHTML — all DOM is built with the `ui.el` builder.
 */

import { api, KINDS, KIND_META } from '../api.js';
import { ui } from '../ui.js';

const {
  el, icon, badge, kindBadge, truthyBadge,
  toastOk, toastErr, toastWarn, toastInfo,
  modal, dataTable, kvGrid, emptyState, skeleton, jsonBlock,
  fmtInt, fmtBytes, fmtWhen, fmtAgo, copyable, debounce,
} = ui;

/** Maximum accepted upload size for the file analysis tabs. */
const MAX_UPLOAD_BYTES = 16 * 1024 * 1024;

/** Schemes offered in the decode selector before any encode result arrives. */
const COMMON_SCHEMES = [
  'hex', 'base32', 'base64', 'base85', 'url', 'html',
  'rot13', 'binary', 'decimal', 'reversed', 'morse', 'zlib_base64',
];

/** Human labels for the entity-extraction categories. */
const CATEGORY_LABELS = {
  emails: 'Emails', urls: 'URLs', domains: 'Domains', ipv4: 'IPv4', ipv6: 'IPv6',
  asn: 'AS numbers', macs: 'MAC addresses', ibans: 'IBANs', imeis: 'IMEIs',
  hashes: 'Hashes', cves: 'CVEs', crypto_addresses: 'Crypto addresses',
  coords: 'Coordinates', phone_candidates: 'Phone candidates',
  user_handles: 'User handles', tracking_ids: 'Tracking IDs',
};

/** Category → tracker kind for clickable entity chips. */
const CATEGORY_LOOKUP = {
  emails: 'email', ips: 'ip', ipv4: 'ip', ipv6: 'ip', domains: 'domain',
  urls: 'url', hashes: 'hash', cves: 'cve', crypto_addresses: 'crypto',
  macs: 'mac', ibans: 'iban', imeis: 'imei', coords: 'coords',
  phone_candidates: 'phone', asn: 'asn',
};

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
/* Shared helpers                                                          */
/* ---------------------------------------------------------------------- */

/** Human-readable error text for callouts and toasts. */
function errText(err) {
  return err instanceof Error ? err.message : String(err ?? 'unknown error');
}

/** Inline danger callout with an optional retry button. */
function errorCallout(message, onRetry, what = 'Tool call failed') {
  return el('div', { class: 'callout danger', role: 'alert' }, [
    icon('alert'),
    el('div', { class: 'grow' }, [
      el('strong', {}, [what]),
      el('div', { class: 'muted sm break-all' }, [message]),
    ]),
    onRetry ? el('button', { class: 'btn btn-sm', onclick: onRetry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]) : null,
  ]);
}

/** Compact danger note for inline form feedback. */
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

/** Standalone copy button (icon only). */
function copyBtn(value, title = 'Copy') {
  return el('button', {
    class: 'copy-btn', type: 'button', title, 'aria-label': title,
    onclick: async (e) => {
      e.stopPropagation();
      try {
        await navigator.clipboard.writeText(String(value));
        toastOk('Copied to clipboard');
      } catch {
        toastErr('Clipboard unavailable');
      }
    },
  }, [icon('copy', { size: 13 })]);
}

/** Card with a mono header row and a full-width preformatted value. */
function valueCard(name, value, opts = {}) {
  return el('div', { class: `tools-result-card${opts.big ? ' tools-result-big' : ''}` }, [
    el('div', { class: 'tools-result-head' }, [
      el('span', { class: 'mono xs strong' }, [name]),
      el('span', { class: 'spacer' }),
      copyBtn(value),
    ]),
    el('pre', { class: `tools-result-value mono ${opts.big ? 'lg' : 'sm'}` }, [String(value)]),
  ]);
}

/** External map link styled as a small button. */
function mapLink(label, href) {
  return el('a', {
    class: 'btn btn-sm', href, target: '_blank', rel: 'noopener noreferrer',
  }, [icon('external', { size: 12 }), label]);
}

/** Row of OSM / Google / Apple map links built client-side from lat/lon. */
function mapsRow(lat, lon) {
  const q = `${lat},${lon}`;
  return el('div', { class: 'tools-maps-row' }, [
    mapLink('OpenStreetMap',
      `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=15/${lat}/${lon}`),
    mapLink('Google Maps', `https://maps.google.com/?q=${q}`),
    mapLink('Apple Maps', `https://maps.apple.com/?q=${q}`),
  ]);
}

const num = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};
const str = (v) => (v === null || v === undefined ? '' : String(v));
const asDict = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : null);
const asArray = (v) => (Array.isArray(v) ? v : null);

/** Parse a timestamp-ish value into epoch ms (null when unparseable). */
function toTimeMs(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value;
  const s = String(value);
  const t = /^\d+$/.test(s) ? Number(s) : Date.parse(s);
  if (!Number.isFinite(t)) return null;
  return t < 1e12 && /^\d+$/.test(s) ? t * 1000 : t;
}

/** Card section helper (head icon + title + optional badge). */
function sectionCard(title, iconName, body, extra) {
  return el('div', { class: 'card' }, [
    el('div', { class: 'card-head' }, [
      icon(iconName, { size: 16 }),
      el('span', { class: 'card-title' }, [title]),
      extra ?? null,
    ]),
    el('div', { class: 'card-body stack' }, [].concat(body)),
  ]);
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'tools',
  title: 'Tools',
  subtitle: 'Analyst toolbox — encoders, decoders & file analysis',
  icon: 'wrench',
  section: 'platform',
  order: 20,

  /**
   * Mount the toolbox (tabs render lazily and are cached by ui.tabs).
   * @param {HTMLElement} root
   */
  async render(root) {
    loadNavigate();
    const tabsUi = ui.tabs([
      { key: 'encode', label: 'Encode / Decode', icon: 'lock', render: tabEncode },
      { key: 'jwt', label: 'JWT', icon: 'key', render: tabJwt },
      { key: 'hashid', label: 'Hash ID', icon: 'finger', render: tabHashId },
      { key: 'coords', label: 'Coordinates', icon: 'map', render: tabCoords },
      { key: 'extract', label: 'Extract', icon: 'search', render: tabExtract },
      { key: 'squat', label: 'Typosquats', icon: 'globe', render: tabSquat },
      { key: 'file', label: 'File analysis', icon: 'file', render: tabFile },
      { key: 'batch', label: 'Batch', icon: 'layers', render: tabBatch },
    ]);
    root.replaceChildren(tabsUi.root);
  },
};

/* ====================================================================== */
/* Tab 1 — Encode / Decode                                                 */
/* ====================================================================== */

function tabEncode() {
  const input = el('textarea', {
    class: 'textarea tools-input', rows: 3, spellcheck: 'false',
    placeholder: 'Paste text to encode — every scheme updates as you type…',
    'aria-label': 'Text to encode',
  });
  const status = el('div', { class: 'muted xs' });
  const grid = el('div', { class: 'tools-result-grid' });
  const hashesEl = el('div', { class: 'stack', hidden: true });

  const schemeSelect = el('select', {
    class: 'select', 'aria-label': 'Decode scheme',
  }, COMMON_SCHEMES.map((s) => el('option', { value: s }, [s])));
  const decodeInput = el('textarea', {
    class: 'textarea', rows: 3, spellcheck: 'false',
    placeholder: 'Paste an encoded value to decode with the selected scheme…',
    'aria-label': 'Value to decode',
  });
  const decodeBtn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('unlock', { size: 14 }), 'Decode',
  ]);
  const decodeOut = el('div', { class: 'stack' });

  /** Debounced "encode everything" call. */
  const runEncode = debounce(async () => {
    const text = input.value;
    if (!text.trim()) {
      grid.replaceChildren();
      hashesEl.hidden = true;
      status.textContent = '';
      return;
    }
    grid.replaceChildren(el('div', { class: 'card' }, [
      el('div', { class: 'card-body' }, [ui.loading('Encoding…')]),
    ]));
    try {
      const res = await api.encodings(text);
      if (!grid.isConnected) return;
      renderEncodeResults(res);
    } catch (err) {
      if (!grid.isConnected) return;
      grid.replaceChildren(errorCallout(errText(err), () => runEncode(), 'Encoding failed'));
      status.textContent = '';
    }
  }, 400);

  input.addEventListener('input', runEncode);

  /** Paint scheme cards (+ digest cards when the response carries them). */
  function renderEncodeResults(res) {
    const dict = asDict(res) ?? {};
    const cards = [];
    let hashes = null;
    for (const [scheme, value] of Object.entries(dict)) {
      if ((scheme === 'hashes' || scheme === 'digests') && asDict(value)) {
        hashes = asDict(value);
        continue;
      }
      if (typeof value !== 'string' && typeof value !== 'number') continue;
      cards.push(valueCard(scheme, String(value)));
    }
    grid.replaceChildren(...(cards.length ? cards : [emptyState({
      title: 'No encodings returned',
      hint: 'The backend returned no usable scheme values for this input.',
      icon: 'lock',
    })]));
    status.textContent = `${cards.length} scheme${cards.length === 1 ? '' : 's'} computed`;

    /* Refresh the decode scheme list with whatever the backend knows. */
    const known = [...new Set([...COMMON_SCHEMES, ...Object.keys(dict)
      .filter((k) => k !== 'hashes' && k !== 'digests')])];
    const current = schemeSelect.value;
    schemeSelect.replaceChildren(...known.map((s) => el('option', { value: s }, [s])));
    schemeSelect.value = known.includes(current) ? current : known[0];

    if (hashes && Object.keys(hashes).length) {
      hashesEl.hidden = false;
      hashesEl.replaceChildren(sectionCard('Digests', 'finger',
        el('div', { class: 'tools-result-grid' }, Object.entries(hashes)
          .filter(([, v]) => typeof v === 'string' || typeof v === 'number')
          .map(([algo, digest]) => valueCard(algo, String(digest)))),
        badge(`${Object.keys(hashes).length}`, 'accent')));
    } else {
      hashesEl.hidden = true;
      hashesEl.replaceChildren();
    }
  }

  decodeBtn.addEventListener('click', async () => {
    const value = decodeInput.value.trim();
    if (!value) { toastWarn('Paste a value to decode first'); return; }
    decodeBtn.disabled = true;
    decodeOut.replaceChildren(ui.loading('Decoding…'));
    try {
      const res = await api.decode({ scheme: schemeSelect.value, value });
      if (!decodeOut.isConnected) return;
      const text = typeof res === 'string' ? res
        : str(asDict(res)?.result ?? asDict(res)?.decoded ?? asDict(res)?.value ?? asDict(res)?.text);
      const note = str(asDict(res)?.note);
      decodeOut.replaceChildren(
        valueCard(`decoded · ${schemeSelect.value}`, text || '(empty result)', { big: true }),
        note ? el('div', { class: 'callout info' }, [
          icon('info', { size: 14 }), el('div', { class: 'grow sm' }, [note]),
        ]) : null,
      );
    } catch (err) {
      if (!decodeOut.isConnected) return;
      decodeOut.replaceChildren(errorCallout(errText(err), undefined, 'Decode failed'));
    } finally {
      decodeBtn.disabled = false;
    }
  });

  return el('div', { class: 'stack-lg' }, [
    sectionCard('Encode every scheme at once', 'lock', [
      input, status, grid, hashesEl,
    ]),
    sectionCard('Decode a single value', 'unlock', [
      fieldEl('Scheme', schemeSelect, 'The list grows as the backend reports the schemes it knows.'),
      fieldEl('Value', decodeInput),
      el('div', { class: 'flex end' }, [decodeBtn]),
      decodeOut,
    ]),
  ]);
}

/* ====================================================================== */
/* Tab 2 — JWT inspector                                                   */
/* ====================================================================== */

function tabJwt() {
  const input = el('textarea', {
    class: 'textarea mono', rows: 4, spellcheck: 'false',
    placeholder: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    'aria-label': 'JWT token',
  });
  const btn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('zap', { size: 14 }), 'Inspect token',
  ]);
  const out = el('div', { class: 'stack-lg' });

  async function run() {
    const token = input.value.trim();
    if (!token) { toastWarn('Paste a JWT first'); return; }
    btn.disabled = true;
    out.replaceChildren(skeleton(5));
    try {
      const res = await api.jwt(token);
      if (!out.isConnected) return;
      renderJwt(asDict(res) ?? { error: str(res) });
    } catch (err) {
      if (!out.isConnected) return;
      out.replaceChildren(errorCallout(errText(err), run, 'JWT inspection failed'));
    } finally {
      btn.disabled = false;
    }
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); run(); }
  });

  function renderJwt(res) {
    const parts = [];
    if (res.error) {
      parts.push(el('div', { class: 'callout danger' }, [
        icon('alert'),
        el('div', { class: 'grow' }, [
          el('strong', {}, ['Token could not be parsed']),
          el('div', { class: 'muted sm' }, [str(res.error)]),
        ]),
      ]));
    }

    const header = asDict(res.header) ?? {};
    if (Object.keys(header).length) {
      parts.push(sectionCard('Header', 'key', kvGrid(Object.entries(header)
        .map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : str(v)]))));
    }

    const payload = asDict(res.payload) ?? {};
    const claimsInfo = asDict(res.claims) ?? {};
    if (Object.keys(payload).length) {
      parts.push(sectionCard('Payload claims', 'layers', [
        kvGrid(Object.entries(payload).map(([k, v]) => [k, claimValue(k, v, claimsInfo)])),
        identifiersRow(payload, asDict(res.identifiers)),
      ]));
    }

    const signatureLength = num(res.signature_length);
    if (signatureLength !== null || str(res.signature_hex)) {
      parts.push(sectionCard('Signature', 'shield', kvGrid([
        ['length (bytes)', signatureLength ?? '—'],
        ['preview (hex)', str(res.signature_hex) || '—'],
      ])));
    }

    const notes = asArray(res.notes) ?? [];
    if (notes.length) {
      parts.push(sectionCard('Notes & warnings', 'alert',
        notes.map((note) => {
          const text = str(note);
          const lower = text.toLowerCase();
          const cls = lower.includes('critical') ? 'danger'
            : (lower.includes('warning') || lower.includes('warn')) ? 'warn' : 'info';
          return el('div', { class: `callout ${cls}` }, [
            icon(cls === 'info' ? 'info' : 'alert', { size: 14 }),
            el('div', { class: 'grow sm' }, [text]),
          ]);
        }), badge(`${notes.length}`, 'warn')));
    }

    if (Object.keys(header).length || Object.keys(payload).length) {
      parts.push(jsonBlock({ header, payload }, 'Raw JWT JSON'));
    }
    if (!parts.length) parts.push(jsonBlock(res, 'Raw response'));
    out.replaceChildren(...parts);
  }

  /** One claim cell: raw value + human time + expiry verdict. */
  function claimValue(key, value, claimsInfo) {
    if (!['exp', 'iat', 'nbf'].includes(key)) {
      return typeof value === 'object' ? JSON.stringify(value) : str(value);
    }
    const info = asDict(claimsInfo[key]) ?? {};
    const ms = toTimeMs(info.datetime ?? value);
    const expired = key === 'exp'
      ? (typeof info.expired === 'boolean' ? info.expired
        : (ms !== null ? ms <= Date.now() : null))
      : null;
    return el('span', { class: 'tools-claim' }, [
      el('span', { class: 'mono sm' }, [typeof value === 'object' ? JSON.stringify(value) : str(value)]),
      ms !== null ? el('span', { class: 'muted xs' }, [`  ·  ${fmtWhen(ms)}`]) : null,
      expired === true ? badge('expired', 'danger') : null,
      expired === false ? badge('valid', 'ok') : null,
    ]);
  }

  /** iss / sub / aud / jti summary chips. */
  function identifiersRow(payload, identifiers) {
    const source = { ...payload, ...(identifiers ?? {}) };
    const chips = [];
    for (const key of ['iss', 'sub', 'aud', 'jti']) {
      const value = source[key];
      if (value === null || value === undefined || value === '') continue;
      chips.push(el('span', { class: 'chip chip-src', title: key }, [
        el('span', { class: 'faint xs' }, [key]),
        el('span', { class: 'mono xs' }, [typeof value === 'object' ? JSON.stringify(value) : str(value)]),
      ]));
    }
    return chips.length ? el('div', { class: 'tools-chip-row' }, chips) : null;
  }

  return el('div', { class: 'stack-lg' }, [
    sectionCard('JSON Web Token inspector', 'key', [
      fieldEl('Token', input, 'Decoded locally-ish — signatures are not verified. Press ⌘/Ctrl+Enter to inspect.'),
      el('div', { class: 'flex end' }, [btn]),
    ]),
    out,
  ]);
}

/* ====================================================================== */
/* Tab 3 — Hash identifier                                                 */
/* ====================================================================== */

function tabHashId() {
  const input = el('input', {
    class: 'input input-mono', spellcheck: 'false', autocomplete: 'off',
    placeholder: 'e.g. 5d41402abc4b2a76b9719d911017c592',
    'aria-label': 'Hash value to identify',
  });
  const btn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('finger', { size: 14 }), 'Identify',
  ]);
  const out = el('div', { class: 'stack' });

  async function run() {
    const value = input.value.trim();
    if (!value) { toastWarn('Paste a hash first'); return; }
    btn.disabled = true;
    out.replaceChildren(skeleton(3));
    try {
      const res = await api.hashId(value);
      if (!out.isConnected) return;
      const candidates = asArray(res) ?? asArray(asDict(res)?.candidates)
        ?? asArray(asDict(res)?.results) ?? [];
      render(candidates.filter((c) => c && typeof c === 'object'));
    } catch (err) {
      if (!out.isConnected) return;
      out.replaceChildren(errorCallout(errText(err), run, 'Hash identification failed'));
    } finally {
      btn.disabled = false;
    }
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); run(); }
  });

  function render(candidates) {
    if (!candidates.length) {
      out.replaceChildren(emptyState({
        title: 'No candidate formats',
        hint: 'The backend could not match this value against any known digest shape.',
        icon: 'finger',
      }));
      return;
    }
    out.replaceChildren(el('div', { class: 'grid grid-2' }, candidates.map((c) => {
      const confidence = str(c.confidence).toLowerCase();
      const badgeNode = confidence === 'high' ? badge('high', 'ok', { dot: true })
        : confidence === 'medium' ? badge('medium', 'warn')
          : badge(confidence || 'low', 'muted');
      const length = num(c.length);
      return el('div', { class: 'card card-hover tools-candidate' }, [
        el('div', { class: 'card-body stack' }, [
          el('div', { class: 'flex gap-2 wrap' }, [
            el('span', { class: 'mono strong sm break-all' }, [str(c.name ?? 'unknown')]),
            el('span', { class: 'spacer' }),
            badgeNode,
          ]),
          str(c.note) ? el('p', { class: 'muted xs' }, [str(c.note)]) : null,
          el('div', { class: 'flex gap-2 wrap' }, [
            str(c.charset) ? el('span', { class: 'chip' }, [str(c.charset)]) : null,
            length !== null && length > 0 ? el('span', { class: 'chip' }, [`${length} B decoded`]) : null,
          ]),
        ]),
      ]);
    })));
  }

  return el('div', { class: 'stack-lg' }, [
    sectionCard('Hash format identifier', 'finger', [
      fieldEl('Hash-like value', input, 'Length, charset and prefixes are matched against known digest families.'),
      el('div', { class: 'flex end' }, [btn]),
    ]),
    out,
  ]);
}

/* ====================================================================== */
/* Tab 4 — Coordinate converter                                            */
/* ====================================================================== */

function tabCoords() {
  const input = el('input', {
    class: 'input input-mono', spellcheck: 'false', autocomplete: 'off',
    placeholder: `48.8584, 2.2945 · N 48° 51' 29" · 31U 448288 5411087 · 31U DQ 48288 11087`,
    'aria-label': 'Coordinates to convert',
  });
  const btn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('map', { size: 14 }), 'Convert',
  ]);
  const out = el('div', { class: 'stack-lg' });

  async function run() {
    const value = input.value.trim();
    if (!value) { toastWarn('Enter coordinates first'); return; }
    btn.disabled = true;
    out.replaceChildren(skeleton(3));
    try {
      const res = await api.coordsConvert({ value });
      if (!out.isConnected) return;
      render(asDict(res) ?? {});
    } catch (err) {
      if (!out.isConnected) return;
      out.replaceChildren(errorCallout(errText(err), run, 'Coordinate conversion failed'));
    } finally {
      btn.disabled = false;
    }
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); run(); }
  });

  function render(res) {
    /* Merge common nesting wrappers into one flat view. */
    const flat = {
      ...(asDict(res.formats) ?? {}), ...(asDict(res.conversions) ?? {}),
      ...(asDict(res.coords) ?? {}), ...(asDict(res.geo) ?? {}), ...res,
    };
    const lat = num(flat.latitude ?? flat.lat);
    const lon = num(flat.longitude ?? flat.lon ?? flat.lng);
    const decimal = str(flat.decimal ?? flat.dd ?? (lat !== null && lon !== null ? `${lat}, ${lon}` : ''));
    const formats = [
      ['DMS', flat.dms ?? flat.dms_display ?? flat.latitude_dms],
      ['DDM', flat.ddm ?? flat.ddm_display],
      ['UTM', flat.utm],
      ['MGRS', flat.mgrs],
      ['Geohash', flat.geohash],
      ['Maidenhead', flat.maidenhead],
    ].filter(([, v]) => str(v));

    const parts = [];
    if (decimal) {
      parts.push(sectionCard('Decimal degrees', 'map', [
        el('div', { class: 'tools-coords-big mono' }, [
          el('span', { class: 'strong lg' }, [decimal]),
        ]),
        lat !== null && lon !== null ? el('div', { class: 'flex gap-2 wrap mt-2' }, [
          copyBtn(lat, 'Copy latitude'), el('span', { class: 'mono sm' }, [`lat ${lat}`]),
          copyBtn(lon, 'Copy longitude'), el('span', { class: 'mono sm' }, [`lon ${lon}`]),
        ]) : null,
        lat !== null && lon !== null ? mapsRow(lat, lon) : null,
      ], copyBtn(decimal, 'Copy decimal')));
    }

    if (formats.length) {
      parts.push(sectionCard('All formats', 'layers',
        el('div', { class: 'tools-result-grid' }, formats.map(([name, value]) =>
          valueCard(name, value)))));
    }

    const extras = [
      num(flat.elevation ?? flat.altitude) !== null ? `elevation ${num(flat.elevation ?? flat.altitude)} m` : '',
      str(flat.country ?? flat.country_name) ? `country: ${str(flat.country ?? flat.country_name)}` : '',
      str(flat.timezone ?? flat.timezone_name) ? `tz: ${str(flat.timezone ?? flat.timezone_name)}` : '',
    ].filter(Boolean);
    if (extras.length) {
      parts.push(el('div', { class: 'flex gap-2 wrap' }, extras.map((text) =>
        el('span', { class: 'chip chip-src' }, [text]))));
    }

    if (!parts.length) {
      parts.push(el('div', { class: 'callout warn' }, [
        icon('alert', { size: 14 }),
        el('div', { class: 'grow sm' }, ['The backend returned no recognisable coordinate fields for this input.']),
      ]), jsonBlock(res, 'Raw response'));
    }
    out.replaceChildren(...parts);
  }

  return el('div', { class: 'stack-lg' }, [
    sectionCard('Coordinate converter', 'map', [
      fieldEl('Coordinates', input, 'Decimal degrees, DMS, UTM and MGRS are all accepted.'),
      el('div', { class: 'flex end' }, [btn]),
    ]),
    out,
  ]);
}

/* ====================================================================== */
/* Tab 5 — Entity extraction                                               */
/* ====================================================================== */

function tabExtract() {
  const input = el('textarea', {
    class: 'textarea tools-input', rows: 7, spellcheck: 'false',
    placeholder: 'Paste an email body, paste dump, report excerpt or log — emails, IPs, domains, hashes, CVEs, crypto addresses, coordinates… are all pulled out.',
    'aria-label': 'Text to analyse',
  });
  const btn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('search', { size: 14 }), 'Extract entities',
  ]);
  const out = el('div', { class: 'stack-lg' });

  async function run() {
    const text = input.value;
    if (!text.trim()) { toastWarn('Paste some text first'); return; }
    btn.disabled = true;
    out.replaceChildren(skeleton(4));
    try {
      const res = await api.extract({ text });
      if (!out.isConnected) return;
      const found = asDict(res) ?? {};
      const entities = asDict(found.entities) ?? asDict(found.result) ?? found;
      render(entities);
    } catch (err) {
      if (!out.isConnected) return;
      out.replaceChildren(errorCallout(errText(err), run, 'Extraction failed'));
    } finally {
      btn.disabled = false;
    }
  }
  btn.addEventListener('click', run);

  function render(entities) {
    const order = Object.keys(CATEGORY_LABELS);
    const extraKeys = Object.keys(entities).filter((k) => !order.includes(k));
    const categories = [...order, ...extraKeys]
      .map((key) => ({ key, values: asArray(entities[key]) ?? [] }))
      .filter((c) => c.values.length && c.values.every((v) => v !== null && v !== undefined));
    const total = categories.reduce((acc, c) => acc + c.values.length, 0);

    if (!total) {
      out.replaceChildren(emptyState({
        title: 'No entities found',
        hint: 'Nothing OSINT-pivotable was detected in this text — or the text is too short.',
        icon: 'search',
      }));
      return;
    }

    out.replaceChildren(
      el('p', { class: 'muted sm' }, [
        el('strong', {}, [`${total} entit${total === 1 ? 'y' : 'ies'}`]),
        ` across ${categories.length} categor${categories.length === 1 ? 'y' : 'ies'}. `,
        'Click a chip to pivot into a lookup; the copy button copies just that value.',
      ]),
      ...categories.map((cat) => {
        const kind = CATEGORY_LOOKUP[cat.key] ?? null;
        return sectionCard(
          CATEGORY_LABELS[cat.key] ?? cat.key.replace(/_/g, ' '), 'search',
          el('div', { class: 'tools-chip-row' }, cat.values.map((value) =>
            entityChip(String(value), kind))),
          badge(`${cat.values.length}`, 'accent'),
        );
      }),
    );
  }

  /** One entity chip: copyable, and clickable when the kind maps to a tracker. */
  function entityChip(value, kind) {
    const chip = el('span', {
      class: `chip tools-chip${kind ? ' tools-chip-link' : ''}`,
      ...(kind ? {
        role: 'button', tabindex: 0, title: `Look up as ${KIND_META[kind]?.label ?? kind}`,
        onclick: () => nav('lookup', { kind, target: value }),
        onkeydown: (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            nav('lookup', { kind, target: value });
          }
        },
      } : {}),
    }, [el('span', { class: 'tools-chip-value mono' }, [value]), copyBtn(value, `Copy ${value}`)]);
    return chip;
  }

  return el('div', { class: 'stack-lg' }, [
    sectionCard('Entity extraction', 'search', [
      fieldEl('Text', input, 'Weak kinds (phones, handles, tracking IDs) are candidates — verify before acting.'),
      el('div', { class: 'flex end' }, [btn]),
    ]),
    out,
  ]);
}

/* ====================================================================== */
/* Tab 6 — Typosquat generator                                             */
/* ====================================================================== */

function tabSquat() {
  const input = el('input', {
    class: 'input input-mono', spellcheck: 'false', autocomplete: 'off',
    placeholder: 'defend-me.com', 'aria-label': 'Domain to defend',
  });
  const btn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('globe', { size: 14 }), 'Generate',
  ]);
  const out = el('div', { class: 'stack' });

  const state = { variants: [] };

  async function run() {
    const domain = input.value.trim();
    if (!domain) { toastWarn('Enter a domain first'); return; }
    btn.disabled = true;
    out.replaceChildren(skeleton(4));
    try {
      const res = await api.squat({ domain });
      if (!out.isConnected) return;
      state.variants = (asArray(res) ?? asArray(asDict(res)?.variants) ?? [])
        .filter((v) => v && typeof v === 'object' && str(v.domain));
      render();
    } catch (err) {
      if (!out.isConnected) return;
      out.replaceChildren(errorCallout(errText(err), run, 'Typosquat generation failed'));
    } finally {
      btn.disabled = false;
    }
  }
  btn.addEventListener('click', run);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); run(); }
  });

  function render() {
    if (!state.variants.length) {
      out.replaceChildren(emptyState({
        title: 'No variants generated',
        hint: 'The domain could not be parsed (or every generated variant collided with the original).',
        icon: 'globe',
      }));
      return;
    }

    const categories = [...new Set(state.variants.map((v) => str(v.category)))].filter(Boolean);
    const filter = el('select', { class: 'select', 'aria-label': 'Filter by category' }, [
      el('option', { value: '' }, ['All categories']),
      ...categories.map((c) => el('option', { value: c }, [c])),
    ]);
    filter.addEventListener('change', () => renderTable(filter.value));

    const copyAll = el('button', { class: 'btn btn-sm', type: 'button', title: 'Copy every domain' }, [
      icon('copy', { size: 13 }), 'Copy all',
    ]);
    copyAll.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(state.variants.map((v) => str(v.domain)).join('\n'));
        toastOk(`${state.variants.length} domains copied`);
      } catch {
        toastErr('Clipboard unavailable');
      }
    });

    out.replaceChildren(
      el('div', { class: 'filter-bar' }, [
        badge(`${state.variants.length} variants`, 'accent'),
        el('span', { class: 'spacer' }),
        filter,
        copyAll,
      ]),
      el('div', { class: 'tools-table' }),
    );
    renderTable('');
  }

  function renderTable(category) {
    const rows = state.variants
      .filter((v) => !category || str(v.category) === category)
      .sort((a, b) => (num(b.risk) ?? -1) - (num(a.risk) ?? -1));
    const holder = out.querySelector('.tools-table');
    if (!holder) return;
    holder.replaceChildren(dataTable({
      columns: [
        { key: 'domain', label: 'Domain', render: (row) => copyable(str(row.domain), { short: 36 }) },
        { key: 'category', label: 'Category', render: (row) => badge(str(row.category || '—'), 'muted') },
        { key: 'risk', label: 'Risk', value: (row) => num(row.risk) ?? -1, render: riskCell },
        { key: 'description', label: 'Description', render: (row) => el('span', { class: 'muted sm' }, [str(row.description)]) },
      ],
      rows,
      empty: 'No variants in this category',
    }));
  }

  function riskCell(row) {
    const risk = num(row.risk);
    if (risk === null) return el('span', { class: 'faint sm' }, ['—']);
    const cls = risk >= 70 ? 'danger' : risk >= 40 ? 'warn' : '';
    const color = risk >= 70 ? 'var(--danger)' : risk >= 40 ? 'var(--warn)' : 'var(--accent)';
    return el('div', { class: 'src-rate' }, [
      el('div', { class: 'progress', style: { minWidth: '90px' } }, [
        el('div', { class: `progress-bar ${cls}`, style: { width: `${Math.min(100, risk)}%` } }),
      ]),
      el('span', { class: 'mono xs strong', style: { color } }, [`${risk}`]),
    ]);
  }

  return el('div', { class: 'stack-lg' }, [
    sectionCard('Typosquat generator', 'globe', [
      fieldEl('Domain to defend', input, 'Fifteen variant families: omission, insertion, homoglyph, bitsquat, combo…'),
      el('div', { class: 'flex end' }, [btn]),
    ]),
    out,
  ]);
}

/* ====================================================================== */
/* Tab 7 — File analysis (EXIF / steganography)                            */
/* ====================================================================== */

function tabFile() {
  const exifResults = el('div', { class: 'stack' });
  const stegoResults = el('div', { class: 'stack' });

  const exifCol = el('div', { class: 'stack' }, [
    dropzone('EXIF & metadata', 'map',
      'JPEG · PNG · WebP · GIF · TIFF — camera, GPS, software and editing history.',
      (file, status) => runFile('exif', file, exifResults, status)),
    exifResults,
  ]);
  const stegoCol = el('div', { class: 'stack' }, [
    dropzone('Steganography analysis', 'shield',
      'PNG · BMP · GIF · JPEG — LSB planes, entropy profile, embedded payloads.',
      (file, status) => runFile('stego', file, stegoResults, status)),
    stegoResults,
  ]);

  /** Validate + upload + render for one of the two analyzers. */
  async function runFile(kind, file, results, status) {
    if (file.size > MAX_UPLOAD_BYTES) {
      toastErr(`“${file.name}” is ${fmtBytes(file.size)} — the client-side limit is 16 MB`);
      return;
    }
    status.replaceChildren(ui.loading(`Analyzing ${file.name} (${fmtBytes(file.size)})…`));
    results.replaceChildren(skeleton(4));
    try {
      const res = kind === 'exif' ? await api.exif(file) : await api.stego(file);
      if (!results.isConnected) return;
      status.replaceChildren(el('span', { class: 'muted xs' }, [
        `${file.name} · ${fmtBytes(file.size)}`,
        asDict(res)?.format ? el('span', { class: 'chip' }, [str(asDict(res).format)]) : null,
      ]));
      results.replaceChildren(kind === 'exif' ? renderExif(asDict(res) ?? {}) : renderStego(asDict(res) ?? {}));
    } catch (err) {
      if (!results.isConnected) return;
      status.replaceChildren();
      results.replaceChildren(errorCallout(errText(err), () => runFile(kind, file, results, status),
        'File analysis failed'));
    }
  }

  return el('div', { class: 'stack-lg' }, [
    el('div', { class: 'grid grid-2 tools-dropzones' }, [exifCol, stegoCol]),
    el('p', { class: 'faint xs' }, [
      'Uploads are analysed server-side but never leave the host. Maximum 16 MB per file.',
    ]),
  ]);
}

/**
 * Build one drag & drop zone (click / keyboard / drag events all wired).
 * @param {string} title
 * @param {string} iconName
 * @param {string} hint
 * @param {(file: File, status: HTMLElement) => void} onFile
 */
function dropzone(title, iconName, hint, onFile) {
  const input = el('input', {
    type: 'file', class: 'dropzone-input',
    accept: 'image/*,.bmp,.tif,.tiff,.webp',
    'aria-label': `${title} — choose a file`,
  });
  const status = el('div', { class: 'dropzone-status xs' });
  const zone = el('div', {
    class: 'dropzone card', role: 'button', tabindex: 0,
    'aria-label': `${title}: drop a file here or press Enter to browse`,
  }, [
    el('div', { class: 'dropzone-inner' }, [
      icon(iconName, { size: 26 }),
      el('div', { class: 'dropzone-title strong' }, [title]),
      el('div', { class: 'dropzone-hint muted xs' }, [hint]),
      el('div', { class: 'dropzone-hint faint xs' }, ['Drop a file here or click to browse · max 16 MB']),
      status,
    ]),
    input,
  ]);

  const activate = (e) => { e.preventDefault(); e.stopPropagation(); zone.classList.add('drag-over'); };
  const deactivate = (e) => { e.preventDefault(); e.stopPropagation(); zone.classList.remove('drag-over'); };
  zone.addEventListener('dragenter', activate);
  zone.addEventListener('dragover', activate);
  zone.addEventListener('dragleave', deactivate);
  zone.addEventListener('drop', (e) => {
    deactivate(e);
    const file = e.dataTransfer?.files?.[0];
    if (file) onFile(file, status);
  });
  zone.addEventListener('click', (e) => {
    if (e.target === input) return; // let the native input handle its own click
    input.click();
  });
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      input.click();
    }
  });
  input.addEventListener('change', () => {
    const file = input.files?.[0];
    if (file) onFile(file, status);
    input.value = '';
  });

  return { root: zone, status };
}

/** Render the EXIF analyzer result. */
function renderExif(res) {
  const parts = [];
  if (res.error && !res.format) {
    parts.push(el('div', { class: 'callout danger' }, [
      icon('alert'),
      el('div', { class: 'grow' }, [
        el('strong', {}, ['EXIF analysis failed']),
        el('div', { class: 'muted sm' }, [str(res.error)]),
      ]),
    ]));
  }

  const file = asDict(res.file) ?? {};
  const gps = asDict(res.gps) ?? {};
  const exif = asDict(res.exif) ?? {};

  parts.push(sectionCard('File facts', 'file', [
    el('div', { class: 'flex gap-2 wrap' }, [
      res.format ? badge(str(res.format), 'accent') : null,
      file.size ? el('span', { class: 'chip' }, [fmtBytes(file.size)]) : null,
      file.width && file.height ? el('span', { class: 'chip' }, [`${file.width} × ${file.height} px`]) : null,
    ]),
    file.sha256 ? el('div', { class: 'flex gap-2 mt-2 wrap' }, [
      el('span', { class: 'faint xs' }, ['sha256']), copyable(str(file.sha256), { short: 24 }),
    ]) : null,
    file.md5 ? el('div', { class: 'flex gap-2 mt-1 wrap' }, [
      el('span', { class: 'faint xs' }, ['md5']), copyable(str(file.md5), { short: 24 }),
    ]) : null,
    asDict(res.xmp) ? el('div', { class: 'mt-2' }, [badge('XMP packet present', 'info')]) : null,
  ]));

  /* GPS mini-card with live map links. */
  const lat = num(gps.latitude);
  const lon = num(gps.longitude);
  const coordsText = str(gps.coords) || (lat !== null && lon !== null ? `${lat}, ${lon}` : '');
  if (coordsText) {
    parts.push(sectionCard('GPS', 'map', [
      el('div', { class: 'tools-coords-big mono' }, [
        el('span', { class: 'strong lg' }, [coordsText]),
        el('span', { class: 'spacer' }),
        copyBtn(coordsText, 'Copy coordinates'),
      ]),
      str(gps.latitude_dms) || str(gps.longitude_dms) ? el('div', { class: 'muted xs mt-2' }, [
        `${str(gps.latitude_dms)}  ${str(gps.longitude_dms)}`,
      ]) : null,
      num(gps.altitude_m) !== null
        ? el('div', { class: 'muted xs mt-1' }, [`altitude ${num(gps.altitude_m)} m`]) : null,
      lat !== null && lon !== null ? el('div', { class: 'mt-3' }, [mapsRow(lat, lon)]) : null,
    ]));
  }

  const metaEntries = Object.entries(exif).filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (metaEntries.length) {
    parts.push(sectionCard('Metadata', 'layers',
      kvGrid(metaEntries.slice(0, 80).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : str(v)])),
      badge(`${metaEntries.length}`, 'accent')));
  }

  const timeline = (asArray(res.timeline) ?? []).map((t) => str(t)).filter(Boolean);
  if (timeline.length) {
    parts.push(sectionCard('Timeline hints', 'clock',
      timeline.map((stamp) => {
        const ms = toTimeMs(stamp);
        return el('div', { class: 'flex gap-2 wrap' }, [
          icon('clock', { size: 12 }),
          el('span', { class: 'mono sm' }, [stamp]),
          ms !== null ? el('span', { class: 'faint xs' }, [`· ${fmtWhen(ms)} (${fmtAgo(ms)})`]) : null,
        ]);
      })));
  }

  const notes = (asArray(res.osint_notes) ?? []).map((n) => str(n)).filter(Boolean);
  if (notes.length) {
    parts.push(sectionCard('OSINT notes', 'info',
      notes.map((note) => el('div', { class: 'callout info' }, [
        icon('info', { size: 14 }),
        el('div', { class: 'grow sm' }, [note]),
      ]))));
  }

  const strings = (asArray(res.strings) ?? [])
    .map((s) => (asDict(s) ? str(s.value) : str(s))).filter(Boolean).slice(0, 40);
  if (strings.length) {
    parts.push(el('details', { class: 'card tools-strings' }, [
      el('summary', {}, [`Interesting strings (${strings.length})`]),
      el('pre', { class: 'mono xs' }, [strings.join('\n')]),
    ]));
  }

  if (!parts.length) parts.push(jsonBlock(res, 'Raw EXIF response'));
  return el('div', { class: 'stack' }, parts);
}

/** Render the steganography analyzer result. */
function renderStego(res) {
  const parts = [];
  const summary = asDict(res.summary) ?? {};
  const verdict = str(summary.verdict).toLowerCase();
  const suspicion = num(summary.suspicion) ?? 0;
  const verdictBadge = verdict.includes('highly')
    ? badge('highly suspicious', 'danger', { icon: 'alert' })
    : verdict === 'suspicious' ? badge('suspicious', 'warn', { icon: 'alert' })
      : verdict ? badge(verdict, 'ok', { dot: true }) : badge('unknown', 'muted');
  const barCls = suspicion >= 70 ? 'danger' : suspicion >= 40 ? 'warn' : '';

  parts.push(sectionCard('Verdict', 'shield', [
    el('div', { class: 'flex gap-3 wrap' }, [
      verdictBadge,
      res.format ? el('span', { class: 'chip' }, [str(res.format)]) : null,
    ]),
    el('div', { class: 'src-rate mt-3' }, [
      el('div', { class: 'progress', style: { minWidth: '160px' } }, [
        el('div', { class: `progress-bar ${barCls}`, style: { width: `${Math.min(100, suspicion)}%` } }),
      ]),
      el('span', { class: 'mono xs strong' }, [`${suspicion}% suspicion`]),
    ]),
    el('ul', { class: 'tools-findings mt-3' }, (asArray(summary.findings) ?? [])
      .map((f) => str(f)).filter(Boolean).map((text) =>
        el('li', {}, [text]))),
  ]));

  const entropy = asDict(res.entropy) ?? {};
  const windows = (asArray(entropy.windows) ?? [])
    .map((w) => asDict(w)).filter(Boolean);
  if (windows.length) {
    const overall = num(entropy.overall ?? entropy.mean ?? entropy.mean_entropy);
    parts.push(sectionCard('Entropy profile', 'zap', [
      el('div', { class: 'tools-entropy-chart', role: 'img', 'aria-label': 'Entropy per window' },
        windows.map((w) => el('div', {
          class: 'tools-entropy-bar',
          title: `byte ${num(w.offset) ?? '?'} · ${num(w.entropy_bits) ?? '?'} bits/byte`,
          style: { height: `${Math.max(4, Math.min(100, ((num(w.entropy_bits) ?? 0) / 8) * 100))}%` },
        }))),
      overall !== null ? el('div', { class: 'muted xs mt-2' }, [`overall entropy ${overall} bits/byte`]) : null,
      (asArray(entropy.high_entropy_regions) ?? []).length ? el('div', { class: 'mt-2' }, [
        badge(`${asArray(entropy.high_entropy_regions).length} high-entropy region(s)`, 'warn'),
      ]) : null,
    ]));
  }

  const embedded = asDict(res.embedded_files) ?? {};
  const findings = (asArray(embedded.findings) ?? []).filter((f) => asDict(f));
  const trailing = asDict(embedded.trailing_data);
  if (findings.length || trailing) {
    parts.push(sectionCard('Embedded files', 'file', [
      ...findings.map((hit) => el('div', { class: 'tools-embedded' }, [
        badge(str(hit.type ?? 'blob'), 'warn'),
        el('span', { class: 'mono xs' }, [`offset ${num(hit.offset) ?? '?'}`]),
        str(hit.details) ? el('span', { class: 'muted xs' }, [str(hit.details)]) : null,
      ])),
      trailing ? el('div', { class: 'callout warn' }, [
        icon('alert', { size: 14 }),
        el('div', { class: 'grow sm' }, [str(trailing.note ?? 'trailing data after the container end')]),
      ]) : null,
    ]));
  }

  const lsb = asDict(res.lsb) ?? {};
  const lsbEntries = Object.entries(lsb)
    .filter(([, v]) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
    .slice(0, 14);
  if (lsbEntries.length) {
    parts.push(sectionCard('LSB / container details', 'cpu',
      kvGrid(lsbEntries.map(([k, v]) => [k, str(v)]))));
  }

  const strings = (asArray(res.strings) ?? []).map((s) => str(s)).filter(Boolean).slice(0, 40);
  if (strings.length) {
    parts.push(el('details', { class: 'card tools-strings' }, [
      el('summary', {}, [`Raw strings ≥ 8 chars (${strings.length})`]),
      el('pre', { class: 'mono xs' }, [strings.join('\n')]),
    ]));
  }

  if (!parts.length) parts.push(jsonBlock(res, 'Raw stego response'));
  return el('div', { class: 'stack' }, parts);
}

/* ====================================================================== */
/* Tab 8 — Batch lookup                                                    */
/* ====================================================================== */

function tabBatch() {
  const kindSelect = el('select', { class: 'select', 'aria-label': 'Batch target kind' },
    KINDS.map((k) => el('option', { value: k }, [KIND_META[k]?.label ?? k])));
  const input = el('textarea', {
    class: 'textarea tools-input', rows: 8, spellcheck: 'false',
    placeholder: 'one target per line…\n8.8.8.8\n1.1.1.1\n9.9.9.9',
    'aria-label': 'Batch targets',
  });
  const btn = el('button', { class: 'btn btn-primary', type: 'button' }, [
    icon('play', { size: 14 }), 'Run batch',
  ]);
  const out = el('div', { class: 'stack' });

  async function run() {
    const lines = input.value.split('\n').map((s) => s.trim()).filter(Boolean);
    if (!lines.length) { toastWarn('Enter at least one target'); return; }
    let targets = lines;
    if (targets.length > 25) {
      toastWarn(`Batch capped at 25 targets — running the first 25 of ${targets.length} lines`);
      targets = targets.slice(0, 25);
    }
    btn.disabled = true;
    out.replaceChildren(ui.loading(
      `Running batch of ${targets.length} ${kindSelect.value} targets — this can take a while…`));
    try {
      const res = await api.batch({ kind: kindSelect.value, targets, risk: false });
      if (!out.isConnected) return;
      render(res, targets);
    } catch (err) {
      if (!out.isConnected) return;
      out.replaceChildren(errorCallout(errText(err), run, 'Batch run failed'));
    } finally {
      btn.disabled = false;
    }
  }
  btn.addEventListener('click', run);

  function render(res, targets) {
    const raw = asArray(res) ?? asArray(asDict(res)?.results) ?? asArray(asDict(res)?.batch) ?? [];
    const rows = raw.map((row) => {
      const holder = asDict(row) ?? {};
      const result = asDict(holder.result) ?? holder;
      const info = asDict(result.info) ?? asDict(result.fields) ?? {};
      const fields = Object.entries(info)
        .filter(([, v]) => v !== null && v !== undefined && v !== '');
      const errors = asArray(result.errors) ?? (result.error ? [result.error] : []);
      return {
        target: str(holder.target ?? holder.value ?? result.target ?? ''),
        success: Boolean(result.success),
        fieldCount: num(result.field_count) ?? fields.length,
        fields: fields.slice(0, 4).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`),
        error: str(errors[0] ?? (result.success ? '' : 'lookup failed')),
      };
    });

    if (!rows.length && targets.length) {
      out.replaceChildren(jsonBlock(res, 'Raw batch response'));
      return;
    }

    out.replaceChildren(
      el('p', { class: 'muted sm' }, [
        `${rows.filter((r) => r.success).length} / ${rows.length} targets succeeded `,
        `· kind ${kindSelect.value}`,
      ]),
      dataTable({
        columns: [
          { key: 'target', label: 'Target', render: (row) => el('span', { class: 'mono sm break-all' }, [row.target || '—']) },
          { key: 'success', label: 'Success', value: (row) => (row.success ? 1 : 0), render: (row) => truthyBadge(row.success, 'ok', 'failed') },
          { key: 'fieldCount', label: 'Fields', value: (row) => row.fieldCount, render: (row) => el('span', { class: 'mono sm' }, [fmtInt(row.fieldCount)]) },
          { key: 'fields', label: 'Top fields', sortable: false, render: fieldsCell },
          { key: 'error', label: 'Error', sortable: false, render: errorCell },
        ],
        rows,
        rowClass: (row) => (row.success ? 'row-ok' : 'row-err'),
        empty: 'No results',
      }),
    );
  }

  function fieldsCell(row) {
    if (!row.fields.length) return el('span', { class: 'faint sm' }, ['—']);
    return el('span', { class: 'tools-chip-row' }, row.fields.map((pair) =>
      el('span', { class: 'chip tools-chip mono xs', title: pair }, [pair])));
  }

  function errorCell(row) {
    return row.error
      ? el('span', { class: 'tools-err sm', title: row.error }, [row.error])
      : el('span', { class: 'faint sm' }, ['—']);
  }

  return el('div', { class: 'stack-lg' }, [
    sectionCard('Batch lookup', 'layers', [
      fieldEl('Kind', kindSelect),
      fieldEl('Targets (one per line)', input, 'Maximum 25 targets per run — longer lists are trimmed client-side.'),
      el('div', { class: 'flex end' }, [btn]),
    ]),
    out,
  ]);
}

export default view;
