/**
 * ObscuraLens web UI — zero-dependency offline world map (v6.0 part 3).
 *
 * An SVG world map rendered entirely from a small set of *highly simplified*
 * continent outlines hard-coded below. There is no tile server, no CDN, no
 * network fetch of any kind: the whole planet is ~450 [lon, lat] vertices,
 * so the map view works in air-gapped installs exactly like the rest of the
 * app.
 *
 * ⚠ The outlines are teaching-grade silhouettes, NOT survey data. Coastlines
 * are smoothed to 20-60 vertices per landmass, fjords/bays are stylised,
 * small islands are merged or dropped, and the Caspian and Baltic seas are
 * partially filled. Good enough to see where your lookups cluster; never
 * good enough to navigate a ship.
 *
 * What the module provides:
 *
 *   - `equirectangular(lat, lon, width, height)` / `mercator(...)` — the two
 *     projection functions (Web Mercator clamps latitude to ±85°),
 *   - `OlMap` — an SVG map bound to a container element with markers,
 *     radius circles, great-circle lines, auto-fit bounds, click callbacks,
 *     a hover tooltip, an SVG `export()` (for report embedding) and a
 *     ResizeObserver-driven redraw,
 *   - `worldMap` — the module facade singleton `{ OlMap }`.
 *
 * Colours are read from the CSS custom-property palette on every render
 * (land uses low-contrast `--panel-2`/`--panel-3`, markers use `--kind-*`
 * tokens with palette fallbacks) so theme switches recolour live maps. The
 * module never touches the DOM at import time — every bit of DOM work
 * happens inside methods, so it imports cleanly headlessly.
 */

/* ---------------------------------------------------------------------- */
/* Theme / colour utilities                                                */
/* ---------------------------------------------------------------------- */

/** Fallbacks mirroring base.css dark-theme tokens (used when CSS is absent). */
const FALLBACK_DARK = {
  land: '#1a2331',
  landStroke: '#2b3648',
  grid: 'rgba(139, 149, 167, 0.14)',
  graticule: 'rgba(139, 149, 167, 0.22)',
  equator: 'rgba(45, 212, 167, 0.55)',
  tropic: 'rgba(139, 149, 167, 0.30)',
  text: '#8b95a7',
  bg: '#0a0e14',
  accent: '#2dd4a7',
  palette: ['#2dd4a7', '#f5a524', '#b58cff', '#4cc3ff',
    '#f2637a', '#8fd15f', '#e8965a', '#5fb0c9'],
};

/** Light-theme fallbacks (mirroring base.css `[data-theme=light]`). */
const FALLBACK_LIGHT = {
  land: '#eef2f7',
  landStroke: '#c6cfdb',
  grid: 'rgba(95, 107, 125, 0.16)',
  graticule: 'rgba(95, 107, 125, 0.28)',
  equator: 'rgba(13, 158, 124, 0.55)',
  tropic: 'rgba(95, 107, 125, 0.35)',
  text: '#5f6b7d',
  bg: '#f4f6f9',
  accent: '#0d9e7c',
  palette: ['#0d9e7c', '#c47d0e', '#8458e0', '#1279c4',
    '#d23c55', '#5a9e31', '#c96a2d', '#2d7f96'],
};

/**
 * Read one CSS custom property from :root, trimmed.
 *
 * @param {string} name Custom property name including leading `--`.
 * @param {string} fallback Value used when the property is empty.
 * @returns {string}
 */
function cssVar(name, fallback) {
  try {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
    return value || fallback;
  } catch {
    return fallback;
  }
}

/**
 * Snapshot of the map-relevant design tokens. Re-read on every render so
 * `[data-theme=light]` switches recolour existing maps.
 *
 * @param {string} mode 'dark' | 'light' — fallback palette when CSS is absent.
 * @returns {{land: string, landStroke: string, grid: string,
 *   graticule: string, equator: string, tropic: string,
 *   text: string, bg: string, accent: string, palette: string[]}}
 */
function theme(mode) {
  const base = mode === 'light' ? FALLBACK_LIGHT : FALLBACK_DARK;
  const palette = [];
  for (let i = 1; i <= 8; i += 1) {
    palette.push(cssVar(`--chart-${i}`, base.palette[i - 1]));
  }
  return {
    land: cssVar('--panel-2', base.land),
    landStroke: cssVar('--line-strong', base.landStroke),
    grid: cssVar('--chart-grid', base.grid),
    graticule: cssVar('--line-strong', base.graticule),
    equator: withAlpha(cssVar('--accent', base.accent), 0.55),
    tropic: base.tropic,
    text: cssVar('--text-muted', base.text),
    bg: cssVar('--bg', base.bg),
    accent: cssVar('--accent', base.accent),
    palette,
  };
}

/**
 * Lazy 1×1 canvas used to normalise arbitrary CSS colour strings.
 *
 * @type {HTMLCanvasElement|null}
 */
let normalizeCanvas = null;

/**
 * Normalise any CSS colour to `#rrggbb` or `rgba(...)` via canvas fillStyle.
 *
 * @param {string} color
 * @returns {string}
 */
function normalizeColor(color) {
  if (!normalizeCanvas) {
    normalizeCanvas = document.createElement('canvas');
    normalizeCanvas.width = 1;
    normalizeCanvas.height = 1;
  }
  const ctx = normalizeCanvas.getContext('2d');
  ctx.fillStyle = '#000000';
  ctx.fillStyle = String(color);
  return ctx.fillStyle;
}

/**
 * Parse a CSS colour into [r, g, b, a]; returns null when unparseable.
 *
 * @param {string} color
 * @returns {[number, number, number, number]|null}
 */
function parseColor(color) {
  if (color === null || color === undefined) return null;
  const s = String(color).trim();
  if (!s) return null;
  let m = s.match(/^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i);
  if (m) {
    const hex = m[1];
    const byte = (i) => parseInt(hex.slice(i, i + 2), 16);
    if (hex.length === 3) {
      return [parseInt(hex[0] + hex[0], 16), parseInt(hex[1] + hex[1], 16),
        parseInt(hex[2] + hex[2], 16), 1];
    }
    if (hex.length === 6) return [byte(0), byte(2), byte(4), 1];
    return [byte(0), byte(2), byte(4), byte(6) / 255];
  }
  m = s.match(/^rgba?\(([^)]+)\)$/i);
  if (m) {
    const parts = m[1].split(/[,/\s]+/).filter(Boolean).map(Number);
    if (parts.length >= 3 && parts.slice(0, 3).every(Number.isFinite)) {
      const a = parts.length >= 4 && Number.isFinite(parts[3])
        ? Math.max(0, Math.min(1, parts[3])) : 1;
      return [parts[0], parts[1], parts[2], a];
    }
  }
  try {
    const norm = normalizeColor(s);
    if (norm !== s) return parseColor(norm);
  } catch { /* canvas unavailable — give up gracefully */ }
  return null;
}

/**
 * Apply an alpha to any CSS colour.
 *
 * @param {string} color
 * @param {number} alpha
 * @returns {string}
 */
function withAlpha(color, alpha) {
  const p = parseColor(color);
  if (!p) return color;
  return `rgba(${Math.round(p[0])}, ${Math.round(p[1])}, ${Math.round(p[2])}, ${alpha})`;
}

/**
 * Colour for one target kind: the `--kind-*` token when the theme defines
 * one, else a deterministic palette slot (v6.0 kinds have no token yet).
 *
 * @param {string|null|undefined} kind Target kind ('ip', 'bssid', ...).
 * @param {string[]} palette Fallback palette (theme().palette).
 * @returns {string}
 */
function kindColor(kind, palette) {
  const known = ['ip', 'domain', 'email', 'username', 'phone', 'url',
    'crypto', 'hash', 'cve', 'asn', 'mac', 'iban', 'imei', 'coords',
    'vin', 'flight', 'mmsi', 'app', 'bssid', 'plate'];
  if (kind && known.includes(kind)) {
    const token = cssVar(`--kind-${kind}`, '');
    if (token) return token;
  }
  const index = kind ? known.indexOf(kind) : -1;
  return palette[(index >= 0 ? index : known.length) % palette.length];
}

/* ---------------------------------------------------------------------- */
/* Simplified land outlines                                                */
/* ---------------------------------------------------------------------- */

/**
 * Teaching-grade continent outlines.
 *
 * Each entry is one closed ring of `[lon, lat]` vertices (clockwise or
 * counter-clockwise — SVG fills either). Shared land borders (Urals,
 * Caucasus, Scandinavia) may overlap a few pixels; both sides carry the
 * same low-contrast fill so the seam is invisible.
 *
 * @type {Array<{name: string, ring: Array<[number, number]>}>}
 */
const LAND = [
  { name: 'North America', ring: [
    [-168, 65], [-162, 66], [-156, 71], [-146, 70], [-138, 69], [-130, 69],
    [-122, 70], [-114, 68], [-106, 68], [-98, 67], [-92, 66], [-86, 66],
    [-82, 62], [-79, 55], [-64, 60], [-60, 55], [-56, 51], [-66, 45],
    [-70, 43], [-74, 40], [-76, 36], [-81, 31], [-80, 26], [-81, 25],
    [-83, 29], [-88, 30], [-94, 29], [-97, 26], [-97, 21], [-91, 18],
    [-87, 21.5], [-88, 16], [-85, 12], [-83, 9], [-79, 8], [-81, 8],
    [-85, 10], [-88, 13], [-92, 15], [-96, 16], [-105, 20], [-107, 24],
    [-110, 24], [-113, 29], [-117, 32], [-121, 35], [-124, 40], [-124, 46],
    [-125, 49], [-131, 53], [-137, 58], [-146, 60], [-152, 58], [-158, 56],
    [-164, 60],
  ] },
  { name: 'South America', ring: [
    [-77, 8], [-72, 12], [-68, 11], [-64, 10], [-60, 8], [-55, 6], [-52, 4],
    [-50, 0], [-44, -2], [-38, -5], [-35, -8], [-39, -13], [-39, -18],
    [-41, -22], [-45, -24], [-48, -26], [-52, -32], [-56, -35], [-58, -39],
    [-63, -41], [-65, -45], [-66, -49], [-69, -52], [-71, -54], [-74, -50],
    [-74, -46], [-73, -40], [-71, -30], [-70, -23], [-70, -18], [-76, -14],
    [-81, -6], [-80, -2], [-78, 1],
  ] },
  { name: 'Europe', ring: [
    [-9.5, 37], [-6, 36], [-2, 36.5], [3, 42.5], [7, 43.5], [9, 44.3],
    [12, 42], [14, 40.5], [16, 38], [17.2, 39], [13.8, 43.5], [15, 44.5],
    [17, 43], [19, 42], [20.5, 40], [22.5, 37], [24, 38.5], [26.5, 40.5],
    [29, 41], [35, 42], [41, 41.5], [39.5, 44.5], [36.5, 45.5], [30.5, 46.5],
    [30, 50.5], [37, 55.5], [57, 51], [60, 56], [60, 62], [60, 68],
    [40, 66.5], [33, 69.5], [26, 71], [10, 63.5], [5, 61.5], [5.5, 58.5],
    [9.5, 59], [12, 56.5], [13.5, 55.5], [19, 54.5], [24.5, 59.5],
    [29.5, 60], [25, 60.2], [21.5, 61.5], [21, 63.5], [24, 65.3],
    [19.5, 63.5], [17.5, 61.5], [18.5, 59.3], [13, 55.3], [10.5, 57.3],
    [8.1, 55.5], [9.2, 54.8], [8.5, 53.9], [5, 53], [1.5, 49.8],
    [-4.8, 48.4], [-2.5, 47.2], [-9, 43.5], [-9, 39],
  ] },
  { name: 'Africa', ring: [
    [-6, 35], [0, 36], [10, 37], [11, 33], [19, 30], [25, 31], [32, 31],
    [34, 28], [35, 23], [37, 18], [40, 15], [43, 11], [51, 12], [51, 10],
    [44, 4], [41, -2], [39, -7], [36, -14], [35, -19], [33, -24], [28, -32],
    [25, -34], [20, -34], [18, -32], [16, -28], [12, -18], [13, -12],
    [12, -6], [9, 0], [9, 4], [6, 4], [3, 6], [-4, 5], [-8, 4], [-13, 8],
    [-17, 12], [-17, 15], [-16, 18], [-13, 22], [-10, 26], [-9, 30],
  ] },
  { name: 'Asia', ring: [
    [60, 68], [76, 72], [104, 77], [120, 73], [150, 70], [178, 66],
    [166, 56], [157, 51], [155, 55], [150, 59], [142, 59], [141, 53],
    [134, 45], [132, 43], [129, 35.5], [126, 37.5], [121, 40], [122.5, 37],
    [121.8, 31], [119, 26], [116, 23], [113.8, 22.2], [108.5, 21.5],
    [109, 13], [105, 9], [100.5, 13.5], [103.5, 1.5], [101, 3], [98.5, 9],
    [97.5, 15], [91.5, 22.5], [83, 17.5], [80.3, 13.5], [77.5, 8.1],
    [73, 15.5], [69, 22], [67, 24.5], [57.3, 25.8], [48.7, 30], [50, 26],
    [59, 22.5], [55, 17.5], [49, 14], [43.3, 12.6], [42.7, 16.4], [39, 21],
    [35.5, 28], [32.7, 29.9], [35.9, 35.5], [36, 36.6], [30.5, 36.3],
    [26.5, 38.5], [29, 41], [32, 41.8], [41, 41.3], [45, 42], [49, 44],
    [57, 51], [60, 56], [60, 62],
  ] },
  { name: 'Australia', ring: [
    [142.5, -10.7], [145.5, -15], [146.5, -19], [149, -21], [153, -27.5],
    [151.5, -33.9], [146.5, -39], [141, -38.5], [138.5, -35.5], [134, -32.5],
    [125, -32.5], [119, -34.5], [115, -34.5], [115.5, -31], [113.5, -26],
    [114, -21.5], [122, -18], [128, -15], [130.8, -12.4], [137, -16],
  ] },
  { name: 'Greenland', ring: [
    [-45, 60], [-49, 62], [-53, 66], [-55, 69], [-53, 71], [-49, 74],
    [-58, 76], [-40, 78], [-25, 79], [-20, 77], [-18, 75], [-22, 70],
    [-25, 68], [-33, 65], [-38, 63], [-42, 61],
  ] },
  { name: 'Antarctica', ring: [
    [-180, -78], [-150, -75], [-120, -73], [-90, -72], [-70, -68],
    [-60, -63], [-58, -72], [-40, -70], [-10, -70], [20, -69], [40, -67],
    [80, -66], [120, -66], [150, -68], [170, -71], [180, -78], [180, -90],
    [-180, -90],
  ] },
  { name: 'Great Britain', ring: [
    [-5.7, 50.05], [-2.5, 50.6], [1.4, 51.1], [1.7, 52.9], [0.2, 53.6],
    [-1.5, 55], [-3, 56], [-2, 57.7], [-4, 58.6], [-5, 58.3], [-5.5, 56.5],
    [-5, 55], [-3.5, 54.7], [-4.5, 53.3], [-5.2, 51.7], [-3, 51.4],
    [-4.5, 50.9],
  ] },
  { name: 'Japan', ring: [
    [130.5, 31], [131.5, 32], [133, 34], [135.5, 34], [138, 34.6],
    [139.8, 35.3], [141, 38], [141.5, 41], [143.5, 42], [145.5, 43.5],
    [141.5, 45.4], [140.3, 43.5], [139.9, 40.5], [137, 37], [133, 35.5],
    [131, 34.5], [130, 33.5], [129.5, 32.5],
  ] },
  { name: 'Madagascar', ring: [
    [45.2, -25.6], [47.5, -24], [49.4, -18], [50.2, -15], [49.3, -11.9],
    [47.8, -14.5], [46.3, -15.7], [44.3, -20.2], [43.7, -23.4],
  ] },
  { name: 'New Zealand (North)', ring: [
    [173, -34.4], [178.5, -37.7], [177, -39.2], [174.8, -41.3],
    [174.1, -39.1], [174.4, -36.4], [174.5, -35.2],
  ] },
  { name: 'New Zealand (South)', ring: [
    [174, -41.2], [173, -42.5], [171, -45], [168.5, -46.6], [170.5, -46],
    [170.5, -43.5], [171.5, -41.8], [172.7, -40.6],
  ] },
  { name: 'Iceland', ring: [
    [-24.5, 65.2], [-21, 66.5], [-17, 66.5], [-14.5, 65.8], [-15, 64.3],
    [-19, 63.9], [-22.5, 63.8], [-24, 64.5],
  ] },
  { name: 'Luzon', ring: [
    [120.6, 18.4], [122.2, 16.5], [122.3, 14.2], [121.2, 13.9], [120.6, 14.8],
    [120.2, 16.2],
  ] },
  { name: 'Mindanao', ring: [
    [122.5, 7.8], [125.5, 9.7], [126.4, 8.3], [126.3, 7.2], [125.2, 5.9],
    [123.3, 5.6], [122, 6.9],
  ] },
  { name: 'Sri Lanka', ring: [
    [80.2, 9.8], [81.5, 8.3], [81.9, 7], [81, 5.9], [79.9, 7.2], [79.7, 8.7],
  ] },
  { name: 'Cuba', ring: [
    [-84.9, 21.9], [-82.3, 23.2], [-79.8, 23], [-76.2, 21.4], [-74.2, 20.2],
    [-77, 20.7], [-80.2, 21.9], [-84, 22],
  ] },
  { name: 'Ireland', ring: [
    [-10, 51.5], [-8, 51.6], [-6, 52.2], [-6.2, 53.4], [-6.4, 54.4],
    [-7.4, 55.3], [-8.5, 54.5], [-10, 53.8], [-10, 52.3],
  ] },
  { name: 'New Guinea', ring: [
    [131, -0.9], [136, -2], [141, -2.6], [145, -4.8], [148, -7.5],
    [150.8, -10.2], [147, -8.2], [143, -8.5], [138, -8.2], [133, -8],
    [132, -4], [131, -2.3],
  ] },
  { name: 'Borneo', ring: [
    [109, 1.5], [111, 3], [114, 4.8], [117, 7], [118.5, 5], [117.5, 2.5],
    [116.2, -1.5], [114, -3.5], [110.5, -3], [109, 0.5],
  ] },
  { name: 'Sumatra', ring: [
    [95.3, 5.6], [98.7, 3.6], [101, 1.3], [103.5, -1.2], [105.8, -5.9],
    [104, -5.2], [101, -2.6], [98.5, 0.5], [96, 3.2],
  ] },
  { name: 'Java', ring: [
    [105.2, -6.8], [106.8, -6.1], [110.5, -6.4], [112.7, -6.9], [114.4, -8.4],
    [111.1, -8.3], [107.8, -7.9], [105.7, -7.2],
  ] },
];

/* ---------------------------------------------------------------------- */
/* Projections                                                             */
/* ---------------------------------------------------------------------- */

/**
 * Equirectangular (plate carrée) projection.
 *
 * Latitude ±90° maps to the full height, longitude ±180° to the full width
 * — one degree is the same length everywhere, so the grid is perfectly
 * rectangular and shapes near the poles look stretched.
 *
 * @param {number} lat Latitude in degrees (-90..90).
 * @param {number} lon Longitude in degrees (-180..180).
 * @param {number} width Map width in user units.
 * @param {number} height Map height in user units.
 * @returns {[number, number]} `[x, y]` — y grows southwards.
 */
export function equirectangular(lat, lon, width, height) {
  const clampedLat = Math.max(-90, Math.min(90, Number(lat) || 0));
  const clampedLon = Math.max(-180, Math.min(180, Number(lon) || 0));
  const x = ((clampedLon + 180) / 360) * width;
  const y = ((90 - clampedLat) / 180) * height;
  return [x, y];
}

/** Web Mercator clamps latitude here — beyond ~85° the formula explodes. */
const MERCATOR_MAX_LAT = 85;

/**
 * Web Mercator projection (the standard slippy-map projection).
 *
 * Longitude maps linearly; latitude is stretched by `ln(tan(π/4 + φ/2))`
 * so compass bearings stay locally true. Latitudes beyond ±85° are clamped
 * (that is why Greenland looks enormous and Antarctica becomes a band).
 *
 * @param {number} lat Latitude in degrees (clamped to ±85).
 * @param {number} lon Longitude in degrees (-180..180).
 * @param {number} width Map width in user units.
 * @param {number} height Map height in user units.
 * @returns {[number, number]} `[x, y]` — y grows southwards.
 */
export function mercator(lat, lon, width, height) {
  const clampedLat = Math.max(-MERCATOR_MAX_LAT,
    Math.min(MERCATOR_MAX_LAT, Number(lat) || 0));
  const clampedLon = Math.max(-180, Math.min(180, Number(lon) || 0));
  const x = ((clampedLon + 180) / 360) * width;
  const mercN = Math.log(Math.tan(Math.PI / 4
    + (clampedLat * Math.PI / 180) / 2));
  const y = (height / 2) * (1 - mercN / Math.PI);
  return [x, y];
}

/** Registry the OlMap class draws its projection function from. */
const PROJECTIONS = { equirectangular, mercator };

/* ---------------------------------------------------------------------- */
/* Spherical helpers                                                       */
/* ---------------------------------------------------------------------- */

/**
 * Degrees → radians.
 *
 * @param {number} deg
 * @returns {number}
 */
function toRad(deg) {
  return (Number(deg) || 0) * Math.PI / 180;
}

/** Mean Earth radius in kilometres (spherical approximation). */
const EARTH_RADIUS_KM = 6371;

/**
 * Destination point given a start, a bearing and a distance.
 *
 * Classic spherical direct problem — used to trace radius circles that
 * respect the projection (a "circle" of constant km looks like an ellipse
 * on a flat map and pinches near the poles).
 *
 * @param {number} lat Start latitude (degrees).
 * @param {number} lon Start longitude (degrees).
 * @param {number} bearingDeg Compass bearing (0 = north, 90 = east).
 * @param {number} distanceKm Great-circle distance in kilometres.
 * @returns {[number, number]} `[lat, lon]` of the destination.
 */
export function destinationPoint(lat, lon, bearingDeg, distanceKm) {
  const angular = distanceKm / EARTH_RADIUS_KM;
  const bearing = toRad(bearingDeg);
  const latRad = toRad(lat);
  const lonRad = toRad(lon);
  const sinLat = Math.sin(latRad);
  const cosLat = Math.cos(latRad);
  const sinAng = Math.sin(angular);
  const cosAng = Math.cos(angular);

  const destLat = Math.asin(sinLat * cosAng
    + cosLat * sinAng * Math.cos(bearing));
  const destLon = lonRad + Math.atan2(
    sinAng * Math.sin(bearing) * cosLat,
    cosAng - sinLat * Math.sin(destLat));
  return [destLat * 180 / Math.PI,
    ((destLon * 180 / Math.PI + 540) % 360) - 180];
}

/**
 * Great-circle interpolation between two points (spherical slerp).
 *
 * @param {{lat: number, lon: number}} from Start point.
 * @param {{lat: number, lon: number}} to End point.
 * @param {number} [segments=16] Number of segments (vertices minus one).
 * @returns {Array<[number, number]>} `[lat, lon]` vertices, inclusive.
 */
export function greatCirclePoints(from, to, segments = 16) {
  const steps = Math.max(2, Math.round(segments) || 16);
  const lat1 = toRad(from.lat);
  const lon1 = toRad(from.lon);
  const lat2 = toRad(to.lat);
  const lon2 = toRad(to.lon);
  const d = 2 * Math.asin(Math.sqrt(
    Math.sin((lat2 - lat1) / 2) ** 2
    + Math.cos(lat1) * Math.cos(lat2) * Math.sin((lon2 - lon1) / 2) ** 2));
  const points = [];
  if (d === 0) {
    return [[from.lat, from.lon], [to.lat, to.lon]];
  }
  for (let i = 0; i <= steps; i += 1) {
    const t = i / steps;
    const a = Math.sin((1 - t) * d) / Math.sin(d);
    const b = Math.sin(t * d) / Math.sin(d);
    const x = a * Math.cos(lat1) * Math.cos(lon1)
      + b * Math.cos(lat2) * Math.cos(lon2);
    const y = a * Math.cos(lat1) * Math.sin(lon1)
      + b * Math.cos(lat2) * Math.sin(lon2);
    const z = a * Math.sin(lat1) + b * Math.sin(lat2);
    points.push([
      Math.atan2(z, Math.sqrt(x * x + y * y)) * 180 / Math.PI,
      Math.atan2(y, x) * 180 / Math.PI,
    ]);
  }
  return points;
}

/* ---------------------------------------------------------------------- */
/* SVG plumbing                                                            */
/* ---------------------------------------------------------------------- */

/** SVG 1.1 namespace — every element below is created with createElementNS. */
const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Create one namespaced SVG element with attributes.
 *
 * @param {string} tag Element tag ('path', 'circle', 'g', ...).
 * @param {Object<string, string|number>} [attrs] Attribute map.
 * @returns {SVGElement}
 */
function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    node.setAttribute(key, String(value));
  }
  return node;
}

/**
 * Build an SVG path `d` string from a ring of `[lon, lat]` vertices using
 * the given projection + viewport.
 *
 * @param {Array<[number, number]>} ring `[lon, lat]` vertices.
 * @param {function(number, number, number, number): [number, number]} proj
 * @param {{x: number, y: number, w: number, h: number}} view
 * @returns {string} Path data (closed with `Z`).
 */
function ringToPath(ring, proj, view) {
  if (!Array.isArray(ring) || !ring.length) return '';
  const parts = [];
  ring.forEach((vertex, i) => {
    const [lon, lat] = vertex;
    const [px, py] = proj(Number(lat), Number(lon), view.w, view.h);
    const x = (view.x + px).toFixed(1);
    const y = (view.y + py).toFixed(1);
    parts.push(`${i === 0 ? 'M' : 'L'}${x} ${y}`);
  });
  parts.push('Z');
  return parts.join(' ');
}

/* ---------------------------------------------------------------------- */
/* OlMap                                                                   */
/* ---------------------------------------------------------------------- */

/** Default SVG user-unit size of the full world (2:1 equirectangular ratio). */
const BASE_W = 960;
const BASE_H = 480;

/**
 * An offline world map bound to a container element.
 *
 * The map is one `<svg>` element rebuilt from data state on every render:
 * graticule → land → overlay circles/lines → markers. All coordinates live
 * in the SVG user-space defined by `viewBox` (full world by default,
 * tightened by {@link OlMap#fitBounds}).
 */
export class OlMap {
  /**
   * @param {HTMLElement} container Element the SVG map mounts into.
   * @param {{projection?: 'equirectangular'|'mercator',
   *          theme?: 'dark'|'light',
   *          padding?: number}} [options]
   *   `projection` defaults to equirectangular; `theme` only picks the
   *   fallback palette (CSS tokens always win when present); `padding`
   *   (default 24) is the margin kept around fitBounds viewports.
   */
  constructor(container, options = {}) {
    this.container = container ?? null;
    this.projection = options.projection === 'mercator'
      ? 'mercator' : 'equirectangular';
    this.themeMode = options.theme === 'light' ? 'light' : 'dark';
    this.padding = Number.isFinite(+options.padding)
      ? Math.max(0, +options.padding) : 24;

    /** @type {Array<Object>} Marker records (see addMarker). */
    this.markers = [];
    /** @type {Array<Object>} Radius-circle records (see addCircle). */
    this.circles = [];
    /** @type {Array<Object>} Great-circle line records (see addLine). */
    this.lines = [];

    /** @type {Array<function(Object)>>} Marker-click callbacks. */
    this._clickHandlers = [];
    /** Current viewport in full-world user units. */
    this.viewBox = { x: 0, y: 0, w: BASE_W, h: BASE_H };
    /** @type {SVGElement|null} */
    this.svg = null;
    /** @type {HTMLElement|null} */
    this._tip = null;
    this._observer = null;
    this._markerSeq = 0;

    if (this.container && typeof ResizeObserver !== 'undefined') {
      this._observer = new ResizeObserver(() => this.render());
      this._observer.observe(this.container);
    }
  }

  /**
   * Projection function for the current settings, evaluated against the
   * current viewport.
   *
   * @param {number} lat
   * @param {number} lon
   * @returns {[number, number]} `[x, y]` in current user units.
   */
  project(lat, lon) {
    const proj = PROJECTIONS[this.projection] || equirectangular;
    const [px, py] = proj(lat, lon, this.viewBox.w, this.viewBox.h);
    return [this.viewBox.x + px, this.viewBox.y + py];
  }

  /**
   * (Re)build the SVG map from current data state. Safe to call repeatedly;
   * never throws when the container is missing (headless no-op).
   *
   * @returns {OlMap} this — chainable.
   */
  render() {
    if (!this.container || typeof document === 'undefined') return this;
    const T = theme(this.themeMode);

    if (!this.svg || !this.svg.isConnected) {
      this.svg = svgEl('svg', {
        class: 'ol-map',
        viewBox: `${this.viewBox.x} ${this.viewBox.y} ${this.viewBox.w} ${this.viewBox.h}`,
        preserveAspectRatio: 'xMidYMid meet',
        'aria-label': 'Offline world map',
      });
      this.svg.style.display = 'block';
      this.svg.style.width = '100%';
      this.svg.style.height = '100%';
      this.container.append(this.svg);
    }
    this.svg.setAttribute('viewBox',
      `${this.viewBox.x} ${this.viewBox.y} ${this.viewBox.w} ${this.viewBox.h}`);
    this.svg.setAttribute('aria-label',
      `Offline world map — ${this.markers.length} markers `
      + `(${this.projection} projection)`);
    this.svg.replaceChildren();

    this.svg.append(this._graticuleLayer(T));
    this.svg.append(this._landLayer(T));
    this.svg.append(this._overlayLayer(T));
    this.svg.append(this._markerLayer(T));
    return this;
  }

  /**
   * Graticule: meridians + parallels every 30°, plus the dashed equator
   * and tropics.
   *
   * @param {Object} T Theme snapshot.
   * @returns {SVGElement}
   */
  _graticuleLayer(T) {
    const g = svgEl('g', { class: 'ol-map-graticule' });
    const maxLat = this.projection === 'mercator' ? MERCATOR_MAX_LAT : 90;

    for (let lon = -180; lon < 180; lon += 30) {
      const [x1, y1] = this.project(maxLat, lon);
      const [x2, y2] = this.project(-maxLat, lon);
      g.append(svgEl('line', {
        x1: x1.toFixed(1), y1: y1.toFixed(1),
        x2: x2.toFixed(1), y2: y2.toFixed(1),
        stroke: T.grid, 'stroke-width': 0.8,
      }));
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      if (lat === 0) continue; // the equator gets its own styled line
      const [x1, y1] = this.project(lat, -180);
      const [x2, y2] = this.project(lat, 180);
      g.append(svgEl('line', {
        x1: x1.toFixed(1), y1: y1.toFixed(1),
        x2: x2.toFixed(1), y2: y2.toFixed(1),
        stroke: T.grid, 'stroke-width': 0.8,
      }));
    }
    // Equator — accent, long dashes (the reference line of the map).
    {
      const [x1, y1] = this.project(0, -180);
      const [x2, y2] = this.project(0, 180);
      g.append(svgEl('line', {
        x1: x1.toFixed(1), y1: y1.toFixed(1),
        x2: x2.toFixed(1), y2: y2.toFixed(1),
        stroke: T.equator, 'stroke-width': 1.2, 'stroke-dasharray': '10 6',
      }));
    }
    // Tropics — faint dotted lines.
    for (const lat of [23.44, -23.44]) {
      const [x1, y1] = this.project(lat, -180);
      const [x2, y2] = this.project(lat, 180);
      g.append(svgEl('line', {
        x1: x1.toFixed(1), y1: y1.toFixed(1),
        x2: x2.toFixed(1), y2: y2.toFixed(1),
        stroke: T.tropic, 'stroke-width': 0.9, 'stroke-dasharray': '3 5',
      }));
    }
    return g;
  }

  /**
   * Land layer: one low-contrast filled path per outline.
   *
   * @param {Object} T Theme snapshot.
   * @returns {SVGElement}
   */
  _landLayer(T) {
    const g = svgEl('g', { class: 'ol-map-land' });
    const proj = PROJECTIONS[this.projection] || equirectangular;
    for (const land of LAND) {
      const d = ringToPath(land.ring, proj, this.viewBox);
      if (!d) continue;
      g.append(svgEl('path', {
        d,
        fill: T.land,
        stroke: T.landStroke,
        'stroke-width': 0.8,
        'stroke-linejoin': 'round',
      }));
    }
    return g;
  }

  /**
   * Overlay layer: radius circles and great-circle lines.
   *
   * @param {Object} T Theme snapshot.
   * @returns {SVGElement}
   */
  _overlayLayer(T) {
    const g = svgEl('g', { class: 'ol-map-overlays' });
    for (const circle of this.circles) {
      // 24 points at a constant great-circle distance — the shape accounts
      // for the latitude squeeze by construction (no cos patch needed).
      const parts = [];
      for (let bearing = 0; bearing < 360; bearing += 15) {
        const [lat, lon] = destinationPoint(circle.lat, circle.lon, bearing,
          circle.radiusKm);
        const [px, py] = this.project(lat, lon);
        parts.push(`${bearing === 0 ? 'M' : 'L'}${px.toFixed(1)} ${py.toFixed(1)}`);
      }
      const node = svgEl('path', {
        d: parts.join(' ') + ' Z',
        fill: withAlpha(T.accent, 0.10),
        stroke: withAlpha(T.accent, 0.45), 'stroke-width': 1,
        'stroke-dasharray': '6 4',
      });
      this._attachTip(node, [
        [circle.label || 'circle', `${Math.round(circle.radiusKm)} km radius`],
      ]);
      g.append(node);
    }
    for (const line of this.lines) {
      const pts = greatCirclePoints(line.from, line.to, 16);
      const d = pts.map(([lat, lon], i) => {
        const [px, py] = this.project(lat, lon);
        return `${i === 0 ? 'M' : 'L'}${px.toFixed(1)} ${py.toFixed(1)}`;
      }).join(' ');
      const node = svgEl('path', {
        d, fill: 'none',
        stroke: T.accent, 'stroke-width': 1.4,
        'stroke-dasharray': '2 4', 'stroke-linecap': 'round',
      });
      this._attachTip(node, [[line.label || 'link',
        `${line.from.lat.toFixed(1)}, ${line.from.lon.toFixed(1)} → `
        + `${line.to.lat.toFixed(1)}, ${line.to.lon.toFixed(1)}`]]);
      g.append(node);
    }
    return g;
  }

  /**
   * Marker layer: coloured dots with an enlarged invisible hit area.
   *
   * @param {Object} T Theme snapshot.
   * @returns {SVGElement}
   */
  _markerLayer(T) {
    const g = svgEl('g', { class: 'ol-map-markers' });
    this.markers.forEach((marker, index) => {
      const [x, y] = this.project(marker.lat, marker.lon);
      const color = marker.kind
        ? kindColor(marker.kind, T.palette) : T.accent;
      const node = svgEl('g', {
        class: 'ol-map-marker',
        'data-kind': marker.kind || '',
        'data-label': marker.label || '',
      });
      node.append(svgEl('circle', {
        cx: x.toFixed(1), cy: y.toFixed(1), r: 5,
        fill: color, stroke: T.bg, 'stroke-width': 1.5,
      }));
      const hit = svgEl('circle', {
        cx: x.toFixed(1), cy: y.toFixed(1), r: 11,
        fill: 'transparent', 'data-index': index,
      });
      hit.style.cursor = 'pointer';
      this._attachTip(hit, [
        [marker.label || marker.kind || 'marker',
          marker.value !== undefined && marker.value !== null
            ? String(marker.value) : `${marker.lat.toFixed(2)}, ${marker.lon.toFixed(2)}`],
      ]);
      hit.addEventListener('click', () => {
        for (const cb of this._clickHandlers) {
          try { cb(marker); } catch { /* a broken listener never breaks the map */ }
        }
      });
      node.append(hit);
      g.append(node);
    });
    return g;
  }

  /**
   * Attach hover tooltip handlers to one SVG node.
   *
   * @param {SVGElement} node
   * @param {Array<[string, string]>} rows
   */
  _attachTip(node, rows) {
    node.addEventListener('mouseenter', () => this._showTip(node, rows));
    node.addEventListener('mouseleave', () => this._hideTip());
  }

  /**
   * Ensure the `.ol-map-tip` tooltip div exists inside the container.
   *
   * @returns {HTMLElement|null}
   */
  _ensureTip() {
    if (!this.container) return null;
    if (!this._tip || !this._tip.isConnected) {
      const tip = document.createElement('div');
      tip.className = 'ol-map-tip';
      tip.style.position = 'absolute';
      tip.style.pointerEvents = 'none';
      tip.style.display = 'none';
      this.container.append(tip);
      this._tip = tip;
    }
    if (getComputedStyle(this.container).position === 'static') {
      this.container.style.position = 'relative';
    }
    return this._tip;
  }

  /**
   * Show the tooltip anchored above an SVG node.
   *
   * @param {SVGElement} node
   * @param {Array<[string, string]>} rows
   */
  _showTip(node, rows) {
    const tip = this._ensureTip();
    if (!tip) return;
    tip.replaceChildren(...rows.map(([label, value]) => {
      const row = document.createElement('div');
      row.className = 'tip-row';
      const lab = document.createElement('span');
      lab.className = 'tip-label';
      lab.textContent = String(label);
      const val = document.createElement('span');
      val.className = 'tip-val';
      val.textContent = String(value);
      row.append(lab, val);
      return row;
    }));
    const nodeRect = node.getBoundingClientRect();
    const boxRect = this.container.getBoundingClientRect();
    tip.style.display = 'block';
    const tipRect = tip.getBoundingClientRect();
    const left = nodeRect.left - boxRect.left + nodeRect.width / 2
      - tipRect.width / 2;
    tip.style.left = `${Math.max(4, Math.min(
      boxRect.width - tipRect.width - 4, Math.round(left)))}px`;
    tip.style.top = `${Math.max(4, Math.round(
      nodeRect.top - boxRect.top - tipRect.height - 6))}px`;
  }

  /** Hide the tooltip. */
  _hideTip() {
    if (this._tip) this._tip.style.display = 'none';
  }

  /* ---- data API ----------------------------------------------------- */

  /**
   * Add one marker at a geographic position.
   *
   * @param {{lat: number, lon: number, label?: string,
   *          kind?: string, value?: *}} spec
   * @returns {Object} The stored marker record (with its `id`).
   */
  addMarker(spec = {}) {
    const lat = Number(spec.lat);
    const lon = Number(spec.lon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
    this._markerSeq += 1;
    const marker = {
      id: this._markerSeq,
      lat, lon,
      label: spec.label ?? '',
      kind: spec.kind ?? '',
      value: spec.value,
    };
    this.markers.push(marker);
    this.render();
    return marker;
  }

  /**
   * Add many markers at once (one render, not N).
   *
   * @param {Array<{lat: number, lon: number, label?: string,
   *          kind?: string, value?: *}>} list
   * @returns {OlMap} this — chainable.
   */
  addMarkers(list = []) {
    for (const spec of Array.isArray(list) ? list : []) {
      if (!spec) continue;
      const lat = Number(spec.lat);
      const lon = Number(spec.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
      this._markerSeq += 1;
      this.markers.push({
        id: this._markerSeq,
        lat, lon,
        label: spec.label ?? '',
        kind: spec.kind ?? '',
        value: spec.value,
      });
    }
    this.render();
    return this;
  }

  /**
   * Drop every marker (circles/lines are kept).
   *
   * @returns {OlMap} this — chainable.
   */
  clearMarkers() {
    this.markers = [];
    this._hideTip();
    this.render();
    return this;
  }

  /**
   * Add a radius circle (approximate: 24 points at a constant great-circle
   * distance, so the shape already accounts for latitude squeeze — no
   * separate cos-correction is needed at draw time).
   *
   * @param {{lat: number, lon: number, radiusKm: number,
   *          label?: string}} spec
   * @returns {Object|null} The stored circle record.
   */
  addCircle(spec = {}) {
    const lat = Number(spec.lat);
    const lon = Number(spec.lon);
    const radiusKm = Number(spec.radiusKm);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)
      || !Number.isFinite(radiusKm) || radiusKm <= 0) return null;
    const circle = { lat, lon, radiusKm, label: spec.label ?? '' };
    this.circles.push(circle);
    this.render();
    return circle;
  }

  /**
   * Add a great-circle line between two points.
   *
   * @param {{from: {lat: number, lon: number},
   *          to: {lat: number, lon: number}, label?: string}} spec
   * @returns {Object|null} The stored line record.
   */
  addLine(spec = {}) {
    const from = spec.from || {};
    const to = spec.to || {};
    if (!Number.isFinite(+from.lat) || !Number.isFinite(+from.lon)
      || !Number.isFinite(+to.lat) || !Number.isFinite(+to.lon)) return null;
    const line = {
      from: { lat: +from.lat, lon: +from.lon },
      to: { lat: +to.lat, lon: +to.lon },
      label: spec.label ?? '',
    };
    this.lines.push(line);
    this.render();
    return line;
  }

  /**
   * Tighten the viewport around a set of geographic points.
   *
   * Points are projected against the *full-world* frame (never the current
   * viewport, so repeated fitBounds calls never compound), padded by
   * `this.padding` user units, clamped to the world and floored at a
   * 48-unit box so a single marker does not zoom to infinity.
   *
   * @param {Array<{lat: number, lon: number}>} points
   * @returns {OlMap} this — chainable.
   */
  fitBounds(points = []) {
    const list = (Array.isArray(points) ? points : []).filter(
      (p) => p && Number.isFinite(+p.lat) && Number.isFinite(+p.lon));
    if (!list.length) {
      this.viewBox = { x: 0, y: 0, w: BASE_W, h: BASE_H };
      this.render();
      return this;
    }
    const proj = PROJECTIONS[this.projection] || equirectangular;
    let minX = Infinity; let minY = Infinity;
    let maxX = -Infinity; let maxY = -Infinity;
    for (const p of list) {
      const [x, y] = proj(+p.lat, +p.lon, BASE_W, BASE_H);
      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
      if (y < minY) minY = y;
      if (y > maxY) maxY = y;
    }
    const pad = this.padding;
    minX = Math.max(0, minX - pad);
    minY = Math.max(0, minY - pad);
    maxX = Math.min(BASE_W, maxX + pad);
    maxY = Math.min(BASE_H, maxY + pad);
    let w = Math.max(48, maxX - minX);
    let h = Math.max(48, maxY - minY);
    if (minX + w > BASE_W) minX = BASE_W - w;
    if (minY + h > BASE_H) minY = BASE_H - h;
    this.viewBox = { x: minX, y: minY, w, h };
    this.render();
    return this;
  }

  /**
   * Register a marker-click callback. Clicks receive the marker record.
   *
   * @param {function(Object): void} cb
   * @returns {function(): void} Unsubscribe function.
   */
  onMarkerClick(cb) {
    if (typeof cb !== 'function') return () => {};
    this._clickHandlers.push(cb);
    return () => {
      this._clickHandlers = this._clickHandlers.filter((fn) => fn !== cb);
    };
  }

  /**
   * The current map as a standalone SVG string (for report embedding).
   *
   * @returns {string} `<svg>…</svg>` markup, '' before the first render.
   */
  export() {
    return this.svg ? this.svg.outerHTML : '';
  }

  /**
   * Compact state summary for status lines and tests.
   *
   * @returns {{markers: number, circles: number, lines: number,
   *   bounds: {latMin: number, latMax: number, lonMin: number,
   *            lonMax: number}|null,
   *   projection: string, viewBox: Object}}
   */
  mapSummary() {
    let bounds = null;
    if (this.markers.length) {
      const lats = this.markers.map((m) => m.lat);
      const lons = this.markers.map((m) => m.lon);
      bounds = {
        latMin: Math.min(...lats), latMax: Math.max(...lats),
        lonMin: Math.min(...lons), lonMax: Math.max(...lons),
      };
    }
    return {
      markers: this.markers.length,
      circles: this.circles.length,
      lines: this.lines.length,
      bounds,
      projection: this.projection,
      viewBox: { ...this.viewBox },
    };
  }

  /**
   * Tear the map down: observer disconnected, DOM untouched afterwards.
   *
   * @returns {OlMap} this — chainable.
   */
  destroy() {
    if (this._observer) {
      this._observer.disconnect();
      this._observer = null;
    }
    if (this._tip && this._tip.isConnected) this._tip.remove();
    this._tip = null;
    this._clickHandlers = [];
    return this;
  }
}

/* ---------------------------------------------------------------------- */
/* Public API                                                              */
/* ---------------------------------------------------------------------- */

/** Map module facade — see the module docstring for the full behaviour list. */
export const worldMap = { OlMap };

export default worldMap;
