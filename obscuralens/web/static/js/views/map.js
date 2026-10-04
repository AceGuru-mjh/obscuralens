/**
 * ObscuraLens web UI — Map view (v6.0 part 3).
 *
 * Offline world map over `GET /api/map/points`: every stored lookup that
 * resolved to coordinates (coords/IP/BSSID history) becomes a kind-coloured
 * marker on the canvas-free SVG world map from `maps.js`. The whole thing
 * renders from a bundled 17-continent GeoJSON simplification — zero tiles,
 * zero network, works fully offline.
 *
 * Interactions: projection toggle (equirectangular ⇄ mercator, rebuilt),
 * fit-to-markers zoom, marker click → sliding detail panel with a link into
 * the entity profile view, a kind legend that doubles as a per-kind
 * visibility filter, an SVG export of the current map and a lat/lon range
 * stats bar. With no geo-bearing history the continents still render
 * beneath an empty-state overlay.
 */

import { api } from '../api.js';
import { ui } from '../ui.js';
import { navigate } from '../main.js';
import { OlMap } from '../maps.js';
import { colorFor } from '../charts2.js';

const { el, icon, badge, kindBadge, fmtInt, emptyState, toastOk, toastErr } = ui;

/** Marker-fetch window: newest rows scanned for coordinates. */
const POINT_LIMIT = 1000;

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
      el('div', { class: 'strong sm' }, ['Could not load map points']),
      el('div', { class: 'muted xs' }, [errText(message)]),
    ]),
    el('button', { class: 'btn btn-sm', type: 'button', onclick: retry }, [
      icon('refresh', { size: 13 }), 'Retry',
    ]),
  ]);
}

/**
 * Normalise a /api/map/points payload into marker specs.
 *
 * @param {*} payload
 * @returns {Array<{lat: number, lon: number, label: string, kind: string}>}
 */
function pointsOf(payload) {
  const raw = payload && typeof payload === 'object' && Array.isArray(payload.points)
    ? payload.points : (Array.isArray(payload) ? payload : []);
  return raw
    .map((p) => ({
      lat: Number(p?.lat),
      lon: Number(p?.lon),
      label: String(p?.label ?? ''),
      kind: String(p?.kind ?? '').toLowerCase(),
    }))
    .filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lon)
      && Math.abs(p.lat) <= 90 && Math.abs(p.lon) <= 180);
}

/** The current document theme for the map fallback palette. */
function mapTheme() {
  try {
    return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

/* ---------------------------------------------------------------------- */
/* View                                                                    */
/* ---------------------------------------------------------------------- */

export const view = {
  id: 'map',
  title: 'Map',
  subtitle: 'Offline geographic view',
  icon: 'map',
  section: 'investigation',
  order: 35,

  /**
   * Mount the map view.
   *
   * @param {HTMLElement} root #view container.
   * @param {URLSearchParams} params Route params (unused — points come from
   *        stored history, not the URL).
   */
  async render(root, params) {
    void params;

    /* ---- state --------------------------------------------------------- */

    let projection = 'equirectangular';
    /** @type {Array<{lat: number, lon: number, label: string, kind: string}>} */
    let points = [];
    /** @type {OlMap|null} */
    let map = null;
    /** Kinds currently visible on the map (legend toggles flip these). */
    const visibleKinds = new Set();

    /* ---- toolbar -------------------------------------------------------- */

    const countBadge = el('span', { class: 'badge badge-muted' }, ['0 points']);
    const projButtons = {
      equirectangular: el('button', {
        class: 'btn btn-sm', type: 'button', 'aria-pressed': 'true',
      }, ['Equirectangular']),
      mercator: el('button', {
        class: 'btn btn-sm', type: 'button', 'aria-pressed': 'false',
      }, ['Mercator']),
    };
    const fitBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
      icon('search', { size: 13 }), 'Fit to points',
    ]);
    const resetBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
      icon('globe', { size: 13 }), 'Whole world',
    ]);
    const refreshBtn = el('button', { class: 'btn btn-sm', type: 'button' }, [
      icon('refresh', { size: 13 }), 'Reload',
    ]);
    const exportBtn = el('button', {
      class: 'btn btn-sm', type: 'button',
      title: 'Download the current map as a standalone SVG',
    }, [
      icon('download', { size: 13 }), 'Export SVG',
    ]);

    const toolbar = el('div', { class: 'filter-bar map-toolbar' }, [
      el('span', { class: 'btn-group', role: 'group', 'aria-label': 'Projection' }, [
        projButtons.equirectangular, projButtons.mercator,
      ]),
      fitBtn,
      resetBtn,
      refreshBtn,
      exportBtn,
      el('span', { class: 'spacer' }),
      countBadge,
    ]);

    /* ---- stage / detail panel / legend / stats -------------------------- */

    const mapStage = el('div', { class: 'map-stage', 'aria-label': 'World map stage' });
    const mapEmpty = el('div', { class: 'map-empty', hidden: true }, [
      emptyState({
        title: 'No geo-located lookups yet',
        hint: 'Run coords or IP lookups — every stored result with coordinates '
          + 'lights up here as a kind-coloured marker.',
        icon: 'map',
      }),
    ]);
    const detailPanel = el('aside', { class: 'map-detail', hidden: true,
      'aria-label': 'Marker details' });
    const legend = el('div', { class: 'map-legend', 'aria-label': 'Kind legend' });
    const statsBar = el('div', { class: 'map-statsbar mono xs' }, ['']);

    const mapCard = el('div', { class: 'card map-card' }, [
      toolbar,
      el('div', { class: 'map-frame' }, [mapStage, mapEmpty, detailPanel, legend]),
      statsBar,
    ]);
    const errorSlot = el('div', { hidden: true });

    root.replaceChildren(el('div', { class: 'view-map' }, [
      el('div', { class: 'page-head' }, [
        el('div', { class: 'titles' }, [
          el('h1', { class: 'page-title' }, ['Map']),
          el('p', { class: 'page-desc' }, [
            'Every geo-located target in your history on one offline world map — '
            + 'no tiles, no CDN, no data leaves the browser. Click a marker for '
            + 'its profile.',
          ]),
        ]),
      ]),
      el('div', { class: 'stack-lg' }, [mapCard, errorSlot]),
    ]));

    /* ---- map lifecycle --------------------------------------------------- */

    /** The subset of points whose kind is currently visible. */
    function visiblePoints() {
      if (!visibleKinds.size) return points;
      return points.filter((p) => visibleKinds.has(p.kind));
    }

    /**
     * Rebuild the OlMap from scratch (projection switch / first mount /
     * legend toggle).
     *
     * @param {string} nextProjection
     * @param {boolean} [fit] Tighten the viewport around the markers.
     */
    function buildMap(nextProjection, fit = false) {
      projection = nextProjection === 'mercator' ? 'mercator' : 'equirectangular';
      if (map) {
        map.destroy();
        map = null;
      }
      mapStage.replaceChildren();
      detailPanel.hidden = true;
      map = new OlMap(mapStage, { projection, theme: mapTheme() });
      map.onMarkerClick((marker) => showDetail(marker));
      const shown = visiblePoints();
      if (shown.length) map.addMarkers(shown);
      if (fit && shown.length) map.fitBounds(shown);
      else map.render();
      refreshChrome();
    }

    /** Update badge, legend, stats bar and empty overlay from current state. */
    function refreshChrome() {
      const shown = visiblePoints();
      countBadge.textContent = `${fmtInt(shown.length)} of ${fmtInt(points.length)} point${points.length === 1 ? '' : 's'}`;
      mapEmpty.hidden = points.length > 0;

      // legend doubles as a kind-visibility toggle: click a chip to hide or
      // show every marker of that kind (an empty visible-set means "all")
      const byKind = new Map();
      for (const p of points) byKind.set(p.kind, (byKind.get(p.kind) ?? 0) + 1);
      legend.replaceChildren(...[...byKind.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([kind, n]) => {
          const active = !visibleKinds.size || visibleKinds.has(kind);
          return el('button', {
            class: `map-legend-item${active ? '' : ' is-off'}`,
            type: 'button',
            title: active ? `Hide ${kind || 'unknown'} markers` : `Show ${kind || 'unknown'} markers`,
            'aria-pressed': String(active),
            onclick: () => toggleKind(kind),
          }, [
            el('span', {
              class: 'map-legend-dot',
              style: { background: safeColor(kind) },
            }),
            el('span', { class: 'xs' }, [kind || 'unknown']),
            el('span', { class: 'faint xs' }, [String(n)]),
          ]);
        }));

      const summary = map ? map.mapSummary() : null;
      const bounds = summary?.bounds;
      const filtered = visibleKinds.size > 0 && shown.length !== points.length;
      statsBar.replaceChildren(el('span', {}, [
        `${fmtInt(summary?.markers ?? shown.length)} markers · `
        + `${summary?.projection ?? projection}`
        + (filtered ? ' · kind filter on' : ''),
        bounds
          ? ` · lat ${bounds.latMin.toFixed(2)}…${bounds.latMax.toFixed(2)}`
            + ` · lon ${bounds.lonMin.toFixed(2)}…${bounds.lonMax.toFixed(2)}`
          : ' · no bounds',
      ]));
    }

    /** Toggle one kind's marker visibility and rebuild the map. */
    function toggleKind(kind) {
      if (!visibleKinds.size) {
        // first toggle: everything currently shown becomes the baseline
        for (const p of points) visibleKinds.add(p.kind);
      }
      if (visibleKinds.has(kind)) visibleKinds.delete(kind);
      else visibleKinds.add(kind);
      if (visibleKinds.size === 0 || visibleKinds.size === new Set(points.map((p) => p.kind)).size) {
        // all-on or all-off collapse back to "no filter"
        visibleKinds.clear();
      }
      buildMap(projection, visibleKinds.size > 0);
    }

    /** Marker colour that survives headless colour reads. */
    function safeColor(kind) {
      try {
        return colorFor(kind) || cssAccent();
      } catch {
        return cssAccent();
      }
    }

    function cssAccent() {
      try {
        return getComputedStyle(document.documentElement)
          .getPropertyValue('--accent').trim() || '#2dd4a7';
      } catch {
        return '#2dd4a7';
      }
    }

    /** Show the sliding detail panel for one marker record. */
    function showDetail(marker) {
      const kind = String(marker?.kind ?? '').toLowerCase();
      const target = String(marker?.label ?? '');
      const closeBtn = el('button', {
        class: 'btn btn-sm btn-ghost', type: 'button',
        'aria-label': 'Close details',
        onclick: () => { detailPanel.hidden = true; },
      }, [icon('x', { size: 13 })]);

      detailPanel.replaceChildren(
        el('div', { class: 'map-detail-head' }, [
          kind ? kindBadge(kind) : badge('point', 'accent'),
          el('span', { class: 'grow' }),
          closeBtn,
        ]),
        el('div', { class: 'map-detail-target mono' }, [target || '—']),
        el('div', { class: 'map-detail-coords mono xs' }, [
          `lat ${Number(marker?.lat).toFixed(4)} · lon ${Number(marker?.lon).toFixed(4)}`,
        ]),
        el('div', { class: 'map-detail-actions' }, [
          kind && target ? el('button', {
            class: 'btn btn-sm btn-primary', type: 'button',
            onclick: () => navigate('profile', { kind, target }),
          }, [icon('finger', { size: 13 }), 'Open profile']) : null,
          el('button', {
            class: 'btn btn-sm', type: 'button',
            onclick: () => navigate('lookup', { kind: kind || 'auto', target }),
          }, [icon('search', { size: 13 }), 'Look up']),
        ]),
      );
      detailPanel.hidden = false;
    }

    /* ---- toolbar wiring --------------------------------------------------- */

    projButtons.equirectangular.addEventListener('click', () => {
      if (projection === 'equirectangular') return;
      setProjection('equirectangular');
    });
    projButtons.mercator.addEventListener('click', () => {
      if (projection === 'mercator') return;
      setProjection('mercator');
    });

    function setProjection(next) {
      for (const [name, btn] of Object.entries(projButtons)) {
        btn.setAttribute('aria-pressed', String(name === next));
      }
      const shown = visiblePoints();
      buildMap(next, shown.length > 0 && shown.length <= 40);
    }

    fitBtn.addEventListener('click', () => {
      const shown = visiblePoints();
      if (map && shown.length) map.fitBounds(shown);
      refreshChrome();
    });

    resetBtn.addEventListener('click', () => {
      visibleKinds.clear();
      buildMap(projection, false);
    });

    refreshBtn.addEventListener('click', () => { loadPoints(true); });

    exportBtn.addEventListener('click', () => {
      try {
        const svg = map ? map.export() : '';
        if (!svg) {
          toastErr('The map has not rendered yet — nothing to export');
          return;
        }
        const name = `obscuralens-map-${projection}-${new Date().toISOString()
          .slice(0, 10)}.svg`;
        ui.download(name, svg, 'image/svg+xml');
        toastOk(`Exported ${name}`);
      } catch (err) {
        toastErr(`Export failed: ${errText(err)}`);
      }
    });

    /* ---- data loading ------------------------------------------------------ */

    async function loadPoints(keepViewport = false) {
      refreshBtn.disabled = true;
      errorSlot.hidden = true;
      errorSlot.replaceChildren();
      try {
        const payload = await api.mapPoints(POINT_LIMIT);
        if (!mapStage.isConnected) return;
        points = pointsOf(payload);
        visibleKinds.clear(); // fresh data resets any kind filter
        buildMap(projection, !keepViewport && points.length > 0
          && points.length <= 40);
      } catch (err) {
        // the continents still render — only the markers are missing
        if (!mapStage.isConnected) return;
        errorSlot.hidden = false;
        errorSlot.replaceChildren(failCallout(err, () => loadPoints(true)));
      } finally {
        refreshBtn.disabled = false;
      }
    }

    /* ---- boot ---------------------------------------------------------------- */

    buildMap(projection);
    refreshChrome();
    await loadPoints();
  },
};

export default view;
