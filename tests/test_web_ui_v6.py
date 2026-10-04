# ---------------------------------------------------------------------------
# ObscuraLens v6.0 -- web UI expansion tests (part 3, second half).
#
# Covers the five new SPA views (monitor / analytics / map / compare /
# profile), their wiring (VIEW_IDS, api.js client methods, CSS selectors)
# and the analytics endpoints the analytics view consumes that
# tests/test_analytics.py::TestAnalyticsWeb does not already pin down.
#
# The sandbox has no JavaScript runtime, so view behaviour is asserted at
# the source level (the same approach as tests/test_web_stream.py); HTTP
# behaviour runs through fastapi's TestClient. Nothing touches the network.
# ---------------------------------------------------------------------------

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from obscuralens.web import create_app  # noqa: E402

STATIC = Path(__file__).resolve().parent.parent / "obscuralens" / "web" / "static"


def _read(*parts):
    """Read one static asset (JS/CSS) as text."""
    return (STATIC.joinpath(*parts)).read_text(encoding="utf-8")


@pytest.fixture()
def client():
    return TestClient(create_app())


NEW_VIEWS = {
    "monitor": {"section": "workspace", "order": 20, "icon": "zap"},
    "analytics": {"section": "workspace", "order": 25, "icon": "flask"},
    "map": {"section": "investigation", "order": 35, "icon": "map"},
    "compare": {"section": "investigation", "order": 40, "icon": "layers"},
    "profile": {"section": "investigation", "order": 45, "icon": "finger"},
}

NEW_API_METHODS = [
    "analyticsStats", "analyticsAnomalies", "analyticsKeywords",
    "analyticsLanguage", "analyticsHistory", "mapPoints", "profile",
    "compare",
]


# --------------------------------------------------------------------------- #
# view registration + wiring (static source checks)
# --------------------------------------------------------------------------- #

class TestViewRegistration:

    def test_view_ids_contains_all_new_views(self):
        source = _read("js", "main.js")
        start = source.index("const VIEW_IDS")
        end = source.index("];", start)
        block = source[start:end]
        for view_id in NEW_VIEWS:
            assert f"'{view_id}'" in block, view_id

    def test_view_ids_has_no_duplicates(self):
        import re

        source = _read("js", "main.js")
        start = source.index("const VIEW_IDS")
        end = source.index("];", start)
        ids = re.findall(r"'([a-z]+)'", source[start:end])
        assert len(ids) == len(set(ids))
        assert len(ids) == 15  # 10 original + 5 new

    @pytest.mark.parametrize("view_id", sorted(NEW_VIEWS))
    def test_view_module_contract(self, view_id):
        spec = NEW_VIEWS[view_id]
        source = _read("js", "views", f"{view_id}.js")
        assert "export const view" in source
        assert f"id: '{view_id}'" in source
        assert f"section: '{spec['section']}'" in source
        assert f"order: {spec['order']}" in source
        assert f"icon: '{spec['icon']}'" in source
        assert "title: '" in source
        assert "subtitle: '" in source
        assert "async render(root" in source
        # every view ships a default export like its siblings
        assert "export default view" in source

    def test_api_client_has_new_methods(self):
        source = _read("js", "api.js")
        for method in NEW_API_METHODS:
            assert f"{method}(" in source, method

    def test_api_client_methods_are_unique(self):
        source = _read("js", "api.js")
        for method in NEW_API_METHODS:
            assert source.count(f"{method}(") == 1, method

    def test_api_client_targets_new_endpoints(self):
        source = _read("js", "api.js")
        for path in ("/api/analytics/stats", "/api/analytics/anomalies",
                     "/api/analytics/keywords", "/api/analytics/language",
                     "/api/analytics/history", "/api/map/points",
                     "/api/profile/", "/api/compare"):
            assert path in source, path

    def test_views_reference_lazy_router_safely(self):
        # map.js / profile.js import navigate directly from main.js exactly
        # like dashboard.js does (dynamic view loading avoids the cycle)
        for name in ("map", "profile"):
            source = _read("js", "views", f"{name}.js")
            assert "from '../main.js'" in source


# --------------------------------------------------------------------------- #
# index.html + static serving (TestClient)
# --------------------------------------------------------------------------- #

class TestNavIntegration:

    def test_index_has_nav_section_containers(self, client):
        response = client.get("/")
        assert response.status_code == 200
        for container in ("nav-workspace", "nav-investigation",
                          "nav-platform"):
            assert f'id="{container}"' in response.text, container

    def test_index_links_stylesheet_and_module(self, client):
        response = client.get("/")
        assert '/static/css/views.css' in response.text
        assert '/static/js/main.js' in response.text
        assert 'type="module"' in response.text

    @pytest.mark.parametrize("asset", [
        "js/views/monitor.js", "js/views/analytics.js", "js/views/map.js",
        "js/views/compare.js", "js/views/profile.js",
    ])
    def test_new_view_modules_are_served(self, client, asset):
        response = client.get(f"/static/{asset}")
        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"]
        assert "export const view" in response.text

    def test_views_css_is_served(self, client):
        response = client.get("/static/css/views.css")
        assert response.status_code == 200
        assert "monitorFadeIn" in response.text


# --------------------------------------------------------------------------- #
# analytics endpoints -- only the cases TestAnalyticsWeb leaves open
# (bins echo, z-score threshold, keywords top, language 400, history
# envelope with a custom limit, clusters parameter echo)
# --------------------------------------------------------------------------- #

class TestAnalyticsEndpoints:

    def test_stats_bins_parameter_controls_bin_count(self, client):
        response = client.post("/api/analytics/stats",
                               json={"values": [1, 2, 3, 4, 5, 6], "bins": 3})
        assert response.status_code == 200
        assert len(response.json()["histogram"]["bin_counts"]) == 3
        assert len(response.json()["histogram"]["bin_labels"]) == 3

    def test_anomalies_zscore_threshold_is_honoured(self, client):
        response = client.post(
            "/api/analytics/anomalies",
            json={"values": [1, 2, 3, 4, 100], "method": "zscore",
                  "threshold": 1.5})
        assert response.status_code == 200
        assert response.json()["anomaly_count"] >= 1

    def test_anomalies_zscore_default_masks_the_outlier(self, client):
        # documented detector quirk: the outlier drags the mean along, so a
        # default 3-sigma cut-off finds nothing in a 1..100 spike
        response = client.post(
            "/api/analytics/anomalies",
            json={"values": [1, 2, 3, 4, 100], "method": "zscore"})
        assert response.status_code == 200
        assert response.json()["anomaly_count"] == 0

    def test_keywords_top_parameter_caps_rows(self, client):
        response = client.post(
            "/api/analytics/keywords",
            json={"text": "alpha beta gamma delta epsilon alpha beta gamma",
                  "top": 3})
        assert response.status_code == 200
        assert response.json()["keyword_count"] <= 3

    def test_language_rejects_blank_text(self, client):
        response = client.post("/api/analytics/language", json={"text": "  "})
        assert response.status_code == 400

    def test_history_envelope_with_limit(self, client):
        response = client.get("/api/analytics/history?limit=10")
        assert response.status_code == 200
        body = response.json()
        for key in ("total_queries", "span_days", "kind_frequency",
                    "hour_profile", "weekday_profile", "success_rates",
                    "source_reliability", "anomalies", "top_targets"):
            assert key in body, key

    def test_clusters_echoes_parameters(self, client):
        response = client.post(
            "/api/analytics/clusters",
            json={"points": [[52.0, 13.0], [52.01, 13.01], [52.02, 13.02]],
                  "eps_km": 10, "min_points": 2})
        assert response.status_code == 200
        body = response.json()
        assert body["eps_km"] == 10
        assert body["min_points"] == 2
        assert body["point_count"] == 3


# --------------------------------------------------------------------------- #
# sse.js + monitor view (source-level; the endpoint itself is covered by
# tests/test_web_stream.py)
# --------------------------------------------------------------------------- #

class TestMonitorSse:

    def test_sse_module_shape(self):
        source = _read("js", "sse.js")
        assert "export class SseClient" in source
        assert "export const sse" in source
        assert "export const TOPICS" in source
        for topic in ("'connected'", "'lookup'", "'watch'", "'heartbeat'",
                      "'disconnect'"):
            assert topic in source, topic

    def test_sse_has_reconnect_and_fallback(self):
        source = _read("js", "sse.js")
        assert "EventSource" in source
        assert "fallbackPoll" in source
        assert "_scheduleReconnect" in source
        assert "MAX_BACKOFF_MS" in source
        assert "subscribeEvents" in source

    def test_monitor_view_uses_shared_sse(self):
        source = _read("js", "views", "monitor.js")
        assert "from '../sse.js'" in source
        assert "sse.connect()" in source
        assert "sse.on(" in source

    def test_monitor_never_closes_shared_stream(self):
        # the singleton is shared app-wide; the monitor must only
        # unsubscribe its own callbacks, never close the wire
        source = _read("js", "views", "monitor.js")
        assert "sse.close(" not in source

    def test_monitor_detaches_when_navigating_away(self):
        source = _read("js", "views", "monitor.js")
        assert "hashchange" in source
        assert "detach" in source
        assert "isConnected" in source
        assert "MAX_FEED_ROWS" in source

    def test_monitor_renders_connection_state_and_filters(self):
        source = _read("js", "views", "monitor.js")
        for marker in ("stateDot", "lastBeat", "muteBtn", "hide-", "counter"):
            assert marker in source, marker


# --------------------------------------------------------------------------- #
# CSS integration
# --------------------------------------------------------------------------- #

class TestCssIntegration:

    def test_new_view_selectors_exist(self):
        source = _read("css", "views.css")
        for selector in (".view-monitor", ".view-analytics", ".view-map",
                         ".view-compare", ".view-profile", ".monitor-feed",
                         ".compare-grid", ".profile-header", ".map-detail",
                         ".monitor-dot", ".compare-diff-group",
                         ".profile-stats"):
            assert selector in source, selector

    def test_new_animations_exist(self):
        source = _read("css", "views.css")
        assert "@keyframes monitorFadeIn" in source
        assert "@keyframes mapPanelIn" in source

    def test_new_sections_use_design_tokens(self):
        source = _read("css", "views.css")
        start = source.index("===== view: monitor")
        new_css = source[start:]
        assert "var(--panel-2)" in new_css
        assert "var(--line)" in new_css
        assert "var(--ok)" in new_css or "var(--danger)" in new_css
        assert "var(--sp-4)" in new_css

    def test_topic_filter_rules_exist(self):
        source = _read("css", "views.css")
        for topic in ("lookup", "watch", "heartbeat"):
            assert f'.monitor-feed.hide-{topic}' in source, topic


# --------------------------------------------------------------------------- #
# per-view source sanity (engine usage, data wiring, guards)
# --------------------------------------------------------------------------- #

class TestViewSourceSanity:

    def test_analytics_view_consumes_all_engines(self):
        source = _read("js", "views", "analytics.js")
        for call in ("api.analyticsStats", "api.analyticsAnomalies",
                     "api.analyticsKeywords", "api.analyticsLanguage",
                     "api.analyticsHistory", "charts2.boxplot",
                     "charts2.treemap", "charts2.heatmap",
                     "charts2.stackedBar", "charts2.sparkline"):
            assert call in source, call

    def test_analytics_view_sections_load_independently(self):
        source = _read("js", "views", "analytics.js")
        assert "Promise.allSettled" in source
        assert "failCallout" in source
        assert "emptyState" in source

    def test_map_view_uses_map_engine(self):
        source = _read("js", "views", "map.js")
        assert "from '../maps.js'" in source
        assert "new OlMap(" in source
        for method in ("addMarkers", "fitBounds", "onMarkerClick",
                       "mapSummary", "destroy", "export"):
            assert method in source, method
        assert "api.mapPoints" in source
        assert "toggleKind" in source  # legend doubles as kind filter
        assert "ui.download" in source  # SVG export action

    def test_map_view_supports_both_projections(self):
        source = _read("js", "views", "map.js")
        assert "equirectangular" in source
        assert "mercator" in source

    def test_compare_view_wiring(self):
        source = _read("js", "views", "compare.js")
        assert "api.compare(" in source
        assert "Select a kind for side" in source  # validation message
        assert "Enter a target for side" in source
        assert "Swap" in source
        for group in ("added", "removed", "differing"):
            assert f"payload?.{group}" in source, group

    def test_profile_view_wiring(self):
        source = _read("js", "views", "profile.js")
        assert "api.profile(" in source
        assert "api.lookup(" in source
        assert "api.watchAdd" in source
        assert "download(" in source  # JSON export action
        assert "found" in source      # not-found guidance branch

    def test_profile_view_deep_links(self):
        source = _read("js", "views", "profile.js")
        assert "params.get('kind')" in source
        assert "params.get('target')" in source
        assert "history.replaceState" in source
        assert "navigate('lookup'" in source
