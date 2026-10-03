"""
Optional FastAPI web UI and JSON REST API for ObscuraLens.

This module is an *extra*: the core package and CLI never import it, and
FastAPI/uvicorn are imported lazily inside :func:`create_app` / :func:`serve`
so that `import obscuralens` keeps working when the optional dependencies are
absent. Install them with::

    pip install "obscuralens[web]"

The API exposes the same trackers, investigation graph, source catalogues,
statistics and watchlist as the CLI, plus a small self-contained dashboard at
``/`` that talks to those endpoints with ``fetch``.
"""

from dataclasses import asdict
from typing import Any, Callable, Dict, Optional

from .. import __version__
from .. import investigate as investigate_module
from ..core.cache import cache
from ..core.metrics import metrics
from ..database import db
from ..trackers import (
    ASNTracker,
    CryptoTracker,
    CVETracker,
    DomainTracker,
    EmailTracker,
    HashTracker,
    IPTracker,
    PhoneTracker,
    URLTracker,
    UsernameTracker,
)
from ..utils.validators import (
    validate_asn,
    validate_crypto_address,
    validate_cve,
    validate_domain,
    validate_email,
    validate_hash,
    validate_ip,
    validate_phone,
    validate_url,
    validate_username,
)
from ..watchlist import watchlist

KINDS = ('ip', 'phone', 'username', 'email', 'domain', 'url', 'crypto',
         'hash', 'cve', 'asn')

_VALIDATORS: Dict[str, Callable[[str], Any]] = {
    'ip': validate_ip,
    'phone': validate_phone,
    'username': validate_username,
    'email': validate_email,
    'domain': validate_domain,
    'url': validate_url,
    'crypto': validate_crypto_address,
    'hash': validate_hash,
    'cve': validate_cve,
    'asn': validate_asn,
}

_TRACKERS: Dict[str, Any] = {
    'ip': IPTracker,
    'phone': PhoneTracker,
    'username': UsernameTracker,
    'email': EmailTracker,
    'domain': DomainTracker,
    'url': URLTracker,
    'crypto': CryptoTracker,
    'hash': HashTracker,
    'cve': CVETracker,
    'asn': ASNTracker,
}

# Field each tracker uses to echo back the queried target.
_TARGET_KEY = {
    'ip': 'ip',
    'phone': 'phone_number',
    'username': 'username',
    'email': 'email',
    'domain': 'domain',
    'url': 'url',
    'crypto': 'address',
    'hash': 'hash',
    'cve': 'cve',
    'asn': 'asn',
}

_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ObscuraLens</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem;
    background: #0d1117; color: #c9d1d9;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  h1 { margin: 0; font-size: 1.5rem; color: #58a6ff; }
  .sub { margin: .25rem 0 1.25rem; color: #8b949e; font-size: .85rem; }
  .controls { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1rem; }
  input, select, button {
    font: inherit; padding: .5rem .75rem; border-radius: 6px;
    border: 1px solid #30363d; background: #161b22; color: #c9d1d9;
  }
  input { flex: 1 1 18rem; min-width: 12rem; }
  button { cursor: pointer; background: #21262d; border-color: #30363d; }
  button:hover { background: #30363d; border-color: #58a6ff; }
  #output {
    background: #010409; border: 1px solid #30363d; border-radius: 6px;
    padding: 1rem; min-height: 18rem; overflow: auto; white-space: pre-wrap;
    word-break: break-word; font-size: .85rem; line-height: 1.4;
  }
</style>
</head>
<body>
<h1>ObscuraLens</h1>
<p class="sub">Multi-source OSINT console &mdash; dashboard</p>
<div class="controls">
  <input id="target" placeholder="IP, phone, username, email, domain, URL, crypto, hash, CVE or AS number"
         autofocus>
  <select id="kind" title="Target type">
    <option value="auto">auto</option>
    <option value="ip">ip</option>
    <option value="phone">phone</option>
    <option value="username">username</option>
    <option value="email">email</option>
    <option value="domain">domain</option>
    <option value="url">url</option>
    <option value="crypto">crypto</option>
    <option value="hash">hash</option>
    <option value="cve">cve</option>
    <option value="asn">asn</option>
  </select>
  <button onclick="lookup()">Look up</button>
  <button onclick="risk()">Risk</button>
  <button onclick="investigate()">Investigate</button>
  <button onclick="timeline()">Timeline</button>
  <button onclick="correlateAll()">Correlate</button>
  <button onclick="intel()">Intel</button>
  <button onclick="watch()">Watch</button>
</div>
<pre id="output">Ready.</pre>
<script>
  const $ = function (id) { return document.getElementById(id); };

  async function request(url, options) {
    const out = $('output');
    out.textContent = 'Loading...';
    try {
      const res = await fetch(url, options || {});
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      out.textContent = 'Error: ' + err;
    }
  }

  function targetValue() {
    const target = $('target').value.trim();
    if (!target) { $('output').textContent = 'Enter a target first.'; }
    return target;
  }

  function lookup() {
    const target = targetValue();
    if (!target) { return; }
    const kind = $('kind').value;
    if (kind === 'auto') {
      request('/api/investigate?target=' + encodeURIComponent(target) +
              '&pivot=false');
      return;
    }
    request('/api/lookup/' + kind + '/' + encodeURIComponent(target));
  }

  function investigate() {
    const target = targetValue();
    if (!target) { return; }
    request('/api/investigate?target=' + encodeURIComponent(target) +
            '&pivot=true');
  }

  function risk() {
    const target = targetValue();
    if (!target) { return; }
    const kind = $('kind').value;
    if (kind === 'auto') {
      request('/api/investigate?target=' + encodeURIComponent(target) +
              '&pivot=false');
      return;
    }
    request('/api/risk/' + kind + '/' + encodeURIComponent(target));
  }

  function timeline() {
    request('/api/timeline?limit=100');
  }

  function correlateAll() {
    request('/api/correlate');
  }

  function intel() {
    const target = targetValue();
    if (!target) { return; }
    request('/api/intel/' + encodeURIComponent(target));
  }

  function watch() {
    const target = targetValue();
    if (!target) { return; }
    request('/api/watch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target, label: '' })
    });
  }
</script>
</body>
</html>
"""


def create_app():
    """
    Build the ObscuraLens FastAPI application.

    FastAPI is imported here rather than at module import time so the rest of
    the package does not depend on the optional ``web`` extra.

    Raises:
        ImportError: if FastAPI is not installed, with an install hint.
    """
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ImportError(
            'The ObscuraLens web UI requires FastAPI. '
            'Install it with: pip install "obscuralens[web]"'
        ) from exc

    app = FastAPI(
        title='ObscuraLens',
        version=__version__,
        description='Optional OSINT web UI and JSON REST API.',
    )

    @app.get('/', response_class=HTMLResponse)
    def dashboard() -> str:
        """Self-contained dark dashboard (no external assets)."""
        return _DASHBOARD_HTML

    @app.get('/api/health')
    def api_health() -> Dict[str, Any]:
        """Liveness probe with the package version."""
        return {'status': 'ok', 'version': __version__}

    @app.get('/api/lookup/{kind}/{target}')
    def api_lookup(kind: str, target: str) -> Dict[str, Any]:
        """Run the tracker for one kind and return its raw result dict."""
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        ok, error = _VALIDATORS[kind](target)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        try:
            return _TRACKERS[kind]().track(target)
        except Exception as exc:  # never leak a tracker traceback
            message = f"{type(exc).__name__}: {exc}"
            return {
                _TARGET_KEY[kind]: target,
                'info': {},
                'sources_ok': [],
                'sources_failed': {kind: message},
                'field_count': 0,
                'success': False,
                'errors': [message],
                'error': message,
            }

    @app.get('/api/investigate')
    def api_investigate(target: str, pivot: bool = True) -> Dict[str, Any]:
        """Auto-detect a target and (optionally) follow related pivots."""
        if investigate_module.detect_kind(target) is None:
            raise HTTPException(status_code=400, detail='unknown target type')
        try:
            return investigate_module.investigate(target, pivot=pivot)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @app.get('/api/sources')
    def api_sources() -> Dict[str, Any]:
        """Source catalogues for the kinds that publish one."""
        from ..trackers.asn_sources import SOURCE_CATALOG as ASN_CATALOG
        from ..trackers.crypto_sources import SOURCE_CATALOG as CRYPTO_CATALOG
        from ..trackers.cve_sources import SOURCE_CATALOG as CVE_CATALOG
        from ..trackers.domain_sources import SOURCE_CATALOG as DOMAIN_CATALOG
        from ..trackers.email_sources import SOURCE_CATALOG as EMAIL_CATALOG
        from ..trackers.hash_sources import SOURCE_CATALOG as HASH_CATALOG
        from ..trackers.ip_sources import SOURCE_CATALOG as IP_CATALOG
        from ..trackers.url_sources import SOURCE_CATALOG as URL_CATALOG

        return {
            'ip': IP_CATALOG,
            'email': EMAIL_CATALOG,
            'domain': DOMAIN_CATALOG,
            'url': URL_CATALOG,
            'crypto': CRYPTO_CATALOG,
            'hash': HASH_CATALOG,
            'cve': CVE_CATALOG,
            'asn': ASN_CATALOG,
        }

    @app.get('/api/stats')
    def api_stats() -> Dict[str, Any]:
        """Database, cache, network and source-health statistics."""
        from ..health import health
        return {
            'database': db.get_statistics(),
            'cache': cache.stats(),
            'network': metrics.snapshot(),
            'source_health': health.get_health(),
        }

    # -- v4.0 endpoints -------------------------------------------------------

    @app.get('/api/risk/{kind}/{target}')
    def api_risk(kind: str, target: str) -> Dict[str, Any]:
        """Run a lookup and attach explainable heuristic risk scoring."""
        from ..correlation import attach_risk
        if kind not in KINDS:
            raise HTTPException(status_code=400, detail='unknown kind')
        ok, error = _VALIDATORS[kind](target)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        try:
            result = _TRACKERS[kind]().track(target)
            attach_risk(kind, result)
            return result
        except Exception as exc:
            return {
                _TARGET_KEY[kind]: target, 'info': {}, 'success': False,
                'errors': [f"{type(exc).__name__}: {exc}"],
            }

    @app.get('/api/timeline')
    def api_timeline(target: Optional[str] = None,
                     limit: int = 100) -> Dict[str, Any]:
        """Chronological event timeline across stored lookup history."""
        from ..correlation import build_timeline, history_records
        records = history_records(limit=max(limit * 3, 200))
        if target:
            needle = target.lower()
            records = [r for r in records
                       if needle in str(r.get('value', '')).lower()]
        return build_timeline(records, cap=limit)

    @app.get('/api/correlate')
    def api_correlate(limit: Optional[int] = None) -> Dict[str, Any]:
        """Correlation graph, clusters and bridge entities from history."""
        from ..config import config
        from ..correlation import build_graph, history_records
        records = history_records(
            limit=limit or config.app_config.correlation_max_history)
        if not records:
            return {'entities': [], 'links': [], 'clusters': [], 'stats': {}}
        return build_graph(records)

    @app.get('/api/correlate/pair')
    def api_correlate_pair(a: str, b: str) -> Dict[str, Any]:
        """Shared-infrastructure comparison between two targets."""
        from ..correlation import correlate
        return correlate(a, b)

    @app.get('/api/intel/{target}')
    def api_intel(target: str) -> Dict[str, Any]:
        """Threat-intel verdict for an IP: Tor exit, blocklist feeds."""
        from ..intel import feeds as intel_feeds
        from ..intel import tor as intel_tor
        ok, error = validate_ip(target)
        if not ok:
            raise HTTPException(status_code=400, detail=error)
        return {
            'ip': target,
            'feeds': intel_feeds.check_ip(target),
            'tor_exit': intel_tor.is_tor_exit(target),
            'relay': intel_tor.relay_details(target),
        }

    @app.get('/api/cases')
    def api_cases_list() -> Any:
        """Every investigation case with item/note/tag counts."""
        from ..cases import cases
        return cases.list_cases(include_archived=True)

    @app.get('/api/cases/{case_id}')
    def api_cases_get(case_id: int) -> Dict[str, Any]:
        """One case with items, notes and tags."""
        from ..cases import cases
        case = cases.get_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail='not found')
        return case

    @app.post('/api/cases', status_code=201)
    def api_cases_create(body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a case ({name, description})."""
        from ..cases import cases
        payload = body or {}
        name = str(payload.get('name', '') or '')
        if not name.strip():
            raise HTTPException(status_code=400, detail='name is required')
        return cases.create_case(
            name.strip(), description=str(payload.get('description', '') or ''))

    @app.get('/api/export/{fmt}/{target}')
    def api_export(fmt: str, target: str, pivot: bool = True) -> Dict[str, Any]:
        """Export an investigation entity graph as text (graphml/gexf/dot/...)."""
        from ..export import EXPORT_FORMATS, render
        if fmt not in EXPORT_FORMATS:
            raise HTTPException(status_code=400, detail='unknown format')
        if investigate_module.detect_kind(target) is None:
            raise HTTPException(status_code=400, detail='unknown target type')
        payload = investigate_module.investigate(target, pivot=pivot)
        text = render(payload.get('entities', []), payload.get('links', []), fmt)
        return {'target': target, 'format': fmt, 'graph': text,
                'entities': len(payload.get('entities', [])),
                'links': len(payload.get('links', []))}

    @app.get('/api/watch')
    def api_watch_list() -> Any:
        """Every watched target as a plain dict."""
        return [asdict(entry) for entry in watchlist.list()]

    @app.post('/api/watch', status_code=201)
    def api_watch_add(body: Dict[str, Any]) -> Dict[str, Any]:
        """Add a target to the watchlist; 409-style errors become 400."""
        target = str((body or {}).get('target', '') or '')
        label = str((body or {}).get('label', '') or '')
        try:
            watch_id = watchlist.add(target, label=label)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        return {'id': watch_id}

    @app.delete('/api/watch/{identifier}')
    def api_watch_remove(identifier: str) -> Dict[str, Any]:
        """Remove a watch by numeric id or target string."""
        ident: Any = int(identifier) if identifier.isdigit() else identifier
        removed = watchlist.remove(ident)
        if not removed:
            raise HTTPException(status_code=404, detail='not found')
        return {'removed': removed}

    @app.post('/api/watch/check')
    def api_watch_check(identifier: Optional[str] = None) -> Any:
        """Check one watch (id or target) or every watch; returns diffs."""
        ident: Any = None
        if identifier:
            ident = int(identifier) if identifier.isdigit() else identifier
        return [asdict(diff) for diff in watchlist.check(ident)]

    return app


def serve(host: str = '127.0.0.1', port: int = 8000,
          reload: bool = False, open_browser: bool = False) -> None:
    """
    Run the web UI with uvicorn.

    Args:
        host: interface to bind (default loopback only)
        port: TCP port to listen on
        reload: enable uvicorn's auto-reloader for development
        open_browser: open the dashboard in the default browser once the
            server is up (handy for the standalone executable)

    Raises:
        ImportError: if uvicorn is not installed, with an install hint.
    """
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise ImportError(
            'The ObscuraLens web server requires uvicorn. '
            'Install it with: pip install "obscuralens[web]"'
        ) from exc

    app = create_app()
    url = f'http://{host}:{port}'
    print(f'ObscuraLens web UI: {url}')
    if open_browser:
        import threading
        import time
        import urllib.request
        import webbrowser

        def _open_when_ready() -> None:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(url + '/api/health',
                                                timeout=2):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                return
            webbrowser.open(url)

        threading.Thread(target=_open_when_ready, daemon=True).start()
    uvicorn.run(app, host=host, port=port, reload=reload)
