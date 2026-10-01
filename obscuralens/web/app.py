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
    DomainTracker,
    EmailTracker,
    IPTracker,
    PhoneTracker,
    UsernameTracker,
)
from ..utils.validators import (
    validate_domain,
    validate_email,
    validate_ip,
    validate_phone,
    validate_username,
)
from ..watchlist import watchlist

KINDS = ('ip', 'phone', 'username', 'email', 'domain')

_VALIDATORS: Dict[str, Callable[[str], Any]] = {
    'ip': validate_ip,
    'phone': validate_phone,
    'username': validate_username,
    'email': validate_email,
    'domain': validate_domain,
}

_TRACKERS: Dict[str, Any] = {
    'ip': IPTracker,
    'phone': PhoneTracker,
    'username': UsernameTracker,
    'email': EmailTracker,
    'domain': DomainTracker,
}

# Field each tracker uses to echo back the queried target.
_TARGET_KEY = {
    'ip': 'ip',
    'phone': 'phone_number',
    'username': 'username',
    'email': 'email',
    'domain': 'domain',
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
  <input id="target" placeholder="IP, phone, username, email or domain"
         autofocus>
  <select id="kind" title="Target type">
    <option value="auto">auto</option>
    <option value="ip">ip</option>
    <option value="phone">phone</option>
    <option value="username">username</option>
    <option value="email">email</option>
    <option value="domain">domain</option>
  </select>
  <button onclick="lookup()">Look up</button>
  <button onclick="investigate()">Investigate</button>
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
        from ..trackers.domain_sources import SOURCE_CATALOG as DOMAIN_CATALOG
        from ..trackers.email_sources import SOURCE_CATALOG as EMAIL_CATALOG
        from ..trackers.ip_sources import SOURCE_CATALOG as IP_CATALOG

        return {
            'ip': IP_CATALOG,
            'email': EMAIL_CATALOG,
            'domain': DOMAIN_CATALOG,
        }

    @app.get('/api/stats')
    def api_stats() -> Dict[str, Any]:
        """Database, cache and per-session network statistics."""
        return {
            'database': db.get_statistics(),
            'cache': cache.stats(),
            'network': metrics.snapshot(),
        }

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
          reload: bool = False) -> None:
    """
    Run the web UI with uvicorn.

    Args:
        host: interface to bind (default loopback only)
        port: TCP port to listen on
        reload: enable uvicorn's auto-reloader for development

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
    print(f'ObscuraLens web UI: http://{host}:{port}')
    uvicorn.run(app, host=host, port=port, reload=reload)
