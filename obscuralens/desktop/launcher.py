"""
Single-instance launcher for the ObscuraLens Desktop beta.

``obscuralens-desktop`` (the console script wired up in ``pyproject.toml``)
boots the local web UI with a browser window and keeps running until the
user presses ``Ctrl+C``.  The launch sequence is:

1. print the desktop banner (:func:`obscuralens.desktop.branding.render_banner`),
2. acquire the single-instance lock
   (:class:`obscuralens.desktop.singleinstance.InstanceLock`) -- a second
   launch prints the URL of the running instance and exits 0,
3. probe for a free TCP port in the configured port range,
4. lazily build the FastAPI app + uvicorn server
   (:func:`build_server`) -- when the optional ``web`` extra is missing the
   launcher fails with a friendly ``pip install "obscuralens[web]"`` hint
   instead of a stack trace,
5. run the server on a daemon thread and print the staged splash lines
   (:func:`obscuralens.desktop.branding.startup_sequence`),
6. wait for readiness, open the browser (unless ``--no-browser``),
7. block until ``Ctrl+C``, then shut the server down gracefully, release
   the lock and exit 0.

Design for testability: no top-level side effects, threads and uvicorn are
only touched inside :func:`launch`, and every helper (port probe,
readiness probe, browser opener, server builder) can be injected or
monkeypatched.  The module imports the standard library plus the light
desktop siblings only -- ``fastapi``/``uvicorn``/``webbrowser`` are
imported inside function bodies behind ``ImportError`` guards so the plain
CI test job can import this file without the web extra.
"""

import argparse
import contextlib
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Tuple

from .branding import (
    DESKTOP_NAME,
    render_banner,
    render_splash,
    startup_sequence,
)
from .channel import default_channel, get_channel
from .singleinstance import InstanceLock, lock_url
from .updater import UpdateChecker

#: Environment variable that disables automatic browser opening.
NO_BROWSER_ENV = "OBSCURALENS_NO_BROWSER"

#: Readiness endpoint polled before the browser is opened.
READY_PATH = "/api/stats"

#: Exit codes used by :func:`launch` and :func:`main`.
EXIT_OK = 0
EXIT_FAILURE = 1

#: How long :func:`_shutdown_server` waits for the uvicorn thread.
SHUTDOWN_JOIN_TIMEOUT = 5.0

ProbeCallable = Callable[[str], bool]


# ---------------------------------------------------------------------------
# Launch options
# ---------------------------------------------------------------------------

@dataclass
class LaunchOptions:
    """
    Everything the launcher needs to know, in one injectable object.

    Attributes:
        host: interface to bind (default loopback only, like ``serve``).
        port: preferred TCP port; the first free port at or above it inside
            ``port_range`` is used.
        port_range: inclusive ``(low, high)`` probe window (default 8000-8020).
        no_browser: never open a browser window automatically.
        open_delay: seconds to wait after readiness before opening the
            browser (gives uvicorn a moment to finish logging).
        timeout_ready: seconds to wait for the readiness endpoint.
        channel: channel name for the desktop runtime (defaults to the
            package channel); used by ``--check-update`` flows.
        single_instance: acquire the ``desktop.lock`` before starting.
        browser: browser to open (``firefox``, ``chrome``, ...) or ``None``
            for the system default.
    """

    host: str = "127.0.0.1"
    port: int = 8000
    port_range: Tuple[int, int] = (8000, 8020)
    no_browser: bool = False
    open_delay: float = 1.0
    timeout_ready: float = 15.0
    channel: Optional[str] = None
    single_instance: bool = True
    browser: Optional[str] = None

    def resolved_channel(self) -> str:
        """Channel name taking the package default into account."""
        return get_channel(self.channel).name


# ---------------------------------------------------------------------------
# Port helpers
# ---------------------------------------------------------------------------

def find_free_port(host: str = "127.0.0.1", start: int = 8000,
                   attempts: int = 21) -> Optional[int]:
    """
    First bindable port at or above ``start`` within ``attempts`` tries.

    Each candidate is probed with a real ``bind(2)`` (``SO_REUSEADDR``
    deliberately *not* set, so a TIME_WAIT socket still counts as taken)
    and the probe socket is closed before returning.  ``None`` when every
    candidate is busy or sockets are unavailable.
    """
    attempts = max(1, int(attempts))
    for offset in range(attempts):
        port = int(start) + offset
        if not 0 < port < 65536:
            continue
        probe = None
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind((host, port))
        except OSError:
            continue
        finally:
            if probe is not None:
                with contextlib.suppress(OSError):
                    probe.close()
        return port
    return None


def port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """Whether a TCP ``connect`` to ``host:port`` succeeds right now."""
    probe = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(max(0.05, float(timeout)))
        return probe.connect_ex((host, int(port))) == 0
    except OSError:
        return False
    finally:
        if probe is not None:
            with contextlib.suppress(OSError):
                probe.close()


def _port_attempts(options: LaunchOptions) -> int:
    """Number of ports to probe for a :class:`LaunchOptions` instance."""
    start = int(options.port)
    low, high = options.port_range or (start, start)
    try:
        end = max(int(high), start)
        low = int(low)
    except (TypeError, ValueError):
        return 1
    if end < start or low > start:
        # Preferred port outside the configured window: honour it exactly.
        return 1
    return max(1, min(end - start + 1, 200))


# ---------------------------------------------------------------------------
# Readiness probing
# ---------------------------------------------------------------------------

def _http_probe(url: str, timeout: float = 2.0) -> bool:
    """
    Default readiness probe (urllib GET, never raises).

    Any HTTP status -- including 4xx/5xx -- counts as ready: it proves the
    server is accepting connections.  Only connection-level failures
    (refused, timeout, DNS) report ``False``.
    """
    try:
        import urllib.error
        import urllib.request

        request = urllib.request.Request(
            url, headers={"User-Agent": "ObscuraLens-Desktop-Probe"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1)
            return True
    except urllib.error.HTTPError:
        return True  # the server answered; that is all we need
    except Exception:
        return False


def wait_until_ready(host: str,
                     port: int,
                     path: str = READY_PATH,
                     timeout: float = 15.0,
                     interval: float = 0.25,
                     probe: Optional[ProbeCallable] = None) -> bool:
    """
    Poll ``http://host:port/path`` until it answers or *timeout* expires.

    ``probe`` may be injected for tests: a ``callable(url) -> bool``.  The
    loop catches ``URLError`` (and everything else) from the default urllib
    probe, sleeps *interval* seconds between attempts and never raises.
    """
    url = "http://{0}:{1}{2}".format(host, int(port), path or "/")
    deadline = time.monotonic() + max(0.0, float(timeout))
    interval = max(0.01, float(interval))
    while True:
        if probe is not None:
            try:
                if probe(url):
                    return True
            except Exception:
                pass
        elif _http_probe(url):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(interval, remaining))


# ---------------------------------------------------------------------------
# Browser opening
# ---------------------------------------------------------------------------

#: Friendly browser-name aliases accepted by ``--browser`` / LaunchOptions.
_BROWSER_ALIASES = {
    "firefox": ("firefox",),
    "chrome": ("google-chrome", "chrome", "windows-default"),
    "chromium": ("chromium", "chromium-browser"),
    "edge": ("edge", "windows-default"),
    "safari": ("safari", "macosx"),
    "opera": ("opera",),
}


def _browser_disabled() -> bool:
    """``OBSCURALENS_NO_BROWSER`` semantics: any truthy value disables."""
    value = os.environ.get(NO_BROWSER_ENV, "").strip().lower()
    return value not in ("", "0", "false", "no", "off")


def _resolve_browser(webbrowser_module: Any, name: str) -> Optional[Any]:
    """Map a friendly browser name to a webbrowser controller."""
    candidates = _BROWSER_ALIASES.get(name, (name,))
    for candidate in candidates:
        try:
            return webbrowser_module.get(candidate)
        except Exception:  # webbrowser.Error and friends
            continue
    return None


def open_browser(url: str, browser: Optional[str] = None) -> bool:
    """
    Open *url* in a browser; ``False`` on any failure, never raises.

    Honours ``OBSCURALENS_NO_BROWSER`` (any truthy value disables opening)
    and the optional *browser* name (``firefox``, ``chrome``, ``chromium``,
    ``edge``, ``safari``, ``opera``) resolved through ``webbrowser.get``.
    ``webbrowser`` itself is imported lazily so headless/locked-down
    environments never break the import of this module.
    """
    if _browser_disabled():
        return False
    try:
        import webbrowser
    except ImportError:
        return False
    name = str(browser or "").strip().lower()
    try:
        if not name:
            return bool(webbrowser.open(url, new=2, autoraise=True))
        controller = _resolve_browser(webbrowser, name)
        if controller is None:
            return False
        return bool(controller.open(url, new=2, autoraise=True))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Server construction
# ---------------------------------------------------------------------------

def _missing_web_message(component: str, exc: Optional[BaseException] = None) -> str:
    """Friendly error shown when the optional web stack is unavailable."""
    reason = " ({0})".format(exc) if exc else ""
    return "\n".join(
        [
            "The desktop edition needs the optional web stack -- {0} is not "
            "available in this Python environment{1}.".format(component, reason),
            "",
            'Install it with:   pip install "obscuralens[web]"',
            "or download the bundled ObscuraLens Desktop executable from the",
            "releases page, which ships the web server inside the binary:",
            "  https://github.com/AceGuru-mjh/obscuralens/releases",
        ]
    )


def build_server(host: str, port: int) -> Tuple[Optional[Any], str]:
    """
    Build the uvicorn server for the ObscuraLens web app.

    Returns ``(server, "")`` on success -- the server is a
    ``uvicorn.Server`` configured for ``host:port`` with a quiet log level,
    started later by :func:`launch` on a daemon thread.  On failure
    returns ``(None, friendly_message)``: a missing FastAPI/uvicorn gets a
    ``pip install "obscuralens[web]"`` hint, and any other construction
    error is reported without leaking a traceback.  FastAPI and uvicorn
    are imported *inside* this function, so importing the launcher never
    requires the web extra.
    """
    try:
        from ..web import create_app
    except ImportError as exc:
        return None, _missing_web_message("the ObscuraLens web app", exc)

    try:
        import uvicorn
    except ImportError as exc:
        return None, _missing_web_message("uvicorn", exc)

    try:
        app = create_app()
    except ImportError as exc:
        return None, _missing_web_message("FastAPI", exc)
    except Exception as exc:
        return None, "failed to build the ObscuraLens web app: {0}".format(exc)

    try:
        config = uvicorn.Config(
            app,
            host=str(host),
            port=int(port),
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
    except Exception as exc:
        return None, "failed to configure the web server: {0}".format(exc)
    return server, ""


# ---------------------------------------------------------------------------
# Small runtime helpers
# ---------------------------------------------------------------------------

def _print(message: str) -> None:
    """print() that survives closed pipes (frozen executables, redirects)."""
    with contextlib.suppress(OSError, ValueError):
        print(message, flush=True)


def _safe_open_browser(url: str, browser: Optional[str]) -> None:
    """Browser opener used from timer threads; never raises."""
    with contextlib.suppress(Exception):
        open_browser(url, browser)


def _run_server(server: Any) -> None:
    """Target of the server thread; a crashed server is reported, not fatal."""
    try:
        server.run()
    except Exception as exc:  # pragma: no cover - uvicorn is quite stable
        _print(render_splash("web-server", "server thread crashed: {0}".format(exc)))


def _shutdown_server(server: Any, thread: Optional[threading.Thread]) -> None:
    """Ask uvicorn to exit and wait for the thread to finish."""
    with contextlib.suppress(Exception):  # pragma: no cover - defensive
        server.should_exit = True
    if thread is not None:
        with contextlib.suppress(Exception):
            if thread.is_alive():
                thread.join(timeout=SHUTDOWN_JOIN_TIMEOUT)


# ---------------------------------------------------------------------------
# The launch sequence
# ---------------------------------------------------------------------------

def launch(options: Optional[LaunchOptions] = None) -> int:
    """
    Run the desktop app until ``Ctrl+C``; returns a process exit code.

    ``0`` on a clean shutdown *and* when another instance is already
    running (that case prints the running instance's URL); ``1`` when no
    port is free or the web stack is unavailable.  Never raises.
    """
    opts = options if options is not None else LaunchOptions()
    _print(render_banner())

    # -- single instance -------------------------------------------------
    lock: Optional[InstanceLock] = None
    if opts.single_instance:
        lock = InstanceLock()
        if not lock.acquire():
            running_url = lock_url(lock.path) or "http://{0}:{1}".format(
                opts.host, opts.port
            )
            _print(render_splash("init", "another instance is already running"))
            _print("{0} is already running: {1}".format(DESKTOP_NAME, running_url))
            _print("Close that window (or press Ctrl+C in it) before starting a new one.")
            return EXIT_OK

    # -- port selection ---------------------------------------------------
    port = find_free_port(opts.host, opts.port, _port_attempts(opts))
    if port is None:
        _print(
            "No free port found for {0} in the range starting at {1}; "
            "close the application using it or pass --port.".format(opts.host, opts.port)
        )
        if lock is not None:
            lock.release()
        return EXIT_FAILURE
    base_url = "http://{0}:{1}".format(opts.host, port)
    if lock is not None:
        lock.write_url(base_url)

    # -- staged splash -----------------------------------------------------
    for line in startup_sequence():
        _print(line)

    # -- server -------------------------------------------------------------
    server, error = build_server(opts.host, port)
    if server is None:
        _print(error)
        if lock is not None:
            lock.release()
        return EXIT_FAILURE

    thread: Optional[threading.Thread] = None
    try:
        thread = threading.Thread(
            target=_run_server, args=(server,), name="obscuralens-desktop-web", daemon=True
        )
        thread.start()
    except Exception as exc:  # pragma: no cover - thread creation rarely fails
        _print("could not start the server thread: {0}".format(exc))
        if lock is not None:
            lock.release()
        return EXIT_FAILURE

    # -- readiness + browser -------------------------------------------------
    if wait_until_ready(opts.host, port, timeout=opts.timeout_ready):
        _print(render_splash("web-server", "ready at {0}".format(base_url)))
    else:
        _print(render_splash("web-server", "no answer from the readiness probe yet"))
    if not opts.no_browser:
        try:
            timer = threading.Timer(
                max(0.0, float(opts.open_delay)),
                _safe_open_browser,
                args=(base_url + "/", opts.browser),
            )
            timer.daemon = True
            timer.start()
        except Exception:  # pragma: no cover - timer creation rarely fails
            _safe_open_browser(base_url + "/", opts.browser)

    _print("Listening on {0}".format(base_url))
    _print("The web UI is local-only; press Ctrl+C here to stop {0}.".format(DESKTOP_NAME))

    # -- block until Ctrl+C ---------------------------------------------------
    exit_code = EXIT_OK
    stop_event = threading.Event()
    try:
        while not stop_event.wait(0.5):
            pass
    except KeyboardInterrupt:
        _print(render_splash("web-server", "shutting down (Ctrl+C)"))
    except Exception as exc:  # pragma: no cover - defensive
        _print("unexpected error while running: {0}".format(exc))
        exit_code = EXIT_FAILURE
    finally:
        _shutdown_server(server, thread)
        if lock is not None:
            lock.release()
    _print(render_splash("web-server", "stopped"))
    return exit_code


# ---------------------------------------------------------------------------
# Command line interface
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Argument parser for the ``obscuralens-desktop`` console script."""
    parser = argparse.ArgumentParser(
        prog="obscuralens-desktop",
        description=(
            "ObscuraLens Desktop (beta): start the local web UI in a browser "
            "window and keep it running until Ctrl+C."
        ),
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="interface to bind (default: loopback only)",
    )
    parser.add_argument(
        "--port", type=int, default=8000,
        help="preferred TCP port (default: 8000; the first free port up to 8020 is used)",
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="never open a browser window automatically",
    )
    parser.add_argument(
        "--browser", default=None, metavar="NAME",
        help="browser to open: firefox, chrome, chromium, edge, safari or opera",
    )
    parser.add_argument(
        "--channel", default=None, metavar="NAME",
        help="release channel to report/check (stable, beta or nightly; default: beta)",
    )
    parser.add_argument(
        "--version", action="store_true",
        help="print the desktop version and exit",
    )
    parser.add_argument(
        "--diagnostics", action="store_true",
        help="print a full diagnostics report and exit",
    )
    parser.add_argument(
        "--check-update", action="store_true",
        dest="check_update",
        help="check GitHub for a newer release and exit",
    )
    return parser


def _print_version() -> None:
    from .branding import desktop_version

    channel = default_channel().name
    _print("{0} v{1} ({2} channel)".format(DESKTOP_NAME, desktop_version(), channel))


def _run_diagnostics() -> int:
    """Print the diagnostics report (import kept lazy; module stays light)."""
    from .diagnostics import diagnostics_report

    _print(diagnostics_report(check_network=False))
    return EXIT_OK


def _run_update_check(channel: Optional[str]) -> int:
    """Print an update notice; informational, so always exit 0."""
    checker = UpdateChecker(channel=channel)
    info = checker.check_quiet()
    if info is None:
        _print(
            "Could not check for updates: {0}".format(
                checker.last_error or "the update service is unreachable"
            )
        )
        return EXIT_OK
    _print(checker.format_notice(info))
    _print(checker.announcement(info))
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI entry point for ``obscuralens-desktop`` (returns an exit code).

    ``--version``, ``--diagnostics`` and ``--check-update`` are handled
    inline; anything else is forwarded to :func:`launch`.  The console
    script wrapper turns the return value into the process exit status via
    ``sys.exit``.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        _print_version()
        return EXIT_OK
    if args.diagnostics:
        return _run_diagnostics()
    if args.check_update:
        return _run_update_check(args.channel)

    options = LaunchOptions(
        host=args.host,
        port=args.port,
        no_browser=args.no_browser,
        channel=args.channel,
        browser=args.browser,
    )
    return launch(options)


__all__ = [
    "EXIT_FAILURE",
    "EXIT_OK",
    "LaunchOptions",
    "NO_BROWSER_ENV",
    "READY_PATH",
    "SHUTDOWN_JOIN_TIMEOUT",
    "build_server",
    "find_free_port",
    "launch",
    "main",
    "open_browser",
    "port_open",
    "wait_until_ready",
]
