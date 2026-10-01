"""
Terminal UI for ObscuraLens.

An optional, full-screen interactive console built on Textual. It offers a
single form: type a target, choose a kind (or let auto-detection pick one), and
either run a per-kind lookup or a bounded investigation. Results are rendered
with the same field formatting as the rest of the project and appended to a
scrollable log.

Textual is an optional dependency, so it is imported lazily and importing this
module never requires it. Install the extra to use the UI::

    pip install "obscuralens[tui]"

The entry points are :func:`run_tui` (used by a future ``tui`` subcommand) and
its alias :func:`main`.
"""

from typing import Any, Dict, List, Optional

from .investigate import detect_kind, investigate
from .trackers import (
    DomainTracker,
    EmailTracker,
    IPTracker,
    PhoneTracker,
    UsernameTracker,
)
from .utils import render_table
from .utils.formatting import rows_from_fields

KINDS = ('auto', 'ip', 'phone', 'username', 'email', 'domain')

_INSTALL_HINT = (
    'Textual is required for the ObscuraLens terminal UI. '
    'Install the optional extra with: pip install "obscuralens[tui]"'
)

_TRACKERS = {
    'ip': IPTracker,
    'phone': PhoneTracker,
    'username': UsernameTracker,
    'email': EmailTracker,
    'domain': DomainTracker,
}


# ---------------------------------------------------------------------------
# Pure helpers (no Textual import needed)
# ---------------------------------------------------------------------------

def _resolve_kind(kind: Optional[str], target: str) -> Optional[str]:
    """Return an explicit kind, or auto-detect it from the target."""
    if kind in (None, '', 'auto'):
        return detect_kind(target)
    return kind


def _run_tracker(kind: str, target: str) -> Dict[str, Any]:
    """Run the tracker for ``kind`` against ``target``."""
    return _TRACKERS[kind]().track(target)


def _render_result(kind: str, result: Dict[str, Any]) -> str:
    """Render one tracker result as a text table for the log."""
    lines: List[str] = []
    info = result.get('info') or {}

    if kind == 'username':
        found = [r for r in result.get('results', [])
                 if r.get('status') == 'found']
        if found:
            lines.append(render_table(
                [[r.get('platform', ''), r.get('url', ''),
                  r.get('confidence', '')] for r in found],
                headers=['Platform', 'URL', 'Confidence']))

    rows = rows_from_fields(info)
    if rows:
        lines.append(render_table(rows, headers=['Field', 'Value']))

    failed = result.get('sources_failed')
    if failed:
        lines.append(f"Unavailable: {', '.join(failed)}")

    return '\n'.join(lines) or '(no data)'


def _render_investigation(payload: Dict[str, Any]) -> str:
    """Render an investigation payload as a text report for the log."""
    lines = [
        f"Target: {payload.get('target')} "
        f"(kind: {payload.get('kind')})",
    ]
    for kind in payload.get('order', []):
        result = payload.get('results', {}).get(kind)
        if result:
            lines.append(f"--- {kind.upper()} ---")
            lines.append(_render_result(kind, result))

    entities = payload.get('entities') or []
    if entities:
        lines.append('--- ENTITIES ---')
        lines.append(render_table(
            [[e.get('type', ''), e.get('value', ''), e.get('role', '')]
             for e in entities],
            headers=['Type', 'Value', 'Role']))

    errors = payload.get('errors') or []
    if errors:
        lines.append(f"Errors: {'; '.join(errors)}")

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Textual application
# ---------------------------------------------------------------------------

def create_app_class():
    """
    Build and return the Textual ``App`` subclass.

    Textual is imported here so that merely importing :mod:`obscuralens.tui`
    does not require the optional dependency. Raises :class:`ImportError` with
    install instructions when Textual is unavailable.
    """
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Horizontal, Vertical
        from textual.widgets import (
            Button,
            Footer,
            Header,
            Input,
            RichLog,
            Select,
        )
    except ImportError as exc:  # pragma: no cover - exercised without textual
        raise ImportError(_INSTALL_HINT) from exc

    class ObscuraLensTUI(App):
        """Full-screen ObscuraLens lookup console."""

        TITLE = 'ObscuraLens'
        SUB_TITLE = 'OSINT terminal UI'
        CSS = """
        Screen { layout: vertical; }
        #form { height: auto; padding: 1 2; }
        #target { width: 100%; }
        #kind { margin-top: 1; }
        #buttons { height: auto; margin-top: 1; }
        #buttons Button { margin-right: 1; }
        #log { border: round $primary; height: 1fr; }
        """
        BINDINGS = [
            ('ctrl+q', 'quit', 'Quit'),
            ('ctrl+l', 'clear', 'Clear'),
        ]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical(id='form'):
                yield Input(
                    placeholder='Target: IP, phone, username, email or domain',
                    id='target',
                )
                yield Select(
                    [(kind.title(), kind) for kind in KINDS],
                    value='auto',
                    allow_blank=False,
                    id='kind',
                )
                with Horizontal(id='buttons'):
                    yield Button('Look up', id='lookup', variant='primary')
                    yield Button('Investigate', id='investigate')
                    yield Button('Clear', id='clear')
            yield RichLog(id='log', markup=False, highlight=False, wrap=True)
            yield Footer()

        # -- widget access ---------------------------------------------------

        def _log(self) -> RichLog:
            return self.query_one('#log', RichLog)

        def _target(self) -> str:
            return self.query_one('#target', Input).value.strip()

        def _kind(self) -> str:
            value = self.query_one('#kind', Select).value
            if value is Select.BLANK:  # pragma: no cover - allow_blank is False
                return 'auto'
            return str(value)

        def _write(self, text: str) -> None:
            self._log().write(text)

        # -- actions ---------------------------------------------------------

        def action_clear(self) -> None:
            self.query_one('#target', Input).value = ''
            self._log().clear()

        def on_button_pressed(self, event: 'Button.Pressed') -> None:
            button_id = event.button.id or ''
            if button_id == 'clear':
                self.action_clear()
            elif button_id == 'lookup':
                self._do_lookup()
            elif button_id == 'investigate':
                self._do_investigate()

        # -- command handlers ------------------------------------------------

        def _do_lookup(self) -> None:
            target = self._target()
            if not target:
                self._write('Enter a target first.')
                return
            kind = _resolve_kind(self._kind(), target)
            if kind is None:
                self._write(f'Could not determine target type: {target!r}')
                return
            self._write(f'> {kind}: {target}')
            try:
                result = _run_tracker(kind, target)
                self._write(_render_result(kind, result))
            except Exception as exc:  # never crash the UI on a lookup
                self._write(f'Error: {type(exc).__name__}: {exc}')

        def _do_investigate(self) -> None:
            target = self._target()
            if not target:
                self._write('Enter a target first.')
                return
            self._write(f'> investigate: {target}')
            try:
                payload = investigate(target, pivot=False)
                self._write(_render_investigation(payload))
            except Exception as exc:  # never crash the UI on an investigation
                self._write(f'Error: {type(exc).__name__}: {exc}')

    return ObscuraLensTUI


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run_tui() -> None:
    """Launch the interactive terminal UI."""
    app_class = create_app_class()
    app_class().run()


def main() -> None:
    """Alias for :func:`run_tui` for use as a console entry point."""
    run_tui()


if __name__ == '__main__':  # pragma: no cover
    main()
