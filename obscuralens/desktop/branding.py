r"""
Branding and console chrome for the ObscuraLens Desktop beta.

Everything the desktop launcher prints -- the startup banner, staged
splash lines, the About text, update notices and channel badges -- lives
here so the wording stays consistent between ``obscuralens-desktop``, the
``obscuralens desktop`` docs and the diagnostics view.

Two constraints shape this module:

* **Pure ASCII.**  The desktop executable must render on Windows ``cmd.exe`
  with a legacy code page, so every rendered string sticks to characters
  below ``U+0080`` and the box drawing uses ``+ - |`` like the ASCII
  fallbacks in :mod:`obscuralens.utils.helpers`.
* **Import-light.**  Only the standard library and the light sibling module
  :mod:`obscuralens.desktop.channel` are imported at module level; colours
  are applied by small local helpers instead of pulling in the full
  ``utils`` stack (which imports ``tabulate`` and reconfigures console
  streams at import time).
"""

import os
import platform
import sys
import textwrap
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Iterable, Iterator, Optional, Tuple

from .. import __desktop_channel__, __version__
from .channel import detect_platform

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from .updater import UpdateInfo

#: Channel this build reports (mirrors ``obscuralens.__desktop_channel__``).
DESKTOP_CHANNEL = __desktop_channel__

#: Product name shown in banners, titles and update notices.
DESKTOP_NAME = "ObscuraLens Desktop"

#: Project homepage / release page.
HOMEPAGE = "https://github.com/AceGuru-mjh/obscuralens"

#: Figlet-style ASCII logo.  Pure ASCII, at most ~64 columns wide so it
#: fits the default 72-column banner box on a standard terminal.
BETA_ASCII_ART = r"""
   ________               __      ______
  / ____/ /_  ____  _____/ /_    /_  __/________ ______/ /__
 / / __/ __ \/ __ \/ ___/ __/_____/ / / ___/ __ `/ ___/ //_/
/ /_/ / / / / /_/ (__  ) /_/_____/ / / /  / /_/ / /__/ ,<
\____/_/ /_/\____/____/\__/     /_/ /_/   \__,_/\___/_/|_|
"""

#: Shown under the banner on every desktop launch.
BETA_DISCLAIMER = (
    "BETA PRE-RELEASE: the desktop edition is under active development and "
    "may be unstable or change without notice. Investigations run locally on "
    "your machine; results depend on the public data sources and API keys you "
    "configure. Report problems at " + HOMEPAGE + "/issues."
)

#: Stages the launcher walks through on startup, in order.
DEFAULT_STAGES: Tuple[str, ...] = (
    "init",
    "config",
    "data-packs",
    "web-server",
    "browser",
)

#: Default one-line message per startup stage.
_STAGE_MESSAGES: Dict[str, str] = {
    "init": "loading the desktop runtime",
    "config": "reading configuration and API keys",
    "data-packs": "checking offline data packs",
    "web-server": "starting the local web server",
    "browser": "opening the web UI",
}


# ---------------------------------------------------------------------------
# Colour support (small, local, optional)
# ---------------------------------------------------------------------------

_ANSI_TAGS: Dict[str, str] = {
    "red": "\033[1;31m",
    "green": "\033[1;32m",
    "yellow": "\033[1;33m",
    "blue": "\033[1;34m",
    "magenta": "\033[1;35m",
    "cyan": "\033[1;36m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _colors_enabled() -> bool:
    """ANSI colours only on a TTY and when NO_COLOR is unset."""
    if os.environ.get("NO_COLOR") or os.environ.get("OBSCURALENS_NO_COLOR"):
        return False
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):  # pragma: no cover - exotic streams
        return False


def colorize(text: str, tag: str) -> str:
    """Wrap *text* in the ANSI sequence for *tag* (no-op when colours off)."""
    if not _colors_enabled():
        return text
    code = _ANSI_TAGS.get(tag, "")
    if not code:
        return text
    return code + text + _ANSI_TAGS["reset"]


# ---------------------------------------------------------------------------
# Channel badge
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChannelBadge:
    """
    Small bracketed channel label used in banners and update notices.

    ``color_tag`` names an ANSI colour from the local palette above; it is
    only applied when :meth:`render` is called with ``colored=True`` and
    colours are enabled in this terminal.
    """

    label: str
    color_tag: str = "yellow"
    stable: bool = False

    def render(self, compact: bool = False, colored: bool = False) -> str:
        """Render the badge; ``compact`` drops the padding spaces."""
        text = "[{0}]".format(self.label.strip()) if compact \
            else "[ {0} ]".format(self.label.strip())
        if colored:
            return colorize(text, self.color_tag)
        return text


#: Badge per channel name; anything unknown is treated as beta-ish.
_BADGES: Dict[str, ChannelBadge] = {
    "stable": ChannelBadge("STABLE CHANNEL", "green", True),
    "beta": ChannelBadge("BETA CHANNEL", "yellow", False),
    "nightly": ChannelBadge("NIGHTLY CHANNEL", "magenta", False),
}


def badge_for_channel(name: Optional[str] = None) -> ChannelBadge:
    """Badge for a channel name (defaults to this build's channel)."""
    key = (name or channel_name() or "beta").strip().lower()
    if key not in _BADGES:
        key = "beta"
    return _BADGES[key]


# ---------------------------------------------------------------------------
# Version / channel helpers
# ---------------------------------------------------------------------------

def channel_name() -> str:
    """Lowercase name of the channel this build reports."""
    return str(DESKTOP_CHANNEL or "beta").strip().lower()


def desktop_version() -> str:
    """Version of the ObscuraLens package this desktop build ships."""
    return __version__


def is_beta() -> bool:
    """True when this build reports the beta channel."""
    return channel_name() == "beta"


def is_nightly() -> bool:
    """
    True when this build is a nightly.

    Nightlies are detected through the ``OBSCURALENS_NIGHTLY`` environment
    variable (set by the nightly workflow inside the executable) or a
    ``nightly`` channel value.
    """
    env = os.environ.get("OBSCURALENS_NIGHTLY", "").strip().lower()
    if env and env not in ("0", "false", "no", "off"):
        return True
    return channel_name() == "nightly"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _box(lines: Iterable[str], width: int) -> Tuple[str, ...]:
    """Wrap *lines* in a pure-ASCII ``+---+`` frame of exactly *width* columns."""
    inner = max(1, width - 2)
    bordered = ["+" + "-" * inner + "+"]
    for line in lines:
        clipped = str(line)[:inner]
        bordered.append("|" + clipped.ljust(inner) + "|")
    bordered.append("+" + "-" * inner + "+")
    return tuple(bordered)


def render_banner(width: int = 72) -> str:
    """
    Full startup banner: ASCII logo, version, channel badge and disclaimer.

    The banner is pure ASCII (safe for ``cmd.exe``), every line is exactly
    ``width`` columns wide when ``width`` can accommodate the logo, and the
    frame uses the ``+ - |`` characters consistent with the ASCII fallback
    box drawing in :mod:`obscuralens.utils.helpers`.
    """
    width = max(int(width), 40)
    art = [line.rstrip() for line in BETA_ASCII_ART.strip("\n").splitlines()]
    art = [line for line in art if line.strip()]
    art_width = max((len(line) for line in art), default=0)
    box_width = max(width, art_width + 6, 46)

    badge = badge_for_channel()
    content = []
    for line in art:
        content.append("  " + line)
    content.append("")
    content.append("  {0}  v{1}".format(DESKTOP_NAME, desktop_version()))
    content.append("  {0}".format(badge.render()))
    content.append("")
    for wrapped in textwrap.wrap(BETA_DISCLAIMER, max(20, box_width - 6)):
        content.append("  " + wrapped)
    return "\n".join(_box(content, box_width))


def render_splash(stage: str, message: str, width: int = 72) -> str:
    """
    One progress-styled startup line: ``[desktop] <stage> -> <message>``.

    Long lines are clipped to *width* columns so staged output stays aligned
    in narrow terminals.  Pure ASCII, no trailing newline.
    """
    line = "[desktop] {0} -> {1}".format(str(stage), str(message))
    limit = max(20, int(width))
    if len(line) > limit:
        line = line[: limit - 3] + "..."
    return line


def about_text() -> str:
    """
    Multi-line About block (version, channel, python, platform, license).

    Used by the docs, the ``--version`` output and the diagnostics view.
    """
    info = detect_platform()
    lines = [
        "{0} v{1}".format(DESKTOP_NAME, desktop_version()),
        "",
        "channel  : {0}".format(channel_name()),
        "python   : {0} {1}".format(
            platform.python_implementation(), platform.python_version()
        ),
        "platform : {0}".format(info.summary()),
        "binary   : {0}".format(info.executable or "unknown"),
        "frozen   : {0}".format("yes" if info.is_frozen else "no"),
        "home     : {0}".format(HOMEPAGE),
        "license  : MIT License -- see LICENSE in the repository",
        "",
        "All investigations run locally; nothing leaves this machine",
        "except requests to the public data sources you configure.",
    ]
    return "\n".join(lines)


def update_notice(info: Optional["UpdateInfo"]) -> str:
    """
    Friendly "update available" / "up to date" block for the terminal.

    Accepts an :class:`~obscuralens.desktop.updater.UpdateInfo` (or ``None``
    when the check could not reach the update service) and renders a boxed,
    pure-ASCII notice.  The updater types are only imported for typing, so
    this module stays import-light.
    """
    if info is None:
        return "\n".join(
            _box(
                [
                    "UPDATE CHECK UNAVAILABLE",
                    "",
                    "Could not reach the ObscuraLens release service.",
                    "Check your internet connection and try again with",
                    "  obscuralens-desktop --check-update",
                ],
                72,
            )
        )
    width = 72
    if not info.is_newer:
        body = [
            "UP TO DATE",
            "",
            "{0} v{1} is the newest {2}-channel build.".format(
                DESKTOP_NAME, info.current_version, info.channel
            ),
        ]
        if info.latest_tag:
            body.append("Latest published release: {0}".format(info.latest_tag))
        return "\n".join(_box(body, width))

    body = [
        "UPDATE AVAILABLE",
        "",
        "current : v{0} ({1} channel)".format(info.current_version, info.channel),
        "latest  : {0} (v{1}){2}".format(
            info.latest_version,
            info.latest_tag,
            " [pre-release]" if info.is_prerelease else "",
        ),
    ]
    if info.download_url:
        body.append("download: {0}".format(info.download_url))
    if info.release_url:
        body.append("release : {0}".format(info.release_url))
    if info.published_at:
        body.append("published: {0}".format(info.published_at))
    if info.notes_excerpt:
        body.append("")
        for wrapped in textwrap.wrap(info.notes_excerpt, width - 6):
            body.append("  " + wrapped)
    body.extend(
        [
            "",
            "Beta channel hint: you can switch back to the stable build at",
            "any time -- both channels read the same local database.",
        ]
    )
    return "\n".join(_box(body, width))


def startup_sequence(stages: Optional[Iterable[str]] = None,
                     messages: Optional[Dict[str, str]] = None,
                     width: int = 72) -> Iterator[str]:
    """
    Yield one :func:`render_splash` line per startup stage, in order.

    The default stages are ``init``, ``config``, ``data-packs``,
    ``web-server`` and ``browser``.  Custom stages and per-stage message
    overrides keep the generator usable from tests and from alternative
    front-ends (for example a future splash window).
    """
    overrides = messages or {}
    for stage in stages if stages is not None else DEFAULT_STAGES:
        message = overrides.get(stage) or _STAGE_MESSAGES.get(stage, "working")
        yield render_splash(stage, message, width=width)


__all__ = [
    "BETA_ASCII_ART",
    "BETA_DISCLAIMER",
    "ChannelBadge",
    "DEFAULT_STAGES",
    "DESKTOP_CHANNEL",
    "DESKTOP_NAME",
    "HOMEPAGE",
    "about_text",
    "badge_for_channel",
    "channel_name",
    "colorize",
    "desktop_version",
    "is_beta",
    "is_nightly",
    "render_banner",
    "render_splash",
    "startup_sequence",
    "update_notice",
]
