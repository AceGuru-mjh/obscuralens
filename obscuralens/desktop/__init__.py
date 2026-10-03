"""
ObscuraLens Desktop -- the beta desktop runtime.

This package turns the optional ObscuraLens web UI into a self-contained
*desktop application*: one console command (``obscuralens-desktop``) that

* refuses to start a second copy while one is already running
  (:mod:`obscuralens.desktop.singleinstance`),
* picks a free local port and boots the FastAPI app on a background
  uvicorn thread (:mod:`obscuralens.desktop.launcher`),
* opens the web UI in the system browser and prints staged splash lines
  (:mod:`obscuralens.desktop.branding`),
* knows which release channel it belongs to and where new releases are
  published (:mod:`obscuralens.desktop.channel`),
* checks GitHub for newer desktop builds (:mod:`obscuralens.desktop.updater`),
* and can print a full environment report for bug reports
  (:mod:`obscuralens.desktop.diagnostics`).

The downloadable executable published by the ``desktop-beta.yml`` workflow
(``ObscuraLens-<version>-win-x64.exe`` and friends) bundles the optional
``web`` extra; in a plain checkout the launcher degrades gracefully and
tells the user to ``pip install "obscuralens[web]"``.

Every module here is import-light (standard library only at import time;
FastAPI/uvicorn/webbrowser are imported inside function bodies behind
``ImportError`` guards), so ``import obscuralens.desktop`` works in the
plain CI test job without the web extra.
"""

from .. import __desktop_channel__, __version__
from .branding import (
    BETA_ASCII_ART,
    BETA_DISCLAIMER,
    ChannelBadge,
    DESKTOP_CHANNEL,
    DESKTOP_NAME,
    about_text,
    desktop_version,
    is_beta,
    is_nightly,
    render_banner,
    render_splash,
    startup_sequence,
    update_notice,
)
from .channel import (
    CHANNELS,
    DEFAULT_REPO,
    PlatformInfo,
    ReleaseChannel,
    asset_name,
    channel_for_tag,
    current_channel_info,
    current_repo_slug,
    current_tag,
    default_channel,
    detect_platform,
    download_url,
    get_channel,
    github_release_api_url,
    github_releases_list_url,
)
from .diagnostics import (
    DependencyStatus,
    collect_diagnostics,
    diagnostics_report,
    render_diagnostics,
)
from .launcher import LaunchOptions, launch
from .singleinstance import InstanceLock, lock_info, lock_url
from .updater import (
    UpdateChecker,
    UpdateInfo,
    check_for_updates,
    compare_versions,
    parse_version,
)

__all__ = [
    # identity / branding
    "BETA_ASCII_ART",
    "BETA_DISCLAIMER",
    "ChannelBadge",
    "DESKTOP_CHANNEL",
    "DESKTOP_NAME",
    "__desktop_channel__",
    "__version__",
    "about_text",
    "desktop_version",
    "is_beta",
    "is_nightly",
    "render_banner",
    "render_splash",
    "startup_sequence",
    "update_notice",
    # channels
    "CHANNELS",
    "DEFAULT_REPO",
    "PlatformInfo",
    "ReleaseChannel",
    "asset_name",
    "channel_for_tag",
    "current_channel_info",
    "current_repo_slug",
    "current_tag",
    "default_channel",
    "detect_platform",
    "download_url",
    "get_channel",
    "github_release_api_url",
    "github_releases_list_url",
    # updates
    "UpdateChecker",
    "UpdateInfo",
    "check_for_updates",
    "compare_versions",
    "parse_version",
    # launcher
    "LaunchOptions",
    "launch",
    "main",
    # single instance
    "InstanceLock",
    "lock_info",
    "lock_url",
    # diagnostics
    "DependencyStatus",
    "collect_diagnostics",
    "diagnostics_report",
    "render_diagnostics",
]


def __getattr__(name: str):
    """
    Lazy attribute access (PEP 562).

    ``main`` -- the ``obscuralens-desktop`` CLI entry point -- is imported
    on first access so that ``import obscuralens.desktop`` stays minimal
    for library users who only want branding/updater helpers.
    """
    if name == "main":
        from .launcher import main as _main

        return _main
    raise AttributeError("module {0!r} has no attribute {1!r}".format(__name__, name))
