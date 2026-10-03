"""
Release-channel registry for the ObscuraLens desktop editions.

The desktop program publishes three channels:

* ``stable``  -- tags like ``v5.1.0``; regular GitHub releases.  What most
  users should run.
* ``beta``    -- tags like ``v5.1.0-beta.1``; published as GitHub
  *pre-releases*.  The downloadable desktop executable is built from this
  channel by the ``desktop-beta.yml`` workflow (matrix: ``win-x64`` exe,
  ``linux-x64`` and ``macos-arm64`` binaries).
* ``nightly`` -- the rolling ``nightly`` tag, rebuilt every night from
  ``main`` by the ``desktop-nightly.yml`` workflow.

This module is the single source of truth for how GitHub API URLs, release
asset file names and the current display tag are derived, so the updater,
the launcher and the diagnostics view always agree.

The module is import-light (standard library only, plus the constant block
of ``obscuralens/__init__.py``): it can be imported by the plain CI test
job where the optional web extra is not installed, and importing it never
touches the network or the filesystem.
"""

import os
import platform
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .. import __desktop_channel__ as _PACKAGE_CHANNEL
from .. import __version__

#: GitHub repository that hosts ObscuraLens releases (owner/name).
DEFAULT_REPO = "AceGuru-mjh/obscuralens"

#: Environment variable overriding the repository slug (useful for forks).
REPO_SLUG_ENV = "OBSCURALENS_REPO_SLUG"

#: Environment variable overriding the display tag of this build.
DESKTOP_TAG_ENV = "OBSCURALENS_DESKTOP_TAG"

#: Stem used for every packaged release asset (``ObscuraLens-<ver>-<plat>``).
ASSET_STEM = "ObscuraLens"

#: Asset suffix per packaged platform key.  Platforms that are not in this
#: map have no downloadable binary; :func:`asset_name` returns ``None`` for
#: them so callers can fall back to the plain ``pip`` installation.
PLATFORM_ASSET_SUFFIXES: Dict[str, str] = {
    "win-x64": ".exe",
    "linux-x64": "",
    "macos-arm64": "",
}


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

@dataclass
class PlatformInfo:
    """Where this build is running, as far as packaging is concerned."""

    #: ``sys.platform`` value (``win32`` / ``linux`` / ``darwin`` ...).
    system: str
    #: ``platform.machine()`` value, lower-cased (``x86_64`` / ``arm64`` ...).
    machine: str
    #: Operating-system release string (kernel version, Windows build ...).
    release: str
    #: Normalised architecture label (``x64`` / ``arm64`` / ``x86`` ...).
    arch: str
    #: Packaging key such as ``win-x64`` or ``macos-arm64``.
    key: str
    #: True when running from a PyInstaller-frozen executable.
    is_frozen: bool
    #: Path of the running interpreter (or of the frozen executable).
    executable: str

    def summary(self) -> str:
        """One-line human-readable platform description."""
        frozen = ", frozen executable" if self.is_frozen else ""
        return "{0} {1} ({2}, {3}){4}".format(
            self.system or "unknown", self.release or "-", self.machine, self.arch, frozen
        )


def _arch_for(machine: str) -> str:
    """Map a ``platform.machine()`` string to a normalised arch label."""
    value = (machine or "").strip().lower()
    if value in ("x86_64", "amd64", "x64"):
        return "x64"
    if value in ("aarch64", "arm64"):
        return "arm64"
    if value in ("i386", "i486", "i586", "i686", "x86"):
        return "x86"
    return "unknown"


def _platform_key(system: str, machine: str) -> str:
    """Map ``sys.platform`` + machine to a packaging key."""
    arch = _arch_for(machine)
    if system.startswith("win"):
        return "win-{0}".format(arch)
    if system.startswith("linux"):
        return "linux-{0}".format(arch)
    if system == "darwin":
        return "macos-{0}".format(arch)
    return "unknown"


def detect_platform() -> PlatformInfo:
    """
    Detect the current platform (never raises, never touches the network).

    ``is_frozen`` uses ``getattr(sys, 'frozen', False)`` -- the attribute
    PyInstaller sets inside the desktop executable.
    """
    system = sys.platform or ""
    machine = (platform.machine() or "").strip().lower()
    try:
        release = platform.release() or ""
    except Exception:  # pragma: no cover - platform hooks can misbehave
        release = ""
    return PlatformInfo(
        system=system,
        machine=machine or "unknown",
        release=release,
        arch=_arch_for(machine),
        key=_platform_key(system, machine),
        is_frozen=bool(getattr(sys, "frozen", False)),
        executable=sys.executable or "",
    )


# ---------------------------------------------------------------------------
# Release channels
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReleaseChannel:
    """
    One release channel of the desktop edition.

    Attributes:
        name: lowercase channel name (``stable`` / ``beta`` / ``nightly``).
        tag_prefix: tag pattern used by this channel.  ``stable`` uses the
            literal prefix ``v``, ``beta`` the glob ``v*-beta*`` and
            ``nightly`` the literal tag ``nightly``.
        prerelease: whether GitHub marks this channel's releases as
            pre-releases.
        feed_url: GitHub API URL the updater polls for the newest release.
        notes_url: human-facing release-notes page.
    """

    name: str
    tag_prefix: str
    prerelease: bool
    feed_url: str
    notes_url: str

    def asset_for(self, platform_key: Any, version: Optional[str] = None) -> Optional[str]:
        """
        Asset file name for *platform_key* in this channel.

        ``version`` defaults to the running package version.  Returns
        ``None`` when the platform has no packaged binary.
        """
        return asset_name(version or __version__, platform_key)

    def __str__(self) -> str:
        return "{0} channel (tags: {1})".format(self.name, self.tag_prefix)


#: Declarative recipe per channel; :func:`_build_channel` turns these into
#: :class:`ReleaseChannel` instances with fully-qualified URLs.
_CHANNEL_SPECS: Dict[str, Dict[str, Any]] = {
    "stable": {
        "tag_prefix": "v",
        "prerelease": False,
        # GitHub's /releases/latest endpoint points at the newest
        # non-prerelease -- exactly what the stable channel wants.
        "feed": "latest",
    },
    "beta": {
        "tag_prefix": "v*-beta*",
        "prerelease": True,
        # /releases/latest ignores pre-releases, so the beta channel has to
        # scan the release list instead (see updater.latest_release).
        "feed": "list",
    },
    "nightly": {
        "tag_prefix": "nightly",
        "prerelease": True,
        # The rolling nightly tag always has exactly one attached release.
        "feed": "tags:nightly",
    },
}


def current_repo_slug() -> str:
    """
    Repository slug to talk to (``owner/name``).

    Honours ``OBSCURALENS_REPO_SLUG``; the value may be a bare slug, a
    ``https://github.com/<slug>`` URL or a ``*.git`` clone URL.  Invalid
    overrides are ignored in favour of :data:`DEFAULT_REPO`.
    """
    raw = os.environ.get(REPO_SLUG_ENV, "").strip()
    if raw:
        slug = raw.strip("/")
        if slug.startswith("https://github.com/"):
            slug = slug[len("https://github.com/"):]
        elif slug.startswith("github.com/"):
            slug = slug[len("github.com/"):]
        if slug.endswith(".git"):
            slug = slug[: -len(".git")]
        slug = slug.strip("/")
        if slug and "/" in slug and " " not in slug:
            return slug
    return DEFAULT_REPO


def github_release_api_url(repo_slug: Optional[str] = None,
                           tag: Optional[str] = None) -> str:
    """
    GitHub *releases* API URL for a repository.

    With ``tag`` the URL addresses ``releases/tags/<tag>``; without it the
    ``releases/latest`` endpoint is returned (which never resolves to a
    pre-release -- see :func:`github_releases_list_url` for the beta flow).
    """
    slug = repo_slug or current_repo_slug()
    base = "https://api.github.com/repos/{0}/releases".format(slug)
    if tag:
        return "{0}/tags/{1}".format(base, tag)
    return "{0}/latest".format(base)


def github_releases_list_url(repo_slug: Optional[str] = None, per_page: int = 20) -> str:
    """GitHub *release list* API URL (the feed the beta channel scans)."""
    slug = repo_slug or current_repo_slug()
    per_page = max(1, min(100, int(per_page)))
    return "https://api.github.com/repos/{0}/releases?per_page={1}".format(slug, per_page)


def _build_channel(name: str, repo: Optional[str]) -> ReleaseChannel:
    spec = _CHANNEL_SPECS[name]
    feed = str(spec["feed"])
    if feed == "latest":
        feed_url = github_release_api_url(repo)
    elif feed == "list":
        feed_url = github_releases_list_url(repo)
    else:  # "tags:<tag>"
        feed_url = github_release_api_url(repo, tag=feed.split(":", 1)[1])
    return ReleaseChannel(
        name=name,
        tag_prefix=str(spec["tag_prefix"]),
        prerelease=bool(spec["prerelease"]),
        feed_url=feed_url,
        notes_url="https://github.com/{0}/releases".format(repo or current_repo_slug()),
    )


#: Canonical channel registry, keyed by lowercase channel name.  The URLs
#: inside point at :data:`DEFAULT_REPO`; :func:`get_channel` rebuilds them
#: with the currently configured repository slug.
CHANNELS: Dict[str, ReleaseChannel] = {
    name: _build_channel(name, DEFAULT_REPO) for name in ("stable", "beta", "nightly")
}


def get_channel(name: Optional[str] = None) -> ReleaseChannel:
    """
    Look up a release channel by name (case-insensitive).

    ``None`` selects the channel this build belongs to
    (:func:`default_channel`).  Unknown names deliberately fall back to the
    **beta** channel instead of raising ``KeyError``: the desktop beta is
    the flagship distribution, every CLI flag that accepts a channel name
    stays usable, and a typo degrades to the safest *supported* pre-release
    channel rather than crashing the launcher.
    """
    slug = current_repo_slug()
    if name is None:
        return _build_channel(default_channel().name, slug)
    key = str(name).strip().lower()
    if key in _CHANNEL_SPECS:
        return _build_channel(key, slug)
    return _build_channel("beta", slug)


def default_channel() -> ReleaseChannel:
    """The channel declared by the package (``obscuralens.__desktop_channel__``)."""
    key = str(_PACKAGE_CHANNEL or "beta").strip().lower()
    if key not in _CHANNEL_SPECS:
        key = "beta"
    return _build_channel(key, current_repo_slug())


def channel_for_tag(tag: Any) -> Optional[ReleaseChannel]:
    """
    Which channel a git tag belongs to.

    Rules: ``v5.1.0`` -> stable; ``v5.1.0-beta.1`` -> beta; ``nightly`` or
    ``nightly-<date>`` -> nightly; anything else (``v5.1.0-rc.1``,
    ``release-1``, ``""``) -> ``None``.  A leading ``v`` is optional.
    """
    value = str(tag or "").strip().lower()
    if not value:
        return None
    if value == "nightly" or value.startswith("nightly-"):
        return get_channel("nightly")
    if "-nightly" in value:
        return get_channel("nightly")
    if value.startswith("v") or value[:1].isdigit():
        if "-beta" in value:
            return get_channel("beta")
        rest = value[1:] if value.startswith("v") else value
        if rest and all(ch.isdigit() or ch == "." for ch in rest):
            return get_channel("stable")
    return None


# ---------------------------------------------------------------------------
# Assets and tags
# ---------------------------------------------------------------------------

def asset_name(version: Any, platform_key: Any) -> Optional[str]:
    """
    Release asset file name for a version + platform.

    >>> asset_name("5.1.0-beta.1", "win-x64")
    'ObscuraLens-5.1.0-beta.1-win-x64.exe'

    ``platform_key`` may be a packaging key (``win-x64`` ...) or a
    :class:`PlatformInfo` instance.  Windows assets carry a ``.exe``
    suffix; the linux/macos binaries do not.  Unsupported or unknown
    platforms return ``None``, and so do empty versions.
    """
    if isinstance(platform_key, PlatformInfo):
        platform_key = platform_key.key
    key = str(platform_key or "").strip().lower()
    if key not in PLATFORM_ASSET_SUFFIXES:
        return None
    clean = str(version or "").strip().lstrip("vV")
    if not clean:
        return None
    return "{0}-{1}-{2}{3}".format(ASSET_STEM, clean, key, PLATFORM_ASSET_SUFFIXES[key])


def download_url(tag: Any, version: Any, platform_key: Any,
                 repo_slug: Optional[str] = None) -> str:
    """
    Full ``https`` URL of a release asset, or ``""`` when there is none.

    >>> download_url("v5.1.0-beta.1", "5.1.0-beta.1", "win-x64")
    'https://github.com/AceGuru-mjh/obscuralens/releases/download/v5.1.0-beta.1/ObscuraLens-5.1.0-beta.1-win-x64.exe'
    """
    name = asset_name(version, platform_key)
    clean_tag = str(tag or "").strip()
    if not name or not clean_tag:
        return ""
    slug = repo_slug or current_repo_slug()
    return "https://github.com/{0}/releases/download/{1}/{2}".format(slug, clean_tag, name)


def current_tag(channel: Optional[str] = None) -> str:
    """
    Display tag of *this* build (``v5.1.0-beta.1`` style).

    The ``OBSCURALENS_DESKTOP_TAG`` environment variable wins when set (the
    release workflows inject the real tag into the build).  Otherwise the
    tag is derived from the package version and channel: beta appends the
    default ``-beta.1`` suffix, nightly reports the rolling ``nightly``
    tag and stable reports ``v<version>``.
    """
    override = os.environ.get(DESKTOP_TAG_ENV, "").strip()
    if override:
        return override
    chan = get_channel(channel)
    if chan.name == "nightly":
        return "nightly"
    if chan.name == "beta":
        return "v{0}-beta.1".format(__version__)
    return "v{0}".format(__version__)


def current_channel_info() -> Dict[str, Any]:
    """
    Dictionary summarising the channel this build belongs to.

    Keys: ``name``, ``tag_prefix``, ``prerelease``, ``feed_url``,
    ``notes_url``, ``current_tag``, ``repo``, ``package_channel``.
    """
    chan = default_channel()
    return {
        "name": chan.name,
        "tag_prefix": chan.tag_prefix,
        "prerelease": chan.prerelease,
        "feed_url": chan.feed_url,
        "notes_url": chan.notes_url,
        "current_tag": current_tag(),
        "repo": current_repo_slug(),
        "package_channel": _PACKAGE_CHANNEL,
    }


__all__ = [
    "ASSET_STEM",
    "CHANNELS",
    "DEFAULT_REPO",
    "DESKTOP_TAG_ENV",
    "PlatformInfo",
    "PLATFORM_ASSET_SUFFIXES",
    "ReleaseChannel",
    "REPO_SLUG_ENV",
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
]
