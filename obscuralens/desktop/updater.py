"""
GitHub-release update checker for the ObscuraLens desktop edition.

The desktop executable is distributed through GitHub releases (see
:mod:`obscuralens.desktop.channel`), so "checking for updates" means:

1. ask the GitHub releases API for the newest release of the channel this
   build belongs to,
2. compare its tag with the running package version using sane
   pre-release ordering rules,
3. pick the packaged asset that matches the current platform.

Robustness rules for this module:

* **It never raises.**  :meth:`UpdateChecker.check` returns ``None`` when
  the network is unreachable, the feed is malformed or anything else goes
  wrong; the reason is recorded in ``UpdateChecker.last_error``.
* **The fetch function is injectable.**  ``UpdateChecker(fetch=...)``
  accepts any ``callable(url, timeout) -> (status, text)``; the tests use
  canned GitHub API payloads and never touch the network.
* **Import-light.**  Only the standard library and the light sibling
  :mod:`obscuralens.desktop.channel` are imported at module level.

Version ordering rules
----------------------
``5.1.0-beta.1 < 5.1.0`` (pre-releases sort below the release they
anticipate), ``beta.2 > beta.1`` (numeric, not lexicographic, so
``beta.10 > beta.9``), ``rc.1 > beta.9`` (label rank: nightly < dev/alpha <
beta < rc) and bare ``nightly`` tags sort below every numbered version.
PEP 440 short forms are accepted: ``5.1.0b1`` == ``5.1.0-beta.1``.
"""

import json
import re
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import __version__
from .channel import (
    ASSET_STEM,
    ReleaseChannel,
    asset_name,
    channel_for_tag,
    current_repo_slug,
    detect_platform,
    get_channel,
    github_release_api_url,
    github_releases_list_url,
)

#: A fetch function maps ``(url, timeout)`` to ``(http_status, body_text)``.
FetchCallable = Callable[[str, float], Tuple[int, str]]

#: Cap on how many bytes of a release payload we read (GitHub release JSON
#: with a long body stays well below this; the cap just bounds memory when
#: a misbehaving proxy returns something huge).
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

#: Pre-release label ranking used by :func:`compare_versions`.  Lower rank
#: sorts earlier; unknown labels rank last among pre-releases.
_LABEL_ORDER: Dict[str, int] = {
    "nightly": 0,
    "dev": 1,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "c": 3,
}

#: PEP 440 short labels normalised to their long forms so ``5.1.0b1``
#: parses identically to ``5.1.0-beta.1``.
_NORMALIZED_LABELS: Dict[str, str] = {
    "a": "alpha",
    "b": "beta",
    "c": "rc",
}

_VERSION_RE = re.compile(
    r"^(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-.]?(?P<label>alpha|beta|rc|nightly|dev|a|b|c))?"
    r"(?:[.\-]?(?P<num>\d+))?"
    r"(?:[-.](?P<extra>[a-z0-9.\-]+))?$"
)


# ---------------------------------------------------------------------------
# Version parsing and comparison
# ---------------------------------------------------------------------------

def _nightly_stamp(text: str) -> int:
    """Extract the ``YYYYMMDD`` stamp from a nightly tag (0 when absent)."""
    for run in re.findall(r"\d+", text):
        if len(run) == 8:
            return int(run)
    for run in re.findall(r"\d+", text):
        if len(run) >= 6:
            return int(run)
    return 0


def _parse_loose(text: str) -> Tuple[Tuple[int, ...], Tuple[Tuple[str, int], ...]]:
    """Best-effort parse for strings the strict regex rejects."""
    digits = re.search(r"\d+(?:\.\d+)*", text)
    if digits is None:
        return ((0,), ())
    release = tuple(int(part) for part in digits.group(0).split("."))
    rest = text[digits.end():]
    label = re.search(r"(alpha|beta|rc|nightly|dev)", rest)
    if label is None:
        return (release, ())
    number = re.search(r"\d+", rest[label.end():])
    pre = (label.group(1), int(number.group(0)) if number else 0)
    return (release, (pre,))


def parse_version(value: Any) -> Tuple[Tuple[int, ...], Tuple[Tuple[str, int], ...]]:
    """
    Split a version string into ``(release, pre_release)`` tuples.

    >>> parse_version("5.1.0")
    ((5, 1, 0), ())
    >>> parse_version("v5.1.0-beta.1")
    ((5, 1, 0), (('beta', 1),))
    >>> parse_version("5.1.0b1") == parse_version("5.1.0-beta.1")
    True
    >>> parse_version("nightly-20250101-abcdef1")
    ((0,), (('nightly', 20250101),))

    Accepted forms: ``5.1.0``, ``v5.1.0``, ``5.1``, ``5.1.0-beta.1``,
    ``5.1.0b1`` / ``5.1.0a1`` / ``5.1.0rc1`` (PEP 440 short forms),
    ``5.1.0-rc.2``, ``5.1.0-nightly.20250101`` and the bare nightly tags
    ``nightly`` / ``nightly-<date>-<commit>``.  Nightly tags map to the
    sentinel release ``(0,)`` with a ``('nightly', <date>)`` pre-release
    part, which makes them sort below every numbered version while two
    nightlies still compare by their date stamp.  Unparseable input yields
    ``((0,), ())`` instead of raising.
    """
    text = str(value or "").strip().lower()
    if not text:
        return ((0,), ())
    if text == "nightly" or text.startswith("nightly-"):
        return ((0,), (("nightly", _nightly_stamp(text)),))
    match = _VERSION_RE.match(text)
    if match is None:
        return _parse_loose(text)
    release = tuple(int(part) for part in match.group("release").split("."))
    label = match.group("label")
    if not label:
        return (release, ())
    label = _NORMALIZED_LABELS.get(label, label)
    number = match.group("num")
    pre = (label, int(number) if number else 0)
    return (release, (pre,))


def compare_versions(a: Any, b: Any) -> int:
    """
    Compare two version strings: ``-1`` if ``a < b``, ``0`` if equal, ``1`` if ``a > b``.

    >>> compare_versions("5.1.0-beta.1", "5.1.0")
    -1
    >>> compare_versions("5.1.0-beta.2", "5.1.0-beta.1")
    1
    >>> compare_versions("5.1.0-rc.1", "5.1.0-beta.9")
    1
    >>> compare_versions("nightly", "5.1.0")
    -1

    Rules: release tuples compare numerically after zero-padding (``5.1``
    equals ``5.1.0``); a version without a pre-release part sorts *above*
    the same version with one; pre-release parts compare by label rank
    (nightly < dev/alpha < beta < rc) then by numeric suffix; nightly
    sentinels sort lowest of all.
    """
    release_a, pre_a = parse_version(a)
    release_b, pre_b = parse_version(b)
    width = max(len(release_a), len(release_b))
    padded_a = release_a + (0,) * (width - len(release_a))
    padded_b = release_b + (0,) * (width - len(release_b))
    if padded_a < padded_b:
        return -1
    if padded_a > padded_b:
        return 1
    if not pre_a and not pre_b:
        return 0
    if not pre_a:
        return 1  # a is the plain release, b is a pre-release -> a is newer
    if not pre_b:
        return -1
    for (label_a, num_a), (label_b, num_b) in zip(pre_a, pre_b):
        rank_a = _LABEL_ORDER.get(label_a, 50)
        rank_b = _LABEL_ORDER.get(label_b, 50)
        if rank_a != rank_b:
            return -1 if rank_a < rank_b else 1
        if num_a != num_b:
            return -1 if num_a < num_b else 1
    if len(pre_a) != len(pre_b):
        return -1 if len(pre_a) < len(pre_b) else 1
    return 0


def _excerpt(text: str, limit: int = 240) -> str:
    """Collapse whitespace and clip a release body for display."""
    clean = " ".join(str(text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: max(1, limit - 3)].rstrip() + "..."


# ---------------------------------------------------------------------------
# Update result object
# ---------------------------------------------------------------------------

@dataclass
class UpdateInfo:
    """Result of one update check (all fields are plain strings/bools)."""

    #: Version of the running build (package ``__version__``).
    current_version: str
    #: Version of the newest release found (tag without the leading ``v``).
    latest_version: str
    #: Full tag of the newest release, e.g. ``v5.1.0-beta.2``.
    latest_tag: str
    #: Channel the check ran against (``stable`` / ``beta`` / ``nightly``).
    channel: str
    #: ``browser_download_url`` of the asset matching this platform (may be
    #: empty when the release has no matching asset).
    download_url: str = ""
    #: Human-facing release page on GitHub.
    release_url: str = ""
    #: ISO timestamp of the release publication (as reported by GitHub).
    published_at: str = ""
    #: Shortened release-notes body.
    notes_excerpt: str = ""
    #: True when ``latest_version`` is newer than ``current_version``.
    is_newer: bool = False
    #: True when GitHub marks the release as a pre-release.
    is_prerelease: bool = False
    #: Names of every asset attached to the release.
    asset_names: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Compact multi-line summary for logs and diagnostics."""
        lines = [
            "current  : {0} ({1})".format(self.current_version, self.channel),
            "latest   : {0} [{1}]{2}".format(
                self.latest_version,
                self.latest_tag,
                " -- newer" if self.is_newer else " -- up to date",
            ),
        ]
        if self.download_url:
            lines.append("download : {0}".format(self.download_url))
        if self.release_url:
            lines.append("release  : {0}".format(self.release_url))
        if self.published_at:
            lines.append("published: {0}".format(self.published_at))
        if self.asset_names:
            lines.append("assets   : {0}".format(", ".join(self.asset_names)))
        if self.notes_excerpt:
            lines.append("notes    : {0}".format(self.notes_excerpt))
        return "\n".join(lines)

    def __str__(self) -> str:
        state = "newer" if self.is_newer else "up to date"
        return "UpdateInfo({0} for {1} channel, {2})".format(
            self.latest_tag or self.latest_version, self.channel, state
        )


# ---------------------------------------------------------------------------
# Default fetch (urllib, never raises)
# ---------------------------------------------------------------------------

def _urllib_fetch(url: str, timeout: float = 10.0) -> Tuple[int, str]:
    """
    Default ``fetch`` implementation built on :mod:`urllib.request`.

    Sends the User-Agent GitHub requires for API requests and returns
    ``(status, body_text)``.  Network errors yield ``(0, "")`` and HTTP
    errors yield ``(http_code, "")`` -- this function never raises, which
    keeps :meth:`UpdateChecker.check` exception-free.
    """
    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ObscuraLens-Desktop/{0}".format(__version__),
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 0) or 200)
            body = response.read(MAX_RESPONSE_BYTES)
            return status, body.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:  # must precede URLError: subclass
        return int(getattr(exc, "code", 0) or 0), ""
    except (urllib.error.URLError, OSError, ValueError):
        return 0, ""


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------

class UpdateChecker:
    """
    Check GitHub for a newer ObscuraLens Desktop release.

    Args:
        repo: repository slug; defaults to ``OBSCURALENS_REPO_SLUG`` or
            ``AceGuru-mjh/obscuralens``.
        channel: channel name (or :class:`ReleaseChannel`); defaults to the
            channel declared by the package.
        timeout: per-request timeout in seconds.
        fetch: injectable ``callable(url, timeout) -> (status, text)`` used
            by the tests; defaults to :func:`_urllib_fetch`.

    Every public method is exception-free: failures are reported through
    ``None`` results and the :attr:`last_error` message string.
    """

    def __init__(self,
                 repo: Optional[str] = None,
                 channel: Any = None,
                 timeout: float = 10,
                 fetch: Optional[FetchCallable] = None):
        self.repo = str(repo or "").strip() or current_repo_slug()
        if isinstance(channel, ReleaseChannel):
            channel = channel.name
        self.channel = get_channel(channel).name
        self.timeout = float(timeout)
        self.fetch: FetchCallable = fetch or _urllib_fetch
        self.last_error = ""

    # -- internals -------------------------------------------------------

    def _fetch(self, url: str) -> Tuple[int, str]:
        """Call the (possibly injected) fetcher without ever raising."""
        try:
            status, text = self.fetch(url, self.timeout)
            return int(status or 0), str(text or "")
        except Exception as exc:  # defensive: a broken fetcher must not kill us
            self.last_error = "fetch failed: {0}".format(exc)
            return 0, ""

    def _fetch_json(self, url: str) -> Any:
        status, text = self._fetch(url)
        if status == 0:
            if not self.last_error:
                self.last_error = "could not reach the update service"
            return None
        if status != 200:
            self.last_error = "update feed returned http {0}".format(status)
            return None
        if not text:
            self.last_error = "update feed returned an empty body"
            return None
        try:
            return json.loads(text)
        except ValueError:
            self.last_error = "update feed returned malformed JSON"
            return None

    def _latest_stable_release(self) -> Optional[Dict[str, Any]]:
        payload = self._fetch_json(github_release_api_url(self.repo))
        if not isinstance(payload, dict) or not payload.get("tag_name"):
            if not self.last_error:
                self.last_error = "no stable release found in the feed"
            return None
        return payload

    def _release_for_tag(self, tag: str) -> Optional[Dict[str, Any]]:
        payload = self._fetch_json(github_release_api_url(self.repo, tag=tag))
        if not isinstance(payload, dict) or not payload.get("tag_name"):
            if not self.last_error:
                self.last_error = "no release found for tag {0}".format(tag)
            return None
        return payload

    def _latest_beta_release(self) -> Optional[Dict[str, Any]]:
        """
        Newest beta pre-release.

        Why a release *list*?  GitHub's ``releases/latest`` endpoint
        deliberately ignores pre-releases, so the beta channel cannot use
        it: we scan ``releases?per_page=20`` instead and pick the first
        entry that is flagged ``prerelease`` *and* carries a beta tag
        (``v*-beta*``).  If the feed contains pre-releases but none of them
        is beta-tagged, the first pre-release is used as a documented
        fallback so the checker still reports something useful.
        """
        payload = self._fetch_json(github_releases_list_url(self.repo))
        if not isinstance(payload, list) or not payload:
            if not self.last_error:
                self.last_error = "release feed is empty or malformed"
            return None
        fallback: Optional[Dict[str, Any]] = None
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            tag = str(entry.get("tag_name") or "")
            if not tag or not entry.get("prerelease"):
                continue
            channel = channel_for_tag(tag)
            if channel is not None and channel.name == "beta":
                return entry
            if fallback is None:
                fallback = entry
        if fallback is not None:
            return fallback
        self.last_error = "no beta pre-release found in the release feed"
        return None

    @staticmethod
    def _asset_matches(name: str, expected: Optional[str], version: str,
                       platform_key: str) -> bool:
        """Does *name* look like the packaged asset for this platform?"""
        if expected and name == expected:
            return True
        return (
            bool(version)
            and bool(platform_key)
            and name.startswith(ASSET_STEM)
            and version in name
            and platform_key in name
        )

    def _check(self) -> Optional[UpdateInfo]:
        self.last_error = ""
        release = self.latest_release()
        if not release:
            if not self.last_error:
                self.last_error = "no release information available"
            return None

        tag = str(release.get("tag_name") or "").strip()
        latest_version = tag.lstrip("vV")
        if not latest_version:
            name = str(release.get("name") or "").strip().lower()
            digits = re.search(r"\d+(?:\.\d+)*", name)
            latest_version = digits.group(0) if digits else ""
        if not latest_version:
            self.last_error = "release carries no usable version tag"
            return None

        current = __version__
        platform_key = detect_platform().key
        expected = asset_name(latest_version, platform_key)

        asset_names: List[str] = []
        download_url = ""
        assets = release.get("assets")
        if isinstance(assets, list):
            for entry in assets:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name") or "")
                if not name:
                    continue
                asset_names.append(name)
                url = str(entry.get("browser_download_url") or "")
                if not download_url and url and self._asset_matches(
                    name, expected, latest_version, platform_key
                ):
                    download_url = url

        return UpdateInfo(
            current_version=current,
            latest_version=latest_version,
            latest_tag=tag,
            channel=self.channel,
            download_url=download_url,
            release_url=str(release.get("html_url") or ""),
            published_at=str(release.get("published_at") or ""),
            notes_excerpt=_excerpt(release.get("body")),
            is_newer=compare_versions(latest_version, current) > 0,
            is_prerelease=bool(release.get("prerelease")),
            asset_names=asset_names,
        )

    # -- public API ------------------------------------------------------

    def latest_release(self) -> Optional[Dict[str, Any]]:
        """
        Newest release dict of this checker's channel, or ``None``.

        The dict is the parsed GitHub API payload (``tag_name``,
        ``prerelease``, ``assets``, ``html_url``, ``published_at``,
        ``body`` ...).  Stable uses ``releases/latest``, nightly uses
        ``releases/tags/nightly`` and beta scans the release list (see
        :meth:`_latest_beta_release` for the reasoning).
        """
        try:
            if self.channel == "beta":
                return self._latest_beta_release()
            if self.channel == "nightly":
                return self._release_for_tag("nightly")
            return self._latest_stable_release()
        except Exception as exc:  # pragma: no cover - defensive guard
            self.last_error = "release lookup failed: {0}".format(exc)
            return None

    def check(self) -> Optional[UpdateInfo]:
        """
        Full update check; ``None`` when offline or the feed is unusable.

        Never raises.  On failure the reason is available in
        :attr:`last_error`.
        """
        try:
            return self._check()
        except Exception as exc:  # pragma: no cover - defensive guard
            self.last_error = "update check failed: {0}".format(exc)
            return None

    def check_quiet(self) -> Optional[UpdateInfo]:
        """
        Same as :meth:`check` but guarantees a non-empty :attr:`last_error`.

        Intended for background/scheduled checks where the caller only
        wants "result or explanation", without exceptions or console noise.
        """
        info = self.check()
        if info is None and not self.last_error:
            self.last_error = "update check produced no result"
        return info

    def format_notice(self, info: Optional[UpdateInfo]) -> str:
        """
        Channel-aware multi-line notice for the terminal (pure ASCII).

        ``None`` renders an offline notice, an up-to-date ``info`` renders
        a short confirmation and a newer ``info`` renders the full
        "update available" box with download links and the notes excerpt.
        """
        width = 72
        if info is None:
            reason = self.last_error or "the update service is unreachable"
            return "\n".join(
                _box_lines(
                    [
                        "UPDATE CHECK FAILED",
                        "",
                        "Could not determine the latest release:",
                        "  {0}".format(reason),
                        "",
                        "Retry anytime with:  obscuralens-desktop --check-update",
                    ],
                    width,
                )
            )
        if not info.is_newer:
            return "\n".join(
                _box_lines(
                    [
                        "UP TO DATE",
                        "",
                        "{0} v{1} is the newest {2}-channel release.".format(
                            "ObscuraLens Desktop", info.current_version, info.channel
                        ),
                    ],
                    width,
                )
            )

        if info.channel == "beta":
            channel_hint = (
                "You are on the beta channel; this pre-release is newer",
                "than your current beta build.",
            )
        elif info.channel == "nightly":
            channel_hint = (
                "A fresh nightly build is available; nightlies track",
                "main and may be less stable than beta or stable.",
            )
        else:
            channel_hint = (
                "A new stable build is available; the download replaces",
                "your current binary without touching your data.",
            )
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
        if info.published_at:
            body.append("published: {0}".format(info.published_at))
        if info.download_url:
            body.append("download: {0}".format(info.download_url))
        elif info.asset_names:
            body.append("assets  : {0}".format(", ".join(info.asset_names[:3])))
        if info.release_url:
            body.append("release : {0}".format(info.release_url))
        body.append("")
        body.extend(channel_hint)
        if info.notes_excerpt:
            body.append("")
            body.extend(_wrap_ascii(info.notes_excerpt, width - 6, indent="  "))
        return "\n".join(_box_lines(body, width))

    def announcement(self, info: Optional[UpdateInfo]) -> str:
        """One-line short version of the notice (no newlines)."""
        if info is None:
            reason = self.last_error or "offline"
            return "Update check unavailable ({0}).".format(reason)
        if not info.is_newer:
            return "ObscuraLens Desktop v{0} ({1}) is up to date.".format(
                info.current_version, info.channel
            )
        return "Update available: {0} (you have v{1}) -- {2}".format(
            info.latest_tag or info.latest_version,
            info.current_version,
            info.release_url or "see the releases page",
        )


def _box_lines(lines: List[str], width: int) -> List[str]:
    """Pure-ASCII ``+---+`` frame (mirrors branding, kept local on purpose)."""
    inner = max(1, width - 2)
    bordered = ["+" + "-" * inner + "+"]
    for line in lines:
        bordered.append("|" + str(line)[:inner].ljust(inner) + "|")
    bordered.append("+" + "-" * inner + "+")
    return bordered


def _wrap_ascii(text: str, width: int, indent: str = "") -> List[str]:
    """Word-wrap *text* to *width* columns, indented, without hyphenation."""
    return [
        indent + line
        for line in (textwrap.wrap(str(text), max(10, width)) or [""])
    ]


def check_for_updates(channel: Any = None,
                      repo: Optional[str] = None,
                      timeout: float = 10,
                      fetch: Optional[FetchCallable] = None) -> Optional[UpdateInfo]:
    """
    Convenience one-shot update check (never raises, no console output).

    ``channel`` may be a channel name or a :class:`ReleaseChannel`; the
    fetcher is injectable for tests exactly like on :class:`UpdateChecker`.
    """
    return UpdateChecker(repo=repo, channel=channel, timeout=timeout, fetch=fetch).check()


__all__ = [
    "MAX_RESPONSE_BYTES",
    "UpdateChecker",
    "UpdateInfo",
    "check_for_updates",
    "compare_versions",
    "parse_version",
]
