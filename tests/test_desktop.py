"""
Offline tests for the ObscuraLens desktop package.

Covers branding, the channel registry, version parsing/comparison and the
GitHub update checker (with an injectable fake fetch -- no network), the
single-instance lock, the launcher helpers/CLI (uvicorn and webbrowser are
faked through ``sys.modules``) and the diagnostics report.

The suite runs in the plain CI job without fastapi/uvicorn installed; the
one test that needs the real web stack is skipped automatically.
"""

import json
import os
import socket
import sys
import time
from pathlib import Path

import pytest

import obscuralens.desktop as desktop_pkg
from obscuralens import __version__ as PACKAGE_VERSION
from obscuralens.desktop import (
    DESKTOP_CHANNEL,
    LaunchOptions,
    ReleaseChannel,
    UpdateChecker,
    UpdateInfo,
    branding,
    desktop_version,
    diagnostics,
    launcher,
    singleinstance,
    updater,
)
from obscuralens.desktop import (
    channel as channel_mod,
)

SLUG = "AceGuru-mjh/obscuralens"
LIST_URL = channel_mod.github_releases_list_url()
LATEST_URL = channel_mod.github_release_api_url()
NIGHTLY_URL = channel_mod.github_release_api_url(tag="nightly")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def ascii_only(text):
    """Every character is plain ASCII (safe for cmd.exe)."""
    return all(ord(char) < 128 for char in text)


def make_release(tag, prerelease=False, assets=None, body="Bug fixes and polish.",
                 published="2025-01-15T12:00:00Z"):
    """Build a canned GitHub release-API payload."""
    names = list(assets or [])
    return {
        "tag_name": tag,
        "name": "ObscuraLens {0}".format(tag),
        "prerelease": prerelease,
        "html_url": "https://github.com/{0}/releases/tag/{1}".format(SLUG, tag),
        "published_at": published,
        "body": body,
        "assets": [
            {
                "name": name,
                "browser_download_url": (
                    "https://github.com/{0}/releases/download/{1}/{2}".format(SLUG, tag, name)
                ),
            }
            for name in names
        ],
    }


class FakeFetch:
    """Injectable ``fetch(url, timeout) -> (status, text)`` with a call log."""

    def __init__(self, mapping=None, default=(200, "[]")):
        self.mapping = dict(mapping or {})
        self.default = default
        self.calls = []

    def __call__(self, url, timeout=10):
        self.calls.append((url, timeout))
        if url in self.mapping:
            return self.mapping[url]
        return self.default


def current_platform_key():
    return channel_mod.detect_platform().key


def _module_available(name):
    """Whether an importable module exists (without importing it)."""
    try:
        import importlib.util

        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def _web_stack_available():
    """Whether the full web stack (fastapi + uvicorn + obscuralens.web) imports."""
    if not (_module_available("fastapi") and _module_available("uvicorn")):
        return False
    try:
        import obscuralens.web  # noqa: F401

        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Branding
# ---------------------------------------------------------------------------

class TestBranding:

    def test_banner_contains_version_and_name(self):
        banner = branding.render_banner()
        assert "v{0}".format(PACKAGE_VERSION) in banner
        assert branding.DESKTOP_NAME in banner

    def test_banner_contains_channel_badge(self):
        banner = branding.render_banner()
        assert branding.badge_for_channel().render() in banner

    def test_banner_pure_ascii(self):
        assert ascii_only(branding.render_banner())
        assert ascii_only(branding.render_banner(width=100))

    def test_banner_lines_equal_width(self):
        for width in (72, 90):
            lines = branding.render_banner(width=width).splitlines()
            assert len(lines) > 6
            assert {len(line) for line in lines} == {width}

    def test_banner_widens_for_tiny_widths(self):
        lines = branding.render_banner(width=20).splitlines()
        assert len({len(line) for line in lines}) == 1
        assert len(lines[0]) >= 40  # the ASCII logo forces a wider box

    def test_banner_mentions_beta_disclaimer(self):
        banner = branding.render_banner()
        assert "BETA PRE-RELEASE" in banner

    def test_splash_format(self):
        assert branding.render_splash("web-server", "starting") == (
            "[desktop] web-server -> starting"
        )

    def test_splash_ascii_and_single_line(self):
        splash = branding.render_splash("init", "loading the desktop runtime")
        assert ascii_only(splash)
        assert "\n" not in splash

    def test_splash_truncates_long_messages(self):
        splash = branding.render_splash("init", "x" * 200, width=40)
        assert len(splash) <= 40
        assert splash.endswith("...")

    def test_about_text_contents(self):
        about = branding.about_text()
        assert "v{0}".format(PACKAGE_VERSION) in about
        assert branding.channel_name() in about
        assert branding.HOMEPAGE in about
        assert "MIT" in about
        assert "python" in about.lower()
        assert "platform" in about.lower()

    def test_about_text_ascii(self):
        assert ascii_only(branding.about_text())

    def test_disclaimer_ascii_and_beta(self):
        assert ascii_only(branding.BETA_DISCLAIMER)
        assert "BETA PRE-RELEASE" in branding.BETA_DISCLAIMER
        assert "issues" in branding.BETA_DISCLAIMER

    def test_ascii_art_is_ascii_and_multiline(self):
        assert ascii_only(branding.BETA_ASCII_ART)
        assert len(branding.BETA_ASCII_ART.strip().splitlines()) >= 4

    def test_constants(self):
        assert branding.DESKTOP_NAME == "ObscuraLens Desktop"
        assert DESKTOP_CHANNEL == branding.DESKTOP_CHANNEL == "beta"
        assert branding.HOMEPAGE.startswith("https://github.com/")

    def test_desktop_version_matches_package(self):
        assert desktop_version() == PACKAGE_VERSION

    def test_is_beta_true_for_beta_channel(self):
        assert branding.is_beta() is True

    def test_is_beta_false_for_other_channel(self, monkeypatch):
        monkeypatch.setattr(branding, "DESKTOP_CHANNEL", "stable")
        assert branding.is_beta() is False

    def test_is_nightly_env_flag(self, monkeypatch):
        monkeypatch.delenv("OBSCURALENS_NIGHTLY", raising=False)
        monkeypatch.setattr(branding, "DESKTOP_CHANNEL", "beta")
        assert branding.is_nightly() is False
        monkeypatch.setenv("OBSCURALENS_NIGHTLY", "1")
        assert branding.is_nightly() is True

    def test_is_nightly_channel_value(self, monkeypatch):
        monkeypatch.delenv("OBSCURALENS_NIGHTLY", raising=False)
        monkeypatch.setattr(branding, "DESKTOP_CHANNEL", "nightly")
        assert branding.is_nightly() is True

    def test_badge_render_plain(self):
        badge = branding.ChannelBadge("BETA CHANNEL", "yellow", False)
        assert badge.render() == "[ BETA CHANNEL ]"

    def test_badge_render_compact(self):
        badge = branding.ChannelBadge("BETA", "yellow", False)
        assert badge.render(compact=True) == "[BETA]"

    def test_badge_colored_respects_no_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        badge = branding.ChannelBadge("BETA", "yellow", False)
        assert badge.render(colored=True) == "[ BETA ]"

    def test_badge_for_channel_fallback(self):
        assert branding.badge_for_channel("bogus").label == "BETA CHANNEL"
        assert branding.badge_for_channel("stable").stable is True

    def test_startup_sequence_default_order(self):
        stages = [
            line.split("] ", 1)[1].split(" ->", 1)[0]
            for line in branding.startup_sequence()
        ]
        assert stages == ["init", "config", "data-packs", "web-server", "browser"]

    def test_startup_sequence_ascii_lines(self):
        for line in branding.startup_sequence():
            assert line.startswith("[desktop] ")
            assert ascii_only(line)

    def test_startup_sequence_custom_messages(self):
        lines = list(branding.startup_sequence(messages={"init": "custom boot message"}))
        assert "custom boot message" in lines[0]
        assert len(lines) == 5

    def test_update_notice_newer(self):
        info = UpdateInfo(
            current_version="5.1.0",
            latest_version="5.2.0",
            latest_tag="v5.2.0",
            channel="beta",
            download_url="https://github.com/{0}/releases/download/v5.2.0/app.exe".format(SLUG),
            release_url="https://github.com/{0}/releases/tag/v5.2.0".format(SLUG),
            is_newer=True,
            is_prerelease=True,
        )
        notice = branding.update_notice(info)
        assert "UPDATE AVAILABLE" in notice
        assert "v5.2.0" in notice
        assert "5.1.0" in notice
        assert ascii_only(notice)

    def test_update_notice_up_to_date(self):
        info = UpdateInfo(
            current_version="5.1.0",
            latest_version="5.1.0",
            latest_tag="v5.1.0",
            channel="beta",
        )
        notice = branding.update_notice(info)
        assert "UP TO DATE" in notice
        assert "5.1.0" in notice

    def test_update_notice_unreachable(self):
        notice = branding.update_notice(None)
        assert "UPDATE CHECK UNAVAILABLE" in notice
        assert ascii_only(notice)


# ---------------------------------------------------------------------------
# Channel registry
# ---------------------------------------------------------------------------

class TestChannelRegistry:

    def test_registry_contains_three_channels(self):
        assert set(channel_mod.CHANNELS) == {"stable", "beta", "nightly"}

    def test_channel_flags(self):
        assert channel_mod.CHANNELS["stable"].prerelease is False
        assert channel_mod.CHANNELS["beta"].prerelease is True
        assert channel_mod.CHANNELS["nightly"].prerelease is True
        assert channel_mod.CHANNELS["stable"].tag_prefix == "v"
        assert channel_mod.CHANNELS["beta"].tag_prefix == "v*-beta*"
        assert channel_mod.CHANNELS["nightly"].tag_prefix == "nightly"

    def test_channel_urls_point_at_github(self):
        for channel in channel_mod.CHANNELS.values():
            assert channel.feed_url.startswith("https://api.github.com/repos/")
            assert channel.notes_url.startswith("https://github.com/")

    def test_release_channel_str(self):
        text = str(channel_mod.CHANNELS["beta"])
        assert "beta" in text
        assert "v*-beta*" in text

    @pytest.mark.parametrize("name", ["stable", "beta", "nightly"])
    def test_get_channel_known_names(self, name):
        assert channel_mod.get_channel(name).name == name

    def test_get_channel_case_insensitive(self):
        assert channel_mod.get_channel("BETA").name == "beta"
        assert channel_mod.get_channel(" Beta ").name == "beta"

    def test_get_channel_unknown_falls_back_to_beta(self):
        fallback = channel_mod.get_channel("bogus")
        assert fallback.name == "beta"
        assert fallback == channel_mod.get_channel("beta")

    def test_get_channel_none_uses_package_channel(self):
        assert channel_mod.get_channel(None).name == "beta"
        assert channel_mod.default_channel().name == "beta"

    @pytest.mark.parametrize("tag,expected", [
        ("v5.1.0", "stable"),
        ("5.1.0", "stable"),
        ("v5.2.7", "stable"),
        ("v5.1.0-beta.1", "beta"),
        ("v5.1.0-beta.7", "beta"),
        ("5.1.1-beta.2", "beta"),
        ("nightly", "nightly"),
        ("nightly-20250101", "nightly"),
        ("nightly-20250101-abcdef1", "nightly"),
        ("v5.1.0-nightly", "nightly"),
        ("v5.1.0-rc.1", None),
        ("release-1", None),
        ("", None),
        (None, None),
    ])
    def test_channel_for_tag(self, tag, expected):
        result = channel_mod.channel_for_tag(tag)
        if expected is None:
            assert result is None
        else:
            assert result is not None
            assert result.name == expected

    @pytest.mark.parametrize("version,key,expected", [
        ("5.1.0-beta.1", "win-x64", "ObscuraLens-5.1.0-beta.1-win-x64.exe"),
        ("v5.1.0", "win-x64", "ObscuraLens-5.1.0-win-x64.exe"),
        ("5.1.0-beta.1", "linux-x64", "ObscuraLens-5.1.0-beta.1-linux-x64"),
        ("5.1.0", "macos-arm64", "ObscuraLens-5.1.0-macos-arm64"),
        ("5.1.0", "win-arm64", None),
        ("5.1.0", "unknown", None),
        ("", "win-x64", None),
    ])
    def test_asset_name(self, version, key, expected):
        assert channel_mod.asset_name(version, key) == expected

    def test_asset_name_accepts_platform_info(self):
        info = channel_mod.PlatformInfo(
            system="win32", machine="amd64", release="10", arch="x64", key="win-x64",
            is_frozen=True, executable="C:/ObscuraLens.exe",
        )
        assert channel_mod.asset_name("5.1.0", info) == "ObscuraLens-5.1.0-win-x64.exe"

    def test_channel_asset_for_uses_package_version(self):
        channel = channel_mod.get_channel("win-x64")  # unknown name -> beta
        expected = channel_mod.asset_name(PACKAGE_VERSION, "linux-x64")
        assert channel.asset_for("linux-x64") == expected

    def test_download_url_format_win(self):
        url = channel_mod.download_url("v5.1.0-beta.1", "5.1.0-beta.1", "win-x64")
        assert url == (
            "https://github.com/{0}/releases/download/v5.1.0-beta.1/"
            "ObscuraLens-5.1.0-beta.1-win-x64.exe".format(SLUG)
        )

    def test_download_url_empty_for_unusable_input(self):
        assert channel_mod.download_url("v5.1.0", "5.1.0", "sunos-sparc") == ""
        assert channel_mod.download_url("", "5.1.0", "win-x64") == ""

    def test_repo_slug_env_override(self, monkeypatch):
        monkeypatch.setenv("OBSCURALENS_REPO_SLUG", "octocat/widgets")
        assert channel_mod.current_repo_slug() == "octocat/widgets"
        assert "octocat/widgets" in channel_mod.github_release_api_url()
        assert "octocat/widgets" in channel_mod.get_channel("beta").feed_url

    @pytest.mark.parametrize("raw,expected", [
        ("https://github.com/octocat/widgets", "octocat/widgets"),
        ("github.com/octocat/widgets", "octocat/widgets"),
        ("https://github.com/octocat/widgets.git", "octocat/widgets"),
        ("not-a-slug", SLUG),
        ("", SLUG),
    ])
    def test_repo_slug_url_forms(self, monkeypatch, raw, expected):
        monkeypatch.setenv("OBSCURALENS_REPO_SLUG", raw)
        assert channel_mod.current_repo_slug() == expected

    def test_github_release_api_url_latest(self):
        assert channel_mod.github_release_api_url() == (
            "https://api.github.com/repos/{0}/releases/latest".format(SLUG)
        )

    def test_github_release_api_url_with_tag(self):
        assert channel_mod.github_release_api_url(tag="v5.1.0-beta.1") == (
            "https://api.github.com/repos/{0}/releases/tags/v5.1.0-beta.1".format(SLUG)
        )

    def test_github_releases_list_url(self):
        assert channel_mod.github_releases_list_url() == (
            "https://api.github.com/repos/{0}/releases?per_page=20".format(SLUG)
        )
        custom = channel_mod.github_releases_list_url("a/b", per_page=5)
        assert custom == "https://api.github.com/repos/a/b/releases?per_page=5"

    def test_current_tag_beta_default(self, monkeypatch):
        monkeypatch.delenv("OBSCURALENS_DESKTOP_TAG", raising=False)
        assert channel_mod.current_tag() == "v{0}-beta.1".format(PACKAGE_VERSION)

    def test_current_tag_per_channel(self, monkeypatch):
        monkeypatch.delenv("OBSCURALENS_DESKTOP_TAG", raising=False)
        assert channel_mod.current_tag(channel="stable") == "v{0}".format(PACKAGE_VERSION)
        assert channel_mod.current_tag(channel="nightly") == "nightly"

    def test_current_tag_env_override(self, monkeypatch):
        monkeypatch.setenv("OBSCURALENS_DESKTOP_TAG", "v9.9.9-beta.9")
        assert channel_mod.current_tag() == "v9.9.9-beta.9"

    def test_detect_platform_fields(self):
        info = channel_mod.detect_platform()
        assert isinstance(info, channel_mod.PlatformInfo)
        assert info.system == sys.platform
        assert info.machine
        assert info.arch in ("x64", "arm64", "x86", "unknown")
        assert info.key in (
            "win-x64", "win-arm64", "win-x86", "win-unknown",
            "linux-x64", "linux-arm64", "linux-x86", "linux-unknown",
            "macos-x64", "macos-arm64", "macos-x86", "macos-unknown",
            "unknown",
        )
        assert info.is_frozen is False  # running under pytest, not PyInstaller
        assert info.executable

    def test_platform_info_summary(self):
        info = channel_mod.detect_platform()
        summary = info.summary()
        assert info.system in summary
        assert info.machine in summary
        assert ascii_only(summary)

    def test_current_channel_info_keys(self):
        info = channel_mod.current_channel_info()
        assert set(info) == {
            "name", "tag_prefix", "prerelease", "feed_url", "notes_url",
            "current_tag", "repo", "package_channel",
        }
        assert info["name"] == "beta"
        assert info["prerelease"] is True
        assert info["repo"] == SLUG


# ---------------------------------------------------------------------------
# Version parsing and comparison
# ---------------------------------------------------------------------------

class TestVersionParsing:

    @pytest.mark.parametrize("value,release,pre", [
        ("5.1.0", (5, 1, 0), ()),
        ("v5.1.0", (5, 1, 0), ()),
        ("5.1", (5, 1), ()),
        ("5", (5,), ()),
        ("5.1.0.2", (5, 1, 0, 2), ()),
        ("5.1.0-beta.1", (5, 1, 0), (("beta", 1),)),
        ("v5.1.0-beta.2", (5, 1, 0), (("beta", 2),)),
        ("5.1.0-beta", (5, 1, 0), (("beta", 0),)),
        ("5.1.0b1", (5, 1, 0), (("beta", 1),)),
        ("5.1.0a2", (5, 1, 0), (("alpha", 2),)),
        ("5.1.0rc3", (5, 1, 0), (("rc", 3),)),
        ("5.1.0-rc.1", (5, 1, 0), (("rc", 1),)),
        ("5.1.0-nightly.20250101", (5, 1, 0), (("nightly", 20250101),)),
        ("nightly", (0,), (("nightly", 0),)),
        ("nightly-20250101-abcdef1", (0,), (("nightly", 20250101),)),
        ("", (0,), ()),
        ("unknown", (0,), ()),
        (None, (0,), ()),
    ])
    def test_parse_version(self, value, release, pre):
        assert updater.parse_version(value) == (release, pre)

    @pytest.mark.parametrize("a,b,expected", [
        ("5.1.0", "5.1.0", 0),
        ("5.1", "5.1.0", 0),
        ("5.1.0", "5.0.9", 1),
        ("5.1.0", "5.1.1", -1),
        ("5.1.0", "5.10.0", -1),
        ("v5.2.0", "5.1.0", 1),
        ("6.0.0", "5.9.9", 1),
        ("5.1.0-beta.1", "5.1.0", -1),
        ("5.1.0", "5.1.0-beta.1", 1),
        ("5.1.0-beta.2", "5.1.0-beta.1", 1),
        ("5.1.0-beta.1", "5.1.0-beta.2", -1),
        ("5.1.0-beta.9", "5.1.0-beta.10", -1),
        ("5.1.0-beta.1", "5.1.0-beta.1", 0),
        ("5.1.0b1", "5.1.0-beta.1", 0),
        ("5.1.0-rc.1", "5.1.0-beta.9", 1),
        ("5.1.0-beta.9", "5.1.0-rc.1", -1),
        ("5.1.0-alpha.5", "5.1.0-beta.1", -1),
        ("5.1.0-rc.1", "5.1.0-alpha.5", 1),
        ("nightly", "5.1.0", -1),
        ("nightly", "5.1.0-beta.1", -1),
        ("5.1.0-nightly", "5.1.0-beta.1", -1),
        ("nightly-20250201-aaaaaaa", "nightly-20250101-bbbbbbb", 1),
        ("nightly-20250101-a", "nightly-20250101-b", 0),
    ])
    def test_compare_versions(self, a, b, expected):
        assert updater.compare_versions(a, b) == expected


# ---------------------------------------------------------------------------
# Update checker (fake fetch, no network)
# ---------------------------------------------------------------------------

class TestUpdateChecker:

    def test_checker_defaults(self):
        checker = UpdateChecker()
        assert checker.repo == SLUG
        assert checker.channel == "beta"
        assert checker.timeout == 10
        assert checker.last_error == ""
        assert callable(checker.fetch)

    def test_checker_accepts_channel_object(self):
        checker = UpdateChecker(channel=ReleaseChannel(
            name="nightly", tag_prefix="nightly", prerelease=True,
            feed_url="x", notes_url="y",
        ))
        assert checker.channel == "nightly"

    def test_check_beta_newer(self):
        key = current_platform_key()
        matching = "ObscuraLens-6.0.0-beta.1-{0}".format(key)
        release = make_release(
            "v6.0.0-beta.1",
            prerelease=True,
            assets=[matching, "ObscuraLens-6.0.0-beta.1-win-x64.exe"],
        )
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([release]))})
        checker = UpdateChecker(fetch=fetcher)
        info = checker.check()
        assert info is not None
        assert info.is_newer is True
        assert info.latest_tag == "v6.0.0-beta.1"
        assert info.latest_version == "6.0.0-beta.1"
        assert info.channel == "beta"
        assert info.is_prerelease is True
        assert info.download_url.endswith(matching)
        assert matching in info.asset_names
        assert "ObscuraLens-6.0.0-beta.1-win-x64.exe" in info.asset_names
        assert checker.last_error == ""
        assert fetcher.calls and fetcher.calls[0][0] == LIST_URL

    def test_check_beta_up_to_date(self):
        release = make_release("v5.1.0-beta.1", prerelease=True)
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([release]))})
        info = UpdateChecker(fetch=fetcher).check()
        assert info is not None
        assert info.is_newer is False
        assert info.latest_tag == "v5.1.0-beta.1"

    def test_check_beta_skips_stable_entries(self):
        stable = make_release("v9.9.9")
        beta = make_release("v5.1.1-beta.1", prerelease=True)
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([stable, beta]))})
        info = UpdateChecker(fetch=fetcher).check()
        assert info is not None
        assert info.latest_tag == "v5.1.1-beta.1"
        assert info.is_prerelease is True

    def test_check_beta_falls_back_to_first_prerelease(self):
        rc_only = make_release("v7.0.0-rc.1", prerelease=True)
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([rc_only]))})
        info = UpdateChecker(fetch=fetcher).check()
        assert info is not None
        assert info.latest_tag == "v7.0.0-rc.1"

    def test_check_beta_none_when_feed_has_no_prerelease(self):
        stable = make_release("v9.9.9")
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([stable]))})
        checker = UpdateChecker(fetch=fetcher)
        assert checker.check() is None
        assert checker.last_error

    def test_check_stable_uses_latest_endpoint(self):
        release = make_release("v5.2.0")
        fetcher = FakeFetch({LATEST_URL: (200, json.dumps(release))})
        checker = UpdateChecker(channel="stable", fetch=fetcher)
        info = checker.check()
        assert [url for url, _ in fetcher.calls] == [LATEST_URL]
        assert info is not None
        assert info.is_newer is True
        assert info.is_prerelease is False
        assert info.channel == "stable"

    def test_check_nightly_uses_tag_endpoint(self):
        release = make_release("nightly", prerelease=True)
        fetcher = FakeFetch({NIGHTLY_URL: (200, json.dumps(release))})
        checker = UpdateChecker(channel="nightly", fetch=fetcher)
        info = checker.check()
        assert fetcher.calls[0][0] == NIGHTLY_URL
        assert NIGHTLY_URL.endswith("/releases/tags/nightly")
        assert info is not None
        assert info.latest_tag == "nightly"
        assert info.is_newer is False  # the nightly sentinel sorts lowest

    def test_check_offline_returns_none(self):
        checker = UpdateChecker(fetch=FakeFetch(default=(0, "")))
        assert checker.check() is None
        assert checker.last_error

    def test_check_http_error_returns_none(self):
        checker = UpdateChecker(fetch=FakeFetch(default=(404, "")))
        assert checker.check() is None
        assert "404" in checker.last_error

    def test_check_bad_json_returns_none(self):
        checker = UpdateChecker(fetch=FakeFetch(default=(200, "not json")))
        assert checker.check() is None
        assert "json" in checker.last_error.lower()

    def test_check_never_raises_with_broken_fetch(self):
        def broken(url, timeout):
            raise RuntimeError("kaput")

        checker = UpdateChecker(fetch=broken)
        assert checker.check() is None
        assert "kaput" in checker.last_error

    def test_check_with_no_matching_asset(self):
        release = make_release(
            "v5.1.5-beta.1", prerelease=True, assets=["README.md", "sha256sums.txt"]
        )
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([release]))})
        info = UpdateChecker(fetch=fetcher).check()
        assert info is not None
        assert info.download_url == ""
        assert set(info.asset_names) == {"README.md", "sha256sums.txt"}

    def test_check_quiet_sets_last_error(self):
        checker = UpdateChecker(fetch=FakeFetch(default=(0, "")))
        assert checker.check_quiet() is None
        assert checker.last_error != ""

    def test_check_quiet_returns_info_when_available(self):
        release = make_release("v5.1.0-beta.1", prerelease=True)
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([release]))})
        info = UpdateChecker(fetch=fetcher).check_quiet()
        assert info is not None
        assert info.latest_tag == "v5.1.0-beta.1"

    def test_format_notice_newer(self):
        info = UpdateInfo(
            current_version="5.1.0",
            latest_version="5.2.0",
            latest_tag="v5.2.0",
            channel="beta",
            download_url="https://github.com/{0}/x.exe".format(SLUG),
            release_url="https://github.com/{0}/releases/tag/v5.2.0".format(SLUG),
            published_at="2025-02-01T10:00:00Z",
            notes_excerpt="Fixed the launcher.",
            is_newer=True,
            is_prerelease=True,
        )
        notice = UpdateChecker().format_notice(info)
        assert "UPDATE AVAILABLE" in notice
        assert "v5.2.0" in notice
        assert "5.1.0" in notice
        assert "x.exe" in notice
        assert "Fixed the launcher." in notice
        assert ascii_only(notice)
        assert {len(line) for line in notice.splitlines()} == {72}

    def test_format_notice_up_to_date(self):
        info = UpdateInfo(
            current_version="5.1.0", latest_version="5.1.0",
            latest_tag="v5.1.0", channel="beta",
        )
        notice = UpdateChecker().format_notice(info)
        assert "UP TO DATE" in notice
        assert "5.1.0" in notice

    def test_format_notice_offline(self):
        checker = UpdateChecker(fetch=FakeFetch(default=(0, "")))
        checker.check_quiet()
        notice = checker.format_notice(None)
        assert "UPDATE CHECK FAILED" in notice
        assert ascii_only(notice)

    def test_announcement_one_line_newer(self):
        info = UpdateInfo(
            current_version="5.1.0", latest_version="5.2.0", latest_tag="v5.2.0",
            channel="beta", release_url="https://github.com/x/tag/v5.2.0", is_newer=True,
        )
        line = UpdateChecker().announcement(info)
        assert "\n" not in line
        assert "v5.2.0" in line
        assert "5.1.0" in line

    def test_announcement_up_to_date(self):
        info = UpdateInfo(
            current_version="5.1.0", latest_version="5.1.0",
            latest_tag="v5.1.0", channel="beta",
        )
        assert "up to date" in UpdateChecker().announcement(info)

    def test_announcement_offline(self):
        checker = UpdateChecker(fetch=FakeFetch(default=(0, "")))
        checker.check_quiet()
        line = checker.announcement(None)
        assert "\n" not in line
        assert "unavailable" in line.lower()

    def test_update_info_summary_and_str(self):
        info = UpdateInfo(
            current_version="5.1.0", latest_version="5.2.0", latest_tag="v5.2.0",
            channel="beta", download_url="https://example.invalid/app.exe",
            release_url="https://example.invalid/tag/v5.2.0",
            is_newer=True, asset_names=["app.exe", "app.tar.gz"],
        )
        summary = info.summary()
        assert "5.1.0" in summary and "5.2.0" in summary
        assert "app.exe" in summary
        text = str(info)
        assert "v5.2.0" in text
        assert "beta" in text

    def test_check_for_updates_with_injected_fetch(self):
        release = make_release("v6.0.0-beta.1", prerelease=True)
        fetcher = FakeFetch({LIST_URL: (200, json.dumps([release]))})
        info = updater.check_for_updates(fetch=fetcher)
        assert info is not None
        assert info.is_newer is True


# ---------------------------------------------------------------------------
# Single-instance lock
# ---------------------------------------------------------------------------

class TestSingleInstance:

    def test_acquire_and_release(self, tmp_path):
        path = tmp_path / "desktop.lock"
        lock = singleinstance.InstanceLock(path=path)
        assert lock.held is False
        assert lock.acquire() is True
        assert lock.held is True
        assert path.exists()
        lock.release()
        assert lock.held is False
        assert not path.exists()

    def test_lock_file_contains_pid(self, tmp_path):
        path = tmp_path / "desktop.lock"
        lock = singleinstance.InstanceLock(path=path)
        lock.acquire()
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        assert first_line == str(os.getpid())
        lock.release()

    def test_second_lock_refuses(self, tmp_path):
        path = tmp_path / "desktop.lock"
        first = singleinstance.InstanceLock(path=path)
        second = singleinstance.InstanceLock(path=path)
        assert first.acquire() is True
        assert second.acquire() is False
        assert second.held is False
        first.release()

    def test_reacquire_after_release(self, tmp_path):
        path = tmp_path / "desktop.lock"
        lock = singleinstance.InstanceLock(path=path)
        assert lock.acquire() is True
        lock.release()
        assert lock.acquire() is True
        lock.release()

    def test_stale_lock_taken_over_dead_pid(self, tmp_path):
        path = tmp_path / "desktop.lock"
        path.write_text("999999999\n0\n", encoding="utf-8")
        if os.name == "nt":
            # Windows has no PID probe (_pid_alive is conservatively True),
            # so staleness there comes from file age: backdate the lock.
            old = time.time() - (singleinstance.STALE_AFTER_SECONDS + 3600)
            os.utime(str(path), (old, old))
        lock = singleinstance.InstanceLock(path=path)
        assert lock.acquire() is True  # PID cannot exist -> stale
        lock.release()

    def test_stale_lock_taken_over_old_garbage(self, tmp_path):
        path = tmp_path / "desktop.lock"
        path.write_text("not-a-pid\n", encoding="utf-8")
        old = time.time() - (singleinstance.STALE_AFTER_SECONDS + 3600)
        os.utime(str(path), (old, old))
        lock = singleinstance.InstanceLock(path=path, stale_after=3600)
        assert lock.acquire() is True
        lock.release()

    def test_fresh_garbage_lock_is_kept(self, tmp_path):
        path = tmp_path / "desktop.lock"
        path.write_text("garbage\n", encoding="utf-8")
        lock = singleinstance.InstanceLock(path=path)
        assert lock.acquire() is False  # unknown owner, fresh file

    @pytest.mark.skipif(os.name == "nt", reason="POSIX os.kill(pid, 0) probing")
    def test_live_pid_refuses(self, tmp_path):
        path = tmp_path / "desktop.lock"
        path.write_text("{0}\n{1}\n".format(os.getpid(), int(time.time())), encoding="utf-8")
        lock = singleinstance.InstanceLock(path=path)
        assert lock.acquire() is False

    def test_lock_info_reads_pid_and_age(self, tmp_path):
        path = tmp_path / "desktop.lock"
        path.write_text("999999999\n", encoding="utf-8")
        info = singleinstance.lock_info(path)
        assert info is not None
        assert info["pid"] == 999999999
        assert info["age_seconds"] >= 0
        assert info["path"] == str(path)
        if os.name != "nt":
            assert info["alive"] is False

    def test_lock_info_missing_file(self, tmp_path):
        assert singleinstance.lock_info(tmp_path / "nope.lock") is None

    def test_lock_info_unreadable_pid(self, tmp_path):
        path = tmp_path / "desktop.lock"
        path.write_text("hello\n", encoding="utf-8")
        info = singleinstance.lock_info(path)
        assert info["pid"] is None
        assert info["alive"] is False

    def test_context_manager_releases(self, tmp_path):
        path = tmp_path / "desktop.lock"
        with singleinstance.InstanceLock(path=path) as lock:
            assert lock.held is True
        assert lock.held is False
        assert not path.exists()

    def test_context_manager_raises_when_refused(self, tmp_path):
        path = tmp_path / "desktop.lock"
        first = singleinstance.InstanceLock(path=path)
        assert first.acquire() is True
        with pytest.raises(RuntimeError), singleinstance.InstanceLock(path=path):
            pass  # pragma: no cover - never reached
        first.release()

    def test_release_without_acquire_is_noop(self, tmp_path):
        lock = singleinstance.InstanceLock(path=tmp_path / "desktop.lock")
        lock.release()  # must not raise
        assert lock.held is False

    def test_double_release_safe(self, tmp_path):
        path = tmp_path / "desktop.lock"
        lock = singleinstance.InstanceLock(path=path)
        lock.acquire()
        lock.release()
        lock.release()
        assert not path.exists()

    def test_stale_lock_path_classmethod(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OBSCURALENS_CONFIG_DIR", str(tmp_path))
        assert singleinstance.InstanceLock.stale_lock_path() == (
            tmp_path / "desktop.lock"
        )

    def test_default_path_respects_config_dir_env(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OBSCURALENS_CONFIG_DIR", str(tmp_path))
        lock = singleinstance.InstanceLock()
        assert lock.path == tmp_path / "desktop.lock"

    def test_write_url_and_lock_url(self, tmp_path):
        path = tmp_path / "desktop.lock"
        lock = singleinstance.InstanceLock(path=path)
        lock.acquire()
        lock.write_url("http://127.0.0.1:8123/")
        assert singleinstance.lock_url(path) == "http://127.0.0.1:8123/"
        lock.release()
        assert singleinstance.lock_url(path) == ""

    def test_lock_url_ignores_non_url_files(self, tmp_path):
        path = tmp_path / "desktop.lock"
        path.write_text("123\n456\njust some words\n", encoding="utf-8")
        assert singleinstance.lock_url(path) == ""


# ---------------------------------------------------------------------------
# Launcher helpers
# ---------------------------------------------------------------------------

class TestLauncherHelpers:

    def test_launch_options_defaults(self):
        options = LaunchOptions()
        assert options.host == "127.0.0.1"
        assert options.port == 8000
        assert options.port_range == (8000, 8020)
        assert options.no_browser is False
        assert options.open_delay == 1.0
        assert options.timeout_ready == 15.0
        assert options.single_instance is True
        assert options.browser is None
        assert options.resolved_channel() == "beta"

    def test_launch_options_overrides(self):
        options = LaunchOptions(
            host="0.0.0.0", port=9100, port_range=(9100, 9110), no_browser=True,
            open_delay=0.25, timeout_ready=3.0, channel="stable",
            single_instance=False, browser="firefox",
        )
        assert options.host == "0.0.0.0"
        assert options.port == 9100
        assert options.port_range == (9100, 9110)
        assert options.no_browser is True
        assert options.open_delay == 0.25
        assert options.timeout_ready == 3.0
        assert options.channel == "stable"
        assert options.resolved_channel() == "stable"
        assert options.single_instance is False
        assert options.browser == "firefox"

    def test_find_free_port_skips_busy_port(self):
        busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        try:
            found = launcher.find_free_port("127.0.0.1", port, 25)
        finally:
            busy.close()
        assert found is not None
        assert found != port
        verify = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            verify.bind(("127.0.0.1", found))
        finally:
            verify.close()

    def test_find_free_port_none_when_sockets_broken(self, monkeypatch):
        class BrokenSocket:
            def __init__(self, *args, **kwargs):
                raise OSError("sockets disabled")

        class FakeSocketModule:
            AF_INET = 2
            SOCK_STREAM = 1
            socket = BrokenSocket

        monkeypatch.setattr(launcher, "socket", FakeSocketModule)
        assert launcher.find_free_port("127.0.0.1", 8000, 5) is None

    def test_port_open_true_for_bound_socket(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            assert launcher.port_open("127.0.0.1", port) is True
        finally:
            server.close()

    def test_port_open_false_for_closed_port(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        assert launcher.port_open("127.0.0.1", dead) is False

    def test_wait_until_ready_injected_probe_immediate(self):
        calls = []

        def probe(url):
            calls.append(url)
            return True

        assert launcher.wait_until_ready("127.0.0.1", 8123, probe=probe) is True
        assert calls == ["http://127.0.0.1:8123/api/stats"]

    def test_wait_until_ready_times_out(self):
        start = time.monotonic()
        result = launcher.wait_until_ready(
            "127.0.0.1", 8123, probe=lambda url: False, timeout=0.3, interval=0.05
        )
        assert result is False
        assert time.monotonic() - start >= 0.25

    def test_wait_until_ready_default_probe_offline(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        result = launcher.wait_until_ready(
            "127.0.0.1", dead, timeout=0.5, interval=0.1
        )
        assert result is False

    def test_open_browser_disabled_by_env(self, monkeypatch):
        monkeypatch.delenv("OBSCURALENS_NO_BROWSER", raising=False)
        monkeypatch.setenv("OBSCURALENS_NO_BROWSER", "1")
        assert launcher.open_browser("http://127.0.0.1:9/") is False
        monkeypatch.setenv("OBSCURALENS_NO_BROWSER", "yes")
        assert launcher.open_browser("http://127.0.0.1:9/") is False

    def test_open_browser_uses_webbrowser_module(self, monkeypatch):
        opened = []

        class FakeWebbrowser:
            def open(self, url, new=0, autoraise=True):
                opened.append((url, new))
                return True

            def get(self, name):
                raise RuntimeError("no named browsers")

        monkeypatch.delenv("OBSCURALENS_NO_BROWSER", raising=False)
        monkeypatch.setitem(sys.modules, "webbrowser", FakeWebbrowser())
        assert launcher.open_browser("http://127.0.0.1:9/") is True
        assert opened == [("http://127.0.0.1:9/", 2)]

    def test_open_browser_named_browser(self, monkeypatch):
        opened = []

        class FakeController:
            def open(self, url, new=0, autoraise=True):
                opened.append(url)
                return True

        class FakeWebbrowser:
            def open(self, url, new=0, autoraise=True):
                raise AssertionError("default browser must not be used")

            def get(self, name):
                if name == "firefox":
                    return FakeController()
                raise RuntimeError("unknown browser")

        monkeypatch.delenv("OBSCURALENS_NO_BROWSER", raising=False)
        monkeypatch.setitem(sys.modules, "webbrowser", FakeWebbrowser())
        assert launcher.open_browser("http://127.0.0.1:9/", "firefox") is True
        assert opened == ["http://127.0.0.1:9/"]

    def test_open_browser_unknown_browser_name(self, monkeypatch):
        class FakeWebbrowser:
            def open(self, url, new=0, autoraise=True):
                return True

            def get(self, name):
                raise RuntimeError("no such browser")

        monkeypatch.delenv("OBSCURALENS_NO_BROWSER", raising=False)
        monkeypatch.setitem(sys.modules, "webbrowser", FakeWebbrowser())
        assert launcher.open_browser("http://127.0.0.1:9/", "mosaic") is False

    def test_open_browser_import_error(self, monkeypatch):
        monkeypatch.delenv("OBSCURALENS_NO_BROWSER", raising=False)
        monkeypatch.setitem(sys.modules, "webbrowser", None)
        assert launcher.open_browser("http://127.0.0.1:9/") is False

    def test_build_server_missing_uvicorn(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "uvicorn", None)
        server, message = launcher.build_server("127.0.0.1", 8123)
        assert server is None
        assert 'pip install "obscuralens[web]"' in message
        assert "releases" in message

    def test_build_server_missing_fastapi(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "fastapi", None)
        server, message = launcher.build_server("127.0.0.1", 8123)
        assert server is None
        assert "web" in message

    @pytest.mark.skipif(
        not _web_stack_available(),
        reason="web stack (fastapi/uvicorn + obscuralens.web) not importable",
    )
    def test_build_server_success(self):
        server, message = launcher.build_server("127.0.0.1", 0)
        assert message == ""
        assert server is not None
        assert hasattr(server, "should_exit")


# ---------------------------------------------------------------------------
# Launcher flow (fully faked runtime)
# ---------------------------------------------------------------------------

class FakeServer:
    def __init__(self):
        self.should_exit = False
        self.ran = False

    def run(self):
        self.ran = True


class FakeTimer:
    def __init__(self, delay, function, args=()):
        self.function = function
        self.args = args

    def start(self):
        self.function(*self.args)

    def cancel(self):
        pass


class FakeThread:
    def __init__(self, target=None, args=(), name=None, daemon=None):
        self._target = target
        self._args = args
        self.daemon = daemon
        self.started = False

    def start(self):
        self.started = True
        if self._target:
            self._target(*self._args)

    def is_alive(self):
        return False

    def join(self, timeout=None):
        return None


class StopNowEvent:
    """Event whose wait() raises KeyboardInterrupt like a real Ctrl+C."""

    def wait(self, timeout=None):
        raise KeyboardInterrupt()

    def is_set(self):
        return False


class FakeThreadingModule:
    Timer = FakeTimer
    Thread = FakeThread
    Event = staticmethod(lambda: StopNowEvent())


class TestLauncherFlow:

    def test_launch_full_flow_graceful_shutdown(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("OBSCURALENS_CONFIG_DIR", str(tmp_path))
        server = FakeServer()
        monkeypatch.setattr(launcher, "threading", FakeThreadingModule)
        monkeypatch.setattr(
            launcher, "find_free_port", lambda host, start, attempts=21: 8123
        )
        monkeypatch.setattr(
            launcher, "build_server", lambda host, port: (server, "")
        )
        monkeypatch.setattr(launcher, "wait_until_ready", lambda *a, **k: True)

        result = launcher.launch(LaunchOptions(no_browser=True))

        assert result == 0
        assert server.ran is True
        assert server.should_exit is True
        out = capsys.readouterr().out
        assert "Listening on http://127.0.0.1:8123" in out
        assert "Ctrl+C" in out
        assert "stopped" in out
        assert not singleinstance.default_lock_path().exists()

    def test_launch_already_running_exits_zero(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("OBSCURALENS_CONFIG_DIR", str(tmp_path))
        lock = singleinstance.InstanceLock()
        assert lock.acquire() is True
        lock.write_url("http://127.0.0.1:8123/")
        try:
            result = launcher.launch(LaunchOptions(single_instance=True))
        finally:
            lock.release()
        assert result == 0
        out = capsys.readouterr().out
        assert "already running" in out
        assert "http://127.0.0.1:8123" in out

    def test_launch_reports_missing_web_stack(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("OBSCURALENS_CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr(
            launcher, "build_server", lambda host, port: (None, "web extra missing")
        )
        result = launcher.launch(LaunchOptions(single_instance=True))
        assert result == 1
        out = capsys.readouterr().out
        assert "web extra missing" in out
        assert not singleinstance.default_lock_path().exists()

    def test_launch_fails_when_no_port_is_free(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("OBSCURALENS_CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr(launcher, "find_free_port", lambda *a, **k: None)
        result = launcher.launch(LaunchOptions(single_instance=True))
        assert result == 1
        out = capsys.readouterr().out
        assert "No free port" in out
        assert not singleinstance.default_lock_path().exists()

    def test_launch_without_single_instance_skips_lock(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OBSCURALENS_CONFIG_DIR", str(tmp_path))
        server = FakeServer()
        monkeypatch.setattr(launcher, "threading", FakeThreadingModule)
        monkeypatch.setattr(
            launcher, "find_free_port", lambda host, start, attempts=21: 8124
        )
        monkeypatch.setattr(
            launcher, "build_server", lambda host, port: (server, "")
        )
        monkeypatch.setattr(launcher, "wait_until_ready", lambda *a, **k: True)
        result = launcher.launch(
            LaunchOptions(no_browser=True, single_instance=False)
        )
        assert result == 0
        # no lock file was ever created
        assert not (tmp_path / "desktop.lock").exists()

    def test_main_version(self, capsys):
        assert launcher.main(["--version"]) == 0
        out = capsys.readouterr().out
        assert PACKAGE_VERSION in out
        assert "Desktop" in out
        assert "beta" in out

    def test_main_diagnostics(self, capsys):
        assert launcher.main(["--diagnostics"]) == 0
        out = capsys.readouterr().out
        assert "Python" in out
        assert "-- Dependencies" in out

    def test_main_check_update_offline(self, monkeypatch, capsys):
        monkeypatch.setattr(updater.UpdateChecker, "check", lambda self: None)
        assert launcher.main(["--check-update"]) == 0
        out = capsys.readouterr().out
        assert "Could not check for updates" in out

    def test_main_check_update_available(self, monkeypatch, capsys):
        info = UpdateInfo(
            current_version="5.1.0", latest_version="5.2.0", latest_tag="v5.2.0",
            channel="beta", release_url="https://github.com/x/tag/v5.2.0", is_newer=True,
        )
        monkeypatch.setattr(updater.UpdateChecker, "check", lambda self: info)
        assert launcher.main(["--check-update"]) == 0
        out = capsys.readouterr().out
        assert "UPDATE AVAILABLE" in out
        assert "v5.2.0" in out

    def test_main_forwards_options_to_launch(self, monkeypatch):
        recorded = {}

        def fake_launch(options):
            recorded["options"] = options
            return 0

        monkeypatch.setattr(launcher, "launch", fake_launch)
        result = launcher.main(["--host", "0.0.0.0", "--port", "9100", "--no-browser"])
        assert result == 0
        options = recorded["options"]
        assert options.host == "0.0.0.0"
        assert options.port == 9100
        assert options.no_browser is True
        assert options.single_instance is True

    def test_main_defaults(self, monkeypatch):
        recorded = {}

        def fake_launch(options):
            recorded["options"] = options
            return 0

        monkeypatch.setattr(launcher, "launch", fake_launch)
        assert launcher.main([]) == 0
        options = recorded["options"]
        assert options.host == "127.0.0.1"
        assert options.port == 8000
        assert options.no_browser is False
        assert options.browser is None

    def test_main_rejects_unknown_flag(self):
        with pytest.raises(SystemExit):
            launcher.main(["--definitely-not-a-flag"])


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

class TestDiagnostics:

    def test_collect_has_sections(self):
        report = diagnostics.collect_diagnostics()
        for key in ("python", "app", "paths", "dependencies", "data_packs", "environment"):
            assert key in report
        assert "network" not in report  # offline by default

    def test_python_section_values(self):
        python = diagnostics.collect_diagnostics()["python"]
        assert python["version"] == sys.version.split()[0]
        assert python["platform"] == sys.platform
        assert python["machine"]
        assert python["executable"]

    def test_app_section_matches_package(self):
        app = diagnostics.collect_diagnostics()["app"]
        assert app["version"] == PACKAGE_VERSION
        assert app["channel"] == "beta"
        assert app["name"] == "ObscuraLens Desktop"

    def test_frozen_flag_present(self):
        report = diagnostics.collect_diagnostics()
        assert report["app"]["frozen"] is False  # plain interpreter under pytest
        assert report["app"]["exe_path"]

    def test_paths_section_keys(self):
        paths = diagnostics.collect_diagnostics()["paths"]
        assert "config_dir" in paths
        assert "database" in paths
        assert "cache" in paths

    def test_dependencies_entries_shape(self):
        dependencies = diagnostics.collect_diagnostics()["dependencies"]
        assert len(dependencies) >= 10
        for entry in dependencies:
            assert set(entry) == {"module", "importable", "version", "note"}
            assert isinstance(entry["importable"], bool)
            assert isinstance(entry["version"], str)
            assert entry["note"]
        modules = {entry["module"] for entry in dependencies}
        assert {"requests", "yaml", "jinja2", "fastapi", "uvicorn", "PyInstaller"} <= modules

    def test_render_contains_sections(self):
        text = diagnostics.render_diagnostics(diagnostics.collect_diagnostics())
        for header in ("-- Python", "-- Application", "-- Paths", "-- Dependencies",
                       "-- Data packs", "-- Environment"):
            assert header in text
        assert "fastapi" in text

    def test_render_is_ascii(self):
        report = diagnostics.collect_diagnostics()
        assert ascii_only(diagnostics.render_diagnostics(report))

    def test_render_dependency_table(self):
        dependencies = [
            {"module": "requests", "importable": True, "version": "2.31.0", "note": "core"},
            {"module": "fastapi", "importable": False, "version": "unknown", "note": "web"},
        ]
        table = diagnostics.render_dependency_table(dependencies)
        assert "requests" in table
        assert "fastapi" in table
        assert "ok" in table
        assert "missing" in table
        assert ascii_only(table)

    def test_diagnostics_report_json_roundtrip(self):
        payload = json.loads(diagnostics.diagnostics_report(as_json=True))
        assert payload["app"]["version"] == PACKAGE_VERSION
        assert payload["app"]["channel"] == "beta"
        assert isinstance(payload["dependencies"], list)
        assert "network" not in payload

    def test_diagnostics_report_default_text(self):
        text = diagnostics.diagnostics_report()
        assert "-- Python" in text
        assert PACKAGE_VERSION in text

    def test_collect_network_section(self, monkeypatch):
        monkeypatch.setattr(diagnostics, "_network_reachable", lambda timeout: False)
        report = diagnostics.collect_diagnostics(check_network=True)
        assert report["network"]["checked"] is True
        assert report["network"]["reachable"] is False
        assert report["network"]["target"] == "https://github.com"

        monkeypatch.setattr(diagnostics, "_network_reachable", lambda timeout: True)
        report = diagnostics.collect_diagnostics(check_network=True)
        assert report["network"]["reachable"] is True

    def test_check_dependency_stdlib_module(self):
        status = diagnostics.check_dependency("json", "stdlib")
        assert status.importable is True
        assert status.module == "json"
        assert status.note == "stdlib"

    def test_check_dependency_missing_module(self):
        status = diagnostics.check_dependency("definitely_not_a_module_xyz")
        assert status.importable is False
        assert status.version == "unknown"

    def test_data_packs_section(self):
        section = diagnostics.collect_diagnostics()["data_packs"]
        assert section["available"] is True
        assert section["pack_count"] >= 1
        assert section["entries_total"] >= 0
        assert isinstance(section["packs"], list)
        if section["packs"]:
            pack = section["packs"][0]
            assert {"name", "file", "entries", "bytes"} <= set(pack)

    def test_dependency_status_dataclass(self):
        status = diagnostics.DependencyStatus(
            module="x", importable=True, version="1.0", note="why"
        )
        assert status.module == "x"
        assert status.importable is True
        assert status.version == "1.0"
        assert status.note == "why"


# ---------------------------------------------------------------------------
# Package surface
# ---------------------------------------------------------------------------

class TestPackageSurface:

    def test_documented_exports_exist(self):
        for name in (
            "DESKTOP_CHANNEL", "current_channel_info", "desktop_version",
            "UpdateChecker", "UpdateInfo", "ReleaseChannel", "LaunchOptions",
            "launch", "diagnostics_report", "render_banner",
        ):
            assert hasattr(desktop_pkg, name)
        assert callable(desktop_pkg.launch)
        assert callable(desktop_pkg.current_channel_info)

    def test_all_names_resolve(self):
        for name in desktop_pkg.__all__:
            assert getattr(desktop_pkg, name, None) is not None, name

    def test_lazy_main_attribute(self):
        main = desktop_pkg.main  # triggers the module __getattr__
        assert callable(main)
        assert desktop_pkg.main is launcher.main

    def test_unknown_attribute_raises(self):
        _missing = "sentinel"
        with pytest.raises(AttributeError):
            _missing = desktop_pkg.definitely_not_an_attribute
        assert _missing == "sentinel"  # the assignment never happened

    def test_desktop_channel_matches_package(self):
        import obscuralens

        assert DESKTOP_CHANNEL == obscuralens.__desktop_channel__ == "beta"

    def test_no_module_level_web_imports(self):
        """The desktop package must stay importable without the web extra."""
        package_dir = Path(desktop_pkg.__file__).resolve().parent
        sources = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(package_dir.glob("*.py"))
        }
        assert {"__init__.py", "branding.py", "channel.py", "updater.py",
                "singleinstance.py", "launcher.py", "diagnostics.py"} <= set(sources)
        banned = ("import fastapi", "import uvicorn", "import webbrowser",
                  "from fastapi", "from uvicorn", "from webbrowser")
        for name, source in sources.items():
            for lineno, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(banned):
                    assert line.startswith((" ", "\t")), (
                        "module-level web import in {0}:{1}".format(name, lineno)
                    )
