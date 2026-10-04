"""
Username Tracker Module

Honest three-state detection: found / not_found / unknown.

Two classes of platform:
  * JSON API platforms (Keybase, HackerNews, Lichess, Codeberg, DockerHub,
    Dev.to, Chess.com) where the service itself confirms existence - these get
    high confidence.
  * HTML platforms where many sites serve an identical JavaScript shell for
    existing and missing accounts. A bare HTTP 200 is never enough there: a hit
    requires positive profile evidence or a platform-specific signal. Bot walls
    (403/429/999) and network errors are "unknown", never a hit or a miss.
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..database import db
from ..health import health
from ..utils.http_client import http
from .username_sources import API_PLATFORMS, HTML_VERDICT_RULES, api_profile, extract, generic_profile
from .username_sources import HTML_PLATFORMS as EXTRA_HTML_PLATFORMS


@dataclass
class UsernameResult:
    """Username check result for one platform."""
    platform: str = ""
    url: str = ""
    exists: bool = False          # True only on a confident hit
    status: str = "unknown"       # found | not_found | unknown
    confidence: str = "low"       # high | medium | low
    reason: str = ""              # why this verdict was reached
    status_code: int = 0
    response_time: float = 0.0
    profile: dict = field(default_factory=dict)
    error: str = ""


# Platforms where a plain 200-vs-404 status split was verified empirically.
# Missing accounts answer HTTP 404 (handled above); a bare 200 on the profile
# URL is therefore a hit - the Sherlock-style signal. Since v5.2 this set is
# actually consulted by _verdict (it used to be declared but dead code).
STATUS_RELIABLE = {
    'Dribbble', 'Flickr', 'Snapchat', 'SoundCloud',
    'Twitter', 'Vimeo', 'YouTube',
    # v5.2 additions - every split re-verified live before shipping:
    'Gitee', 'Hugging Face', 'GoodReads', 'SourceForge', 'Strava',
    'MyAnimeList', 'RubyGems', 'Issuu', 'Itch.io', 'Launchpad',
    'Sketchfab', 'SpeakerDeck', 'About.me', 'Credly', 'Disqus',
    'Instructables', 'MyMiniFactory', 'Scratch', 'TradingView',
    'WakaTime', 'Geocaching', 'HackMD', 'Crowdin', 'Freesound',
    'GitBook', 'HubPages', 'IFTTT', 'Kongregate', 'Laracast',
    'Memrise', 'OpenGameArt', 'Pokemon Showdown', 'Tenor',
    'TheMovieDB', 'Windy', 'YouPic', 'Exophase', 'write.as',
    'Bitwarden Forum', 'Ionic Forum', 'n8n Community', 'Rclone Forum',
    'Joplin Forum', 'Ubuntu Discourse', 'Rust Users', 'Blender Artists',
    'Linktree', 'AtCoder', 'MyDramaList', '9GAG', 'VK', 'OK.ru',
    'HackerOne', 'LinuxFR', 'Fosstodon', 'Pixelfed',
}

# Generic "this account does not exist" markers, matched case-insensitively.
NOT_FOUND_MARKERS = (
    "user profile not found",
    "this account doesn't exist",
    "this account does not exist",
    "account doesn't exist",
    "couldn't find this account",
    "could not find this account",
    "page not found",
    "content isn't available",
    "sorry, this page isn't available",
    "nobody on reddit",
    "user not found",
    "profile not found",
    "the page you were looking",
    "does not exist",
    "the specified profile could not be found",
    "user hasn't logged in",
    "account has been suspended",
)

# Bot-wall / rate-limit statuses: the response says nothing about the account.
BLOCKED_STATUSES = {400, 401, 403, 429, 999}

# Fields that count as positive profile evidence (a generic <title> alone
# does not, because JS shells all carry one).
EVIDENCE_FIELDS = {
    'bio', 'followers', 'following', 'subscribers', 'likes', 'videos',
    'shots', 'photos', 'projects', 'posts', 'connections', 'karma',
    'avatar', 'location', 'company', 'links', 'joined', 'created',
    'verified',
}

# HTML platforms checked by scraping their public profile pages.
HTML_PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{}"},
    {"name": "Twitter", "url": "https://twitter.com/{}"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}"},
    {"name": "YouTube", "url": "https://www.youtube.com/@{}"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}"},
    {"name": "Medium", "url": "https://medium.com/@{}"},
    {"name": "Quora", "url": "https://www.quora.com/profile/{}"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}"},
    {"name": "Behance", "url": "https://www.behance.net/{}"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}"},
    {"name": "Telegram", "url": "https://t.me/{}"},
    {"name": "GitLab", "url": "https://gitlab.com/{}"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{}"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com"},
    {"name": "WordPress", "url": "https://{}.wordpress.com"},
    {"name": "Blogger", "url": "https://{}.blogspot.com"},
    # v4.0 additions ------------------------------------------------------
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}"},
    {"name": "Mastodon", "url": "https://mastodon.social/@{}"},
    {"name": "Wattpad", "url": "https://www.wattpad.com/user/{}"},
    {"name": "SlideShare", "url": "https://www.slideshare.net/{}"},
    {"name": "Redbubble", "url": "https://www.redbubble.com/people/{}/shop"},
    {"name": "Hackaday.io", "url": "https://hackaday.io/{}"},
    {"name": "Last.fm", "url": "https://www.last.fm/user/{}"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{}"},
    # v5.2 additions ------------------------------------------------------
    # Each platform below was probed live before being added: an existing
    # account answers HTTP 200 and a missing one answers 404, so they ride
    # the STATUS_RELIABLE fast path above. Platforms that bot-wall every
    # scripted client (Codepen, Codewars, LeetCode, npm, ArtStation, Trakt,
    # osu!, MixCloud, Newgrounds, Rumble, ProductHunt, Untappd, Discogs,
    # Wikipedia, Fandom, Imgur, Speedrun.com and others) were tested and
    # deliberately NOT added - they could only ever report "unknown".
    {"name": "Gitee", "url": "https://gitee.com/{}"},
    {"name": "Hugging Face", "url": "https://huggingface.co/{}"},
    {"name": "GoodReads", "url": "https://www.goodreads.com/{}"},
    {"name": "SourceForge", "url": "https://sourceforge.net/u/{}/profile"},
    {"name": "Strava", "url": "https://www.strava.com/athletes/{}"},
    {"name": "MyAnimeList", "url": "https://myanimelist.net/profile/{}"},
    {"name": "RubyGems", "url": "https://rubygems.org/profiles/{}"},
    {"name": "Issuu", "url": "https://issuu.com/{}"},
    {"name": "Itch.io", "url": "https://{}.itch.io"},
    {"name": "Launchpad", "url": "https://launchpad.net/~{}"},
    {"name": "Sketchfab", "url": "https://sketchfab.com/{}"},
    {"name": "SpeakerDeck", "url": "https://speakerdeck.com/{}"},
    {"name": "About.me", "url": "https://about.me/{}"},
    {"name": "Credly", "url": "https://www.credly.com/users/{}"},
    {"name": "Disqus", "url": "https://disqus.com/by/{}"},
    {"name": "Instructables", "url": "https://www.instructables.com/member/{}/"},
    {"name": "MyMiniFactory", "url": "https://www.myminifactory.com/users/{}"},
    {"name": "Scratch", "url": "https://scratch.mit.edu/users/{}/"},
    {"name": "TradingView", "url": "https://www.tradingview.com/u/{}/"},
    {"name": "WakaTime", "url": "https://wakatime.com/@{}"},
    {"name": "Geocaching", "url": "https://www.geocaching.com/profile/?u={}"},
    {"name": "HackMD", "url": "https://hackmd.io/@{}"},
    {"name": "Crowdin", "url": "https://crowdin.com/profile/{}"},
    {"name": "Freesound", "url": "https://freesound.org/people/{}/"},
    {"name": "GitBook", "url": "https://{}.gitbook.io/"},
    {"name": "HubPages", "url": "https://hubpages.com/@{}"},
    {"name": "IFTTT", "url": "https://ifttt.com/p/{}"},
    {"name": "Kongregate", "url": "https://www.kongregate.com/accounts/{}"},
    {"name": "Laracast", "url": "https://laracasts.com/@{}"},
    {"name": "Memrise", "url": "https://www.memrise.com/user/{}/"},
    {"name": "OpenGameArt", "url": "https://opengameart.org/users/{}"},
    {"name": "Pokemon Showdown", "url": "https://pokemonshowdown.com/users/{}"},
    {"name": "Tenor", "url": "https://tenor.com/users/{}"},
    {"name": "TheMovieDB", "url": "https://www.themoviedb.org/u/{}"},
    {"name": "Windy", "url": "https://community.windy.com/user/{}"},
    {"name": "YouPic", "url": "https://youpic.com/photographer/{}/"},
    {"name": "Exophase", "url": "https://www.exophase.com/user/{}/"},
    {"name": "write.as", "url": "https://write.as/{}"},
    {"name": "Bitwarden Forum", "url": "https://community.bitwarden.com/u/{}"},
    {"name": "Ionic Forum", "url": "https://forum.ionicframework.com/u/{}"},
    {"name": "n8n Community", "url": "https://community.n8n.io/u/{}"},
    {"name": "Rclone Forum", "url": "https://forum.rclone.org/u/{}"},
    {"name": "Joplin Forum", "url": "https://discourse.joplinapp.org/u/{}"},
    {"name": "Ubuntu Discourse", "url": "https://discourse.ubuntu.com/u/{}"},
    {"name": "Rust Users", "url": "https://users.rust-lang.org/u/{}"},
    {"name": "Blender Artists", "url": "https://blenderartists.org/u/{}"},
    {"name": "Linktree", "url": "https://linktr.ee/{}"},
    {"name": "AtCoder", "url": "https://atcoder.jp/users/{}"},
    {"name": "MyDramaList", "url": "https://www.mydramalist.com/profile/{}"},
    {"name": "9GAG", "url": "https://9gag.com/u/{}"},
    {"name": "VK", "url": "https://vk.com/{}"},
    {"name": "OK.ru", "url": "https://ok.ru/{}"},
    {"name": "HackerOne", "url": "https://hackerone.com/{}"},
    {"name": "LinuxFR", "url": "https://linuxfr.org/users/{}"},
    {"name": "Fosstodon", "url": "https://fosstodon.org/@{}"},
    {"name": "Pixelfed", "url": "https://pixelfed.social/{}"},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}"},
]


def _build_platforms() -> List[Dict[str, Any]]:
    """Combine HTML and API platforms into one lookup table."""
    # v5.2: the Patreon/Etsy/Substack/Replit entries that username_sources
    # has always declared are actually unioned in here now (they used to be
    # documented but never scanned - dead registry).
    platforms: List[Dict[str, Any]] = [
        dict(platform, api=False)
        for platform in HTML_PLATFORMS + EXTRA_HTML_PLATFORMS
    ]
    for name, spec in API_PLATFORMS.items():
        platforms.append({'name': name, 'url': spec['url'], 'api': True})
    return platforms


class UsernameTracker:
    """Username Tracker with honest three-state detection."""

    def __init__(self):
        self.timeout = config.app_config.request_timeout
        self.platforms = _build_platforms()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track(self, username: str, deep: bool = True,
              platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan every platform for a username.

        Args:
            username: Username to track
            deep: Extract profile details on hits. False = fast sweep.
            platforms: Optional list of platform names to restrict the scan.

        Returns:
            Results with found / not_found / unknown buckets.
        """
        selected = self.platforms
        if platforms:
            wanted = [p.strip().lower() for p in platforms if p and p.strip()]
            selected = [
                p for p in self.platforms
                if any(w == p['name'].lower() or w in p['name'].lower()
                       for w in wanted)
            ]

        result: Dict[str, Any] = {
            'username': username,
            'results': [],
            'found_count': 0,
            'not_found_count': 0,
            'unknown_count': 0,
            'total_checked': 0,
            'total_fields': 0,
            'deep': deep,
            'platforms_checked': [p['name'] for p in selected],
            'success': True,
            'errors': [],
        }

        workers = min(12, max(1, config.app_config.max_workers))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(self._check_platform, p, username, deep): p
                for p in selected
            }
            for future in as_completed(future_map):
                platform = future_map[future]
                try:
                    check = future.result()
                    result['results'].append(asdict(check))
                    result['total_checked'] += 1
                    result['total_fields'] += len(check.profile)
                    if check.status == 'found':
                        result['found_count'] += 1
                    elif check.status == 'not_found':
                        result['not_found_count'] += 1
                    else:
                        result['unknown_count'] += 1
                except Exception as e:
                    result['errors'].append(f"{platform['name']}: {type(e).__name__}")
                    result['unknown_count'] += 1

        result['results'].sort(key=lambda x: x['platform'])

        # Feed the source-health tracker: a username platform 'works' when it
        # returned a definite verdict (found / not_found).
        platform_status = {
            record['platform']: {
                'ok': record['status'] in ('found', 'not_found'),
                'error': record.get('error') or '',
            }
            for record in result['results']
        }
        health.record_batch('username', platform_status)

        db.save_query('username', username, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else "")
        return result

    def batch_track(self, usernames: list, deep: bool = True) -> list:
        """Scan multiple usernames (sequentially; each scan is parallel)."""
        return [self.track(u.strip(), deep=deep) for u in usernames if u.strip()]

    # ------------------------------------------------------------------
    # Per-platform check
    # ------------------------------------------------------------------

    def _check_platform(self, platform: Dict[str, Any], username: str,
                        deep: bool) -> UsernameResult:
        if platform.get('api'):
            return self._check_api_platform(platform, username, deep)

        name = platform['name']
        url = platform['url'].format(username)
        started = time.time()

        try:
            response = http.get(url, allow_redirects=True)
        except Exception as e:
            return UsernameResult(
                platform=name, url=url, exists=False, status='unknown',
                confidence='low', reason='network error',
                status_code=0, response_time=round(time.time() - started, 2),
                error=type(e).__name__,
            )

        elapsed = round(time.time() - started, 2)
        status, confidence, reason = self._verdict(name, username, response)

        profile: Dict[str, Any] = {}
        if status == 'found' and deep and response.text:
            profile = extract(name, response.text)
            if not profile:
                # v5.2: platforms without a bespoke extractor still get a
                # light Open-Graph profile in deep scans. This only enriches
                # the report - it never feeds the verdict (og: meta tags on
                # JS shells would otherwise fabricate hits).
                profile = generic_profile(response.text)

        return UsernameResult(
            platform=name, url=url, exists=(status == 'found'),
            status=status, confidence=confidence, reason=reason,
            status_code=response.status_code, response_time=elapsed,
            profile=profile,
        )

    def _check_api_platform(self, platform: Dict[str, Any], username: str,
                            deep: bool) -> UsernameResult:
        """Check a platform through its JSON API: high-confidence verdicts."""
        name = platform['name']
        spec = API_PLATFORMS[name]
        # v5.2: 'url' and 'api_url' may be callables so a platform can build
        # its URLs from the username context (Bluesky resolves the actor
        # handle differently for dotted and bare usernames).
        profile_url = (spec['url'](username) if callable(spec['url'])
                       else spec['url'].format(username))
        api_url = (spec['api_url'](username) if callable(spec['api_url'])
                   else spec['api_url'].format(username))
        started = time.time()

        ok, data, err = http.get_json(api_url)
        elapsed = round(time.time() - started, 2)

        if not ok:
            # v5.2: some APIs answer "no such account" with a non-404 status
            # (Bluesky replies 400 with a JSON error body); a per-platform
            # err_verdicts map declares those transport errors as misses.
            err_map = spec.get('err_verdicts') or {}
            if err == 'not found':
                return UsernameResult(
                    platform=name, url=profile_url, exists=False,
                    status='not_found', confidence='high',
                    reason='api returned 404 (no such account)',
                    status_code=404, response_time=elapsed,
                )
            if err_map.get(err) is False:
                return UsernameResult(
                    platform=name, url=profile_url, exists=False,
                    status='not_found', confidence='high',
                    reason=f'api answered no-such-account ({err})',
                    status_code=400, response_time=elapsed,
                )
            return UsernameResult(
                platform=name, url=profile_url, exists=False,
                status='unknown', confidence='low',
                reason=f'api error: {err or "unknown"}',
                status_code=0, response_time=elapsed, error=err,
            )

        try:
            verdict = spec['verdict'](data)
        except Exception:
            verdict = None

        if verdict is True:
            profile = api_profile(name, data) if deep else {}
            return UsernameResult(
                platform=name, url=profile_url, exists=True,
                status='found', confidence='high',
                reason='api confirms the account exists',
                status_code=200, response_time=elapsed, profile=profile,
            )
        if verdict is False:
            return UsernameResult(
                platform=name, url=profile_url, exists=False,
                status='not_found', confidence='high',
                reason='api reports no such account',
                status_code=200, response_time=elapsed,
            )
        return UsernameResult(
            platform=name, url=profile_url, exists=False,
            status='unknown', confidence='low',
            reason='unexpected api response',
            status_code=200, response_time=elapsed,
        )

    # ------------------------------------------------------------------
    # Verdict logic
    # ------------------------------------------------------------------

    def _verdict(self, platform: str, username: str,
                 response: Any) -> Tuple[str, str, str]:
        """
        Decide found / not_found / unknown for one response.

        Returns (status, confidence, reason).
        """
        code = response.status_code
        body = response.text or ""
        low = body.lower()

        # Network-level blocks say nothing about the account.
        if code in BLOCKED_STATUSES:
            return 'unknown', 'low', f'http {code} bot-wall, cannot determine'

        # Cloudflare / captcha interstitials.
        if (code == 403
                or ('just a moment' in low[:3000]
                    and 'cloudflare' in low[:6000])) \
                and ('cf-chl' in low or 'challenge-platform' in low):
            return 'unknown', 'low', 'captcha wall, cannot determine'

        # Explicit not-found pages.
        if code == 404:
            return 'not_found', 'high', 'http 404'

        if code in (301, 302, 303, 307, 308):
            final = (response.url or '').lower()
            if any(t in final for t in ('login', 'signup', 'signin', 'register',
                                        'error', '404', 'not-found')):
                return 'not_found', 'medium', 'redirected to login/error page'
            return 'unknown', 'low', 'redirect, ambiguous'

        if code != 200:
            return 'unknown', 'low', f'http {code}, ambiguous'

        # --- HTTP 200 from here on --------------------------------------
        if self._has_not_found_marker(low):
            return 'not_found', 'high', 'not-found marker in page'

        handler = getattr(self, f"_rule_{platform.lower()}", None)
        if handler is not None:
            verdict = handler(username, body, low, response)
            if verdict is not None:
                return verdict

        # v5.2: verdict rules registered by username_sources (Patreon, Etsy,
        # Substack, Replit, Hashnode) - same (username, body, low, response)
        # contract as the tracker rules above.
        sources_rule = HTML_VERDICT_RULES.get(platform)
        if sources_rule is not None:
            try:
                verdict = sources_rule(username, body, low, response)
            except Exception:
                verdict = None
            if verdict is not None:
                return verdict

        # Generic rule: a 200 needs positive profile evidence, otherwise the
        # page is indistinguishable from a JS shell.
        evidence = self._evidence_keys(body, platform)
        if evidence:
            return 'found', 'medium', f"profile evidence: {', '.join(evidence[:4])}"

        # v5.2: platforms whose 200-vs-404 split was verified empirically.
        # Marker checks, captcha walls and platform rules above already
        # filtered the shells, so a bare 200 here is an honest hit.
        if platform in STATUS_RELIABLE:
            return 'found', 'medium', 'verified 200-vs-404 status split'

        return 'unknown', 'low', 'http 200 but no profile evidence (JS shell?)'

    @staticmethod
    def _has_not_found_marker(low: str) -> bool:
        return any(m in low for m in NOT_FOUND_MARKERS)

    def _evidence_keys(self, body: str, platform: str) -> List[str]:
        """Profile fields the extractor found, restricted to real evidence."""
        try:
            data = extract(platform, body)
        except Exception:
            return []
        return [k for k in data if k in EVIDENCE_FIELDS and data[k]]

    # ------------------------------------------------------------------
    # Platform-specific rules (return None to fall through to generic rule)
    # ------------------------------------------------------------------

    def _rule_telegram(self, username: str, body: str, low: str,
                       response: Any) -> Optional[Tuple[str, str, str]]:
        # Real channel/group : "Telegram: View @name" + tgme_page_extra block.
        # Missing            : "Telegram: Contact @name", no extra block.
        title = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        title_text = (title.group(1).strip().lower() if title else '')
        if title_text.startswith('telegram: view @'):
            return 'found', 'high', 'channel page with member/subscriber block'
        if title_text.startswith('telegram: contact @'):
            return 'not_found', 'high', 'no such channel (contact prompt)'
        if 'tgme_page_extra' in low or 'tgme_page_title' in low:
            return 'found', 'medium', 'channel page structure present'
        return None

    def _rule_github(self, username: str, body: str, low: str,
                     response: Any) -> Optional[Tuple[str, str, str]]:
        # Missing accounts 404; existing ones carry a profile avatar + vcard.
        if 'octocat' not in low and ("couldn't find" in low or 'page could not be found' in low):
            return 'not_found', 'high', 'github 404 page'
        evidence = self._evidence_keys(body, 'GitHub')
        if evidence:
            return 'found', 'high', f"profile evidence: {', '.join(evidence[:4])}"
        return 'unknown', 'low', 'no github profile block found'

    def _rule_twitch(self, username: str, body: str, low: str,
                     response: Any) -> Optional[Tuple[str, str, str]]:
        # Real channel : og:title "Ninja - Twitch" with channel bio.
        # Missing      : og:title exactly "Twitch" + generic homepage meta.
        from .username_sources import _meta
        title = (_meta(body, 'title') or '').strip()
        if title.lower() == 'twitch':
            return 'not_found', 'high', 'twitch homepage shell, no such channel'
        if username.lower() in title.lower() and 'twitch' in title.lower():
            return 'found', 'high', f'channel title: {title[:60]}'
        evidence = self._evidence_keys(body, 'Twitch')
        # Generic homepage meta (name=Twitch + stock bio) is not evidence.
        evidence = [e for e in evidence
                    if not (e == 'bio' and 'leading video platform' in low)]
        if evidence or (username.lower() in low and 'follower' in low):
            return 'found', 'medium', f"channel evidence: {', '.join(evidence[:4])}"
        return 'unknown', 'low', 'twitch shell ambiguous'

    def _rule_twitter(self, username: str, body: str, low: str,
                      response: Any) -> Optional[Tuple[str, str, str]]:
        if 'user profile not found' in low or 'account doesn' in low:
            return 'not_found', 'high', 'x not-found page'
        evidence = self._evidence_keys(body, 'Twitter')
        if evidence:
            return 'found', 'medium', f"profile evidence: {', '.join(evidence[:4])}"
        # X serves the same shell for suspended/missing accounts.
        return 'unknown', 'low', 'no profile evidence in x shell'

    def _rule_youtube(self, username: str, body: str, low: str,
                      response: Any) -> Optional[Tuple[str, str, str]]:
        if '404 not found' in low[:5000]:
            return 'not_found', 'high', 'youtube 404 page'
        evidence = self._evidence_keys(body, 'YouTube')
        if evidence:
            return 'found', 'medium', f"channel evidence: {', '.join(evidence[:4])}"
        return None

    def _rule_gitlab(self, username: str, body: str, low: str,
                     response: Any) -> Optional[Tuple[str, str, str]]:
        title = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        title_text = (title.group(1).strip() if title else '')
        if 'gitlab' in title_text.lower() and username.lower() in title_text.lower():
            return 'found', 'medium', 'gitlab user page title'
        return None

    def _rule_reddit(self, username: str, body: str, low: str,
                     response: Any) -> Optional[Tuple[str, str, str]]:
        # Old Reddit serves the same shell for everyone; never claim a hit.
        return 'unknown', 'low', 'reddit serves identical shell, use logged-in api'

    def _rule_instagram(self, username: str, body: str, low: str,
                        response: Any) -> Optional[Tuple[str, str, str]]:
        return 'unknown', 'low', 'instagram requires login, shell is identical'

    def _rule_tiktok(self, username: str, body: str, low: str,
                     response: Any) -> Optional[Tuple[str, str, str]]:
        evidence = self._evidence_keys(body, 'TikTok')
        # TikTok embeds the handle in every shell, so demand follower stats.
        if 'followers' in evidence or 'likes' in evidence:
            return 'found', 'medium', f"tiktok stats: {', '.join(evidence[:4])}"
        return 'unknown', 'low', 'tiktok shell identical without stats'

    def _rule_spotify(self, username: str, body: str, low: str,
                      response: Any) -> Optional[Tuple[str, str, str]]:
        return 'unknown', 'low', 'spotify shell identical, use authenticated api'

    def _rule_medium(self, username: str, body: str, low: str,
                     response: Any) -> Optional[Tuple[str, str, str]]:
        return 'unknown', 'low', 'medium bot-wall, cannot determine'

    def _rule_facebook(self, username: str, body: str, low: str,
                       response: Any) -> Optional[Tuple[str, str, str]]:
        return 'unknown', 'low', 'facebook requires login, cannot determine'

    def _rule_linkedin(self, username: str, body: str, low: str,
                       response: Any) -> Optional[Tuple[str, str, str]]:
        evidence = self._evidence_keys(body, 'LinkedIn')
        if evidence:
            return 'found', 'medium', f"profile evidence: {', '.join(evidence[:4])}"
        return 'unknown', 'low', 'linkedin bot-wall, cannot determine'
