"""
Per-platform profile extraction for username OSINT.

Turns a raw HTML response into structured profile facts: display name, bio,
follower counts, avatar, verified badge, links. Every extractor is wrapped so a
layout change degrades to "no data" instead of raising.
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _epoch_date(value: Any) -> Optional[str]:
    """Convert an epoch (seconds or milliseconds) to an ISO date string."""
    if value is None:
        return None
    try:
        stamp = float(value)
    except (TypeError, ValueError):
        return None
    if stamp > 1e12:  # milliseconds
        stamp /= 1000.0
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime('%Y-%m-%d')
    except (OverflowError, OSError, ValueError):
        return None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first(pattern: str, text: str, flags: int = re.I | re.S) -> Optional[str]:
    m = re.search(pattern, text, flags)
    if not m:
        return None
    if m.groups():
        return (m.group(1) or '').strip() or None
    return (m.group(0) or '').strip() or None


def _clean(text: Optional[str], limit: int = 300) -> Optional[str]:
    if not text:
        return None
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'&(?:amp|lt|gt|quot|#39);', lambda m: {
        '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'"
    }.get(m.group(0), ' '), text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:limit] if text else None


def _count_number(text: Optional[str]) -> Optional[int]:
    if not text:
        return None
    m = re.search(r'([\d.,]+)\s*([KMB])?', text, re.I)
    if not m:
        return None
    raw = m.group(1).replace(',', '')
    mult = {'k': 1_000, 'm': 1_000_000, 'b': 1_000_000_000}.get(
        (m.group(2) or '').lower(), 1)
    try:
        return int(float(raw) * mult)
    except ValueError:
        return None


def _meta(html: str, *names: str) -> Optional[str]:
    for name in names:
        patterns = [
            rf'<meta[^>]+property=["\']og:{name}["\'][^>]+content=["\']([^"\']+)["\']',
            rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:{name}["\']',
            rf'<meta[^>]+name=["\']{name}["\'][^>]+content=["\']([^"\']+)["\']',
            rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']{name}["\']',
        ]
        for pattern in patterns:
            m = re.search(pattern, html, re.I)
            if m and m.group(1).strip():
                return _clean(m.group(1))
    return None


def _json_ld(html: str) -> Dict[str, Any]:
    for match in re.finditer(
            r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            html, re.I | re.S):
        try:
            data = json.loads(match.group(1).strip())
        except (ValueError, TypeError):
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict):
                return item
    return {}


def _title(html: str) -> Optional[str]:
    return _clean(_first(r'<title[^>]*>(.*?)</title>', html))


# ---------------------------------------------------------------------------
# Platform extractors
# ---------------------------------------------------------------------------

def github(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    ld = _json_ld(html)

    data['name'] = _clean(ld.get('name')) or _meta(html, 'title') or _title(html)
    bio = ld.get('description') or _meta(html, 'description')
    if not bio:
        bio = _first(r'<div[^>]+class="[^"]*p-note[^"]*"[^>]*>(.*?)</div>', html)
    data['bio'] = _clean(bio, 400)

    avatar = _meta(html, 'image')
    if not avatar:
        avatar = _first(r'<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"', html)
    data['avatar'] = avatar

    if ld.get('sameAs'):
        data['links'] = ld['sameAs'] if isinstance(ld['sameAs'], list) else [ld['sameAs']]

    location = _first(r'<li[^>]+itemprop=["\']homeLocation["\'][^>]*>(.*?)</li>', html)
    data['location'] = _clean(location)

    repos = _first(r'<span[^>]+id=["\']profile-repos-count-title["\'][^>]*>\s*([^<]+)', html)
    if repos:
        data['public_repos'] = _count_number(repos)
    followers = _first(r'<a[^>]+href=["\']/[^"\']*/followers["\'][^>]*>\s*(?:Followers\s*)?([\d.,KMk]+)', html)
    if followers:
        data['followers'] = _count_number(followers)

    created = _first(r'<span[^>]+title=["\']Joined ([^"\']+)["\']', html) or \
        _first(r'Joined\s+([A-Za-z]+\s+\d+\s+\d+)', html)
    if created:
        data['joined'] = created

    org = _first(r'<span[^>]+itemprop=["\']worksFor["\'][^>]*>(.*?)</span>', html)
    data['company'] = _clean(org)
    return data


def reddit(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _title(html)
    ld = _json_ld(html)
    if ld.get('name'):
        data['name'] = _clean(ld['name'])
    data['bio'] = _clean(_meta(html, 'description') or ld.get('description'), 400)
    data['avatar'] = _meta(html, 'image')
    created = _first(r'<time[^>]+datetime=["\']([^"\']+)["\']', html)
    if created:
        data['created'] = created
    data['karma'] = _count_number(_first(r'([\d.,]+)\s*karma', html))
    return data


def medium(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    followers = _first(r'([\d.,]+[KMB]?)\s*followers', html)
    if followers:
        data['followers'] = _count_number(followers)
    return data


def telegram(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_first(r'<div[^>]+class="[^"]*tgme_page_title[^"]*"[^>]*>.*?<span[^>]*>(.*?)</span>', html))
    if not data['name']:
        data['name'] = _title(html)
    data['bio'] = _clean(_first(r'<div[^>]+class="[^"]*tgme_page_description[^"]*"[^>]*>(.*?)</div>', html), 400)
    subscribers = _first(r'([\d.,]+)\s*subscribers', html)
    if subscribers:
        data['subscribers'] = _count_number(subscribers)
    data['verified'] = 'tgme_page_verified' in html or 'Verified' in html
    return data


def instagram(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title', 'description'))
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    data['posts'] = _count_number(_first(r'([\d.,]+[KMB]?)\s*posts', html))
    data['followers'] = _count_number(_first(r'([\d.,]+[KMB]?)\s*followers', html))
    data['following'] = _count_number(_first(r'([\d.,]+[KMB]?)\s*following', html))
    data['verified'] = 'is_verified' in html
    return data


def twitter(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title'))
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    data['verified'] = 'Verified' in html[:4000] or 'blue_verified' in html
    return data


def tiktok(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    title = _clean(_meta(html, 'title'))
    # TikTok embeds the handle in every shell; the bare app title means nothing.
    if title and title.lower() not in ('tiktok - make your day', 'tiktok'):
        data['name'] = title
    bio = _clean(_meta(html, 'description'), 400)
    if bio and 'make your day' not in bio.lower():
        data['bio'] = bio
    data['avatar'] = _meta(html, 'image')
    data['likes'] = _count_number(_first(r'([\d.,]+[KMB]?)\s*Likes', html, re.I))
    data['following'] = _count_number(_first(r'([\d.,]+[KMB]?)\s*Following', html, re.I))
    data['followers'] = _count_number(_first(r'([\d.,]+[KMB]?)\s*Followers', html, re.I))
    data['verified'] = '"verified":true' in html.replace(' ', '')
    return data


def linkedin(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title'))
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    data['location'] = _clean(_first(r'<span[^>]+class="[^"]*topcard__flavor--location[^"]*"[^>]*>(.*?)</span>', html))
    connections = _first(r'([\d.,]+[KMB]?)\s*connections', html, re.I)
    if connections:
        data['connections'] = _count_number(connections)
    return data


def pinterest(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def twitch(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def youtube(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title'))
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    subs = _first(r'([\d.,]+[KMB]?)\s*subscribers', html, re.I)
    if subs:
        data['subscribers'] = _count_number(subs)
    videos = _first(r'([\d.,]+[KMB]?)\s*videos', html, re.I)
    if videos:
        data['videos'] = _count_number(videos)
    return data


def vimeo(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def soundcloud(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def behance(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def dribbble(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
        'shots': _count_number(_first(r'([\d.,]+[KMB]?)\s*Shots', html, re.I)),
        'followers': _count_number(_first(r'([\d.,]+[KMB]?)\s*Followers', html, re.I)),
    }


def flickr(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
        'photos': _count_number(_first(r'([\d.,]+[KMB]?)\s*Photos', html, re.I)),
    }


def deviantart(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def spotify(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


# ---------------------------------------------------------------------------
# v4.0 platform extractors
# ---------------------------------------------------------------------------

def steam(html: str) -> Dict[str, Any]:
    """Steam community profile: display name, level, location, avatar."""
    data: Dict[str, Any] = {}
    data['name'] = (
        _clean(_first(r'<span[^>]+class="[^"]*actual_persona_name[^"]*"[^>]*>(.*?)</span>', html))
        or _meta(html, 'title')
    )
    level = _first(r'<span[^>]+class="[^"]*friendPlayerLevelNum[^"]*"[^>]*>\s*(\d+)<', html)
    if level:
        data['level'] = int(level)
    location = _first(r'<img[^>]+class="flag"[^>]*>\s*([^<]+)', html)
    data['location'] = _clean(location)
    avatar = _first(r'<img[^>]+src="([^"]+)"[^>]+class="[^"]*playerAvatar[^"]*"', html)
    if not avatar:
        avatar = _meta(html, 'image')
    data['avatar'] = avatar
    data['bio'] = _clean(_meta(html, 'description'), 400)
    return data


def mastodon(html: str) -> Dict[str, Any]:
    """Mastodon (mastodon.social) public profile page."""
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    followers = _first(r'([\d.,]+)\s*[Ff]ollowers', html)
    if followers:
        data['followers'] = _count_number(followers)
    following = _first(r'([\d.,]+)\s*[Ff]ollowing', html)
    if following:
        data['following'] = _count_number(following)
    created = _first(r'<time[^>]+datetime="([^"]+)"', html)
    if created:
        data['created'] = created
    data['verified'] = 'verified' in html.lower() and 'badge' in html.lower()
    return data


def wattpad(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    followers = _first(r'([\d.,]+[KMB]?)\s*[Ff]ollowers', html)
    if followers:
        data['followers'] = _count_number(followers)
    works = _first(r'([\d.,]+[KMB]?)\s*[Ww]orks', html)
    if works:
        data['works'] = _count_number(works)
    return data


def slideshare(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    uploads = _first(r'([\d.,]+[KMB]?)\s*(?:[Ss]lide|[Uu]pload)', html)
    if uploads:
        data['uploads'] = _count_number(uploads)
    followers = _first(r'([\d.,]+[KMB]?)\s*[Ff]ollowers', html)
    if followers:
        data['followers'] = _count_number(followers)
    return data


def redbubble(html: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    designs = _first(r'([\d.,]+[KMB]?)\s*(?:[Dd]esigns?|[Ww]orks)', html)
    if designs:
        data['designs'] = _count_number(designs)
    followers = _first(r'([\d.,]+[KMB]?)\s*[Ff]ollowers', html)
    if followers:
        data['followers'] = _count_number(followers)
    return data


def hackaday(html: str) -> Dict[str, Any]:
    """Hackaday.io member profile."""
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    following = _first(r'([\d.,]+[KMB]?)\s*[Ff]ollowing', html)
    if following:
        data['following'] = _count_number(following)
    followers = _first(r'([\d.,]+[KMB]?)\s*[Ff]ollowers', html)
    if followers:
        data['followers'] = _count_number(followers)
    projects = _first(r'([\d.,]+[KMB]?)\s*(?:[Cc]reated|[Pp]rojects)', html)
    if projects:
        data['projects'] = _count_number(projects)
    return data


def lastfm(html: str) -> Dict[str, Any]:
    """Last.fm listener profile: scrobbles and join date."""
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    scrobbles = _first(r'([\d.,]+[KMB]?)\s*scrobbles', html, re.I)
    if scrobbles:
        data['scrobbles'] = _count_number(scrobbles)
    artists = _first(r'([\d.,]+[KMB]?)\s*[Aa]rtists', html)
    if artists:
        data['artists'] = _count_number(artists)
    joined = _first(r'[Ss]crobbling since ([A-Za-z]+ \d{4})', html)
    if joined:
        data['joined'] = joined
    return data


def kaggle(html: str) -> Dict[str, Any]:
    """Kaggle public profile: rank, followers, stats."""
    data: Dict[str, Any] = {}
    data['name'] = _clean(_meta(html, 'title')) or _title(html)
    data['bio'] = _clean(_meta(html, 'description'), 400)
    data['avatar'] = _meta(html, 'image')
    followers = _first(r'([\d.,]+[KMB]?)\s*[Ff]ollowers', html)
    if followers:
        data['followers'] = _count_number(followers)
    following = _first(r'([\d.,]+[KMB]?)\s*[Ff]ollowing', html)
    if following:
        data['following'] = _count_number(following)
    # Kaggle title (Expert / Master / Grandmaster) is a strong signal.
    title = _first(r'"(?:rankTitle|currentRanking)"\s*:\s*"([^"]+)"', html)
    if title:
        data['title'] = _clean(title)
    return data


def gitlab(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
        'projects': _count_number(_first(r'([\d.,]+[KMB]?)\s*Projects', html, re.I)),
    }


def bitbucket(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def snapchat(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def facebook(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def quora(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def tumblr(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def wordpress(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
    }


def blogger(html: str) -> Dict[str, Any]:
    return {
        'name': _clean(_meta(html, 'title')),
        'bio': _clean(_meta(html, 'description'), 400),
        'avatar': _meta(html, 'image'),
        'posts': _count_number(_first(r'([\d.,]+)\s*posts', html, re.I)),
    }


EXTRACTORS: Dict[str, Any] = {
    'GitHub': github,
    'Reddit': reddit,
    'Medium': medium,
    'Telegram': telegram,
    'Instagram': instagram,
    'Twitter': twitter,
    'TikTok': tiktok,
    'LinkedIn': linkedin,
    'Pinterest': pinterest,
    'Twitch': twitch,
    'YouTube': youtube,
    'Vimeo': vimeo,
    'SoundCloud': soundcloud,
    'Behance': behance,
    'Dribbble': dribbble,
    'Flickr': flickr,
    'DeviantArt': deviantart,
    'Spotify': spotify,
    'GitLab': gitlab,
    'Bitbucket': bitbucket,
    'Snapchat': snapchat,
    'Facebook': facebook,
    'Quora': quora,
    'Tumblr': tumblr,
    'WordPress': wordpress,
    'Blogger': blogger,
    # v4.0 additions
    'Steam': steam,
    'Mastodon': mastodon,
    'Wattpad': wattpad,
    'SlideShare': slideshare,
    'Redbubble': redbubble,
    'Hackaday.io': hackaday,
    'Last.fm': lastfm,
    'Kaggle': kaggle,
}


def extract(platform: str, html: str) -> Dict[str, Any]:
    """Run the extractor for a platform, dropping empty values."""
    fn = EXTRACTORS.get(platform)
    if fn is None or not html:
        return {}
    try:
        data = fn(html)
    except Exception:
        return {}
    return {k: v for k, v in data.items()
            if v is not None and v != '' and v != [] and v != {}}


# ---------------------------------------------------------------------------
# JSON API platforms
#
# These return structured data, so existence can be decided with high
# confidence instead of guessing from an HTML shell. Each entry provides:
#   api_url  - request URL template
#   url      - human-facing profile URL template
#   verdict  - callable(data) -> True (exists) / False (missing) / None (unknown)
#   extract  - callable(data) -> profile dict
# ---------------------------------------------------------------------------

def _keybase_verdict(data: Dict[str, Any]) -> Optional[bool]:
    status = data.get('status') or {}
    code = status.get('code')
    if code == 205 or status.get('name') == 'NOT_FOUND':
        return False
    if code == 0 and data.get('them'):
        return True
    return None


def _keybase_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    them = data.get('them') or []
    if not them:
        return {}
    user = them[0] or {}
    basics = user.get('basics') or {}
    profile = user.get('profile') or {}
    return {
        'name': basics.get('username_cased') or basics.get('username'),
        'full_name': profile.get('full_name'),
        'bio': profile.get('bio'),
        'location': profile.get('location'),
        'created': _epoch_date(basics.get('ctime')),
        'links': [profile['website']] if profile.get('website') else None,
    }


def _hn_verdict(data: Any) -> Optional[bool]:
    if data is None:
        return False
    if isinstance(data, dict):
        return bool(data.get('id'))
    return None


def _hn_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'name': data.get('id'),
        'bio': data.get('about'),
        'karma': data.get('karma'),
        'created': _epoch_date(data.get('created')),
        'posts': len(data.get('submitted') or []) or None,
    }


def _lichess_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    profile = data.get('profile') if isinstance(data.get('profile'), dict) else {}
    count = data.get('count') if isinstance(data.get('count'), dict) else {}
    perfs = data.get('perfs') if isinstance(data.get('perfs'), dict) else {}
    best_name, best_rating = None, None
    for game, perf in perfs.items():
        if not isinstance(perf, dict):
            continue
        rating = perf.get('rating')
        if rating and (best_rating is None or rating > best_rating):
            best_name, best_rating = game, rating

    # playTime is seconds in most responses but an object in some.
    play_time = data.get('playTime')
    if isinstance(play_time, dict):
        play_time = play_time.get('total')
    hours = round(play_time / 3600, 1) if isinstance(
        play_time, (int, float)) and play_time else None

    return {
        'name': data.get('username') or data.get('id'),
        'bio': profile.get('bio'),
        'country': profile.get('country'),
        'title': data.get('title'),
        'joined': _epoch_date(data.get('createdAt')),
        'patron': data.get('patron'),
        'games_total': count.get('all'),
        'wins': count.get('win'),
        'losses': count.get('loss'),
        'draws': count.get('draw'),
        'best_rating': f"{best_name} {best_rating}" if best_name else None,
        'play_time_hours': hours,
        'links': profile.get('links') or None,
    }


def _codeberg_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'name': data.get('full_name') or data.get('login'),
        'username': data.get('login'),
        'bio': data.get('description'),
        'location': data.get('location'),
        'avatar': data.get('avatar_url'),
        'joined': (data.get('created') or '')[:10] or None,
        'followers': data.get('followers_count'),
        'following': data.get('following_count'),
        'starred_repos': data.get('starred_repos_count'),
        'links': [data['website']] if data.get('website') else None,
    }


def _dockerhub_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'name': data.get('full_name') or data.get('orgname'),
        'username': data.get('orgname') or data.get('username'),
        'location': data.get('location'),
        'company': data.get('company'),
        'joined': (data.get('date_joined') or '')[:10] or None,
        'avatar': data.get('gravatar_url'),
        'links': [data['profile_url']] if data.get('profile_url') else None,
    }


def _devto_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'name': data.get('name'),
        'username': data.get('username'),
        'bio': data.get('summary'),
        'location': data.get('location'),
        'joined': data.get('joined_at'),
        'twitter': data.get('twitter_username'),
        'github': data.get('github_username'),
        'links': [data['website_url']] if data.get('website_url') else None,
        'avatar': data.get('profile_image'),
    }


def _chesscom_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    country = data.get('country') or ''
    links = [link for link in (data.get('url'), data.get('twitch_url')) if link]
    return {
        'name': data.get('name') or data.get('username'),
        'username': data.get('username'),
        'title': data.get('title'),
        'bio': data.get('status'),
        'location': data.get('location'),
        'country': country.rsplit('/', 1)[-1] or None,
        'followers': data.get('followers'),
        'joined': _epoch_date(data.get('joined')),
        'last_online': _epoch_date(data.get('last_online')),
        'is_streamer': data.get('is_streamer'),
        'verified': data.get('verified'),
        'avatar': data.get('avatar'),
        'links': links or None,
    }


def _api_verdict(data: Any) -> Optional[bool]:
    """Default: a valid JSON object from an endpoint that 404s for missing users."""
    if isinstance(data, dict):
        return True if data else None
    return None


API_PLATFORMS: Dict[str, Dict[str, Any]] = {
    'Keybase': {
        'api_url': 'https://keybase.io/_/api/1.0/user/lookup.json?username={}',
        'url': 'https://keybase.io/{}',
        'verdict': _keybase_verdict,
        'extract': _keybase_profile,
    },
    'HackerNews': {
        'api_url': 'https://hacker-news.firebaseio.com/v0/user/{}.json',
        'url': 'https://news.ycombinator.com/user?id={}',
        'verdict': _hn_verdict,
        'extract': _hn_profile,
    },
    'Lichess': {
        'api_url': 'https://lichess.org/api/user/{}',
        'url': 'https://lichess.org/@/{}',
        'verdict': _api_verdict,
        'extract': _lichess_profile,
    },
    'Codeberg': {
        'api_url': 'https://codeberg.org/api/v1/users/{}',
        'url': 'https://codeberg.org/{}',
        'verdict': _api_verdict,
        'extract': _codeberg_profile,
    },
    'DockerHub': {
        'api_url': 'https://hub.docker.com/v2/users/{}/',
        'url': 'https://hub.docker.com/u/{}',
        'verdict': _api_verdict,
        'extract': _dockerhub_profile,
    },
    'Dev.to': {
        'api_url': 'https://dev.to/api/users/by_username?url={}',
        'url': 'https://dev.to/{}',
        'verdict': _api_verdict,
        'extract': _devto_profile,
    },
    'Chess.com': {
        'api_url': 'https://api.chess.com/pub/player/{}',
        'url': 'https://www.chess.com/member/{}',
        'verdict': _api_verdict,
        'extract': _chesscom_profile,
    },
}


def api_profile(platform: str, data: Any) -> Dict[str, Any]:
    """Extract profile facts from an API payload, never raising."""
    spec = API_PLATFORMS.get(platform)
    if spec is None or not isinstance(data, dict):
        return {}
    try:
        profile = spec['extract'](data) or {}
    except Exception:
        return {}
    return {k: v for k, v in profile.items()
            if v is not None and v != '' and v != [] and v != {}}
