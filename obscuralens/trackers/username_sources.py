"""
Per-platform profile extraction for username OSINT.

Turns a raw HTML response into structured profile facts: display name, bio,
follower counts, avatar, verified badge, links. Every extractor is wrapped so a
layout change degrades to "no data" instead of raising.
"""

import json
import re
from typing import Any, Dict, Optional

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
