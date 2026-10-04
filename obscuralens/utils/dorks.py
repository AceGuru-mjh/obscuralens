"""
Search-dork generator (v6.1).

Builds ready-to-open search-engine links for a target of any kind - the
"dork builder" pattern popularised by OSINT Terminal, with ObscuraLens's
20-kind coverage. Pure string formatting, zero network: the analyst clicks
the links (or feeds them to a browser automation) and stays in control of
every active query, which keeps the tool's passive-first promise intact.

Engines: Google, Bing, DuckDuckGo, Yandex and GitHub code search. Each kind
contributes the templates an investigator actually reaches for first -
exposed files for domains, leak-site mentions for emails, platform-scoped
searches for usernames, exploit hunting for CVEs.
"""

from typing import Dict, List, Optional
from urllib.parse import quote

from .validators import detect_hash_algorithm, url_parts

#: Engine name -> URL template with the quoted query inserted.
ENGINES: Dict[str, str] = {
    'Google': 'https://www.google.com/search?q={}',
    'Bing': 'https://www.bing.com/search?q={}',
    'DuckDuckGo': 'https://duckduckgo.com/?q={}',
    'Yandex': 'https://yandex.com/search/?text={}',
    'GitHub Code': 'https://github.com/search?type=code&q={}',
}

#: Kinds that carry dork templates today (surfaced by `obscuralens dorks
#: --list` and the web tools view).
KINDS_WITH_DORKS = (
    'ip', 'domain', 'email', 'username', 'phone', 'url', 'crypto',
    'hash', 'cve', 'asn', 'mac', 'coords', 'iban',
)


def _q(text: str) -> str:
    """URL-encode a query fragment."""
    return quote(text, safe='')


def _links(queries: List[tuple]) -> List[Dict[str, str]]:
    """Expand (engine, raw_query, label) triples into link dicts."""
    out: List[Dict[str, str]] = []
    for engine, query, label in queries:
        template = ENGINES.get(engine)
        if not template:
            continue
        out.append({
            'engine': engine,
            'label': label,
            'query': query,
            'url': template.format(_q(query)),
        })
    return out


def dorks_for(kind: str, target: str) -> List[Dict[str, str]]:
    """
    Build the dork links for one target of a given kind.

    Returns a list of ``{'engine', 'label', 'query', 'url'}`` dicts, best
    first. Unknown kinds and unparseable targets answer ``[]``; the caller
    decides how to surface that.
    """
    value = (target or '').strip()
    if not value:
        return []
    kind = (kind or '').strip().lower()

    if kind == 'domain':
        return _links([
            ('Google', f'site:{value}', 'Pages on the domain'),
            ('Google', f'site:*.{value}', 'Pages on any subdomain'),
            ('Google', f'site:{value} inurl:login OR inurl:signin OR inurl:admin', 'Login/admin surfaces'),
            ('Google', f'site:{value} ext:env OR ext:sql OR ext:bak OR ext:log OR ext:conf', 'Exposed files'),
            ('Google', f'site:{value} inurl:api OR inurl:token OR inurl:secret', 'API/token paths'),
            ('Google', f'"{value}" -site:{value}', 'Off-domain mentions'),
            ('GitHub Code', f'"{value}" password OR secret OR token', 'Leaked secrets referencing the domain'),
            ('Bing', f'site:{value}', 'Bing index of the domain'),
        ])
    if kind == 'ip':
        return _links([
            ('Google', f'"{value}"', 'Exact IP mentions'),
            ('Google', f'"{value}" shodan OR censys OR zoom', 'Scanner records'),
            ('Google', f'"{value}" malware OR botnet OR c2', 'Th Intel associations'),
            ('Bing', f'"{value}"', 'Bing IP mentions'),
        ])
    if kind == 'email':
        return _links([
            ('Google', f'"{value}"', 'Exact address mentions'),
            ('Google', f'"{value}" password OR leaked OR dump', 'Leak-site context'),
            ('Google', f'site:pastebin.com "{value}"', 'Pastebin appearances'),
            ('GitHub Code', f'"{value}"', 'Commits and gists carrying the address'),
            ('DuckDuckGo', f'"{value}"', 'DDG address mentions'),
        ])
    if kind == 'username':
        return _links([
            ('Google', f'"{value}"', 'Exact handle mentions'),
            ('Google', f'"{value}" site:reddit.com', 'Reddit activity'),
            ('Google', f'"{value}" site:t.me/s/', 'Telegram channel posts'),
            ('Google', f'"{value}" site:github.com', 'GitHub presence'),
            ('Google', f'"{value}" profile OR bio OR "about me"', 'Profile pages'),
            ('GitHub Code', f'"{value}"', 'Code and config appearances'),
        ])
    if kind == 'phone':
        compact = value.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        return _links([
            ('Google', f'"{value}"', 'Exact number mentions'),
            ('Google', f'"{compact}" spam OR scam OR fraud', 'Spam-report hits'),
            ('Google', f'"{value}" site:whocalledme.com OR site:tellows.com', 'Crowd-sourced reports'),
            ('DuckDuckGo', f'"{value}"', 'DDG number mentions'),
        ])
    if kind == 'url':
        parts = url_parts(value)
        host = parts.get('host') or value
        return _links([
            ('Google', f'site:{host}', 'Pages on the host'),
            ('Google', f'"{value}"', 'Exact URL mentions'),
            ('Google', f'site:{host} ext:php OR ext:asp OR ext:jsp inurl:id=', 'Legacy dynamic surfaces'),
        ])
    if kind == 'crypto':
        return _links([
            ('Google', f'"{value}"', 'Exact address mentions'),
            ('Google', f'"{value}" scam OR fraud OR stolen OR hack', 'Illicit-use reports'),
            ('Google', f'"{value}" site:etherscan.io OR site:blockchair.com OR site:tronscan.org', 'Explorer annotations'),
        ])
    if kind == 'hash':
        algo = detect_hash_algorithm(value) or 'hash'
        return _links([
            ('Google', f'"{value}"', 'Exact digest mentions'),
            ('Google', f'"{value}" malware OR {algo}', 'Malware corpus hits'),
            ('DuckDuckGo', f'"{value}"', 'DDG digest mentions'),
        ])
    if kind == 'cve':
        ident = value.upper()
        return _links([
            ('Google', f'"{ident}"', 'Exact identifier mentions'),
            ('Google', f'"{ident}" exploit OR poc OR metasploit', 'Public exploits'),
            ('GitHub Code', f'"{ident}"', 'Proof-of-concept code'),
            ('Google', f'"{ident}" patch OR advisory', 'Vendor advisories'),
        ])
    if kind == 'asn':
        number = ''.join(ch for ch in value if ch.isdigit())
        if not number:
            return []
        return _links([
            ('Google', f'"AS{number}"', 'AS number mentions'),
            ('Google', f'"AS{number}" outage OR hijack OR route-leak', 'Routing incidents'),
        ])
    if kind == 'mac':
        compact = value.replace(':', '').replace('-', '').replace('.', '').lower()
        return _links([
            ('Google', f'"{value}"', 'Exact MAC mentions'),
            ('Google', f'"{compact}"', 'Compact-form mentions'),
        ])
    if kind == 'coords':
        return _links([
            ('Google', f'"{value}"', 'Exact coordinate string mentions'),
            ('Google', f'"{value}" geotagged OR exif OR photo', 'Geotagged media'),
        ])
    if kind == 'iban':
        compact = value.replace(' ', '').upper()
        return _links([
            ('Google', f'"{value}"', 'Exact IBAN mentions'),
            ('Google', f'"{compact}"', 'Compact-form mentions'),
        ])
    return []


def dorks_for_target(target: str, kind: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Dork links for a target, auto-detecting the kind when not given.

    Convenience wrapper for the CLI and web layer: falls back to
    ``detect_kind`` and answers ``[]`` for unrecognised targets.
    """
    if kind:
        return dorks_for(kind, target)
    # Local import to avoid a cycle at module load.
    from ..investigate import detect_kind
    detected = detect_kind(target)
    if detected is None:
        return []
    return dorks_for(detected, target)


__all__ = ['ENGINES', 'KINDS_WITH_DORKS', 'dorks_for', 'dorks_for_target']
