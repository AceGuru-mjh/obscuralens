"""
Bounded same-domain web crawler (EXPERIMENTAL).

A polite BFS crawler that stays on the start host (``www.`` prefixes are
treated as the same host), honours a robots.txt subset (User-agent groups,
Disallow prefix rules with ``*`` wildcards via :mod:`fnmatch`, Allow ignored),
sleeps between page fetches and caps both link-hop depth and total pages.

For every fetched page it records status, title, content type, server header,
same-host links, external links, e-mail addresses and technology hints
(X-Powered-By header, generator meta tag, wp-content / cdn-cgi markers).

Every fetch goes through the shared HTTP client; failures are recorded in the
report's ``errors`` list instead of raised. Requires
``app.experimental_features`` to be enabled.
"""

import fnmatch
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..config import config
from ..utils.http_client import http, jitter

__all__ = ['crawl', 'crawl_sections', 'parse_robots']

# Bodies larger than this are truncated before parsing (defensive).
_MAX_TEXT_CHARS = 1_000_000
_CAP_EXTERNAL_DOMAINS = 30
_CAP_EMAILS = 50
_CAP_PAGE_ROWS = 25

_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
_LINK_RE = re.compile(r'<a\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\']', re.I)
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+')
_GENERATOR_RES = (
    re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', re.I),
)
# The User-agent token this crawler identifies as for robots matching.
_UA_TOKEN = 'obscuralens'


def _strip_www(netloc: str) -> str:
    """Normalise a netloc for same-host comparison (case + www prefix)."""
    host = (netloc or '').lower()
    if host.startswith('www.'):
        host = host[4:]
    return host


def _normalise_url(url: str) -> str:
    """Absolute http(s) URL with a lowercased host and no fragment."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                       parts.path or '/', parts.query, ''))


def parse_robots(text: Any, user_agent: str = _UA_TOKEN) -> List[str]:
    """
    EXPERIMENTAL: parse a robots.txt subset into Disallow rules for our agent.

    Line-based parser (no external library): ``User-agent:`` lines start a
    group, ``Disallow:`` rules apply when the group names ``*`` or our agent
    token, ``Allow:`` is ignored, empty rules are ignored and inline ``#``
    comments are stripped. Rules keep their ``*`` wildcards and optional
    trailing ``$`` anchors; see :func:`_robots_allows` for matching. Never
    raises.
    """
    if not isinstance(text, str):
        return []
    wanted = (user_agent or '').strip().lower()
    rules: List[str] = []
    group_agents: List[str] = []
    saw_directive = False
    for raw_line in text.splitlines():
        line = raw_line.split('#', 1)[0].strip()
        if not line or ':' not in line:
            continue
        directive, _, value = line.partition(':')
        directive = directive.strip().lower()
        value = value.strip()
        if directive == 'user-agent':
            if saw_directive:
                group_agents = []  # a new group begins
                saw_directive = False
            if value:
                group_agents.append(value.lower())
            continue
        if not group_agents:
            continue
        saw_directive = True
        if directive == 'disallow' and value and (
                '*' in group_agents or wanted in group_agents):
            rules.append(value)
    return rules


def _rule_pattern(rule: str) -> str:
    """robots rule -> fnmatch glob with prefix semantics.

    A plain rule is a prefix match ('/private' blocks '/private/page'), a
    trailing ``*`` stays a wildcard and a trailing ``$`` anchors the end.
    """
    if rule.endswith('$'):
        return rule[:-1]
    if rule.endswith('*'):
        return rule
    return rule + '*'


def _robots_allows(url: str, rules: List[str]) -> bool:
    """Whether ``url`` passes every Disallow rule (fnmatch on path+query)."""
    try:
        parts = urlsplit(url)
        target = parts.path or '/'
        if parts.query:
            target += '?' + parts.query
    except ValueError:
        return True
    return not any(fnmatch.fnmatchcase(target, _rule_pattern(rule))
                   for rule in rules)


def _text_header(response: Any, name: str) -> str:
    """Read a header from a response without ever raising."""
    try:
        value = response.headers.get(name)
    except Exception:
        return ''
    return str(value) if value else ''


def _page_title(html: str) -> str:
    """First <title> text, tag-stripped, whitespace-collapsed, 200 chars."""
    match = _TITLE_RE.search(html)
    if not match:
        return ''
    title = re.sub(r'<[^>]+>', '', match.group(1))
    title = re.sub(r'\s+', ' ', title).strip()
    return title[:200]


def _harvest_links(html: str, base_url: str,
                   crawl_host: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Harvest hrefs from ``html``.

    Returns ``(same_host_urls, external_urls, mailto_addresses)``: absolute
    URLs resolved against ``base_url`` (the page's final URL), deduplicated
    and order-preserving; fragments dropped, queries kept, non-http(s)
    schemes skipped. Same-host is judged against the crawl host, so a
    cross-host redirect can never widen the link set.
    """
    internal: List[str] = []
    external: List[str] = []
    mailto: List[str] = []
    seen = set()
    for match in _LINK_RE.finditer(html):
        href = (match.group(1) or '').strip()
        if not href:
            continue
        lowered = href.lower()
        if lowered.startswith('mailto:'):
            mailto.append(href[len('mailto:'):])
            continue
        if lowered.startswith(('javascript:', 'tel:', 'data:', '#')):
            continue
        try:
            absolute = _normalise_url(urljoin(base_url, href))
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if parts.scheme not in ('http', 'https') or not parts.netloc:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        if _strip_www(parts.netloc) == crawl_host:
            internal.append(absolute)
        else:
            external.append(absolute)
    return internal, external, mailto


def _extract_emails(html: str, mailto_addresses: List[str]) -> List[str]:
    """Unique lowercase e-mails found in page text and mailto: targets."""
    found = {match.group(0).lower() for match in _EMAIL_RE.finditer(html)}
    for address in mailto_addresses:
        target = address.split('?', 1)[0].strip().lower()
        if _EMAIL_RE.fullmatch(target):
            found.add(target)
    return sorted(found)


def _tech_hints(html: str, response: Any) -> List[str]:
    """Technology fingerprints for one page (deduped, order-preserving)."""
    hints: List[str] = []
    powered_by = _text_header(response, 'X-Powered-By')
    if powered_by:
        hints.append(powered_by[:80])
    for pattern in _GENERATOR_RES:
        match = pattern.search(html)
        if match:
            hints.append(re.sub(r'\s+', ' ', match.group(1)).strip()[:80])
            break
    low = html.lower()
    if 'wp-content' in low or 'wp-includes' in low:
        hints.append('WordPress')
    if 'cdn-cgi' in low:
        hints.append('Cloudflare')
    return list(dict.fromkeys(h for h in hints if h))


def crawl(url: Any, max_depth: Optional[int] = None,
          max_pages: Optional[int] = None, delay: Optional[float] = None,
          respect_robots: bool = True) -> Dict[str, Any]:
    """
    EXPERIMENTAL: crawl a website, staying on the start host.

    BFS over same-host links; ``max_depth`` counts link *hops* from the start
    URL (start page = depth 0). Redirects are followed by the HTTP client
    (``allow_redirects=True``) and the landing URL resolves relative links,
    but the host comparison always uses the start host, so a cross-host
    redirect can never widen the crawl. robots.txt is fetched once and its
    Disallow rules honoured (skipped URLs are listed in ``robots_skipped``).

    Args:
        url: start URL (http/https only).
        max_depth: link-hop cap; default ``app.crawler_max_depth`` (2).
        max_pages: fetch-attempt cap (errors included); default
            ``app.crawler_max_pages`` (20).
        delay: polite pause between page fetches (jittered); default
            ``app.crawler_delay`` (1.0s).
        respect_robots: fetch and honour robots.txt (default True).

    Returns:
        ``{'pages': [...], 'page_count', 'link_count', 'external_domains',
        'emails', 'tech_hints', 'errors', 'started', 'duration_ms',
        'crawled_urls' (fetch attempts), 'robots_skipped'}`` or
        ``{'error': ...}`` for invalid input / disabled experimental
        features. Never raises.
    """
    if not config.app_config.experimental_features:
        return {'error': 'experimental features disabled'}

    if not isinstance(url, str) or not url.strip().lower().startswith(
            ('http://', 'https://')):
        return {'error': 'invalid url (expected http(s)://host/...)'}

    try:
        start = _normalise_url(url)
        start_parts = urlsplit(start)
    except ValueError:
        return {'error': 'invalid url (unparseable)'}
    if not start_parts.netloc:
        return {'error': 'invalid url (no host)'}

    app = config.app_config
    depth_limit = max_depth if max_depth is not None else app.crawler_max_depth
    page_limit = max_pages if max_pages is not None else app.crawler_max_pages
    pause = delay if delay is not None else app.crawler_delay
    try:
        depth_limit = max(0, int(depth_limit))
        page_limit = max(1, int(page_limit))
        pause = max(0.0, float(pause))
    except (TypeError, ValueError):
        return {'error': 'invalid crawl limits (max_depth/max_pages/delay)'}

    started_at = datetime.now(timezone.utc)
    clock = time.time()
    host = _strip_www(start_parts.netloc)

    rules: List[str] = []
    if respect_robots:
        robots_url = f'{start_parts.scheme}://{start_parts.netloc}/robots.txt'
        try:
            ok, text, _err = http.get_text(robots_url)
        except Exception:
            ok, text = False, ''
        if ok and isinstance(text, str):
            rules = parse_robots(text)

    pages: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    robots_skipped: List[str] = []
    crawled_urls: List[str] = []           # every URL whose fetch was attempted
    internal_links = set()                 # distinct same-host URLs discovered
    external_domains = set()
    emails_all = set()
    tech_all = set()
    fetches = 0
    queued = {start}
    queue: List[Tuple[str, int]] = [(start, 0)]

    while queue and fetches < page_limit:
        current, depth = queue.pop(0)
        try:
            netloc = urlsplit(current).netloc
        except ValueError:
            continue
        if not current or _strip_www(netloc) != host:
            continue
        if respect_robots and rules and not _robots_allows(current, rules):
            robots_skipped.append(current)
            continue

        fetches += 1
        crawled_urls.append(current)
        try:
            response = http.get(current, allow_redirects=True)
        except Exception as e:
            errors.append({'url': current, 'error': type(e).__name__})
            time.sleep(jitter(pause))
            continue

        try:
            status = int(response.status_code)
        except Exception:
            status = 0
        try:
            text = response.text or ''
        except Exception:
            text = ''
        if len(text) > _MAX_TEXT_CHARS:
            text = text[:_MAX_TEXT_CHARS]
        try:
            final_url = _normalise_url(response.url or current)
        except Exception:
            final_url = current

        links, external, mailto = _harvest_links(text, final_url, host)
        emails = _extract_emails(text, mailto)
        hints = _tech_hints(text, response)

        page: Dict[str, Any] = {
            'url': current,
            'status': status,
            'title': _page_title(text),
            'content_type': _text_header(response, 'Content-Type'),
            'server': _text_header(response, 'Server'),
            'links': links,
            'external_links': external,
            'emails': emails,
            'tech_hints': hints,
        }
        if final_url != current:
            page['final_url'] = final_url
        pages.append(page)

        emails_all.update(emails)
        tech_all.update(hints)
        for link in external:
            try:
                netloc = urlsplit(link).netloc
            except ValueError:
                continue
            if netloc:
                external_domains.add(netloc.lower())
        for link in links:
            internal_links.add(link)
            if depth + 1 <= depth_limit and link not in queued:
                queued.add(link)
                queue.append((link, depth + 1))

        time.sleep(jitter(pause))

    return {
        'pages': pages,
        'page_count': len(pages),
        'link_count': len(internal_links),
        'external_domains': sorted(d for d in external_domains if d)[
            :_CAP_EXTERNAL_DOMAINS],
        'emails': sorted(emails_all)[:_CAP_EMAILS],
        'tech_hints': sorted(tech_all),
        'errors': errors,
        'started': started_at.isoformat(),
        'duration_ms': int((time.time() - clock) * 1000),
        'crawled_urls': crawled_urls,
        'robots_skipped': robots_skipped,
    }


def crawl_sections(report: Any) -> List[Dict[str, Any]]:
    """
    EXPERIMENTAL: report sections for a :func:`crawl` result.

    A summary grid, a pages table (URL / status / title / links / e-mails),
    then e-mail, technology-hint and external-domain tables when populated.
    Error reports render as a single explanatory text section. Never raises.
    """
    if not isinstance(report, dict) or report.get('error'):
        reason = report.get('error') if isinstance(report, dict) else 'malformed result'
        return [{'title': 'Web Crawl', 'type': 'text',
                 'content': f'Crawl unavailable: {reason}'}]

    sections: List[Dict[str, Any]] = [{
        'title': 'Crawl Summary',
        'type': 'grid',
        'data': {
            'Pages crawled': report.get('page_count', 0),
            'Links discovered': report.get('link_count', 0),
            'External domains': len(report.get('external_domains') or []),
            'E-mails found': len(report.get('emails') or []),
            'Tech hints': len(report.get('tech_hints') or []),
            'Fetch errors': len(report.get('errors') or []),
            'Robots-skipped URLs': len(report.get('robots_skipped') or []),
            'Duration (ms)': report.get('duration_ms', 0),
        },
    }]

    rows = [[page.get('url', ''), page.get('status', ''),
             page.get('title', ''), len(page.get('links') or []),
             len(page.get('emails') or [])]
            for page in (report.get('pages') or [])[:_CAP_PAGE_ROWS]]
    if rows:
        sections.append({'title': 'Pages', 'type': 'table',
                         'columns': ['URL', 'Status', 'Title', 'Links', 'E-mails'],
                         'rows': rows})

    if report.get('emails'):
        sections.append({'title': 'E-mail Addresses', 'type': 'table',
                         'columns': ['Address'],
                         'rows': [[e] for e in report['emails']]})
    if report.get('tech_hints'):
        sections.append({'title': 'Technology Hints', 'type': 'table',
                         'columns': ['Hint'],
                         'rows': [[h] for h in report['tech_hints']]})
    if report.get('external_domains'):
        sections.append({'title': 'External Domains', 'type': 'table',
                         'columns': ['Domain'],
                         'rows': [[d] for d in report['external_domains']]})
    return sections
