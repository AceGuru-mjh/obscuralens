"""
Username permutation scanning (EXPERIMENTAL).

Generates plausible username variants (leet speak, prefixes, suffixes,
doublings) and sweeps them across the *same* platform registry the production
username tracker uses, so permutation hits and normal hits share one verdict
logic (three-state detection, bot-wall awareness).

Platform checks reuse ``UsernameTracker._check_platform`` - the identical code
path a regular username scan takes (HTML platforms only; permutation sweeps
keep the blast radius small). The tracker's 'unknown' verdict (bot walls, JS
shells) is reported here as ``'error'`` with the tracker's reason attached,
because a permutation sweep cannot confirm anything from it.

Politeness: ``time.sleep(jitter(0.4))`` between every request, and a hard cap
of 60 total requests per run (variants x platforms).
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..utils.http_client import http, jitter

__all__ = [
    'generate_variants',
    'scan_variants',
    'permutation_summary',
]

# Hard ceiling on requests issued by one scan_variants() call.
_MAX_TOTAL_REQUESTS = 60
# Politeness pause between platform checks (seconds, before jitter).
_REQUEST_DELAY = 0.4

# Leet substitutions applied all-at-once for the "full leet" variant.
_LEET_MAP = str.maketrans({'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5'})

# Single-character leet substitutions worth trying on their own.
_LEET_SINGLES = (('s', '5'), ('o', '0'))

# Suffixes appended directly to the base username ('' just re-yields the base).
_SUFFIXES = ['', '.', '_', '-', '123', '1234', '01', '007', 'x', 'xx',
             'official', 'real', 'the', 'its', 'im', 'hi']
# Year suffixes: birth years and recent years.
_SUFFIX_YEARS = [str(year) for year in range(1990, 2007)] + \
    [str(year) for year in range(2020, 2026)]

# Prefixes prepended directly to the base username.
_PREFIXES = ['real', 'the', 'its', 'im', 'iam', 'mr', 'dr']

_ALLOWED = re.compile(r'^[a-z0-9._-]{3,30}$', re.IGNORECASE)


def _clean_base(username: Any) -> str:
    """Lowercase the input and strip everything outside [a-z0-9._-]."""
    text = str(username or '').lower()
    return re.sub(r'[^a-z0-9._-]', '', text)


def _valid_variant(candidate: Any) -> bool:
    """Variant is a plausible account handle: charset + length 3..30.

    Case-tolerant on purpose: generated variants are lowercase except the
    deliberate uppercase form (URL paths are case-sensitive on some
    platforms), which still has to pass the same charset and length rules.
    """
    return bool(isinstance(candidate, str) and _ALLOWED.match(candidate))


def generate_variants(username: str,
                      max_variants: Optional[int] = None) -> List[str]:
    """
    EXPERIMENTAL: generate plausible username variants for a base handle.

    Deterministic, deduplicated and ordered by likely relevance:
    exact (sanitised) input, uppercase form, leet substitutions (full leet +
    common singles), suffixes (separators, numbers, years, words), prefixes,
    then the doubled username.

    Args:
        username: raw handle; sanitised to ``[a-z0-9._-]`` + lowercase first.
        max_variants: cap on the returned list; defaults to
            ``app.permutation_max_candidates`` (48).

    Returns:
        Ordered unique list (possibly empty for garbage input). Never raises.
        The uppercase entry is the one deliberately non-lowercase variant -
        URL paths are case-sensitive on some platforms.
    """
    if not isinstance(username, str):
        return []
    base = _clean_base(username)
    if not _valid_variant(base):
        return []

    limit = max_variants
    if limit is None:
        limit = config.app_config.permutation_max_candidates
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return []

    candidates: List[str] = [base, base.upper()]

    # Leet variants: full substitution first, then the common singles.
    full_leet = base.translate(_LEET_MAP)
    candidates.append(full_leet)
    for source, replacement in _LEET_SINGLES:
        if source in base:
            candidates.append(base.replace(source, replacement))

    # Suffix variants: separators, numbers, words and years.
    for suffix in _SUFFIXES + _SUFFIX_YEARS:
        candidates.append(base + suffix)

    # Prefix variants.
    for prefix in _PREFIXES:
        candidates.append(prefix + base)

    # The classic "doubled" handle.
    candidates.append(base + base)

    seen = set()
    ordered: List[str] = []
    for candidate in candidates:
        if not _valid_variant(candidate):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)
        if len(ordered) >= limit:
            break
    return ordered


def _load_registry() -> Tuple[Optional[Any], List[Dict[str, Any]]]:
    """
    Lazy-import the username tracker's platform registry.

    Returns ``(tracker_class_or_None, html_platforms)``; both empty when the
    tracker module cannot be imported (defensive - never raises).
    """
    try:
        from ..trackers.username_tracker import HTML_PLATFORMS, UsernameTracker
    except Exception:  # ImportError or anything the module import triggers
        return None, []
    return UsernameTracker, list(HTML_PLATFORMS)


def _select_platforms(platforms: Optional[Any],
                      max_platforms: Optional[int]) -> List[Dict[str, Any]]:
    """Resolve the platform list for a run: arg (dicts or names) or registry."""
    _, registry = _load_registry()
    limit = max_platforms
    if limit is None:
        limit = config.app_config.permutation_platforms
    try:
        limit = max(0, int(limit))
    except (TypeError, ValueError):
        limit = 0

    if platforms is None:
        return registry[:limit] if limit else []

    selected: List[Dict[str, Any]] = []
    if isinstance(platforms, (list, tuple)):
        for entry in platforms:
            if isinstance(entry, dict) and entry.get('name') and entry.get('url'):
                selected.append({'name': str(entry['name']),
                                 'url': str(entry['url'])})
            elif isinstance(entry, str):
                wanted = entry.strip().lower()
                for known in registry:
                    if known['name'].lower() == wanted:
                        selected.append(known)
                        break
    if limit:
        selected = selected[:limit]
    return selected


def _plain_check(url_template: str, variant: str) -> Dict[str, Any]:
    """
    Fallback check when the tracker class is unavailable: bare status split.

    404 -> not_found, 200 -> found, anything else / transport error -> error.
    Deliberately naive; documented as inferior to the tracker's verdicts.
    """
    url = url_template.format(variant)
    try:
        response = http.get(url, allow_redirects=True)
        status_code = response.status_code
    except Exception as e:
        return {'variant': variant, 'url': url, 'status': 'error',
                'http_status': 0, 'reason': f'network error: {type(e).__name__}'}
    if status_code == 404:
        status = 'not_found'
    elif status_code == 200:
        status = 'found'
    else:
        status = 'error'
    return {'variant': variant, 'url': url, 'status': status,
            'http_status': status_code, 'reason': f'http {status_code}'}


def scan_variants(variants: Any, platforms: Optional[Any] = None,
                  max_platforms: Optional[int] = None) -> Any:
    """
    EXPERIMENTAL: sweep username variants across the tracker's HTML platforms.

    Each (variant, platform) pair is checked through ``UsernameTracker.
    _check_platform`` - the same verdict logic a normal username scan uses.
    The tracker's 'unknown' verdict maps to ``'error'`` here (indeterminate,
    never a hit); its reason is preserved in the result row.

    Args:
        variants: iterable of username strings (sanitised + deduped here).
        platforms: optional platform dicts (``{'name', 'url'}``) or platform
            names; default = first N HTML platforms from the username tracker.
        max_platforms: platform cap; defaults to ``app.permutation_platforms``.

    Returns:
        A list of rows ``[{'variant', 'platform', 'url', 'status',
        'http_status', 'reason', 'confidence'}]`` on success. Errors are
        returned as ``{'error': ...}`` dictionaries instead (experimental
        features disabled, no platforms available); empty input returns
        ``[]`` - callers should test ``isinstance(result, dict) and
        result.get('error')``. Total requests are hard-capped at 60 per run:
        with the default 5 platforms only the first 12 (most relevant)
        variants are scanned. Never raises.
    """
    if not config.app_config.experimental_features:
        return {'error': 'experimental features disabled'}

    if not isinstance(variants, (list, tuple, set)):
        if variants is None:
            return []
        variants = [variants]
    cleaned: List[str] = []
    seen = set()
    for variant in variants:
        candidate = _clean_base(variant)
        if _valid_variant(candidate) and candidate not in seen:
            seen.add(candidate)
            cleaned.append(candidate)
    if not cleaned:
        return []

    selected = _select_platforms(platforms, max_platforms)
    if not selected:
        return {'error': 'no platforms available for permutation scan'}

    # Hard request cap: variants x platforms <= 60 (first N variants win).
    variant_cap = max(1, _MAX_TOTAL_REQUESTS // len(selected))
    cleaned = cleaned[:variant_cap]

    tracker_class, _ = _load_registry()
    tracker = tracker_class() if tracker_class is not None else None

    results: List[Dict[str, Any]] = []
    first_request = True
    for variant in cleaned:
        for platform in selected:
            if first_request:
                first_request = False
            else:
                time.sleep(jitter(_REQUEST_DELAY))
            results.append(_check_one(tracker, platform, variant))
    return results


def _check_one(tracker: Any, platform: Dict[str, Any],
               variant: str) -> Dict[str, Any]:
    """Run one (variant, platform) check, preferring the tracker's verdict."""
    if tracker is not None:
        try:
            check = tracker._check_platform(dict(platform), variant, False)
            status = check.status
            mapped = status if status in ('found', 'not_found') else 'error'
            return {
                'variant': variant,
                'platform': check.platform or platform['name'],
                'url': check.url,
                'status': mapped,
                'http_status': check.status_code,
                'reason': check.reason or check.error or status,
                'confidence': check.confidence,
            }
        except Exception as e:
            return {'variant': variant, 'platform': platform['name'],
                    'url': platform['url'].format(variant), 'status': 'error',
                    'http_status': 0,
                    'reason': f'check failed: {type(e).__name__}',
                    'confidence': 'low'}
    return _plain_check(platform['url'], variant)


def permutation_summary(results: Any) -> Dict[str, int]:
    """
    EXPERIMENTAL: aggregate a :func:`scan_variants` result list.

    Accepts the raw row list (or a dict carrying one under ``'results'``) and
    returns ``{'scanned', 'found', 'variants_with_hits'}``. Never raises.
    """
    rows: List[Any] = []
    if isinstance(results, dict):
        rows = results.get('results') or []
    elif isinstance(results, (list, tuple)):
        rows = list(results)

    found_variants = set()
    scanned = 0
    found = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        scanned += 1
        if row.get('status') == 'found' and row.get('variant'):
            found += 1
            found_variants.add(row['variant'])
    return {
        'scanned': scanned,
        'found': found,
        'variants_with_hits': len(found_variants),
    }
