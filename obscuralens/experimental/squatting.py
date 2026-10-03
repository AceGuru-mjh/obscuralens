"""
Typosquat / domain-squat variant generation (EXPERIMENTAL).

A pure-Python, fully offline re-implementation of the variant families that
made dnstwist the standard tool for domain-defence triage. Given a domain,
generate every plausible "lookalike" a typosquatter or phisher might
register - keyboard-adjacent slips, dropped or doubled letters, swapped
vowels, hyphen insertions, subdomain prefixes, plural forms, bit-flip
corruptions, Unicode homoglyphs, ASCII digit lookalikes, TLD swaps and
combo-squat word mashups - each labeled with its category and a human
description of the deception.

The generated list is a *watch list*: feed it to domain registration
checks (WHOIS/RDAP), passive DNS or the domain tracker to see which of
the lookalikes actually resolve. :func:`score_variants` ranks the list by
deception risk so an analyst reviews the dangerous ones first, and
:func:`render_table` shapes the output for tabulate.

Design notes: deterministic ordering (category order, then position),
de-duplicated by domain string, the original domain is never included,
and the total is capped at 300 variants so a long SLD cannot explode the
list. Combo-squatting is gated by edit distance to the ``popular_domains``
data pack and draws its brand words from that pack's phishing keywords -
both loaded defensively, so a stripped-down install simply loses those
two families without breaking anything.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

try:  # data_packs is maintained by a parallel workstream; absence is tolerated
    from ..utils import data_packs as _data_packs
except ImportError:  # pragma: no cover - pack module not shipped
    _data_packs = None  # type: ignore

__all__ = [
    'generate_variants',
    'score_variants',
    'render_variants_table',
    'damerau_levenshtein',
    'KEYBOARD_NEIGHBORS',
    'HOMOGLYPHS',
    'HOMOGLYPH_MULTI',
    'ASCII_LOOKALIKES',
    'COMMON_TLDS',
    'TABLE_HEADERS',
]

#: Hard cap on generated variants (dnstwist-style ceiling).
_MAX_VARIANTS = 300

# ---------------------------------------------------------------------------
# Lookalike tables
# ---------------------------------------------------------------------------

#: Adjacent keys on a QWERTY layout (lowercase letters + digit row).
#: Used for insertion and substitution families - the physical typo model.
KEYBOARD_NEIGHBORS: Dict[str, str] = {
    'q': 'w', 'w': 'qe', 'e': 'wr', 'r': 'et', 't': 'ry', 'y': 'tu',
    'u': 'yi', 'i': 'uo', 'o': 'ip', 'p': 'o',
    'a': 's', 's': 'ad', 'd': 'sf', 'f': 'dg', 'g': 'fh', 'h': 'gj',
    'j': 'hk', 'k': 'jl', 'l': 'k',
    'z': 'x', 'x': 'zc', 'c': 'xv', 'v': 'cb', 'b': 'vn', 'n': 'bm',
    'm': 'n',
    '1': '2', '2': '13', '3': '24', '4': '35', '5': '46', '6': '57',
    '7': '68', '8': '79', '9': '80', '0': '9',
}

#: Latin homoglyphs: the ~40 most-abused Unicode lookalikes (letter ->
#: Unicode letter only; digit swaps live in ASCII_LOOKALIKES instead).
HOMOGLYPHS: Dict[str, str] = {
    'a': 'àáâãäåāą', 'e': 'éèêëēě', 'i': 'íìîïī', 'o': 'óòôõöøō',
    'u': 'úùûüū', 'c': 'çćč', 'n': 'ñń', 's': 'śš', 'y': 'ý',
    'z': 'źž', 'd': 'đ', 'g': 'ğ', 'l': 'ł', 'r': 'ř', 't': 'ŧ',
}

#: Multi-character Latin confusables ('rn' reads as 'm' at domain size).
HOMOGLYPH_MULTI: Dict[str, str] = {'rn': 'm'}

#: ASCII digit/letter lookalikes swapped in cheap lookalike domains.
ASCII_LOOKALIKES: Dict[str, str] = {
    '0': 'o', 'o': '0', '1': 'l', 'l': '1', 'i': '1', '3': 'e', 'e': '3',
    '5': 's', 's': '5', '7': 't', 't': '7', '8': 'b', 'b': '8', '9': 'g',
    'g': '9', '6': 'b', '2': 'z', 'z': '2',
}

#: Common TLDs used for the tld_swap family.
COMMON_TLDS: Tuple[str, ...] = (
    'com', 'net', 'org', 'io', 'co', 'info', 'biz', 'xyz', 'app', 'dev',
    'online', 'site', 'store',
)

#: Subdomain prefixes used for the subdomain family.
_SUBDOMAIN_PREFIXES: Tuple[str, ...] = (
    'www', 'secure', 'mail', 'login', 'account', 'support', 'portal',
    'app', 'shop', 'web', 'admin',
)

#: Fixed brand words for combo-squatting (always offered).
_COMBO_FIXED: Tuple[str, ...] = (
    'login', 'secure', 'account', 'verify', 'wallet', 'support', 'signin',
    'password', 'update', 'billing', 'recovery',
)

#: Curated vocabulary intersected with the ``phishing_keywords`` pack to
#: pick the extra combo-squat words (single, domain-friendly tokens).
_COMBO_PREFERRED = frozenset((
    'login', 'secure', 'account', 'verify', 'wallet', 'support', 'signin',
    'password', 'update', 'billing', 'recovery', 'alert', 'confirm',
    'unlock', 'limited', 'urgent', 'bonus', 'airdrop', 'client', 'invoice',
    'payment', 'security', 'session', 'portal', 'service', 'online',
))

#: Maximum combo words (fixed + pack-derived) per domain.
_MAX_COMBO_WORDS = 24

#: Characters allowed in a generated SLD.
_ALLOWED_SLD_RE = re.compile(r'[a-z0-9-]+')

# Module-level caches for the two data packs (empty loads retry later).
_POPULAR_CACHE: Optional[List[str]] = None
_KEYWORD_CACHE: Optional[List[str]] = None


def _load_pack(name: str) -> List[str]:
    """Load one data pack through the (possibly absent) data_packs module."""
    if _data_packs is None:
        return []
    try:
        values = _data_packs.load_data_pack(name)
    except Exception:
        return []
    if not isinstance(values, (list, tuple, set)):
        return []
    return [item.strip().lower() for item in values
            if isinstance(item, str) and item.strip()]


def _popular_domains() -> List[str]:
    """Cached popular-domains pack; an empty load is retried on the next call."""
    global _POPULAR_CACHE
    if _POPULAR_CACHE:
        return _POPULAR_CACHE
    values = _load_pack('popular_domains')
    if values:
        _POPULAR_CACHE = values
    return values


def _phishing_keywords() -> List[str]:
    """Cached phishing-keywords pack; an empty load is retried on the next call."""
    global _KEYWORD_CACHE
    if _KEYWORD_CACHE:
        return _KEYWORD_CACHE
    values = _load_pack('phishing_keywords')
    if values:
        _KEYWORD_CACHE = values
    return values


def _combo_words() -> List[str]:
    """Fixed combo words plus pack keywords intersected with the curated set."""
    words = list(_COMBO_FIXED)
    pack_words = sorted(
        word for word in _phishing_keywords()
        if word in _COMBO_PREFERRED and word not in words
    )
    words.extend(pack_words)
    return words[:_MAX_COMBO_WORDS]


# ---------------------------------------------------------------------------
# Domain parsing
# ---------------------------------------------------------------------------


def _parse_domain(domain: Any) -> Optional[Tuple[str, str, str]]:
    """
    Reduce any domain-ish input to ``(sld, tld, full)``.

    Tolerates URLs (``https://``), paths, queries and ports by stripping
    them, then enforces plain ASCII label rules. The registrable core is
    the last two labels, so ``www.google.com`` yields ``('google',
    'com', 'www.google.com')``; multi-label public suffixes such as
    ``google.co.uk`` are intentionally not resolved (no offline
    public-suffix list), so the core there is ``('co', 'uk')``.

    Returns None for anything that is not a plausible domain.
    """
    if not isinstance(domain, str):
        return None
    text = domain.strip().lower()
    if '://' in text:
        text = text.split('://', 1)[1]
    text = text.split('/', 1)[0].split('?', 1)[0].split('#', 1)[0]
    if ':' in text:
        text = text.split(':', 1)[0]
    text = text.strip('.')
    if not text or len(text) > 253:
        return None
    labels = text.split('.')
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or len(label) > 63 or not _ALLOWED_SLD_RE.fullmatch(label):
            return None
        if label.startswith('-') or label.endswith('-'):
            return None
    return labels[-2], labels[-1], text


def _valid_sld(sld: str) -> bool:
    """True when ``sld`` is a legal single DNS label (1-63, no edge hyphens)."""
    return bool(sld) and len(sld) <= 63 and bool(_ALLOWED_SLD_RE.fullmatch(sld)) \
        and not sld.startswith('-') and not sld.endswith('-')


# ---------------------------------------------------------------------------
# Damerau-Levenshtein distance
# ---------------------------------------------------------------------------


def _bounded(distance: int, cap: Optional[int]) -> int:
    """Exact distance, or ``cap + 1`` when it exceeds the bound."""
    if cap is None or distance <= cap:
        return distance
    return cap + 1


def damerau_levenshtein(a: str, b: str, cap: Optional[int] = None) -> int:
    """
    Damerau-Levenshtein distance with the classic transposition row.

    Edit distance counting substitutions, insertions, deletions AND
    adjacent transpositions ('ab' -> 'ba' costs 1), implemented with three
    rolling rows so memory stays O(len(b)). The optional ``cap`` bounds
    the computation: when the true distance provably exceeds ``cap`` the
    function returns ``cap + 1`` early instead of finishing the matrix
    (the trick used by the phishing scorer for cheap distance checks).

    Args:
        a: first string.
        b: second string.
        cap: optional upper bound; None computes the exact distance.

    Returns:
        The edit distance, or ``cap + 1`` when it exceeds ``cap``.
    """
    if a == b:
        return 0
    if not a:
        return _bounded(len(b), cap)
    if not b:
        return _bounded(len(a), cap)
    if cap is not None and abs(len(a) - len(b)) > cap:
        return cap + 1
    # Row 0 twice: prev2 is only read once i > 1, by which time it holds
    # the genuine row for i - 2.
    prev2 = list(range(len(b) + 1))
    prev1 = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i] + [0] * len(b)
        row_min = i
        for j, char_b in enumerate(b, 1):
            cost = 0 if char_a == char_b else 1
            value = min(prev1[j] + 1, current[j - 1] + 1, prev1[j - 1] + cost)
            # Classic transposition row: 'ab' <-> 'ba' for one edit.
            if i > 1 and j > 1 and char_a == b[j - 2] and a[i - 2] == char_b:
                value = min(value, prev2[j - 2] + 1)
            current[j] = value
            if value < row_min:
                row_min = value
        if cap is not None and row_min > cap:
            return cap + 1
        prev2, prev1 = prev1, current
    return prev1[-1]


# ---------------------------------------------------------------------------
# Variant families (each returns [{'domain', 'description'}])
# ---------------------------------------------------------------------------


def _variants_omission(sld: str, tld: str) -> List[Dict[str, str]]:
    """Drop each character in turn (fat-finger misses a key entirely)."""
    out: List[Dict[str, str]] = []
    for index, char in enumerate(sld):
        candidate = sld[:index] + sld[index + 1:]
        if _valid_sld(candidate):
            out.append({'domain': f'{candidate}.{tld}',
                        'description': f"omit '{char}' at position {index}"})
    return out


def _variants_insertion(sld: str, tld: str) -> List[Dict[str, str]]:
    """Insert a keyboard-adjacent character next to every character."""
    out: List[Dict[str, str]] = []
    for index, char in enumerate(sld):
        for neighbor in KEYBOARD_NEIGHBORS.get(char, ''):
            for position in (index, index + 1):
                candidate = sld[:position] + neighbor + sld[position:]
                if _valid_sld(candidate):
                    out.append({'domain': f'{candidate}.{tld}',
                                'description': f"insert '{neighbor}' (key next to '{char}') "
                                               f"at position {position}"})
    return out


def _variants_substitution(sld: str, tld: str) -> List[Dict[str, str]]:
    """Substitute each character with a keyboard-adjacent key."""
    out: List[Dict[str, str]] = []
    for index, char in enumerate(sld):
        for neighbor in KEYBOARD_NEIGHBORS.get(char, ''):
            candidate = sld[:index] + neighbor + sld[index + 1:]
            if _valid_sld(candidate):
                out.append({'domain': f'{candidate}.{tld}',
                            'description': f"substitute '{char}' with adjacent key '{neighbor}' "
                                           f"at position {index}"})
    return out


def _variants_transposition(sld: str, tld: str) -> List[Dict[str, str]]:
    """Swap each adjacent character pair (typing order inversion)."""
    out: List[Dict[str, str]] = []
    for index in range(len(sld) - 1):
        if sld[index] == sld[index + 1]:
            continue
        candidate = sld[:index] + sld[index + 1] + sld[index] + sld[index + 2:]
        if _valid_sld(candidate):
            out.append({'domain': f'{candidate}.{tld}',
                        'description': f"transpose '{sld[index]}{sld[index + 1]}' "
                                       f"at position {index}"})
    return out


def _variants_duplication(sld: str, tld: str) -> List[Dict[str, str]]:
    """Double each character in turn (held key too long)."""
    out: List[Dict[str, str]] = []
    for index, char in enumerate(sld):
        candidate = sld[:index] + char + sld[index:]
        if _valid_sld(candidate):
            out.append({'domain': f'{candidate}.{tld}',
                        'description': f"duplicate '{char}' at position {index}"})
    return out


def _variants_hyphenation(sld: str, tld: str) -> List[Dict[str, str]]:
    """Insert a hyphen between each adjacent character pair."""
    out: List[Dict[str, str]] = []
    for index in range(1, len(sld)):
        candidate = sld[:index] + '-' + sld[index:]
        if _valid_sld(candidate):
            out.append({'domain': f'{candidate}.{tld}',
                        'description': f"hyphen inserted at position {index}"})
    return out


def _variants_subdomain(sld: str, tld: str) -> List[Dict[str, str]]:
    """Prepend trust-lending subdomain labels to the ORIGINAL domain."""
    out: List[Dict[str, str]] = []
    for prefix in _SUBDOMAIN_PREFIXES:
        out.append({'domain': f'{prefix}.{sld}.{tld}',
                    'description': f"subdomain prefix '{prefix}.' on the untouched original"})
    return out


def _variants_vowel_swap(sld: str, tld: str) -> List[Dict[str, str]]:
    """Swap each vowel for another vowel inside the SLD."""
    out: List[Dict[str, str]] = []
    vowels = 'aeiou'
    for index, char in enumerate(sld):
        if char not in vowels:
            continue
        for vowel in vowels:
            if vowel == char:
                continue
            candidate = sld[:index] + vowel + sld[index + 1:]
            if _valid_sld(candidate):
                out.append({'domain': f'{candidate}.{tld}',
                            'description': f"vowel swap '{char}' -> '{vowel}' at position {index}"})
    return out


def _variants_plural(sld: str, tld: str) -> List[Dict[str, str]]:
    """Append an 's' to the SLD (plural reading of the brand)."""
    if sld.endswith('s') or not _valid_sld(sld + 's'):
        return []
    return [{'domain': f'{sld}s.{tld}', 'description': "plural form ('s' appended)"}]


def _variants_singular(sld: str, tld: str) -> List[Dict[str, str]]:
    """Strip a trailing 's' from the SLD (singular reading of the brand)."""
    if not sld.endswith('s') or len(sld) < 4:
        return []
    candidate = sld[:-1]
    if not _valid_sld(candidate):
        return []
    return [{'domain': f'{candidate}.{tld}', 'description': "singular form (trailing 's' dropped)"}]


def _variants_bitsquat(sld: str, tld: str) -> List[Dict[str, str]]:
    """Corrupt each character by +/-1 codepoint or a single bit flip."""
    out: List[Dict[str, str]] = []
    allowed = set('abcdefghijklmnopqrstuvwxyz0123456789-')
    for index, char in enumerate(sld):
        replacements = {chr(ord(char) + 1), chr(ord(char) - 1)}
        replacements.update(chr(ord(char) ^ bit) for bit in (1, 2, 4, 8, 16, 32))
        for replacement in sorted(replacements):
            if replacement == char or replacement not in allowed:
                continue
            candidate = sld[:index] + replacement + sld[index + 1:]
            if _valid_sld(candidate):
                out.append({'domain': f'{candidate}.{tld}',
                            'description': f"bitsquat '{char}' -> '{replacement}' "
                                           f"(bit-level corruption at position {index})"})
    return out


def _variants_homoglyph(sld: str, tld: str) -> List[Dict[str, str]]:
    """Replace letters with their most-abused Unicode homoglyphs."""
    out: List[Dict[str, str]] = []
    for index, char in enumerate(sld):
        for glyph in HOMOGLYPHS.get(char, ''):
            candidate = sld[:index] + glyph + sld[index + 1:]
            out.append({'domain': f'{candidate}.{tld}',
                        'description': f"homoglyph '{char}' -> '{glyph}' at position {index}"})
    for source, target in HOMOGLYPH_MULTI.items():
        start = sld.find(source)
        while start != -1:
            candidate = sld[:start] + target + sld[start + len(source):]
            out.append({'domain': f'{candidate}.{tld}',
                        'description': f"multi-char confusable '{source}' reads as '{target}'"})
            start = sld.find(source, start + 1)
    return out


def _variants_ascii(sld: str, tld: str) -> List[Dict[str, str]]:
    """Swap characters with their ASCII digit/letter lookalikes."""
    out: List[Dict[str, str]] = []
    for index, char in enumerate(sld):
        lookalike = ASCII_LOOKALIKES.get(char)
        if not lookalike:
            continue
        candidate = sld[:index] + lookalike + sld[index + 1:]
        if _valid_sld(candidate):
            out.append({'domain': f'{candidate}.{tld}',
                        'description': f"ascii lookalike '{char}' -> '{lookalike}' "
                                       f"at position {index}"})
    return out


def _variants_tld(sld: str, tld: str) -> List[Dict[str, str]]:
    """Keep the SLD, swap the TLD for another common one."""
    out: List[Dict[str, str]] = []
    for replacement in COMMON_TLDS:
        if replacement == tld:
            continue
        out.append({'domain': f'{sld}.{replacement}',
                    'description': f"same SLD under the common TLD '.{replacement}'"})
    return out


def _brand_matches(sld: str) -> List[str]:
    """Popular-domain SLDs equal to, or within edit distance 2 of, ``sld``."""
    matched: List[str] = []
    for entry in _popular_domains():
        labels = entry.split('.')
        if len(labels) < 2:
            continue
        brand = labels[-2]
        if brand == sld or damerau_levenshtein(sld, brand, cap=2) <= 2:
            matched.append(brand)
    return matched


def _variants_combo(sld: str, tld: str) -> List[Dict[str, str]]:
    """Mash phishing brand words onto the SLD (only for popular brands)."""
    if not _brand_matches(sld):
        return []
    out: List[Dict[str, str]] = []
    for word in _combo_words():
        for candidate, description in (
            (f'{sld}{word}', f"combo-squat: '{word}' appended directly"),
            (f'{word}{sld}', f"combo-squat: '{word}' prepended directly"),
            (f'{sld}-{word}', f"combo-squat: '{word}' appended with a hyphen"),
            (f'{word}-{sld}', f"combo-squat: '{word}' prepended with a hyphen"),
        ):
            candidate_sld = candidate.strip('-')
            if _valid_sld(candidate_sld):
                out.append({'domain': f'{candidate_sld}.{tld}', 'description': description})
    return out


#: Category registry in generation (and presentation) order.
_CATEGORY_FUNCS: Tuple[Tuple[str, Any], ...] = (
    ('omission', _variants_omission),
    ('insertion', _variants_insertion),
    ('substitution', _variants_substitution),
    ('transposition', _variants_transposition),
    ('duplication', _variants_duplication),
    ('hyphenation', _variants_hyphenation),
    ('subdomain', _variants_subdomain),
    ('vowel_swap', _variants_vowel_swap),
    ('plural', _variants_plural),
    ('singular', _variants_singular),
    ('bitsquat', _variants_bitsquat),
    ('homoglyph', _variants_homoglyph),
    ('ascii_similarity', _variants_ascii),
    ('tld_swap', _variants_tld),
    ('combo_squat', _variants_combo),
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_variants(domain: str) -> List[Dict[str, str]]:
    """
    EXPERIMENTAL: generate typo/squat variants of a domain.

    Fifteen families, generated in this order: omission, insertion,
    substitution, transposition, duplication, hyphenation, subdomain,
    vowel_swap, plural, singular, bitsquat, homoglyph, ascii_similarity,
    tld_swap and combo_squat (the last one only fires when the SLD matches
    or sits within Damerau-Levenshtein distance 2 of a ``popular_domains``
    pack entry). URLs are tolerated (scheme/path/port stripped); the
    registrable core (last two labels) is what gets mutated.

    Args:
        domain: the domain (or URL) to defend, e.g. ``'google.com'``.

    Returns:
        ``[{'domain': str, 'category': str, 'description': str}]`` -
        de-duplicated by domain string, the original domain excluded,
        capped at :data:`_MAX_VARIANTS` entries. Anything unparsable as a
        domain yields ``[]``. Never raises.
    """
    parsed = _parse_domain(domain)
    if parsed is None:
        return []
    sld, tld, original = parsed
    seen = {original}
    variants: List[Dict[str, str]] = []
    for category, generator in _CATEGORY_FUNCS:
        for produced in generator(sld, tld):
            candidate = produced['domain']
            if candidate in seen:
                continue
            seen.add(candidate)
            variants.append({'domain': candidate, 'category': category,
                             'description': produced['description']})
            if len(variants) >= _MAX_VARIANTS:
                return variants
    return variants


#: Base risk by Damerau-Levenshtein distance from the original domain.
_DISTANCE_BASE: Dict[int, int] = {0: 100, 1: 88, 2: 74, 3: 60, 4: 48, 5: 38}

#: Base risk for distances beyond the table.
_DEFAULT_BASE = 30

#: Fixed bonuses per category (deception hard to spot at a glance).
_CATEGORY_BONUS: Dict[str, int] = {
    'homoglyph': 22, 'bitsquat': 18, 'ascii_similarity': 18, 'combo_squat': 16,
    'subdomain': 14, 'tld_swap': 10, 'vowel_swap': 8, 'omission': 6,
    'transposition': 6, 'plural': 6, 'singular': 6, 'substitution': 5,
    'duplication': 5, 'insertion': 5, 'hyphenation': 4,
}

#: Bonus when a phishing keyword from the data pack appears in the variant.
_KEYWORD_BONUS = 8


def score_variants(variants: List[Dict[str, Any]], original: str) -> List[Dict[str, Any]]:
    """
    EXPERIMENTAL: add a 0-100 deception-risk score and sort descending.

    Scoring rubric (documented so verdicts are auditable):

    * **Base (distance):** Damerau-Levenshtein distance between the full
      variant domain and the original - 0:100, 1:88, 2:74, 3:60, 4:48,
      5:38, anything further:30. Typos that still read like the brand are
      the dangerous ones.
    * **Category bonus (fixed):** homoglyph +22 (visually near-perfect
      impersonation), bitsquat +18, ascii_similarity +18 (o/0, l/1),
      combo_squat +16 (adds credential-harvest words), subdomain +14
      (looks official), tld_swap +10, vowel_swap +8, the mechanical typo
      families +4..+6.
    * **Keyword bonus:** +8 when any ``phishing_keywords`` pack keyword
      (>= 4 chars) appears inside the variant domain.
    * The sum is clamped to 0-100; ties break alphabetically by domain.

    Args:
        variants: list as returned by :func:`generate_variants` (entries
            without a ``domain`` key are dropped, never crash the run).
        original: the original domain (used for distance scoring).

    Returns:
        New list of ``{'domain', 'category', 'description', 'risk'}``
        sorted by risk descending. Never raises.
    """
    parsed = _parse_domain(original)
    reference = parsed[2] if parsed else str(original or '').strip().lower()
    keywords = [word for word in _phishing_keywords() if len(word) >= 4]
    scored: List[Dict[str, Any]] = []
    for variant in variants:
        if not isinstance(variant, dict) or not variant.get('domain'):
            continue
        domain = str(variant['domain'])
        distance = damerau_levenshtein(domain, reference, cap=8)
        base = _DISTANCE_BASE.get(distance, _DEFAULT_BASE)
        bonus = _CATEGORY_BONUS.get(str(variant.get('category', '')), 0)
        if any(keyword in domain for keyword in keywords):
            bonus += _KEYWORD_BONUS
        enriched = dict(variant)
        enriched['risk'] = max(0, min(100, base + bonus))
        scored.append(enriched)
    scored.sort(key=lambda item: (-int(item.get('risk', 0)), str(item.get('domain', ''))))
    return scored


#: Column headers matching :func:`render_variants_table` row shape.
TABLE_HEADERS: Tuple[str, ...] = ('Domain', 'Category', 'Risk', 'Description')


def render_variants_table(variants: List[Dict[str, Any]]) -> List[List[Any]]:
    """
    EXPERIMENTAL: shape variants into a tabulate-ready list of rows.

    Args:
        variants: scored or unscored variant dicts (risk renders as '-'
            when :func:`score_variants` has not been applied).

    Returns:
        ``[[domain, category, risk, description], ...]`` - feed straight
        to ``tabulate.tabulate(rows, headers=squatting.TABLE_HEADERS)``.
        Non-dict entries are skipped; never raises.
    """
    rows: List[List[Any]] = []
    for variant in variants:
        if not isinstance(variant, dict):
            continue
        risk = variant.get('risk')
        rows.append([
            str(variant.get('domain', '')),
            str(variant.get('category', '')),
            risk if isinstance(risk, int) else '-',
            str(variant.get('description', '')),
        ])
    return rows
