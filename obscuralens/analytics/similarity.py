"""
String similarity and fuzzy matching for identity resolution (v6.0 Part 2).

OSINT lives in a world of near-misses: ``john.smith@`` vs ``johns.mith@``,
``paypa1.com`` vs ``paypal.com``, ``AceGuru`` vs ``AceGuruu``. Attackers
register lookalikes on purpose (typosquatting) and humans type lookalikes
by accident (form entry), and both land in the analyst's lap as "is this
the same actor?" questions. Exact equality answers none of them.

This module packages the standard toolbox - Levenshtein distance, Jaro and
Jaro-Winkler similarity, Soundex and a simplified Metaphone hint, n-gram
Jaccard and Sørensen-Dice, sparse-dict cosine, and the combined
:func:`typosquat_score` - all on pure stdlib with defensive input handling,
so a ``None`` candidate or a non-string never detonates a matching pipeline.

Design contract:

* **Case-insensitive by default** (``casefold=True`` parameters), because
  usernames, domains and e-mails do not case-differentiate in practice.
* **0.0 means "nothing in common", 1.0 means "identical"** across every
  similarity function; distances (Levenshtein) are counts in the other
  direction. Ratios make different algorithms comparable and cacheable.
* **Never raises**: ``None`` and non-string inputs coerce to text ('' for
  None, ``str(x)`` otherwise) and simply produce 0-similarity results
  rather than exceptions.
* **No heavyweight deps**: difflib's ratios are convenient but opaque;
  these implementations are the textbook ones, documented per function.
"""

import math
from typing import Any, Dict, Iterable, List, Set

__all__ = [
    'cosine_similarity',
    'dice_coefficient',
    'jaro',
    'jaro_winkler',
    'levenshtein',
    'levenshtein_ratio',
    'metaphone_hint',
    'most_similar',
    'ngram_similarity',
    'soundex',
    'typosquat_score',
]

#: English vowels stripped by the typosquat skeleton heuristic.
_VOWELS = frozenset('aeiouy')

#: Maximum prefix length that boosts Jaro-Winkler (classic cap of 4).
_MAX_WINKLER_PREFIX = 4

#: Upper bound for the Winkler prefix scale (values beyond 0.25 can exceed 1.0).
_MAX_PREFIX_SCALE = 0.25

#: Common prefix length (capped) honoured by the typosquat score.
_TYPOSQUAT_PREFIX_CAP = 4

#: Soundex letter groups: consonant -> digit code.
_SOUNDEX_CODE = {
    'B': '1', 'F': '1', 'P': '1', 'V': '1',
    'C': '2', 'G': '2', 'J': '2', 'K': '2', 'Q': '2', 'S': '2', 'X': '2', 'Z': '2',
    'D': '3', 'T': '3',
    'L': '4',
    'M': '5', 'N': '5',
    'R': '6',
}

#: Letters that Soundex drops but that do *not* separate same-code groups.
_SOUNDEX_TRANSPARENT = frozenset('HW')

#: Simplified Metaphone prefix rules (initial-cluster simplifications).
_METAPHONE_PREFIX = (
    ('KN', 'N'),
    ('GN', 'N'),
    ('PN', 'N'),
    ('WR', 'R'),
    ('AE', 'E'),
)


# ---------------------------------------------------------------------------
# Text normalisation and n-gram helpers
# ---------------------------------------------------------------------------

def _as_text(value: Any) -> str:
    """Coerce anything to a string: None -> '', others via str()."""
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    return str(value)


def _prep(value: Any, casefold: bool) -> str:
    """Normalise input to comparable text (None-safe, optionally folded)."""
    text = _as_text(value)
    return text.casefold() if casefold else text


def _ngrams(text: str, n: int) -> Set[str]:
    """Set of character n-grams; strings shorter than n yield an empty set."""
    if n < 1 or len(text) < n:
        return set()
    return {text[i:i + n] for i in range(len(text) - n + 1)}


def _common_prefix_len(a: str, b: str) -> int:
    """Length of the shared leading run of two strings."""
    limit = min(len(a), len(b))
    for i in range(limit):
        if a[i] != b[i]:
            return i
    return limit


# ---------------------------------------------------------------------------
# Edit distance
# ---------------------------------------------------------------------------

def levenshtein(a: Any, b: Any, casefold: bool = True) -> int:
    """Levenshtein edit distance (insert / delete / substitute, cost 1 each).

    The two-row rolling-array implementation keeps only ``O(min(len(a),
    len(b)))`` memory - the full (m+1)x(n+1) matrix is never materialised,
    which matters when a matching pipeline scores thousands of candidates
    per query.

    Args:
        a: First string (None -> '', non-strings via str()).
        b: Second string (None -> '', non-strings via str()).
        casefold: Fold case before comparing (default True).

    Returns:
        The minimum number of single-character edits turning ``a`` into
        ``b``. Identical strings give 0; an empty versus a length-n string
        gives n.

    Example:
        >>> levenshtein('kitten', 'sitting')
        3
        >>> levenshtein('Google', 'google')
        0
    """
    left = _prep(a, casefold)
    right = _prep(b, casefold)
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    # Keep the shorter string as the row axis to minimise the rolling rows.
    if len(right) > len(left):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i] + [0] * len(right)
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current[j] = min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + cost,  # substitution / match
            )
        previous = current
    return previous[-1]


def levenshtein_ratio(a: Any, b: Any, casefold: bool = True) -> float:
    """Normalised Levenshtein similarity: ``1 - distance / max_len``.

    Args:
        a: First string (None -> '', non-strings via str()).
        b: Second string (None -> '', non-strings via str()).
        casefold: Fold case before comparing (default True).

    Returns:
        Similarity in ``[0, 1]`` - 1.0 for identical (or two empty) strings,
        0.0 when nothing matches. Two empty strings are a perfect match.

    Example:
        >>> round(levenshtein_ratio('kitten', 'sitting'), 4)
        0.5714
        >>> levenshtein_ratio('', '')
        1.0
    """
    left = _prep(a, casefold)
    right = _prep(b, casefold)
    longest = max(len(left), len(right))
    if longest == 0:
        return 1.0
    return 1.0 - levenshtein(left, right, casefold=False) / longest


# ---------------------------------------------------------------------------
# Jaro family
# ---------------------------------------------------------------------------

def jaro(a: Any, b: Any, casefold: bool = True) -> float:
    """Jaro similarity - the letter-shuffle aware sibling of edit distance.

    Counts matches within a window of ``floor(max(len)/2) - 1`` positions
    and penalises transpositions, yielding ``1/3 * (m/|a| + m/|b| + (m -
    t/2)/m)``. Jaro rewards strings that keep most letters in roughly the
    right places, which is exactly the shape of keying mistakes.

    Args:
        a: First string (None -> '', non-strings via str()).
        b: Second string (None -> '', non-strings via str()).
        casefold: Fold case before comparing (default True).

    Returns:
        Similarity in ``[0, 1]``: 1.0 identical, 0.0 no shared characters
        (or one side empty). Two empty strings are a perfect match.

    Example:
        >>> round(jaro('MARTHA', 'MARHTA'), 4)
        0.9444
        >>> round(jaro('DWAYNE', 'DUANE'), 4)
        0.8222
    """
    left = _prep(a, casefold)
    right = _prep(b, casefold)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    len_left, len_right = len(left), len(right)
    window = max(len_left, len_right) // 2 - 1
    if window < 0:
        window = 0
    left_matched = [False] * len_left
    right_matched = [False] * len_right
    matches = 0
    for i, left_char in enumerate(left):
        lower = max(0, i - window)
        upper = min(len_right, i + window + 1)
        for j in range(lower, upper):
            if not right_matched[j] and right[j] == left_char:
                left_matched[i] = True
                right_matched[j] = True
                matches += 1
                break
    if matches == 0:
        return 0.0
    # Count matched characters that appear in a different order.
    transpositions = 0
    k = 0
    for i in range(len_left):
        if not left_matched[i]:
            continue
        while not right_matched[k]:
            k += 1
        if left[i] != right[k]:
            transpositions += 1
        k += 1
    transpositions //= 2
    return (
        matches / len_left
        + matches / len_right
        + (matches - transpositions) / matches
    ) / 3.0


def jaro_winkler(
    a: Any,
    b: Any,
    prefix_scale: float = 0.1,
    max_prefix: int = 4,
    casefold: bool = True,
) -> float:
    """Jaro-Winkler similarity with the common-prefix boost.

    Winkler's refinement: when the Jaro score already clears 0.7, a shared
    prefix of up to ``max_prefix`` characters adds
    ``prefix * prefix_scale * (1 - jaro)`` - because human typos rarely
    disturb the start of a name, agreement up front is strong evidence.

    Args:
        a: First string (None -> '', non-strings via str()).
        b: Second string (None -> '', non-strings via str()).
        prefix_scale: Boost weight per prefix character (default 0.1,
            clamped to ``[0, 0.25]`` so the result can never exceed 1.0 by
            construction of the formula's cap).
        max_prefix: Maximum boosting prefix length (default 4; values
            below 1 disable the boost).
        casefold: Fold case before comparing (default True).

    Returns:
        Similarity in ``[0, 1]`` (hard-capped at 1.0).

    Example:
        >>> round(jaro_winkler('MARTHA', 'MARHTA'), 4)
        0.9611
        >>> round(jaro_winkler('DIXON', 'DICKSONX'), 4)
        0.8133
    """
    scale = prefix_scale
    if not isinstance(scale, (int, float)) or isinstance(scale, bool) \
            or not math.isfinite(float(scale)):
        scale = 0.1
    scale = min(max(float(scale), 0.0), _MAX_PREFIX_SCALE)
    base = jaro(a, b, casefold=casefold)
    if base <= 0.7:
        return base
    left = _prep(a, casefold)
    right = _prep(b, casefold)
    try:
        limit = int(max_prefix)
    except (TypeError, ValueError):
        limit = _MAX_WINKLER_PREFIX
    if limit < 1:
        return base
    prefix = min(_common_prefix_len(left, right), limit)
    return min(1.0, base + prefix * scale * (1.0 - base))


# ---------------------------------------------------------------------------
# Phonetic algorithms
# ---------------------------------------------------------------------------

def soundex(s: Any) -> str:
    """Standard American Soundex code (4 characters: letter + 3 digits).

    The 1918 census algorithm, still the fastest "do these names sound
    alike" filter: the first letter is preserved, consonants map to six
    digit groups, adjacent same-code letters collapse, ``H``/``W`` do not
    separate same-code letters while vowels do, and the code is zero-padded
    or truncated to exactly four characters (NARA rules).

    Args:
        s: Input string (None -> '', non-strings via str()). Non-alphabetic
            characters are ignored; only ASCII letters are coded.

    Returns:
        The 4-character Soundex code, or ``''`` when no ASCII letters exist.

    Example:
        >>> soundex('Robert') == soundex('Rupert')
        True
        >>> soundex('Robert')
        'R163'
        >>> soundex('Tymczak')
        'T522'
        >>> soundex('Ashcraft')
        'A261'
    """
    text = _as_text(s).upper()
    letters = [ch for ch in text if 'A' <= ch <= 'Z']
    if not letters:
        return ''
    output = letters[0]
    previous_code = _SOUNDEX_CODE.get(letters[0], '')
    for ch in letters[1:]:
        if len(output) >= 4:
            break
        if ch in _SOUNDEX_TRANSPARENT:
            # H and W vanish without breaking same-code adjacency.
            continue
        code = _SOUNDEX_CODE.get(ch, '')
        if code:
            if code != previous_code:
                output += code
            previous_code = code
        else:
            # Vowel: dropped, but resets adjacency so a repeated code
            # after a vowel is coded again.
            previous_code = ''
    return output[:4].ljust(4, '0')


def metaphone_hint(s: Any) -> str:
    """Simplified Metaphone-style phonetic hint.

    **This is a deliberately reduced variant, not Double Metaphone.** It
    applies only the highest-yield classic rules: collapse runs of repeated
    letters, and simplify the notorious silent initial clusters ``KN`` ->
    ``N``, ``GN`` -> ``N``, ``PN`` -> ``N``, ``WR`` -> ``R`` and ``AE`` ->
    ``E``. It exists for one job - cheap grouping of obviously-identical
    sounding handles before an expensive edit-distance pass - and makes no
    claim about the full Metaphone rule set (no vowel context rules, no
    origin heuristics, no alternate codes).

    Args:
        s: Input string (None -> '', non-strings via str()). Non-alphabetic
            characters are dropped; input is upper-cased.

    Returns:
        The simplified phonetic skeleton (unpadded, variable length).

    Example:
        >>> metaphone_hint('KNIGHT')
        'NIGHT'
        >>> metaphone_hint('GNOME')
        'NOME'
        >>> metaphone_hint('WRONG')
        'RONG'
        >>> metaphone_hint('LETTER')
        'LETER'
    """
    text = _as_text(s).upper()
    letters = [ch for ch in text if 'A' <= ch <= 'Z']
    if not letters:
        return ''
    for prefix, replacement in _METAPHONE_PREFIX:
        if letters and ''.join(letters).startswith(prefix):
            letters = list(replacement) + letters[len(prefix):]
            break
    collapsed: List[str] = []
    for ch in letters:
        if not collapsed or collapsed[-1] != ch:
            collapsed.append(ch)
    return ''.join(collapsed)


# ---------------------------------------------------------------------------
# N-gram similarity
# ---------------------------------------------------------------------------

def ngram_similarity(a: Any, b: Any, n: int = 2, casefold: bool = True) -> float:
    """Jaccard similarity over character n-gram sets.

    Bigram overlap is the classic compromise between letter-level and
    word-level comparison: it tolerates a single insertion or swap while
    still noticing wholesale differences.

    Args:
        a: First string (None -> '', non-strings via str()).
        b: Second string (None -> '', non-strings via str()).
        n: Gram length (default 2 bigrams); values below 1 are treated as 1.
        casefold: Fold case before comparing (default True).

    Returns:
        ``|A intersect B| / |A union B|`` in ``[0, 1]``; two strings too
        short to form grams (including two empties) are considered
        identical and give 1.0, one short/empty side gives 0.0.

    Example:
        >>> round(ngram_similarity('night', 'nacht'), 4)
        0.1429
    """
    try:
        size = int(n)
    except (TypeError, ValueError):
        size = 2
    if size < 1:
        size = 1
    left = _ngrams(_prep(a, casefold), size)
    right = _ngrams(_prep(b, casefold), size)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    union = left | right
    if not union:  # pragma: no cover - both non-empty implies non-empty union
        return 1.0
    return len(left & right) / len(union)


def dice_coefficient(a: Any, b: Any, n: int = 2, casefold: bool = True) -> float:
    """Sørensen-Dice coefficient over character n-grams.

    ``2 * |A intersect B| / (|A| + |B|)`` - like Jaccard but weighted
    toward shared content, so one extra gram in a long string hurts less.
    Dice tends to run higher than Jaccard on the same pair, which suits
    candidate-ranking (more visible separation near the top).

    Args:
        a: First string (None -> '', non-strings via str()).
        b: Second string (None -> '', non-strings via str()).
        n: Gram length (default 2 bigrams); values below 1 are treated as 1.
        casefold: Fold case before comparing (default True).

    Returns:
        Coefficient in ``[0, 1]``; two gram-less strings give 1.0.

    Example:
        >>> round(dice_coefficient('night', 'nacht'), 4)
        0.25
    """
    try:
        size = int(n)
    except (TypeError, ValueError):
        size = 2
    if size < 1:
        size = 1
    left = _ngrams(_prep(a, casefold), size)
    right = _ngrams(_prep(b, casefold), size)
    total = len(left) + len(right)
    if total == 0:
        return 1.0
    return 2.0 * len(left & right) / total


# ---------------------------------------------------------------------------
# Vector similarity
# ---------------------------------------------------------------------------

def cosine_similarity(vec_a: Dict[Any, float], vec_b: Dict[Any, float]) -> float:
    """Cosine similarity between two sparse dict-of-weight vectors.

    For feature bags like ``{'osint': 3, 'recon': 1}`` (term counts, rule
    weights). Only shared keys contribute to the dot product; magnitudes
    come from the full vectors.

    Args:
        vec_a: Mapping of feature -> weight. Non-numeric or non-finite
            weights are skipped; ``None`` or a non-dict yields 0.0.
        vec_b: Second mapping, same rules.

    Returns:
        Cosine of the angle between the vectors in ``[-1, 1]`` (hard-clamped
        against float drift). When either vector is empty or has zero
        magnitude the direction is undefined and the convention here is
        0.0 - no measurable similarity - rather than a division by zero.

    Example:
        >>> round(cosine_similarity({'a': 1, 'b': 1}, {'a': 1}), 4)
        0.7071
        >>> cosine_similarity({}, {})
        0.0
    """
    if not isinstance(vec_a, dict) or not isinstance(vec_b, dict):
        return 0.0

    def _numeric(source: Dict[Any, float]) -> Dict[Any, float]:
        cleaned: Dict[Any, float] = {}
        for key, weight in source.items():
            if isinstance(weight, bool) or not isinstance(weight, (int, float)):
                continue
            value = float(weight)
            if math.isfinite(value):
                cleaned[key] = value
        return cleaned

    left = _numeric(vec_a)
    right = _numeric(vec_b)
    if not left or not right:
        return 0.0
    dot = 0.0
    for key, weight in left.items():
        if key in right:
            dot += weight * right[key]
    norm_a = math.sqrt(sum(w * w for w in left.values()))
    norm_b = math.sqrt(sum(w * w for w in right.values()))
    if norm_a <= 0.0 or norm_b <= 0.0:
        return 0.0
    score = dot / (norm_a * norm_b)
    return max(-1.0, min(1.0, score))


# ---------------------------------------------------------------------------
# Retrieval and combination scoring
# ---------------------------------------------------------------------------

def most_similar(
    query: Any,
    candidates: Iterable[Any],
    method: str = 'jaro_winkler',
    top: int = 5,
    threshold: float = 0.5,
) -> List[Dict[str, Any]]:
    """Rank candidates against a query with a chosen string metric.

    The lookup behind "did we see this handle before" screens: score every
    candidate, drop the weak ones, return the strongest few with the method
    and score attached so the result is self-documenting in a report.

    Args:
        query: The string to match (None -> '', non-strings via str()).
        candidates: Iterable of candidate strings; ``None`` input yields [].
        method: One of ``'levenshtein_ratio'``, ``'jaro'``,
            ``'jaro_winkler'``, ``'ngram'``, ``'dice'``. Unknown method
            names return an empty list (a typo in a pipeline config must
            not crash the run).
        top: Maximum number of results (values below 0 mean 0).
        threshold: Minimum score to keep (default 0.5).

    Returns:
        List of ``{'value', 'score', 'method'}`` dicts sorted by score
        descending (ties broken alphabetically by value).

    Example:
        >>> hits = most_similar('paypal.com', ['paypal.com', 'paypa1.com', 'gmail.com'],
        ...                     method='jaro_winkler')
        >>> hits[0]['value'], hits[0]['method']
        ('paypal.com', 'jaro_winkler')
    """
    registry = {
        'levenshtein_ratio': levenshtein_ratio,
        'jaro': jaro,
        'jaro_winkler': jaro_winkler,
        'ngram': ngram_similarity,
        'dice': dice_coefficient,
    }
    scorer = registry.get(method) if isinstance(method, str) else None
    if scorer is None:
        return []
    try:
        limit = int(top)
    except (TypeError, ValueError):
        limit = 5
    if limit < 0:
        limit = 0
    if candidates is None:
        return []
    try:
        iterator = iter(candidates)
    except TypeError:
        return []

    scored: List[Dict[str, Any]] = []
    for candidate in iterator:
        score = scorer(query, candidate)
        if score >= threshold:
            scored.append({'value': _as_text(candidate), 'score': score, 'method': method})
    scored.sort(key=lambda item: (-item['score'], item['value']))
    return scored[:limit]


def _strip_vowels(text: str) -> str:
    """Remove vowels for the typosquat consonant skeleton."""
    return ''.join(ch for ch in text if ch not in _VOWELS)


def typosquat_score(a: Any, b: Any) -> float:
    """Combined lookalike risk score aimed at domain and brand squatting.

    Three signals an attacker cannot simultaneously avoid when imitating a
    brand, each contributing to a 0..1 risk:

    * **Edit closeness (50%)** - Levenshtein ratio: a squat is *near* the
      original ('paypa1' vs 'paypal', 'g00gle' vs 'google').
    * **Prefix retention (25%)** - the first four characters matching:
      lookalikes keep the trusted start of a name so victims skim past
      the rest.
    * **Vowel-skeleton match (25%)** - Levenshtein ratio of the
      vowel-stripped skeletons: dropping, adding or swapping vowels
      ('microsft', 'amazan') leaves the consonant frame intact, and is a
      favourite trick because it reads the same aloud.

    Args:
        a: First string (None -> '', non-strings via str()).
        b: Second string (None -> '', non-strings via str()).

    Returns:
        Risk score in ``[0, 1]`` - higher means the pair looks more like a
        deliberate typosquat of one another. Identical strings score 1.0;
        empty input (nothing to imitate) scores 0.0. This is a heuristic
        triage score for humans, not a verdict.

    Example:
        >>> score = typosquat_score('paypa1.com', 'paypal.com')
        >>> round(score, 2)
        0.91
        >>> typosquat_score('totally-different.net', 'google.com') < 0.5
        True
    """
    left = _as_text(a).casefold()
    right = _as_text(b).casefold()
    if not left or not right:
        return 0.0
    edit = levenshtein_ratio(left, right, casefold=False)
    prefix = min(_common_prefix_len(left, right), _TYPOSQUAT_PREFIX_CAP) / _TYPOSQUAT_PREFIX_CAP
    skeleton = levenshtein_ratio(_strip_vowels(left), _strip_vowels(right), casefold=False)
    score = 0.5 * edit + 0.25 * prefix + 0.25 * skeleton
    return max(0.0, min(1.0, score))
