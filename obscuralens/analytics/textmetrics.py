"""
Text analytics for OSINT evidence triage (v6.0 Part 2).

Real investigations drown in prose: paste dumps, breach notification text,
forum posts, ransom notes, advisory bodies, chat exports. This module turns
that prose into numbers a report can cite - token statistics, TF-IDF
keyword mining, Flesch readability, script/language fingerprints, character
profiles, extractive summaries, redaction sweeps and multi-metric string
similarity - using nothing but the Python standard library.

It deliberately sits *on top of* the layers Part 2 already shipped: fuzzy
scoring delegates to :mod:`obscuralens.analytics.similarity`, and entity
detection delegates to the validator-driven
:mod:`obscuralens.experimental.entity_extract` pipeline instead of
re-implementing a second, drifting set of regexes.

Design contract (mirrored across the analytics package):

* **Defensive by default.** ``None``, non-string and empty input yields a
  safe empty structure (``[]``, ``{}``, ``''`` or a zeroed profile), never
  an exception; a broken sentence or unparsable row is dropped, not fatal.
* **Pure functions.** No state, no I/O, no network: every call is safe to
  cache, replay and parallelise inside a rendered report.
* **Unicode-aware.** Tokenisation uses ``\\w+`` over real Unicode, scripts
  are detected through :mod:`unicodedata` names, and CJK text is handled
  as first-class input rather than mangled through ASCII assumptions.

The readability and language-guess heuristics are documented approximations
- good enough to triage a paste dump, not a substitute for a linguist.
"""

import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from ..experimental.entity_extract import extract_entities, redact_entities
from .similarity import (
    cosine_similarity,
    jaro_winkler,
    levenshtein_ratio,
    ngram_similarity,
)

__all__ = [
    'char_profile',
    'detect_language_script',
    'extract_keywords',
    'ngrams',
    'readability',
    'redaction_sweep',
    'summarize_text',
    'term_frequencies',
    'text_similarity_report',
    'tfidf',
    'tokenize',
]

#: Unicode-aware word splitter: letters, digits, underscores and CJK runs
#: (``\\w`` is Unicode-aware for ``str`` patterns in Python 3).
_TOKEN_RE = re.compile(r'\w+')

#: Sentence terminators: full stop, question, exclamation, newline runs.
_SENTENCE_RE = re.compile(r'[.!?]+|\n+')

#: English vowel groups for the syllable-count approximation.
_VOWEL_GROUP_RE = re.compile(r'[aeiouy]+')

#: Hexadecimal characters, used by :func:`char_profile`'s hex-leaning ratio.
_HEX_CHARS = frozenset('0123456789abcdefABCDEF')

#: Compact English stopword list (~120 high-frequency function words).
_ENGLISH_STOPWORDS = frozenset([
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'also', 'am',
    'an', 'and', 'another', 'any', 'are', "aren't", 'as', 'at', 'be',
    'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but',
    'by', 'can', 'cannot', 'could', "couldn't", 'did', "didn't", 'do',
    'does', "doesn't", 'doing', "don't", 'down', 'during', 'each', 'either',
    'few', 'for', 'from', 'further', 'had', "hadn't", 'has', "hasn't",
    'have', "haven't", 'having', 'he', 'her', 'here', 'hers', 'herself',
    'him', 'himself', 'his', 'how', 'however', 'i', 'if', 'in', 'into', 'is',
    "isn't", 'it', 'its', 'itself', 'just', "let's", 'may', 'me', 'might',
    'more', 'most', 'must', "mustn't", 'my', 'myself', 'neither', 'no', 'nor',
    'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our',
    'ours', 'ourselves', 'out', 'over', 'own', 'per', 'same', 'shall',
    "shan't", 'she', 'should', "shouldn't", 'so', 'some', 'such', 'than',
    'that', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there',
    'therefore', 'these', 'they', 'this', 'those', 'though', 'through',
    'thus', 'to', 'too', 'under', 'until', 'up', 'upon', 'via', 'was',
    "wasn't", 'we', 'were', "weren't", 'what', 'when', 'where', 'whether',
    'which', 'while', 'who', 'whom', 'why', 'with', 'within', 'without',
    "won't", 'would', "wouldn't", 'you', 'your', 'yours', 'yourself',
    'yourselves',
])

#: Common Chinese function words / particles (~20), used both for keyword
#: filtering and as the zh language hint.
_CHINESE_STOPWORDS = frozenset(
    '的了是在有和就不都而与及等把被让从到对为以于或也没很这那你我他她它它们'
    '什么怎么因为所以但是')

#: Combined stopword vocabulary for keyword extraction.
_STOPWORDS = _ENGLISH_STOPWORDS | _CHINESE_STOPWORDS

#: Known syllable-count exceptions where the vowel-group heuristic fails
#: (checked before the heuristic, lower-case keys only).
_SYLLABLE_EXCEPTIONS = {
    'being': 2, 'business': 2, 'businesses': 3, 'curious': 3, 'doing': 2,
    'everything': 3, 'everywhere': 3, 'forever': 3, 'going': 2, 'obvious': 3,
    'previous': 3, 'seeing': 2, 'serious': 3, 'shoreline': 2, 'simile': 3,
    'somebody': 3, 'various': 3,
}

#: Tracked Unicode scripts in canonical order (ties in
#: :func:`detect_language_script` resolve to the earlier script).
_SCRIPT_ORDER: Tuple[str, ...] = (
    'Latin', 'Cyrillic', 'Greek', 'Han', 'Hangul', 'Hiragana', 'Katakana',
    'Arabic', 'Hebrew', 'Devanagari', 'Thai',
)

#: Script name -> prefix of the Unicode character name (unicodedata.name).
_SCRIPT_PREFIXES: Dict[str, str] = {
    'Latin': 'LATIN',
    'Cyrillic': 'CYRILLIC',
    'Greek': 'GREEK',
    'Han': 'CJK',
    'Hangul': 'HANGUL',
    'Hiragana': 'HIRAGANA',
    'Katakana': 'KATAKANA',
    'Arabic': 'ARABIC',
    'Hebrew': 'HEBREW',
    'Devanagari': 'DEVANAGARI',
    'Thai': 'THAI',
}

#: High-frequency stopword hints per language (~10 each) for the language
#: guess. zh/ja are matched character-wise (no spaces in those scripts).
_LANGUAGE_HINTS: Dict[str, frozenset] = {
    'en': frozenset(('the', 'and', 'is', 'of', 'to', 'in', 'that', 'it',
                     'for', 'was')),
    'zh': frozenset('的了是在有我你他这不和就'),
    'ja': frozenset(('の', 'は', 'が', 'を', 'に', 'で', 'と', 'です', 'ます',
                     'から')),
    'ko': frozenset(('은', '는', '이', '가', '을', '를', '에', '의', '도',
                     '하다')),
    'de': frozenset(('der', 'die', 'das', 'und', 'ist', 'von', 'zu', 'den',
                     'mit', 'sich')),
    'fr': frozenset(('le', 'la', 'les', 'de', 'et', 'est', 'en', 'du', 'que',
                     'qui')),
    'es': frozenset(('el', 'la', 'de', 'que', 'y', 'en', 'los', 'del', 'se',
                     'por')),
    'ru': frozenset(('и', 'в', 'не', 'на', 'что', 'с', 'по', 'для', 'это',
                     'как')),
}

#: Flesch Reading Ease score bands (score floor -> label), high to low.
_FLESCH_BANDS: Tuple[Tuple[float, str], ...] = (
    (90.0, 'very easy'), (80.0, 'easy'), (70.0, 'fairly easy'),
    (60.0, 'plain English'), (50.0, 'fairly difficult'), (30.0, 'difficult'),
    (0.0, 'very difficult'),
)

#: Empty readability envelope reused for unusable input.
_EMPTY_READABILITY: Dict[str, Any] = {
    'flesch_reading_ease': None,
    'flesch_kincaid_grade': None,
    'flesch_label': None,
    'sentences': 0,
    'words': 0,
    'syllables': 0,
    'avg_words_per_sentence': None,
    'avg_syllables_per_word': None,
}


# ---------------------------------------------------------------------------
# Tokenisation and term statistics
# ---------------------------------------------------------------------------

def tokenize(text: Any, lowercase: bool = True, min_length: int = 1) -> List[str]:
    """Split text into Unicode word tokens.

    Uses the ``\\w+`` regular expression over ``str`` (Unicode-aware in
    Python 3), so Latin words, digits, underscores and uninterrupted CJK
    runs all become tokens. Punctuation and whitespace vanish.

    Args:
        text: The text to tokenise. Non-string input (``None``, numbers,
            objects) yields an empty list rather than a ``str()`` surprise.
        lowercase: Lower-case every token (default True) so downstream
            frequency counting is case-insensitive.
        min_length: Drop tokens shorter than this (values below 1 behave
            as 1; non-numeric values fall back to 1).

    Returns:
        List of tokens in order of appearance. Never raises.

    Example:
        >>> tokenize('Hello, World!')
        ['hello', 'world']
        >>> tokenize('这是中文文本', lowercase=False)
        ['这是中文文本']
    """
    if not isinstance(text, str):
        return []
    tokens = _TOKEN_RE.findall(text)
    if lowercase:
        tokens = [token.lower() for token in tokens]
    keep = _safe_int(min_length, 1)
    if keep < 1:
        keep = 1
    return [token for token in tokens if len(token) >= keep]


def _safe_int(value: Any, default: int) -> int:
    """Best-effort integer coercion with a fallback (never raises)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    number = float(value)
    if not math.isfinite(number):
        return default
    return int(number)


def _clean_tokens(tokens: Any) -> List[str]:
    """Coerce a token-list argument into a list of plain strings.

    ``None`` and non-iterables yield ``[]``; a bare string counts as a
    one-token list (documented convention); non-string items inside an
    iterable are dropped rather than stringified.
    """
    if tokens is None:
        return []
    if isinstance(tokens, str):
        return [tokens]
    if isinstance(tokens, bytes) or not isinstance(tokens, (list, tuple, set, frozenset)):
        return []
    return [item for item in tokens if isinstance(item, str)]


def ngrams(tokens: Any, n: int = 2) -> List[str]:
    """Join consecutive token runs into n-gram strings.

    Args:
        tokens: A token list (as produced by :func:`tokenize`). ``None``
            yields ``[]``; a bare string is treated as a single token.
        n: Run length (default 2 for bigrams). Values below 1, or larger
            than the token count, yield an empty list.

    Returns:
        N-grams as space-joined strings (``['new york', 'york city']`` for
        ``n=2``), in order. Never raises.

    Example:
        >>> ngrams(['alpha', 'beta', 'gamma'])
        ['alpha beta', 'beta gamma']
    """
    cleaned = _clean_tokens(tokens)
    size = _safe_int(n, 2)
    if size < 1 or size > len(cleaned):
        return []
    return [' '.join(cleaned[i:i + size]) for i in range(len(cleaned) - size + 1)]


def term_frequencies(tokens: Any) -> Dict[str, int]:
    """Count occurrences of every token.

    Args:
        tokens: A token list (``None`` / non-iterable yields an empty dict;
            non-string items are dropped).

    Returns:
        Mapping ``token -> count`` ordered by count descending, then
        alphabetically, so report rendering is deterministic.

    Example:
        >>> term_frequencies(['b', 'a', 'b'])
        {'b': 2, 'a': 1}
    """
    counter = Counter(_clean_tokens(tokens))
    ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return dict(ordered)


def tfidf(documents: Any) -> List[Dict[str, float]]:
    """Classic TF-IDF vectors for a batch of token documents.

    For each document the term frequency is ``count / len(doc)``; the
    document frequency ``df`` counts how many documents contain the term;
    the smoothed inverse document frequency is
    ``idf = log((N + 1) / (df + 1)) + 1`` (the ``+1`` smoothing keeps terms
    appearing in every document from collapsing to zero, the N+1 numerator
    avoids division by zero). Each document vector is then L2-normalised so
    dot products become cosine similarities directly.

    Args:
        documents: List (or tuple) of documents. Each document is a token
            list; a bare string is tokenised with :func:`tokenize` as a
            convenience. Anything else yields ``[]``.

    Returns:
        One ``{term: weight}`` dict per input document, in input order.
        Empty documents map to an empty vector. Never raises.

    Example:
        >>> vectors = tfidf([['osint', 'osint', 'recon'], ['recon', 'tools']])
        >>> round(vectors[0]['osint'], 4) == round(vectors[0]['recon'], 4)
        False
    """
    if documents is None or isinstance(documents, (str, bytes)):
        return []
    if not isinstance(documents, (list, tuple)):
        return []
    docs: List[List[str]] = []
    for document in documents:
        if isinstance(document, str):
            docs.append(tokenize(document))
        else:
            docs.append(_clean_tokens(document))
    total = len(docs)
    if total == 0:
        return []

    document_frequency: Counter = Counter()
    for document in docs:
        for term in set(document):
            document_frequency[term] += 1

    vectors: List[Dict[str, float]] = []
    for document in docs:
        if not document:
            vectors.append({})
            continue
        vector: Dict[str, float] = {}
        length = float(len(document))
        for term, count in Counter(document).items():
            tf_value = count / length
            idf_value = math.log((total + 1.0) / (document_frequency[term] + 1.0)) + 1.0
            vector[term] = tf_value * idf_value
        norm = math.sqrt(sum(weight * weight for weight in vector.values()))
        if norm > 0.0:
            vector = {term: weight / norm for term, weight in vector.items()}
        vectors.append(vector)
    return vectors


def extract_keywords(text: Any, top: int = 10, min_freq: int = 1) -> List[Dict[str, Any]]:
    """Mine the most frequent meaningful terms from one text.

    Tokens are lower-cased, stripped of stopwords (English + Chinese
    function words) and bare numbers, then ranked by frequency. The weight
    is each term's share of all meaningful tokens - a simple, explainable
    score that stays honest in a case note.

    Args:
        text: The text to mine (non-string input yields ``[]``).
        top: Maximum number of keywords returned (values below 0 mean 0).
        min_freq: Drop terms appearing fewer than this many times
            (values below 1 behave as 1).

    Returns:
        List of ``{'term', 'count', 'weight'}`` dicts sorted by count
        descending, ties broken alphabetically. Never raises.

    Example:
        >>> keywords = extract_keywords('recon recon tools recon data')
        >>> keywords[0]['term'], keywords[0]['count']
        ('recon', 3)
    """
    if not isinstance(text, str):
        return []
    tokens = tokenize(text, lowercase=True)
    meaningful = [token for token in tokens
                  if token not in _STOPWORDS and not token.isdigit()]
    if not meaningful:
        return []
    counts = Counter(meaningful)
    total = len(meaningful)
    minimum = _safe_int(min_freq, 1)
    if minimum < 1:
        minimum = 1
    limit = _safe_int(top, 10)
    if limit < 0:
        limit = 0
    items = [(term, count) for term, count in counts.items() if count >= minimum]
    items.sort(key=lambda item: (-item[1], item[0]))
    return [{'term': term, 'count': count, 'weight': round(count / total, 6)}
            for term, count in items[:limit]]


# ---------------------------------------------------------------------------
# Readability
# ---------------------------------------------------------------------------

def _is_cjk_char(char: str) -> bool:
    """True when a character is a Han ideograph or Japanese kana."""
    name = unicodedata.name(char, '')
    return bool(name) and (name.startswith('CJK')
                           or name.startswith('HIRAGANA')
                           or name.startswith('KATAKANA'))


def _count_syllables(word: str) -> int:
    """Approximate the syllable count of one lower-cased word.

    Vowel-group heuristic with a trailing-silent-``e`` adjustment and a
    small exception table for known failures; CJK characters count as one
    syllable each (each kana/ideograph is a beat). Tolerance is about
    +/- one syllable per word, which averages out over a sentence.
    """
    if not word:
        return 0
    if word in _SYLLABLE_EXCEPTIONS:
        return _SYLLABLE_EXCEPTIONS[word]
    cjk = sum(1 for char in word if _is_cjk_char(char))
    if cjk:
        return cjk
    groups = len(_VOWEL_GROUP_RE.findall(word))
    if word.endswith('e') and not word.endswith('le') and groups > 1:
        groups -= 1
    return max(1, groups)


def _split_sentences(text: str) -> List[str]:
    """Split text into non-empty sentence fragments (terminator runs split)."""
    parts = (part.strip() for part in _SENTENCE_RE.split(text))
    return [part for part in parts if part]


def _flesch_label(score: float) -> str:
    """Map a Flesch Reading Ease score onto its classic band label."""
    for floor, label in _FLESCH_BANDS:
        if score >= floor:
            return label
    return 'very difficult'  # pragma: no cover - below 0 is clamped by the 0.0 floor


def readability(text: Any) -> Dict[str, Any]:
    """Flesch Reading Ease and Flesch-Kincaid Grade of one text.

    Formulas (classic):

    * Reading Ease ``= 206.835 - 1.015 * words/sentence - 84.6 *
      syllables/word`` (higher = easier; 60-70 is plain English).
    * Kincaid Grade ``= 0.39 * words/sentence + 11.8 * syllables/word -
      15.59`` (approximate US school grade needed to comprehend it).

    Sentences split on ``.!?`` and newline runs; words are tokens that
    contain at least one letter; syllables use the documented vowel-group
    approximation with CJK characters counted as one beat each.

    Args:
        text: The text to score. Non-string or empty input yields the
            zeroed envelope with ``None`` scores rather than an exception.

    Returns:
        Dict with ``'flesch_reading_ease'``, ``'flesch_kincaid_grade'``,
        ``'flesch_label'`` (band label for the ease score), ``'sentences'``,
        ``'words'``, ``'syllables'``, ``'avg_words_per_sentence'`` and
        ``'avg_syllables_per_word'`` (the last two ``None`` when wordless).

    Example:
        >>> report = readability('The cat sat on the mat. The dog ran away.')
        >>> report['sentences'], report['words']
        (2, 10)
    """
    if not isinstance(text, str) or not text.strip():
        return dict(_EMPTY_READABILITY)
    sentences = _split_sentences(text)
    words = [token for token in _TOKEN_RE.findall(text)
             if any(char.isalpha() for char in token)]
    syllables = sum(_count_syllables(word.lower()) for word in words)
    if not sentences or not words:
        return dict(_EMPTY_READABILITY)

    words_per_sentence = len(words) / len(sentences)
    syllables_per_word = syllables / len(words)
    ease = 206.835 - 1.015 * words_per_sentence - 84.6 * syllables_per_word
    grade = 0.39 * words_per_sentence + 11.8 * syllables_per_word - 15.59
    return {
        'flesch_reading_ease': round(ease, 2),
        'flesch_kincaid_grade': round(grade, 2),
        'flesch_label': _flesch_label(ease),
        'sentences': len(sentences),
        'words': len(words),
        'syllables': syllables,
        'avg_words_per_sentence': round(words_per_sentence, 3),
        'avg_syllables_per_word': round(syllables_per_word, 3),
    }


# ---------------------------------------------------------------------------
# Script and language fingerprinting
# ---------------------------------------------------------------------------

def _script_of(char: str) -> Optional[str]:
    """Resolve one character to a tracked script name (None if untracked)."""
    name = unicodedata.name(char, '')
    if not name:
        return None
    for script, prefix in _SCRIPT_PREFIXES.items():
        if name.startswith(prefix):
            return script
    return None


def detect_language_script(text: Any) -> Dict[str, Any]:
    """Fingerprint the Unicode scripts and likely language of a text.

    Every character is classified through its :mod:`unicodedata` name into
    one of eleven tracked scripts (Latin, Cyrillic, Greek, Han, Hangul,
    Hiragana, Katakana, Arabic, Hebrew, Devanagari, Thai). On top of the
    script census a stopword-ratio language guess runs for eight languages
    (en/zh/ja/ko/de/fr/es/ru): space-delimited languages match whole
    tokens, zh matches stopword characters among Han characters and ja
    matches particles among kana/Han characters.

    Args:
        text: The text to fingerprint. Non-string or empty input yields
            ``'unknown'`` dominant script, zeroed counts and ``None``
            language guess.

    Returns:
        Dict with keys:

        * ``'dominant_script'`` - script with the most characters (ties
          resolve to the earlier script in the canonical order).
        * ``'script_counts'`` - characters per tracked script (all eleven
          keys always present).
        * ``'hint'`` - one-line human-readable summary for reports.
        * ``'language_guess'`` - ISO code of the best stopword ratio, or
          ``None`` when nothing matched.
        * ``'confidence'`` - the winning stopword ratio in ``[0, 1]``
          (0.0 when no guess). A guess is a hint, not identification.

    Example:
        >>> detect_language_script('Hello world this is English text')['dominant_script']
        'Latin'
        >>> detect_language_script('这是中文文本')['dominant_script']
        'Han'
    """
    counts: Dict[str, int] = dict.fromkeys(_SCRIPT_ORDER, 0)
    if isinstance(text, str):
        for char in text:
            script = _script_of(char)
            if script is not None:
                counts[script] += 1

    total_scripted = sum(counts.values())
    dominant = 'unknown'
    if total_scripted > 0:
        dominant = max(_SCRIPT_ORDER, key=lambda script: counts[script])
        share = counts[dominant] / total_scripted
        hint = f'{dominant} script dominates ({share:.0%} of script characters)'
    else:
        hint = 'no tracked script characters found'

    language, confidence = _language_guess(text if isinstance(text, str) else '')
    return {
        'dominant_script': dominant,
        'script_counts': dict(counts),
        'hint': hint,
        'language_guess': language,
        'confidence': round(confidence, 4),
    }


def _language_guess(text: str) -> Tuple[Optional[str], float]:
    """Best stopword-ratio language guess for one text (never raises).

    Returns the ISO code and ratio of the strongest language hint, or
    ``(None, 0.0)`` when no hint fires. Chinese and Japanese are matched
    character-wise because those scripts carry no spaces.
    """
    if not text.strip():
        return None, 0.0
    tokens = tokenize(text, lowercase=True)
    scores: Dict[str, float] = {}
    for language in ('en', 'de', 'fr', 'es', 'ru', 'ko'):
        hints = _LANGUAGE_HINTS[language]
        hits = sum(1 for token in tokens if token in hints)
        scores[language] = hits / len(tokens) if tokens else 0.0

    han_chars = [char for char in text if _script_of(char) == 'Han']
    if han_chars:
        zh_hints = _LANGUAGE_HINTS['zh']
        hits = sum(1 for char in han_chars if char in zh_hints)
        scores['zh'] = hits / len(han_chars)

    kana_han = [char for char in text
                if _script_of(char) in ('Han', 'Hiragana', 'Katakana')]
    if kana_han:
        ja_hints = _LANGUAGE_HINTS['ja']
        hits = sum(text.count(particle) for particle in ja_hints)
        scores['ja'] = min(1.0, hits / len(kana_han))

    if not scores:
        return None, 0.0
    best_language = max(sorted(scores), key=lambda language: scores[language])
    best_score = scores[best_language]
    if best_score <= 0.0:
        return None, 0.0
    return best_language, min(1.0, best_score)


# ---------------------------------------------------------------------------
# Character profile
# ---------------------------------------------------------------------------

def char_profile(text: Any) -> Dict[str, Any]:
    """Count what a text is made of, character by character.

    The profile answers "what am I looking at" before any deeper analysis:
    a hash dump is digits and hex-leaning, a ransom note is punctuation and
    uppercase, a paste-dump ID column is digits with high entropy.

    Args:
        text: The text to profile. Non-string input yields the zeroed
            envelope (``'length': 0``, ``None`` ratios and entropy).

    Returns:
        Dict with keys:

        * ``'length'`` - total characters.
        * ``'letters'`` / ``'digits'`` / ``'punctuation'`` / ``'symbols'``
          / ``'whitespace'`` / ``'other'`` - per-category counts
          (Unicode general categories L / N / P / S / whitespace / rest).
        * ``'uppercase'`` / ``'lowercase'`` - cased-letter counts.
        * ``'unique_chars'`` - distinct characters.
        * ``'hex_ratio'`` - hex characters among alphanumeric characters
          (``None`` when there are none); values above ~0.9 with many
          digits suggest hashes or hex-encoded payloads.
        * ``'entropy'`` - Shannon entropy over the character distribution
          in bits per character (``None`` for empty text).

    Example:
        >>> profile = char_profile('deadbeef 1234')
        >>> profile['length'], profile['hex_ratio']
        (13, 1.0)
    """
    if not isinstance(text, str) or not text:
        return {
            'length': 0, 'letters': 0, 'digits': 0, 'punctuation': 0,
            'symbols': 0, 'whitespace': 0, 'other': 0, 'uppercase': 0,
            'lowercase': 0, 'unique_chars': 0, 'hex_ratio': None,
            'entropy': None,
        }

    letters = digits = punctuation = symbols = whitespace = other = 0
    uppercase = lowercase = alnum = hexish = 0
    for char in text:
        category = unicodedata.category(char)
        if category.startswith('L'):
            letters += 1
            alnum += 1
            if char.isupper():
                uppercase += 1
            elif char.islower():
                lowercase += 1
        elif category.startswith('N'):
            digits += 1
            alnum += 1
        elif category.startswith('P'):
            punctuation += 1
        elif category.startswith('S'):
            symbols += 1
        elif char.isspace():
            whitespace += 1
        else:
            other += 1
        if char in _HEX_CHARS:
            hexish += 1

    hex_ratio = (hexish / alnum) if alnum > 0 else None
    return {
        'length': len(text),
        'letters': letters,
        'digits': digits,
        'punctuation': punctuation,
        'symbols': symbols,
        'whitespace': whitespace,
        'other': other,
        'uppercase': uppercase,
        'lowercase': lowercase,
        'unique_chars': len(set(text)),
        'hex_ratio': hex_ratio,
        'entropy': _char_entropy(text),
    }


def _char_entropy(text: str) -> Optional[float]:
    """Shannon entropy of the character distribution, bits per character."""
    if not text:
        return None
    total = len(text)
    entropy = 0.0
    for count in Counter(text).values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# Extractive summarisation and redaction
# ---------------------------------------------------------------------------

def summarize_text(text: Any, max_sentences: int = 3) -> str:
    """Extractive summary: the highest-scoring sentences, original order.

    Sentences are split on terminator runs, every non-stopword token is
    weighted by its frequency across the whole text, each sentence scores
    the sum of its tokens' frequencies, and the top ``max_sentences``
    winners are re-joined in their original order. Classic frequency-based
    extraction: cheap, explainable, no model required.

    Args:
        text: The text to summarise. Non-string or empty input yields ''.
        max_sentences: How many sentences to keep (values below 1 yield '';
            non-numeric values fall back to 3).

    Returns:
        The summary string. Never raises.

    Example:
        >>> text = ('Recon tools matter. Recon tools gather data. '
        ...         'Weather is nice today. Data drives decisions.')
        >>> 'Recon tools gather data' in summarize_text(text, max_sentences=2)
        True
    """
    if not isinstance(text, str) or not text.strip():
        return ''
    limit = _safe_int(max_sentences, 3)
    if limit < 1:
        return ''
    sentences = _split_sentences(text)
    if not sentences:
        return ''

    tokens = tokenize(' '.join(sentences), lowercase=True)
    frequencies = Counter(token for token in tokens if token not in _STOPWORDS)
    scored: List[Tuple[int, str, int]] = []
    for index, sentence in enumerate(sentences):
        words = tokenize(sentence, lowercase=True)
        score = sum(frequencies[word] for word in words
                    if word not in _STOPWORDS)
        scored.append((index, sentence, score))

    winners = sorted(scored, key=lambda item: (-item[2], item[0]))[:limit]
    winners.sort(key=lambda item: item[0])
    return ' '.join(sentence for _index, sentence, _score in winners)


def redaction_sweep(text: Any) -> Dict[str, Any]:
    """Count pivot-target entities and produce a redacted preview.

    Delegates to the validator-driven
    :func:`obscuralens.experimental.entity_extract.extract_entities`
    pipeline (emails, URLs, IPs, crypto addresses, CVEs, coordinates and
    friends) - this module never re-implements those regexes - then counts
    hits per kind and runs :func:`redact_entities` for a placeholder-masked
    preview that is safe to paste into a shared report.

    Args:
        text: The text to sweep. Non-string input yields zeroed counts and
            an empty preview.

    Returns:
        Dict with keys:

        * ``'counts'`` - ``{kind: count}`` for every kind that hit.
        * ``'total'`` - total entities found.
        * ``'preview'`` - the redacted text (entities replaced by
          ``[EMAIL #1]``-style placeholders).
        * ``'original_length'`` / ``'preview_length'`` - character counts
          before and after redaction.

    Example:
        >>> sweep = redaction_sweep('contact admin@evil-corp.com now')
        >>> sweep['total'] >= 1 and '[EMAIL #1]' in sweep['preview']
        True
    """
    if not isinstance(text, str):
        return {'counts': {}, 'total': 0, 'preview': '',
                'original_length': 0, 'preview_length': 0}
    found = extract_entities(text)
    counts: Dict[str, int] = {}
    total = 0
    if isinstance(found, dict):
        for kind, values in found.items():
            if isinstance(values, (list, tuple)) and values:
                counts[str(kind)] = len(values)
                total += len(values)
    preview = redact_entities(text)
    return {
        'counts': counts,
        'total': total,
        'preview': preview,
        'original_length': len(text),
        'preview_length': len(preview),
    }


# ---------------------------------------------------------------------------
# Multi-metric similarity report
# ---------------------------------------------------------------------------

def text_similarity_report(a: Any, b: Any) -> Dict[str, Any]:
    """Compare two texts across four independent similarity metrics.

    Character-level agreement (Jaro-Winkler, Levenshtein ratio), n-gram
    overlap (Sørensen-Dice over bigrams) and semantic bag-of-words
    agreement (cosine over TF-IDF vectors) each catch different fraud
    patterns - typosquatting fools characters, plagiarism rewords bags -
    so the report carries all four plus their mean.

    Args:
        a, b: The texts to compare (``None`` becomes ``''``; non-strings
            are stringified, matching the similarity module's convention).

    Returns:
        Dict with ``'jaro_winkler'``, ``'levenshtein_ratio'``, ``'ngram'``,
        ``'cosine'`` (all in ``[0, 1]``), ``'mean'`` (average of the four)
        and ``'length_a'`` / ``'length_b'`` character counts. Never raises.

    Example:
        >>> report = text_similarity_report('paypal.com', 'paypa1.com')
        >>> report['jaro_winkler'] > 0.85
        True
    """
    text_a = '' if a is None else (a if isinstance(a, str) else str(a))
    text_b = '' if b is None else (b if isinstance(b, str) else str(b))

    vectors = tfidf([tokenize(text_a), tokenize(text_b)])
    cosine = (cosine_similarity(vectors[0], vectors[1])
              if len(vectors) == 2 else 0.0)

    jaro_winkler_score = jaro_winkler(text_a, text_b)
    levenshtein_score = levenshtein_ratio(text_a, text_b)
    ngram_score = ngram_similarity(text_a, text_b, 2)
    mean_score = (jaro_winkler_score + levenshtein_score + ngram_score
                  + cosine) / 4.0
    return {
        'jaro_winkler': jaro_winkler_score,
        'levenshtein_ratio': levenshtein_score,
        'ngram': ngram_score,
        'cosine': cosine,
        'mean': mean_score,
        'length_a': len(text_a),
        'length_b': len(text_b),
    }
