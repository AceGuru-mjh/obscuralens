"""
Polyglot encoder/decoder workbench (EXPERIMENTAL).

A Swiss-army module for OSINT triage of mysterious strings. Point it at a blob
lifted from a phishing URL parameter, a suspicious webhook payload, a CTF
flag fragment or a token pasted into a chat, and it will:

* encode one input through *every* known scheme at once (:func:`encode_all`)
  - handy for building detection rules that catch the same secret however it
  is smuggled;
* try every scheme in reverse and rank the candidates that decode to
  human-readable text (:func:`decode_auto`) - the "magic decoder" an analyst
  fires at an opaque blob before spending manual effort on it;
* compute every standard checksum/digest of a value (:func:`hash_all`) so the
  result can be pasted straight into hash-lookup services.

Supported schemes (``SCHEMES``, an insertion-ordered mapping): hex, base32
(RFC 4648), base64 (standard + URL-safe fallback on decode), base85 (b85 /
git-style for encode, b85-then-ascii85 on decode), URL percent-encoding,
HTML entities, ROT13, Caesar shift (parameterised via
:func:`caesar_encode`), space-separated binary and decimal codepoints, plain
reversal, ITU Morse code, and zlib-compressed data armored in base64.
Two parameterised helpers live outside ``SCHEMES`` because they need a key:
:func:`xor_key_encode` / :func:`xor_key_decode`.

XOR is *encoding obfuscation*, not encryption - it is included for CTF
triage and for spotting trivially-obfuscated exfiltration, and is documented
as such everywhere it surfaces.

Everything is pure stdlib and entirely offline. Decode functions raise
``ValueError`` with a clear message on malformed input; the aggregate
entry points (:func:`encode_all`, :func:`decode_auto`) swallow those errors
and simply skip the failing scheme, so an analyst never sees a crash -
only a shorter result list. Byte-to-text decoding always uses
``errors='replace'`` so undecodable garbage degrades to U+FFFD replacement
characters (which :func:`_printable_ratio` deliberately counts as
non-printable evidence) instead of raising.
"""

import base64
import binascii
import hashlib
import html
import re
import zlib
from typing import Any, Callable, Dict, List, Tuple
from urllib.parse import quote, unquote

__all__ = [
    'SCHEMES',
    'MORSE_TABLE',
    'encode_all',
    'decode_auto',
    'hash_all',
    'caesar_encode',
    'caesar_decode',
    'xor_key_encode',
    'xor_key_decode',
]

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

#: Minimum fraction of printable characters for a decode candidate to count
#: as "readable text" in :func:`decode_auto`. U+FFFD replacement characters
#: count as NON-printable here - they are evidence of a failed decode.
_MIN_PRINTABLE = 0.90

#: Maximum decode candidates returned by :func:`decode_auto`.
_MAX_DECODE_CANDIDATES = 24

#: Embedded mini-dictionary for the "does this look like English?" heuristic
#: (the ~60 most frequent English words). Purely local, no corpus file.
_COMMON_WORDS = frozenset((
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'it',
    'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this',
    'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or',
    'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
    'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me',
    'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
    'take', 'people', 'into', 'year', 'your', 'good', 'some', 'them',
))

_WORD_RE = re.compile(r'[a-z]+')

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _printable_ratio(text: str) -> float:
    """
    Fraction of characters that are printable, counting U+FFFD as bad.

    ``str.isprintable`` alone classifies the Unicode replacement character
    (U+FFFD) as printable, which would let ``errors='replace'`` decode
    garbage masquerade as readable text. This helper deliberately counts
    every replacement character as non-printable so failed decodes score
    low in :func:`decode_auto`. Empty strings score 0.0.
    """
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() and ch != '\ufffd')
    return printable / len(text)


def _require_text(value: Any, label: str) -> str:
    """Return ``value`` unchanged when it is a str, else raise ValueError."""
    if not isinstance(value, str):
        raise ValueError(f'{label} must be a string, got {type(value).__name__}')
    return value


def _squash(value: str) -> str:
    """Strip all whitespace from a payload (decoders tolerate wrapped input)."""
    return re.sub(r'\s+', '', value)


# ---------------------------------------------------------------------------
# Caesar / ROT13
# ---------------------------------------------------------------------------


def _caesar_shift(text: str, shift: int) -> str:
    """Shift ASCII letters by ``shift`` positions (wraps, preserves case)."""
    shift %= 26
    lower = 'abcdefghijklmnopqrstuvwxyz'
    upper = lower.upper()
    table = str.maketrans(
        lower + upper,
        lower[shift:] + lower[:shift] + upper[shift:] + upper[:shift],
    )
    return text.translate(table)


def caesar_encode(text: str, shift: int = 3) -> str:
    """
    EXPERIMENTAL: Caesar-shift ASCII letters of ``text`` forward by ``shift``.

    The classic 3-position Caesar cipher used by the ``caesar`` entry in
    ``SCHEMES``; pass any shift for ROT-N. Non-letters pass through
    untouched. Useful for spotting shifted indicators in CTF material or
    lightly obfuscated malware strings.
    """
    return _caesar_shift(_require_text(text, 'text'), shift)


def caesar_decode(text: str, shift: int = 3) -> str:
    """Reverse :func:`caesar_encode` (same shift, opposite direction)."""
    return _caesar_shift(_require_text(text, 'text'), -shift)


# ---------------------------------------------------------------------------
# Hex / base32 / base64 / base85 / zlib-armor
# ---------------------------------------------------------------------------


def hex_encode(text: str) -> str:
    """Encode text as lowercase hexadecimal (UTF-8 bytes, no separators)."""
    return _require_text(text, 'text').encode('utf-8').hex()


def hex_decode(value: str) -> str:
    """
    Decode hexadecimal to text.

    Tolerant of whitespace and an optional ``0x``/``0X`` prefix; raises
    ``ValueError`` for non-hex characters or an odd digit count. Output is
    decoded as UTF-8 with ``errors='replace'`` so odd byte sequences
    degrade instead of crashing.
    """
    candidate = _squash(_require_text(value, 'value'))
    if candidate[:2].lower() == '0x':
        candidate = candidate[2:]
    if not candidate:
        raise ValueError('empty hex payload')
    if not re.fullmatch(r'[0-9a-fA-F]+', candidate):
        raise ValueError('value contains non-hexadecimal characters')
    if len(candidate) % 2:
        raise ValueError(f'odd hex length ({len(candidate)} digits)')
    return bytes.fromhex(candidate).decode('utf-8', errors='replace')


def base32_encode(text: str) -> str:
    """Encode text as RFC 4648 base32 (A-Z, 2-7, padded)."""
    return base64.b32encode(_require_text(text, 'text').encode('utf-8')).decode('ascii')


def base32_decode(value: str) -> str:
    """
    Decode base32 to text, padding loosely.

    Case-insensitive input and missing ``=`` padding are tolerated (the
    payload is re-padded to a multiple of 8 before decoding). Raises
    ``ValueError`` for characters outside the base32 alphabet or impossible
    padding layouts.
    """
    candidate = _squash(_require_text(value, 'value')).upper()
    if not candidate:
        raise ValueError('empty base32 payload')
    if not re.fullmatch(r'[A-Z2-7]*={0,6}', candidate):
        raise ValueError('value contains characters outside the base32 alphabet')
    candidate += '=' * ((-len(candidate)) % 8)
    try:
        data = base64.b32decode(candidate)
    except (binascii.Error, ValueError) as err:
        raise ValueError(f'invalid base32 payload: {err}') from None
    return data.decode('utf-8', errors='replace')


def base64_encode(text: str) -> str:
    """Encode text as standard (RFC 3548) base64."""
    return base64.b64encode(_require_text(text, 'text').encode('utf-8')).decode('ascii')


def base64_decode(value: str) -> str:
    """
    Decode base64 to text, with a URL-safe fallback.

    Whitespace is stripped and padding is added before a strict standard
    decode; if that fails the URL-safe alphabet (``-``/``_``) is remapped
    onto ``+``/``/`` and retried. Raises ``ValueError`` only when both
    alphabets fail, so analysts can paste either flavor of token.
    """
    candidate = _squash(_require_text(value, 'value'))
    if not candidate:
        raise ValueError('empty base64 payload')
    candidate += '=' * ((-len(candidate)) % 4)
    try:
        data = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        translated = candidate.translate(str.maketrans('-_', '+/'))
        try:
            data = base64.b64decode(translated, validate=True)
        except (binascii.Error, ValueError) as err:
            raise ValueError(f'invalid base64 payload: {err}') from None
    return data.decode('utf-8', errors='replace')


def base85_encode(text: str) -> str:
    """Encode text as base85 using the git-style ``b85`` alphabet."""
    return base64.b85encode(_require_text(text, 'text').encode('utf-8')).decode('ascii')


def base85_decode(value: str) -> str:
    """
    Decode base85 to text, trying ``b85`` first then ascii85.

    The encoder emits the git-style ``b85`` alphabet; the decoder also
    accepts classic ascii85 after stripping optional Adobe ``<~``/``~>``
    framing, because both flavors show up in PDFs and patches during
    malware triage.
    """
    candidate = _squash(_require_text(value, 'value'))
    if not candidate:
        raise ValueError('empty base85 payload')
    try:
        data = base64.b85decode(candidate)
    except (binascii.Error, ValueError):
        stripped = candidate
        if stripped.startswith('<~'):
            stripped = stripped[2:]
        if stripped.endswith('~>'):
            stripped = stripped[:-2]
        try:
            data = base64.a85decode(stripped, adobe=False)
        except (binascii.Error, ValueError) as err:
            raise ValueError(f'invalid base85 payload: {err}') from None
    return data.decode('utf-8', errors='replace')


def gzip_encode(text: str) -> str:
    """
    Compress text with zlib and armor it in base64 for text safety.

    The wire format is ``base64(zlib(utf-8 text))`` - safe to paste into
    JSON, chat messages or logs without binary corruption. Binary gzip
    blobs that were *not* base64-armored will not decode here (and are
    usually not valid UTF-8 text anyway).
    """
    compressed = zlib.compress(_require_text(text, 'text').encode('utf-8'), 9)
    return base64.b64encode(compressed).decode('ascii')


def gzip_decode(value: str) -> str:
    """
    Reverse :func:`gzip_encode`: base64-dearmor, then zlib-decompress.

    Raises ``ValueError`` when the payload is not base64 or not a zlib
    stream; decompressed bytes are decoded as UTF-8 with
    ``errors='replace'``.
    """
    candidate = _squash(_require_text(value, 'value'))
    if not candidate:
        raise ValueError('empty gzip payload')
    candidate += '=' * ((-len(candidate)) % 4)
    try:
        compressed = base64.b64decode(candidate, validate=True)
        data = zlib.decompress(compressed)
    except (binascii.Error, ValueError, zlib.error) as err:
        raise ValueError(f'value is not base64-armored zlib data: {err}') from None
    return data.decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
# URL percent / HTML entities
# ---------------------------------------------------------------------------


def url_percent_encode(text: str) -> str:
    """
    Percent-encode text for use inside a URL.

    Everything outside the always-safe set (letters, digits, ``_.-~``) is
    escaped - the behavior of ``urllib.parse.quote(text, safe='')``.
    """
    return quote(_require_text(text, 'text'), safe='')


def url_percent_decode(value: str) -> str:
    """Decode percent escapes (``%41%42`` style), tolerating stray bytes."""
    return unquote(_require_text(value, 'value'), errors='replace')


def html_entity_encode(text: str) -> str:
    """Escape text to HTML entities (``&``, ``<``, ``>``, quotes)."""
    return html.escape(_require_text(text, 'text'), quote=True)


def html_entity_decode(value: str) -> str:
    """Decode HTML entities (named, decimal and hexadecimal)."""
    return html.unescape(_require_text(value, 'value'))


# ---------------------------------------------------------------------------
# ROT13, reversal
# ---------------------------------------------------------------------------


def rot13_encode(text: str) -> str:
    """Apply ROT13 to ASCII letters (its own inverse; classic CTF obfuscation)."""
    return _caesar_shift(_require_text(text, 'text'), 13)


def reversed_encode(text: str) -> str:
    """Reverse the string (cheapest possible obfuscation; self-inverse)."""
    return _require_text(text, 'text')[::-1]


def reversed_decode(value: str) -> str:
    """Reverse the string again (reversal is its own inverse)."""
    return _require_text(value, 'value')[::-1]


# ---------------------------------------------------------------------------
# Binary / decimal codepoints
# ---------------------------------------------------------------------------


def binary_encode(text: str) -> str:
    """Encode text as space-separated 8-bit groups (``01000001 01100010``)."""
    data = _require_text(text, 'text').encode('utf-8')
    return ' '.join(format(byte, '08b') for byte in data)


def binary_decode(value: str) -> str:
    """
    Decode binary groups to text, tolerant of spaces or no separators.

    Whitespace is stripped entirely, so ``0100000101100010`` (no spaces)
    and ``01000001 01100010`` (spaced) both decode. Raises ``ValueError``
    for characters other than 0/1 or a bit count that is not a multiple
    of 8.
    """
    candidate = _squash(_require_text(value, 'value'))
    if not candidate:
        raise ValueError('empty binary payload')
    if not re.fullmatch(r'[01]+', candidate):
        raise ValueError('value contains characters other than 0 and 1')
    if len(candidate) % 8:
        raise ValueError(f'binary length {len(candidate)} is not a multiple of 8')
    data = bytes(int(candidate[i:i + 8], 2) for i in range(0, len(candidate), 8))
    return data.decode('utf-8', errors='replace')


def decimal_encode(text: str) -> str:
    """Encode text as space-separated decimal codepoints (``79 98 115``)."""
    return ' '.join(str(ord(ch)) for ch in _require_text(text, 'text'))


def decimal_decode(value: str) -> str:
    """
    Decode decimal codepoints to text.

    Accepts space, comma or semicolon separators. Raises ``ValueError``
    for non-numeric tokens, out-of-range codepoints or lone surrogates.
    """
    tokens = [token for token in re.split(r'[\s,;]+', _require_text(value, 'value').strip()) if token]
    if not tokens:
        raise ValueError('empty decimal payload')
    chars: List[str] = []
    for token in tokens:
        if not re.fullmatch(r'[0-9]+', token):
            raise ValueError(f'non-numeric codepoint token: {token!r}')
        code = int(token)
        if not 0 <= code <= 0x10FFFF:
            raise ValueError(f'codepoint out of Unicode range: {code}')
        if 0xD800 <= code <= 0xDFFF:
            raise ValueError(f'lone surrogate codepoint: {code}')
        chars.append(chr(code))
    return ''.join(chars)


# ---------------------------------------------------------------------------
# Morse
# ---------------------------------------------------------------------------

#: ITU Morse alphabet: letters, digits and the most common punctuation.
MORSE_TABLE: Dict[str, str] = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '/': '-..-.', '=': '-...-',
    '+': '.-.-.', '-': '-....-', '_': '..--.-', '(': '-.--.', ')': '-.--.-',
    "'": '.----.', '!': '-.-.--', '&': '.-...', ':': '---...', ';': '-.-.-.',
    '"': '.-..-.', '@': '.--.-.',
}

_REVERSE_MORSE: Dict[str, str] = {code: char for char, code in MORSE_TABLE.items()}


def morse_encode(text: str) -> str:
    """
    Encode text to ITU Morse code.

    Letters within a word are separated by a single space, words by
    ``' / '``. Characters outside the table are skipped (documented
    limitation); lower- and uppercase both work.
    """
    payload = _require_text(text, 'text').upper()
    words: List[str] = []
    for word in payload.split():
        letters = [MORSE_TABLE[ch] for ch in word if ch in MORSE_TABLE]
        if letters:
            words.append(' '.join(letters))
    if not words:
        raise ValueError('text contains no Morse-encodable characters')
    return ' / '.join(words)


def morse_decode(value: str) -> str:
    """
    Decode Morse code to text, tolerant of spacing and separators.

    ``/`` (with or without surrounding spaces) separates words; runs of
    dots/dashes separated by anything else are letters. Unknown sequences
    decode to ``?``. Raises ``ValueError`` when no Morse symbols at all
    are present (so :func:`decode_auto` skips plain text).
    """
    payload = _require_text(value, 'value').strip()
    if not re.search(r'[.\-]', payload):
        raise ValueError('value contains no Morse symbols (dots/dashes)')
    words: List[str] = []
    for chunk in re.split(r'\s*/\s*', payload):
        letters: List[str] = []
        for token in re.split(r'\s+', chunk):
            token = token.strip()
            if not token:
                continue
            letters.append(_REVERSE_MORSE.get(token, '?'))
        if letters:
            words.append(''.join(letters))
    if not words:
        raise ValueError('no decodable Morse letters found')
    return ' '.join(words)


# ---------------------------------------------------------------------------
# XOR (obfuscation, NOT encryption)
# ---------------------------------------------------------------------------


def xor_key_encode(text: str, key: str) -> str:
    """
    EXPERIMENTAL: XOR text with a repeating key, returning hex.

    This is **encoding obfuscation, not encryption** - there is no key
    stretching, no nonce and no authentication. It exists because
    single-byte and repeating-key XOR show up constantly in CTF
    challenges, malware config blobs and trivially-obfuscated exfiltration
    channels, and an analyst needs to round-trip them locally.
    """
    data = _require_text(text, 'text').encode('utf-8')
    key_bytes = _require_text(key, 'key').encode('utf-8')
    if not key_bytes:
        raise ValueError('key must not be empty')
    masked = bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(data))
    return masked.hex()


def xor_key_decode(value: str, key: str) -> str:
    """
    Reverse :func:`xor_key_encode`: hex -> bytes -> XOR with the key.

    Tolerates whitespace and an ``0x`` prefix on the hex payload. Output
    is decoded as UTF-8 with ``errors='replace'`` - a wrong key yields
    replacement characters rather than an exception, which is itself a
    useful signal that the key guess was wrong.
    """
    candidate = _squash(_require_text(value, 'value'))
    if candidate[:2].lower() == '0x':
        candidate = candidate[2:]
    if not candidate:
        raise ValueError('empty XOR payload')
    if not re.fullmatch(r'[0-9a-fA-F]+', candidate):
        raise ValueError('XOR payload must be a hexadecimal string')
    if len(candidate) % 2:
        raise ValueError(f'odd hex length ({len(candidate)} digits)')
    key_bytes = _require_text(key, 'key').encode('utf-8')
    if not key_bytes:
        raise ValueError('key must not be empty')
    data = bytes.fromhex(candidate)
    plain = bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(data))
    return plain.decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
# The scheme registry
# ---------------------------------------------------------------------------

#: Ordered registry of every fixed-key scheme. Each entry is a dict with
#: ``label`` (short human name), ``description`` (one-line OSINT framing),
#: ``encode`` (str -> str) and ``decode`` (str -> str or ValueError).
#: Parameterised transforms (Caesar shift, XOR key) live outside this
#: registry because they need extra arguments.
SCHEMES: Dict[str, Dict[str, Any]] = {
    'hex': {
        'label': 'Hexadecimal',
        'description': 'UTF-8 bytes as hex digits - very common in malware configs.',
        'encode': hex_encode,
        'decode': hex_decode,
    },
    'base32': {
        'label': 'Base32 (RFC 4648)',
        'description': 'A-Z/2-7 alphabet, popular in DNS exfiltration and TOTP secrets.',
        'encode': base32_encode,
        'decode': base32_decode,
    },
    'base64': {
        'label': 'Base64 (standard)',
        'description': 'The workhorse of JWTs, webhooks and stolen-credential blobs.',
        'encode': base64_encode,
        'decode': base64_decode,
    },
    'base85': {
        'label': 'Base85 (b85 / ascii85)',
        'description': 'Dense binary armor seen in patches, PDFs and git binary deltas.',
        'encode': base85_encode,
        'decode': base85_decode,
    },
    'url_percent': {
        'label': 'URL percent-encoding',
        'description': '%XX escapes used to smuggle payloads through URL parameters.',
        'encode': url_percent_encode,
        'decode': url_percent_decode,
    },
    'html_entity': {
        'label': 'HTML entities',
        'description': '&amp;-style escapes used to hide strings from naive filters.',
        'encode': html_entity_encode,
        'decode': html_entity_decode,
    },
    'rot13': {
        'label': 'ROT13',
        'description': 'Self-inverse letter shift - the classic spoiler/CTF obfuscation.',
        'encode': rot13_encode,
        'decode': rot13_encode,
    },
    'caesar': {
        'label': 'Caesar (shift 3)',
        'description': 'Classic Caesar; use caesar_encode(text, shift) for other shifts.',
        'encode': lambda text: caesar_encode(text, 3),
        'decode': lambda text: caesar_decode(text, 3),
    },
    'binary': {
        'label': 'Binary (8-bit groups)',
        'description': 'Space-separated bits; common in puzzle/CTF material.',
        'encode': binary_encode,
        'decode': binary_decode,
    },
    'decimal': {
        'label': 'Decimal codepoints',
        'description': 'Space-separated Unicode codepoints, e.g. "79 98 115".',
        'encode': decimal_encode,
        'decode': decimal_decode,
    },
    'reversed': {
        'label': 'Reversed text',
        'description': 'String reversal - the cheapest obfuscation there is.',
        'encode': reversed_encode,
        'decode': reversed_decode,
    },
    'morse': {
        'label': 'Morse code (ITU)',
        'description': 'Dots and dashes; letters spaced, words separated by "/".',
        'encode': morse_encode,
        'decode': morse_decode,
    },
    'gzip': {
        'label': 'zlib + base64 armor',
        'description': 'base64(zlib(text)) - text-safe compressed payloads.',
        'encode': gzip_encode,
        'decode': gzip_decode,
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encode_all(text: str) -> Dict[str, str]:
    """
    EXPERIMENTAL: encode ``text`` through every scheme at once.

    One input in, one labeled result per scheme out - the reverse view an
    analyst wants when writing detection rules: catch the secret whether
    the actor hexed it, based it, armored it or morse'd it.

    Args:
        text: the plaintext to encode (any str; non-str raises ValueError).

    Returns:
        ``{scheme_name: encoded_value}`` in ``SCHEMES`` order. Schemes
        that raise on this input (e.g. Morse for symbol-only text) are
        silently skipped, so the dict may be partial - never a crash.
    """
    payload = _require_text(text, 'text')
    results: Dict[str, str] = {}
    for name, scheme in SCHEMES.items():
        try:
            results[name] = scheme['encode'](payload)
        except (ValueError, UnicodeError):
            continue
    return results


def _score_result(text: str) -> float:
    """
    Heuristic readability score, 0-100, for a decoded candidate.

    Rubric: 40% printable ratio (U+FFFD counts as non-printable), 30%
    letter ratio, 30% dictionary-ish credit - up to full credit when three
    or more embedded common English words appear. Tuned so that a clean
    English decode beats "decode returned the input unchanged" results.
    """
    printable = _printable_ratio(text)
    letter_ratio = sum(1 for ch in text if ch.isalpha()) / max(1, len(text))
    hits = sum(1 for word in _WORD_RE.findall(text.lower()) if word in _COMMON_WORDS)
    dictionary_ratio = min(1.0, hits / 3.0)
    score = 100.0 * (0.40 * printable + 0.30 * letter_ratio + 0.30 * dictionary_ratio)
    return round(score, 1)


def decode_auto(value: str) -> List[Dict[str, Any]]:
    """
    EXPERIMENTAL: the "magic decoder" - try every scheme and rank results.

    Point this at a mysterious blob before spending manual effort: every
    scheme in ``SCHEMES`` gets a chance to decode it, candidates whose
    output is at least 90% printable survive, and each survivor is scored
    on printability, letter ratio and an embedded common-English-words
    heuristic. The list is sorted by score (descending), ties broken by
    scheme order.

    Args:
        value: the suspicious string (non-string / blank input yields ``[]``).

    Returns:
        ``[{'scheme': name, 'result': decoded_text, 'score': 0-100,
        'note': analyst_hint}]`` best-first. A note is always present; it
        flags "output identical to input" (weak evidence) cases and other
        scheme-specific caveats. Schemes that raise are simply absent.
    """
    payload = value if isinstance(value, str) else ''
    if not payload.strip():
        return []
    scored: List[Tuple[float, int, Dict[str, Any]]] = []
    for order, (name, scheme) in enumerate(SCHEMES.items()):
        try:
            result = scheme['decode'](payload)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(result, str) or not result:
            continue
        if _printable_ratio(result) < _MIN_PRINTABLE:
            continue
        note = f"decoded via the {scheme['label']} scheme"
        if result == payload:
            note = 'output identical to input (weak evidence - scheme was a no-op)'
        entry = {'scheme': name, 'result': result, 'score': _score_result(result), 'note': note}
        scored.append((entry['score'], order, entry))
        if len(scored) >= _MAX_DECODE_CANDIDATES:
            break
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in scored]


def hash_all(text: str) -> Dict[str, str]:
    """
    EXPERIMENTAL: compute every standard digest of ``text`` at once.

    Emits md5, sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_512,
    blake2s, blake2b (lowercase hex) plus the zlib CRC32 checksum
    (8 hex digits) - a labeled dict ready to paste into hash-lookup
    services or paste into a report as "known digests of this string".

    Args:
        text: the value to digest; hashed as UTF-8 bytes (non-str raises
            ValueError; the empty string is allowed and meaningful).

    Returns:
        ``{'md5': '...', ..., 'crc32': '........'}`` in a stable order.
    """
    payload = _require_text(text, 'text').encode('utf-8')
    builders: Tuple[Tuple[str, Callable[[bytes], Any]], ...] = (
        ('md5', hashlib.md5), ('sha1', hashlib.sha1), ('sha224', hashlib.sha224),
        ('sha256', hashlib.sha256), ('sha384', hashlib.sha384),
        ('sha512', hashlib.sha512), ('sha3_256', hashlib.sha3_256),
        ('sha3_512', hashlib.sha3_512), ('blake2s', hashlib.blake2s),
        ('blake2b', hashlib.blake2b),
    )
    digests: Dict[str, str] = {}
    for name, builder in builders:
        digests[name] = builder(payload).hexdigest()
    digests['crc32'] = format(zlib.crc32(payload) & 0xFFFFFFFF, '08x')
    return digests
