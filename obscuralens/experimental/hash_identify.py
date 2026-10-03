"""
Hash format identification (EXPERIMENTAL).

Paste an opaque digest from a breach dump, a malware config, a database
row or a forensic artifact and get the candidate algorithms it could be,
ranked by confidence, with the raw digest size and charset profile
attached - the triage step before choosing a cracking mode or a lookup
service.

Detection is purely structural (length + charset + prefix markers): it
cannot distinguish two algorithms that share a digest length (SHA-256 vs
Keccak-256 vs BLAKE2s all emit 64 hex characters), so same-length
alternatives are listed with medium confidence and contextual notes -
most importantly the EVM/Ethereum Keccak-256 trap, which has burned many
an analyst who assumed "64 hex = SHA-256".

Also ships :func:`checksum_matches`, a tiny offline wordlist matcher for
password-hash triage (is this md5/sha1/sha256 of any of these candidate
plaintexts?), and the ``HASH_FAMILIES`` reference table for docs and UI
rendering.
"""

import hashlib
import re
from typing import Any, Dict, Iterable, List, Union

__all__ = ['identify_hash', 'checksum_matches', 'HASH_FAMILIES']

# ---------------------------------------------------------------------------
# Reference table (docs / UI rendering)
# ---------------------------------------------------------------------------

#: Structural reference for every family :func:`identify_hash` knows about.
#: ``hex_length`` is the character count of the hex form, ``digest_bytes``
#: the decoded size; password-hashing formats use 0 (variable encoding).
HASH_FAMILIES: Dict[str, Dict[str, Any]] = {
    'MD5': {'digest_bytes': 16, 'hex_length': 32, 'charset': 'hex',
            'note': 'Broken collision resistance; still everywhere in file checksums.'},
    'MD4': {'digest_bytes': 16, 'hex_length': 32, 'charset': 'hex',
            'note': 'Legacy; basis of NTLM. Trivially crackable.'},
    'NTLM': {'digest_bytes': 16, 'hex_length': 32, 'charset': 'hex',
             'note': 'MD4 over UTF-16LE password; Windows dump staple.'},
    'LM': {'digest_bytes': 16, 'hex_length': 32, 'charset': 'hex',
           'note': ' DES-based, 7-char halves, uppercase-only; usually shown uppercase.'},
    'SHA-1': {'digest_bytes': 20, 'hex_length': 40, 'charset': 'hex',
              'note': 'Deprecated for security uses; git commits still use it.'},
    'RIPEMD-160': {'digest_bytes': 20, 'hex_length': 40, 'charset': 'hex',
                   'note': 'EU-designed SHA-1 alternative; Bitcoin addresses use it.'},
    'Tiger-160': {'digest_bytes': 20, 'hex_length': 40, 'charset': 'hex',
                  'note': 'Old hash forum benchmark digest.'},
    'SHA-224': {'digest_bytes': 28, 'hex_length': 56, 'charset': 'hex',
                'note': 'Truncated SHA-2 variant.'},
    'SHA3-224': {'digest_bytes': 28, 'hex_length': 56, 'charset': 'hex',
                 'note': 'Keccak-standardised SHA-3 variant.'},
    'SHA-256': {'digest_bytes': 32, 'hex_length': 64, 'charset': 'hex',
                'note': 'Current default digest; Bitcoin proof-of-work.'},
    'SHA3-256': {'digest_bytes': 32, 'hex_length': 64, 'charset': 'hex',
                 'note': 'NIST SHA-3 (padding differs from Keccak).'},
    'Keccak-256': {'digest_bytes': 32, 'hex_length': 64, 'charset': 'hex',
                   'note': 'Original Keccak padding - what Ethereum/EVM actually hashes with.'},
    'BLAKE2s': {'digest_bytes': 32, 'hex_length': 64, 'charset': 'hex',
                'note': 'Fast SHA-3 competitor, 32-byte flavor.'},
    'SHA-384': {'digest_bytes': 48, 'hex_length': 96, 'charset': 'hex',
                'note': 'Truncated SHA-512 variant.'},
    'SHA3-384': {'digest_bytes': 48, 'hex_length': 96, 'charset': 'hex',
                 'note': 'NIST SHA-3, 384-bit flavor.'},
    'SHA-512': {'digest_bytes': 64, 'hex_length': 128, 'charset': 'hex',
                'note': '64-bit-word SHA-2; password storage should add a KDF.'},
    'SHA3-512': {'digest_bytes': 64, 'hex_length': 128, 'charset': 'hex',
                 'note': 'NIST SHA-3, 512-bit flavor.'},
    'Whirlpool': {'digest_bytes': 64, 'hex_length': 128, 'charset': 'hex',
                  'note': 'ISO/IEC digest; rare outside older crypto libraries.'},
    'BLAKE2b': {'digest_bytes': 64, 'hex_length': 128, 'charset': 'hex',
                'note': 'BLAKE2, 64-byte flavor (default digest_bytes).'},
    'CRC32': {'digest_bytes': 4, 'hex_length': 8, 'charset': 'hex',
              'note': 'Checksum, NOT a hash - no collision resistance at all.'},
    'CRC64': {'digest_bytes': 8, 'hex_length': 16, 'charset': 'hex',
              'note': 'Checksum (e.g. Redis keys); not cryptographic.'},
    'MySQL pre-4.1': {'digest_bytes': 16, 'hex_length': 16, 'charset': 'hex',
                      'note': 'Old PASSWORD() output; ancient databases only.'},
    'MySQL 4.1+': {'digest_bytes': 20, 'hex_length': 40, 'charset': 'custom',
                   'note': "SHA1(SHA1(password)) prefixed with '*'; 41 chars total."},
    'bcrypt': {'digest_bytes': 0, 'hex_length': 60, 'charset': 'bcrypt',
               'note': 'Adaptive password hash: $2a/$2b/$2y$ + cost + salt + digest.'},
    'Argon2': {'digest_bytes': 0, 'hex_length': 95, 'charset': 'argon2',
               'note': 'Memory-hard KDF (PHC string format): $argon2id$v=...$m=...,t=...,p=...'},
    'JWT': {'digest_bytes': 0, 'hex_length': 0, 'charset': 'jwt',
            'note': 'Compact JWS: three dot-separated base64url segments.'},
}

#: Confidence ranking used to sort candidates (stable within one level).
_CONFIDENCE_RANK = {'high': 0, 'medium': 1, 'low': 2}

# ---------------------------------------------------------------------------
# Structural regexes
# ---------------------------------------------------------------------------

_HEX_FULL_RE = re.compile(r'[0-9a-fA-F]+')
_BCRYPT_RE = re.compile(r'^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$')
_ARGON2_RE = re.compile(
    r'^\$argon2(id|i|d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$')
_MYSQL41_RE = re.compile(r'^\*[0-9a-fA-F]{40}$')
_B64URL_RE = re.compile(r'[A-Za-z0-9_-]+')
_B64_RE = re.compile(r'[A-Za-z0-9+/]+={0,2}')

#: Base64 character counts (padding stripped) that decode to standard digest sizes.
#: e.g. 20 bytes -> 27 unpadded / 28 padded characters.
_B64_LENGTHS = {
    22: ('MD5 (base64)', 16),
    27: ('SHA-1 (base64)', 20),
    38: ('SHA-224 (base64)', 28),
    43: ('SHA-256 (base64)', 32),
    64: ('SHA-384 (base64)', 48),
    86: ('SHA-512 (base64)', 64),
}

#: Hex-digest rules: hex char count -> (name, confidence, bytes, note).
_HEX_RULES: Dict[int, List[Dict[str, Any]]] = {
    8: [
        {'name': 'CRC32', 'confidence': 'medium', 'digest_bytes': 4,
         'note': 'checksum, not a cryptographic hash (file-transfer sanity checks)'},
    ],
    16: [
        {'name': 'MySQL pre-4.1 (old PASSWORD())', 'confidence': 'medium', 'digest_bytes': 16,
         'note': '16-byte legacy MySQL password hash'},
        {'name': 'CRC64', 'confidence': 'low', 'digest_bytes': 8,
         'note': '64-bit checksum (Redis keyspace ids); non-cryptographic'},
    ],
    32: [
        {'name': 'MD5', 'confidence': 'high', 'digest_bytes': 16,
         'note': 'the most common 32-hex digest (file checksums, legacy password stores)'},
        {'name': 'NTLM', 'confidence': 'medium', 'digest_bytes': 16,
         'note': 'MD4 of the UTF-16LE password; uppercase hex is typical in Windows dumps'},
        {'name': 'MD4', 'confidence': 'medium', 'digest_bytes': 16,
         'note': 'legacy digest, indistinguishable from NTLM by shape alone'},
        {'name': 'LM', 'confidence': 'low', 'digest_bytes': 16,
         'note': 'DES-based halves; almost always rendered uppercase'},
    ],
    40: [
        {'name': 'SHA-1', 'confidence': 'high', 'digest_bytes': 20,
         'note': 'git object ids, legacy certificates, older password stores'},
        {'name': 'RIPEMD-160', 'confidence': 'medium', 'digest_bytes': 20,
         'note': 'same shape as SHA-1; used in Bitcoin and older PGP'},
        {'name': 'Tiger-160', 'confidence': 'low', 'digest_bytes': 20,
         'note': 'legacy Tiger digest; rare today'},
    ],
    56: [
        {'name': 'SHA-224', 'confidence': 'high', 'digest_bytes': 28,
         'note': 'truncated SHA-2 family'},
        {'name': 'SHA3-224', 'confidence': 'medium', 'digest_bytes': 28,
         'note': 'SHA-3 flavor with identical length'},
    ],
    64: [
        {'name': 'SHA-256', 'confidence': 'high', 'digest_bytes': 32,
         'note': 'current default digest (file integrity, certificates, Bitcoin PoW)'},
        {'name': 'SHA3-256', 'confidence': 'medium', 'digest_bytes': 32,
         'note': 'NIST SHA-3 with different padding than Keccak'},
        {'name': 'Keccak-256', 'confidence': 'medium', 'digest_bytes': 32,
         'note': 'EVM/Ethereum hashing - identical 64-hex shape, NOT SHA3-256'},
        {'name': 'BLAKE2s', 'confidence': 'medium', 'digest_bytes': 32,
         'note': '32-byte BLAKE2 flavor'},
    ],
    96: [
        {'name': 'SHA-384', 'confidence': 'high', 'digest_bytes': 48,
         'note': 'truncated SHA-512; common in TLS suites'},
        {'name': 'SHA3-384', 'confidence': 'medium', 'digest_bytes': 48,
         'note': 'SHA-3 flavor with identical length'},
    ],
    128: [
        {'name': 'SHA-512', 'confidence': 'high', 'digest_bytes': 64,
         'note': '64-bit-word SHA-2 variant'},
        {'name': 'SHA3-512', 'confidence': 'medium', 'digest_bytes': 64,
         'note': 'SHA-3 flavor with identical length'},
        {'name': 'BLAKE2b', 'confidence': 'medium', 'digest_bytes': 64,
         'note': 'default 64-byte BLAKE2 flavor'},
        {'name': 'Whirlpool', 'confidence': 'medium', 'digest_bytes': 64,
         'note': 'ISO/IEC 10118-3 digest; rare in the wild'},
    ],
}


def _charset_profile(value: str) -> str:
    """Classify the character set used by a candidate digest string."""
    if _HEX_FULL_RE.fullmatch(value):
        return 'hex'
    if _BCRYPT_RE.match(value):
        return 'bcrypt'
    if _ARGON2_RE.match(value):
        return 'argon2'
    if _B64URL_RE.fullmatch(value):
        return 'base64url'
    if _B64_RE.fullmatch(value):
        return 'base64'
    if value.count('.') == 2 and all(value.split('.')):
        return 'jwt'
    return 'custom'


def identify_hash(value: str) -> List[Dict[str, Any]]:
    """
    EXPERIMENTAL: identify the likely format(s) of a hash-like string.

    Structural analysis only - exact length/charset/prefix matches produce
    candidates ``{'name', 'confidence', 'length' (decoded bytes),
    'charset', 'note'}`` sorted high -> medium -> low (stable order within
    a level). Because length alone cannot split same-size algorithms,
    every same-size alternative is listed with an explanatory note (see
    the Keccak-256 entry for the classic Ethereum trap).

    Recognised shapes: hex digests of 8/16/32/40/56/64/96/128 chars;
    base64-encoded digests (24/28/44/56/64/88 chars); bcrypt
    (``$2a$/$2b$/$2y$``, cost extracted); Argon2 PHC strings (type,
    memory, time, lanes parsed); MySQL 4.1+ (``*`` + 40 hex); and raw JWT
    compact serializations. An optional ``0x`` prefix is tolerated on hex
    input. Unknown shapes return a single low-confidence 'Unknown' entry
    describing what was seen instead of an empty list.

    Args:
        value: the digest string (non-string/empty input yields ``[]``).

    Returns:
        Ranked candidate list; empty input returns ``[]``.
    """
    if not isinstance(value, str):
        return []
    candidate = value.strip()
    if not candidate:
        return []
    profile = _charset_profile(candidate)
    candidates: List[Dict[str, Any]] = []

    def entry(name: str, confidence: str, length: int, note: str) -> None:
        candidates.append({'name': name, 'confidence': confidence, 'length': length,
                           'charset': profile, 'note': note})

    # --- JWT compact serialization ---------------------------------------
    if profile == 'jwt':
        entry('JWT token (compact JWS)', 'high', 0,
              'three dot-separated base64url segments - decode with jwt_tools.inspect_jwt '
              'rather than treating it as a digest')
        return _ranked(candidates)

    # --- bcrypt -------------------------------------------------------------
    match = _BCRYPT_RE.match(candidate)
    if match:
        cost = int(match.group(1))
        entry('bcrypt', 'high', 0,
              f'cost factor {cost} ({"weak" if cost < 10 else "acceptable" if cost < 13 else "strong"}); '
              'salt and digest embedded in the 60-char string')
        return _ranked(candidates)

    # --- Argon2 (PHC string format) ----------------------------------------
    match = _ARGON2_RE.match(candidate)
    if match:
        variant = {'id': 'Argon2id (hybrid)', 'i': 'Argon2i (side-channel resistant)',
                   'd': 'Argon2d (GPU-resistant)'}[match.group(1)]
        version = match.group(2)
        memory, iterations, lanes = int(match.group(3)), int(match.group(4)), int(match.group(5))
        entry('Argon2', 'high', 0,
              f'{variant}, v={version}, m={memory} KiB, t={iterations} iterations, p={lanes} lanes')
        return _ranked(candidates)

    # --- MySQL 4.1+ ----------------------------------------------------------
    if _MYSQL41_RE.match(candidate):
        entry('MySQL 4.1+ password', 'high', 20,
              "'*' + 40 hex: SHA1(SHA1(password)) - the '*' prefix is the giveaway")
        return _ranked(candidates)

    # --- hex rules ------------------------------------------------------------
    hex_candidate = candidate[2:] if candidate[:2].lower() == '0x' else candidate
    hex_note = ' (0x prefix tolerated)' if hex_candidate is not candidate else ''
    if _HEX_FULL_RE.fullmatch(hex_candidate) and len(hex_candidate) in _HEX_RULES:
        uppercase_hint = bool(re.fullmatch(r'[0-9A-F]+', hex_candidate)) and \
            any(ch.isalpha() for ch in hex_candidate)
        for rule in _HEX_RULES[len(hex_candidate)]:
            note = rule['note'] + hex_note
            if uppercase_hint and rule['name'] in ('NTLM', 'LM'):
                note += ' - uppercase-only hex supports this reading'
            entry(rule['name'], rule['confidence'], rule['digest_bytes'], note)
        if not uppercase_hint and len(hex_candidate) == 32:
            candidates[0]['note'] += ' (lowercase hex is the unix-style presentation)'
        return _ranked(candidates)

    # --- base64-encoded digests ----------------------------------------------
    # Pure-hex strings whose length matched no hex rule also land here: a
    # 27-char all-hex string is equally plausible as unpadded SHA-1 base64.
    if profile in ('base64', 'base64url', 'hex'):
        unpadded = candidate.rstrip('=')
        base64_rule = _B64_LENGTHS.get(len(unpadded))
        if base64_rule:
            name, digest_bytes = base64_rule
            entry(name, 'medium', digest_bytes,
                  f'{len(candidate)} base64 characters decode to {digest_bytes} bytes '
                  '(as used in XML-DSig DigestValue and many API responses)')
            return _ranked(candidates)

    # --- nothing matched -------------------------------------------------------
    entry('Unknown', 'low', 0,
          f'no known digest format matches {len(candidate)} characters of {profile} text')
    return _ranked(candidates)


def _ranked(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stable-sort candidates high -> medium -> low."""
    return sorted(candidates, key=lambda item: _CONFIDENCE_RANK.get(item['confidence'], 3))


# ---------------------------------------------------------------------------
# Offline checksum triage
# ---------------------------------------------------------------------------

#: Algorithms tried by :func:`checksum_matches` (cheap, exhaustive locally).
_MATCH_ALGORITHMS = ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')

#: Hard cap on candidate plaintexts so a pasted novel cannot stall a scan.
_MAX_CANDIDATES = 10000


def checksum_matches(value: str, candidates_text: Union[str, Iterable[str]]) -> Dict[str, Any]:
    """
    EXPERIMENTAL: test candidate plaintexts against a digest, offline.

    The quick triage step for password hashes from small wordlists: is
    this ``value`` the md5/sha1/sha224/sha256/sha384/sha512 of any of
    these strings? No network, no cracking rig - just a handful of digest
    computations, which is exactly right for "is it the username? the
    company name? the literal word 'password'?" checks.

    Args:
        value: the digest to match (hex, any of the supported lengths).
        candidates_text: candidate plaintexts - a string with one
            candidate per line, or any iterable of strings.

    Returns:
        ``{'value', 'algorithms_tested', 'candidates_tried', 'matches':
        [{'algorithm', 'plaintext'}], 'matched': bool}``; malformed input
        returns the same shape with an ``'error'`` key instead of raising.
    """
    result: Dict[str, Any] = {
        'value': value if isinstance(value, str) else '',
        'algorithms_tested': list(_MATCH_ALGORITHMS),
        'candidates_tried': 0,
        'matches': [],
        'matched': False,
    }
    if not isinstance(value, str) or not value.strip():
        result['error'] = 'no digest provided'
        return result
    target = value.strip().lower()
    if not _HEX_FULL_RE.fullmatch(target):
        result['error'] = 'digest must be a hexadecimal string'
        return result

    if isinstance(candidates_text, str):
        plain_candidates = candidates_text.splitlines()
    elif isinstance(candidates_text, Iterable):
        plain_candidates = [str(item) for item in candidates_text]
    else:
        result['error'] = 'candidates must be a string or an iterable of strings'
        return result

    matches: List[Dict[str, str]] = []
    tried = 0
    for plaintext in plain_candidates:
        text = plaintext.strip()
        if not text:
            continue
        tried += 1
        if tried > _MAX_CANDIDATES:
            break
        payload = text.encode('utf-8')
        for algorithm in _MATCH_ALGORITHMS:
            if hashlib.new(algorithm, payload).hexdigest() == target:
                matches.append({'algorithm': algorithm, 'plaintext': text})
    result['candidates_tried'] = min(tried, _MAX_CANDIDATES)
    result['matches'] = matches
    result['matched'] = bool(matches)
    return result
