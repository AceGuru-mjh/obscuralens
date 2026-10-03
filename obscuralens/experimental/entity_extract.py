"""
Entity extraction from arbitrary text (EXPERIMENTAL).

Paste an email body, a forum post, a paste-dump entry or a threat-report
paragraph and pull every OSINT pivot target out of it: email addresses,
URLs, bare domains, IPv4/IPv6 literals, AS-number mentions, MAC addresses,
IBANs, IMEIs, file hashes, CVE identifiers, cryptocurrency addresses,
geographic coordinates, phone-number candidates, @-handles and parcel
tracking numbers.

The pipeline is validator-driven: a regex proposes, the shared
``utils.validators`` module disposes. That keeps the same three-state
verdict logic the production trackers use (mod-97 for IBANs, Luhn for
IMEIs, charset/shape rules for crypto addresses, coordinate range checks)
instead of a second, drifting copy of those rules.

Two-phase design, because weak entities live off leftovers:

1. **Strong entities** are extracted first, in confidence order
   (emails, URLs, IPs, MACs, IBANs, IMEIs, crypto, hashes, CVEs,
   coordinates, ASNs); every confirmed hit is masked out of a working
   copy of the text so a 15-digit IMEI can never double-report as a
   FedEx tracking number or a phone.
2. **Weak candidates** (handles, phones, tracking IDs) run against the
   fully masked text and are labelled ``*_candidates`` in the result -
   they are leads to verify, not confirmed entities. Domains are scanned
   against the ORIGINAL text so hosts inside URLs and emails also count.

Every category list is de-duplicated (case-insensitively where that is
safe), preserves first-appearance order and is capped at 50 entries.
:func:`redact_entities` / :func:`redact_with_map` turn the same pipeline
into a safe-sharing formatter that replaces entities with numbered
placeholders and hands back the reversible mapping.
"""

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..utils import validators

__all__ = [
    'extract_entities',
    'summarize_entities',
    'redact_entities',
    'redact_with_map',
    'ENTITY_KINDS',
]

#: Per-category cap (keeps a pasted log from producing 10k hits).
_MAX_PER_KIND = 50

#: Result keys in presentation order (also the redaction kind vocabulary).
ENTITY_KINDS: Tuple[str, ...] = (
    'emails', 'urls', 'domains', 'ipv4', 'ipv6', 'asn', 'macs', 'ibans',
    'imeis', 'hashes', 'cves', 'crypto_addresses', 'coords',
    'phone_candidates', 'user_handles', 'tracking_ids',
)

#: Placeholder labels used by :func:`redact_entities` ('[EMAIL #1]' style).
_REDACT_LABELS: Dict[str, str] = {
    'emails': 'EMAIL', 'urls': 'URL', 'domains': 'DOMAIN', 'ipv4': 'IPV4',
    'ipv6': 'IPV6', 'asn': 'ASN', 'macs': 'MAC', 'ibans': 'IBAN',
    'imeis': 'IMEI', 'hashes': 'HASH', 'cves': 'CVE',
    'crypto_addresses': 'CRYPTO', 'coords': 'COORDS', 'phone_candidates': 'PHONE',
    'user_handles': 'HANDLE', 'tracking_ids': 'TRACKING',
}

# ---------------------------------------------------------------------------
# Module-level regexes (the "propose" half of propose -> validate)
# ---------------------------------------------------------------------------

# Email addresses: local@domain.tld - validated by validators.validate_email.
_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')

# Absolute URLs (http/https); trailing punctuation is stripped before validation.
_URL_RE = re.compile(r'\bhttps?://[^\s<>"\']+', re.IGNORECASE)

# Dotted-quad IPv4 - validated through the ipaddress module.
_IPV4_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')

# Candidate IPv6 runs (hex digits + colons); anything with 2+ colons is fed
# to ipaddress.ip_address() which keeps only genuine IPv6 literals. MAC
# addresses (6 groups) fail that check and survive for the MAC extractor.
_IPV6_CAND_RE = re.compile(r'(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{2,45}(?![0-9A-Fa-f:])')

# MAC addresses in colon / dash / Cisco-dot notation - validators.validate_mac.
_MAC_RE = re.compile(
    r'\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b'
    r'|\b[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}\b'
    r'|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b')

# IBANs: compact form and printed form (single spaces between groups).
_IBAN_COMPACT_RE = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b')
_IBAN_SPACED_RE = re.compile(r'\b[A-Z]{2}\d{2}(?:[ ][A-Z0-9]{4}){3,7}(?:[ ][A-Z0-9]{1,4})?\b')

# IMEIs: 15/16-digit runs, or lightly punctuated forms - Luhn-checked.
_IMEI_RE = re.compile(r'(?<!\d)\d{15}(?:\d)?(?!\d)')
_IMEI_PUNCT_RE = re.compile(r'\b\d{2}[\s-]?\d{6}[\s-]?\d{6}[\s-]?\d\b')

# Cryptocurrency addresses: one pattern per chain family, all funnelled
# through validators.detect_crypto_chain() for the final verdict.
_CRYPTO_RES = (
    re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),      # BTC base58
    re.compile(r'\b(?:bc|ltc)1[a-z0-9]{11,71}\b'),            # bech32
    re.compile(r'\b0x[a-fA-F0-9]{40}\b'),                     # ETH / EVM
    re.compile(r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),   # XMR
    re.compile(r'\bD[a-mzA-HJ-NP-Z1-9]{25,34}\b'),            # DOGE
    re.compile(r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b'),       # LTC base58
    re.compile(r'\br[1-9A-HJ-NP-Za-km-z]{24,34}\b'),          # XRP
    re.compile(r'\baddr1[a-z0-9]{40,120}\b'),                 # ADA
)

# CVE identifiers - validated/normalised via validators.normalize_cve.
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

# Coordinates in decimal degrees, inlined in prose ("48.8584, 2.2945").
# At least one decimal point is required so "2, 3" list syntax is not
# mistaken for a location; validators.parse_coords does the real check.
_COORD_DD_RE = re.compile(
    r'(?<![\d.])-?\d{1,3}(?:\.\d+)?\s*[,;]\s*-?\d{1,3}(?:\.\d+)?(?![\d.])')

# Coordinates in degrees/minutes/seconds with hemisphere letters; only
# matches that survive validators.parse_coords are reported. Marker runs
# (° ' " : spaces) between the number groups are consumed greedily so
# "N 48° 51' 29\"" and "48°51'29\"N" shapes both match.
_COORD_DMS_RE = re.compile(
    r"[NSns]\s*\d{1,3}(?:[°'\"d:\s]+\d{1,2}(?:\.\d+)?){0,2}[°'\"d:\s]*[NSns]?\s*[,;]?\s+"
    r"[EWew]\s*\d{1,3}(?:[°'\"d:\s]+\d{1,2}(?:\.\d+)?){0,2}[°'\"d:\s]*[EWew]?",
)

# AS-number mentions ("AS1234" / "as 1234") - validators.validate_asn.
_ASN_RE = re.compile(r'\bAS\s?\d{1,10}\b', re.IGNORECASE)

# Bare domains - validated by validators.validate_domain. Scanned against
# the ORIGINAL text (URLs and emails contribute their hosts too).
_DOMAIN_RE = re.compile(r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b')

# @-handles: 2-30 safe characters after '@' (emails are excluded by the
# lookbehind/lookahead so 'admin@evil-corp.com' never yields '@evil').
_HANDLE_RE = re.compile(r'(?<![\w@.])@[A-Za-z0-9_]{2,30}(?![\w@.])')

# Phone-ish runs: optional '+', then digits with spaces/dashes/parens.
# Must contain a separator or '+' so pure-digit IMEIs do not dominate.
_PHONE_RE = re.compile(r'\+?\d[\d\s\-()]{7,}\d')

# Parcel tracking numbers (no strong checksums exist for most of these,
# hence 'tracking_candidates').
_TRACKING_RES = (
    re.compile(r'\b1Z[0-9A-Z]{16}\b'),        # UPS
    re.compile(r'(?<!\d)\d{12}(?!\d)'),       # FedEx 12
    re.compile(r'(?<!\d)\d{15}(?!\d)'),       # FedEx 15
    re.compile(r'(?<!\d)\d{10}(?!\d)'),       # DHL
    re.compile(r'(?<!\d)\d{20}(?!\d)'),       # USPS 20
    re.compile(r'(?<!\d)\d{22}(?!\d)'),       # USPS 22
)

# Tokenizer for hash scanning: alnum runs, hex runs, digest sizes.
_ALNUM_RE = re.compile(r'[0-9A-Za-z]+')
_HEX_TOKEN_RE = re.compile(r'[0-9A-Fa-f]+')
_DIGEST_LENGTHS = frozenset((32, 40, 56, 64, 96, 128))

#: Trailing punctuation commonly glued onto URLs in prose.
_URL_TRAILING = '.,;:!?)]}>\'"'

# Extraction order for strong entities (masking happens after each kind).
_STRONG_ORDER: Tuple[str, ...] = (
    'emails', 'urls', 'ipv6', 'ipv4', 'macs', 'ibans', 'imeis',
    'crypto_addresses', 'hashes', 'cves', 'coords', 'asn',
)

# Weak candidates run against the fully masked text, in this order.
_WEAK_ORDER: Tuple[str, ...] = ('user_handles', 'phone_candidates', 'tracking_ids')

# ---------------------------------------------------------------------------
# Internal plumbing
# ---------------------------------------------------------------------------

_Hit = Tuple[str, int, int]  # (value, start, end) span in the working text.


def _dedup(hits: List[_Hit], key_lower: bool = True) -> List[_Hit]:
    """First-appearance-order, case-(in)sensitive de-duplication of hits."""
    seen = set()
    unique: List[_Hit] = []
    for value, start, end in hits:
        marker = value.lower() if key_lower else value
        if marker in seen:
            continue
        seen.add(marker)
        unique.append((value, start, end))
        if len(unique) >= _MAX_PER_KIND:
            break
    return unique


def _mask(text: str, hits: Iterable[_Hit]) -> str:
    """Blank out hit spans with spaces (length-preserving, offsets stable)."""
    chars = list(text)
    for _value, start, end in hits:
        for index in range(start, min(end, len(chars))):
            chars[index] = ' '
    return ''.join(chars)


def _strip_trailing(value: str) -> str:
    """Remove prose punctuation glued to the end of a URL match."""
    return value.rstrip(_URL_TRAILING)


def _extract_emails(text: str) -> List[_Hit]:
    """Email addresses confirmed by validators.validate_email."""
    hits: List[_Hit] = []
    for match in _EMAIL_RE.finditer(text):
        value = match.group(0)
        ok, _ = validators.validate_email(value)
        if ok:
            hits.append((value, match.start(), match.end()))
    return _dedup(hits)


def _extract_urls(text: str) -> List[_Hit]:
    """Absolute http(s) URLs confirmed by validators.validate_url."""
    hits: List[_Hit] = []
    for match in _URL_RE.finditer(text):
        value = _strip_trailing(match.group(0))
        ok, _ = validators.validate_url(value)
        if not ok:
            continue
        trimmed = len(match.group(0)) - len(value)
        hits.append((value, match.start(), match.end() - trimmed))
    return _dedup(hits)


def _extract_ipv4(text: str) -> List[_Hit]:
    """IPv4 literals confirmed by the ipaddress module."""
    hits: List[_Hit] = []
    for match in _IPV4_RE.finditer(text):
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        hits.append((match.group(0), match.start(), match.end()))
    return _dedup(hits)


def _extract_ipv6(text: str) -> List[_Hit]:
    """IPv6 literals: candidate hex/colon runs filtered by ipaddress."""
    hits: List[_Hit] = []
    for match in _IPV6_CAND_RE.finditer(text):
        candidate = match.group(0)
        if candidate.count(':') < 2:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        hits.append((candidate.lower(), match.start(), match.end()))
    return _dedup(hits)


def _extract_macs(text: str) -> List[_Hit]:
    """MAC addresses confirmed by validators.validate_mac."""
    hits: List[_Hit] = []
    for match in _MAC_RE.finditer(text):
        value = match.group(0)
        ok, _ = validators.validate_mac(value)
        if ok:
            hits.append((value, match.start(), match.end()))
    return _dedup(hits)


def _extract_ibans(text: str) -> List[_Hit]:
    """IBANs (compact or printed spacing) passing the mod-97 checksum."""
    hits: List[_Hit] = []
    patterns = (_IBAN_COMPACT_RE, _IBAN_SPACED_RE)
    for pattern in patterns:
        for match in pattern.finditer(text):
            normalized = validators.normalize_iban(match.group(0))
            if not normalized:
                continue
            ok, _ = validators.validate_iban(normalized)
            if ok:
                hits.append((normalized, match.start(), match.end()))
    return _dedup(hits)


def _extract_imeis(text: str) -> List[_Hit]:
    """IMEI/IMEISV numbers passing the Luhn check."""
    hits: List[_Hit] = []
    spans: List[_Hit] = []
    for match in _IMEI_RE.finditer(text):
        spans.append((match.group(0), match.start(), match.end()))
    for match in _IMEI_PUNCT_RE.finditer(text):
        spans.append((match.group(0), match.start(), match.end()))
    for raw, start, end in spans:
        normalized = validators.normalize_imei(raw)
        if not normalized:
            continue
        ok, _ = validators.validate_imei(normalized)
        if ok:
            hits.append((normalized, start, end))
    return _dedup(hits)


def _extract_crypto(text: str) -> List[_Hit]:
    """Cryptocurrency addresses confirmed by validators.detect_crypto_chain."""
    hits: List[_Hit] = []
    for pattern in _CRYPTO_RES:
        for match in pattern.finditer(text):
            value = match.group(0)
            if validators.detect_crypto_chain(value):
                hits.append((value, match.start(), match.end()))
    return _dedup(hits)


def _extract_hashes(text: str) -> List[_Hit]:
    """
    Hex digests found by tokenizing, then rejoining split hex fragments.

    Text is split on non-alphanumeric characters; single all-hex tokens of
    a known digest length are reported directly, and pairs of adjacent hex
    tokens (each >= 4 chars) separated by exactly one character are re-
    joined when the merged length is a digest length - that catches
    line-wrapped or dash-split digests in pasted reports. Every candidate
    is confirmed by validators.detect_hash_algorithm.
    """
    hits: List[_Hit] = []
    tokens = list(_ALNUM_RE.finditer(text))
    hex_tokens = [(m.group(), m.start(), m.end()) for m in tokens if _HEX_TOKEN_RE.fullmatch(m.group())]
    for value, start, end in hex_tokens:
        if len(value) in _DIGEST_LENGTHS and validators.detect_hash_algorithm(value):
            hits.append((value, start, end))
    for index in range(len(hex_tokens) - 1):
        value_a, start_a, end_a = hex_tokens[index]
        value_b, start_b, end_b = hex_tokens[index + 1]
        if start_b - end_a != 1:
            continue
        merged = value_a + value_b
        if len(value_a) < 4 or len(value_b) < 4:
            continue
        if len(merged) in _DIGEST_LENGTHS and validators.detect_hash_algorithm(merged):
            hits.append((merged, start_a, end_b))
    return _dedup(hits)


def _extract_cves(text: str) -> List[_Hit]:
    """CVE identifiers, normalised to uppercase via validators.normalize_cve."""
    hits: List[_Hit] = []
    for match in _CVE_RE.finditer(text):
        normalized = validators.normalize_cve(match.group(0))
        if normalized:
            hits.append((normalized, match.start(), match.end()))
    return _dedup(hits)


def _extract_coords(text: str) -> List[_Hit]:
    """Coordinate pairs (DD or DMS) verified by validators.parse_coords."""
    hits: List[_Hit] = []
    spans: List[_Hit] = []
    for match in _COORD_DD_RE.finditer(text):
        if '.' in match.group(0):
            spans.append((match.group(0), match.start(), match.end()))
    for match in _COORD_DMS_RE.finditer(text):
        spans.append((match.group(0), match.start(), match.end()))
    for raw, start, end in spans:
        parsed = validators.parse_coords(raw)
        if parsed is None:
            continue
        normalized = validators.normalize_coords(raw)
        hits.append((normalized, start, end))
    return _dedup(hits)


def _extract_asn(text: str) -> List[_Hit]:
    """AS-number mentions normalised to 'AS1234' via validators.normalize_asn."""
    hits: List[_Hit] = []
    for match in _ASN_RE.finditer(text):
        number = validators.normalize_asn(match.group(0))
        if number:
            hits.append((f'AS{number}', match.start(), match.end()))
    return _dedup(hits)


def _extract_domains(text: str) -> List[_Hit]:
    """Bare domains (from the ORIGINAL text, so URL hosts count too)."""
    hits: List[_Hit] = []
    for match in _DOMAIN_RE.finditer(text):
        value = match.group(0)
        ok, _ = validators.validate_domain(value)
        if ok:
            hits.append((value.lower(), match.start(), match.end()))
    return _dedup(hits)


def _extract_handles(text: str) -> List[_Hit]:
    """@-handle candidates (no validator exists - these are leads only)."""
    hits: List[_Hit] = []
    for match in _HANDLE_RE.finditer(text):
        hits.append((match.group(0), match.start(), match.end()))
    return _dedup(hits)


def _extract_phones(text: str) -> List[_Hit]:
    """Phone-number candidates confirmed by validators.validate_phone."""
    hits: List[_Hit] = []
    for match in _PHONE_RE.finditer(text):
        value = match.group(0)
        ok, _ = validators.validate_phone(value)
        if ok:
            hits.append((value, match.start(), match.end()))
    return _dedup(hits)


def _extract_tracking(text: str) -> List[_Hit]:
    """Parcel tracking-number candidates (UPS/FedEx/DHL/USPS shapes)."""
    hits: List[_Hit] = []
    for pattern in _TRACKING_RES:
        for match in pattern.finditer(text):
            hits.append((match.group(0), match.start(), match.end()))
    return _dedup(hits)


#: Strong-entity extractors, keyed by result kind.
_STRONG_EXTRACTORS = {
    'emails': _extract_emails,
    'urls': _extract_urls,
    'ipv6': _extract_ipv6,
    'ipv4': _extract_ipv4,
    'macs': _extract_macs,
    'ibans': _extract_ibans,
    'imeis': _extract_imeis,
    'crypto_addresses': _extract_crypto,
    'hashes': _extract_hashes,
    'cves': _extract_cves,
    'coords': _extract_coords,
    'asn': _extract_asn,
}

#: Weak-candidate extractors, keyed by result kind.
_WEAK_EXTRACTORS = {
    'user_handles': _extract_handles,
    'phone_candidates': _extract_phones,
    'tracking_ids': _extract_tracking,
}


def _collect(text: str) -> Dict[str, List[_Hit]]:
    """
    Run the two-phase pipeline; returns kind -> [(value, start, end)].

    All spans refer to the ORIGINAL text: masking only ever substitutes
    spaces, so offsets never shift between phases.
    """
    collected: Dict[str, List[_Hit]] = {}
    scratch = text
    for kind in _STRONG_ORDER:
        hits = _STRONG_EXTRACTORS[kind](scratch)
        collected[kind] = hits
        scratch = _mask(scratch, hits)
    for kind in _WEAK_ORDER:
        hits = _WEAK_EXTRACTORS[kind](scratch)
        collected[kind] = hits
        scratch = _mask(scratch, hits)
    collected['domains'] = _extract_domains(text)
    return {kind: collected.get(kind, []) for kind in ENTITY_KINDS}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_entities(text: str) -> Dict[str, List[str]]:
    """
    EXPERIMENTAL: extract every OSINT pivot target from arbitrary text.

    Args:
        text: the text to scan (email body, paste, dump, report excerpt).
            Non-string or empty input yields an all-empty result.

    Returns:
        ``{kind: [values...]}`` for every kind in :data:`ENTITY_KINDS`
        (emails, urls, domains, ipv4, ipv6, asn, macs, ibans, imeis,
        hashes, cves, crypto_addresses, coords, phone_candidates,
        user_handles, tracking_ids). Values are de-duplicated, in
        first-appearance order, capped at 50 per kind. Strong kinds are
        validator-confirmed; weak kinds (phones, handles, tracking ids)
        are candidates to verify. Never raises.
    """
    result: Dict[str, List[str]] = {kind: [] for kind in ENTITY_KINDS}
    if not isinstance(text, str) or not text.strip():
        return result
    collected = _collect(text)
    for kind in ENTITY_KINDS:
        result[kind] = [value for value, _start, _end in collected[kind]]
    return result


def summarize_entities(found: Dict[str, Any]) -> Dict[str, int]:
    """
    EXPERIMENTAL: count extracted entities per kind plus a grand total.

    Args:
        found: a dict as returned by :func:`extract_entities` (anything
            else is tolerated and reported as an empty summary).

    Returns:
        ``{kind: count}`` for every non-empty kind, plus ``'total'``.
    """
    if not isinstance(found, dict):
        return {'total': 0}
    summary: Dict[str, int] = {}
    total = 0
    for kind in ENTITY_KINDS:
        values = found.get(kind)
        if isinstance(values, (list, tuple)) and values:
            summary[kind] = len(values)
            total += len(values)
    summary['total'] = total
    return summary


def _normalize_kinds(kinds: Optional[Iterable[str]]) -> List[str]:
    """Validate a kind selection against ENTITY_KINDS (None means 'all')."""
    if kinds is None:
        return list(ENTITY_KINDS)
    if isinstance(kinds, str):
        kinds = [kinds]
    selected = [kind for kind in kinds if kind in ENTITY_KINDS]
    return selected or list(ENTITY_KINDS)


def redact_with_map(text: str, kinds: Optional[Iterable[str]] = None) -> Tuple[str, Dict[str, str]]:
    """
    EXPERIMENTAL: replace entities with placeholders, returning the mapping.

    Args:
        text: the text to sanitise for safe report sharing.
        kinds: iterable of :data:`ENTITY_KINDS` names to redact
            (default: every kind). Unknown names are ignored; an empty
            selection falls back to all kinds.

    Returns:
        ``(redacted_text, mapping)`` where every selected entity became a
        numbered placeholder like ``[EMAIL #1]`` / ``[URL #2]`` (numbered
        per kind in order of appearance) and ``mapping`` is
        ``{placeholder: original_value}`` - the analyst's private decode
        table, kept out of the shared document. Overlapping entities
        resolve to the higher-priority (earlier-starting, longer) one,
        so a domain inside an email is consumed by the email redaction.
        Non-string / empty input returns ``(text, {})``. Never raises.
    """
    if not isinstance(text, str) or not text.strip():
        return text, {}
    selected = _normalize_kinds(kinds)
    collected = _collect(text)
    spans: List[Tuple[int, int, str, str]] = []
    for kind in selected:
        for value, start, end in collected[kind]:
            spans.append((start, end, kind, value))
    if not spans:
        return text, {}
    # Earliest start first; longer spans win ties (email over its domain).
    spans.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    chosen: List[Tuple[int, int, str, str]] = []
    last_end = -1
    for start, end, kind, value in spans:
        if start >= last_end:
            chosen.append((start, end, kind, value))
            last_end = end

    counters: Dict[str, int] = {}
    mapping: Dict[str, str] = {}
    replacements: List[Tuple[int, int, str]] = []
    for start, end, kind, value in chosen:
        counters[kind] = counters.get(kind, 0) + 1
        placeholder = f'[{_REDACT_LABELS[kind]} #{counters[kind]}]'
        replacements.append((start, end, placeholder))
        mapping[placeholder] = value

    chars = list(text)
    for start, end, placeholder in sorted(replacements, reverse=True):
        chars[start:end] = [placeholder]
    return ''.join(chars), mapping


def redact_entities(text: str, kinds: Optional[Iterable[str]] = None) -> str:
    """
    EXPERIMENTAL: replace extracted entities with placeholders in place.

    The one-liner form of :func:`redact_with_map` for when the reversal
    mapping is not needed: ``admin@evil-corp.com`` becomes
    ``[EMAIL #1]``, ``https://evil-corp.com/login`` becomes ``[URL #1]``
    and so on, producing text that is safe to paste into a shared report
    without leaking the pivot targets themselves.

    Args:
        text: the text to sanitise.
        kinds: entity kinds to redact (default: all kinds).

    Returns:
        The redacted text; input that is not a non-empty string is
        returned unchanged. Never raises.
    """
    redacted, _mapping = redact_with_map(text, kinds)
    return redacted
