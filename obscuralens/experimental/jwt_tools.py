"""
JWT inspection workbench (EXPERIMENTAL) - decode and analyse, never verify.

JSON Web Tokens are everywhere in OSINT material: leaked API keys in paste
dumps, session cookies in malware config, OAuth artifacts in incident
response tickets. This module splits a compact JWS token apart, decodes the
base64url header and payload, and enriches them with analyst-oriented
notes: claim timelines (iat/nbf/exp with expiry verdicts), algorithm
risk hints (``alg: none`` is a critical finding), key-identifier hints
(``kid``/``x5c``) and token size statistics.

**No signature verification is attempted - by design.** Verifying an
asymmetric JWT (RS*/ES*/PS*) requires the signer's public key or
certificate chain, which is simply not available offline; verifying a
symmetric JWT (HS*) requires the shared secret, which an analyst almost
never holds. Half-verified tokens are worse than openly-unverified ones,
so this module only *decodes and describes*. Every result carries a
standing reminder that unsigned claims are untrusted claims: until the
signature is verified with the real key material, treat the payload as
attacker-controlled data (a fact routinely forgotten when pretty-printing
tokens into reports).
"""

import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

__all__ = ['decode_jwt', 'inspect_jwt', 'PAYLOAD_LABELS']

#: Friendly descriptions for the claims analysts meet most often. Exported
#: so UIs and reports can label raw claim names without duplicating knowledge.
PAYLOAD_LABELS: Dict[str, str] = {
    'iss': 'Issuer - who created/signed the token',
    'sub': 'Subject - the principal the token is about (user id, client id)',
    'aud': 'Audience - who the token is intended for',
    'exp': 'Expiration time (epoch seconds) - reject after this moment',
    'nbf': 'Not-before time (epoch seconds) - reject before this moment',
    'iat': 'Issued-at time (epoch seconds)',
    'jti': 'JWT ID - unique token identifier for replay tracking',
    'kid': 'Key ID - which key signed the token (header claim)',
    'alg': 'Algorithm used for signing (header claim)',
    'typ': 'Token type, normally "JWT" (header claim)',
    'cty': 'Content type of the payload (header claim)',
    'scope': 'Space-separated requested scopes',
    'scopes': 'Scope list (non-standard variant of "scope")',
    'x5c': 'X.509 certificate chain embedded in the header',
    'x5u': 'URL to fetch the signer certificate (header claim)',
    'x5t': 'SHA-1 thumbprint of the signer certificate (header claim)',
    'jku': 'URL to the JWK set used for signing (header claim)',
    'azp': 'Authorized party - the client this token was issued to',
    'nonce': 'Value binding the token to an auth request',
    'at_hash': 'Access-token hash binding (OpenID Connect)',
    'c_hash': 'Code hash binding (OpenID Connect)',
    'amr': 'Authentication method references (how the user logged in)',
    'sid': 'Session ID (OpenID Connect back-channel logout)',
    'name': 'Human-readable display name',
    'email': 'Subject email address',
    'preferred_username': 'Subject login/handle',
    'roles': 'Role assignments carried by the token',
    'permissions': 'Permission grants carried by the token',
}

#: Clock skew tolerance (seconds) before an iat is called "in the future".
_FUTURE_TOLERANCE = 60

#: Signature preview length in bytes (kept short - it is a fingerprint hint).
_SIGNATURE_PREVIEW_BYTES = 16


def _b64url_decode(segment: str) -> bytes:
    """
    Base64url-decode one JWT segment, adding the stripped padding back.

    Raises ``ValueError`` when the segment cannot be decoded (wrong
    alphabet or impossible padding) - callers translate that into an
    analyst-readable note.
    """
    candidate = segment.strip()
    if not candidate:
        raise ValueError('empty segment')
    candidate += '=' * ((-len(candidate)) % 4)
    try:
        return base64.urlsafe_b64decode(candidate)
    except (binascii.Error, ValueError) as err:
        raise ValueError(f'invalid base64url segment: {err}') from None


def _segment_json(segment: str) -> Tuple[Dict[str, Any], str, List[str]]:
    """
    Decode one segment into ``(obj, raw_text, notes)``.

    Failures never raise: a non-decodable or non-JSON segment yields an
    empty dict, the best-effort raw text, and a note explaining what went
    wrong ('invalid_json' / 'invalid_base64' / 'not_an_object').
    """
    notes: List[str] = []
    try:
        raw = _b64url_decode(segment).decode('utf-8', errors='replace')
    except ValueError as err:
        return {}, '', [f'invalid_base64: {err}']
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as err:
        return {}, raw, [f'invalid_json: segment is not valid JSON ({err})']
    if not isinstance(parsed, dict):
        return {}, raw, ['not_an_object: segment decoded to JSON, but not a JSON object']
    return parsed, raw, notes


def _epoch_to_iso(value: Any) -> Optional[str]:
    """Render a numeric epoch claim as a UTC ISO-8601 string (None if unparsable)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        stamp = datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return stamp.isoformat()


def _claim_analysis(name: str, payload: Dict[str, Any], now: float) -> Tuple[Dict[str, Any], List[str]]:
    """
    Analyse one time claim (iat/nbf/exp) into a summary dict plus notes.

    Booleans and non-numeric values produce a type-warning note instead of
    a crash; ``exp`` additionally reports ``expired`` and seconds-until.
    """
    summary: Dict[str, Any] = {'present': name in payload, 'raw': payload.get(name)}
    notes: List[str] = []
    value = payload.get(name)
    iso = _epoch_to_iso(value)
    summary['datetime'] = iso
    if not summary['present']:
        notes.append(f'missing {name} claim')
        return summary, notes
    if iso is None:
        notes.append(f'{name} claim is not a numeric epoch value ({value!r})')
        return summary, notes
    delta = float(value) - now
    summary['seconds_from_now'] = round(delta, 1)
    if name == 'exp':
        summary['expired'] = delta <= 0
        if summary['expired']:
            notes.append(f'token expired {abs(int(delta))} seconds ago')
        else:
            notes.append(f'token valid for another {int(delta)} seconds')
    elif name == 'nbf' and delta > 0:
        notes.append(f'not-before is {int(delta)} seconds in the future (token not yet valid)')
    elif name == 'iat' and delta > _FUTURE_TOLERANCE:
        notes.append(f'issued-at is {int(delta)} seconds in the future (clock skew or forgery)')
    return summary, notes


def _alg_analysis(header: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Classify the ``alg`` header claim into a family plus analyst notes."""
    alg = header.get('alg')
    analysis: Dict[str, Any] = {'value': alg}
    notes: List[str] = []
    if not isinstance(alg, str) or not alg:
        analysis['family'] = 'unknown'
        notes.append('alg header claim is missing - signature scheme unspecified')
        return analysis, notes
    lowered = alg.lower()
    if lowered == 'none':
        analysis['family'] = 'none'
        notes.append('CRITICAL: alg is "none" - the token is UNSIGNED; anyone can forge its payload')
    elif lowered.startswith('hs'):
        analysis['family'] = 'HMAC (symmetric)'
        notes.append(f'alg is {alg}: symmetric HMAC - offline verification is possible '
                     'IF the shared secret is known (try candidate secrets locally)')
    elif lowered.startswith(('rs', 'ps', 'es')) or lowered.startswith('eddsa'):
        analysis['family'] = 'asymmetric'
        notes.append(f'alg is {alg}: asymmetric signature - the issuer public key '
                     '(or x5c certificate chain) is required for verification')
    else:
        analysis['family'] = 'non-standard'
        notes.append(f'alg is {alg}: non-standard algorithm - inspect manually before trusting')
    return analysis, notes


def decode_jwt(token: str) -> Dict[str, Any]:
    """
    EXPERIMENTAL: split and decode a compact JWS token (no verification).

    Args:
        token: a JWT in compact serialization (``header.payload.signature``).

    Returns:
        ``{'header': dict, 'payload': dict, 'signature_hex': str,
        'signature_length': int, 'header_raw': str, 'payload_raw': str,
        'notes': [str]}`` - segments that fail to decode yield empty dicts
        plus explanatory notes. ``signature_hex`` previews the first 16
        bytes of the decoded signature.

    Raises:
        ValueError: when the token is not a string of three dot-separated
        parts (garbage in should fail loudly, not silently).
    """
    if not isinstance(token, str):
        raise ValueError(f'JWT must be a string, got {type(token).__name__}')
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError(f'JWT must have 3 dot-separated parts, got {len(parts)}')
    header, header_raw, header_notes = _segment_json(parts[0])
    payload, payload_raw, payload_notes = _segment_json(parts[1])
    notes = [f'header {note}' for note in header_notes]
    notes += [f'payload {note}' for note in payload_notes]
    signature_hex = ''
    signature_length = 0
    try:
        signature = _b64url_decode(parts[2])
    except ValueError as err:
        notes.append(f'signature {err}')
    else:
        signature_length = len(signature)
        preview = signature[:_SIGNATURE_PREVIEW_BYTES]
        signature_hex = preview.hex() + ('...' if len(signature) > len(preview) else '')
    return {
        'header': header,
        'payload': payload,
        'signature_hex': signature_hex,
        'signature_length': signature_length,
        'header_raw': header_raw,
        'payload_raw': payload_raw,
        'notes': notes,
    }


def inspect_jwt(token: str) -> Dict[str, Any]:
    """
    EXPERIMENTAL: fully inspect a JWT - decode, enrich, warn.

    Builds on :func:`decode_jwt` and adds the analysis an analyst actually
    wants before pasting a token into a report: human-readable claim
    datetimes with expiry verdicts, issuer/subject/audience/jti summary,
    algorithm risk analysis (``alg: none`` is flagged CRITICAL),
    key-material hints (``kid``, ``x5c`` chain, ``jku``/``x5u`` URLs -
    both classic key-confusion attack surfaces), and token size stats.

    Args:
        token: a JWT in compact serialization.

    Returns:
        Everything :func:`decode_jwt` returns plus ``claims``, ``alg``,
        ``identifiers``, ``key_info``, ``token_stats`` and an aggregated
        ``notes`` list (critical notes first). Malformed input returns
        ``{'error': ..., 'notes': [...]}`` instead of raising, so a typo'd
        token cannot crash a scan.
    """
    try:
        decoded = decode_jwt(token)
    except ValueError as err:
        return {'error': str(err), 'notes': [str(err)]}

    header = decoded['header']
    payload = decoded['payload']
    now = datetime.now(timezone.utc).timestamp()
    notes: List[str] = list(decoded['notes'])

    claims: Dict[str, Any] = {}
    for claim_name in ('iat', 'nbf', 'exp'):
        summary, claim_notes = _claim_analysis(claim_name, payload, now)
        claims[claim_name] = summary
        notes.extend(claim_notes)

    identifiers = {
        'iss': payload.get('iss'),
        'sub': payload.get('sub'),
        'aud': payload.get('aud'),
        'jti': payload.get('jti'),
    }
    alg, alg_notes = _alg_analysis(header)
    notes.extend(alg_notes)

    x5c = header.get('x5c')
    key_info: Dict[str, Any] = {
        'kid': header.get('kid') if isinstance(header.get('kid'), str) else None,
        'x5c_present': isinstance(x5c, list) and bool(x5c),
        'x5c_count': len(x5c) if isinstance(x5c, list) else 0,
        'jku': header.get('jku') if isinstance(header.get('jku'), str) else None,
        'x5u': header.get('x5u') if isinstance(header.get('x5u'), str) else None,
    }
    if key_info['jku'] or key_info['x5u']:
        notes.append('jku/x5u header URL present - the token tries to direct key fetches; '
                     'classic key-confusion/SSRF surface, fetch with care')
    if alg['family'] == 'asymmetric' and not key_info['x5c_present']:
        notes.append('asymmetric alg but no x5c chain embedded - the verification key '
                     'must be sourced out-of-band (JWKS endpoint, kid lookup)')

    if decoded['signature_length'] and decoded['signature_length'] < 16:
        notes.append(f'signature is only {decoded["signature_length"]} byte(s) - too short '
                     'for any standard JWT algorithm; treat the token as a test/sample artifact')
    if not payload:
        notes.append('payload is empty or undecodable - nothing to analyse beyond the header')
    elif len(payload) <= 1:
        notes.append('payload carries very few claims - minimal token (machine-to-machine '
                     'or forged placeholder)')

    token_stats = {
        'total_length': len(token.strip()),
        'header_length': len(token.strip().split('.')[0]),
        'payload_length': len(token.strip().split('.')[1]),
        'signature_length': decoded['signature_length'],
    }

    notes.append('claims are NOT verified - payload content is attacker-controlled '
                 'until the signature is checked with the real key material')

    result = dict(decoded)
    result['claims'] = claims
    result['alg'] = alg
    result['identifiers'] = identifiers
    result['key_info'] = key_info
    result['token_stats'] = token_stats
    result['notes'] = notes
    return result
