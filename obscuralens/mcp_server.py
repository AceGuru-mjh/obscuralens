"""
Model Context Protocol (MCP) server for ObscuraLens.

Exposes 40 ObscuraLens tools to AI assistants over stdio using
newline-delimited JSON-RPC 2.0 (one JSON object per line), which is the
transport MCP defines. This is deliberately *not* LSP Content-Length
framing.

Tool families:

* 14 target lookups - ip, phone, username, email, domain, url, crypto,
  hash, cve, asn and the v5.0 mac, iban, imei and coords kinds.
* 6 v6.0 sensor lookups - vin_lookup, flight_lookup, mmsi_lookup,
  app_lookup, bssid_lookup and plate_lookup.
* 6 investigation and history views - investigate, risk_report,
  correlate, timeline, tools_geo_profile and tools_patterns.
* 2 intel/health views - threat_intel and source_health.
* 2 watchlist actions - watch_list and watch_check.
* 10 v5.0 analyst toolbox tools - tools_encode, tools_decode, tools_jwt,
  tools_hash_id, tools_extract, tools_squat, tools_exif, tools_stego,
  tools_coords_convert and the 10-target-capped tools_batch.

Run it with::

    python -m obscuralens.mcp_server

Only JSON-RPC responses are written to stdout; diagnostics go to stderr, so
the stream stays machine-parsable.
"""

import json
import sys
from dataclasses import asdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__

_PROTOCOL_VERSION = '2024-11-05'

TOOLS: List[Dict[str, Any]] = [
    {
        'name': 'ip_lookup',
        'description': 'Look up geolocation, network and reputation data for '
                       'an IP address.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'IPv4 or IPv6 address.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'phone_lookup',
        'description': 'Parse a phone number and report its carrier, region '
                       'and type.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Phone number to look up.'},
                'region': {'type': 'string',
                           'description': 'Default region code used when the '
                                          'number has no country prefix '
                                          '(default: ID).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'username_lookup',
        'description': 'Scan public platforms for a username.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Username to scan for.'},
                'fast': {'type': 'boolean',
                         'description': 'Skip profile extraction on hits '
                                        '(default: false).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'email_lookup',
        'description': 'Look up an email address for domain, MX, breach and '
                       'reputation data.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Email address to look up.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'domain_lookup',
        'description': 'Look up registration, DNS, certificate transparency '
                       'and HTTP data for a domain.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Domain name to look up.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'investigate',
        'description': 'Auto-detect a target kind and optionally follow '
                       'bounded related pivots.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'IP / domain / email / phone / '
                                          'username to investigate.'},
                'pivot': {'type': 'boolean',
                          'description': 'Follow related targets '
                                         '(default: true).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'watch_list',
        'description': 'List every target currently on the watchlist.',
        'inputSchema': {
            'type': 'object',
            'properties': {},
            'additionalProperties': False,
        },
    },
    {
        'name': 'watch_check',
        'description': 'Run and diff watched targets, returning changes since '
                       'the previous check.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'identifier': {
                    'type': ['string', 'integer'],
                    'description': 'Watch id or target to check '
                                   '(default: all watched targets).',
                },
            },
            'additionalProperties': False,
        },
    },
    # -- v4.0 tools ------------------------------------------------------------
    {
        'name': 'url_lookup',
        'description': 'Analyze a URL: redirect chain, HTTP response, safety '
                       'verdicts and archive history.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string', 'description': 'http(s) URL.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'crypto_lookup',
        'description': 'Analyze a cryptocurrency address (btc/eth/xmr/doge/'
                       'ltc/xrp/ada): balances, totals and activity dates.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Cryptocurrency address.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'hash_lookup',
        'description': 'Look up a file hash across malware repositories '
                       'and reputation services.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'md5/sha1/sha256 file hash.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'cve_lookup',
        'description': 'Look up a CVE: description, CVSS, EPSS, references '
                       'and affected products.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'CVE identifier (CVE-YYYY-NNNN).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'asn_lookup',
        'description': 'Look up an autonomous system: holder, country, '
                       'announced prefixes and peers.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': ['string', 'integer'],
                           'description': 'AS number (AS15169 or 15169).'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'risk_report',
        'description': 'Run a lookup and attach explainable heuristic risk '
                       'scoring (score, verdict, signals).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'kind': {'type': 'string',
                         'enum': ['ip', 'phone', 'username', 'email', 'domain',
                                  'url', 'crypto', 'hash', 'cve', 'asn'],
                         'description': 'Target kind.'},
                'target': {'type': 'string', 'description': 'Target value.'},
            },
            'required': ['kind', 'target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'correlate',
        'description': 'Correlate two targets against stored history and '
                       'report shared infrastructure, or scan the whole '
                       'history for clusters.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'a': {'type': 'string', 'description': 'First target value.'},
                'b': {'type': 'string', 'description': 'Second target value.'},
                'all': {'type': 'boolean',
                        'description': 'Scan the whole history for clusters '
                                       'instead of comparing two targets.'},
            },
            'additionalProperties': False,
        },
    },
    {
        'name': 'timeline',
        'description': 'Build a chronological event timeline across stored '
                       'lookup history.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string',
                           'description': 'Restrict to one target (optional).'},
                'limit': {'type': 'integer',
                          'description': 'Maximum events (default: 100).'},
            },
            'additionalProperties': False,
        },
    },
    {
        'name': 'threat_intel',
        'description': 'Check an IP against Tor exit lists and blocklist '
                       'feeds (Spamhaus DROP, Feodo, FireHOL level-1).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string', 'description': 'IPv4 address.'},
            },
            'required': ['target'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'source_health',
        'description': 'Per-source reliability statistics and circuit-breaker '
                       'state across all lookups.',
        'inputSchema': {
            'type': 'object',
            'properties': {},
            'additionalProperties': False,
        },
    },
    # -- v5.0 tools ------------------------------------------------------------
    {
        'name': 'mac_lookup',
        'description': 'Look up a MAC address (EUI-48/64): vendor from the '
                       'IEEE OUI registry, locally-administered and multicast '
                       'flags, reserved blocks, virtual-NIC detection and '
                       'EUI-64/IPv6 hints. Keyless sources only.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'mac': {'type': 'string',
                        'description': 'MAC address in any common notation: '
                                       'colon, dash, Cisco dotted or bare hex.'},
            },
            'required': ['mac'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'iban_lookup',
        'description': 'Validate and dissect an International Bank Account '
                       'Number: ISO 13616 mod-97 verdict, country, expected '
                       'length and BBAN structure, bank code and account '
                       'slices. Offline arithmetic plus a keyless openiban '
                       'enrichment when reachable.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'iban': {'type': 'string',
                         'description': 'IBAN with or without spaces (e.g. '
                                        'DE89370400440532013000).'},
            },
            'required': ['iban'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'imei_lookup',
        'description': 'Validate and dissect an IMEI or IMEISV: Luhn check '
                       'with the expected check digit, TAC to manufacturer '
                       'and model via the offline pack, reporting body '
                       'identifier, serial and pretty formatting. Fully '
                       'offline (keyless, no network).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'imei': {'type': 'string',
                         'description': 'IMEI (15 digits) or IMEISV (16 '
                                        'digits), with or without dashes.'},
            },
            'required': ['imei'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'coords_lookup',
        'description': 'Look up a geographic position in any notation '
                       '(decimal degrees, DMS, UTM or MGRS): reverse geocode '
                       'to a place and address, elevation and gridded '
                       're-encodings. Keyless sources (Nominatim, '
                       'BigDataCloud, Open-Elevation) plus offline math.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'coords': {'type': 'string',
                           'description': 'Coordinates in decimal degrees, '
                                          'DMS, UTM or MGRS form.'},
            },
            'required': ['coords'],
            'additionalProperties': False,
        },
    },
    # -- v6.0 additions --------------------------------------------------------
    {
        'name': 'vin_lookup',
        'description': 'Decode a Vehicle Identification Number (ISO 3779): '
                       'check-digit verdict, World Manufacturer Identifier '
                       'with manufacturer and assembly country, model-year '
                       'candidates, plant code and production serial, plus '
                       'NHTSA vPIC make/model/body/engine details for North '
                       'American market vehicles. Offline decomposition plus '
                       'the keyless vPIC decoder.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'vin': {'type': 'string',
                        'description': '17-character VIN (letters and digits '
                                       'without I, O or Q), e.g. '
                                       '1M8GDM9AXKP042788; hyphens and '
                                       'lowercase are tolerated.'},
            },
            'required': ['vin'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'flight_lookup',
        'description': 'Decode a flight designator (IATA like BA2490 or ICAO '
                       'like DLH400A): airline name, country and callsign '
                       'from the offline IATA/ICAO pack, IATA/ICAO renderings '
                       'and the radio callsign, plus today\'s live status, '
                       'departure/arrival airports and aircraft registration '
                       'when an aviationstack API key is configured.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'flight': {'type': 'string',
                           'description': 'Flight designator: 2-letter IATA '
                                          'or 3-letter ICAO carrier code, '
                                          '1-4 digit flight number and an '
                                          'optional suffix letter.'},
            },
            'required': ['flight'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'mmsi_lookup',
        'description': 'Decode a Maritime Mobile Service Identity (ITU-R '
                       'M.1085): station class (ship, coast, group, handheld, '
                       'aid-to-navigation), Maritime Identification Digit, '
                       'serial digits and the flag country from the offline '
                       'MID pack. Fully offline (keyless, no network).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'mmsi': {'type': 'string',
                         'description': '9-digit MMSI, e.g. 366910000; a '
                                        '\"MMSI:\" marker and dash/space '
                                        'separators are tolerated.'},
            },
            'required': ['mmsi'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'app_lookup',
        'description': 'Software package intelligence for an '
                       '<ecosystem>:<name> coordinate: the registry record '
                       '(pypi.org, registry.npmjs.org, crates.io, Docker Hub '
                       'or api.github.com) with version, summary, author, '
                       'license, downloads and timestamps, offline ecosystem '
                       'metadata (registry URL, name rules, mirrors) and the '
                       'known CVEs from a keyless OSV.dev query. Only the '
                       'registry matching the ecosystem is contacted.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'app': {'type': 'string',
                        'description': 'Package coordinate such as '
                                       "'pypi:requests', 'npm:@babel/core', "
                                       "'crate:serde', 'docker:library/nginx' "
                                       "or 'github:psf/requests'; the "
                                       'ecosystem prefix is case-insensitive.'},
            },
            'required': ['app'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'bssid_lookup',
        'description': 'WiFi access point intelligence for a BSSID (EUI-48): '
                       'vendor from the offline IEEE OUI pack, '
                       'multicast/locally-administered bits (randomized MAC '
                       'detection), EUI-64 and IPv6 interface-id expansion, '
                       'and crowd-sourced geolocation (keyless mylnikov.org, '
                       'keyed WiGLE). Works offline thanks to the pack and '
                       'the bit math.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'bssid': {'type': 'string',
                          'description': '48-bit BSSID in colon, dash, Cisco '
                                         'dotted or bare hex notation, e.g. '
                                         '00:1A:2B:3C:4D:5E.'},
            },
            'required': ['bssid'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'plate_lookup',
        'description': 'License plate format intelligence: matches the plate '
                       'text against a curated pack of 79 national formats '
                       '(country prefix or loose pattern matching with a '
                       'confidence per candidate), resolves German '
                       'distinguishing-sign city codes and analyses the '
                       'letter/digit composition with an EU vs North American '
                       'style heuristic. Fully offline (keyless, no network).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'plate': {'type': 'string',
                          'description': 'Plate text, optionally prefixed with '
                                         "the issuing country: 'DE:B-AB 1234', "
                                         "'GB:AB12 CDE' or 'US-CA:8ABC123'."},
            },
            'required': ['plate'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_encode',
        'description': 'Encode text through every supported scheme at once '
                       '(hex, base32, base64, base85, URL percent, HTML '
                       'entities, ROT13, Caesar, binary, decimal, reversed, '
                       'Morse, gzip) and compute every standard digest (md5 '
                       'through blake2b plus crc32). Purely offline.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'text': {'type': 'string',
                         'description': 'The plaintext to encode and digest.'},
            },
            'required': ['text'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_decode',
        'description': 'Decode an encoded value: with an explicit scheme, '
                       'decode exactly that scheme; without one, try every '
                       'scheme and rank the best-scoring candidates. Purely '
                       'offline.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'value': {'type': 'string',
                          'description': 'The encoded string to decode.'},
                'scheme': {'type': 'string',
                           'description': 'Optional explicit scheme: hex, '
                                          'base32, base64, base85, '
                                          'url_percent, html_entity, rot13, '
                                          'caesar, binary, decimal, '
                                          'reversed, morse or gzip. Omit to '
                                          'auto-detect.'},
            },
            'required': ['value'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_jwt',
        'description': 'Inspect a JWT (compact serialization) without '
                       'verifying the signature: decoded header and payload, '
                       'human-readable claim times with expiry verdicts, '
                       'algorithm risk analysis and key-material hints. '
                       'Purely offline.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'token': {'type': 'string',
                          'description': 'JWT token string '
                                         '(header.payload.signature).'},
            },
            'required': ['token'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_hash_id',
        'description': 'Identify the likely algorithm of a hash-like string: '
                       'length, charset and prefix analysis over the md5/sha '
                       'families, bcrypt, Argon2, MySQL and base64 digests, '
                       'with confidence levels and same-length alternatives. '
                       'Purely offline.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'hash': {'type': 'string',
                         'description': 'The digest string to identify.'},
            },
            'required': ['hash'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_extract',
        'description': 'Extract every OSINT pivot target from arbitrary '
                       'text: emails, URLs, domains, IPv4/IPv6, ASN, MAC, '
                       'IBAN, IMEI, hashes, CVEs, crypto addresses, '
                       'coordinates, phone candidates, handles and tracking '
                       'ids, with per-kind counts. Purely offline.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'text': {'type': 'string',
                         'description': 'Text to scan (paste, email body, '
                                        'report excerpt).'},
            },
            'required': ['text'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_squat',
        'description': 'Generate typo and typosquatting variants of a domain '
                       'across 15 families (omission, insertion, homoglyph, '
                       'bitsquat, tld_swap, ...) and score each variant 0-100 '
                       'for deception risk. Offline; returns the 60 '
                       'highest-risk variants.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'domain': {'type': 'string',
                           'description': 'Domain (or URL) to defend, e.g. '
                                          'google.com.'},
                'min_risk': {'type': 'integer',
                             'description': 'Only return variants scoring at '
                                            'least this risk (0-100, '
                                            'default: 0).'},
            },
            'required': ['domain'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_exif',
        'description': 'Analyze the metadata of a local image file: EXIF, '
                       'GPS (decimal, DMS and a tracker-ready coords '
                       'string), camera summary, timeline hints, file hashes '
                       'and OSINT notes. Privacy: the file is read locally '
                       'and never uploaded anywhere.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'path': {'type': 'string',
                         'description': 'Path of a local image file (jpeg, '
                                        'png, gif, bmp or webp).'},
            },
            'required': ['path'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_stego',
        'description': 'Local steganography triage of an image file: LSB '
                       'plane scoring (PNG/BMP/GIF), entropy profiling, '
                       'embedded-file carving and trailing-data detection, '
                       'with a verdict and suspicion score. Privacy: the '
                       'file is read locally and never uploaded anywhere.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'path': {'type': 'string',
                         'description': 'Path of a local image file (png, '
                                        'bmp, gif or jpeg).'},
            },
            'required': ['path'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_coords_convert',
        'description': 'Convert coordinates between every supported format: '
                       'parses decimal degrees, DMS, UTM or MGRS input and '
                       'emits decimal degrees, DMS, DDM, geohash, Maidenhead, '
                       'UTM and MGRS notations plus a timezone hint. Purely '
                       'offline.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'value': {'type': 'string',
                          'description': 'Coordinates in decimal degrees, DMS, '
                                         'UTM or MGRS form (e.g. 48.8584, '
                                         '2.2945 or 31U DQ 48288 11087).'},
            },
            'required': ['value'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_geo_profile',
        'description': 'Summarize the geographic footprint of the stored '
                       'lookup history: distinct countries, top country and '
                       'region, coordinate activity, geohash clusters, time '
                       'span and the top-10 country histogram. Reads the '
                       'local database only.',
        'inputSchema': {
            'type': 'object',
            'properties': {},
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_patterns',
        'description': 'Pattern-of-life report for one repeatedly looked-up '
                       'target from stored history: cadence, burstiness, '
                       'hour-of-day and weekday profile. Reads local history '
                       'only.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'kind': {'type': 'string',
                         'description': 'Target kind as stored in history, '
                                        'e.g. ip, domain, email or coords.'},
                'value': {'type': 'string',
                          'description': 'Target value as stored in history.'},
            },
            'required': ['kind', 'value'],
            'additionalProperties': False,
        },
    },
    {
        'name': 'tools_batch',
        'description': 'Run one lookup kind across multiple targets with the '
                       'batch engine. MCP safety caps the run at 10 targets; '
                       'returns a summary plus one status line per target. '
                       'Uses the same keyless/keyed sources as single '
                       'lookups.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'kind': {'type': 'string',
                         'description': 'Target kind (ip, domain, mac, iban, '
                                        'coords, ...).'},
                'targets': {
                    'type': 'array',
                    'items': {'type': 'string'},
                    'description': 'Targets to look up (max 10; extras are '
                                   'dropped and reported).',
                },
                'risk': {'type': 'boolean',
                         'description': 'Attach heuristic risk scoring to '
                                        'each result (default: false).'},
            },
            'required': ['kind', 'targets'],
            'additionalProperties': False,
        },
    },
]


def _target(arguments: Dict[str, Any]) -> str:
    """Return the required ``target`` argument or raise ValueError."""
    target = arguments.get('target')
    if not isinstance(target, str) or not target.strip():
        raise ValueError('target is required')
    return target


def _identifier(value: Any) -> Any:
    """Coerce a numeric watch identifier string to int (CLI convention)."""
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


class _ToolError(Exception):
    """
    Tool-level error whose message reaches the client verbatim.

    The JSON-RPC loop reports unexpected exceptions as
    ``'TypeName: message'`` error results. Raising this subclass instead
    keeps optional-module messages clean (for example ``'module not
    available in this build'``) while still marking the response with
    ``isError: true``.
    """


def _required_str(arguments: Dict[str, Any], key: str) -> str:
    """
    Return a required non-blank string argument or raise ValueError.

    Mirrors :func:`_target` for the v5.0/v6.0 tools whose primary argument
    is not called ``target`` (``mac``, ``iban``, ``imei``, ``coords``,
    ``vin``, ``flight``, ``mmsi``, ``text``, ``value``, ``token``,
    ``hash``, ``domain``, ``path`` or ``kind``).
    """
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{key} is required')
    return value


def call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatch one MCP tool call to the matching ObscuraLens function.

    Trackers are imported lazily so this module can be imported cheaply and
    tests can monkeypatch the tracker classes; every v5.0 handler below
    follows the same lazy-import convention. The v5.0 tools are dispatched
    through the ``_HANDLERS`` registry after the built-in branches above.
    Raises ValueError for an unknown tool; callers translate that into an
    ``isError`` result.
    """
    arguments = arguments or {}
    if name == 'ip_lookup':
        from .trackers import IPTracker
        return IPTracker().track(_target(arguments))
    if name == 'phone_lookup':
        from .trackers import PhoneTracker
        region = arguments.get('region') or 'ID'
        return PhoneTracker().track(_target(arguments), default_region=region)
    if name == 'username_lookup':
        from .trackers import UsernameTracker
        deep = not bool(arguments.get('fast'))
        return UsernameTracker().track(_target(arguments), deep=deep)
    if name == 'email_lookup':
        from .trackers import EmailTracker
        return EmailTracker().track(_target(arguments))
    if name == 'domain_lookup':
        from .trackers import DomainTracker
        return DomainTracker().track(_target(arguments))
    if name == 'investigate':
        from .investigate import investigate
        pivot = bool(arguments.get('pivot', True))
        return investigate(_target(arguments), pivot=pivot)
    if name == 'url_lookup':
        from .trackers import URLTracker
        return URLTracker().track(_target(arguments))
    if name == 'crypto_lookup':
        from .trackers import CryptoTracker
        return CryptoTracker().track(_target(arguments))
    if name == 'hash_lookup':
        from .trackers import HashTracker
        return HashTracker().track(_target(arguments))
    if name == 'cve_lookup':
        from .trackers import CVETracker
        return CVETracker().track(_target(arguments))
    if name == 'asn_lookup':
        from .trackers import ASNTracker
        return ASNTracker().track(str(arguments.get('target', '')))
    if name == 'risk_report':
        from .correlation import attach_risk
        from .trackers import (
            ASNTracker,
            CryptoTracker,
            CVETracker,
            DomainTracker,
            EmailTracker,
            HashTracker,
            IPTracker,
            PhoneTracker,
            URLTracker,
            UsernameTracker,
        )
        kind = arguments.get('kind')
        tracker_classes = {
            'ip': IPTracker, 'phone': PhoneTracker,
            'username': UsernameTracker, 'email': EmailTracker,
            'domain': DomainTracker, 'url': URLTracker,
            'crypto': CryptoTracker, 'hash': HashTracker,
            'cve': CVETracker, 'asn': ASNTracker,
        }
        if kind not in tracker_classes:
            raise ValueError(f'unknown kind: {kind}')
        result = tracker_classes[kind]().track(_target(arguments))
        attach_risk(str(kind), result)
        return result
    if name == 'correlate':
        from .correlation import build_graph, correlate, history_records
        if arguments.get('all'):
            records = history_records(
                limit=arguments.get('limit') or None)
            return build_graph(records)
        a = arguments.get('a')
        b = arguments.get('b')
        if not a or not b:
            raise ValueError('correlate needs both a and b, or all=true')
        return correlate(str(a), str(b))
    if name == 'timeline':
        from .correlation import build_timeline, history_records
        limit = arguments.get('limit') or 100
        records = history_records(limit=max(int(limit) * 3, 200))
        target = arguments.get('target')
        if target:
            needle = str(target).lower()
            records = [r for r in records
                       if needle in str(r.get('value', '')).lower()]
        return build_timeline(records, cap=int(limit))
    if name == 'threat_intel':
        from .intel import feeds as intel_feeds
        from .intel import tor as intel_tor
        target = _target(arguments)
        return {
            'ip': target,
            'feeds': intel_feeds.check_ip(target),
            'tor_exit': intel_tor.is_tor_exit(target),
            'relay': intel_tor.relay_details(target),
        }
    if name == 'source_health':
        from .health import health
        return {'sources': health.get_health()}
    if name == 'watch_list':
        from .watchlist import watchlist
        return {'entries': [asdict(entry) for entry in watchlist.list()]}
    if name == 'watch_check':
        from .watchlist import watchlist
        identifier = _identifier(arguments.get('identifier'))
        return {'diffs': [asdict(diff) for diff in watchlist.check(identifier)]}
    handler = _HANDLERS.get(name)
    if handler is not None:
        return handler(arguments)
    raise ValueError(f'unknown tool: {name}')


# ---------------------------------------------------------------------------
# v5.0 tools: handlers registered in _HANDLERS and dispatched by call_tool
# ---------------------------------------------------------------------------

#: MCP safety cap for ``tools_batch``: one call runs at most this many
#: lookups, so a single client request can never keep every source busy
#: for minutes.
_MAX_BATCH_TARGETS = 10

#: How many auto-detected candidates ``tools_decode`` reports (decode_auto
#: scores and sorts every scheme's attempt; only the best survive here).
_MAX_DECODE_CANDIDATES = 6

#: How many typosquat variants ``tools_squat`` returns (highest risk first).
_MAX_SQUAT_VARIANTS = 60


def _compact_tracker_result(result: Dict[str, Any], key: str) -> Dict[str, Any]:
    """
    Compact one tracker report for an MCP response.

    Keeps the merged ``info`` fields, per-source status and the standard
    verdict keys, but replaces the full ``field_sources`` provenance map
    with per-field confirmation counts (how many sources supplied each
    field) so the JSON payload stays small.
    """
    counts: Dict[str, int] = {}
    for field, sources in (result.get('field_sources') or {}).items():
        if isinstance(sources, (list, tuple)):
            counts[field] = len(sources)
    return {
        key: result.get(key, ''),
        'info': result.get('info', {}),
        'sources_ok': result.get('sources_ok', []),
        'sources_failed': result.get('sources_failed', {}),
        'provenance_counts': counts,
        'field_count': result.get('field_count', 0),
        'success': result.get('success', False),
        'errors': result.get('errors', []),
    }


def _tool_mac_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vendor and bit-level anatomy of a MAC address (EUI-48/EUI-64).

    Input: ``mac`` - any common notation (``'B8:27:EB:AA:BB:CC'``,
    ``'b8-27-eb-aa-bb-cc'``, Cisco dotted ``'b827.ebdc.aabb'`` or bare hex).

    Output: compact tracker report - canonical ``mac``, merged ``info``
    fields (vendor, assignment block, locally-administered / multicast
    flags, reserved blocks, virtual-NIC detection, EUI-64 and IPv6 hints),
    ``sources_ok`` / ``sources_failed``, per-field provenance counts and
    the standard verdict keys. Invalid identifiers return
    ``success=False`` without touching the network or history.

    Sources: keyless only - offline IEEE OUI pack, macvendors.com and
    maclookup.app; the offline sources keep the lookup useful with the
    network down.
    """
    from .trackers import MACTracker
    result = MACTracker().track(_required_str(arguments, 'mac'))
    return _compact_tracker_result(result, 'mac')


def _tool_iban_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and dissect an International Bank Account Number.

    Input: ``iban`` - IBAN with or without spaces (e.g.
    ``'DE89370400440532013000'``); the mod-97 checksum decides validity.

    Output: compact tracker report - canonical ``iban``, merged ``info``
    fields (mod-97 verdict, country, expected length and BBAN structure
    verdict, bank code / account slices, bank name and BIC when the
    enrichment answers), source status and provenance counts. Identifiers
    failing the checksum return ``success=False`` before any network
    traffic or history write.

    Sources: offline mod-97 + country structure pack (always available)
    plus the keyless openiban API - no API keys are used.
    """
    from .trackers import IBANTracker
    result = IBANTracker().track(_required_str(arguments, 'iban'))
    return _compact_tracker_result(result, 'iban')


def _tool_imei_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and dissect an IMEI or IMEISV identifier.

    Input: ``imei`` - 15-digit IMEI or 16-digit IMEISV, with or without
    dashes/spaces; the Luhn check digit decides validity.

    Output: compact tracker report - canonical ``imei``, merged ``info``
    fields (TAC-derived manufacturer and model, reporting body identifier,
    serial, check-digit verdict with the expected digit on failure, pretty
    AA-BBBBBB-CCCCCC-D form), source status and provenance counts. Invalid
    identifiers return ``success=False`` without network or history.

    Sources: fully offline (3GPP TS 23.003 decomposition + curated TAC
    pack) - no network, no keys.
    """
    from .trackers import IMEITracker
    result = IMEITracker().track(_required_str(arguments, 'imei'))
    return _compact_tracker_result(result, 'imei')


def _tool_coords_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Place intelligence for a geographic position in any notation.

    Input: ``coords`` - decimal degrees (``'48.8584, 2.2945'``), DMS, UTM
    (``'31U 448288 5411087'``) or MGRS (``'31U DQ 48288 11087'``).

    Output: compact tracker report whose ``info`` carries latitude,
    longitude, geohash, mgrs, utm, the reverse-geocoded place
    (``formatted_address`` with city / region / country), elevation and
    solar geometry; ``latitude``, ``longitude``, ``geohash``, ``mgrs``,
    ``utm`` and ``place`` are additionally lifted to the top level for
    convenience. Unparseable input returns ``success=False`` without
    touching the network.

    Sources: keyless - Nominatim, BigDataCloud and Open-Elevation plus the
    offline ``geohash_local`` math source (which always succeeds, so a
    report still carries the coordinates themselves when offline).
    """
    from .trackers import CoordsTracker
    result = CoordsTracker().track(_required_str(arguments, 'coords'))
    compact = _compact_tracker_result(result, 'coords')
    info = result.get('info') or {}
    for top_key, info_key in (('latitude', 'latitude'),
                              ('longitude', 'longitude'),
                              ('geohash', 'geohash'), ('mgrs', 'mgrs'),
                              ('utm', 'utm'), ('place', 'formatted_address')):
        compact[top_key] = info.get(info_key)
    return compact


# ---------------------------------------------------------------------------
# v6.0 additions: vin / flight / mmsi / app / bssid / plate lookup handlers
# ---------------------------------------------------------------------------

def _tool_vin_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vehicle intelligence for a VIN (ISO 3779 / NHTSA vPIC).

    Input: ``vin`` - 17-character Vehicle Identification Number; hyphens,
    spaces and lowercase are tolerated (``'1M8-GDM9-A-XKP042788'`` works).

    Output: compact tracker report - canonical ``vin``, merged ``info``
    fields (WMI, manufacturer and assembly country from the offline ISO
    3780 pack, transliterated check-digit verdict with the expected digit
    on failure, model-year candidates from the 30-year code cycle, plant
    code, production serial, and vPIC make / model / body class / engine /
    plant details for North American market vehicles), ``sources_ok`` /
    ``sources_failed``, per-field provenance counts and the standard
    verdict keys. Identifiers failing the check digit return
    ``success=False`` before any network traffic or history write.

    Sources: offline ISO 3779 decomposition (always available) plus the
    keyless NHTSA vPIC decoder - no API keys are used.
    """
    from .trackers import VINTracker
    result = VINTracker().track(_required_str(arguments, 'vin'))
    return _compact_tracker_result(result, 'vin')


def _tool_flight_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Airline and live-status intelligence for a flight designator.

    Input: ``flight`` - designator such as ``'UA1'``, ``'BA2490'`` or
    ``'DLH400A'`` (2-letter IATA or 3-letter ICAO carrier code, 1-4 digit
    flight number, optional single suffix letter).

    Output: compact tracker report - canonical ``flight``, merged ``info``
    fields (airline name, country and callsign from the offline IATA/ICAO
    pack, carrier-code type, IATA/ICAO renderings, radio callsign,
    direction and number-band convention notes, plus today's live status,
    departure/arrival airports and aircraft registration when an
    aviationstack key is configured), source status and provenance
    counts. The offline sources always answer, so the report works with
    the network down.

    Sources: offline airline pack + designator anatomy (always available)
    plus aviationstack.com live status when the OBSCURALENS_
    AVIATIONSTACK_API_KEY is configured.
    """
    from .trackers import FlightTracker
    result = FlightTracker().track(_required_str(arguments, 'flight'))
    return _compact_tracker_result(result, 'flight')


def _tool_mmsi_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maritime identity anatomy for an MMSI (ITU-R M.1085).

    Input: ``mmsi`` - nine-digit Maritime Mobile Service Identity; a
    ``'MMSI:'`` marker and dash/space separators are tolerated
    (``'366-910-000'`` normalises to ``'366910000'``).

    Output: compact tracker report - canonical ``mmsi``, merged ``info``
    fields (station class from the leading digits - ship, coast, group,
    handheld, aid-to-navigation or reserved - Maritime Identification
    Digit, station serial digits, ITU series label and the flag country
    from the offline MID pack), source status and provenance counts.
    Shape failures return ``success=False`` without network or history.

    Sources: fully offline (ITU-R M.1085 structure decode + curated MID
    pack) - no network, no keys.
    """
    from .trackers import MMSITracker
    result = MMSITracker().track(_required_str(arguments, 'mmsi'))
    return _compact_tracker_result(result, 'mmsi')


def _tool_app_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Software package intelligence for an <ecosystem>:<name> coordinate.

    Input: ``app`` - a package coordinate such as ``'pypi:requests'``,
                                       "'crate:serde', 'docker:library/nginx' "
                                       "or 'github:psf/requests'; the "
    case-insensitive and the name grammar is validated per ecosystem.

    Output: compact tracker report - canonical ``app``, merged ``info``
    fields (offline ecosystem metadata: label, registry URL, namespace,
    package name, name conventions, mirror notes; the registry record:
    version, summary, description, author, license, homepage, downloads,
    stars, timestamps; and the OSV.dev vulnerability count with per-CVE
    id/summary/severity records for pypi/npm/crates.io), ``sources_ok`` /
    ``sources_failed``, per-field provenance counts and the standard
    verdict keys. Only the registry matching the ecosystem is queried;
    malformed coordinates return ``success=False`` without network or
    history writes.

    Sources: offline ecosystem metadata (always available) plus the one
    keyless registry reader matching the ecosystem and the keyless
    OSV.dev query - no API keys are used.
    """
    from .trackers import AppTracker
    result = AppTracker().track(_required_str(arguments, 'app'))
    return _compact_tracker_result(result, 'app')


def _tool_bssid_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    WiFi access point intelligence for a BSSID (EUI-48).

    Input: ``bssid`` - 48-bit access point address in colon
    (``'00:1A:2B:3C:4D:5E'``), dash, Cisco dotted (``'001a.2b3c.4d5e'``)
    or bare hex notation; lower case is tolerated.

    Output: compact tracker report - canonical ``bssid``, merged ``info``
    fields (vendor and OUI prefix from the offline curated IEEE pack,
    multicast / locally-administered bits with their transmission and
    assignment classes, EUI-64 expansion, modified-EUI-64 IPv6 interface
    identifier and link-local hint, randomization hint when the local bit
    is set, plus crowd-sourced latitude / longitude / accuracy range and
    the WiGLE SSID / encryption / last-seen record when a key is
    configured), source status and provenance counts. Malformed
    identifiers return ``success=False`` without network or history.

    Sources: offline OUI pack + EUI-48 bit decomposition (always
    available) plus keyless api.mylnikov.org geolocation and keyed
    WiGLE.net network search.
    """
    from .trackers import BSSIDTracker
    result = BSSIDTracker().track(_required_str(arguments, 'bssid'))
    return _compact_tracker_result(result, 'bssid')


def _tool_plate_lookup(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    License plate format intelligence (fully offline).

    Input: ``plate`` - plate text, optionally prefixed with the issuing
                                         "'GB:AB12 CDE' or 'US-CA:8ABC123'."},
    lower case and doubled spaces are tolerated.

    Output: compact tracker report - canonical ``plate``, merged ``info``
    fields (the matched-country candidate list with region, example and
    confidence per candidate; the parsed country prefix and whether the
    curated pack knows it; the composition analysis with letter/digit
    counts and separators; the German city code when a ``DE:`` plate's
    leading token resolves; and the EU-style vs North-American-style
    heuristic), source status and provenance counts. Malformed values
    return ``success=False`` without network or history.

    Sources: fully offline - the curated plate format pack (79 national
    formats) plus pure-Python composition analysis. National owner
    registries are deliberately not queried (they are paywalled and
    lawful-purpose gated everywhere).
    """
    from .trackers import PlateTracker
    result = PlateTracker().track(_required_str(arguments, 'plate'))
    return _compact_tracker_result(result, 'plate')


def _tool_encode(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Every encoding and every digest of a text, in one call.

    Input: ``text`` - the plaintext to transform.

    Output: ``{'text': echo, 'encodings': {scheme: value}, 'hashes':
    {algorithm: digest}}``. Encodings cover hex, base32, base64, base85,
    URL percent, HTML entities, ROT13, Caesar, binary, decimal, reversed,
    Morse and gzip; hashes cover md5, the sha1/sha2/sha3 families,
    blake2s/b and crc32. Schemes that cannot encode the input are silently
    skipped, so ``encodings`` may be partial - never a failure.

    Purely offline: nothing is transmitted anywhere.
    """
    from .experimental.encoders import encode_all, hash_all
    text = _required_str(arguments, 'text')
    return {'text': text, 'encodings': encode_all(text), 'hashes': hash_all(text)}


def _tool_decode(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decode an encoded value - one explicit scheme or ranked auto-detection.

    Input: ``value`` - the encoded string; optional ``scheme`` - one of the
    ``encoders.SCHEMES`` names (hex, base32, base64, base85, url_percent,
    html_entity, rot13, caesar, binary, decimal, reversed, morse, gzip).

    Output: with ``scheme``, ``{'value', 'scheme', 'decoded'}`` - a
    ValueError-style tool error surfaces when that scheme cannot decode
    the value. Without, ``{'value', 'candidates': [...]}`` with the
    top-ranked ``{'scheme', 'result', 'score', 'note'}`` entries from
    ``decode_auto`` (best first, capped at 6, notes flag no-op decodes).

    Purely offline.
    """
    from .experimental.encoders import SCHEMES, decode_auto
    value = _required_str(arguments, 'value')
    scheme = arguments.get('scheme')
    if scheme is not None:
        name = str(scheme).strip().lower()
        if name not in SCHEMES:
            available = ', '.join(sorted(SCHEMES))
            raise ValueError(f'unknown scheme: {name!r}; available: {available}')
        return {'value': value, 'scheme': name,
                'decoded': SCHEMES[name]['decode'](value)}
    candidates = decode_auto(value)[:_MAX_DECODE_CANDIDATES]
    return {'value': value, 'candidates': candidates}


def _tool_jwt(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inspect a JWT without verifying its signature.

    Input: ``token`` - a JWT in compact serialization
    (``header.payload.signature``).

    Output: decoded ``header`` and ``payload``, ``alg`` risk analysis
    (``alg: none`` is flagged critical), human-readable ``claims`` with
    expiry verdicts, ``identifiers`` (iss / sub / aud / jti), ``key_info``
    (kid / x5c / jku / x5u attack-surface hints), ``token_stats`` and an
    aggregated ``notes`` list (critical first). Malformed tokens return
    ``{'error': ..., 'notes': [...]}`` instead of raising.

    Purely offline. The payload is attacker-controlled until the signature
    is verified with real key material - the notes say so explicitly.
    """
    from .experimental.jwt_tools import inspect_jwt
    result = inspect_jwt(_required_str(arguments, 'token'))
    if 'error' in result:
        return {'error': result['error'], 'notes': result.get('notes', [])}
    return {
        'header': result.get('header', {}),
        'payload': result.get('payload', {}),
        'alg': result.get('alg'),
        'claims': result.get('claims', {}),
        'identifiers': result.get('identifiers', {}),
        'key_info': result.get('key_info', {}),
        'token_stats': result.get('token_stats', {}),
        'notes': result.get('notes', []),
    }


def _tool_hash_id(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Identify the likely algorithm behind a hash-like string.

    Input: ``hash`` - the digest string (hex, base64-armored, bcrypt or
    Argon2 PHC form; a leading ``0x`` is tolerated).

    Output: ``{'hash': echo, 'candidates': [...]}`` where each candidate
    is ``{'name', 'confidence', 'length', 'charset', 'note'}`` sorted
    high-to-low. Same-length alternatives (Keccak-256 vs sha256, for
    example) are all listed with explanatory notes; unrecognised shapes
    return a single low-confidence 'Unknown' entry.

    Purely offline structural analysis - no hash database is consulted
    (pair the result with ``hash_lookup`` for reputation data).
    """
    from .experimental.hash_identify import identify_hash
    value = _required_str(arguments, 'hash')
    return {'hash': value, 'candidates': identify_hash(value)}


def _tool_extract(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract every OSINT pivot target from arbitrary text.

    Input: ``text`` - the text to scan (email body, paste, dump, report
    excerpt).

    Output: ``{'text_length', 'entities': {kind: [values]}, 'summary'}``.
    Strong kinds (emails, urls, domains, ipv4, ipv6, asn, macs, ibans,
    imeis, hashes, cves, crypto_addresses, coords) are validator-confirmed;
    weak kinds (phone_candidates, user_handles, tracking_ids) are leads to
    verify. ``summary`` counts entities per kind plus a grand total.

    Purely offline.
    """
    from .experimental.entity_extract import extract_entities, summarize_entities
    text = _required_str(arguments, 'text')
    entities = extract_entities(text)
    return {
        'text_length': len(text),
        'entities': entities,
        'summary': summarize_entities(entities),
    }


def _tool_squat(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Typosquatting variants of a domain, scored for deception risk.

    Input: ``domain`` - the domain (or URL) to defend; optional
    ``min_risk`` - only return variants scoring at least this risk
    (0-100, default 0).

    Output: ``{'domain', 'total_variants', 'returned', 'min_risk',
    'variants': [...]}`` where each variant is ``{'domain', 'category',
    'description', 'risk'}`` sorted by risk descending, capped at the 60
    most dangerous entries.

    Purely offline: variants are generated (15 families - omission,
    insertion, substitution, transposition, duplication, hyphenation,
    subdomain, vowel_swap, plural, singular, bitsquat, homoglyph,
    ascii_similarity, tld_swap, combo_squat) and scored with an explainable
    distance + category rubric. No DNS or registration data is fetched;
    feed interesting variants to ``domain_lookup`` for live checks.
    """
    from .experimental.squatting import generate_variants, score_variants
    domain = _required_str(arguments, 'domain')
    raw_risk = arguments.get('min_risk')
    if raw_risk is None:
        min_risk = 0
    elif isinstance(raw_risk, bool) or not isinstance(raw_risk, (int, float)):
        raise ValueError('min_risk must be an integer between 0 and 100')
    else:
        min_risk = max(0, min(100, int(raw_risk)))
    scored = score_variants(generate_variants(domain), domain)
    selected = [v for v in scored if v.get('risk', 0) >= min_risk]
    selected = selected[:_MAX_SQUAT_VARIANTS]
    return {
        'domain': domain,
        'total_variants': len(scored),
        'returned': len(selected),
        'min_risk': min_risk,
        'variants': selected,
    }


def _tool_exif(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Metadata triage of a local image file (EXIF, GPS, camera, timeline).

    Input: ``path`` - path of a local image file (jpeg, png, gif, bmp or
    webp) readable by this process.

    Output: the full ``exif_reader.analyze`` report - container metadata,
    friendly EXIF, GPS as decimal + DMS + a tracker-ready ``'lat, lon'``
    coords string, a camera summary, timeline hints, interesting strings,
    file hashes and actionable ``osint_notes``. Missing or unreadable
    files return ``{'error': ...}`` instead of raising.

    Privacy: analysis is local-only - the file is read from disk and
    nothing ever leaves the machine.
    """
    from .experimental.exif_reader import analyze
    path = _required_str(arguments, 'path')
    result = analyze(path)
    result['path'] = path
    return result


def _tool_stego(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Local steganography triage of an image file.

    Input: ``path`` - path of a local image file (png, bmp, gif or jpeg).

    Output: the full ``steganography.analyze`` report - ``summary`` with a
    0-100 suspicion score, verdict and findings; ``lsb`` plane analysis
    (PNG / BMP / GIF; JPEG gets entropy + carving only, with a note that
    DCT-domain stego is out of scope), ``entropy`` profiling,
    ``embedded_files`` carving and trailing-data detection. Missing files
    return ``{'error': ..., 'summary': ...}`` instead of raising.

    Privacy: analysis is local-only - the file is read from disk and
    nothing ever leaves the machine.
    """
    from .experimental.steganography import analyze
    path = _required_str(arguments, 'path')
    result = analyze(path)
    result['path'] = path
    return result


def _tool_coords_convert(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert coordinates between every supported notation.

    Input: ``value`` - coordinates in decimal degrees (``'48.8584,
    2.2945'``), DMS, UTM (``'31U 448288 5411087'``) or MGRS (``'31U DQ
    48288 11087'``) form.

    Output: ``latitude`` / ``longitude`` (6-decimal precision) plus the
    ``decimal`` pair, ``latitude_dms`` / ``longitude_dms``, ``ddm``
    (degrees + decimal minutes), ``geohash`` (9 chars), ``maidenhead``
    locator, ``utm`` string with ``utm_parts`` (zone / band / easting /
    northing), ``mgrs``, ``hemisphere`` and a solar ``utc_offset_hint``.
    Outside the UTM latitude range (-80..84) the grid fields are null with
    an explanatory ``utm_note``. Unparseable input raises a
    ValueError-style tool error.

    Purely offline coordinate maths - no reverse geocoding happens here
    (use ``coords_lookup`` for place intelligence).
    """
    from .utils import coordinate_math
    from .utils.validators import parse_coords
    value = _required_str(arguments, 'value')
    try:
        parsed = parse_coords(value)
    except ValueError as exc:
        raise ValueError(f'could not parse coordinates: {exc}') from exc
    if parsed is None:
        raise ValueError('could not parse coordinates: expected decimal '
                         'degrees, DMS, UTM or MGRS form')
    lat, lon = parsed
    result: Dict[str, Any] = {
        'value': value,
        'latitude': round(lat, 6),
        'longitude': round(lon, 6),
        'decimal': f"{lat:.6f}, {lon:.6f}",
        'latitude_dms': coordinate_math.latlon_to_dms(lat, 'lat'),
        'longitude_dms': coordinate_math.latlon_to_dms(lon, 'lon'),
        'ddm': coordinate_math.latlon_to_ddm(lat, lon),
        'geohash': coordinate_math.latlon_to_geohash(lat, lon, 9),
        'maidenhead': coordinate_math.latlon_to_maidenhead(lat, lon, 3),
        'hemisphere': 'northern' if lat >= 0.0 else 'southern',
        'utc_offset_hint': coordinate_math.estimate_timezone_offset(lon),
    }
    try:
        zone, band, easting, northing = coordinate_math.latlon_to_utm(lat, lon)
        result['utm'] = f"{zone}{band} {easting:.0f} {northing:.0f}"
        result['utm_parts'] = {
            'zone': zone, 'band': band,
            'easting': round(easting, 1), 'northing': round(northing, 1),
        }
        result['mgrs'] = coordinate_math.latlon_to_mgrs(lat, lon, 5)
    except ValueError:
        result['utm'] = None
        result['utm_parts'] = None
        result['mgrs'] = None
        result['utm_note'] = 'latitude outside the UTM grid range (-80..84)'
    return result


def _tool_geo_profile(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Geographic footprint summary of the stored lookup history.

    Input: none - the tool takes no arguments and analyses whatever lookup
    history this ObscuraLens instance has accumulated.

    Output: ``profile`` - the one-call analyst summary
    (``distinct_countries``, ``top_country``, ``top_region``,
    ``coords_lookups``, ``geohash_clusters``, ``span_days``) - plus
    ``top_countries`` (the ten largest country histogram entries with
    sample targets), ``total_geo_tagged``, ``total_records`` and
    ``unknown`` counts.

    Reads the local query-history database only - no network, no keys.
    """
    try:
        from .advanced.geospatial import country_breakdown, geo_profile_summary
    except ImportError as exc:
        raise _ToolError('module not available in this build') from exc
    profile = geo_profile_summary()
    breakdown = country_breakdown()
    return {
        'profile': profile,
        'top_countries': breakdown.get('countries', [])[:10],
        'total_geo_tagged': breakdown.get('total_geo_tagged', 0),
        'total_records': breakdown.get('total_records', 0),
        'unknown': breakdown.get('unknown', 0),
    }


def _call_flexible(func: Any, *args: Any, **kwargs: Any) -> Any:
    """
    Call ``func`` with ``kwargs`` filtered to the parameters it declares.

    The ``advanced`` engines are built in parallel work waves, so their
    keyword names may drift while this server is written. When every
    keyword name exists in the signature the call is made by keyword;
    otherwise the arguments are passed positionally in ``args`` order. A
    TypeError raised inside ``func`` is therefore never masked by a
    redundant retry - only the binding strategy changes.
    """
    import inspect
    try:
        parameters = inspect.signature(func).parameters
    except (TypeError, ValueError):
        return func(*args)
    if all(name in parameters for name in kwargs):
        return func(**kwargs)
    return func(*args)


def _tool_patterns(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pattern-of-life report for one repeatedly looked-up target.

    Input: ``kind`` - the target kind as stored in history (ip, domain,
    email, coords, ...); ``value`` - the target value as stored in history
    (normalised forms such as lowercase domains or ``'lat, lon'`` pairs).

    Output: ``{'kind', 'value', 'report'}`` where ``report`` is the
    pattern_report dict produced from the stored history - lookup counts,
    cadence, burstiness and the hour-of-day / weekday activity profile.

    Reads the local query history only - no network, no keys.
    """
    try:
        from .advanced.patterns import pattern_report
    except ImportError as exc:
        raise _ToolError('module not available in this build') from exc
    kind = _required_str(arguments, 'kind')
    value = _required_str(arguments, 'value')
    report = _call_flexible(pattern_report, kind, value, kind=kind, value=value)
    return {'kind': kind, 'value': value, 'report': report}


def _batch_entries(raw: Any) -> List[Any]:
    """
    Normalise a ``run_batch`` return value into per-target entries.

    Accepts the documented list-of-results shape, a dict wrapping its
    results under ``results`` / ``entries`` / ``items``, or any single
    value, so the tool keeps working if the batch engine's envelope
    evolves.
    """
    if isinstance(raw, dict):
        for key in ('results', 'entries', 'items'):
            inner = raw.get(key)
            if isinstance(inner, list):
                return inner
        return [raw]
    if isinstance(raw, (list, tuple)):
        return list(raw)
    return [raw]


def _batch_status(entry: Any) -> Tuple[str, bool]:
    """
    One-line status and success flag for a single batch entry.

    Handles both the ``{'target', 'result': {...}}`` envelope shape and a
    bare tracker-result dict; anything else is stringified defensively so
    a surprise payload can never crash the RPC loop.
    """
    if not isinstance(entry, dict):
        return str(entry)[:120], False
    inner = entry.get('result') if isinstance(entry.get('result'), dict) else entry
    target = (entry.get('target') or entry.get('value')
              or inner.get('target') or inner.get('value') or '?')
    if inner.get('success'):
        return f"{target}: ok ({inner.get('field_count', 0)} fields)", True
    problem = inner.get('errors') or inner.get('error') or 'failed'
    if isinstance(problem, (list, tuple)):
        problem = problem[0] if problem else 'failed'
    return f"{target}: failed ({str(problem)[:80]})", False


def _tool_batch(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run one lookup kind across multiple targets (capped at 10).

    Input: ``kind`` - the target kind (any tracker kind: ip, domain, mac,
    iban, coords, ...); ``targets`` - list of target values, maximum 10
    (extra entries are dropped and reported via ``capped`` /
    ``requested``); optional ``risk`` - attach heuristic risk scoring to
    each result (default false).

    Output: ``{'kind', 'risk', 'requested', 'capped', 'summary',
    'per_target'}`` - ``summary`` counts succeeded / failed targets and
    ``per_target`` carries one status line per target, so a batch never
    floods the context window with full reports.

    MCP safety: the hard 10-target cap keeps one call from keeping every
    source busy for minutes. Uses the same keyless/keyed sources as the
    single-target lookup tools.
    """
    try:
        from .advanced.batch import run_batch
    except ImportError as exc:
        raise _ToolError('module not available in this build') from exc
    kind = _required_str(arguments, 'kind')
    raw_targets = arguments.get('targets')
    if not isinstance(raw_targets, (list, tuple)) or not raw_targets:
        raise ValueError('targets must be a non-empty array of strings')
    targets = [str(item).strip() for item in raw_targets if str(item).strip()]
    if not targets:
        raise ValueError('targets must contain at least one non-blank value')
    requested = len(targets)
    capped = requested > _MAX_BATCH_TARGETS
    targets = targets[:_MAX_BATCH_TARGETS]
    risk = bool(arguments.get('risk', False))
    raw = _call_flexible(run_batch, kind, targets, risk,
                         kind=kind, targets=targets, risk=risk)
    lines: List[str] = []
    succeeded = 0
    for entry in _batch_entries(raw):
        line, ok = _batch_status(entry)
        lines.append(line)
        if ok:
            succeeded += 1
    return {
        'kind': kind,
        'risk': risk,
        'requested': requested,
        'capped': capped,
        'summary': {
            'targets': len(targets),
            'succeeded': succeeded,
            'failed': len(targets) - succeeded,
        },
        'per_target': lines,
    }


#: v5.0 tool registry: tool name -> handler, kept in the same order as the
#: ``TOOLS`` schema entries so the advertised surface and the dispatch
#: table can be reviewed side by side.
_HANDLERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    'mac_lookup': _tool_mac_lookup,
    'iban_lookup': _tool_iban_lookup,
    'imei_lookup': _tool_imei_lookup,
    'coords_lookup': _tool_coords_lookup,
    # v6.0 additions
    'vin_lookup': _tool_vin_lookup,
    'flight_lookup': _tool_flight_lookup,
    'mmsi_lookup': _tool_mmsi_lookup,
    'app_lookup': _tool_app_lookup,
    'bssid_lookup': _tool_bssid_lookup,
    'plate_lookup': _tool_plate_lookup,
    'tools_encode': _tool_encode,
    'tools_decode': _tool_decode,
    'tools_jwt': _tool_jwt,
    'tools_hash_id': _tool_hash_id,
    'tools_extract': _tool_extract,
    'tools_squat': _tool_squat,
    'tools_exif': _tool_exif,
    'tools_stego': _tool_stego,
    'tools_coords_convert': _tool_coords_convert,
    'tools_geo_profile': _tool_geo_profile,
    'tools_patterns': _tool_patterns,
    'tools_batch': _tool_batch,
}


def _success(msg_id: Any, result: Any) -> Dict[str, Any]:
    return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}


def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {'jsonrpc': '2.0', 'id': msg_id,
            'error': {'code': code, 'message': message}}


def handle_request(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Handle a single JSON-RPC message.

    Returns the response dict, or None when the message is a notification
    (which must not be answered).
    """
    if not isinstance(message, dict):
        return _error(None, -32600, 'invalid request')

    msg_id = message.get('id')
    method = message.get('method')
    if not isinstance(method, str):
        return _error(msg_id, -32600, 'invalid request')

    if method.startswith('notifications/'):
        return None

    if method == 'initialize':
        params = message.get('params')
        params = params if isinstance(params, dict) else {}
        requested = params.get('protocolVersion')
        version = requested if isinstance(requested, str) else _PROTOCOL_VERSION
        return _success(msg_id, {
            'protocolVersion': version,
            'capabilities': {'tools': {}},
            'serverInfo': {'name': 'obscuralens', 'version': __version__},
        })

    if method == 'ping':
        return _success(msg_id, {})

    if method == 'tools/list':
        return _success(msg_id, {'tools': TOOLS})

    if method == 'tools/call':
        params = message.get('params')
        if not isinstance(params, dict) or not isinstance(params.get('name'),
                                                           str):
            return _error(msg_id, -32602, 'invalid params')
        arguments = params.get('arguments', {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return _error(msg_id, -32602, 'invalid params')
        try:
            result = call_tool(params['name'], arguments)
            is_error = False
        except _ToolError as exc:
            # Clean tool-level error (e.g. an optional module missing from
            # this build): report the message verbatim, still marked as an
            # error result so clients surface it.
            result = {'error': str(exc)}
            is_error = True
        except Exception as exc:  # never let a tool crash the server loop
            result = {'error': f'{type(exc).__name__}: {exc}'}
            is_error = True
        return _success(msg_id, {
            'content': [{
                'type': 'text',
                'text': json.dumps(result, ensure_ascii=False, default=str),
            }],
            'isError': is_error,
        })

    return _error(msg_id, -32601, 'method not found')


def main(argv: Optional[List[str]] = None) -> int:
    """
    Run the MCP stdio loop.

    Reads one JSON object per line from stdin and writes one JSON response
    per line to stdout (blank lines are ignored). Parse errors are answered
    with a JSON-RPC error whose id is null. EOF ends the loop cleanly.
    """
    stdin = sys.stdin
    stdout = sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = _error(None, -32700, 'parse error')
            print('obscuralens-mcp: parse error on input line', file=sys.stderr)
        else:
            response = handle_request(message)
        if response is None:
            continue
        stdout.write(json.dumps(response, ensure_ascii=False, default=str))
        stdout.write('\n')
        stdout.flush()
    return 0


if __name__ == '__main__':  # pragma: no cover - module entry point
    raise SystemExit(main())
