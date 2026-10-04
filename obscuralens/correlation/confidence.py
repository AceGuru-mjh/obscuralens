"""
Evidence confidence scoring (v6.1).

Risk scoring answers *what the target is*; confidence scoring answers *how
well attested each fact is*. The idea follows Umbra's noisy-OR
corroboration model: every field's confidence is

    1 - product(1 - trust(source)) over its provenance list

so independent sources corroborating each other compound towards certainty,
while a single weak source stays weak. Provenance already exists in every
tracker result (``field_sources``) - this module turns it into a score.

Design notes
------------
* ``SOURCE_TRUST`` tiers curate the trust baseline per source name:
  offline standards-derived maths and curated packs are near-certain
  (0.95); first-party authoritative APIs (registry operators, the CVE
  Program, chain RPCs) are strong (0.9); community aggregators and HTML
  scrapes are moderate (0.75); everything else defaults to 0.8.
* No combination rule treats a source list as more reliable than its most
  trusted member: two aggregators quoting the same upstream still cap out
  below one authoritative record. The noisy-OR product naturally respects
  this because every factor is below 1.
* The output never changes lookups; it is attached alongside
  ``field_sources`` as ``confidence`` and degrades to an empty dict when
  provenance is missing.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

#: Near-certain: offline standards-derived facts and curated data packs.
_TIER_CERTAIN = 0.95
#: Strong: first-party authoritative records (registries, the CVE Program,
#: chain RPCs, standards bodies).
_TIER_AUTHORITY = 0.9
#: Default: reputable keyless APIs whose data is original.
_TIER_DEFAULT = 0.8
#: Moderate: community aggregators, mirrors and HTML scrapes, where the
#: answer may lag or paraphrase an upstream.
_TIER_AGGREGATOR = 0.75

#: Source-name -> trust baseline. Sources not listed default to
#: ``_TIER_DEFAULT``. Deliberately coarse: the value of the model is the
#: corroboration math, not third decimals of per-source calibration.
SOURCE_TRUST: Dict[str, float] = {
    # --- offline standards / curated packs -------------------------------
    'flight_math': _TIER_CERTAIN,
    'vin_math': _TIER_CERTAIN,
    'geohash_local': _TIER_CERTAIN,
    'country_centroids': _TIER_CERTAIN,
    'airline_pack': _TIER_CERTAIN,
    'plate_pack': _TIER_CERTAIN,
    'plate_math': _TIER_CERTAIN,
    'wmi_pack': _TIER_CERTAIN,
    'tac_pack': _TIER_CERTAIN,
    'mid_pack': _TIER_CERTAIN,
    'oui_pack': _TIER_CERTAIN,
    'iban_pack': _TIER_CERTAIN,
    'patterns': _TIER_CERTAIN,
    'disposable': _TIER_CERTAIN,
    # --- first-party authoritative records --------------------------------
    'rdap': _TIER_AUTHORITY,
    'domain_rdap': _TIER_AUTHORITY,
    'cveawg': _TIER_AUTHORITY,
    'cvelist': _TIER_AUTHORITY,
    'kev': _TIER_AUTHORITY,
    'nvd': _TIER_AUTHORITY,
    'ripestat': _TIER_AUTHORITY,
    'asrank': _TIER_AUTHORITY,
    'peeringdb': _TIER_AUTHORITY,
    'reverse_dns': _TIER_AUTHORITY,
    'nhtsa_vpic': _TIER_AUTHORITY,
    'dns': _TIER_AUTHORITY,
    'doh.google': _TIER_AUTHORITY,
    'doh.cloudflare': _TIER_AUTHORITY,
    'hstspreload': _TIER_AUTHORITY,
    # --- chain RPCs / explorers (their own ledger) -------------------------
    'blockchain.info': _TIER_AUTHORITY,
    'blockstream.info': _TIER_AUTHORITY,
    'mempool.space': _TIER_AUTHORITY,
    'solana': _TIER_AUTHORITY,
    'near': _TIER_AUTHORITY,
    'tron': _TIER_AUTHORITY,
    'avax_cchain': _TIER_AUTHORITY,
    'xrpscan': _TIER_AUTHORITY,
    'xrpl_public': _TIER_AUTHORITY,
    'koios': _TIER_AUTHORITY,
    'cosmos': _TIER_AUTHORITY,
    'ethplorer': _TIER_DEFAULT,
    # --- community aggregators / mirrors / scrapes --------------------------
    'circl': _TIER_AGGREGATOR,
    'osv': _TIER_AGGREGATOR,
    'ghsa': _TIER_AGGREGATOR,
    'epss': _TIER_DEFAULT,
    'bgpview': _TIER_AGGREGATOR,
    'crt.sh': _TIER_AGGREGATOR,
    'certspotter': _TIER_AGGREGATOR,
    'hackertarget': _TIER_AGGREGATOR,
    'urlscan': _TIER_AGGREGATOR,
    'wayback': _TIER_AGGREGATOR,
    'otx': _TIER_AGGREGATOR,
    'security_txt': _TIER_AGGREGATOR,
    'ip-api.com': _TIER_AGGREGATOR,
    'ipapi.co': _TIER_AGGREGATOR,
    'ipwhois.app': _TIER_AGGREGATOR,
    'ipwho.is': _TIER_AGGREGATOR,
    'freeipapi': _TIER_AGGREGATOR,
    'db-ip.com': _TIER_AGGREGATOR,
    'iplocation.net': _TIER_AGGREGATOR,
    'ipinfo.io': _TIER_AGGREGATOR,
    'bigdatacloud': _TIER_AGGREGATOR,
    'nominatim': _TIER_AGGREGATOR,
    'open_elevation': _TIER_AGGREGATOR,
    'open_meteo': _TIER_AGGREGATOR,
    'xposedornot': _TIER_AGGREGATOR,
    'emailrep': _TIER_AGGREGATOR,
    'greynoise': _TIER_DEFAULT,
    'proxycheck': _TIER_DEFAULT,
    'ransomware_live': _TIER_AGGREGATOR,
    'threat_feeds': _TIER_AUTHORITY,
    'adsb_lol': _TIER_AGGREGATOR,
    'github_commits': _TIER_AUTHORITY,
    'gravatar': _TIER_AUTHORITY,
    'openpgp': _TIER_AUTHORITY,
    'internetdb': _TIER_DEFAULT,
}

#: Cap on how many sources a single field's confidence line reports.
_MAX_SOURCES_LISTED = 5


def source_trust(name: str) -> float:
    """Trust baseline for a source name (plugins and unknowns: default)."""
    if name.startswith('plugin:'):
        return _TIER_DEFAULT
    return SOURCE_TRUST.get(name, _TIER_DEFAULT)


def field_confidence(provenance: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Score every field listed in a provenance map.

    Returns ``{field: {'score': 0..1, 'sources': n, 'named': [top sources]}}``
    (fields with empty provenance lists are skipped). Never raises; a
    non-dict input yields ``{}``.
    """
    if not isinstance(provenance, dict):
        return {}
    scored: Dict[str, Any] = {}
    for field, sources in provenance.items():
        if not isinstance(sources, list) or not sources:
            continue
        miss = 1.0
        for name in sources:
            miss *= (1.0 - source_trust(str(name)))
        scored[str(field)] = {
            'score': round(1.0 - miss, 3),
            'sources': len(sources),
            'named': [str(s) for s in sources[:_MAX_SOURCES_LISTED]],
        }
    return scored


def _band(score: float) -> str:
    """Human-friendly confidence band for a 0..1 score."""
    if score >= 0.99:
        return 'certain'
    if score >= 0.95:
        return 'very-high'
    if score >= 0.85:
        return 'high'
    if score >= 0.75:
        return 'moderate'
    if score >= 0.5:
        return 'low'
    return 'very-low'


def attach_confidence(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Attach an evidence-confidence block to a tracker result, in place.

    The block lands under ``payload['confidence']`` and never disturbs any
    existing key::

        {
          'overall': 0.87,              # mean over scored fields
          'band': 'high',
          'fields_scored': 24,
          'corroborated': 6,            # fields with 2+ sources
          'per_field': {field: {...}},
        }

    Results without a provenance map (or non-dict payloads) are returned
    untouched - confidence is an annotation, not a gate.
    """
    if not isinstance(payload, dict):
        return payload  # type: ignore[return-value]
    provenance = payload.get('field_sources') or payload.get('provenance')
    if not isinstance(provenance, dict) or not provenance:
        return payload

    try:
        per_field = field_confidence(provenance)
        if not per_field:
            return payload
        scores = [entry['score'] for entry in per_field.values()]
        overall = round(sum(scores) / len(scores), 3) if scores else 0.0
        corroborated = sum(1 for entry in per_field.values()
                           if entry['sources'] >= 2)
        payload['confidence'] = {
            'overall': overall,
            'band': _band(overall),
            'fields_scored': len(per_field),
            'corroborated': corroborated,
            'per_field': per_field,
        }
    except Exception as exc:  # confidence must never break a lookup
        logger.debug('confidence scoring failed: %s', exc)
    return payload


__all__ = ['SOURCE_TRUST', 'source_trust', 'field_confidence',
           'attach_confidence']
