"""
Phone Tracker Module

No public phone-validation API works without a key (numverify, telnyx,
abstractapi and phoneapi all rejected unauthenticated calls during testing),
so enrichment is done locally from the Google libphonenumber metadata plus
derived heuristics. Optional keyed sources (numverify) are supported when a
key is configured.
"""

import concurrent.futures as futures
from typing import Any, Dict, List, Optional

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from ..config import config
from ..database import db
from ..utils.http_client import http

TYPE_NAMES = {
    phonenumbers.PhoneNumberType.MOBILE: "Mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed line",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "Toll free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "Shared cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
    phonenumbers.PhoneNumberType.PAGER: "Pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
}

# Regions where a national number is frequently a business/VoIP range rather
# than a personal mobile. Used only as a weak hint, clearly labelled.
BUSINESS_PREFIX_HINTS = {
    'ID': ['800', '809', '850', '878', '888'],
    'US': ['800', '833', '844', '855', '866', '877', '888'],
    'GB': ['80'],
}


class PhoneTracker:
    """Phone Tracker using local metadata plus optional keyed sources"""

    def __init__(self):
        self.timeout = config.app_config.request_timeout

    def track(self, phone_number: str, default_region: str = "ID") -> Dict[str, Any]:
        """
        Track a phone number.

        Args:
            phone_number: Phone number to track
            default_region: ISO 3166-1 alpha-2 region used to parse
                            numbers without an international prefix

        Returns:
            Dictionary with parsed metadata, derived hints and source status
        """
        status: Dict[str, Dict[str, Any]] = {}
        fields: Dict[str, Any] = {}
        parse_ok = False

        try:
            parsed = phonenumbers.parse(phone_number, default_region)
            fields.update(self._local_metadata(phone_number, parsed, default_region))
            parse_ok = True
            # Parsing succeeds for almost any digit string; only a valid or at
            # least plausible number counts as a successful lookup.
            if fields.get('valid_format') or fields.get('possible'):
                status['libphonenumber'] = {'ok': True, 'error': ''}
            else:
                status['libphonenumber'] = {
                    'ok': False,
                    'error': 'not a valid or plausible number for this region',
                }
        except phonenumbers.NumberParseException as e:
            status['libphonenumber'] = {'ok': False, 'error': str(e)[:80]}

        # Optional keyed source.
        if config.is_configured('numverify'):
            key = config.get_api_key('numverify')
            ok, data, err = http.get_json(
                f"http://apilayer.net/api/validate/num/"
                f"{fields.get('national_number', '')}?country_code={default_region}"
                f"&access_key={key}")
            if ok and data and data.get('valid'):
                fields.update({
                    'numverify_valid': data.get('valid'),
                    'numverify_line_type': data.get('line_type'),
                    'numverify_carrier': data.get('carrier'),
                    'numverify_location': data.get('location'),
                })
                status['numverify'] = {'ok': True, 'error': ''}
            else:
                status['numverify'] = {'ok': False, 'error': err or 'no data'}

        result: Dict[str, Any] = {
            'phone_number': phone_number,
            'info': fields,
            'sources_ok': sorted(n for n, s in status.items() if s['ok']),
            'sources_failed': {n: s['error'] for n, s in status.items() if not s['ok']},
            'field_count': len([v for v in fields.values()
                                if v is not None and v != '' and v != [] and v != {}]),
            'success': status.get('libphonenumber', {}).get('ok', False),
            'errors': [status['libphonenumber']['error']]
                      if not status.get('libphonenumber', {}).get('ok') and parse_ok
                      else [],
        }

        db.save_query('phone', phone_number, result, result['success'], '')

        return result

    def _local_metadata(self, original: str, parsed: Any, region: str) -> Dict[str, Any]:
        """Extract and derive everything libphonenumber knows."""
        region_code = phonenumbers.region_code_for_number(parsed) or region
        num_type = phonenumbers.number_type(parsed)

        timezones = timezone.time_zones_for_number(parsed) or []
        carriers = carrier.name_for_number(parsed, "en")
        location = geocoder.description_for_number(parsed, "id") or ""

        national = str(parsed.national_number or '')

        fields: Dict[str, Any] = {
            'original_number': original,
            'valid_format': phonenumbers.is_valid_number(parsed),
            'possible': phonenumbers.is_possible_number(parsed),
            'country_code': f"+{parsed.country_code}",
            'national_number': national,
            'region_code': region_code,
            'type': TYPE_NAMES.get(num_type, "Unknown"),
            'is_mobile': num_type == phonenumbers.PhoneNumberType.MOBILE,
            'is_voip': num_type == phonenumbers.PhoneNumberType.VOIP,
            'is_toll_free': num_type == phonenumbers.PhoneNumberType.TOLL_FREE,
            'number_length': len(national),
            'e164': phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164),
            'international': phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'national_format': phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            'rfc3966': phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.RFC3966),
        }

        if carriers:
            fields['carrier'] = carriers
        if location:
            fields['location'] = location
        if timezones:
            fields['timezones'] = timezones
            fields['timezone_count'] = len(timezones)
            fields['primary_timezone'] = timezones[0]

        # Derived, best-effort signals.
        hints: List[str] = []
        for prefix in BUSINESS_PREFIX_HINTS.get(region_code, []):
            if national.startswith(prefix):
                hints.append(f'{prefix} prefix often used for business/service lines')
                break
        if fields.get('is_voip'):
            hints.append('VoIP range: number may not be tied to a physical line')
        if not fields['valid_format'] and fields['possible']:
            hints.append('Not a valid number for this region, but the format is plausible')
        if hints:
            fields['hints'] = hints

        return fields

    def batch_track(self, phone_numbers: List[str], default_region: str = "ID",
                    workers: int = 5) -> List[Dict[str, Any]]:
        """Track multiple phone numbers concurrently."""
        targets = [p.strip() for p in phone_numbers if p.strip()]
        results: List[Dict[str, Any]] = [None] * len(targets)  # type: ignore[list-item]

        with futures.ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {
                ex.submit(self.track, p, default_region): i
                for i, p in enumerate(targets)
            }
            for future in futures.as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    results[idx] = {
                        'phone_number': targets[idx], 'info': {}, 'sources_ok': [],
                        'sources_failed': {}, 'field_count': 0,
                        'success': False, 'errors': [type(e).__name__],
                    }
        return results
