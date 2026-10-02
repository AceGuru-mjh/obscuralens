"""
Geographic utilities for ObscuraLens.

Static ISO 3166-1 alpha-2 metadata plus small distance helpers used to
enrich and sanity-check geo coordinates returned by the IP / phone / email
/ domain trackers:

* ``COUNTRIES`` maps every officially assigned alpha-2 code (plus the 'UK'
  and 'EU' exceptionally reserved codes that geo APIs emit in the wild) to
  a ``(name, region)`` tuple.
* ``country_name`` / ``region_of`` / ``flag_emoji`` resolve codes
  case-insensitively and return '' for unknown input instead of raising.
* ``distance_km`` computes the haversine great-circle distance; non-numeric
  input yields 0.0 rather than an exception (documented below).
* ``coordinate_spread`` summarises a set of geo points (pairwise max /
  mean distance, centroid) while skipping malformed entries; it never
  raises, whatever it is fed.

Region classification uses the seven-region model ('Antarctic' collects the
sub-Antarctic territories).  Transcontinental countries are assigned to one
region, UN-geoscheme style: Russia -> Europe; Turkey, Cyprus, the Caucasus
states and Kazakhstan -> Asia; Egypt -> Africa.  Country names use plain
ASCII so reports render safely on legacy Windows code pages.
"""

import math
from typing import Any, Dict, List, Tuple

#: Mean Earth radius used by :func:`distance_km`.
EARTH_RADIUS_KM = 6371.0

#: The seven broad regions referenced by :data:`COUNTRIES`.
REGIONS = (
    'Africa',
    'Asia',
    'Europe',
    'North America',
    'South America',
    'Oceania',
    'Antarctic',
)

#: ISO 3166-1 alpha-2 code -> ``(English short name, broad region)``.
#:
#: All 249 officially assigned codes are present, one per line and sorted
#: alphabetically by code, plus two exceptionally reserved codes that real
#: geo APIs return: 'UK' (United Kingdom) and 'EU' (European Union).
COUNTRIES: Dict[str, Tuple[str, str]] = {
    'AD': ('Andorra', 'Europe'),
    'AE': ('United Arab Emirates', 'Asia'),
    'AF': ('Afghanistan', 'Asia'),
    'AG': ('Antigua and Barbuda', 'North America'),
    'AI': ('Anguilla', 'North America'),
    'AL': ('Albania', 'Europe'),
    'AM': ('Armenia', 'Asia'),
    'AO': ('Angola', 'Africa'),
    'AQ': ('Antarctica', 'Antarctic'),
    'AR': ('Argentina', 'South America'),
    'AS': ('American Samoa', 'Oceania'),
    'AT': ('Austria', 'Europe'),
    'AU': ('Australia', 'Oceania'),
    'AW': ('Aruba', 'North America'),
    'AX': ('Aland Islands', 'Europe'),
    'AZ': ('Azerbaijan', 'Asia'),
    'BA': ('Bosnia and Herzegovina', 'Europe'),
    'BB': ('Barbados', 'North America'),
    'BD': ('Bangladesh', 'Asia'),
    'BE': ('Belgium', 'Europe'),
    'BF': ('Burkina Faso', 'Africa'),
    'BG': ('Bulgaria', 'Europe'),
    'BH': ('Bahrain', 'Asia'),
    'BI': ('Burundi', 'Africa'),
    'BJ': ('Benin', 'Africa'),
    'BL': ('Saint Barthelemy', 'North America'),
    'BM': ('Bermuda', 'North America'),
    'BN': ('Brunei', 'Asia'),
    'BO': ('Bolivia', 'South America'),
    'BQ': ('Caribbean Netherlands', 'North America'),
    'BR': ('Brazil', 'South America'),
    'BS': ('Bahamas', 'North America'),
    'BT': ('Bhutan', 'Asia'),
    'BV': ('Bouvet Island', 'Antarctic'),
    'BW': ('Botswana', 'Africa'),
    'BY': ('Belarus', 'Europe'),
    'BZ': ('Belize', 'North America'),
    'CA': ('Canada', 'North America'),
    'CC': ('Cocos (Keeling) Islands', 'Oceania'),
    'CD': ('Democratic Republic of the Congo', 'Africa'),
    'CF': ('Central African Republic', 'Africa'),
    'CG': ('Republic of the Congo', 'Africa'),
    'CH': ('Switzerland', 'Europe'),
    'CI': ("Cote d'Ivoire", 'Africa'),
    'CK': ('Cook Islands', 'Oceania'),
    'CL': ('Chile', 'South America'),
    'CM': ('Cameroon', 'Africa'),
    'CN': ('China', 'Asia'),
    'CO': ('Colombia', 'South America'),
    'CR': ('Costa Rica', 'North America'),
    'CU': ('Cuba', 'North America'),
    'CV': ('Cabo Verde', 'Africa'),
    'CW': ('Curacao', 'North America'),
    'CX': ('Christmas Island', 'Oceania'),
    'CY': ('Cyprus', 'Asia'),
    'CZ': ('Czechia', 'Europe'),
    'DE': ('Germany', 'Europe'),
    'DJ': ('Djibouti', 'Africa'),
    'DK': ('Denmark', 'Europe'),
    'DM': ('Dominica', 'North America'),
    'DO': ('Dominican Republic', 'North America'),
    'DZ': ('Algeria', 'Africa'),
    'EC': ('Ecuador', 'South America'),
    'EE': ('Estonia', 'Europe'),
    'EG': ('Egypt', 'Africa'),
    'EH': ('Western Sahara', 'Africa'),
    'ER': ('Eritrea', 'Africa'),
    'ES': ('Spain', 'Europe'),
    'ET': ('Ethiopia', 'Africa'),
    'EU': ('European Union', 'Europe'),
    'FI': ('Finland', 'Europe'),
    'FJ': ('Fiji', 'Oceania'),
    'FK': ('Falkland Islands', 'South America'),
    'FM': ('Micronesia', 'Oceania'),
    'FO': ('Faroe Islands', 'Europe'),
    'FR': ('France', 'Europe'),
    'GA': ('Gabon', 'Africa'),
    'GB': ('United Kingdom', 'Europe'),
    'GD': ('Grenada', 'North America'),
    'GE': ('Georgia', 'Asia'),
    'GF': ('French Guiana', 'South America'),
    'GG': ('Guernsey', 'Europe'),
    'GH': ('Ghana', 'Africa'),
    'GI': ('Gibraltar', 'Europe'),
    'GL': ('Greenland', 'North America'),
    'GM': ('Gambia', 'Africa'),
    'GN': ('Guinea', 'Africa'),
    'GP': ('Guadeloupe', 'North America'),
    'GQ': ('Equatorial Guinea', 'Africa'),
    'GR': ('Greece', 'Europe'),
    'GS': ('South Georgia and the South Sandwich Islands', 'Antarctic'),
    'GT': ('Guatemala', 'North America'),
    'GU': ('Guam', 'Oceania'),
    'GW': ('Guinea-Bissau', 'Africa'),
    'GY': ('Guyana', 'South America'),
    'HK': ('Hong Kong', 'Asia'),
    'HM': ('Heard Island and McDonald Islands', 'Antarctic'),
    'HN': ('Honduras', 'North America'),
    'HR': ('Croatia', 'Europe'),
    'HT': ('Haiti', 'North America'),
    'HU': ('Hungary', 'Europe'),
    'ID': ('Indonesia', 'Asia'),
    'IE': ('Ireland', 'Europe'),
    'IL': ('Israel', 'Asia'),
    'IM': ('Isle of Man', 'Europe'),
    'IN': ('India', 'Asia'),
    'IO': ('British Indian Ocean Territory', 'Asia'),
    'IQ': ('Iraq', 'Asia'),
    'IR': ('Iran', 'Asia'),
    'IS': ('Iceland', 'Europe'),
    'IT': ('Italy', 'Europe'),
    'JE': ('Jersey', 'Europe'),
    'JM': ('Jamaica', 'North America'),
    'JO': ('Jordan', 'Asia'),
    'JP': ('Japan', 'Asia'),
    'KE': ('Kenya', 'Africa'),
    'KG': ('Kyrgyzstan', 'Asia'),
    'KH': ('Cambodia', 'Asia'),
    'KI': ('Kiribati', 'Oceania'),
    'KM': ('Comoros', 'Africa'),
    'KN': ('Saint Kitts and Nevis', 'North America'),
    'KP': ('North Korea', 'Asia'),
    'KR': ('South Korea', 'Asia'),
    'KW': ('Kuwait', 'Asia'),
    'KY': ('Cayman Islands', 'North America'),
    'KZ': ('Kazakhstan', 'Asia'),
    'LA': ('Laos', 'Asia'),
    'LB': ('Lebanon', 'Asia'),
    'LC': ('Saint Lucia', 'North America'),
    'LI': ('Liechtenstein', 'Europe'),
    'LK': ('Sri Lanka', 'Asia'),
    'LR': ('Liberia', 'Africa'),
    'LS': ('Lesotho', 'Africa'),
    'LT': ('Lithuania', 'Europe'),
    'LU': ('Luxembourg', 'Europe'),
    'LV': ('Latvia', 'Europe'),
    'LY': ('Libya', 'Africa'),
    'MA': ('Morocco', 'Africa'),
    'MC': ('Monaco', 'Europe'),
    'MD': ('Moldova', 'Europe'),
    'ME': ('Montenegro', 'Europe'),
    'MF': ('Saint Martin', 'North America'),
    'MG': ('Madagascar', 'Africa'),
    'MH': ('Marshall Islands', 'Oceania'),
    'MK': ('North Macedonia', 'Europe'),
    'ML': ('Mali', 'Africa'),
    'MM': ('Myanmar', 'Asia'),
    'MN': ('Mongolia', 'Asia'),
    'MO': ('Macao', 'Asia'),
    'MP': ('Northern Mariana Islands', 'Oceania'),
    'MQ': ('Martinique', 'North America'),
    'MR': ('Mauritania', 'Africa'),
    'MS': ('Montserrat', 'North America'),
    'MT': ('Malta', 'Europe'),
    'MU': ('Mauritius', 'Africa'),
    'MV': ('Maldives', 'Asia'),
    'MW': ('Malawi', 'Africa'),
    'MX': ('Mexico', 'North America'),
    'MY': ('Malaysia', 'Asia'),
    'MZ': ('Mozambique', 'Africa'),
    'NA': ('Namibia', 'Africa'),
    'NC': ('New Caledonia', 'Oceania'),
    'NE': ('Niger', 'Africa'),
    'NF': ('Norfolk Island', 'Oceania'),
    'NG': ('Nigeria', 'Africa'),
    'NI': ('Nicaragua', 'North America'),
    'NL': ('Netherlands', 'Europe'),
    'NO': ('Norway', 'Europe'),
    'NP': ('Nepal', 'Asia'),
    'NR': ('Nauru', 'Oceania'),
    'NU': ('Niue', 'Oceania'),
    'NZ': ('New Zealand', 'Oceania'),
    'OM': ('Oman', 'Asia'),
    'PA': ('Panama', 'North America'),
    'PE': ('Peru', 'South America'),
    'PF': ('French Polynesia', 'Oceania'),
    'PG': ('Papua New Guinea', 'Oceania'),
    'PH': ('Philippines', 'Asia'),
    'PK': ('Pakistan', 'Asia'),
    'PL': ('Poland', 'Europe'),
    'PM': ('Saint Pierre and Miquelon', 'North America'),
    'PN': ('Pitcairn Islands', 'Oceania'),
    'PR': ('Puerto Rico', 'North America'),
    'PS': ('Palestine', 'Asia'),
    'PT': ('Portugal', 'Europe'),
    'PW': ('Palau', 'Oceania'),
    'PY': ('Paraguay', 'South America'),
    'QA': ('Qatar', 'Asia'),
    'RE': ('Reunion', 'Africa'),
    'RO': ('Romania', 'Europe'),
    'RS': ('Serbia', 'Europe'),
    'RU': ('Russia', 'Europe'),
    'RW': ('Rwanda', 'Africa'),
    'SA': ('Saudi Arabia', 'Asia'),
    'SB': ('Solomon Islands', 'Oceania'),
    'SC': ('Seychelles', 'Africa'),
    'SD': ('Sudan', 'Africa'),
    'SE': ('Sweden', 'Europe'),
    'SG': ('Singapore', 'Asia'),
    'SH': ('Saint Helena', 'Africa'),
    'SI': ('Slovenia', 'Europe'),
    'SJ': ('Svalbard and Jan Mayen', 'Europe'),
    'SK': ('Slovakia', 'Europe'),
    'SL': ('Sierra Leone', 'Africa'),
    'SM': ('San Marino', 'Europe'),
    'SN': ('Senegal', 'Africa'),
    'SO': ('Somalia', 'Africa'),
    'SR': ('Suriname', 'South America'),
    'SS': ('South Sudan', 'Africa'),
    'ST': ('Sao Tome and Principe', 'Africa'),
    'SV': ('El Salvador', 'North America'),
    'SX': ('Sint Maarten', 'North America'),
    'SY': ('Syria', 'Asia'),
    'SZ': ('Eswatini', 'Africa'),
    'TC': ('Turks and Caicos Islands', 'North America'),
    'TD': ('Chad', 'Africa'),
    'TF': ('French Southern Territories', 'Antarctic'),
    'TG': ('Togo', 'Africa'),
    'TH': ('Thailand', 'Asia'),
    'TJ': ('Tajikistan', 'Asia'),
    'TK': ('Tokelau', 'Oceania'),
    'TL': ('Timor-Leste', 'Asia'),
    'TM': ('Turkmenistan', 'Asia'),
    'TN': ('Tunisia', 'Africa'),
    'TO': ('Tonga', 'Oceania'),
    'TR': ('Turkey', 'Asia'),
    'TT': ('Trinidad and Tobago', 'North America'),
    'TV': ('Tuvalu', 'Oceania'),
    'TW': ('Taiwan', 'Asia'),
    'TZ': ('Tanzania', 'Africa'),
    'UA': ('Ukraine', 'Europe'),
    'UG': ('Uganda', 'Africa'),
    'UK': ('United Kingdom', 'Europe'),
    'UM': ('United States Minor Outlying Islands', 'Oceania'),
    'US': ('United States', 'North America'),
    'UY': ('Uruguay', 'South America'),
    'UZ': ('Uzbekistan', 'Asia'),
    'VA': ('Vatican City', 'Europe'),
    'VC': ('Saint Vincent and the Grenadines', 'North America'),
    'VE': ('Venezuela', 'South America'),
    'VG': ('British Virgin Islands', 'North America'),
    'VI': ('United States Virgin Islands', 'North America'),
    'VN': ('Vietnam', 'Asia'),
    'VU': ('Vanuatu', 'Oceania'),
    'WF': ('Wallis and Futuna', 'Oceania'),
    'WS': ('Samoa', 'Oceania'),
    'YE': ('Yemen', 'Asia'),
    'YT': ('Mayotte', 'Africa'),
    'ZA': ('South Africa', 'Africa'),
    'ZM': ('Zambia', 'Africa'),
    'ZW': ('Zimbabwe', 'Africa'),
}

#: Regional indicator symbol for the letter 'A' (flag emoji base).
_FLAG_BASE = 0x1F1E6


def _normalize_code(code: Any) -> str:
    """Strip and uppercase a country code; non-strings become ''."""
    if not isinstance(code, str):
        return ''
    return code.strip().upper()


def _is_finite_number(value: Any) -> bool:
    """True for plain ints/floats; bools, NaN, inf and garbage are rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, ValueError):
        return False  # absurdly large ints cannot become floats


def country_name(code: Any) -> str:
    """
    Return the English short country name for an ISO 3166-1 alpha-2 code.

    Lookup is case-insensitive and tolerates surrounding whitespace.
    Unknown codes and non-string input return '' (never an exception).
    """
    entry = COUNTRIES.get(_normalize_code(code))
    return entry[0] if entry else ''


def region_of(code: Any) -> str:
    """
    Return the broad region ('Africa', 'Asia', ...) for an alpha-2 code.

    Unknown codes and non-string input return ''.
    """
    entry = COUNTRIES.get(_normalize_code(code))
    return entry[1] if entry else ''


def flag_emoji(code: Any) -> str:
    """
    Return the flag emoji for a known alpha-2 code, e.g. 'fr' -> FR flag.

    The flag is built from the two regional indicator symbols derived from
    the code's letters.  Codes are matched against :data:`COUNTRIES`, so
    unknown codes ('zz'), wrong-length input and non-strings all yield ''.
    """
    key = _normalize_code(code)
    if key not in COUNTRIES:
        return ''
    return ''.join(chr(_FLAG_BASE + ord(letter) - ord('A')) for letter in key)


def distance_km(lat1: Any, lon1: Any, lat2: Any, lon2: Any) -> float:
    """
    Great-circle distance between two points, in kilometres.

    Uses the haversine formula with a mean Earth radius of 6371.0 km.
    Non-numeric input — strings, None, booleans, NaN, infinity — makes the
    function return 0.0 instead of raising; callers treat 0.0 as "no
    usable distance".  Coordinates are not range-checked.
    """
    values = (lat1, lon1, lat2, lon2)
    if not all(_is_finite_number(value) for value in values):
        return 0.0
    try:
        phi1 = math.radians(float(lat1))
        phi2 = math.radians(float(lat2))
        d_phi = math.radians(float(lat2) - float(lat1))
        d_lambda = math.radians(float(lon2) - float(lon1))
        a = (
            math.sin(d_phi / 2.0) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
        )
        a = min(1.0, max(0.0, a))  # clamp float drift so asin stays defined
        return 2.0 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))
    except (ValueError, OverflowError):
        return 0.0  # absurd magnitudes that overflow the trig functions


def _valid_points(coords: Any) -> List[Tuple[float, float]]:
    """
    Extract ``(lat, lon)`` pairs from coordinate entries, skipping garbage.

    An entry counts as valid when it is a dict with numeric ``lat`` /
    ``lon`` keys inside the usual ranges (lat in [-90, 90], lon in
    [-180, 180]).  Booleans, NaN, infinity and out-of-range values are
    treated as garbage; the ``source`` key is informational and ignored.
    """
    if coords is None or isinstance(coords, (str, bytes)):
        return []
    try:
        entries = list(coords)
    except TypeError:
        return []
    points: List[Tuple[float, float]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        lat = entry.get('lat')
        lon = entry.get('lon')
        if not _is_finite_number(lat) or not _is_finite_number(lon):
            continue
        if not -90.0 <= float(lat) <= 90.0 or not -180.0 <= float(lon) <= 180.0:
            continue
        points.append((float(lat), float(lon)))
    return points


def _zeros_spread(points: int) -> Dict[str, Any]:
    """Summary returned when fewer than two valid points are available."""
    return {
        'points': points,
        'max_distance_km': 0.0,
        'mean_distance_km': 0.0,
        'centroid': {'lat': 0.0, 'lon': 0.0},
        'spread_km': 0.0,
    }


def coordinate_spread(coords: Any) -> Dict[str, Any]:
    """
    Summarise the geographic spread of a list of coordinate entries.

    ``coords`` is a list of ``{'source', 'lat', 'lon'}`` dicts as produced
    by the geo-enabled trackers.  Every unique pair of valid points is
    compared and the result is::

        {
            'points': <number of valid entries>,
            'max_distance_km': <largest pairwise great-circle distance>,
            'mean_distance_km': <mean over all pairwise distances>,
            'centroid': {'lat': <arithmetic mean, rounded to 2>,
                         'lon': <arithmetic mean, rounded to 2>},
            'spread_km': <alias of max_distance_km>,
        }

    Malformed entries (non-dicts, missing keys, non-numeric or
    out-of-range coordinates) are skipped.  With 0 or 1 valid points a
    zeros summary is returned (a single point has no pairwise distances,
    so its position is not echoed).  The function never raises.
    """
    try:
        points = _valid_points(coords)
        count = len(points)
        if count < 2:
            return _zeros_spread(count)
        distances = [
            distance_km(lat1, lon1, lat2, lon2)
            for index, (lat1, lon1) in enumerate(points)
            for lat2, lon2 in points[index + 1:]
        ]
        max_distance = max(distances)
        mean_distance = sum(distances) / len(distances)
        centroid_lat = round(sum(lat for lat, _ in points) / count, 2)
        centroid_lon = round(sum(lon for _, lon in points) / count, 2)
        return {
            'points': count,
            'max_distance_km': max_distance,
            'mean_distance_km': mean_distance,
            'centroid': {'lat': centroid_lat, 'lon': centroid_lon},
            'spread_km': max_distance,
        }
    except Exception:  # last-resort guard: never raise on garbage input
        return _zeros_spread(0)
