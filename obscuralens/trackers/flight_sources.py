"""
Flight designator (IATA/ICAO flight number) intelligence sources.

A flight designator answers "which airline operates this flight": the
two-letter IATA or three-letter ICAO carrier code maps to the airline's
name, country and radio callsign, the numeric run carries airline-specific
conventions (odd numbers for outbound legs, number bands for service types)
and the ICAO callsign is simply ``{ICAO}{number}`` on the radio. This module
mixes two offline sources, one keyed online API and two analyst utilities:

* ``airline_pack``  - offline curated airline pack shipped at
                      ``obscuralens/data/airlines_iata.txt`` (134 curated
                      ``IATA|ICAO|name|country|callsign`` entries covering
                      the world's majors on six continents plus several
                      historically important carriers). Resolves the
                      airline without touching the network.
* ``flight_math``   - pure-Python designator anatomy: carrier code flavour
                      (IATA vs ICAO), flight number digits, optional
                      suffix letter, both flight-code renderings
                      (``UA1`` / ``UAL1``), the radio callsign
                      concatenation and the odd/even direction convention
                      and number-band hints (explicitly labelled as
                      conventions, never evidence).
* ``aviationstack`` - aviationstack.com live flight API (keyed): status,
                      airline confirmation, departure/arrival airports and
                      scheduled times and the aircraft registration
                      (only runs when an ``aviationstack`` API key is
                      configured).

Two utilities ride along because flight analysts constantly need them
without a tracker: :func:`lookup_airport` (built-in table of the world's
major hubs) and :func:`airport_distance` (great-circle kilometres between
two hubs, reusing ``utils.coordinate_math.haversine_km`` instead of a
second implementation).

Every provider runs independently; results are merged field-by-field so a
single flaky source cannot blank out the whole report. Field provenance is
tracked: ``gather_all`` returns which source(s) supplied each value, so a
report can show exactly where a fact came from.
"""

import concurrent.futures as futures
import contextlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..health import health
from ..utils.coordinate_math import haversine_km
from ..utils.data_packs import DATA_DIR
from ..utils.helpers import fanout_workers
from ..utils.http_client import http
from ..utils.validators import normalize_flight, split_flight

#: Airline names / callsigns capped for report sanity.
_MAX_AIRLINE_CHARS = 120

#: Live-flight strings (airport names, timestamps) capped the same way.
_MAX_LIVE_CHARS = 160

#: Parsed airline pack cache: iata -> (icao, name, country, callsign) plus a
#: reverse index icao -> iata. ``None`` means "not loaded yet".
_AIRLINE_CACHE: Optional[Tuple[Dict[str, Tuple[str, str, str, str]],
                               Dict[str, str]]] = None

#: Built-in airport table: IATA code -> (name, city, country, lat, lon).
#: Deliberately NOT a data pack: it only backs the two convenience helpers
#: below, and ~60 global hubs cover the airports a flight designator alone
#: can say anything about (the designator names the airline, not the route;
#: route detail comes from the aviationstack live source).
_AIRPORTS: Dict[str, Tuple[str, str, str, float, float]] = {
    'ATL': ('Hartsfield-Jackson Atlanta International', 'Atlanta', 'United States',
            33.6407, -84.4277),
    'BOS': ('Logan International', 'Boston', 'United States', 42.3656, -71.0096),
    'DEN': ('Denver International', 'Denver', 'United States', 39.8561, -104.6737),
    'DFW': ('Dallas/Fort Worth International', 'Dallas', 'United States',
            32.8998, -97.0403),
    'DTW': ('Detroit Metropolitan Wayne County', 'Detroit', 'United States',
            42.2124, -83.3534),
    'EWR': ('Newark Liberty International', 'Newark', 'United States',
            40.6895, -74.1745),
    'HNL': ('Daniel K. Inouye International', 'Honolulu', 'United States',
            21.3187, -157.9224),
    'IAD': ('Washington Dulles International', 'Washington', 'United States',
            38.9531, -77.4565),
    'IAH': ('George Bush Intercontinental', 'Houston', 'United States',
            29.9902, -95.3368),
    'JFK': ('John F. Kennedy International', 'New York', 'United States',
            40.6413, -73.7781),
    'LAS': ('Harry Reid International', 'Las Vegas', 'United States',
            36.0840, -115.1537),
    'LAX': ('Los Angeles International', 'Los Angeles', 'United States',
            33.9416, -118.4085),
    'MCO': ('Orlando International', 'Orlando', 'United States', 28.4312, -81.3081),
    'MIA': ('Miami International', 'Miami', 'United States', 25.7959, -80.2870),
    'ORD': ('O\'Hare International', 'Chicago', 'United States', 41.9742, -87.9073),
    'PHL': ('Philadelphia International', 'Philadelphia', 'United States',
            39.8744, -75.2424),
    'PHX': ('Phoenix Sky Harbor International', 'Phoenix', 'United States',
            33.4342, -112.0116),
    'SEA': ('Seattle-Tacoma International', 'Seattle', 'United States',
            47.4502, -122.3088),
    'SFO': ('San Francisco International', 'San Francisco', 'United States',
            37.6213, -122.3790),
    'SLC': ('Salt Lake City International', 'Salt Lake City', 'United States',
            40.7899, -111.9791),
    'TPA': ('Tampa International', 'Tampa', 'United States', 27.9755, -82.5332),
    'YVR': ('Vancouver International', 'Vancouver', 'Canada', 49.1967, -123.1815),
    'YYZ': ('Toronto Pearson International', 'Toronto', 'Canada',
            43.6777, -79.6248),
    'YUL': ('Montreal-Trudeau International', 'Montreal', 'Canada',
            45.4703, -73.7408),
    'MEX': ('Mexico City International', 'Mexico City', 'Mexico',
            19.4363, -99.0721),
    'CUN': ('Cancun International', 'Cancun', 'Mexico', 21.0365, -86.8771),
    'PTY': ('Tocumen International', 'Panama City', 'Panama', 9.0714, -79.3835),
    'BOG': ('El Dorado International', 'Bogota', 'Colombia', 4.7016, -74.1469),
    'LIM': ('Jorge Chavez International', 'Lima', 'Peru', -12.0219, -77.1143),
    'SCL': ('Arturo Merino Benitez International', 'Santiago', 'Chile',
            -33.3930, -70.7858),
    'EZE': ('Ministro Pistarini International', 'Buenos Aires', 'Argentina',
            -34.8222, -58.5358),
    'GRU': ('Guarulhos International', 'Sao Paulo', 'Brazil', -23.4356, -46.4731),
    'GIG': ('Galeao International', 'Rio de Janeiro', 'Brazil',
            -22.8100, -43.2506),
    'LHR': ('Heathrow', 'London', 'United Kingdom', 51.4700, -0.4543),
    'LGW': ('Gatwick', 'London', 'United Kingdom', 51.1537, -0.1821),
    'MAN': ('Manchester', 'Manchester', 'United Kingdom', 53.3537, -2.2750),
    'DUB': ('Dublin', 'Dublin', 'Ireland', 53.4213, -6.2701),
    'CDG': ('Charles de Gaulle', 'Paris', 'France', 49.0097, 2.5479),
    'ORY': ('Orly', 'Paris', 'France', 48.7233, 2.3794),
    'AMS': ('Schiphol', 'Amsterdam', 'Netherlands', 52.3105, 4.7683),
    'BRU': ('Brussels', 'Brussels', 'Belgium', 50.9014, 4.4844),
    'FRA': ('Frankfurt am Main', 'Frankfurt', 'Germany', 50.0379, 8.5622),
    'MUC': ('Munich', 'Munich', 'Germany', 48.3537, 11.7861),
    'BER': ('Berlin Brandenburg', 'Berlin', 'Germany', 52.3667, 13.5033),
    'ZRH': ('Zurich', 'Zurich', 'Switzerland', 47.4647, 8.4755),
    'VIE': ('Vienna', 'Vienna', 'Austria', 48.1103, 16.5697),
    'CPH': ('Copenhagen', 'Copenhagen', 'Denmark', 55.6180, 12.6560),
    'ARN': ('Arlanda', 'Stockholm', 'Sweden', 59.6519, 17.9186),
    'OSL': ('Oslo Gardermoen', 'Oslo', 'Norway', 60.1976, 11.1004),
    'HEL': ('Helsinki-Vantaa', 'Helsinki', 'Finland', 60.3172, 24.9633),
    'KEF': ('Keflavik International', 'Reykjavik', 'Iceland', 63.9850, -22.6056),
    'MAD': ('Adolfo Suarez Madrid-Barajas', 'Madrid', 'Spain', 40.4983, -3.5676),
    'BCN': ('El Prat', 'Barcelona', 'Spain', 41.2974, 2.0833),
    'LIS': ('Humberto Delgado', 'Lisbon', 'Portugal', 38.7756, -9.1354),
    'FCO': ('Leonardo da Vinci-Fiumicino', 'Rome', 'Italy', 41.8003, 12.2389),
    'MXP': ('Milan Malpensa', 'Milan', 'Italy', 45.4451, 9.2768),
    'ATH': ('Athens International', 'Athens', 'Greece', 37.9364, 23.9445),
    'IST': ('Istanbul', 'Istanbul', 'Turkey', 41.2753, 28.7519),
    'SVO': ('Sheremetyevo International', 'Moscow', 'Russia', 55.9726, 37.4146),
    'LED': ('Pulkovo', 'Saint Petersburg', 'Russia', 59.8003, 30.2625),
    'WAW': ('Chopin', 'Warsaw', 'Poland', 52.1657, 20.9671),
    'PRG': ('Vaclav Havel', 'Prague', 'Czech Republic', 50.1008, 14.2600),
    'DXB': ('Dubai International', 'Dubai', 'United Arab Emirates',
            25.2532, 55.3657),
    'AUH': ('Zayed International', 'Abu Dhabi', 'United Arab Emirates',
            24.4330, 54.6511),
    'DOH': ('Hamad International', 'Doha', 'Qatar', 25.2731, 51.6081),
    'RUH': ('King Khalid International', 'Riyadh', 'Saudi Arabia',
            24.9576, 46.6988),
    'TLV': ('Ben Gurion', 'Tel Aviv', 'Israel', 32.0114, 34.8867),
    'CAI': ('Cairo International', 'Cairo', 'Egypt', 30.1219, 31.4056),
    'JNB': ('O. R. Tambo International', 'Johannesburg', 'South Africa',
            -26.1367, 28.2411),
    'CPT': ('Cape Town International', 'Cape Town', 'South Africa',
            -33.9715, 18.6021),
    'NBO': ('Jomo Kenyatta International', 'Nairobi', 'Kenya', -1.3192, 36.9278),
    'DEL': ('Indira Gandhi International', 'Delhi', 'India', 28.5562, 77.1000),
    'BOM': ('Chhatrapati Shivaji Maharaj International', 'Mumbai', 'India',
            19.0896, 72.8656),
    'PEK': ('Beijing Capital International', 'Beijing', 'China',
            40.0799, 116.6031),
    'PVG': ('Shanghai Pudong International', 'Shanghai', 'China',
            31.1443, 121.8083),
    'CAN': ('Guangzhou Baiyun International', 'Guangzhou', 'China',
            23.3924, 113.2988),
    'HKG': ('Hong Kong International', 'Hong Kong', 'Hong Kong',
            22.3080, 113.9185),
    'TPE': ('Taoyuan International', 'Taipei', 'Taiwan', 25.0777, 121.2328),
    'ICN': ('Incheon International', 'Seoul', 'South Korea', 37.4602, 126.4407),
    'NRT': ('Narita International', 'Tokyo', 'Japan', 35.7720, 140.1037),
    'HND': ('Haneda', 'Tokyo', 'Japan', 35.5494, 139.7798),
    'KIX': ('Kansai International', 'Osaka', 'Japan', 34.4347, 135.2441),
    'BKK': ('Suvarnabhumi', 'Bangkok', 'Thailand', 13.6900, 100.7501),
    'KUL': ('Kuala Lumpur International', 'Kuala Lumpur', 'Malaysia',
            2.7456, 101.7099),
    'SIN': ('Changi', 'Singapore', 'Singapore', 1.3644, 103.9915),
    'CGK': ('Soekarno-Hatta International', 'Jakarta', 'Indonesia',
            -6.1256, 106.6558),
    'MNL': ('Ninoy Aquino International', 'Manila', 'Philippines',
            14.5086, 121.0194),
    'SGN': ('Tan Son Nhat International', 'Ho Chi Minh City', 'Vietnam',
            10.8188, 106.6519),
    'SYD': ('Kingsford Smith', 'Sydney', 'Australia', -33.9399, 151.1753),
    'MEL': ('Melbourne', 'Melbourne', 'Australia', -37.6690, 144.8410),
    'BNE': ('Brisbane', 'Brisbane', 'Australia', -27.3842, 153.1175),
    'PER': ('Perth', 'Perth', 'Australia', -31.9403, 115.9669),
    'AKL': ('Auckland', 'Auckland', 'New Zealand', -37.0082, 174.7850),
    'NAN': ('Nadi International', 'Nadi', 'Fiji', -17.7554, 177.4434),
}


# ---------------------------------------------------------------------------
# Small parsing helpers shared by the readers
# ---------------------------------------------------------------------------

def _flight_text(value: Any) -> str:
    """
    Coerce ``'ua 1'``, ``'ba-2490'`` or a bare designator into the canonical
    uppercase form; ``''`` when unparseable.

    Readers accept the raw tracker input so they stay usable standalone
    (notebooks, plugins, quick shell experiments).
    """
    return normalize_flight(str(value or ''))


def _load_airline_pack() -> Tuple[Dict[str, Tuple[str, str, str, str]],
                                  Dict[str, str]]:
    """
    Parse the shipped airline pack into IATA and ICAO lookup indexes.

    The pack is a plain-text file at ``obscuralens/data/airlines_iata.txt``
    with one ``IATA|ICAO|name|country|callsign`` entry per line,
    ``#``-comments and blank lines ignored, compiled from the public IATA
    airline coding directory and ICAO Doc 8585 designators (134 curated
    entries). It is parsed directly (not via ``load_data_pack``) because
    airline names and callsigns are case-sensitive - "SPEEDBIRD" and "All
    Nippon Airways" must survive - and cached at module level for the
    process lifetime. A missing or unreadable pack yields empty indexes
    without raising and without caching, so a later call can retry after
    the file is fixed.
    """
    global _AIRLINE_CACHE
    if _AIRLINE_CACHE is not None:
        return _AIRLINE_CACHE

    by_iata: Dict[str, Tuple[str, str, str, str]] = {}
    icao_to_iata: Dict[str, str] = {}
    path: Path = DATA_DIR / 'airlines_iata.txt'
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, ValueError):  # OSError + UnicodeDecodeError
        return by_iata, icao_to_iata

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split('|')
        if len(parts) != 5:
            continue
        iata = parts[0].strip().upper()
        icao = parts[1].strip().upper()
        name = parts[2].strip()
        country = parts[3].strip()
        callsign = parts[4].strip()
        if not (2 <= len(iata) <= 3 and iata.isalnum() and name):
            continue
        by_iata.setdefault(iata, (icao, name, country, callsign))
        if len(icao) == 3 and icao.isalpha():
            icao_to_iata.setdefault(icao, iata)
    _AIRLINE_CACHE = (by_iata, icao_to_iata)
    return _AIRLINE_CACHE


def _lookup_airline(carrier: str) -> Optional[Tuple[str, str, str, str, str]]:
    """
    Resolve a 2- or 3-letter carrier code through the airline pack.

    Returns ``(iata, icao, name, country, callsign)`` with whichever code was
    NOT queried derived from the pack, or ``None`` when the pack misses the
    carrier (a miss is an expected outcome for a curated subset, not an
    error).
    """
    by_iata, icao_to_iata = _load_airline_pack()
    code = (carrier or '').strip().upper()
    if len(code) == 2:
        entry = by_iata.get(code)
        if not entry:
            return None
        icao, name, country, callsign = entry
        return code, icao, name, country, callsign
    if len(code) == 3:
        iata = icao_to_iata.get(code)
        if iata:
            icao, name, country, callsign = by_iata[iata]
            return iata, icao, name, country, callsign
        # Three-letter codes with no ICAO pack entry may still be a genuine
        # IATA designator carried in the IATA index (rare 3-letter IATA
        # codes such as TOM exist in the pack itself).
        entry = by_iata.get(code)
        if entry:
            icao, name, country, callsign = entry
            return code, icao, name, country, callsign
        return None
    return None


# ---------------------------------------------------------------------------
# Source readers: each returns a normalised dict, or {} on failure.
# ---------------------------------------------------------------------------

def _airline_pack(flight_value: Any) -> Dict[str, Any]:
    """
    Offline curated airline pack lookup: the airline behind the carrier code.

    The pack carries 134 hand-curated airlines (the carriers an OSINT
    operator actually meets, plus historically important ones that still
    appear in old records) with names, countries and radio callsigns in
    their registry casing. A miss means "not in this curated subset", NOT
    "unknown airline" - several thousand designators exist and only
    well-documented ones ship; ``flight_math`` still decomposes the
    designator either way.
    """
    flight = _flight_text(flight_value)
    parts = split_flight(flight)
    if not parts:
        return {}

    carrier = parts[0]
    resolved = _lookup_airline(carrier)
    if not resolved:
        # A miss is an EXPECTED outcome for a curated subset (134 of several
        # thousand designators), not a pack failure: answer with an explicit
        # "no airline name" instead of {} so source health records the
        # execution as OK and the circuit breaker never trips on misses.
        return {'airline_name': None}

    iata, icao, name, country, callsign = resolved
    out: Dict[str, Any] = {'airline_name': name[:_MAX_AIRLINE_CHARS]}
    if iata:
        out['airline_iata'] = iata
    if icao:
        out['airline_icao'] = icao
    if country:
        out['country'] = country
    if callsign:
        out['callsign'] = callsign
    return out


def _flight_math(flight_value: Any) -> Dict[str, Any]:
    """
    Pure-Python designator anatomy - the always-available offline half.

    Derives everything the designator itself encodes:

    * ``carrier_code``       - the 2/3-letter carrier code as written.
    * ``carrier_code_type``  - ``'IATA'`` (2 letters) or ``'ICAO'`` (3).
    * ``flight_number_digits``- the numeric run without leading zeros (int).
    * ``digit_count``        - length of the numeric run.
    * ``suffix_letter``      - the optional trailing letter, when present.
    * ``flight_iata_code``   - IATA rendering, e.g. ``'UA1'``.
    * ``flight_icao_code``   - ICAO rendering, e.g. ``'UAL1'`` (only when
                               the airline pack resolves the carrier).
    * ``radio_callsign``     - the ``{ICAO}{number}`` radio form, e.g.
                               ``'BAW2490'`` (only when resolvable).
    * ``direction_hint``     - odd/even convention note (a convention used
                               by many airlines for outbound vs return
                               legs - explicitly not evidence).
    * ``number_band_hint``   - number-band convention note (1-499 daytime
                               services, 500-899 late-night/red-eye,
                               900+ supplemental sections at many
                               airlines - a convention, not evidence).
    """
    flight = _flight_text(flight_value)
    parts = split_flight(flight)
    if not parts:
        return {}

    carrier, number, suffix = parts
    digits = int(number)
    out: Dict[str, Any] = {
        'carrier_code': carrier,
        'carrier_code_type': 'IATA' if len(carrier) == 2 else 'ICAO',
        'flight_number_digits': digits,
        'digit_count': len(number),
        'direction_hint': (
            'odd flight number - outbound/first leg under the common '
            'airline numbering convention (convention only, not evidence)'
            if digits % 2 else
            'even flight number - return/continuation leg under the common '
            'airline numbering convention (convention only, not evidence)'),
    }
    if suffix:
        out['suffix_letter'] = suffix

    resolved = _lookup_airline(carrier)
    if resolved:
        iata, icao, _name, _country, _callsign = resolved
        if iata:
            out['flight_iata_code'] = f"{iata}{number}{suffix}"
        if icao:
            out['flight_icao_code'] = f"{icao}{number}{suffix}"
            out['radio_callsign'] = f"{icao}{number}"
    elif len(carrier) == 2:
        # Unresolved 2-letter carrier: the IATA rendering is still the
        # designator itself, which is worth echoing back.
        out['flight_iata_code'] = f"{carrier}{number}{suffix}"

    if 1 <= digits <= 499:
        out['number_band_hint'] = (
            'number 1-499 - daytime/mainline services at many airlines '
            '(common convention, not evidence)')
    elif 500 <= digits <= 899:
        out['number_band_hint'] = (
            'number 500-899 - late-night/red-eye services at many airlines '
            '(common convention, not evidence)')
    else:
        out['number_band_hint'] = (
            'number 900+ - supplemental/extra sections at many airlines '
            '(common convention, not evidence)')
    return out


def _aviationstack(flight_value: Any, key: str) -> Dict[str, Any]:
    """
    aviationstack.com live flight API (keyed): today's operation of a designator.

    Endpoint: ``GET https://api.aviationstack.com/v1/flights?access_key=
    {key}&flight_iata={iata}``. The response carries a ``data`` list whose
    first entry describes the most recent/current rotation: airline name,
    flight status (scheduled/active/landed/cancelled/diverted), departure
    and arrival airports with IATA codes and scheduled times, and the
    aircraft registration. Only runs when a key is configured; failures
    degrade to ``{}`` so the offline sources carry the report.
    """
    flight = _flight_text(flight_value)
    parts = split_flight(flight)
    if not parts or not key:
        return {}

    carrier, number, suffix = parts
    resolved = _lookup_airline(carrier)
    if resolved and resolved[0]:
        iata_number = f"{resolved[0]}{number}{suffix}"
    else:
        iata_number = f"{carrier}{number}{suffix}"

    ok, data, _err = http.get_json(
        'https://api.aviationstack.com/v1/flights'
        f"?access_key={key}&flight_iata={iata_number}")
    if not ok or not isinstance(data, dict):
        return {}
    flights = data.get('data')
    if not isinstance(flights, list) or not flights:
        return {}
    record = flights[0]
    if not isinstance(record, dict):
        return {}

    out: Dict[str, Any] = {}

    def _copy(source: Any, field: str) -> None:
        if isinstance(source, str) and source.strip():
            out[field] = source.strip()[:_MAX_LIVE_CHARS]

    _copy(record.get('flight_status'), 'avstack_status')
    airline = record.get('airline')
    if isinstance(airline, dict):
        _copy(airline.get('name'), 'avstack_airline')
    aircraft = record.get('aircraft')
    if isinstance(aircraft, dict):
        _copy(aircraft.get('reg_number'), 'avstack_aircraft_registration')
    departure = record.get('departure')
    if isinstance(departure, dict):
        _copy(departure.get('airport'), 'avstack_departure_airport')
        _copy(departure.get('iata'), 'avstack_departure_iata')
        _copy(departure.get('scheduled'), 'avstack_departure_scheduled')
    arrival = record.get('arrival')
    if isinstance(arrival, dict):
        _copy(arrival.get('airport'), 'avstack_arrival_airport')
        _copy(arrival.get('iata'), 'avstack_arrival_iata')
        _copy(arrival.get('scheduled'), 'avstack_arrival_scheduled')
    return out


# ---------------------------------------------------------------------------
# v6.1 addition: adsb.lol live ADS-B positions - the first keyless live
# flight source. Probed live before shipping (bbox queries answer live
# aircraft; callsign queries answer a clean empty array when nothing with
# that callsign is airborne).
# ---------------------------------------------------------------------------

#: Live positions go stale in minutes, so the cache TTL is short; the
#: community API rate limits aggressively, which the per-host rate
#: override in core.ratelimit handles politely.
_ADSB_TTL = 60


def _adsb_lol(flight_value: Any) -> Dict[str, Any]:
    """
    adsb.lol community ADS-B API (keyless, v6.1): live position.

    Endpoint: ``https://api.adsb.lol/v2/callsign/{callsign}`` answers the
    aircraft currently broadcasting that callsign: position, barometric
    altitude, ground speed, track heading, registration, type code, squawk
    and seconds since last contact. Both the raw designator and the ICAO
    radio-callsign form (``LH123`` -> ``DLH123``) are tried, because
    airlines mix the two on the wire. Nothing airborne answers a clean
    empty array - reported honestly as ``adsb_currently_airborne: False``
    rather than a source failure, so a landed/scheduled flight still gets
    its offline pack facts with a live "not in the air right now" verdict.

    Fields: ``adsb_currently_airborne``, ``adsb_callsign``,
    ``adsb_registration``, ``adsb_aircraft_type``, ``adsb_altitude_ft``,
    ``adsb_ground_speed_kn``, ``adsb_track_heading``,
    ``adsb_latitude`` / ``adsb_longitude``, ``adsb_squawk``,
    ``adsb_last_seen_s``.
    """
    flight = _flight_text(flight_value)
    parts = split_flight(flight)
    if not parts:
        return {}

    carrier, number, suffix = parts
    candidates = [f"{carrier}{number}{suffix}".upper()]
    resolved = _lookup_airline(carrier.upper())
    if resolved and resolved[4]:  # radio callsign from the airline pack
        icao_form = f"{resolved[4]}{number}{suffix}".upper()
        if icao_form not in candidates:
            candidates.append(icao_form)

    freshest: Optional[Dict[str, Any]] = None
    freshest_seen: Optional[float] = None
    any_ok = False
    for callsign in candidates:
        ok, d, _ = http.get_json(
            f"https://api.adsb.lol/v2/callsign/{callsign}",
            cache_ttl=_ADSB_TTL)
        if not ok or not isinstance(d, dict):
            continue
        any_ok = True
        for ac in d.get('ac') or []:
            if not isinstance(ac, dict):
                continue
            seen = ac.get('seen')
            try:
                seen_s = float(seen) if seen is not None else None
            except (TypeError, ValueError):
                seen_s = None
            if freshest is None or (seen_s is not None
                                    and (freshest_seen is None
                                         or seen_s < freshest_seen)):
                freshest = ac
                freshest_seen = seen_s

    if freshest is None:
        if any_ok:
            # The API answered and nothing with that callsign is airborne.
            return {'adsb_currently_airborne': False}
        # Every transport attempt failed - no honest conclusion possible.
        return {}

    out: Dict[str, Any] = {'adsb_currently_airborne': True}
    if freshest.get('flight'):
        out['adsb_callsign'] = str(freshest.get('flight')).strip()
    if freshest.get('r'):
        out['adsb_registration'] = str(freshest.get('r')).strip()
    if freshest.get('t'):
        out['adsb_aircraft_type'] = str(freshest.get('t')).strip()
    if freshest.get('squawk'):
        out['adsb_squawk'] = str(freshest.get('squawk'))
    alt = freshest.get('alt_baro')
    if isinstance(alt, (int, float)) or (isinstance(alt, str) and alt.isdigit()):
        with contextlib.suppress(TypeError, ValueError):
            out['adsb_altitude_ft'] = int(alt)
    if freshest.get('gs') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['adsb_ground_speed_kn'] = round(float(freshest.get('gs')), 1)
    if freshest.get('track') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['adsb_track_heading'] = round(float(freshest.get('track')), 1)
    if freshest.get('lat') is not None and freshest.get('lon') is not None:
        with contextlib.suppress(TypeError, ValueError):
            out['adsb_latitude'] = round(float(freshest.get('lat')), 5)
            out['adsb_longitude'] = round(float(freshest.get('lon')), 5)
    if freshest_seen is not None:
        out['adsb_last_seen_s'] = round(freshest_seen, 1)
    return out


# ---------------------------------------------------------------------------
# Analyst utilities (not registered as sources; imported by tests and tools)
# ---------------------------------------------------------------------------

def lookup_airport(code: Any) -> Optional[Dict[str, Any]]:
    """
    Look up one of the built-in major-hub airports by IATA code.

    Args:
        code: three-letter IATA airport code, any casing (``'JFK'``).

    Returns:
        ``{'iata', 'name', 'city', 'country', 'latitude', 'longitude'}`` for
        the ~60 global hubs in the built-in table, ``None`` for everything
        else. Never raises.

    Example:
        lookup_airport('JFK')['city']    # 'New York'
    """
    if not isinstance(code, str):
        return None
    entry = _AIRPORTS.get(code.strip().upper())
    if not entry:
        return None
    name, city, country, lat, lon = entry
    return {'iata': code.strip().upper(), 'name': name, 'city': city,
            'country': country, 'latitude': lat, 'longitude': lon}


def airport_distance(iata_one: Any, iata_two: Any) -> Optional[float]:
    """
    Great-circle distance in kilometres between two known hub airports.

    Reuses :func:`obscuralens.utils.coordinate_math.haversine_km` (the same
    WGS-84 great-circle implementation the coordinates tracker uses) rather
    than a second formula. Unknown airport codes yield ``None``; the same
    airport twice yields ``0.0``. Never raises.

    Example:
        airport_distance('JFK', 'LHR')    # ~5540 km
    """
    first = lookup_airport(iata_one)
    second = lookup_airport(iata_two)
    if not first or not second:
        return None
    return round(haversine_km(first['latitude'], first['longitude'],
                              second['latitude'], second['longitude']), 1)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FREE_SOURCES: Dict[str, Any] = {
    'airline_pack': _airline_pack,
    'flight_math': _flight_math,
    'adsb_lol': _adsb_lol,
}

# aviationstack needs an API key (free tier exists); the reader takes
# (value, key) and is dispatched through the key map in gather_all.
KEYED_SOURCES: Dict[str, Any] = {
    'aviationstack': _aviationstack,
}

# Human-readable metadata used by `obscuralens sources` and the README.
SOURCE_CATALOG = {
    'airline_pack': ('Offline curated airline pack '
                     '(obscuralens/data/airlines_iata.txt): name, country, callsign'),
    'flight_math': ('Offline designator anatomy: IATA/ICAO renderings, radio '
                    'callsign, direction and band conventions'),
    'adsb_lol': ('Live ADS-B position, altitude, speed and aircraft via the '
                 'adsb.lol community API (keyless; v6.1)'),
    'aviationstack': 'aviationstack.com live status, airports and aircraft (API key)',
}


def _keep(value: Any) -> bool:
    # A flight whose carrier resolved to nothing (airline_name == None is
    # filtered below) still has a real direction hint, so only None / '' /
    # [] / {} count as "no data". Pack readers use an explicit None value
    # as the "ran fine, nothing curated" marker, which this same rule
    # filters out of the merged fields.
    return value is not None and value != '' and value != [] and value != {}


def _plugin_sources(kind: str) -> Dict[str, Any]:
    """Extra sources contributed by user plugins (lazy import avoids cycles)."""
    try:
        from .. import plugins
    except ImportError:
        return {}
    getter = getattr(plugins, 'plugin_sources_named', None) or plugins.plugin_sources
    return getter(kind)


def gather_all(flight_value: Any, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Query every applicable flight source in parallel and merge the results.

    Args:
        flight_value: flight designator such as ``'UA1'``, ``'BA2490'`` or
            ``'DLH400A'``; spaces, hyphens and lower case are tolerated
        keys: optional {service: api_key} map - ``{'aviationstack': key}``
            unlocks the keyed live-flight source

    Returns:
        {
          'fields': merged_field_dict (always includes 'flight'),
          'sources': {name: {'ok': bool, 'error': str}},
          'provenance': {field: [source, ...]},
        }

    Raises:
        ValueError: when the value does not parse as a flight designator.
    """
    keys = keys or {}
    flight = _flight_text(flight_value)
    if not flight:
        raise ValueError(f"invalid flight designator: {flight_value!r}")

    tasks: Dict[str, Any] = {}

    for name, fn in FREE_SOURCES.items():
        if config.is_source_enabled(name) and health.source_allowed(name):
            tasks[name] = (lambda f=fn: f(flight))

    for name, fn in _plugin_sources('flight').items():
        source_name = f"plugin:{name}"
        if config.is_source_enabled(source_name) and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=fn: f(flight))

    key_map = {
        'aviationstack': ('aviationstack', lambda k: _aviationstack(flight, k)),
    }
    for service, (source_name, factory) in key_map.items():
        key = keys.get(service)
        if key and config.is_source_enabled(source_name) \
                and health.source_allowed(source_name):
            tasks[source_name] = (lambda f=factory, k=key: f(k))

    results: Dict[str, Dict[str, Any]] = {}
    status: Dict[str, Dict[str, Any]] = {}

    if tasks:
        with futures.ThreadPoolExecutor(max_workers=fanout_workers(len(tasks))) as ex:
            future_map = {ex.submit(fn): name for name, fn in tasks.items()}
            for future in futures.as_completed(future_map):
                name = future_map[future]
                try:
                    data = future.result() or {}
                    results[name] = data
                    status[name] = {'ok': bool(data), 'error': '' if data else 'no data'}
                except Exception as e:  # a broken source must not kill the scan
                    results[name] = {}
                    status[name] = {'ok': False, 'error': type(e).__name__}

    health.record_batch('flight', status)

    merged: Dict[str, Any] = {}
    provenance: Dict[str, List[str]] = {}

    # Source order sets priority for conflicting values; earlier wins, so
    # the shipped curated pack beats the live API mirror on conflict.
    for name in tasks:
        for key, value in (results.get(name) or {}).items():
            if not _keep(value):
                continue
            provenance.setdefault(key, []).append(name)
            merged.setdefault(key, value)

    # The identifier itself is part of the answer, whatever the sources did:
    # the canonical uppercase designator every consumer expects.
    merged['flight'] = flight

    return {'fields': merged, 'sources': status, 'provenance': provenance}
