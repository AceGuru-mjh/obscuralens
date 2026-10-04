"""
Offline tests for obscuralens.utils.coordinate_math (pure maths, zero network).

Focus: round-trips (UTM / MGRS / geohash), known-value anchors, formatting
(DMS / DDM / Maidenhead), solar geometry, the parsing front doors and the
private guard helpers reached through the public API. All expected values
were either hand-derived (bit-by-bit for geohash / Maidenhead), taken from
published reference values (Eiffel Tower / Sydney UTM, quarter-circumference
haversine) or are self-consistency properties documented per test.
"""

import math
import re
from datetime import datetime, timedelta, timezone

import pytest

from obscuralens.utils import coordinate_math as cm
from obscuralens.utils.coordinate_math import (
    band_latitude_range,
    bbox_around,
    dms_parts,
    estimate_timezone_offset,
    geohash_bbox,
    geohash_to_latlon,
    haversine_km,
    latitude_band,
    latlon_to_ddm,
    latlon_to_dms,
    latlon_to_geohash,
    latlon_to_maidenhead,
    latlon_to_mgrs,
    latlon_to_utm,
    mgrs_to_latlon,
    parse_mgrs_string,
    parse_utm_string,
    solar_position,
    utm_to_latlon,
)

# Reference points used across the round-trip suites: both hemispheres,
# zone-boundary longitudes, high latitude (Svalbard), polar-edge latitudes.
ROUND_TRIP_POINTS = [
    (0.0, 0.0),
    (0.0, 3.0),
    (48.8584, 2.2945),     # Paris / Eiffel Tower (zone 31U)
    (-33.8688, 151.2093),  # Sydney (southern hemisphere, zone 56H)
    (51.5074, -0.1278),    # London (zone 30U, negative offset from meridian)
    (35.6762, 139.6503),   # Tokyo (zone 54S)
    (-54.8019, -68.3030),  # Ushuaia (zone 19F)
    (60.0, 8.0),           # Norway exception territory edge (zone 32V)
    (78.2232, 15.6267),    # Svalbard (zone 33X through the exception)
    (-79.5, 45.0),         # Antarctica edge (band C)
    (83.5, 20.0),          # band X (high Arctic)
    (-0.001, -0.001),      # a hair south/west of the null island
]


# --------------------------------------------------------------- guard rails

class TestGuardHelpers:

    def test_clamp(self):
        assert cm._clamp(-5.0, 0.0, 1.0) == 0.0
        assert cm._clamp(0.5, 0.0, 1.0) == 0.5
        assert cm._clamp(9.0, 0.0, 1.0) == 1.0
        assert cm._clamp(-1.0, -2.0, 2.0) == -1.0

    def test_wrap_longitude_rule(self):
        # Actual rule: normalise into [-180, 180); +180 maps to -180.
        assert cm._wrap_longitude(181.0) == -179.0
        assert cm._wrap_longitude(-181.0) == 179.0
        assert cm._wrap_longitude(180.0) == -180.0
        assert cm._wrap_longitude(-180.0) == -180.0
        assert cm._wrap_longitude(0.0) == 0.0
        assert cm._wrap_longitude(360.0) == 0.0
        assert cm._wrap_longitude(540.0) == -180.0

    def test_finite_latlon_happy_path_coerces_strings_and_bools(self):
        assert cm._finite_latlon(1, 2) == (1.0, 2.0)
        assert cm._finite_latlon('1.5', '-2.5') == (1.5, -2.5)
        # Bools are ints in Python and coerce to 1.0 / 0.0 (observed rule).
        assert cm._finite_latlon(True, False) == (1.0, 0.0)

    @pytest.mark.parametrize('lat,lon', [
        ('x', 0), (None, 0), (0, 'y'), (0, None), ([], 0),
        (float('nan'), 0), (0, float('nan')),
        (float('inf'), 0), (0, float('-inf')),
        (91.0, 0), (-91.0, 0), (0, 181.0), (0, -181.0),
    ])
    def test_finite_latlon_rejects_junk(self, lat, lon):
        with pytest.raises(ValueError):
            cm._finite_latlon(lat, lon)

    def test_finite_latlon_error_messages(self):
        with pytest.raises(ValueError, match='non-numeric'):
            cm._finite_latlon('x', 0)
        with pytest.raises(ValueError, match='finite'):
            cm._finite_latlon(float('nan'), 0)
        with pytest.raises(ValueError, match='latitude out of range'):
            cm._finite_latlon(91, 0)
        with pytest.raises(ValueError, match='longitude out of range'):
            cm._finite_latlon(0, 181)

    def test_coerce_zone(self):
        assert cm._coerce_zone(31) == 31
        assert cm._coerce_zone('31') == 31
        assert cm._coerce_zone(31.0) == 31
        assert cm._coerce_zone(' 60 ') == 60

    @pytest.mark.parametrize('zone', [0, -1, 61, 99, '0', '61', 'zz', None, 'x', [1]])
    def test_coerce_zone_rejects_out_of_range_and_junk(self, zone):
        with pytest.raises(ValueError):
            cm._coerce_zone(zone)


# ------------------------------------------------------------ latitude bands

class TestLatitudeBands:

    def test_latitude_band_edges(self):
        # Bands are 8 degrees wide starting at -80; X is stretched to 72-84.
        assert latitude_band(-80.0) == 'C'
        assert latitude_band(-79.9) == 'C'
        assert latitude_band(-72.0) == 'D'
        assert latitude_band(0.0) == 'N'
        assert latitude_band(-0.001) == 'M'
        assert latitude_band(8.0) == 'P'
        assert latitude_band(72.0) == 'X'
        assert latitude_band(84.0) == 'X'

    def test_latitude_band_matches_each_band_start(self):
        letters = 'CDEFGHJKLMNPQRSTUVW'
        for index, letter in enumerate(letters):
            assert latitude_band(-80.0 + 8.0 * index) == letter
        assert latitude_band(-80.0 + 8.0 * 19) == 'X'

    @pytest.mark.parametrize('lat', [-80.1, -91, 84.1, 90])
    def test_latitude_band_out_of_grid_raises(self, lat):
        with pytest.raises(ValueError, match='outside the UTM grid range'):
            latitude_band(lat)

    def test_band_latitude_range_x_is_special_cased(self):
        assert band_latitude_range('X') == (72.0, 84.0)
        assert band_latitude_range('x') == (72.0, 84.0)

    def test_band_latitude_range_case_and_whitespace_tolerant(self):
        assert band_latitude_range(' n ') == band_latitude_range('N')

    @pytest.mark.parametrize('band', ['I', 'O', 'A', 'B', 'Y', 'Z', 'AB'])
    def test_band_latitude_range_invalid_letters_raise(self, band):
        with pytest.raises(ValueError, match='invalid UTM band letter'):
            band_latitude_range(band)

    def test_band_latitude_range_empty_band_falls_through_to_c(self):
        # Observed quirk: str.find('') == 0, so an empty/None band resolves to
        # band C's range instead of raising (kept as a pinned behaviour).
        assert band_latitude_range('') == band_latitude_range('C')
        assert band_latitude_range(None) == band_latitude_range('C')

    def test_band_latitude_range_documented_off_by_eight_bug(self):
        # KNOWN BUG (documented, NOT fixed per task rules): every non-X band
        # returns an upper bound eight degrees too high. 'C' covers -80..-72
        # (latitude_band agrees) but band_latitude_range('C') returns
        # (-80, -64); 'N' should be (0, 8) but returns (0, 16). The X
        # special case above is correct. These assertions pin the CURRENT
        # behaviour so a future fix has to flip them deliberately.
        assert band_latitude_range('C') == (-80.0, -64.0)
        assert band_latitude_range('N') == (0.0, 16.0)
        assert band_latitude_range('W') == (64.0, 80.0)

    def test_band_latitude_range_lower_bounds_stay_correct(self):
        # The lower bound of each band is unaffected by the bug above.
        for index, letter in enumerate('CDEFGHJKLMNPQRSTUVW'):
            assert band_latitude_range(letter)[0] == -80.0 + 8.0 * index


# ------------------------------------------------------------------ UTM zone

class TestZoneOf:

    def test_basic_six_degree_bands(self):
        assert cm._zone_of(0, -180.0) == 1
        assert cm._zone_of(0, -174.0) == 2
        assert cm._zone_of(0, -6.0) == 30
        assert cm._zone_of(0, 0.0) == 31
        assert cm._zone_of(0, 5.999) == 31
        assert cm._zone_of(0, 6.0) == 32
        assert cm._zone_of(0, 174.0) == 60
        assert cm._zone_of(0, 179.999) == 60

    def test_zone_boundaries_sweep(self):
        for k in range(0, 60):
            lon = -180.0 + 6.0 * k
            assert cm._zone_of(0.0, lon) == k + 1
            assert cm._zone_of(0.0, lon + 5.999) == k + 1

    def test_norway_exception(self):
        # 56-64N / 3-12E is forced into zone 32V.
        assert cm._zone_of(56.0, 3.0) == 32
        assert cm._zone_of(63.9, 11.9) == 32
        assert cm._zone_of(55.9, 5.0) == 31   # just south of the exception
        assert cm._zone_of(64.0, 5.0) == 31   # at/above 64 the exception ends
        assert cm._zone_of(60.0, 2.999) == 31
        assert cm._zone_of(60.0, 12.0) == 33

    def test_svalbard_exception(self):
        assert cm._zone_of(72.0, 0.0) == 31
        assert cm._zone_of(78.0, 8.9) == 31
        assert cm._zone_of(78.0, 9.0) == 33
        assert cm._zone_of(78.0, 20.9) == 33
        assert cm._zone_of(78.0, 21.0) == 35
        assert cm._zone_of(78.0, 32.9) == 35
        assert cm._zone_of(78.0, 33.0) == 37
        assert cm._zone_of(78.0, 41.9) == 37
        assert cm._zone_of(78.0, 42.0) == 38    # past the exception: (42+180)//6+1
        assert cm._zone_of(71.9, 10.0) == 32   # below Svalbard latitudes


# ------------------------------------------------------------- UTM forward

class TestUtmForward:

    def test_published_anchor_central_meridian(self):
        # lat 0 / lon 3 is the central meridian of zone 31: easting exactly
        # the false easting, northing exactly zero (hand-derivable).
        zone, band, easting, northing = latlon_to_utm(0.0, 3.0)
        assert zone == 31
        assert band == 'N'
        assert easting == pytest.approx(500000.0, abs=0.05)
        assert northing == pytest.approx(0.0, abs=0.05)

    def test_published_anchor_eiffel_tower(self):
        # Published UTM for the Eiffel Tower: 31U 448252 E, 5411955 N.
        zone, band, easting, northing = latlon_to_utm(48.8584, 2.2945)
        assert zone == 31
        assert band == 'U'
        assert easting == pytest.approx(448252.0, abs=5.0)
        assert northing == pytest.approx(5411955.0, abs=5.0)

    def test_published_anchor_sydney(self):
        # Sydney Opera House: zone 56H, ~334368 E, ~6250948 N (southern
        # hemisphere northing carries the +10,000,000 offset).
        zone, band, easting, northing = latlon_to_utm(-33.8688, 151.2093)
        assert zone == 56
        assert band == 'H'
        assert easting == pytest.approx(334368.0, abs=5.0)
        assert 0.0 < northing < 10000000.0
        assert northing == pytest.approx(6250948.0, abs=5.0)

    def test_southern_hemisphere_offset_is_applied(self):
        north_zone, _, _, north_northing = latlon_to_utm(1.0, 3.0)
        south_zone, _, _, south_northing = latlon_to_utm(-1.0, 3.0)
        assert north_northing < 200000.0
        assert south_northing > 9800000.0  # 10,000,000 - ~110 km

    def test_zone_and_band_exceptions_in_output(self):
        assert latlon_to_utm(60.0, 5.0)[0] == 32      # Norway exception
        assert latlon_to_utm(60.0, 5.0)[1] == 'V'
        assert latlon_to_utm(78.0, 10.0)[0] == 33     # Svalbard exception
        assert latlon_to_utm(78.0, 10.0)[1] == 'X'
        assert latlon_to_utm(70.0, -150.0)[0] == 6    # single-digit zone

    @pytest.mark.parametrize('lat,lon', [(85.0, 0.0), (-81.0, 0.0), (90.0, 0.0)])
    def test_out_of_grid_raises(self, lat, lon):
        with pytest.raises(ValueError, match='outside the UTM grid range'):
            latlon_to_utm(lat, lon)

    @pytest.mark.parametrize('lat,lon', [('x', 0), (0, float('nan')), (91, 0), (0, 200)])
    def test_input_validation_raises(self, lat, lon):
        with pytest.raises(ValueError):
            latlon_to_utm(lat, lon)


# ------------------------------------------------------------- UTM round-trip

class TestUtmRoundTrip:

    @pytest.mark.parametrize('lat,lon', ROUND_TRIP_POINTS)
    def test_round_trip_accuracy(self, lat, lon):
        zone, band, easting, northing = latlon_to_utm(lat, lon)
        back_lat, back_lon = utm_to_latlon(zone, easting, northing,
                                           northern=lat >= 0.0)
        assert back_lat == pytest.approx(lat, abs=1e-6)   # ~0.1 m
        assert back_lon == pytest.approx(lon, abs=1e-6)

    @pytest.mark.parametrize('zone', list(range(1, 61)))
    def test_every_zone_on_the_equator(self, zone):
        # Central meridian of each zone; equator keeps the NATO exceptions off.
        lon = (zone - 1) * 6 - 180 + 3
        z, band, easting, northing = latlon_to_utm(0.0, lon)
        assert z == zone
        assert band == 'N'
        assert easting == pytest.approx(500000.0, abs=1.0)
        assert northing == pytest.approx(0.0, abs=1.0)
        back_lat, back_lon = utm_to_latlon(z, easting, northing, northern=True)
        assert back_lat == pytest.approx(0.0, abs=1e-9)
        assert back_lon == pytest.approx(lon, abs=1e-9)

    def test_zone_edge_accuracy(self):
        # 3 degrees off the central meridian: series error stays centimetres.
        for zone in (1, 17, 31, 45, 60):
            lon = (zone - 1) * 6 - 180 + 3
            _, _, easting, northing = latlon_to_utm(45.0, lon + 2.999)
            back_lat, back_lon = utm_to_latlon(zone, easting, northing)
            assert back_lat == pytest.approx(45.0, abs=1e-6)
            assert back_lon == pytest.approx(lon + 2.999, abs=1e-6)

    def test_high_latitude_round_trip(self):
        for lat in (-79.9, -60.0, 60.0, 79.9, 83.9):
            zone, _, easting, northing = latlon_to_utm(lat, 20.0)
            back_lat, _ = utm_to_latlon(zone, easting, northing, northern=lat >= 0)
            assert back_lat == pytest.approx(lat, abs=1e-6)


# ------------------------------------------------------------- UTM inverse

class TestUtmInverse:

    def test_zone_coercion(self):
        lat, lon = utm_to_latlon('31', 448252.0, 5411955.0)
        assert lat == pytest.approx(48.858, abs=0.01)
        assert lon == pytest.approx(2.294, abs=0.01)
        lat2, lon2 = utm_to_latlon(31.0, 448252.0, 5411955.0)
        assert (lat2, lon2) == (lat, lon)

    def test_southern_flag(self):
        # Same grid numbers, opposite hemispheres: only the flag differs.
        north = utm_to_latlon(56, 334368.6, 6250948.3, northern=True)
        south = utm_to_latlon(56, 334368.6, 6250948.3, northern=False)
        assert north[0] == pytest.approx(56.37, abs=0.01)
        assert south[0] == pytest.approx(-33.868, abs=0.01)  # 10,000,000 m offset
        assert south[1] == pytest.approx(151.209, abs=0.01)  # Sydney longitude
        assert 150.0 < north[1] < 156.0                       # still inside zone 56

    @pytest.mark.parametrize('zone,easting,northing', [
        ('zz', 500000, 0), (None, 500000, 0), (0, 500000, 0), (61, 500000, 0),
        (31, 'a', 0), (31, 500000, 'b'),
    ])
    def test_invalid_inputs_raise(self, zone, easting, northing):
        with pytest.raises(ValueError):
            utm_to_latlon(zone, easting, northing)


# ------------------------------------------------------------------- MGRS

class TestMgrsForward:

    def test_known_reference_paris(self):
        assert latlon_to_mgrs(48.8584, 2.2945) == '31U DQ 48252 11954'

    def test_known_reference_sydney(self):
        assert latlon_to_mgrs(-33.8688, 151.2093) == '56H LH 34368 50948'

    def test_precision_ladder(self):
        refs = [latlon_to_mgrs(48.8584, 2.2945, p) for p in range(1, 6)]
        assert refs == [
            '31U DQ 4 1', '31U DQ 48 11', '31U DQ 482 119',
            '31U DQ 4825 1195', '31U DQ 48252 11954',
        ]

    def test_precision_is_clamped(self):
        assert latlon_to_mgrs(48.8584, 2.2945, 0) == latlon_to_mgrs(48.8584, 2.2945, 1)
        assert latlon_to_mgrs(48.8584, 2.2945, 9) == latlon_to_mgrs(48.8584, 2.2945, 5)
        assert latlon_to_mgrs(48.8584, 2.2945, -3) == latlon_to_mgrs(48.8584, 2.2945, 1)

    def test_leading_zeros_are_padded(self):
        # Zone 30 / London-ish easting near 0 (30U XC 99889 09362 pattern).
        ref = latlon_to_mgrs(51.5, -0.12)
        east, north = ref.split()[2:]
        assert len(east) == len(north) == 5
        assert ref == '30U XC 99889 09362'

    def test_column_sets_per_zone_remainder(self):
        assert cm._mgrs_column_set(1) == 'ABCDEFGH'    # z % 3 == 1
        assert cm._mgrs_column_set(2) == 'JKLMNPQR'    # z % 3 == 2
        assert cm._mgrs_column_set(3) == 'STUVWXYZ'    # z % 3 == 0
        assert cm._mgrs_column_set(60) == 'STUVWXYZ'
        assert cm._mgrs_column_set(31) == 'ABCDEFGH'

    def test_offsets_string_vs_int_reconciliation(self):
        # Strings keep zero padding: 5-digit precision for both.
        assert cm._mgrs_offsets('07350', '083') == (7350.0, 83.0)
        # Ints lost the padding: the longer digit count wins for both.
        assert cm._mgrs_offsets(7350, 83) == (73500.0, 830.0)
        # A 5-digit int pair reads at metre precision directly.
        assert cm._mgrs_offsets(83959, 7350) == (83959.0, 7350.0)
        # Single digits scale to 10 km cells.
        assert cm._mgrs_offsets('1', '2') == (10000.0, 20000.0)

    def test_offsets_reject_junk(self):
        with pytest.raises(ValueError, match='non-numeric MGRS offsets'):
            cm._mgrs_offsets('x', 'y')
        with pytest.raises(ValueError, match='non-numeric MGRS offsets'):
            cm._mgrs_offsets(None, '1')


class TestMgrsRoundTrip:

    @pytest.mark.parametrize('lat,lon', ROUND_TRIP_POINTS + [
        (60.0, 8.0), (10.0, -160.0), (45.0, 175.0), (0.0, -180.0),
    ])
    @pytest.mark.parametrize('precision', [1, 2, 3, 4, 5])
    def test_round_trip_within_cell(self, lat, lon, precision):
        reference = latlon_to_mgrs(lat, lon, precision)
        head, square, east, north = reference.split()
        zone, band = int(head[:-1]), head[-1]
        back_lat, back_lon = mgrs_to_latlon(zone, band, square, east, north)
        # A reference denotes the south-west corner of its cell: the decode
        # must land within ~1.5 cell widths of the original point. Longitude
        # error is measured on the wrapped arc so antimeridian decodes that
        # drift past -180 by a fraction of a cell still compare correctly.
        cell_metres = 10.0 ** (5 - precision) * 1000.0
        if not -180.0 <= back_lon <= 180.0:
            back_lon = cm._wrap_longitude(back_lon)
        assert haversine_km(lat, lon, back_lat, back_lon) * 1000.0 < 1.5 * cell_metres

    @pytest.mark.parametrize('lat,lon', ROUND_TRIP_POINTS)
    def test_round_trip_metre_precision(self, lat, lon):
        reference = latlon_to_mgrs(lat, lon, 5)
        head, square, east, north = reference.split()
        zone, band = int(head[:-1]), head[-1]
        back_lat, back_lon = mgrs_to_latlon(zone, band, square, east, north)
        assert haversine_km(lat, lon, back_lat, back_lon) * 1000.0 < 2.5

    def test_zone_coercion_and_case_tolerance(self):
        lat, lon = mgrs_to_latlon('31', 'u', 'dq', '48252', '11954')
        assert lat == pytest.approx(48.858, abs=0.01)
        assert lon == pytest.approx(2.294, abs=0.01)

    def test_int_offsets_with_lost_padding(self):
        # The documented '83959 07350' case: int 7350 reads as '7350', whose
        # 4 digits are zero-padded to the easting's 5 -> 7350 metres, so the
        # int form decodes to exactly the string form '83959 07350'.
        from_ints = mgrs_to_latlon(31, 'U', 'DQ', 83959, 7350)
        from_strings = mgrs_to_latlon(31, 'U', 'DQ', '83959', '07350')
        assert from_ints[0] == pytest.approx(from_strings[0], abs=1e-6)
        assert from_ints[1] == pytest.approx(from_strings[1], abs=1e-6)
        _, _, easting, _ = latlon_to_utm(*from_ints)
        assert easting == pytest.approx(483959.0, abs=1.0)

    def test_mismatched_band_returns_closest_cycle(self):
        # A wrong band letter never raises: when no row cycle lands inside
        # the band window the decoder falls back to the cycle closest to the
        # band midpoint (observed rule). Zone 31 / band N / square AV decodes
        # to ~17.6N, the closest solution to band N's midpoint.
        lat, lon = mgrs_to_latlon(31, 'N', 'AV', 50000, 50000)
        assert lat == pytest.approx(17.61, abs=0.2)
        assert lon == pytest.approx(-0.3, abs=0.2)
        # And a deep-south variant for band G.
        lat_g, lon_g = mgrs_to_latlon(31, 'G', 'AF', 50000, 50000)
        assert lat_g == pytest.approx(-31.13, abs=0.2)
        assert -1.5 < lon_g < 0.5

    def test_negative_offsets_skip_out_of_range_cycles(self):
        # Negative offsets (junk input) push the first cycle below zero and
        # are skipped; the decode still resolves through the closest cycle.
        lat, lon = mgrs_to_latlon(1, 'X', 'AA', '-99999', '-99999')
        assert 70.0 < lat < 72.0

    def test_row_letter_raise_is_unreachable_defensive_code(self):
        # The 'cannot be placed in band' ValueError (docstring mentions it)
        # is mathematically unreachable: every row letter produces five
        # candidates inside [0, 10,000,000] m and the closest-cycle fallback
        # always fires first. Sweeping bands x row letters must never raise.
        for zone in (1, 2, 31, 33, 56):
            column_set = cm._mgrs_column_set(zone)
            for band in ('C', 'G', 'N', 'W', 'X'):
                for row in ('A', 'C', 'F', 'Q', 'V'):
                    square = column_set[0] + row
                    lat, lon = mgrs_to_latlon(zone, band, square, 50000, 50000)
                    assert -200.0 <= lat <= 100.0
                    assert -300.0 <= lon <= 300.0

    @pytest.mark.parametrize('args,match', [
        ((61, 'U', 'DQ', 1, 1), 'UTM zone out of range'),
        ((31, 'I', 'DQ', 1, 1), 'invalid MGRS band letter'),
        ((31, 'U', 'D', 1, 1), 'MGRS square must be two letters'),
        ((31, 'U', 'ZZ', 1, 1), 'invalid MGRS column letter'),
        ((31, 'U', 'DI', 1, 1), 'invalid MGRS row letter'),
        ((31, 'U', 'DQ', 'x', 1), 'non-numeric MGRS offsets'),
    ])
    def test_malformed_references_raise_cleanly(self, args, match):
        with pytest.raises(ValueError, match=match):
            mgrs_to_latlon(*args)


# ------------------------------------------------------------- DMS / DDM

class TestDmsFormatting:

    def test_dms_parts_signs_and_ranges(self):
        assert dms_parts(48.8584) == (1, 48, 51, pytest.approx(30.24, abs=0.01))
        assert dms_parts(-48.8584) == (-1, 48, 51, pytest.approx(30.24, abs=0.01))
        assert dms_parts(0.0) == (1, 0, 0, 0.0)
        assert dms_parts(-0.25) == (-1, 0, 15, 0.0)

    def test_dms_parts_minute_second_ranges(self):
        for value in (12.3456, -77.9876, 0.9999, 179.9999):
            sign, degrees, minutes, seconds = dms_parts(value)
            assert sign in (1, -1)
            assert 0 <= minutes <= 59
            assert 0.0 <= seconds < 60.0
            assert degrees == int(abs(value))

    def test_dms_parts_float_drift_guard(self):
        # 59.99999999 deg should print as 60 deg 0' 0.0", not 59°59'60.0".
        assert dms_parts(59.99999999) == (1, 60, 0, 0.0)
        assert dms_parts(48.999999999) == (1, 49, 0, 0.0)
        assert dms_parts(-0.0000001) == (-1, 0, 0, pytest.approx(0.00036, abs=1e-4))

    def test_latlon_to_dms_hemispheres(self):
        assert latlon_to_dms(48.8584) == '48°51\'30.2"N'
        assert latlon_to_dms(-33.86) == '33°51\'36.0"S'
        assert latlon_to_dms(2.2945, 'lon') == '2°17\'40.2"E'
        assert latlon_to_dms(-2.2945, 'lon') == '2°17\'40.2"W'
        assert latlon_to_dms(0.0) == '0°0\'0.0"N'
        assert latlon_to_dms(0.0, 'lon') == '0°0\'0.0"E'

    def test_latlon_to_dms_axis_labels(self):
        for axis in ('lat', 'LAT', ' Lat '):
            assert latlon_to_dms(1.0, axis).endswith('N')
        for axis in ('lon', 'LON', ' Lon '):
            assert latlon_to_dms(1.0, axis).endswith('E')

    @pytest.mark.parametrize('value,axis', [
        (100.0, 'lat'), (-91.0, 'lat'), (181.0, 'lon'), (-181.0, 'lon'),
        (float('nan'), 'lat'), (float('inf'), 'lon'),
    ])
    def test_latlon_to_dms_range_errors(self, value, axis):
        with pytest.raises(ValueError):
            latlon_to_dms(value, axis)

    @pytest.mark.parametrize('axis', ['x', '', None, 'latitude', 5])
    def test_latlon_to_dms_bad_axis(self, axis):
        with pytest.raises(ValueError, match="axis must be 'lat' or 'lon'"):
            latlon_to_dms(1.0, axis)

    def test_latlon_to_ddm_format(self):
        assert latlon_to_ddm(48.8584, 2.2945) == '48° 51.504 N, 2° 17.670 E'
        assert latlon_to_ddm(-33.865, 151.2094) == '33° 51.900 S, 151° 12.564 E'
        assert latlon_to_ddm(0.0, 0.0) == '0° 0.000 N, 0° 0.000 E'
        assert latlon_to_ddm(-1.0, -1.0) == '1° 0.000 S, 1° 0.000 W'

    @pytest.mark.parametrize('lat,lon', [(91, 0), (0, 181), ('x', 0), (float('nan'), 0)])
    def test_latlon_to_ddm_validation(self, lat, lon):
        with pytest.raises(ValueError):
            latlon_to_ddm(lat, lon)


# ----------------------------------------------------------------- geohash

class TestGeohash:

    def test_known_hash_null_island(self):
        # Hand-derived: (0, 0) takes the upper half on the first two bits
        # (bits 1,1,0,0,0 -> index 24 -> 's') then rides the lower-left
        # corner of every subsequent halving, so the tail is all zeros.
        assert latlon_to_geohash(0.0, 0.0) == 's00000000'
        assert latlon_to_geohash(0.0, 0.0)[:3] == 's00'

    def test_known_hash_paris(self):
        # Hand-derived prefix for the Eiffel Tower: bits 11010|00000|01001|...
        # -> 'u', '0', '9', 't'; the module emits 'u09tunquc' at precision 9.
        assert latlon_to_geohash(48.8584, 2.2945)[:4] == 'u09t'
        assert latlon_to_geohash(48.8584, 2.2945) == 'u09tunquc'

    def test_precision_and_clamping(self):
        assert len(latlon_to_geohash(10.0, 10.0)) == 9       # default
        assert len(latlon_to_geohash(10.0, 10.0, 1)) == 1
        assert len(latlon_to_geohash(10.0, 10.0, 12)) == 12
        assert len(latlon_to_geohash(10.0, 10.0, 0)) == 1    # clamped low
        assert len(latlon_to_geohash(10.0, 10.0, 13)) == 12  # clamped high
        assert len(latlon_to_geohash(10.0, 10.0, -5)) == 1

    def test_prefix_monotonicity(self):
        base = latlon_to_geohash(48.8584, 2.2945)
        for precision in range(1, len(base) + 1):
            assert latlon_to_geohash(48.8584, 2.2945, precision) == base[:precision]

    @pytest.mark.parametrize('lat,lon', [(91, 0), (0, 181), ('x', 0), (float('nan'), 0)])
    def test_validation_raises(self, lat, lon):
        with pytest.raises(ValueError):
            latlon_to_geohash(lat, lon)

    def test_bbox_monotone_shrink(self):
        previous = geohash_bbox(latlon_to_geohash(48.85, 2.35, 1))
        for precision in range(2, 10):
            box = geohash_bbox(latlon_to_geohash(48.85, 2.35, precision))
            assert box['south'] >= previous['south']
            assert box['north'] <= previous['north']
            assert box['west'] >= previous['west']
            assert box['east'] <= previous['east']
            previous = box

    def test_bbox_contains_the_encoded_point(self):
        for lat, lon in [(0.0, 0.0), (48.8584, 2.2945), (-33.87, 151.21), (89.9, 179.9)]:
            for precision in (1, 4, 9, 12):
                box = geohash_bbox(latlon_to_geohash(lat, lon, precision))
                assert box['south'] - 1e-9 <= lat <= box['north'] + 1e-9
                assert box['west'] - 1e-9 <= lon <= box['east'] + 1e-9

    def test_bbox_first_cell(self):
        # 's' = bits 11000: longitude and latitude both in their upper half
        # once, then lower halves - the cell [0,45] x [0,45].
        assert geohash_bbox('s') == {'south': 0.0, 'north': 45.0,
                                     'west': 0.0, 'east': 45.0}

    @pytest.mark.parametrize('bad', ['', None, '  ', 'ai', 's0z!', 'AB'])
    def test_bbox_invalid_hashes_raise(self, bad):
        with pytest.raises(ValueError):
            geohash_bbox(bad)

    def test_decode_returns_cell_centre(self):
        lat, lon = geohash_to_latlon('u09tunquc')
        box = geohash_bbox('u09tunquc')
        assert lat == pytest.approx((box['south'] + box['north']) / 2.0)
        assert lon == pytest.approx((box['west'] + box['east']) / 2.0)
        assert 48.85 < lat < 48.87
        assert 2.29 < lon < 2.30

    @pytest.mark.parametrize('precision', list(range(1, 13)))
    def test_round_trip_error_bounded_by_half_cell(self, precision):
        lat, lon = 48.8584, 2.2945
        back = geohash_to_latlon(latlon_to_geohash(lat, lon, precision))
        box = geohash_bbox(latlon_to_geohash(lat, lon, precision))
        assert abs(back[0] - lat) <= (box['north'] - box['south'])
        assert abs(back[1] - lon) <= (box['east'] - box['west'])

    def test_decode_invalid_hash_raises(self):
        with pytest.raises(ValueError, match='invalid geohash character'):
            geohash_to_latlon('a')      # 'a' is not in the base32 alphabet
        with pytest.raises(ValueError, match='empty geohash'):
            geohash_to_latlon('')


# ------------------------------------------------------------- maidenhead

class TestMaidenhead:

    def test_known_locators(self):
        # Hand-derived: Paris 48.85/2.35 -> field JN, square 18, sub eu.
        assert latlon_to_maidenhead(48.85, 2.35) == 'JN18eu'
        # Sydney -33.87/151.21 -> field QF, square 56, sub od.
        assert latlon_to_maidenhead(-33.87, 151.21) == 'QF56od'
        # Null island: field JJ (counting starts at -180/-90), square 00.
        assert latlon_to_maidenhead(0.0, 0.0) == 'JJ00aa'

    def test_precision_ladder(self):
        assert latlon_to_maidenhead(48.85, 2.35, 1) == 'JN'
        assert latlon_to_maidenhead(48.85, 2.35, 2) == 'JN18'
        assert latlon_to_maidenhead(48.85, 2.35, 3) == 'JN18eu'
        assert re.match(r'^JN18eu\d\d$', latlon_to_maidenhead(48.85, 2.35, 4))

    def test_precision_clamped(self):
        assert latlon_to_maidenhead(10.0, 20.0, 0) == latlon_to_maidenhead(10.0, 20.0, 1)
        assert latlon_to_maidenhead(10.0, 20.0, 99) == latlon_to_maidenhead(10.0, 20.0, 4)
        assert latlon_to_maidenhead(10.0, 20.0, -1) == latlon_to_maidenhead(10.0, 20.0, 1)

    def test_antimeridian_wraps_to_west(self):
        # +180 wraps to -180 (the [-180, 180) rule): same locator both sides.
        assert latlon_to_maidenhead(10.0, 180.0) == latlon_to_maidenhead(10.0, -180.0)
        assert latlon_to_maidenhead(10.0, 180.0).startswith('A')

    def test_out_of_range_longitude_raises_despite_docstring(self):
        # KNOWN DOC BUG (documented, NOT fixed): the docstring says
        # "longitude wraps", but _finite_latlon rejects |lon| > 180 before
        # the wrap is applied - only exactly +-180 wraps.
        with pytest.raises(ValueError, match='longitude out of range'):
            latlon_to_maidenhead(10.0, 185.0)
        with pytest.raises(ValueError, match='longitude out of range'):
            latlon_to_maidenhead(10.0, -185.0)

    @pytest.mark.parametrize('lat,lon', [(91, 0), (0, 'x')])
    def test_validation(self, lat, lon):
        with pytest.raises(ValueError):
            latlon_to_maidenhead(lat, lon)

    def test_nearby_points_share_prefixes(self):
        paris = latlon_to_maidenhead(48.85, 2.35)
        near = latlon_to_maidenhead(48.86, 2.36)
        assert near == paris  # same 5 x 2.5 arc-minute sub-square
        assert latlon_to_maidenhead(48.9, 2.4)[:4] == paris[:4]
        assert latlon_to_maidenhead(49.5, 3.0)[:2] == paris[:2]
        # Far away shares nothing.
        assert latlon_to_maidenhead(-33.87, 151.21)[0] != paris[0]

    def test_field_letters_cover_the_globe(self):
        for lat in (-89.9, -45.0, 0.0, 45.0, 89.9):
            for lon in (-179.9, -90.0, 0.0, 90.0, 179.9):
                locator = latlon_to_maidenhead(lat, lon, 1)
                assert len(locator) == 2
                assert all('A' <= char <= 'R' for char in locator)


# ------------------------------------------------------------- solar / time

class TestTimezoneEstimate:

    def test_fifteen_degree_step(self):
        assert estimate_timezone_offset(0.0) == 0.0
        assert estimate_timezone_offset(15.0) == 1.0
        assert estimate_timezone_offset(-15.0) == -1.0
        assert estimate_timezone_offset(30.0) == 2.0
        assert estimate_timezone_offset(-30.0) == -2.0
        assert estimate_timezone_offset(7.4) == 0.0
        assert estimate_timezone_offset(7.6) == 1.0
        assert estimate_timezone_offset(-7.6) == -1.0

    def test_bounds_are_clamped(self):
        for lon in (-180.0, -179.0, 179.0, 180.0, 1000.0, -1000.0):
            assert -12.0 <= estimate_timezone_offset(lon) <= 12.0
        assert estimate_timezone_offset(180.0) == 12.0
        assert estimate_timezone_offset(-180.0) == -12.0

    def test_half_degree_longitudes_round_half_to_even(self):
        # Observed rule: Python's banker's rounding at exact .5 steps.
        assert estimate_timezone_offset(7.5) == 0.0
        assert estimate_timezone_offset(-7.5) == 0.0
        assert estimate_timezone_offset(97.5) == 6.0    # 6.5 -> 6
        assert estimate_timezone_offset(-97.5) == -6.0  # -6.5 -> -6

    def test_non_finite_raises(self):
        with pytest.raises(ValueError, match='finite'):
            estimate_timezone_offset(float('nan'))
        with pytest.raises(ValueError, match='finite'):
            estimate_timezone_offset(float('inf'))


class TestMinutesToHhmm:

    def test_formats(self):
        assert cm._minutes_to_hhmm(0) == '00:00'
        assert cm._minutes_to_hhmm(754) == '12:34'
        assert cm._minutes_to_hhmm(1439) == '23:59'

    def test_wraps_modulo_day(self):
        assert cm._minutes_to_hhmm(1440) == '00:00'
        assert cm._minutes_to_hhmm(1500) == '01:00'
        assert cm._minutes_to_hhmm(-30) == '23:30'
        assert cm._minutes_to_hhmm(-1440) == '00:00'

    def test_rounding(self):
        assert cm._minutes_to_hhmm(754.4) == '12:34'
        assert cm._minutes_to_hhmm(754.6) == '12:35'


class TestSolarPosition:

    def test_keys_and_types(self):
        result = solar_position(48.85, 2.35, datetime(2024, 6, 21, 12, 0))
        assert set(result) == {
            'altitude_deg', 'azimuth_deg', 'sunrise_utc', 'sunset_utc',
            'is_daylight', 'declination_deg', 'note',
        }
        assert isinstance(result['altitude_deg'], float)
        assert isinstance(result['azimuth_deg'], float)
        assert isinstance(result['is_daylight'], bool)
        assert result['note'] == ''

    def test_paris_summer_solstice(self):
        result = solar_position(48.85, 2.35, datetime(2024, 6, 21, 12, 0))
        assert result['altitude_deg'] == pytest.approx(64.5, abs=0.5)
        assert 0.0 <= result['azimuth_deg'] < 360.0
        assert result['sunrise_utc'] is not None
        assert result['sunset_utc'] is not None
        assert result['sunrise_utc'] < result['sunset_utc']
        assert re.match(r'^\d{2}:\d{2}$', result['sunrise_utc'])
        assert result['is_daylight'] is True
        assert result['declination_deg'] == pytest.approx(23.4, abs=0.3)

    def test_paris_winter_night(self):
        result = solar_position(48.85, 2.35, datetime(2024, 12, 21, 0, 30))
        assert result['is_daylight'] is False
        assert result['altitude_deg'] < -0.833
        assert result['note'] == ''

    def test_polar_day_and_night(self):
        day = solar_position(70.0, 20.0, datetime(2024, 6, 21, 12, 0))
        assert day['note'] == 'polar day'
        assert day['sunrise_utc'] is None
        assert day['sunset_utc'] is None
        assert day['is_daylight'] is True
        night = solar_position(70.0, 20.0, datetime(2024, 12, 21, 12, 0))
        assert night['note'] == 'polar night'
        assert night['sunrise_utc'] is None
        assert night['sunset_utc'] is None
        assert night['is_daylight'] is False

    def test_equator_equinox_near_zenith(self):
        result = solar_position(0.0, 0.0, datetime(2024, 3, 20, 12, 0,
                                                  tzinfo=timezone.utc))
        assert result['altitude_deg'] == pytest.approx(88.0, abs=0.5)
        assert result['sunrise_utc'] == pytest.approx('06:05') or \
            result['sunrise_utc'].startswith('06:0')
        assert result['sunset_utc'].startswith('18:1')

    def test_naive_datetime_is_treated_as_utc(self):
        naive = datetime(2024, 6, 21, 12, 0)
        aware = datetime(2024, 6, 21, 12, 0, tzinfo=timezone.utc)
        assert solar_position(10.0, 20.0, naive) == solar_position(10.0, 20.0, aware)

    def test_aware_datetime_is_converted(self):
        # 15:00+03:00 and 12:00 UTC are the same instant.
        utc = datetime(2024, 6, 21, 12, 0, tzinfo=timezone.utc)
        shifted = datetime(2024, 6, 21, 15, 0,
                           tzinfo=timezone(timedelta(hours=3)))
        assert solar_position(10.0, 20.0, utc)['altitude_deg'] == \
            solar_position(10.0, 20.0, shifted)['altitude_deg']

    def test_none_uses_now(self):
        result = solar_position(51.5, -0.1)
        assert set(result) == {
            'altitude_deg', 'azimuth_deg', 'sunrise_utc', 'sunset_utc',
            'is_daylight', 'declination_deg', 'note',
        }
        assert -90.0 <= result['altitude_deg'] <= 90.0
        assert 0.0 <= result['azimuth_deg'] < 360.0

    def test_non_datetime_when_raises(self):
        with pytest.raises(ValueError, match='when must be a datetime'):
            solar_position(0.0, 0.0, '2024-06-21')

    @pytest.mark.parametrize('lat,lon', [(91, 0), (0, 181), (float('nan'), 0)])
    def test_coordinate_validation(self, lat, lon):
        with pytest.raises(ValueError):
            solar_position(lat, lon)


# --------------------------------------------------------- distance / bbox

class TestHaversine:

    def test_quarter_equator(self):
        # Published value: 10,007.543 km for 0->90 deg along the equator.
        assert haversine_km(0.0, 0.0, 0.0, 90.0) == pytest.approx(10007.54, abs=0.5)

    def test_paris_to_new_york(self):
        assert haversine_km(48.8566, 2.3522, 40.7128, -74.0060) == \
            pytest.approx(5837.0, abs=5.0)

    def test_antipodal_half_circumference(self):
        assert haversine_km(0.0, 0.0, 0.0, 180.0) == pytest.approx(20015.09, abs=1.0)
        assert haversine_km(0.0, 0.0, 0.0, -180.0) == \
            haversine_km(0.0, 0.0, 0.0, 180.0)

    def test_zero_and_symmetry(self):
        assert haversine_km(10.5, 20.25, 10.5, 20.25) == 0.0
        forward = haversine_km(52.52, 13.405, 48.85, 2.35)
        backward = haversine_km(48.85, 2.35, 52.52, 13.405)
        assert forward == pytest.approx(backward, rel=1e-9)
        assert forward == pytest.approx(878.0, abs=10.0)  # Berlin <-> Paris

    def test_one_degree_of_latitude(self):
        assert haversine_km(0.0, 10.0, 1.0, 10.0) == pytest.approx(111.19, abs=0.3)

    @pytest.mark.parametrize('args', [
        (91, 0, 0, 0), (0, 181, 0, 0), (0, 0, -91, 0), (0, 0, 0, -181),
        ('x', 0, 0, 0), (0, 0, float('nan'), 0), (None, 0, 0, 0),
    ])
    def test_validation_raises(self, args):
        with pytest.raises(ValueError):
            haversine_km(*args)


class TestBboxAround:

    def test_shape_and_deltas(self):
        box = bbox_around(48.85, 2.35, 10.0)
        assert set(box) == {'min_lat', 'max_lat', 'min_lon', 'max_lon',
                            'center_lat', 'center_lon', 'radius_km'}
        assert box['center_lat'] == 48.85
        assert box['center_lon'] == 2.35
        assert box['radius_km'] == 10.0
        assert box['max_lat'] - box['min_lat'] == pytest.approx(2 * 10 / 111.32, rel=1e-6)
        # At lat 48.85 the longitude delta widens by 1 / cos(lat).
        expected_lon = 2 * 10 / (111.32 * math.cos(math.radians(48.85)))
        assert box['max_lon'] - box['min_lon'] == pytest.approx(expected_lon, rel=1e-6)

    def test_equator_box_is_square(self):
        box = bbox_around(0.0, 0.0, 50.0)
        assert box['max_lat'] - box['min_lat'] == pytest.approx(
            box['max_lon'] - box['min_lon'], rel=1e-9)

    def test_polar_cosine_clamp_keeps_bounds_finite(self):
        box = bbox_around(89.9, 0.0, 10.0)
        assert math.isfinite(box['max_lon'])
        assert math.isfinite(box['min_lon'])
        # Clamped cosine of 0.01 keeps the box ~10 km * (1/0.01) wide.
        assert box['max_lon'] == pytest.approx(10.0 / (111.32 * 0.01), rel=1e-6)

    @pytest.mark.parametrize('km', [-1.0, 0.0, float('nan'), float('inf')])
    def test_invalid_radius_raises(self, km):
        with pytest.raises(ValueError, match='radius must be a positive'):
            bbox_around(0.0, 0.0, km)

    def test_non_numeric_radius_raises(self):
        # Observed rule: float('x') raises before the range check.
        with pytest.raises(ValueError, match='could not convert'):
            bbox_around(0.0, 0.0, 'x')

    @pytest.mark.parametrize('lat,lon', [(91, 0), (0, 181), ('x', 0)])
    def test_coordinate_validation(self, lat, lon):
        with pytest.raises(ValueError):
            bbox_around(lat, lon, 5.0)


# --------------------------------------------------------- parsing helpers

class TestParseUtmString:

    def test_spaced_form(self):
        assert parse_utm_string('31U 448288 5411087') == (31, 'U', 448288.0, 5411087.0)

    def test_band_less_form(self):
        assert parse_utm_string('31 448288 5411087') == (31, '', 448288.0, 5411087.0)

    def test_separators_and_decimals(self):
        assert parse_utm_string('  31u 448288, 5411087  ') == \
            (31, 'U', 448288.0, 5411087.0)
        assert parse_utm_string('31U 448288.5; 5411087.5') == \
            (31, 'U', 448288.5, 5411087.5)

    @pytest.mark.parametrize('junk', [
        '', '   ', None, 'junk', '31U', '31U 448288', '316 448288 5411087',
        '31Z 448288 5411087', 'UTM 31U 448288 5411087', '-31U 448288 5411087',
    ])
    def test_non_matching_strings_return_none(self, junk):
        assert parse_utm_string(junk) is None


class TestParseMgrsString:

    def test_spaced_military_form(self):
        assert parse_mgrs_string('31U DQ 48288 11087') == (31, 'U', 'DQ', 48288, 11087)

    def test_case_insensitive(self):
        assert parse_mgrs_string('31u dq 48288 11087') == (31, 'U', 'DQ', 48288, 11087)

    def test_short_offsets(self):
        assert parse_mgrs_string('31U DQ 4 1') == (31, 'U', 'DQ', 4, 1)
        assert parse_mgrs_string('31U DQ 042 011') == (31, 'U', 'DQ', 42, 11)

    @pytest.mark.parametrize('junk', [
        '', '   ', None, 'nope', '31U DQ', '31U DQ 48288', '31U DQ 4828811',
        '31U DQ 482888 110871', '31 DQ 48288 11087',
    ])
    def test_non_matching_strings_return_none(self, junk):
        assert parse_mgrs_string(junk) is None

    def test_round_trip_through_the_parser(self):
        reference = latlon_to_mgrs(48.8584, 2.2945, 4)
        parsed = parse_mgrs_string(reference)
        assert parsed is not None
        lat, lon = mgrs_to_latlon(*parsed)
        assert haversine_km(48.8584, 2.2945, lat, lon) * 1000.0 < 300.0
