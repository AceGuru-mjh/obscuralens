"""Geospatial helper tests (offline; pure functions in advanced.geospatial)."""

from obscuralens.advanced import geospatial


def test_number_parses_finite_floats_only():
    assert geospatial._number('1.5') == 1.5
    assert geospatial._number(42) == 42.0
    assert geospatial._number('nan') is None
    assert geospatial._number('inf') is None
    assert geospatial._number(None) is None
    assert geospatial._number(True) is None   # bool is not a coordinate
    assert geospatial._number('abc') is None


def test_coords_of_reads_payload_first():
    record = {
        'value': '10, 20',
        'payload': {'info': {'latitude': '51.5', 'longitude': '-0.1'}},
    }
    lat, lon = geospatial._coords_of(record)
    assert (lat, lon) == (51.5, -0.1)


def test_coords_of_falls_back_to_value():
    record = {'value': '48.85, 2.35', 'payload': {}}
    lat, lon = geospatial._coords_of(record)
    assert (lat, lon) == (48.85, 2.35)


def test_coords_of_junk_returns_none_pair():
    assert geospatial._coords_of({'value': 'junk', 'payload': {}}) == (None, None)
    assert geospatial._coords_of({'value': '1, 2, 3', 'payload': {}}) == (None, None)
    assert geospatial._coords_of({'value': '1', 'payload': {}}) == (None, None)
    assert geospatial._coords_of({}) == (None, None)


def test_country_breakdown_with_inline_records():
    records = [
        {'value': '8.8.8.8', 'kind': 'ip',
         'payload': {'info': {'country_name': 'United States',
                              'country_code': 'US'}}},
        {'value': '8.8.4.4', 'kind': 'ip',
         'payload': {'info': {'country_name': 'United States',
                              'country_code': 'US'}}},
        {'value': '1.1.1.1', 'kind': 'ip',
         'payload': {'info': {'country_name': 'Australia',
                              'country_code': 'AU'}}},
        {'value': 'no-geo.example', 'kind': 'ip',
         'payload': {'info': {}}},
        {'value': 'other.example', 'kind': 'domain',
         'payload': {'info': {}}},   # non-IP records are not "unknown"
    ]
    out = geospatial.country_breakdown(records)
    assert out['total_records'] == 5
    assert out['total_geo_tagged'] == 3
    assert out['unknown'] == 1       # only the IP record without a country
    countries = {c['country']: c['count'] for c in out['countries']}
    assert countries['United States'] == 2
    assert countries['Australia'] == 1
    # Countries are sorted by count descending.
    assert out['countries'][0]['country'] == 'United States'
