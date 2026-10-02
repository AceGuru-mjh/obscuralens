"""Geo utilities and data-pack loader tests (100% offline)."""

import pytest

from obscuralens.utils import data_packs
from obscuralens.utils.data_packs import (
    data_pack_path,
    get_disposable_domains,
    get_phishing_keywords,
    get_popular_domains,
    is_disposable_email,
    load_data_pack,
    pack_info,
)
from obscuralens.utils.geo import (
    COUNTRIES,
    REGIONS,
    coordinate_spread,
    country_name,
    distance_km,
    flag_emoji,
    region_of,
)

# Three real city coordinates: Paris, Berlin, Madrid.
THREE_POINTS = [
    {'source': 'ipinfo', 'lat': 48.85, 'lon': 2.35},
    {'source': 'ripestat', 'lat': 52.52, 'lon': 13.40},
    {'source': 'ip-api', 'lat': 40.4168, 'lon': -3.7038},
]


# --------------------------------------------------------------------- geo

def test_country_name_lookups():
    assert country_name('us') == 'United States'
    assert country_name('DE') == 'Germany'
    assert country_name('uk') == 'United Kingdom'
    assert country_name('EU') == 'European Union'
    assert country_name('gb') == 'United Kingdom'
    assert country_name('  fr ') == 'France'  # case + whitespace tolerant


def test_country_name_unknown():
    assert country_name('zz') == ''
    assert country_name('') == ''
    assert country_name(None) == ''
    assert country_name(123) == ''


def test_flag_emoji():
    assert flag_emoji('fr') == '\U0001F1EB\U0001F1F7'  # France
    assert flag_emoji('US') == '\U0001F1FA\U0001F1F8'  # United States
    assert len(flag_emoji('jp')) == 2                  # two indicator symbols
    assert flag_emoji('zz') == ''                      # unknown code
    assert flag_emoji('usa') == ''                     # wrong length
    assert flag_emoji('') == ''
    assert flag_emoji(None) == ''
    assert flag_emoji(7) == ''


def test_region_of():
    assert region_of('jp') == 'Asia'
    assert region_of('br') == 'South America'
    assert region_of('US') == 'North America'
    assert region_of('za') == 'Africa'
    assert region_of('au') == 'Oceania'
    assert region_of('aq') == 'Antarctic'
    assert region_of('uk') == 'Europe'
    assert region_of('zz') == ''
    assert region_of(None) == ''


def test_countries_table_shape():
    assert len(COUNTRIES) >= 200
    assert 'GB' in COUNTRIES and 'UK' in COUNTRIES and 'EU' in COUNTRIES
    assert COUNTRIES['UK'] == ('United Kingdom', 'Europe')
    assert COUNTRIES['EU'] == ('European Union', 'Europe')
    assert COUNTRIES['JP'] == ('Japan', 'Asia')
    assert COUNTRIES['BR'] == ('Brazil', 'South America')
    assert list(COUNTRIES) == sorted(COUNTRIES)  # alphabetical by code
    for code, (name, region) in COUNTRIES.items():
        assert len(code) == 2 and code.isupper() and code.isalpha()
        assert isinstance(name, str) and name
        assert region in REGIONS
    assert {region for _, region in COUNTRIES.values()} == set(REGIONS)


def test_distance_paris_to_madrid():
    assert 1000 <= distance_km(48.85, 2.35, 40.4168, -3.7038) <= 1200


def test_distance_same_point_is_zero():
    assert distance_km(10.5, 20.25, 10.5, 20.25) == 0.0


def test_distance_garbage_returns_zero():
    assert distance_km('x', 'y', 1, 2) == 0.0
    assert distance_km(None, 0, 1, 2) == 0.0
    assert distance_km(float('nan'), 0, 1, 2) == 0.0
    assert distance_km(float('inf'), 0, 1, 2) == 0.0
    assert distance_km(True, False, 1, 2) == 0.0  # bools are not coordinates


def test_distance_symmetry():
    forward = distance_km(52.52, 13.405, 48.85, 2.35)  # Berlin -> Paris
    backward = distance_km(48.85, 2.35, 52.52, 13.405)
    assert forward == pytest.approx(backward, rel=1e-9)
    assert 850 <= forward <= 950


def test_coordinate_spread_three_points():
    result = coordinate_spread(THREE_POINTS)
    assert result['points'] == 3
    assert result['max_distance_km'] >= result['mean_distance_km'] > 0
    assert result['spread_km'] == result['max_distance_km']
    assert set(result['centroid']) == {'lat', 'lon'}
    assert 46 < result['centroid']['lat'] < 49   # mean of the three lats
    assert 3 < result['centroid']['lon'] < 5     # mean of the three lons
    assert 1500 < result['max_distance_km'] < 2100  # Berlin <-> Madrid leg


def test_coordinate_spread_single_point():
    result = coordinate_spread([{'source': 'only', 'lat': 10, 'lon': 20}])
    assert result == {
        'points': 1,
        'max_distance_km': 0.0,
        'mean_distance_km': 0.0,
        'centroid': {'lat': 0.0, 'lon': 0.0},
        'spread_km': 0.0,
    }


def test_coordinate_spread_empty_and_non_list():
    for garbage in ([], None, 'paris', 42, {'lat': 1, 'lon': 2}):
        result = coordinate_spread(garbage)
        assert result['points'] == 0
        assert result['max_distance_km'] == 0.0
        assert result['mean_distance_km'] == 0.0
        assert result['spread_km'] == 0.0


def test_coordinate_spread_skips_garbage_entries():
    mixed = [
        THREE_POINTS[0],
        {'source': 'bad', 'lat': 'not-a-number', 'lon': 0},   # string coords
        {'source': 'bad', 'lat': None, 'lon': 12},             # None coord
        {'source': 'bad'},                                     # missing keys
        'garbage',                                             # not a dict
        None,
        THREE_POINTS[1],
        {'source': 'range', 'lat': 999, 'lon': 0},             # out of range
        {'source': 'bool', 'lat': True, 'lon': 2},             # bool coord
        {'source': 'nan', 'lat': float('nan'), 'lon': 2},      # NaN coord
        THREE_POINTS[2],
    ]
    result = coordinate_spread(mixed)
    assert result['points'] == 3
    assert result['mean_distance_km'] > 0
    assert result['max_distance_km'] >= result['mean_distance_km']


def test_coordinate_spread_duplicate_points():
    result = coordinate_spread([THREE_POINTS[0], THREE_POINTS[0]])
    assert result['points'] == 2
    assert result['max_distance_km'] == 0.0
    assert result['mean_distance_km'] == 0.0


# -------------------------------------------------------------- data packs

def test_disposable_pack_contents():
    domains = load_data_pack('disposable_email_domains')
    assert len(domains) >= 2000
    assert len(set(domains)) == len(domains)  # no duplicates
    assert all(domain == domain.lower() for domain in domains)
    assert all(domain and '#' not in domain for domain in domains)


def test_popular_pack_contents():
    domains = load_data_pack('popular_domains')
    assert len(domains) >= 300
    assert len(set(domains)) == len(domains)
    assert all(domain == domain.lower() for domain in domains)
    assert 'gmail.com' in domains


def test_phishing_pack_contents():
    keywords = load_data_pack('phishing_keywords')
    assert len(keywords) >= 600
    assert len(set(keywords)) == len(keywords)
    assert all(kw == kw.lower() and kw and '#' not in kw for kw in keywords)


def test_unknown_and_unsafe_pack_names():
    assert load_data_pack('no_such_pack') == []
    assert load_data_pack('') == []
    assert load_data_pack(None) == []
    assert load_data_pack('../data/disposable_email_domains') == []  # traversal
    assert data_pack_path('no_such_pack') is None
    path = data_pack_path('disposable_email_domains')
    assert path is not None and path.is_file()
    assert path.parent == data_packs.DATA_DIR


def test_pack_cache_identity():
    first = load_data_pack('popular_domains')
    second = load_data_pack('popular_domains')
    assert first is second                       # cached list object reused
    assert load_data_pack('popular_domains') is get_popular_domains()
    assert get_disposable_domains() is get_disposable_domains()
    assert get_phishing_keywords() is get_phishing_keywords()
    assert get_disposable_domains() is load_data_pack('disposable_email_domains')


def test_pack_info_shape():
    data_packs._CACHE.pop('popular_domains', None)  # control cache state
    fresh = pack_info('popular_domains')
    assert set(fresh) == {'name', 'entries', 'loaded'}
    assert fresh['name'] == 'popular_domains'
    assert fresh['entries'] == len(load_data_pack('popular_domains'))
    assert fresh['loaded'] is False                 # not cached when probed
    assert pack_info('popular_domains')['loaded'] is True  # now resident
    assert pack_info('does_not_exist') == {
        'name': 'does_not_exist', 'entries': 0, 'loaded': False,
    }


def test_is_disposable_email():
    # mailinator.com itself is absent from the shipped pack; its
    # .net/.org/.fr/... variants are present, so those are the test values.
    assert is_disposable_email('a@mailinator.net') is True
    assert is_disposable_email('A@MAILINATOR.NET') is True  # case-insensitive
    assert is_disposable_email('a@yopmail.com') is True
    assert is_disposable_email('a@gmail.com') is False
    assert is_disposable_email('not-an-email') is False
    assert is_disposable_email('') is False
    assert is_disposable_email(None) is False
    assert is_disposable_email('a@b@c.com') is False
    assert is_disposable_email('@mailinator.net') is False
