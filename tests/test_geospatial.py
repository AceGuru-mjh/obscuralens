"""
Offline tests for obscuralens.advanced.geospatial (stored-history geo profiling).

Every public function accepts a ``records`` argument, which keeps the whole
suite pure and offline; the ``records=None`` database path is exercised
through a monkeypatched seam (``history_records`` + ``db.get_history``) so no
test ever touches the shared test database or the network. Country centroids
come from the shipped ``country_centroids`` data pack (offline by design).
"""

import json
from datetime import datetime, timezone

import pytest

from obscuralens.advanced import geospatial as gs

# --------------------------------------------------------------- test helpers

class Row:
    """Minimal database history-row stand-in (attribute access)."""

    def __init__(self, query_type, query_value, result_data, created_at):
        self.query_type = query_type
        self.query_value = query_value
        self.result_data = result_data
        self.created_at = created_at


def rec(kind, value, info=None, ts='2024-06-01T10:00:00Z', payload=None):
    """One database-row-shaped record with a JSON-encoded payload."""
    body = {'info': info} if info is not None else (payload or {})
    return {
        'query_type': kind,
        'query_value': value,
        'result_data': json.dumps(body),
        'created_at': ts,
    }


def coords_rec(lat, lon, ts='2024-06-01T10:00:00Z', country=None, code=None):
    info = {'latitude': lat, 'longitude': lon}
    if country:
        info['country'] = country
    if code:
        info['country_code'] = code
    return rec('coords', f'{lat}, {lon}', info, ts)


class FakeDb:
    """Stand-in for the shared database object (only get_history needed).

    Reads the row list through a holder dict so tests can re-point the
    synthetic records after the fixture is installed.
    """

    def __init__(self, holder):
        self.holder = holder
        self.calls = []

    def get_history(self, query_type=None, limit=None):
        self.calls.append((query_type, limit))
        rows = self.holder['coords_rows']
        if query_type is None:
            return rows[:limit] if limit else rows
        return [row for row in rows if row.query_type == query_type][:limit or 800]


@pytest.fixture()
def history_seam(monkeypatch):
    """Patch both history seams; returns a setter for the synthetic records."""
    holder = {'correlation': [], 'coords_rows': []}

    def set_records(correlation_records, coords_rows):
        holder['correlation'] = correlation_records
        holder['coords_rows'] = coords_rows

    monkeypatch.setattr(gs, 'history_records',
                        lambda limit=None: holder['correlation'])
    monkeypatch.setattr(gs, 'db', FakeDb(holder))
    set_records([], [])
    return set_records


# ------------------------------------------------- record plumbing helpers

class TestJsonPayload:

    def test_dict_passthrough(self):
        assert gs._json_payload({'a': 1}) == {'a': 1}

    def test_json_string_decoded(self):
        assert gs._json_payload('{"a": 2}') == {'a': 2}

    def test_junk_returns_empty_dict(self):
        assert gs._json_payload('not json') == {}
        assert gs._json_payload('[1, 2]') == {}      # non-object JSON
        assert gs._json_payload('42') == {}
        assert gs._json_payload('') == {}
        assert gs._json_payload('   ') == {}
        assert gs._json_payload(None) == {}
        assert gs._json_payload(123) == {}
        assert gs._json_payload(['x']) == {}


class TestInfoOf:

    def test_info_dict_extracted(self):
        assert gs._info_of({'info': {'a': 1}}) == {'a': 1}

    def test_payload_without_info_returns_itself(self):
        # Username-style payloads carry their fields at the top level.
        assert gs._info_of({'country': 'FR'}) == {'country': 'FR'}

    def test_junk_shapes(self):
        assert gs._info_of(None) == {}
        assert gs._info_of('x') == {}
        assert gs._info_of({'info': 'not a dict'}) == {'info': 'not a dict'}


class TestFieldPickers:

    def test_first_text(self):
        source = {'country': ' France ', 'country_name': 'French Republic'}
        assert gs._first_text(source, gs._COUNTRY_NAME_FIELDS) == 'France'
        assert gs._first_text({'country': 5}, ('country',)) == ''
        assert gs._first_text({}, ('country',)) == ''

    def test_first_present(self):
        source = {'query_value': 'v', 'target': 't'}
        assert gs._first_present(source, gs._VALUE_KEYS) == 'v'
        assert gs._first_present({}, gs._VALUE_KEYS) is None


class TestNormaliseRecords:

    def test_database_row_shape(self):
        normalised = gs._normalise_records([rec('ip', ' 8.8.8.8 ')])
        assert normalised == [{
            'kind': 'ip',
            'value': '8.8.8.8',
            'payload': {},
            'timestamp': '2024-06-01T10:00:00Z',
        }]

    def test_correlation_shape_uses_created_at(self):
        normalised = gs._normalise_records([{
            'kind': 'IP', 'value': '1.1.1.1', 'payload': {'info': {'a': 1}},
            'created_at': 1717236000,
        }])
        assert normalised[0]['kind'] == 'ip'          # lowercased
        assert normalised[0]['timestamp'] == 1717236000

    def test_api_shape_uses_result_and_timestamp(self):
        normalised = gs._normalise_records([{
            'kind': 'domain', 'value': 'example.fr',
            'result': json.dumps({'info': {'country': 'France'}}),
            'timestamp': '2024-06-01T10:00:00Z',
        }])
        assert normalised[0]['payload'] == {'info': {'country': 'France'}}

    def test_inline_info_records(self):
        # No payload/result/result_data key but an info dict on the record:
        # the record itself becomes the payload.
        normalised = gs._normalise_records([{
            'query_type': 'ip', 'query_value': '8.8.8.8',
            'info': {'country': 'Germany'}, 'created_at': None,
        }])
        assert normalised[0]['payload'] == {'query_type': 'ip',
                                            'query_value': '8.8.8.8',
                                            'info': {'country': 'Germany'},
                                            'created_at': None}

    def test_alternate_kind_and_value_keys(self):
        normalised = gs._normalise_records([{
            'type': 'Coords', 'target': '1, 2', 'time': '2024-06-01T10:00:00Z',
        }])
        assert normalised[0]['kind'] == 'coords'
        assert normalised[0]['value'] == '1, 2'
        assert normalised[0]['timestamp'] == '2024-06-01T10:00:00Z'

    def test_junk_entries_are_dropped(self):
        normalised = gs._normalise_records(
            ['junk', None, 42, {'kind': 'ip', 'value': 'ok'}])
        assert len(normalised) == 1
        assert normalised[0]['value'] == 'ok'

    def test_none_and_non_iterable_yield_empty(self):
        assert gs._normalise_records(None) == []
        assert gs._normalise_records(42) == []
        assert gs._normalise_records('string') == []   # iterates chars, no dicts

    def test_payload_dict_passes_through_undecoded(self):
        normalised = gs._normalise_records([{
            'kind': 'ip', 'value': 'x', 'payload': {'info': {'b': 2}},
        }])
        assert normalised[0]['payload'] == {'info': {'b': 2}}


class TestCoordsRows:

    def test_rows_via_fake_db(self, monkeypatch):
        rows = [Row('coords', '48.85, 2.35',
                    json.dumps({'info': {'latitude': 48.85, 'longitude': 2.35}}),
                    '2024-06-01T10:00:00Z'),
                Row('coords', 'junk', 'not json', None)]
        monkeypatch.setattr(gs, 'db', FakeDb({'coords_rows': rows}))
        records = gs._coords_rows(5)
        assert [r['kind'] for r in records] == ['coords', 'coords']
        assert records[0]['value'] == '48.85, 2.35'
        assert records[0]['payload'] == {'info': {'latitude': 48.85,
                                                  'longitude': 2.35}}
        assert records[1]['payload'] == {}

    def test_database_errors_degrade_to_empty(self, monkeypatch):
        class BoomDb:
            def get_history(self, **kwargs):
                raise RuntimeError('db down')

        monkeypatch.setattr(gs, 'db', BoomDb())
        assert gs._coords_rows(10) == []
        assert gs._coords_rows(10) == []

    def test_none_rows_degrade_to_empty(self, monkeypatch):
        monkeypatch.setattr(gs, 'db', FakeDb(None))
        assert gs._coords_rows(10) == []


class TestLoadRecords:

    def test_merges_correlation_and_coords_rows(self, history_seam):
        correlation = [{'kind': 'ip', 'value': '1.1.1.1',
                        'payload': {'info': {'country': 'Australia'}},
                        'created_at': '2024-06-01T09:00:00Z'}]
        coords = [Row('coords', '48.85, 2.35',
                      json.dumps({'info': {'latitude': 48.85,
                                           'longitude': 2.35}}),
                      '2024-06-01T10:00:00Z')]
        history_seam(correlation, coords)
        loaded = gs._load_records()
        assert [r['kind'] for r in loaded] == ['ip', 'coords']
        assert [r['value'] for r in loaded] == ['1.1.1.1', '48.85, 2.35']

    def test_history_limit_is_passed_to_the_seams(self, history_seam):
        history_seam([], [])
        gs._load_records()
        # history_records and db.get_history are both capped at _HISTORY_LIMIT.
        assert gs._HISTORY_LIMIT == 800

    def test_correlation_failure_degrades_to_coords_only(self, monkeypatch):
        def broken(limit=None):
            raise RuntimeError('history unavailable')

        monkeypatch.setattr(gs, 'history_records', broken)
        monkeypatch.setattr(
            gs, 'db',
            FakeDb({'coords_rows': [Row('coords', '1, 2', None, None)]}))
        loaded = gs._load_records()
        assert [r['kind'] for r in loaded] == ['coords']

    def test_records_argument_none_loads_others_normalise(self, history_seam):
        history_seam([{'kind': 'ip', 'value': '9.9.9.9', 'payload': {},
                       'created_at': None}], [])
        assert [r['value'] for r in gs._records(None)] == ['9.9.9.9']
        assert [r['value'] for r in gs._records([rec('ip', '8.8.8.8')])] == \
            ['8.8.8.8']


# ------------------------------------------------------------ timestamp code

class TestEpochMoment:

    def test_epoch_seconds(self):
        moment = gs._epoch_moment(1717236000.0)
        assert moment == datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)

    def test_epoch_milliseconds_detected_by_magnitude(self):
        assert gs._epoch_moment(1717236000000) == \
            datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)

    @pytest.mark.parametrize('number', [0, -5, 1e8, 999999999, 1e15, 1e16,
                                        float('nan')])
    def test_implausible_values_return_none(self, number):
        assert gs._epoch_moment(number) is None


class TestParseTimestamp:

    def test_datetime_values(self):
        naive = datetime(2024, 6, 1, 10, 0)
        assert gs._parse_timestamp(naive) == \
            datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
        aware = datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
        assert gs._parse_timestamp(aware) == aware

    def test_iso_forms(self):
        expected = datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
        assert gs._parse_timestamp('2024-06-01T10:00:00Z') == expected
        assert gs._parse_timestamp('2024-06-01t10:00:00z') == expected
        assert gs._parse_timestamp('2024-06-01T10:00:00+00:00') == expected
        assert gs._parse_timestamp('2024-06-01 10:00:00') == expected
        assert gs._parse_timestamp('2024-06-01') == \
            datetime(2024, 6, 1, tzinfo=timezone.utc)

    def test_offset_aware_iso(self):
        moment = gs._parse_timestamp('2024-06-01T12:00:00+02:00')
        assert moment == datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)

    def test_fallback_formats(self):
        assert gs._parse_timestamp('2024/06/01 10:00:00') == \
            datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
        assert gs._parse_timestamp('2024/06/01') == \
            datetime(2024, 6, 1, tzinfo=timezone.utc)
        assert gs._parse_timestamp('01 Jun 2024 10:00:00') == \
            datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
        assert gs._parse_timestamp('01 Jun 2024') == \
            datetime(2024, 6, 1, tzinfo=timezone.utc)

    def test_numeric_strings(self):
        assert gs._parse_timestamp('1717236000') == \
            datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)
        assert gs._parse_timestamp('1717236000000') == \
            datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc)

    @pytest.mark.parametrize('junk', [
        None, True, False, '', '   ', 'not a time', '2024-13-45',
        'tomorrow', [], {'a': 1}, float('nan'), -1, 0,
    ])
    def test_unparseable_values_return_none(self, junk):
        assert gs._parse_timestamp(junk) is None


class TestTimestampText:

    def test_datetime_renders_isoformat(self):
        assert gs._timestamp_text(datetime(2024, 6, 1, 10, 0,
                                            tzinfo=timezone.utc)) == \
            '2024-06-01T10:00:00+00:00'

    def test_other_values_render_verbatim_or_empty(self):
        assert gs._timestamp_text('raw') == 'raw'
        assert gs._timestamp_text(1717236000) == '1717236000'
        assert gs._timestamp_text(None) == ''
        assert gs._timestamp_text('') == ''


# --------------------------------------------------------- country resolution

class TestCentroids:

    def test_shipped_pack_loads_more_than_one_hundred_countries(self):
        by_code, by_name = gs._centroids()
        assert len(by_code) > 100
        assert len(by_name) > 100

    def test_known_centroids_have_sane_signs(self):
        assert gs._centroid_for('United States', 'US') == (39.8, -98.6)
        france = gs._centroid_for('France', 'FR')
        assert 46.0 < france[0] < 47.5
        assert 1.5 < france[1] < 3.5
        australia = gs._centroid_for('Australia', 'AU')
        assert australia[0] < 0 and australia[1] > 100

    def test_iso_code_wins_over_name(self):
        assert gs._centroid_for('Narnia', 'US') == (39.8, -98.6)

    def test_aliases_resolve_to_pack_names(self):
        russia = gs._centroid_for('Russian Federation', '')
        assert russia == gs._centroid_for('Russia', '')
        assert 55.0 < russia[0] < 65.0
        assert 90.0 < russia[1] < 110.0
        assert gs._centroid_for('UK', '') == gs._centroid_for('United Kingdom', '')
        assert gs._centroid_for('UAE', '') == \
            gs._centroid_for('United Arab Emirates', '')

    def test_lookup_is_case_insensitive(self):
        assert gs._centroid_for('united states', 'us') == (39.8, -98.6)
        assert gs._centroid_for('FRANCE', 'fr') == gs._centroid_for('France', 'FR')

    def test_unknown_country_returns_none(self):
        assert gs._centroid_for('Atlantis', '') is None
        assert gs._centroid_for('', '') is None
        assert gs._centroid_for(None, None) is None

    def test_malformed_pack_lines_are_skipped(self, monkeypatch):
        pack = [
            'US|39.8|-98.6|united states',
            'XX|not|float|malformed latitude',
            'too|short',
            'FR|46.6|2.4|france',
            '',
        ]
        monkeypatch.setattr(gs, 'load_data_pack', lambda name: list(pack))
        monkeypatch.setattr(gs, '_CENTROIDS_LOADED', False)
        monkeypatch.setattr(gs, '_CENTROID_BY_CODE', {})
        monkeypatch.setattr(gs, '_CENTROID_BY_NAME', {})
        try:
            by_code, by_name = gs._centroids()
            assert by_code == {'US': (39.8, -98.6), 'FR': (46.6, 2.4)}
            assert by_name == {'united states': (39.8, -98.6),
                               'france': (46.6, 2.4)}
        finally:  # force the real pack to reload for later tests
            monkeypatch.setattr(gs, '_CENTROIDS_LOADED', False)

    def test_centroids_are_cached_after_first_load(self):
        first = gs._centroids()
        second = gs._centroids()
        assert first[0] is second[0]
        assert first[1] is second[1]


class TestCountryOf:

    def test_name_and_code_carried(self):
        record = {'payload': {'info': {'country': 'Germany',
                                       'country_code': 'DE'}}}
        assert gs._country_of(record) == ('Germany', 'DE')

    def test_alternate_code_key(self):
        record = {'payload': {'info': {'country': 'Australia',
                                       'countryCode': 'AU'}}}
        assert gs._country_of(record) == ('Australia', 'AU')

    def test_code_only_resolves_display_name(self):
        record = {'payload': {'info': {'country_code': 'DE'}}}
        assert gs._country_of(record) == ('Germany', 'DE')

    def test_code_is_truncated_to_two_letters(self):
        record = {'payload': {'info': {'country_code': 'FRA'}}}
        name, code = gs._country_of(record)
        assert code == 'FR'
        assert name == 'France'

    def test_name_only(self):
        record = {'payload': {'info': {'country': 'France'}}}
        assert gs._country_of(record) == ('France', '')

    def test_inline_top_level_payload(self):
        record = {'payload': {'country': 'France', 'country_code': 'FR'}}
        assert gs._country_of(record) == ('France', 'FR')

    def test_empty_payload_yields_empty_strings(self):
        assert gs._country_of({'payload': {}}) == ('', '')
        assert gs._country_of({'payload': None}) == ('', '')
        assert gs._country_of({}) == ('', '')


class TestNumber:

    def test_scalars(self):
        assert gs._number(5) == 5.0
        assert gs._number('5.5') == 5.5
        assert gs._number(-0.25) == -0.25

    @pytest.mark.parametrize('junk', [None, True, False, 'x', [],
                                      float('nan'), float('inf')])
    def test_junk_returns_none(self, junk):
        assert gs._number(junk) is None


class TestCoordsOf:

    def test_info_coordinates(self):
        record = {'payload': {'info': {'latitude': 48.85, 'longitude': 2.35}},
                  'value': '48.85, 2.35'}
        assert gs._coords_of(record) == (48.85, 2.35)

    def test_string_coordinates_are_coerced(self):
        record = {'payload': {'info': {'latitude': '48.85',
                                       'longitude': '2.35'}}}
        assert gs._coords_of(record) == (48.85, 2.35)

    def test_value_fallback(self):
        record = {'payload': {}, 'value': '48.85, 2.35'}
        assert gs._coords_of(record) == (48.85, 2.35)

    def test_partial_info_falls_back_to_value(self):
        record = {'payload': {'info': {'latitude': 48.85}}, 'value': '1.5, 2.5'}
        assert gs._coords_of(record) == (1.5, 2.5)

    @pytest.mark.parametrize('record', [
        {'payload': {}, 'value': 'junk'},
        {'payload': {}, 'value': '48.85'},
        {'payload': {}, 'value': 'a, b'},
        {'payload': {}, 'value': ''},
        {'payload': {'info': {'latitude': None, 'longitude': None}},
         'value': ''},
        {'payload': {'info': {'latitude': float('nan'), 'longitude': 2.0}},
         'value': 'junk'},
        {},
    ])
    def test_unresolvable_records_return_none_pair(self, record):
        assert gs._coords_of(record) == (None, None)


# -------------------------------------------------------------- aggregates

MIXED_RECORDS = [
    rec('ip', '8.8.8.8', {'country': 'United States', 'country_code': 'US',
                          'state': 'California'}),
    rec('ip', '1.1.1.1', {'country': 'Australia', 'countryCode': 'AU',
                          'region': 'NSW'}),
    rec('ip', '2.2.2.2', {'country': 'Australia'}),
    rec('ip', '9.9.9.9', {}),
    rec('ip', '8.8.4.4', {'country': 'United States', 'country_code': 'US'}),
    coords_rec(48.85, 2.35, country='France', code='FR'),
    coords_rec(48.86, 2.36),
    rec('domain', 'example.fr', {'country': 'France'}),
    rec('username', 'bob', {}),
    rec('email', 'a@b.co', {'country_code': 'CO'}),
]

IP_RECORDS = [
    rec('ip', '8.8.8.8', {'country': 'United States',
                          'country_code': 'US'}, ts='2024-06-01T10:00:00Z'),
    rec('ip', '8.8.4.4', {'country': 'United States',
                          'country_code': 'US'}, ts='2024-06-02T11:00:00Z'),
    rec('ip', '1.1.1.1', {'country': 'Australia',
                          'countryCode': 'AU'}, ts='2024-06-03T12:00:00Z'),
    rec('ip', '9.9.9.9', {}, ts='2024-06-04T13:00:00Z'),
    rec('domain', 'example.fr', {'country': 'France'}),
]


class TestCountryBreakdown:

    def test_counts_and_ordering(self):
        breakdown = gs.country_breakdown(MIXED_RECORDS)
        countries = breakdown['countries']
        assert [(c['country'], c['count']) for c in countries] == [
            ('Australia', 2), ('France', 2), ('United States', 2),
            ('Colombia', 1),
        ]
        # Within one count group the name ascending tie-break applies.
        same_count = [c['country'] for c in countries if c['count'] == 2]
        assert same_count == sorted(same_count)
        assert breakdown['total_geo_tagged'] == 7
        assert breakdown['total_records'] == 10
        assert breakdown['unknown'] == 1  # the country-less ip record

    def test_country_entry_shape(self):
        entry = gs.country_breakdown(MIXED_RECORDS)['countries'][0]
        assert set(entry) == {'country', 'code', 'count', 'targets'}
        assert entry['code'] == 'AU'
        assert entry['targets'] == ['1.1.1.1', '2.2.2.2']

    def test_targets_are_capped_at_five(self):
        records = [rec('ip', f'10.0.0.{i}', {'country': 'Germany',
                                             'country_code': 'DE'})
                   for i in range(8)]
        entry = gs.country_breakdown(records)['countries'][0]
        assert entry['count'] == 8
        assert entry['targets'] == [f'10.0.0.{i}' for i in range(5)]

    def test_code_only_records_contribute(self):
        breakdown = gs.country_breakdown([rec('email', 'a@b.co',
                                              {'country_code': 'CO'})])
        assert breakdown['countries'][0]['country'] == 'Colombia'

    def test_empty_records_yield_well_formed_empty_result(self):
        breakdown = gs.country_breakdown([])
        assert breakdown == {'countries': [], 'total_geo_tagged': 0,
                             'total_records': 0, 'unknown': 0}

    def test_junk_records_argument(self):
        assert gs.country_breakdown('junk') == \
            {'countries': [], 'total_geo_tagged': 0,
             'total_records': 0, 'unknown': 0}
        assert gs.country_breakdown(42) == gs.country_breakdown('junk')

    def test_none_loads_through_the_seams(self, history_seam):
        history_seam([{'kind': 'ip', 'value': '1.1.1.1',
                       'payload': {'info': {'country': 'Australia',
                                            'countryCode': 'AU'}},
                       'created_at': '2024-06-01T09:00:00Z'}],
                     [Row('coords', '48.85, 2.35',
                          json.dumps({'info': {'latitude': 48.85,
                                               'longitude': 2.35,
                                               'country': 'France',
                                               'country_code': 'FR'}}),
                          '2024-06-01T10:00:00Z')])
        breakdown = gs.country_breakdown()
        assert breakdown['total_records'] == 2
        assert {c['country'] for c in breakdown['countries']} == \
            {'Australia', 'France'}


class TestTargetsByCountry:

    def test_match_by_name_fragment(self):
        matches = gs.targets_by_country('united', IP_RECORDS)
        assert [m['value'] for m in matches] == ['8.8.8.8', '8.8.4.4']
        assert all(m['kind'] == 'ip' for m in matches)
        assert matches[0]['timestamp'] == '2024-06-01T10:00:00Z'

    def test_match_by_code_case_insensitive(self):
        assert [m['value'] for m in gs.targets_by_country('au', IP_RECORDS)] == \
            ['1.1.1.1']
        assert [m['value'] for m in gs.targets_by_country('AU', IP_RECORDS)] == \
            ['1.1.1.1']

    def test_non_ip_kinds_are_ignored(self):
        assert gs.targets_by_country('France', IP_RECORDS) == []

    def test_country_less_records_are_skipped(self):
        assert gs.targets_by_country('9.9', IP_RECORDS) == []
        assert gs.targets_by_country('none', IP_RECORDS) == []

    def test_empty_needle_returns_empty(self):
        assert gs.targets_by_country('', IP_RECORDS) == []
        assert gs.targets_by_country(None, IP_RECORDS) == []
        assert gs.targets_by_country('   ', IP_RECORDS) == []

    def test_none_records_load_through_the_seams(self, history_seam):
        history_seam([{'kind': 'ip', 'value': '8.8.8.8',
                       'payload': {'info': {'country': 'United States',
                                            'country_code': 'US'}},
                       'created_at': '2024-06-01T10:00:00Z'}], [])
        matches = gs.targets_by_country('US')
        assert [m['value'] for m in matches] == ['8.8.8.8']
        assert matches[0]['timestamp'] == '2024-06-01T10:00:00Z'


class TestGeohashClusters:

    def test_three_cities_form_three_clusters(self):
        records = [
            coords_rec(48.85, 2.35), coords_rec(48.86, 2.36),   # Paris x2
            coords_rec(52.52, 13.40),                            # Berlin
            coords_rec(40.4168, -3.7038),                        # Madrid
        ]
        clusters = gs.geohash_clusters(records)
        assert len(clusters) == 3
        top = clusters[0]
        assert top['geohash'] == 'u09t'
        assert top['count'] == 2
        assert top['targets'] == ['48.85, 2.35', '48.86, 2.36']
        assert top['center'] == [48.855, 2.355]

    def test_cluster_sorting_count_then_geohash(self):
        clusters = gs.geohash_clusters([
            coords_rec(48.85, 2.35), coords_rec(48.86, 2.36),
            coords_rec(52.52, 13.40),
        ])
        assert [c['count'] for c in clusters] == [2, 1]
        singles = gs.geohash_clusters([coords_rec(52.52, 13.40),
                                       coords_rec(40.4168, -3.7038)])
        assert [c['geohash'] for c in singles] == \
            sorted([c['geohash'] for c in singles])

    def test_precision_parameter_splits_neighbourhoods(self):
        # Two points ~1.1 km apart: one precision-4 cluster, two at 5+.
        records = [coords_rec(48.8500, 2.3500), coords_rec(48.8600, 2.3600)]
        assert len(gs.geohash_clusters(records, 4)) == 1
        assert len(gs.geohash_clusters(records, 6)) == 2

    def test_precision_is_clamped(self):
        records = [coords_rec(48.85, 2.35)]
        assert len(gs.geohash_clusters(records, 0)) == 1     # -> 1
        assert len(gs.geohash_clusters(records, 99)) == 1    # -> 9
        assert len(gs.geohash_clusters(records, 'junk')) == 1  # -> 4
        assert len(gs.geohash_clusters(records, None)) == 1  # -> 4

    def test_non_coords_kinds_are_ignored(self):
        assert gs.geohash_clusters([rec('ip', '8.8.8.8', {'latitude': 1,
                                                          'longitude': 2})]) == []

    def test_unparsable_coordinates_are_skipped(self):
        records = [
            rec('coords', 'junk', {'latitude': 'x', 'longitude': 'y'}),
            rec('coords', '', {}),
            coords_rec(48.85, 2.35),
        ]
        clusters = gs.geohash_clusters(records)
        assert len(clusters) == 1

    def test_out_of_range_coordinates_are_skipped(self):
        # _number accepts 999 as finite; latlon_to_geohash rejects it, and
        # the cluster loop must skip the record instead of raising.
        records = [rec('coords', '999, 999', {'latitude': 999,
                                              'longitude': 999}),
                   coords_rec(48.85, 2.35)]
        assert len(gs.geohash_clusters(records)) == 1

    def test_targets_are_capped_at_ten(self):
        records = [coords_rec(48.85 + i * 0.0001, 2.35) for i in range(15)]
        clusters = gs.geohash_clusters(records, 4)
        assert len(clusters[0]['targets']) == 10
        assert clusters[0]['count'] == 15

    def test_empty_records(self):
        assert gs.geohash_clusters([]) == []
        assert gs.geohash_clusters('junk') == []

    def test_none_records_load_coords_rows_only(self, history_seam):
        history_seam([{'kind': 'ip', 'value': '8.8.8.8', 'payload': {},
                       'created_at': None}],
                     [Row('coords', '48.85, 2.35',
                          json.dumps({'info': {'latitude': 48.85,
                                               'longitude': 2.35}}),
                          '2024-06-01T10:00:00Z')])
        clusters = gs.geohash_clusters()
        assert len(clusters) == 1
        assert clusters[0]['center'] == [48.85, 2.35]


class TestMostLookedUpRegions:

    def test_ranking_and_entry_shape(self):
        regions = gs.most_looked_up_regions(MIXED_RECORDS)
        assert [(r['region'], r['country']) for r in regions] == [
            ('California', 'United States'),
            ('NSW', 'Australia'),
        ]
        assert set(regions[0]) == {'region', 'country', 'count', 'targets'}
        assert regions[0]['targets'] == ['8.8.8.8']

    def test_region_field_vocabulary(self):
        records = [
            rec('ip', 'a', {'state': 'Texas'}),
            rec('ip', 'b', {'region': 'Bavaria'}),
            rec('ip', 'c', {'region_name': 'Andalusia'}),
            rec('ip', 'd', {'regionName': 'Ontario'}),
            rec('ip', 'e', {'stateProv': 'Zealand'}),
            rec('ip', 'f', {'principal_subdivision': 'Sicily'}),
        ]
        found = {r['region'] for r in gs.most_looked_up_regions(records)}
        assert found == {'Texas', 'Bavaria', 'Andalusia', 'Ontario', 'Zealand',
                         'Sicily'}

    def test_coords_and_domain_kinds_contribute(self):
        records = [
            coords_rec(48.85, 2.35, country='France', code='FR'),
            rec('domain', 'x.de', {'region': 'Hamburg'}),
            rec('username', 'bob', {'state': 'Nowhere'}),
        ]
        found = {r['region'] for r in gs.most_looked_up_regions(records)}
        # coords payload has no region field; domain does; username is skipped.
        assert found == {'Hamburg'}

    def test_limit_and_clamping(self):
        records = [rec('ip', f'10.0.0.{i}', {'state': f'S{i}'}) for i in range(7)]
        assert len(gs.most_looked_up_regions(records)) == 7
        assert len(gs.most_looked_up_regions(records, limit=3)) == 3
        assert len(gs.most_looked_up_regions(records, limit=0)) == 1
        assert len(gs.most_looked_up_regions(records, limit=-5)) == 1
        assert len(gs.most_looked_up_regions(records, limit='junk')) == 7

    def test_counts_tie_break_by_region_name(self):
        records = [rec('ip', 'a', {'state': 'Zeta'}),
                   rec('ip', 'b', {'state': 'Alpha'})]
        assert [r['region'] for r in gs.most_looked_up_regions(records)] == \
            ['Alpha', 'Zeta']

    def test_empty_records(self):
        assert gs.most_looked_up_regions([]) == []
        assert gs.most_looked_up_regions('junk') == []

    def test_country_fills_in_when_first_record_lacked_one(self):
        records = [rec('ip', 'a', {'state': 'Texas'}),
                   rec('ip', 'b', {'state': 'Texas', 'country': 'United States',
                                   'country_code': 'US'})]
        regions = gs.most_looked_up_regions(records)
        assert regions[0]['country'] == 'United States'
        assert regions[0]['count'] == 2


class TestToGeojson:

    def test_feature_collection_structure(self):
        breakdown = gs.country_breakdown(MIXED_RECORDS)
        collection = gs.to_geojson(breakdown)
        assert collection['type'] == 'FeatureCollection'
        assert len(collection['features']) == 4
        feature = collection['features'][0]
        assert feature['type'] == 'Feature'
        assert set(feature['properties']) == {'country', 'count', 'targets'}
        assert feature['geometry']['type'] == 'Point'

    def test_geometry_follows_geojson_lon_lat_order(self):
        collection = gs.to_geojson(gs.country_breakdown(MIXED_RECORDS))
        by_country = {f['properties']['country']: f['geometry']['coordinates']
                      for f in collection['features']}
        assert by_country['United States'] == [-98.6, 39.8]
        assert by_country['Australia'][0] > 100   # lon first (positive)
        assert by_country['Australia'][1] < 0     # lat second (negative)
        assert len(by_country) == 4

    def test_unknown_country_keeps_feature_with_null_geometry(self):
        breakdown = {'countries': [{'country': 'Atlantis', 'code': '',
                                    'count': 3, 'targets': ['x']}]}
        collection = gs.to_geojson(breakdown)
        assert len(collection['features']) == 1
        assert collection['features'][0]['geometry'] is None
        assert collection['features'][0]['properties']['count'] == 3

    def test_empty_breakdown(self):
        collection = gs.to_geojson({'countries': []})
        assert collection == {'type': 'FeatureCollection', 'features': []}

    @pytest.mark.parametrize('junk', [None, {}, {'countries': None},
                                      {'countries': 'x'},
                                      {'countries': ['junk', None, 5]}])
    def test_junk_breakdowns_yield_empty_collection(self, junk):
        collection = gs.to_geojson(junk)
        assert collection == {'type': 'FeatureCollection', 'features': []}

    def test_non_list_targets_rendered_as_empty(self):
        breakdown = {'countries': [{'country': 'France', 'code': 'FR',
                                    'count': 1, 'targets': 'not-a-list'}]}
        feature = gs.to_geojson(breakdown)['features'][0]
        assert feature['properties']['targets'] == []


class TestGeoProfileSummary:

    def test_keys_and_values(self):
        records = MIXED_RECORDS + [
            coords_rec(52.52, 13.40, ts='2024-06-05T10:00:00Z'),
        ]
        summary = gs.geo_profile_summary(records)
        assert set(summary) == {'distinct_countries', 'top_country', 'top_region',
                                'coords_lookups', 'geohash_clusters', 'span_days'}
        assert summary['distinct_countries'] == 4
        assert summary['top_country']['country'] == 'Australia'
        assert summary['top_region']['region'] == 'California'
        assert summary['coords_lookups'] == 3
        assert summary['geohash_clusters'] == 2  # Paris (x2) + Berlin
        assert summary['span_days'] == 4.0  # 2024-06-01 -> 2024-06-05

    def test_span_zero_for_identical_timestamps(self):
        records = [rec('ip', 'a', {'country': 'France'}, ts='2024-06-01T10:00:00Z'),
                   rec('ip', 'b', {'country': 'France'}, ts='2024-06-01T10:00:00Z')]
        assert gs.geo_profile_summary(records)['span_days'] == 0.0

    def test_span_none_with_fewer_than_two_timestamps(self):
        records = [rec('ip', 'a', {'country': 'France'}, ts='2024-06-01T10:00:00Z')]
        assert gs.geo_profile_summary(records)['span_days'] is None
        assert gs.geo_profile_summary([])['span_days'] is None

    def test_empty_history_summary(self):
        summary = gs.geo_profile_summary([])
        assert summary == {
            'distinct_countries': 0, 'top_country': None, 'top_region': None,
            'coords_lookups': 0, 'geohash_clusters': 0, 'span_days': None,
        }

    def test_epoch_millisecond_timestamps_contribute_to_span(self):
        records = [rec('ip', 'a', {'country': 'France'}, ts=1717236000),
                   rec('ip', 'b', {'country': 'France'}, ts=1717581600)]
        assert gs.geo_profile_summary(records)['span_days'] == 4.0

    def test_none_records_load_through_the_seams(self, history_seam):
        history_seam([{'kind': 'ip', 'value': '1.1.1.1',
                       'payload': {'info': {'country': 'Australia',
                                            'countryCode': 'AU'}},
                       'created_at': '2024-06-01T10:00:00Z'}],
                     [Row('coords', '48.85, 2.35',
                          json.dumps({'info': {'latitude': 48.85,
                                               'longitude': 2.35}}),
                          '2024-06-01T11:00:00Z')])
        summary = gs.geo_profile_summary()
        assert summary['distinct_countries'] == 1
        assert summary['coords_lookups'] == 1
        assert summary['span_days'] == pytest.approx(1 / 24, abs=0.01)
