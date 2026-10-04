"""Flight designator source and tracker tests (v6.0 kind; fully offline).

Covers the designator validator (IATA/ICAO grammar, separator and lower-case
tolerance, ``split_flight`` parts), the offline ``airline_pack`` and
``flight_math`` readers (carrier resolution, radio callsign concatenation,
number anatomy, direction and band conventions, the airport helper
utilities), the keyed aviationstack reader (record parsing, key gating,
malformed payloads - mocked through ``fake_http``), ``gather_all``
provenance/priority semantics, the tracker envelope and its failure
short-circuits, the shipped rule pack through ``evaluate_rules``,
full-platform registration (CLI parser, web kinds, MCP tool, entity
extraction) and the airline data pack loader (comments, malformed lines,
missing file).
"""

import pytest

from obscuralens import commands
from obscuralens.config import config
from obscuralens.trackers import flight_sources as fs
from obscuralens.trackers.flight_tracker import FlightTracker
from obscuralens.utils.validators import normalize_flight, split_flight, validate_flight

#: Well-formed designators: 2-letter IATA, 3-letter ICAO, 4-digit runs and
#: an operational suffix letter.
VALID_DESIGNATORS = ('UA1', 'BA2490', 'DLH400A', 'LH1234', 'UAL2607',
                     'BA600')

#: A realistic aviationstack ``/v1/flights`` first rotation record.
AVIATIONSTACK_RECORD = {
    'flight_status': 'active',
    'airline': {'name': 'British Airways'},
    'aircraft': {'reg_number': 'G-XLEA'},
    'departure': {'airport': 'Heathrow', 'iata': 'LHR',
                  'scheduled': '2026-10-01T08:25:00+00:00'},
    'arrival': {'airport': 'John F. Kennedy International', 'iata': 'JFK',
                'scheduled': '2026-10-01T11:10:00+00:00'},
}


@pytest.fixture(autouse=True)
def _reset_source_health():
    """Keep persisted source-health streaks from leaking between tests."""
    from obscuralens.health import health
    health.reset()
    yield
    health.reset()


# --------------------------------------------------------------------------- #
# validate_flight / normalize_flight / split_flight
# --------------------------------------------------------------------------- #

class TestValidateFlight:

    @pytest.mark.parametrize('designator', VALID_DESIGNATORS)
    def test_valid_designators(self, designator):
        ok, error = validate_flight(designator)
        assert ok is True
        assert error == ''

    def test_invalid_designators_rejected(self):
        for bad in ('1234',        # no carrier letters
                    'ABCD1',       # four-letter carrier
                    'ABCDE',       # letters only
                    'A1',          # one-letter carrier
                    'UA12345',     # five-digit flight number
                    '24'):         # digits only
            ok, error = validate_flight(bad)
            assert ok is False, bad
            assert 'Invalid flight designator' in error
        # Empty and None get their own message before the grammar runs.
        for empty in ('', None):
            ok, error = validate_flight(empty)
            assert ok is False
            assert 'cannot be empty' in error

    def test_lowercase_and_separator_forms_normalise(self):
        assert normalize_flight('ua 1') == 'UA1'
        assert normalize_flight('ba-2490') == 'BA2490'
        assert normalize_flight('dlh 400a') == 'DLH400A'
        assert validate_flight('ba 2490')[0] is True
        # The separator tolerance never rescues a bad shape.
        assert normalize_flight('ua 12345') == ''

    def test_split_flight_parts(self):
        assert split_flight('DLH400A') == ('DLH', '400', 'A')
        assert split_flight('UA1') == ('UA', '1', '')
        assert split_flight('ba2490') == ('BA', '2490', '')
        # The carrier keeps its 2- or 3-letter shape, so callers can tell
        # an IATA code from an ICAO code by length alone.
        assert len(split_flight('UAL2607')[0]) == 3
        assert split_flight('nope') is None
        assert split_flight('') is None


# --------------------------------------------------------------------------- #
# offline airline_pack + flight_math (+ airport helpers)
# --------------------------------------------------------------------------- #

class TestFlightMathAndAirline:

    def test_iata_carrier_resolves_airline(self):
        out = fs._airline_pack('UA1')
        assert out['airline_name'] == 'United Airlines'
        assert out['airline_iata'] == 'UA'
        assert out['airline_icao'] == 'UAL'
        assert out['country'] == 'United States'
        assert out['callsign'] == 'UNITED'

    def test_icao_carrier_resolves_airline(self):
        # A 3-letter ICAO query resolves through the reverse index and
        # reports both codes.
        out = fs._airline_pack('DLH400A')
        assert out['airline_name'] == 'Lufthansa'
        assert out['airline_iata'] == 'LH'
        assert out['airline_icao'] == 'DLH'
        assert out['country'] == 'Germany'
        assert out['callsign'] == 'LUFTHANSA'

    def test_callsign_and_radio_concatenation(self):
        pack = fs._airline_pack('BA2490')
        math = fs._flight_math('BA2490')
        # The pack carries the radio callsign word, the math source
        # concatenates the ICAO code with the number.
        assert pack['callsign'] == 'SPEEDBIRD'
        assert math['radio_callsign'] == 'BAW2490'
        assert math['flight_icao_code'] == 'BAW2490'
        assert math['flight_iata_code'] == 'BA2490'

    def test_unknown_carrier_reports_none(self):
        # A curated-subset miss is an explicit "no airline name", not {}.
        assert fs._airline_pack('XX9999') == {'airline_name': None}
        math = fs._flight_math('XX9999')
        assert 'airline_name' not in math
        # The unresolved 2-letter carrier still echoes its IATA rendering.
        assert math['flight_iata_code'] == 'XX9999'
        assert 'flight_icao_code' not in math
        assert 'radio_callsign' not in math

    def test_number_and_suffix_anatomy(self):
        ba = fs._flight_math('BA2490')
        assert ba['carrier_code'] == 'BA'
        assert ba['carrier_code_type'] == 'IATA'
        assert ba['flight_number_digits'] == 2490
        assert ba['digit_count'] == 4
        assert 'suffix_letter' not in ba
        dlh = fs._flight_math('DLH400A')
        assert dlh['carrier_code_type'] == 'ICAO'
        assert dlh['flight_number_digits'] == 400
        assert dlh['digit_count'] == 3
        assert dlh['suffix_letter'] == 'A'
        assert dlh['flight_iata_code'] == 'LH400A'
        assert dlh['radio_callsign'] == 'DLH400'  # suffix never goes on radio

    def test_direction_hints(self):
        odd = fs._flight_math('UA1')['direction_hint']
        even = fs._flight_math('BA2490')['direction_hint']
        assert 'outbound' in odd
        assert 'return' in even
        assert 'convention only, not evidence' in odd
        assert 'convention only, not evidence' in even

    def test_number_band_hints(self):
        assert '1-499' in fs._flight_math('UA1')['number_band_hint']
        assert '500-899' in fs._flight_math('BA600')['number_band_hint']
        assert '900+' in fs._flight_math('BA2490')['number_band_hint']
        assert 'convention' in fs._flight_math('UA1')['number_band_hint']

    def test_garbage_returns_empty(self):
        assert fs._flight_math('nope') == {}
        assert fs._airline_pack('nope') == {}
        assert fs._flight_math('') == {}

    def test_airport_helper_utilities(self):
        jfk = fs.lookup_airport('jfk')  # case-insensitive
        assert jfk['city'] == 'New York'
        assert jfk['country'] == 'United States'
        assert jfk['latitude'] == pytest.approx(40.6413)
        assert fs.lookup_airport('ZZZ') is None
        assert fs.lookup_airport(42) is None
        # Great-circle kilometres reuse the shared haversine helper.
        assert fs.airport_distance('JFK', 'LHR') == pytest.approx(5540.0,
                                                                 abs=20.0)
        assert fs.airport_distance('JFK', 'jfk') == 0.0
        assert fs.airport_distance('JFK', 'ZZZ') is None


# --------------------------------------------------------------------------- #
# keyed aviationstack reader (mocked through fake_http)
# --------------------------------------------------------------------------- #

class TestFlightOnline:

    def test_aviationstack_parses_record(self, fake_http):
        fake_http.json = lambda url, **kwargs: (
            True, {'data': [dict(AVIATIONSTACK_RECORD)]}, '')
        out = fs._aviationstack('BA2490', 'KEY123')
        assert out['avstack_status'] == 'active'
        assert out['avstack_airline'] == 'British Airways'
        assert out['avstack_aircraft_registration'] == 'G-XLEA'
        assert out['avstack_departure_airport'] == 'Heathrow'
        assert out['avstack_departure_iata'] == 'LHR'
        assert out['avstack_departure_scheduled'] == '2026-10-01T08:25:00+00:00'
        assert out['avstack_arrival_iata'] == 'JFK'
        # The query URL carries the key and the IATA rendering.
        assert any('access_key=KEY123' in url and 'flight_iata=BA2490' in url
                   for _mode, url in fake_http.calls)

    def test_aviationstack_requires_key(self, fake_http):
        assert fs._aviationstack('BA2490', '') == {}
        assert fs._aviationstack('BA2490', None) == {}
        assert fake_http.calls == []  # no key means no request at all

    def test_aviationstack_malformed_payloads_return_empty(self, fake_http):
        payloads = (
            {'data': []},             # no live rotations today
            {'data': 'nope'},         # data not a list
            {'data': ['nope']},       # record not a dict
            {'unexpected': 'shape'},  # no data key at all
        )
        for payload in payloads:
            fake_http.json = lambda url, data=payload, **kw: (True, data, '')
            assert fs._aviationstack('BA2490', 'KEY123') == {}
        # A transport failure degrades the same way.
        fake_http.json = lambda url, **kwargs: (False, None, 'timeout')
        assert fs._aviationstack('BA2490', 'KEY123') == {}

    def test_gather_adds_keyed_source_only_with_key(self, fake_http):
        fake_http.json = lambda url, **kwargs: (
            True, {'data': [dict(AVIATIONSTACK_RECORD)]}, '')
        without = fs.gather_all('BA2490')
        assert 'aviationstack' not in without['sources']
        with_key = fs.gather_all('BA2490', keys={'aviationstack': 'KEY123'})
        assert with_key['sources']['aviationstack']['ok'] is True
        assert with_key['fields']['avstack_status'] == 'active'


# --------------------------------------------------------------------------- #
# gather_all merge semantics
# --------------------------------------------------------------------------- #

class TestFlightGather:

    def test_gather_all_pack_wins_provenance(self, fake_http):
        out = fs.gather_all('BA2490')
        # airline_pack runs first in FREE_SOURCES, so its name and callsign
        # win over any later mirror of the same fact.
        assert out['fields']['airline_name'] == 'British Airways'
        assert out['provenance']['airline_name'] == ['airline_pack']
        assert out['fields']['flight'] == 'BA2490'
        assert 'flight' not in out['provenance']  # the identifier is not sourced
        assert out['sources']['airline_pack']['ok'] is True
        assert out['sources']['flight_math']['ok'] is True

    def test_gather_all_all_sources_failing(self, monkeypatch):
        def boom(flight):
            raise RuntimeError('source exploded')

        monkeypatch.setattr(fs, 'FREE_SOURCES',
                            {'airline_pack': boom, 'flight_math': boom})
        out = fs.gather_all('BA2490')
        assert out['fields'] == {'flight': 'BA2490'}
        assert out['provenance'] == {}
        for status in out['sources'].values():
            assert status['ok'] is False
            assert status['error'] == 'RuntimeError'

    def test_gather_all_unparseable_raises_valueerror(self):
        with pytest.raises(ValueError):
            fs.gather_all('1234')
        with pytest.raises(ValueError):
            fs.gather_all('')

    def test_gather_all_respects_disabled_sources(self, monkeypatch):
        monkeypatch.setattr(config.app_config, 'disabled_sources',
                            ['flight_math'])
        out = fs.gather_all('BA2490')
        assert 'flight_math' not in out['sources']
        assert 'radio_callsign' not in out['fields']
        assert out['sources']['airline_pack']['ok'] is True


# --------------------------------------------------------------------------- #
# FlightTracker envelope
# --------------------------------------------------------------------------- #

class TestFlightTracker:

    def test_track_envelope_and_merged_fields(self, fake_http):
        result = FlightTracker().track('BA2490')
        assert set(result) == {'flight', 'info', 'field_sources', 'sources_ok',
                               'sources_failed', 'field_count', 'success',
                               'errors'}
        assert result['flight'] == 'BA2490'
        assert result['success'] is True
        # Offline sources only: aviationstack needs a configured key.
        assert result['sources_ok'] == ['airline_pack', 'flight_math']
        assert result['sources_failed'] == {}
        assert result['errors'] == []
        assert result['info']['flight'] == 'BA2490'
        assert result['info']['airline_name'] == 'British Airways'
        assert result['info']['callsign'] == 'SPEEDBIRD'
        assert result['info']['radio_callsign'] == 'BAW2490'
        assert result['field_sources']['airline_name'] == ['airline_pack']
        assert result['field_sources']['radio_callsign'] == ['flight_math']
        assert result['field_count'] >= 10

    def test_track_invalid_short_circuits_without_network(self, fake_http):
        for bad in ('1234', 'UA12345', ''):
            result = FlightTracker().track(bad)
            assert result['success'] is False
            assert result['sources_ok'] == []
            assert result['field_count'] == 0
            assert result['errors']
        assert fake_http.calls == []  # a bad designator never leaves the machine

    def test_track_normalises_input(self, fake_http):
        result = FlightTracker().track('ba 2490')
        assert result['flight'] == 'BA2490'
        assert result['info']['flight'] == 'BA2490'
        assert result['success'] is True

    def test_track_writes_query_history(self, fake_http, tmp_env):
        FlightTracker().track('UA1')
        from obscuralens.database import db
        record = db.get_query_by_id(db.search_history('UA1')[0].id)
        assert record.query_type == 'flight'
        assert record.query_value == 'UA1'
        assert record.success is True

    def test_batch_track_preserves_order_and_isolates_failures(self, fake_http):
        results = FlightTracker().batch_track(['UA1', '1234', 'BA2490'])
        assert len(results) == 3
        assert [r['success'] for r in results] == [True, False, True]
        assert results[1]['field_count'] == 0
        assert results[2]['flight'] == 'BA2490'

    def test_source_names_and_source_catalog(self):
        tracker = FlightTracker()
        assert tracker.source_names() == ['airline_pack', 'aviationstack',
                                          'flight_math']
        catalog = tracker.source_catalog()
        assert set(catalog) == {'airline_pack', 'flight_math',
                                'aviationstack'}
        assert all(catalog.values())  # every source has a description


# --------------------------------------------------------------------------- #
# rule pack
# --------------------------------------------------------------------------- #

class TestFlightRules:

    def test_flight_pack_loads_with_rules(self):
        from obscuralens.rules import load_pack
        pack = load_pack('flight')
        assert pack is not None
        assert pack.kind == 'flight'
        assert pack.rule_count >= 8
        assert {rule.id for rule in pack.rules} >= {'FLIGHT-001', 'FLIGHT-003',
                                                    'FLIGHT-009'}

    def test_registered_carrier_scores_clean(self, fake_http):
        from obscuralens.rules import evaluate_rules
        fields = fs.gather_all('BA2490')['fields']
        evaluation = evaluate_rules('flight', fields)
        assert 'FLIGHT-009' in evaluation.matched_ids  # name+country+callsign
        assert 'FLIGHT-001' not in evaluation.matched_ids
        assert evaluation.band == 'clean'

    def test_unknown_carrier_and_cancelled_status_hit_rules(self):
        from obscuralens.rules import evaluate_rules
        unknown = fs.gather_all('XX9999')['fields']
        evaluation = evaluate_rules('flight', unknown)
        assert 'FLIGHT-001' in evaluation.matched_ids
        assert evaluation.score >= 10
        # A cancelled live rotation hits the medium-severity status rule.
        cancelled = dict(fs.gather_all('BA2490')['fields'],
                         avstack_status='cancelled')
        evaluation = evaluate_rules('flight', cancelled)
        assert 'FLIGHT-003' in evaluation.matched_ids
        assert 'FLIGHT-009' in evaluation.matched_ids


# --------------------------------------------------------------------------- #
# platform registration (CLI / web / MCP / entity extraction)
# --------------------------------------------------------------------------- #

class TestFlightRegistration:

    def test_cli_kinds_and_flight_subcommand_parse(self, capsys):
        assert 'flight' in commands.KINDS
        assert 'flight' in commands._VALIDATORS
        assert commands._HANDLERS['flight'] is commands._cmd_flight
        parser = commands.build_parser()
        args = parser.parse_args(['flight', 'BA2490'])
        assert args.command == 'flight'
        assert args.target == 'BA2490'
        # An invalid designator is rejected before any tracker runs.
        assert commands.run(['flight', '1234']) == 2
        assert 'Error' in capsys.readouterr().err

    def test_cli_flight_json_and_table_output(self, monkeypatch, capsys):
        import json
        result = {
            'flight': 'BA2490',
            'info': {'airline_name': 'British Airways',
                     'radio_callsign': 'BAW2490'},
            'field_sources': {'airline_name': ['airline_pack']},
            'sources_ok': ['airline_pack', 'flight_math'],
            'sources_failed': {}, 'field_count': 2, 'success': True,
            'errors': [],
        }

        class FakeTracker:
            def track(self, target, **kwargs):
                return dict(result)

        monkeypatch.setattr(commands, '_tracker', lambda kind: FakeTracker())
        assert commands.run(['flight', 'BA2490', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['flight'] == 'BA2490'
        assert payload['info']['airline_name'] == 'British Airways'
        assert commands.run(['flight', 'BA2490']) == 0
        out = capsys.readouterr().out
        assert 'British Airways' in out
        assert 'AIRLINE' in out.upper()

    def test_web_app_kinds_include_flight(self):
        web_app = pytest.importorskip('obscuralens.web.app')
        assert 'flight' in web_app.KINDS
        assert 'flight' in web_app._VALIDATORS
        assert 'flight' in web_app._TRACKERS

    def test_mcp_flight_lookup_tool_compacts_result(self, monkeypatch):
        from obscuralens import mcp_server
        from obscuralens.trackers import FlightTracker as tracker_class

        result = {
            'flight': 'BA2490', 'info': {'airline_name': 'British Airways'},
            'field_sources': {'airline_name': ['airline_pack'],
                              'callsign': ['airline_pack']},
            'sources_ok': ['airline_pack', 'flight_math'],
            'sources_failed': {}, 'field_count': 2, 'success': True,
            'errors': [],
        }
        monkeypatch.setattr(tracker_class, 'track',
                            lambda self, target: dict(result))
        payload = mcp_server.call_tool(
            'flight_lookup', {'flight': 'BA2490'})
        assert payload['flight'] == 'BA2490'
        assert payload['success'] is True
        assert payload['provenance_counts'] == {'airline_name': 1,
                                                'callsign': 1}

        tools = mcp_server.handle_request(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
        )['result']['tools']
        assert 'flight_lookup' in {tool['name'] for tool in tools}

    def test_entity_extract_finds_flight_in_text(self):
        from obscuralens.experimental.entity_extract import extract_entities
        found = extract_entities('Flight BA2490 departed London today.')
        assert found['flights'] == ['BA2490']
        # The extractor is pack-gated: an unknown carrier never survives,
        # keeping prose like "THE123" out of the results.
        assert extract_entities('THE123 people attended')['flights'] == []
        assert extract_entities('flight ba2490 lowercase')['flights'] == []


# --------------------------------------------------------------------------- #
# airline data pack loader
# --------------------------------------------------------------------------- #

class TestFlightPack:

    def test_pack_loads_curated_airlines(self):
        by_iata, icao_to_iata = fs._load_airline_pack()
        assert len(by_iata) >= 130
        assert by_iata['UA'] == ('UAL', 'United Airlines', 'United States',
                                 'UNITED')
        assert by_iata['BA'] == ('BAW', 'British Airways', 'United Kingdom',
                                 'SPEEDBIRD')
        assert icao_to_iata['DLH'] == 'LH'

    def test_pack_tolerates_comments_and_bad_lines(self, tmp_path, monkeypatch):
        (tmp_path / 'airlines_iata.txt').write_text(
            '# airline pack header\n'
            '\n'
            'ua|ual|United Airlines|United States|UNITED\n'   # lowercase keys
            'BA|BAW|British Airways\n'          # only four fields
            'XX|XX|No Country||\n'              # empty callsign is fine
            'TOOLONG|XXL|Way Too Long|Nowhere|NOPE\n'
            'DLH|DLH|Lufthansa|Germany|LUFTHANSA\n',
            encoding='utf-8')
        monkeypatch.setattr(fs, 'DATA_DIR', tmp_path)
        monkeypatch.setattr(fs, '_AIRLINE_CACHE', None)
        by_iata, icao_to_iata = fs._load_airline_pack()
        # Keys are uppercased; malformed rows are skipped, not fatal.
        assert by_iata['UA'] == ('UAL', 'United Airlines', 'United States',
                                 'UNITED')
        assert 'BA' not in by_iata       # 4-field line dropped
        assert 'TOOLONG' not in by_iata  # carrier too long
        assert by_iata['DLH'] == ('DLH', 'Lufthansa', 'Germany',
                                  'LUFTHANSA')
        assert icao_to_iata['DLH'] == 'DLH'

    def test_pack_missing_file_is_empty_and_not_cached(self, tmp_path,
                                                       monkeypatch):
        monkeypatch.setattr(fs, 'DATA_DIR', tmp_path)  # no file here
        monkeypatch.setattr(fs, '_AIRLINE_CACHE', None)
        by_iata, icao_to_iata = fs._load_airline_pack()
        assert by_iata == {}
        assert icao_to_iata == {}
        # A missing pack is not cached, so a later call can retry.
        assert fs._AIRLINE_CACHE is None

    def test_data_catalog_airline_mirror(self):
        from obscuralens.utils import data_catalog
        entry = data_catalog.airline('UA')
        assert entry is not None
        assert entry.name == 'United Airlines'
        assert data_catalog.airlines_count() >= 130
        assert data_catalog.airline('XX') is None
