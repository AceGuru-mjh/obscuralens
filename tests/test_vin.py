"""VIN source and tracker tests (v6.0 kind; fully offline).

Covers the ISO 3779 validator (real VINs, I/O/Q rejection, separator and
lower-case tolerance, check-digit verdicts), the offline ``vin_math``
decomposition (WMI pack lookups, region hints, year-code cycle, plant and
serial extraction, position map), the keyless NHTSA vPIC reader (record
parsing, truncation, malformed payloads - mocked through ``fake_http``),
``gather_all`` provenance/priority semantics, the tracker envelope and its
failure short-circuits (an invalid VIN never touches the network), the
shipped rule pack through ``evaluate_rules``, full-platform registration
(CLI parser, web kinds, MCP tool, entity extraction) and the WMI data pack
loader (comments, malformed lines, missing file, key casing).
"""

import pytest

from obscuralens import commands
from obscuralens.config import config
from obscuralens.trackers import vin_sources as vs
from obscuralens.trackers.vin_tracker import VINTracker
from obscuralens.utils.validators import normalize_vin, validate_vin

#: Real, structurally valid VINs (correct ISO 3779 check digits) spanning
#: several regions and manufacturers - Honda US, the classic vPIC sample,
#: Ford US, BMW Germany, Honda Japan.
REAL_VINS = (
    '1HGCM82633A004352',   # Honda Accord, United States
    '1M8GDM9AXKP042788',   # the canonical ISO 3779 worked example
    '1FA6P8CF7L5123456',   # Ford, United States
    'WBA5B5C53FD520230',   # BMW, Germany
    'JHMCM56557C404453',   # Honda, Japan
)

#: A VIN-shaped string whose position-9 check digit is '4' (expected '3').
BAD_CHECK_DIGIT_VIN = '1HGCM82643A004352'

#: Valid VIN carrying the model-year code 'A' (1980 or 2010).
YEAR_A_VIN = '1HGCM8267AA004352'

#: Valid VIN whose WMI is absent from the curated pack (manufacturer None).
UNKNOWN_WMI_VIN = 'JT2BF22K5W0123456'

#: A realistic vPIC ``DecodeVinValues`` record (fields the API fills for a
#: North American market vehicle).
VPIC_RECORD = {
    'Make': 'HONDA',
    'Model': 'Accord',
    'ModelYear': '2003',
    'VehicleType': 'PASSENGER CAR',
    'BodyClass': 'Sedan',
    'DriveType': 'FWD',
    'FuelTypePrimary': 'Gasoline',
    'EngineCylinders': '6',
    'EngineHP': '240',
    'DisplacementL': '3.0',
    'Doors': '4',
    'Manufacturer': 'HONDA OF AMERICA MFG., INC.',
    'PlantCity': 'Marysville',
    'PlantState': 'Ohio',
    'PlantCountry': 'United States',
    'ErrorCode': '0',
    'AdditionalErrorText': '',
}


@pytest.fixture(autouse=True)
def _reset_source_health():
    """Keep persisted source-health streaks from leaking between tests."""
    from obscuralens.health import health
    health.reset()
    yield
    health.reset()


@pytest.fixture()
def vpic_http(fake_http):
    """fake_http primed with a successful vPIC decode for any VIN."""
    fake_http.json = lambda url, **kwargs: (True, {'Results': [dict(VPIC_RECORD)]}, '')
    return fake_http


# --------------------------------------------------------------------------- #
# validate_vin / normalize_vin
# --------------------------------------------------------------------------- #

class TestValidateVIN:

    @pytest.mark.parametrize('vin', REAL_VINS)
    def test_real_vins_validate(self, vin):
        ok, error = validate_vin(vin)
        assert ok is True
        assert error == ''

    def test_wrong_length_and_shape_rejected(self):
        # 16 characters and 18 characters both fail the fixed length.
        assert validate_vin('1HGCM82633A00435')[0] is False
        assert validate_vin('1HGCM82633A0043522')[0] is False
        # Non-alphanumeric junk fails the character set.
        assert validate_vin('1HGCM82633A00435!')[0] is False
        assert 'Invalid VIN format' in validate_vin('1HGCM82633A00435!')[1]
        # Garbage never normalises into anything.
        assert normalize_vin('not-a-vin-at-all') == ''
        assert normalize_vin('') == ''

    def test_ioq_characters_rejected(self):
        for bad in ('1HGCM82633I004352', '1HGCM82633O004352',
                    '1HGCM82633Q004352'):
            ok, error = validate_vin(bad)
            assert ok is False
            assert 'no I/O/Q' in error

    def test_lowercase_and_separator_forms_normalise(self):
        assert validate_vin('1hgcm82633a004352')[0] is True
        assert normalize_vin('1M8-GDM9-A-XKP042788') == '1M8GDM9AXKP042788'
        assert normalize_vin('1m8 gdm9 axkp042788') == '1M8GDM9AXKP042788'
        # The separator tolerance never rescues a wrong length.
        assert normalize_vin('1M8-GDM9-AXKP04278') == ''

    def test_all_digit_17_character_shape(self):
        # Digits are legal VIN characters: an all-digit body validates when
        # (and only when) its position-9 check digit is correct.
        assert validate_vin('12345678712345678')[0] is True
        assert validate_vin('12345678912345678')[0] is False
        assert 'check digit failed' in validate_vin('12345678912345678')[1]

    def test_wrong_check_digit_rejected(self):
        ok, error = validate_vin(BAD_CHECK_DIGIT_VIN)
        assert ok is False
        assert 'check digit failed' in error
        # The same VIN with the computed digit passes.
        assert validate_vin('1HGCM82633A004352')[0] is True

    def test_empty_blank_and_none_rejected(self):
        for empty in ('', None):
            ok, error = validate_vin(empty)
            assert ok is False
            assert 'cannot be empty' in error
        # Whitespace-only input is not "empty" - it fails the shape check.
        ok, error = validate_vin('   ')
        assert ok is False
        assert 'Invalid VIN format' in error


# --------------------------------------------------------------------------- #
# offline vin_math decomposition
# --------------------------------------------------------------------------- #

class TestVINMath:

    def test_wmi_resolves_manufacturer_and_country(self):
        expected = {
            '1FA6P8CF7L5123456': ('1FA', 'Ford', 'United States'),
            'WBA5B5C53FD520230': ('WBA', 'BMW', 'Germany'),
            '1HGCM82633A004352': ('1HG', 'Honda', 'United States'),
        }
        for vin, (wmi, maker, country) in expected.items():
            out = vs._vin_math(vin)
            assert out['wmi'] == wmi
            assert out['manufacturer'] == maker
            assert out['country'] == country

    def test_unknown_wmi_reports_none_manufacturer(self):
        out = vs._vin_math(UNKNOWN_WMI_VIN)
        assert out['manufacturer'] is None
        assert 'country' not in out  # a miss never fabricates a country
        assert out['check_digit_valid'] is True
        # Unparseable input answers with an empty dict, never an exception.
        assert vs._vin_math('nope') == {}
        assert vs._vin_math('') == {}

    def test_first_character_region_hints(self):
        expected = {
            '1HGCM82633A004352': 'United States',
            'WBA5B5C53FD520230': 'Germany',
            'JHMCM56557C404453': 'Japan',
            'KMHFC4CD0UA012345': 'South Korea',
            '3VW5T7AJ1KM012345': 'Mexico',
        }
        for vin, region in expected.items():
            assert vs._vin_math(vin)['region_hint'] == region

    def test_check_digit_verdicts(self):
        good = vs._vin_math('1HGCM82633A004352')
        assert good['check_digit'] == '3'
        assert good['check_digit_valid'] is True
        assert 'expected_check_digit' not in good
        bad = vs._vin_math(BAD_CHECK_DIGIT_VIN)
        assert bad['check_digit_valid'] is False
        assert bad['expected_check_digit'] == '3'

    def test_year_code_decodes_with_cycle_candidates(self):
        out = vs._vin_math(YEAR_A_VIN)
        assert out['year_code'] == 'A'
        assert out['model_year_candidates'] == [1980, 2010]
        assert out['model_year'] == 2010  # the more recent cycle wins
        assert '1980' in out['model_year_cycle']
        assert '2010' in out['model_year_cycle']
        assert '30-year cycle' in out['model_year_cycle']

    def test_non_standard_year_code_is_flagged(self):
        # 'U' is not one of the 30 model-year codes (the alphabet skips it).
        out = vs._vin_math('KMHFC4CD0UA012345')
        assert out['year_code'] == 'U'
        assert 'model_year_candidates' not in out
        assert 'model_year' not in out
        assert 'not a standard model-year code' in out['model_year_cycle']

    def test_plant_serial_and_sections_extracted(self):
        out = vs._vin_math('1HGCM82633A004352')
        assert out['vds'] == 'CM826'      # positions 4-8
        assert out['vis'] == '33A004352'  # positions 9-17
        assert out['plant_code'] == 'A'   # position 11
        assert out['serial_number'] == '004352'  # positions 12-17

    def test_position_map_present_and_complete(self):
        out = vs._vin_math('1HGCM82633A004352')
        position_map = out['position_map']
        assert set(position_map) == {'1-3', '4-8', '9', '10', '11', '12-17'}
        assert 'WMI' in position_map['1-3']
        assert 'Check digit' in position_map['9']
        assert 'serial' in position_map['12-17'].lower()

    def test_vin_math_empty_for_garbage_input(self):
        assert vs._vin_math('nope') == {}
        assert vs._vin_math('') == {}


# --------------------------------------------------------------------------- #
# NHTSA vPIC reader (mocked through fake_http)
# --------------------------------------------------------------------------- #

class TestVINOnline:

    def test_nhtsa_vpic_parses_record(self, vpic_http):
        out = vs._nhtsa_vpic('1HGCM82633A004352')
        assert out['vpic_make'] == 'HONDA'
        assert out['vpic_model'] == 'Accord'
        assert out['vpic_body_class'] == 'Sedan'
        assert out['vpic_plant_city'] == 'Marysville'
        assert out['vpic_plant_state'] == 'Ohio'
        # Numeric API fields are converted to ints.
        assert out['vpic_model_year'] == 2003
        assert out['vpic_engine_cylinders'] == 6
        assert out['vpic_engine_hp'] == 240
        assert out['vpic_displacement_l'] == 3.0
        # The queried VIN rides in the URL.
        assert any('DecodeVinValues/1HGCM82633A004352' in url
                   for _mode, url in vpic_http.calls)

    def test_nhtsa_vpic_truncates_long_values(self, fake_http):
        fake_http.json = lambda url, **kwargs: (
            True, {'Results': [{'Make': 'A' * 200, 'Model': 'B' * 90}]}, '')
        out = vs._nhtsa_vpic('1HGCM82633A004352')
        assert len(out['vpic_make']) == 80
        assert len(out['vpic_model']) == 80

    def test_nhtsa_vpic_malformed_payloads_return_empty(self, fake_http):
        payloads = (
            {'Results': []},                # empty Results list
            {'Results': 'nope'},            # Results not a list
            {'Results': ['nope']},          # record not a dict
            {'unexpected': 'shape'},        # no Results key at all
        )
        for payload in payloads:
            fake_http.json = lambda url, data=payload, **kw: (True, data, '')
            assert vs._nhtsa_vpic('1HGCM82633A004352') == {}
        # A transport failure degrades the same way.
        fake_http.json = lambda url, **kwargs: (False, None, 'connection reset')
        assert vs._nhtsa_vpic('1HGCM82633A004352') == {}

    def test_nhtsa_vpic_invalid_vin_makes_no_request(self, fake_http):
        assert vs._nhtsa_vpic('not-a-vin') == {}
        assert fake_http.calls == []


# --------------------------------------------------------------------------- #
# gather_all merge semantics
# --------------------------------------------------------------------------- #

class TestVINGather:

    def test_gather_all_offline_math_wins_conflicts(self, vpic_http):
        vpic_http.json = lambda url, **kwargs: (
            True, {'Results': [{'Make': 'MISMATCH'}]}, '')
        out = vs.gather_all('1HGCM82633A004352')
        # Source order sets priority: vin_math runs first in FREE_SOURCES,
        # so the standards-derived manufacturer beats the online mirror.
        assert out['fields']['manufacturer'] == 'Honda'
        assert out['provenance']['manufacturer'] == ['vin_math']
        assert out['fields']['vin'] == '1HGCM82633A004352'
        assert 'vin' not in out['provenance']  # the identifier is not sourced
        assert out['sources']['vin_math']['ok'] is True
        assert out['sources']['nhtsa_vpic']['ok'] is True

    def test_gather_all_all_sources_failing(self, monkeypatch):
        def boom(vin):
            raise ValueError('source exploded')

        monkeypatch.setattr(vs, 'FREE_SOURCES',
                            {'vin_math': boom, 'nhtsa_vpic': boom})
        out = vs.gather_all('1HGCM82633A004352')
        assert out['fields'] == {'vin': '1HGCM82633A004352'}
        assert out['provenance'] == {}
        for status in out['sources'].values():
            assert status['ok'] is False
            assert status['error'] == 'ValueError'

    def test_gather_all_unparseable_raises_valueerror(self):
        with pytest.raises(ValueError):
            vs.gather_all('garbage')
        with pytest.raises(ValueError):
            vs.gather_all('')

    def test_gather_all_respects_disabled_sources(self, vpic_http, monkeypatch):
        monkeypatch.setattr(config.app_config, 'disabled_sources',
                            ['nhtsa_vpic'])
        out = vs.gather_all('1HGCM82633A004352')
        assert 'nhtsa_vpic' not in out['sources']
        assert 'vpic_make' not in out['fields']
        assert out['sources']['vin_math']['ok'] is True


# --------------------------------------------------------------------------- #
# VINTracker envelope
# --------------------------------------------------------------------------- #

class TestVINTracker:

    def test_track_envelope_and_merged_fields(self, vpic_http):
        # Separator forms and lower case normalise before the fan-out.
        result = VINTracker().track('1hgcm82633a004352')
        assert set(result) == {'vin', 'info', 'field_sources', 'sources_ok',
                               'sources_failed', 'field_count', 'success',
                               'errors'}
        assert result['vin'] == '1HGCM82633A004352'
        assert result['success'] is True
        assert result['sources_ok'] == ['nhtsa_vpic', 'vin_math']
        assert result['sources_failed'] == {}
        assert result['errors'] == []
        assert result['field_count'] >= 15
        assert result['info']['vin'] == '1HGCM82633A004352'
        assert result['info']['manufacturer'] == 'Honda'
        assert result['info']['vpic_make'] == 'HONDA'
        assert result['field_sources']['manufacturer'] == ['vin_math']
        assert result['field_sources']['vpic_make'] == ['nhtsa_vpic']

    def test_track_invalid_short_circuits_without_network(self, fake_http):
        for bad in ('not-a-vin', BAD_CHECK_DIGIT_VIN, ''):
            result = VINTracker().track(bad)
            assert result['success'] is False
            assert result['sources_ok'] == []
            assert result['field_count'] == 0
            assert result['errors']
        assert fake_http.calls == []  # an invalid VIN never leaves the machine

    def test_track_normalises_separator_forms(self, fake_http):
        result = VINTracker().track('1m8-gdm9-axkp042788')
        assert result['vin'] == '1M8GDM9AXKP042788'
        assert result['info']['vin'] == '1M8GDM9AXKP042788'
        assert result['info']['wmi'] == '1M8'
        assert result['success'] is True  # offline math carries the report

    def test_track_writes_query_history(self, vpic_http, tmp_env):
        VINTracker().track('1M8GDM9AXKP042788')
        from obscuralens.database import db
        record = db.get_query_by_id(
            db.search_history('1M8GDM9AXKP042788')[0].id)
        assert record.query_type == 'vin'
        assert record.query_value == '1M8GDM9AXKP042788'
        assert record.success is True

    def test_batch_track_preserves_order_and_isolates_failures(self, vpic_http):
        results = VINTracker().batch_track(
            ['1HGCM82633A004352', 'garbage', '1M8GDM9AXKP042788'])
        assert len(results) == 3
        assert [r['success'] for r in results] == [True, False, True]
        assert results[1]['field_count'] == 0
        assert results[2]['vin'] == '1M8GDM9AXKP042788'

    def test_source_names_and_source_catalog(self):
        tracker = VINTracker()
        assert tracker.source_names() == ['nhtsa_vpic', 'vin_math']
        catalog = tracker.source_catalog()
        assert set(catalog) == {'vin_math', 'nhtsa_vpic'}
        assert all(catalog.values())  # every source has a description


# --------------------------------------------------------------------------- #
# rule pack
# --------------------------------------------------------------------------- #

class TestVINRules:

    def test_vin_pack_loads_with_rules(self):
        from obscuralens.rules import load_pack
        pack = load_pack('vin')
        assert pack is not None
        assert pack.kind == 'vin'
        assert pack.rule_count >= 8
        assert {rule.id for rule in pack.rules} >= {'VIN-001', 'VIN-002',
                                                    'VIN-009'}

    def test_clean_vin_scores_clean_with_positive_hit(self, vpic_http):
        from obscuralens.rules import evaluate_rules
        fields = vs.gather_all('1HGCM82633A004352')['fields']
        evaluation = evaluate_rules('vin', fields)
        assert 'VIN-009' in evaluation.matched_ids  # valid + registered
        assert 'VIN-001' not in evaluation.matched_ids
        assert evaluation.band == 'clean'

    def test_failed_check_digit_hits_vin_001(self):
        from obscuralens.rules import evaluate_rules
        fields = vs._vin_math(BAD_CHECK_DIGIT_VIN)
        evaluation = evaluate_rules('vin', fields)
        assert 'VIN-001' in evaluation.matched_ids
        assert evaluation.score >= 25
        assert evaluation.band != 'clean'
        # An unknown WMI on an otherwise sound VIN hits VIN-002 instead.
        unknown = evaluate_rules('vin', vs._vin_math(UNKNOWN_WMI_VIN))
        assert 'VIN-002' in unknown.matched_ids
        assert 'VIN-001' not in unknown.matched_ids


# --------------------------------------------------------------------------- #
# platform registration (CLI / web / MCP / entity extraction)
# --------------------------------------------------------------------------- #

class TestVINRegistration:

    def test_cli_kinds_and_vin_subcommand_parse(self, capsys):
        assert 'vin' in commands.KINDS
        assert 'vin' in commands._VALIDATORS
        assert commands._HANDLERS['vin'] is commands._cmd_vin
        parser = commands.build_parser()
        args = parser.parse_args(['vin', '1M8GDM9AXKP042788'])
        assert args.command == 'vin'
        assert args.target == '1M8GDM9AXKP042788'
        # An invalid target is rejected before any tracker runs.
        assert commands.run(['vin', 'not-a-vin']) == 2
        assert 'Error' in capsys.readouterr().err

    def test_cli_vin_json_output(self, monkeypatch, capsys):
        result = {
            'vin': '1M8GDM9AXKP042788', 'info': {'manufacturer': 'Kenworth'},
            'field_sources': {'manufacturer': ['vin_math']},
            'sources_ok': ['vin_math'], 'sources_failed': {},
            'field_count': 1, 'success': True, 'errors': [],
        }

        class FakeTracker:
            def track(self, target, **kwargs):
                return dict(result)

        monkeypatch.setattr(commands, '_tracker', lambda kind: FakeTracker())
        assert commands.run(['vin', '1M8GDM9AXKP042788', '-f', 'json']) == 0
        import json
        payload = json.loads(capsys.readouterr().out)
        assert payload['vin'] == '1M8GDM9AXKP042788'
        assert payload['info']['manufacturer'] == 'Kenworth'

    def test_cli_vin_table_output(self, monkeypatch, capsys):
        result = {
            'vin': '1HGCM82633A004352',
            'info': {'manufacturer': 'Honda', 'country': 'United States',
                     'wmi': '1HG'},
            'field_sources': {}, 'sources_ok': ['vin_math'],
            'sources_failed': {}, 'field_count': 3, 'success': True,
            'errors': [],
        }

        class FakeTracker:
            def track(self, target, **kwargs):
                return dict(result)

        monkeypatch.setattr(commands, '_tracker', lambda kind: FakeTracker())
        assert commands.run(['vin', '1HGCM82633A004352']) == 0
        out = capsys.readouterr().out
        assert 'Honda' in out
        assert 'IDENTITY' in out.upper()

    def test_web_app_kinds_include_vin(self):
        web_app = pytest.importorskip('obscuralens.web.app')
        assert 'vin' in web_app.KINDS
        assert 'vin' in web_app._VALIDATORS
        assert 'vin' in web_app._TRACKERS

    def test_mcp_vin_lookup_tool_compacts_result(self, monkeypatch):
        from obscuralens import mcp_server
        from obscuralens.trackers import VINTracker as tracker_class

        result = {
            'vin': '1M8GDM9AXKP042788', 'info': {'manufacturer': 'Kenworth'},
            'field_sources': {'manufacturer': ['vin_math'],
                              'wmi': ['vin_math']},
            'sources_ok': ['vin_math'], 'sources_failed': {},
            'field_count': 2, 'success': True, 'errors': [],
        }
        monkeypatch.setattr(tracker_class, 'track',
                            lambda self, target: dict(result))
        payload = mcp_server.call_tool(
            'vin_lookup', {'vin': '1M8GDM9AXKP042788'})
        assert payload['vin'] == '1M8GDM9AXKP042788'
        assert payload['success'] is True
        assert payload['provenance_counts'] == {'manufacturer': 1, 'wmi': 1}

        tools = mcp_server.handle_request(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
        )['result']['tools']
        assert 'vin_lookup' in {tool['name'] for tool in tools}

    def test_entity_extract_finds_vin_in_text(self):
        from obscuralens.experimental.entity_extract import extract_entities
        text = ('Vehicle with VIN 1HGCM82633A004352 was seized; the clone '
                'carried 1HGCM82634A004352.')
        found = extract_entities(text)
        # Only the check-digit-valid VIN survives (the clone fails ISO 3779).
        assert found['vins'] == ['1HGCM82633A004352']
        # Lower-case VINs are deliberately not extracted (regex is
        # uppercase-only), so the extractor never re-reads prose.
        assert extract_entities('vin 1hgcm82633a004352 lowercase')['vins'] == []


# --------------------------------------------------------------------------- #
# WMI data pack loader
# --------------------------------------------------------------------------- #

class TestVINPack:

    def test_pack_loads_curated_entries(self):
        pack = vs._load_wmi_pack()
        assert len(pack) >= 160
        assert pack['1FA'] == ('Ford', 'United States')
        assert pack['WBA'] == ('BMW', 'Germany')
        # Registry casing survives the parse.
        assert vs._load_wmi_pack()['WDB'] == ('Mercedes-Benz', 'Germany')

    def test_pack_uppercases_wmi_keys(self, tmp_path, monkeypatch):
        (tmp_path / 'vin_wmi.txt').write_text(
            '# comment line\n'
            '\n'
            '1fa|Ford|United States\n'
            'wba|BMW|Germany\n',
            encoding='utf-8')
        monkeypatch.setattr(vs, 'DATA_DIR', tmp_path)
        monkeypatch.setattr(vs, '_WMI_CACHE', None)
        pack = vs._load_wmi_pack()
        assert pack['1FA'] == ('Ford', 'United States')
        assert pack['WBA'] == ('BMW', 'Germany')

    def test_pack_skips_comments_blank_and_malformed_lines(self, tmp_path,
                                                           monkeypatch):
        (tmp_path / 'vin_wmi.txt').write_text(
            '# header comment\n'
            '\n'
            '1FA|Ford|United States\n'
            'ZZ|too-short|Nowhere\n'          # WMI not 3 characters
            'ABCD|too-long|Nowhere\n'         # WMI not 3 characters
            '1HG|Honda\n'                     # only two fields
            '|NoWMI|Nowhere\n'                # empty WMI
            '1C4|Chrysler|United States\n',
            encoding='utf-8')
        monkeypatch.setattr(vs, 'DATA_DIR', tmp_path)
        monkeypatch.setattr(vs, '_WMI_CACHE', None)
        pack = vs._load_wmi_pack()
        assert set(pack) == {'1FA', '1C4'}
        assert pack['1C4'] == ('Chrysler', 'United States')

    def test_pack_missing_file_is_empty_and_not_cached(self, tmp_path,
                                                       monkeypatch):
        monkeypatch.setattr(vs, 'DATA_DIR', tmp_path)  # no vin_wmi.txt here
        monkeypatch.setattr(vs, '_WMI_CACHE', None)
        assert vs._load_wmi_pack() == {}
        # A missing pack is not cached, so a later call can retry.
        assert vs._WMI_CACHE is None

    def test_data_catalog_wmi_mirror(self):
        from obscuralens.utils import data_catalog
        entry = data_catalog.wmi('1FA')
        assert entry is not None
        assert entry.manufacturer == 'Ford'
        assert data_catalog.wmis_count() >= 160
        assert data_catalog.wmi('ZZZ') is None
