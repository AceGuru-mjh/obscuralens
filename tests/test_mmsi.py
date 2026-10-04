"""MMSI source and tracker tests (v6.0 kind; fully offline).

Covers the ITU-R M.1085 validator (nine-digit shapes, integer input,
``MMSI:`` prefix and separator tolerance, wrong digit counts), the offline
``mmsi_math`` station-class decode (ship / coast / group / handheld / AtoN /
reserved / unassigned series, MID extraction, trailing-zero note) and the
``mid_pack`` flag-state lookup, ``gather_all`` provenance/priority
semantics, the tracker envelope and its failure short-circuits (an invalid
MMSI never touches the sources), the shipped rule pack through
``evaluate_rules``, full-platform registration (CLI parser, web kinds, MCP
tool, entity extraction) and the MID data pack loader (comments, malformed
lines, missing file). The whole kind is offline, so ``fake_http`` is only
used to prove no request is ever made.
"""

import pytest

from obscuralens import commands
from obscuralens.config import config
from obscuralens.trackers import mmsi_sources as ms
from obscuralens.trackers.mmsi_tracker import MMSITracker
from obscuralens.utils.validators import normalize_mmsi, validate_mmsi

#: Well-formed nine-digit identities across the ITU series: US ship,
#: Albania-flag ship, US handheld, US coast station, zero-ending US ship.
VALID_MMSIS = ('366123456', '201123456', '836612345', '003661234',
               '366910000')

#: A ship MMSI whose MID (202) sits inside the 201-775 series but is not
#: in the curated flag-state pack.
UNKNOWN_MID_MMSI = '202123456'


@pytest.fixture(autouse=True)
def _reset_source_health():
    """Keep persisted source-health streaks from leaking between tests."""
    from obscuralens.health import health
    health.reset()
    yield
    health.reset()


# --------------------------------------------------------------------------- #
# validate_mmsi / normalize_mmsi
# --------------------------------------------------------------------------- #

class TestValidateMMSI:

    @pytest.mark.parametrize('mmsi', VALID_MMSIS)
    def test_valid_nine_digit_identities(self, mmsi):
        ok, error = validate_mmsi(mmsi)
        assert ok is True
        assert error == ''

    def test_integer_input_accepted(self):
        assert validate_mmsi(366910000)[0] is True
        assert normalize_mmsi(366910000) == '366910000'
        # A wrong-length integer still fails cleanly.
        assert validate_mmsi(12345)[0] is False

    def test_prefix_and_separator_forms_normalise(self):
        assert normalize_mmsi('MMSI:366910000') == '366910000'
        assert normalize_mmsi('mmsi: 366-910-000') == '366910000'
        assert validate_mmsi('MMSI:366910000')[0] is True
        assert normalize_mmsi('366 910 000') == '366910000'

    def test_wrong_digit_count_rejected(self):
        for bad in ('36691000',      # eight digits
                    '3669100000',    # ten digits
                    '3669100'):      # seven digits
            ok, error = validate_mmsi(bad)
            assert ok is False, bad
            assert 'expected 9 digits' in error

    def test_non_digit_and_empty_input_rejected(self):
        for bad in ('36691ABCD', 'abcdefghi', '', '   ', None):
            ok, error = validate_mmsi(bad)
            assert ok is False, bad
            assert 'MMSI' in error
        # Booleans are explicitly not treated as integers.
        assert normalize_mmsi(True) == ''
        assert normalize_mmsi([366910000]) == ''


# --------------------------------------------------------------------------- #
# offline mmsi_math + mid_pack
# --------------------------------------------------------------------------- #

class TestMMSIMath:

    def test_mid_resolves_flag_country(self):
        expected = {'366123456': 'United States',
                    '232123456': 'United Kingdom',
                    '431123456': 'Japan'}
        for mmsi, country in expected.items():
            assert ms._mid_pack(mmsi)['country'] == country

    def test_unknown_mid_in_range_has_no_country(self):
        # MID 202 sits inside the 201-775 ship series but is absent from the
        # curated pack: an explicit miss, never a fabricated country.
        assert ms._mid_pack(UNKNOWN_MID_MMSI) == {'country': None}
        out = ms._mmsi_math(UNKNOWN_MID_MMSI)
        assert out['mid'] == '202'
        assert out['station_type_code'] == 'ship'

    def test_ship_station_class(self):
        out = ms._mmsi_math('366123456')
        assert out['station_type_code'] == 'ship'
        assert out['station_type'] == 'individual ship station (MID + 6-digit serial)'
        assert out['itu_series'] == 'MID 201-775 individual series'
        assert out['mid'] == '366'
        assert out['serial_digits'] == '123456'

    def test_handheld_class(self):
        out = ms._mmsi_math('836612345')
        assert out['station_type_code'] == 'handheld'
        assert out['mid'] == '366'        # MID sits after the leading 8
        assert out['serial_digits'] == '12345'
        assert 'handheld' in out['itu_series']

    def test_group_and_coast_classes(self):
        group = ms._mmsi_math('036612345')
        assert group['station_type_code'] == 'group'
        assert group['mid'] == '366'
        assert group['serial_digits'] == '12345'
        coast = ms._mmsi_math('003661234')
        assert coast['station_type_code'] == 'coast'
        assert coast['mid'] == '366'      # MID sits after the 00 prefix
        assert coast['serial_digits'] == '1234'

    def test_aton_reserved_and_unassigned_classes(self):
        aton = ms._mmsi_math('993661234')
        assert aton['station_type_code'] == 'aton'
        assert aton['mid'] == '366'
        reserved = ms._mmsi_math('936612345')
        assert reserved['station_type_code'] == 'reserved'
        assert 'mid' not in reserved       # no MID in the reserved series
        assert 'serial_digits' not in reserved
        for unassigned in ('111123456', '200123456', '776123456'):
            out = ms._mmsi_math(unassigned)
            assert out['station_type_code'] == 'unassigned', unassigned
            assert 'mid' not in out

    def test_serial_extraction_and_trailing_zero_note(self):
        zero_ending = ms._mmsi_math('366910000')
        assert zero_ending['serial_digits'] == '910000'
        assert 'trailing_zero_notes' in zero_ending
        assert 'unconfirmed convention' in zero_ending['trailing_zero_notes']
        clean = ms._mmsi_math('366123456')
        assert clean['serial_digits'] == '123456'
        assert 'trailing_zero_notes' not in clean

    def test_garbage_returns_empty(self):
        assert ms._mmsi_math('nope') == {}
        assert ms._mmsi_math('') == {}
        assert ms._mid_pack('nope') == {}


# --------------------------------------------------------------------------- #
# gather_all merge semantics
# --------------------------------------------------------------------------- #

class TestMMSIGather:

    def test_gather_all_math_wins_provenance(self):
        out = ms.gather_all('366910000')
        # mmsi_math runs first in FREE_SOURCES, so the standards-derived
        # station class wins over the pack on any conflict.
        assert out['fields']['station_type_code'] == 'ship'
        assert out['provenance']['station_type_code'] == ['mmsi_math']
        assert out['fields']['country'] == 'United States'
        assert out['provenance']['country'] == ['mid_pack']
        assert out['fields']['mmsi'] == '366910000'
        assert 'mmsi' not in out['provenance']  # the identifier is not sourced
        assert out['sources']['mmsi_math']['ok'] is True
        assert out['sources']['mid_pack']['ok'] is True

    def test_gather_all_all_sources_failing(self, monkeypatch):
        def boom(mmsi):
            raise KeyError('source exploded')

        monkeypatch.setattr(ms, 'FREE_SOURCES',
                            {'mmsi_math': boom, 'mid_pack': boom})
        out = ms.gather_all('366910000')
        assert out['fields'] == {'mmsi': '366910000'}
        assert out['provenance'] == {}
        for status in out['sources'].values():
            assert status['ok'] is False
            assert status['error'] == 'KeyError'

    def test_gather_all_unparseable_raises_valueerror(self):
        with pytest.raises(ValueError):
            ms.gather_all('12345')
        with pytest.raises(ValueError):
            ms.gather_all('garbage')

    def test_gather_all_respects_disabled_sources(self, monkeypatch):
        monkeypatch.setattr(config.app_config, 'disabled_sources',
                            ['mid_pack'])
        out = ms.gather_all('366910000')
        assert 'mid_pack' not in out['sources']
        assert 'country' not in out['fields']
        assert out['sources']['mmsi_math']['ok'] is True


# --------------------------------------------------------------------------- #
# MMSITracker envelope
# --------------------------------------------------------------------------- #

class TestMMSITracker:

    def test_track_envelope_and_merged_fields(self, fake_http):
        result = MMSITracker().track('366910000')
        assert set(result) == {'mmsi', 'info', 'field_sources', 'sources_ok',
                               'sources_failed', 'field_count', 'success',
                               'errors'}
        assert result['mmsi'] == '366910000'
        assert result['success'] is True
        assert result['sources_ok'] == ['mid_pack', 'mmsi_math']
        assert result['sources_failed'] == {}
        assert result['errors'] == []
        assert result['info']['mmsi'] == '366910000'
        assert result['info']['station_type_code'] == 'ship'
        assert result['info']['country'] == 'United States'
        assert result['field_sources']['country'] == ['mid_pack']
        assert result['field_sources']['station_type_code'] == ['mmsi_math']
        # The kind is fully offline: no HTTP client call ever happens.
        assert fake_http.calls == []

    def test_track_invalid_short_circuits_without_sources(self, fake_http):
        for bad in ('12345', '36691ABCD', '3669100000', ''):
            result = MMSITracker().track(bad)
            assert result['success'] is False
            assert result['sources_ok'] == []
            assert result['field_count'] == 0
            assert result['errors']
        assert fake_http.calls == []

    def test_track_normalises_int_and_prefixed_input(self, fake_http):
        assert MMSITracker().track(366910000)['mmsi'] == '366910000'
        result = MMSITracker().track('MMSI:366-910-000')
        assert result['mmsi'] == '366910000'
        assert result['info']['mmsi'] == '366910000'
        assert result['success'] is True

    def test_track_writes_query_history(self, fake_http, tmp_env):
        MMSITracker().track('366910000')
        from obscuralens.database import db
        record = db.get_query_by_id(db.search_history('366910000')[0].id)
        assert record.query_type == 'mmsi'
        assert record.query_value == '366910000'
        assert record.success is True

    def test_batch_track_preserves_order_and_isolates_failures(self, fake_http):
        results = MMSITracker().batch_track(
            ['366910000', '12345', '431123456'])
        assert len(results) == 3
        assert [r['success'] for r in results] == [True, False, True]
        assert results[1]['field_count'] == 0
        assert results[2]['mmsi'] == '431123456'

    def test_source_names_and_source_catalog(self):
        tracker = MMSITracker()
        assert tracker.source_names() == ['mid_pack', 'mmsi_math']
        catalog = tracker.source_catalog()
        assert set(catalog) == {'mmsi_math', 'mid_pack'}
        assert all(catalog.values())  # every source has a description


# --------------------------------------------------------------------------- #
# rule pack
# --------------------------------------------------------------------------- #

class TestMMSIRules:

    def test_mmsi_pack_loads_with_rules(self):
        from obscuralens.rules import load_pack
        pack = load_pack('mmsi')
        assert pack is not None
        assert pack.kind == 'mmsi'
        assert pack.rule_count >= 8
        assert {rule.id for rule in pack.rules} >= {'MMSI-001', 'MMSI-004',
                                                    'MMSI-005'}

    def test_clean_ship_identity_scores_low(self):
        from obscuralens.rules import evaluate_rules
        fields = ms.gather_all('366123456')['fields']
        evaluation = evaluate_rules('mmsi', fields)
        # Fully attributed ship identity: the positive rule (weight 0).
        assert 'MMSI-004' in evaluation.matched_ids
        assert 'MMSI-001' not in evaluation.matched_ids
        assert 'MMSI-006' not in evaluation.matched_ids  # serial not zero-ending
        assert evaluation.band == 'clean'

    def test_unassigned_and_reserved_hit_rules(self):
        from obscuralens.rules import evaluate_rules
        unassigned = ms.gather_all('111123456')['fields']
        evaluation = evaluate_rules('mmsi', unassigned)
        assert 'MMSI-001' in evaluation.matched_ids
        assert evaluation.score >= 15
        reserved = ms.gather_all('936612345')['fields']
        evaluation = evaluate_rules('mmsi', reserved)
        assert 'MMSI-002' in evaluation.matched_ids
        # A non-ship class (handheld) is context, not a risk hit.
        handheld = ms.gather_all('836612345')['fields']
        evaluation = evaluate_rules('mmsi', handheld)
        assert 'MMSI-005' in evaluation.matched_ids
        assert 'MMSI-001' not in evaluation.matched_ids


# --------------------------------------------------------------------------- #
# platform registration (CLI / web / MCP / entity extraction)
# --------------------------------------------------------------------------- #

class TestMMSIRegistration:

    def test_cli_kinds_and_mmsi_subcommand_parse(self, capsys):
        assert 'mmsi' in commands.KINDS
        assert 'mmsi' in commands._VALIDATORS
        assert commands._HANDLERS['mmsi'] is commands._cmd_mmsi
        parser = commands.build_parser()
        args = parser.parse_args(['mmsi', '366910000'])
        assert args.command == 'mmsi'
        assert args.target == '366910000'
        # An invalid identity is rejected before any tracker runs.
        assert commands.run(['mmsi', '12345']) == 2
        assert 'Error' in capsys.readouterr().err

    def test_cli_mmsi_json_and_table_output(self, monkeypatch, capsys):
        import json
        result = {
            'mmsi': '366910000',
            'info': {'station_type_code': 'ship',
                     'country': 'United States'},
            'field_sources': {'country': ['mid_pack']},
            'sources_ok': ['mid_pack', 'mmsi_math'],
            'sources_failed': {}, 'field_count': 2, 'success': True,
            'errors': [],
        }

        class FakeTracker:
            def track(self, target, **kwargs):
                return dict(result)

        monkeypatch.setattr(commands, '_tracker', lambda kind: FakeTracker())
        assert commands.run(['mmsi', '366910000', '-f', 'json']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['mmsi'] == '366910000'
        assert payload['info']['country'] == 'United States'
        assert commands.run(['mmsi', '366910000']) == 0
        out = capsys.readouterr().out
        assert 'United States' in out
        assert 'ITU-R M.1085' in out

    def test_web_app_kinds_include_mmsi(self):
        web_app = pytest.importorskip('obscuralens.web.app')
        assert 'mmsi' in web_app.KINDS
        assert 'mmsi' in web_app._VALIDATORS
        assert 'mmsi' in web_app._TRACKERS

    def test_mcp_mmsi_lookup_tool_compacts_result(self, monkeypatch):
        from obscuralens import mcp_server
        from obscuralens.trackers import MMSITracker as tracker_class

        result = {
            'mmsi': '366910000', 'info': {'country': 'United States'},
            'field_sources': {'country': ['mid_pack'],
                              'mid': ['mmsi_math']},
            'sources_ok': ['mid_pack', 'mmsi_math'], 'sources_failed': {},
            'field_count': 2, 'success': True, 'errors': [],
        }
        monkeypatch.setattr(tracker_class, 'track',
                            lambda self, target: dict(result))
        payload = mcp_server.call_tool('mmsi_lookup', {'mmsi': '366910000'})
        assert payload['mmsi'] == '366910000'
        assert payload['success'] is True
        assert payload['provenance_counts'] == {'country': 1, 'mid': 1}

        tools = mcp_server.handle_request(
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
        )['result']['tools']
        assert 'mmsi_lookup' in {tool['name'] for tool in tools}


# --------------------------------------------------------------------------- #
# MID data pack loader
# --------------------------------------------------------------------------- #

class TestMMSIPack:

    def test_pack_loads_curated_mids(self):
        pack = ms._load_mid_pack()
        assert len(pack) >= 60
        assert pack['366'] == 'United States'
        assert pack['232'] == 'United Kingdom'
        assert pack['431'] == 'Japan'

    def test_pack_tolerates_comments_and_bad_lines(self, tmp_path, monkeypatch):
        (tmp_path / 'mid_codes.txt').write_text(
            '# MID pack header\n'
            '\n'
            '366|United States\n'
            '2|Too Short\n'          # MID not three digits
            '1234|Too Long\n'        # MID not three digits
            'ABC|Not Digits\n'       # non-numeric MID
            '232|\n'                 # empty country
            '|No Country\n'          # empty MID
            '431|Japan\n',
            encoding='utf-8')
        monkeypatch.setattr(ms, 'DATA_DIR', tmp_path)
        monkeypatch.setattr(ms, '_MID_CACHE', None)
        pack = ms._load_mid_pack()
        assert pack == {'366': 'United States', '431': 'Japan'}

    def test_pack_missing_file_is_empty_and_not_cached(self, tmp_path,
                                                       monkeypatch):
        monkeypatch.setattr(ms, 'DATA_DIR', tmp_path)  # no file here
        monkeypatch.setattr(ms, '_MID_CACHE', None)
        assert ms._load_mid_pack() == {}
        # A missing pack is not cached, so a later call can retry.
        assert ms._MID_CACHE is None

    def test_data_catalog_mid_mirror(self):
        from obscuralens.utils import data_catalog
        entry = data_catalog.mid('366')
        assert entry is not None
        assert entry.country == 'United States'
        assert data_catalog.mids_count() >= 60
        assert data_catalog.mid('202') is None


# --------------------------------------------------------------------------- #
# entity extraction
# --------------------------------------------------------------------------- #

class TestMMSIEntity:

    def test_entity_extract_finds_mmsi_in_text(self):
        from obscuralens.experimental.entity_extract import extract_entities
        found = extract_entities(
            'AIS target 366910000 was photographed near Rotterdam.')
        assert found['mmsis'] == ['366910000']
        # Nine digits embedded in a longer number are never re-read.
        assert extract_entities('ref 13669100001 end')['mmsis'] == []

    def test_entity_extract_ignores_special_series_and_case(self):
        from obscuralens.experimental.entity_extract import extract_entities
        # Leading-0 coast/group forms are deliberately not extracted (they
        # collide with other digit runs in prose).
        assert extract_entities('station 003661234 called')['mmsis'] == []
        assert extract_entities('reserved 936612345 called')['mmsis'] == []
        # A mixed-prose sample still finds every ship/handheld identity.
        found = extract_entities(
            'vessels 366910000 and 836612345 plus 431123456 in the strait')
        assert found['mmsis'] == ['366910000', '836612345', '431123456']
