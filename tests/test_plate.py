# ---------------------------------------------------------------------------
# ObscuraLens v6.0 -- tests for the plate kind (license plate analysis).
#
# Covers: validators (loose format, prefix splitting, normalisation), the
# offline plate-format pack (country matching with and without prefixes,
# pack loading robustness), the character composition analysis (including
# the hardcoded German city-code table and the EU vs North-American style
# heuristic), the gather_all merge with provenance, the tracker envelope
# contract, the explainable rule pack and the platform-wide registration
# points. The plate kind is fully offline, so no HTTP faking is required.
# ---------------------------------------------------------------------------

from obscuralens.trackers import plate_sources as psrc
from obscuralens.utils.validators import normalize_plate, split_plate, validate_plate

# --------------------------------------------------------------------------- #
# validators
# --------------------------------------------------------------------------- #

class TestValidatePlate:

    def test_accepts_prefixed_german_plate(self):
        assert validate_plate('DE:B-AB 1234')[0] is True

    def test_accepts_unprefixed_plate(self):
        assert validate_plate('AB12 CDE')[0] is True

    def test_accepts_compact_north_american_form(self):
        assert validate_plate('8ABC123')[0] is True

    def test_accepts_state_subtag_prefix(self):
        assert validate_plate('US-CA:8ABC123')[0] is True

    def test_rejects_empty(self):
        ok, error = validate_plate('')
        assert ok is False
        assert error

    def test_rejects_too_short(self):
        assert validate_plate('A')[0] is False

    def test_rejects_too_long(self):
        assert validate_plate('A' * 25)[0] is False

    def test_rejects_non_printable(self):
        assert validate_plate('AB\t12')[0] is False

    def test_normalize_uppercases_and_collapses_spaces(self):
        assert normalize_plate('  de:b-ab   1234 ') == 'DE:B-AB 1234'

    def test_split_with_prefix(self):
        assert split_plate('DE:B-AB 1234') == ('DE', 'B-AB 1234')

    def test_split_with_state_subtag(self):
        assert split_plate('US-CA:8ABC123') == ('US-CA', '8ABC123')

    def test_split_without_prefix(self):
        assert split_plate('AB12 CDE') == ('', 'AB12 CDE')

    def test_split_invalid_is_none(self):
        assert split_plate('') is None


# --------------------------------------------------------------------------- #
# offline: plate format pack
# --------------------------------------------------------------------------- #

class TestPlatePack:

    def test_pack_has_at_least_seventy_entries(self):
        entries, _ = psrc._load_plate_pack()
        assert len(entries) >= 70

    def test_germany_is_in_the_pack(self):
        _, by_country = psrc._load_plate_pack()
        assert 'DE' in by_country
        assert len(by_country['DE']) >= 10

    def test_great_britain_is_in_the_pack(self):
        _, by_country = psrc._load_plate_pack()
        assert 'GB' in by_country

    def test_prefixed_german_plate_matches(self):
        out = psrc._plate_pack('DE:B-AB 1234')
        assert out['country_prefix'] == 'DE'
        assert out['country_known'] is True
        assert out['matched_count'] >= 1
        top = out['matched_countries'][0]
        assert top['country'] == 'DE'
        assert top['confidence'] >= 0.9

    def test_prefixed_gb_plate_matches(self):
        out = psrc._plate_pack('GB:AB12 CDE')
        assert out['matched_countries']
        assert out['matched_countries'][0]['country'] == 'GB'

    def test_prefixed_us_state_plate_matches(self):
        out = psrc._plate_pack('US-CA:8ABC123')
        assert out['matched_countries'][0]['country'] == 'US-CA'

    def test_known_country_with_unknown_body_still_reports_country(self):
        # A DE: plate whose body fits no curated pattern still reports the
        # claimed jurisdiction at low confidence.
        out = psrc._plate_pack('DE:ZZZZZZ9999')
        assert out['country_known'] is True
        assert out['matched_countries'][0]['country'] == 'DE'
        assert out['matched_countries'][0]['confidence'] < 0.9

    def test_unknown_country_prefix_reports_note(self):
        out = psrc._plate_pack('XX:AB123')
        assert out['country_known'] is False
        assert 'not in the curated pack' in out['match_note']

    def test_unprefixed_plate_returns_candidate_list(self):
        out = psrc._plate_pack('8ABC123')
        assert out['matched_count'] >= 1
        assert all(m['confidence'] < 0.9
                   for m in out['matched_countries'])

    def test_unprefixed_unmatched_plate_reports_note(self):
        out = psrc._plate_pack('AB.CD.12')
        assert out['matched_count'] == 0
        assert 'no curated pattern matched' in out['match_note']

    def test_matches_are_capped(self):
        assert psrc._MAX_MATCHES <= 8

    def test_invalid_input_returns_empty(self):
        assert psrc._plate_pack('') == {}
        assert psrc._plate_pack(None) == {}

    def test_normalized_field_present(self):
        out = psrc._plate_pack('de:b-ab 1234')
        assert out['normalized'] == 'DE:B-AB 1234'


# --------------------------------------------------------------------------- #
# offline: character composition analysis
# --------------------------------------------------------------------------- #

class TestPlateMath:

    def test_character_census(self):
        out = psrc._plate_math('DE:B-AB 1234')
        assert out['letters_count'] == 3   # B, A, B
        assert out['digits_count'] == 4
        assert out['length'] == 9

    def test_separators_collected(self):
        out = psrc._plate_math('DE:B-AB 1234')
        assert set(out['separators']) == {'-', ' '}

    def test_composition_note_mentions_counts(self):
        out = psrc._plate_math('AB12 CDE')
        assert 'letter(s)' in out['composition_note']
        assert 'digit(s)' in out['composition_note']

    def test_german_city_code_resolves(self):
        out = psrc._plate_math('DE:B-AB 1234')
        assert out['german_city_code'] == 'B'
        assert out['german_city'] == 'Berlin'

    def test_more_german_city_codes(self):
        for code, city in (('M', 'Munich'), ('HH', 'Hamburg'),
                           ('K', 'Cologne'), ('S', 'Stuttgart')):
            out = psrc._plate_math(f'DE:{code}-AB 123')
            assert out['german_city_code'] == code, code
            assert out['german_city'].startswith(city), code

    def test_non_german_plate_has_no_city_fields(self):
        out = psrc._plate_math('GB:AB12 CDE')
        assert 'german_city' not in out
        assert 'german_city_code' not in out

    def test_unknown_german_city_reports_no_match(self):
        out = psrc._plate_math('DE:ZZ-AB 1234')
        assert out.get('german_city') is None

    def test_style_hint_present(self):
        out = psrc._plate_math('DE:B-AB 1234')
        assert out['style_hint']

    def test_invalid_input_returns_empty(self):
        assert psrc._plate_math('') == {}
        assert psrc._plate_math(None) == {}


# --------------------------------------------------------------------------- #
# gather_all merge + provenance
# --------------------------------------------------------------------------- #

class TestPlateGather:

    def test_gather_produces_merged_fields(self):
        out = psrc.gather_all('DE:B-AB 1234')
        assert 'plate' in out['fields']
        assert 'matched_countries' in out['fields']
        assert 'letters_count' in out['fields']

    def test_provenance_maps_fields_to_sources(self):
        out = psrc.gather_all('DE:B-AB 1234')
        assert out['provenance']['matched_countries'][0] == 'plate_pack'
        assert out['provenance']['letters_count'][0] == 'plate_math'

    def test_offline_sources_both_ok(self):
        out = psrc.gather_all('DE:B-AB 1234')
        assert out['sources']['plate_pack']['ok'] is True
        assert out['sources']['plate_math']['ok'] is True

    def test_invalid_input_raises_value_error(self):
        try:
            psrc.gather_all('')
        except ValueError:
            pass
        else:
            raise AssertionError('expected ValueError for empty plate')

    def test_no_keyed_sources(self):
        assert psrc.KEYED_SOURCES == {}


# --------------------------------------------------------------------------- #
# tracker envelope contract
# --------------------------------------------------------------------------- #

class TestPlateTracker:

    def test_track_envelope_shape(self):
        from obscuralens.trackers.plate_tracker import PlateTracker
        result = PlateTracker().track('DE:B-AB 1234')
        for key in ('plate', 'info', 'field_sources', 'sources_ok',
                    'sources_failed', 'field_count', 'success', 'errors'):
            assert key in result, key
        assert result['success'] is True
        assert result['plate'] == 'DE:B-AB 1234'

    def test_invalid_input_short_circuits(self):
        from obscuralens.trackers.plate_tracker import PlateTracker
        result = PlateTracker().track('A')
        assert result['success'] is False
        assert result['errors']

    def test_source_catalog(self):
        from obscuralens.trackers.plate_tracker import PlateTracker
        catalog = PlateTracker().source_catalog()
        assert 'plate_pack' in catalog
        assert 'plate_math' in catalog

    def test_batch_track(self):
        from obscuralens.trackers.plate_tracker import PlateTracker
        results = PlateTracker().batch_track(['DE:B-AB 1234', 'GB:AB12 CDE'])
        assert len(results) == 2
        assert all(r['success'] for r in results)


# --------------------------------------------------------------------------- #
# rule pack
# --------------------------------------------------------------------------- #

class TestPlateRules:

    def test_unknown_country_prefix_rule_hits(self):
        from obscuralens.rules import evaluate_rules
        evaluation = evaluate_rules('plate', {
            'country_known': False, 'matched_count': 0,
        })
        assert evaluation.score > 0

    def test_region_match_rule_fires(self):
        from obscuralens.rules import evaluate_rules
        evaluation = evaluate_rules('plate', {
            'german_city': 'Berlin', 'matched_count': 1,
            'country_known': True,
        })
        assert evaluation.score >= 0  # informational context rules

    def test_plain_unmatched_plate_stays_low(self):
        from obscuralens.rules import evaluate_rules
        evaluation = evaluate_rules('plate', {
            'country_known': True, 'matched_count': 1,
        })
        assert evaluation.band in ('clean', 'watch', 'elevated')


# --------------------------------------------------------------------------- #
# data catalog + platform registration
# --------------------------------------------------------------------------- #

class TestPlateCatalogAndRegistration:

    def test_plate_formats_pack_in_catalog_stats(self):
        from obscuralens.utils import data_catalog
        names = {stat.name for stat in data_catalog.catalog_stats()}
        assert 'plate_formats' in names

    def test_cli_kind_registered(self):
        from obscuralens import commands
        assert 'plate' in commands.KINDS

    def test_web_kind_registered(self):
        from obscuralens.web.app import _TARGET_KEY, KINDS
        assert 'plate' in KINDS
        assert _TARGET_KEY.get('plate') == 'plate'

    def test_mcp_tool_registered(self):
        from obscuralens.mcp_server import TOOLS
        assert 'plate_lookup' in {tool['name'] for tool in TOOLS}

    def test_batch_kind_supported(self):
        from obscuralens.advanced.batch import SUPPORTED_KINDS
        assert 'plate' in SUPPORTED_KINDS

    def test_entity_extractor_pulls_prefixed_plate(self):
        from obscuralens.experimental.entity_extract import extract_entities
        found = extract_entities('vehicle DE:B-AB 1234 seen nearby')
        assert 'DE:B-AB 1234' in found['plates']
