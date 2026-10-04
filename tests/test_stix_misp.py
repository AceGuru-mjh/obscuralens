"""STIX 2.1 and MISP export tests (v6.0 part 4): deterministic ids, the
full kind-to-pattern / kind-to-attribute maps, every SDO builder, bundle
and event assembly, file dumps, plus the CLI and web wiring. Fully
offline - the CLI/web cases store their tracker envelope through the
local SQLite history first (the exports describe stored lookups, they
never re-run a tracker)."""

import json
from datetime import datetime

import pytest

from obscuralens.export.misp import (
    MISP_ORG_NAME,
    MISP_ORG_UUID,
    build_event,
    build_misp_event,
    dump_event,
    kind_to_attribute,
    result_to_attributes,
    threat_level_for,
)
from obscuralens.export.stix import (
    STIX_VERSION,
    _stix_id,
    build_bundle,
    build_identity,
    build_indicator,
    build_note,
    build_observed_data,
    build_relationship,
    build_vulnerability,
    dump_bundle,
    kind_to_indicator_pattern,
)


def _envelope():
    """A representative tracker envelope for an IP lookup."""
    return {
        'ip': '8.8.8.8',
        'value': '8.8.8.8',
        'info': {'country': 'US', 'org': 'Google LLC', 'asn': 15169},
        'field_sources': {'country': ['ipapi'], 'org': ['ipapi']},
        'sources_ok': ['ipapi', 'rdap'],
        'sources_failed': {'shodan': 'timeout'},
        'field_count': 3,
        'success': True,
        'errors': [],
    }


def _parse_iso(stamp):
    """Version-proof ISO parse (``Z`` suffix only parses on 3.11+)."""
    return datetime.fromisoformat(str(stamp).replace('Z', '+00:00'))


# --------------------------------------------------------------------------- #
# deterministic ids
# --------------------------------------------------------------------------- #

class TestStixId:

    def test_same_seed_same_id(self):
        assert _stix_id('indicator', 'ip:8.8.8.8') \
            == _stix_id('indicator', 'ip:8.8.8.8')

    def test_different_type_different_id(self):
        assert _stix_id('indicator', 'ip:8.8.8.8') \
            != _stix_id('observed-data', 'ip:8.8.8.8')

    def test_id_format_is_type_double_dash_uuid(self):
        value = _stix_id('indicator', 'ip:8.8.8.8')
        type_, _, digest = value.partition('--')
        assert type_ == 'indicator'
        assert len(digest) == 36  # canonical uuid string
        int(digest.replace('-', ''), 16)  # hex payload


# --------------------------------------------------------------------------- #
# kind -> STIX indicator pattern
# --------------------------------------------------------------------------- #

class TestIndicatorPattern:

    @pytest.mark.parametrize('kind, value, pattern', [
        ('ip', '8.8.8.8', "[ipv4-addr:value = '8.8.8.8']"),
        ('domain', 'example.com', "[domain-name:value = 'example.com']"),
        ('url', 'https://a.example/x',
         "[url:value = 'https://a.example/x']"),
        ('email', 'a@b.example', "[email-addr:value = 'a@b.example']"),
        ('mac', '00:11:22:33:44:55',
         "[mac-addr:value = '00:11:22:33:44:55']"),
        ('bssid', 'AA:BB:CC:DD:EE:FF',
         "[mac-addr:value = 'AA:BB:CC:DD:EE:FF']"),
        ('username', 'neo', "[user-account:user_id = 'neo']"),
        ('phone', '+15551234567', "[x-obscuralens:phone = '+15551234567']"),
        ('crypto', 'bc1qxyz', "[x-obscuralens:crypto-address = 'bc1qxyz']"),
        ('vin', 'WVWZZZ1JZXW000001',
         "[x-obscuralens:vin = 'WVWZZZ1JZXW000001']"),
        ('', 'anything', "[x-obscuralens:value = 'anything']"),
    ])
    def test_kind_pattern_map(self, kind, value, pattern):
        assert kind_to_indicator_pattern(kind, value) == (pattern, 'stix')

    def test_ipv6_detected_by_colon_grammar(self):
        pattern, pattern_type = kind_to_indicator_pattern(
            'ip', '2001:db8::1')
        assert pattern == "[ipv6-addr:value = '2001:db8::1']"
        assert pattern_type == 'stix'

    @pytest.mark.parametrize('digest, algorithm', [
        ('a' * 64, 'SHA-256'),
        ('a' * 40, 'SHA-1'),
        ('a' * 32, 'MD5'),
        ('a' * 12, 'SHA-256'),  # unknown length falls back to SHA-256
    ])
    def test_hash_algorithm_by_length(self, digest, algorithm):
        pattern, _ = kind_to_indicator_pattern('hash', digest)
        assert pattern == f"[file:hashes.'{algorithm}' = '{digest}']"

    def test_cve_has_no_pattern(self):
        # A CVE is exported as a Vulnerability SDO, not an indicator.
        assert kind_to_indicator_pattern('cve', 'CVE-2021-44228') \
            == (None, '')

    def test_single_quotes_and_backslashes_escaped(self):
        pattern, _ = kind_to_indicator_pattern('username', "o'b\\rien")
        assert pattern == r"[user-account:user_id = 'o\'b\\rien']"


# --------------------------------------------------------------------------- #
# SDO builders
# --------------------------------------------------------------------------- #

class TestBuildIndicator:

    def test_core_fields(self):
        indicator = build_indicator('ip', '8.8.8.8')
        assert indicator['type'] == 'indicator'
        assert indicator['spec_version'] == STIX_VERSION == '2.1'
        assert indicator['pattern_type'] == 'stix'
        assert indicator['pattern'] == "[ipv4-addr:value = '8.8.8.8']"
        assert indicator['name'] == 'ip: 8.8.8.8'
        assert indicator['id'].startswith('indicator--')
        _parse_iso(indicator['valid_from'])
        _parse_iso(indicator['created'])
        _parse_iso(indicator['modified'])

    def test_default_and_custom_labels(self):
        assert build_indicator('ip', '8.8.8.8')['labels'] \
            == ['obscuralens', 'ip']
        assert build_indicator('ip', '8.8.8.8',
                               labels=['malicious'])['labels'] \
            == ['malicious']

    def test_confidence_clamped_and_omitted(self):
        assert build_indicator('ip', '8.8.8.8', confidence=150)['confidence'] \
            == 100
        assert build_indicator('ip', '8.8.8.8', confidence=-5)['confidence'] \
            == 0
        assert 'confidence' not in build_indicator('ip', '8.8.8.8',
                                                   confidence='high')
        assert build_indicator('ip', '8.8.8.8', confidence=42)['confidence'] \
            == 42

    def test_cve_degrades_to_custom_pattern(self):
        # Defensive fallback: a cve indicator still carries a pattern.
        indicator = build_indicator('cve', 'CVE-2021-44228')
        assert indicator['pattern'] == \
            "[x-obscuralens:cve = 'CVE-2021-44228']"
        assert indicator['pattern_type'] == 'stix'

    def test_id_is_deterministic(self):
        assert build_indicator('ip', '8.8.8.8')['id'] \
            == build_indicator('ip', '8.8.8.8')['id']
        assert build_indicator('ip', '8.8.8.8')['id'] \
            != build_indicator('ip', '9.9.9.9')['id']


class TestBuildObservedData:

    def test_standard_observable_and_custom_object(self):
        observed = build_observed_data('ip', _envelope())
        assert observed['type'] == 'observed-data'
        assert observed['id'].startswith('observed-data--')
        objects = observed['objects']
        assert objects['0'] == {'type': 'ipv4-addr', 'value': '8.8.8.8'}
        custom = objects['1']
        assert custom['type'] == 'x-obscuralens'
        assert custom['kind'] == 'ip'
        assert custom['value'] == '8.8.8.8'
        assert custom['country'] == 'US'
        assert custom['org'] == 'Google LLC'
        assert custom['asn'] == 15169

    def test_domain_standard_observable(self):
        observed = build_observed_data('domain', {
            'domain': 'example.com', 'info': {'registrar': 'acme'}})
        assert observed['objects']['0'] == {'type': 'domain-name',
                                            'value': 'example.com'}

    def test_phone_has_no_standard_observable(self):
        observed = build_observed_data('phone', {
            'phone': '+15551234567', 'info': {'country': 'US'}})
        # Only the custom object is present for kinds with no standard
        # STIX observable.
        assert list(observed['objects']) == ['0']
        assert observed['objects']['0']['type'] == 'x-obscuralens'

    def test_provenance_block(self):
        observed = build_observed_data('ip', _envelope())
        provenance = observed['objects']['1']['x_provenance']
        assert provenance['sources_ok'] == ['ipapi', 'rdap']
        assert provenance['sources_failed'] == {'shodan': 'timeout'}
        assert provenance['field_sources'] == {'country': ['ipapi'],
                                               'org': ['ipapi']}
        assert provenance['field_count'] == 3
        assert provenance['success'] is True
        assert provenance['errors'] == []

    def test_observation_metadata(self):
        observed = build_observed_data('ip', _envelope())
        assert observed['number_observed'] == 1
        _parse_iso(observed['first_observed'])
        _parse_iso(observed['last_observed'])
        assert observed['spec_version'] == '2.1'

    def test_hostile_keys_sanitised(self):
        observed = build_observed_data('ip', {
            'ip': '8.8.8.8',
            'info': {'AS Number': 'X', 'weird-key!': 1, '': 'empty'}})
        custom = observed['objects']['1']
        assert 'as_number' in custom
        assert 'weird_key_' in custom
        assert custom['field'] == 'empty'  # '' sanitises to a default

    def test_non_dict_envelope_degrades(self):
        observed = build_observed_data('ip', 'not-a-dict')
        assert observed['objects']['0']['type'] == 'x-obscuralens'
        assert 'x_provenance' not in observed['objects']['0']


class TestBuildVulnerability:

    def test_name_and_external_references(self):
        vulnerability = build_vulnerability({
            'cve': 'CVE-2021-44228',
            'info': {'description': 'Remote code execution in Log4j'}})
        assert vulnerability['type'] == 'vulnerability'
        assert vulnerability['name'] == 'CVE-2021-44228'
        assert vulnerability['id'].startswith('vulnerability--')
        assert vulnerability['description'] == \
            'Remote code execution in Log4j'
        references = vulnerability['external_references']
        assert len(references) == 1
        assert references[0]['source_name'] == 'cve.org'
        assert references[0]['external_id'] == 'CVE-2021-44228'
        assert references[0]['url'] == \
            'https://www.cve.org/CVERecord?id=CVE-2021-44228'

    def test_value_key_fallback(self):
        vulnerability = build_vulnerability({'value': 'CVE-2020-1234',
                                             'info': {}})
        assert vulnerability['name'] == 'CVE-2020-1234'

    def test_description_falls_back_to_first_long_string(self):
        vulnerability = build_vulnerability({
            'cve': 'CVE-2021-1', 'info': {'x': 'short', 'notes':
                                         'a reasonably long summary line'}})
        assert vulnerability['description'] == 'a reasonably long summary line'

    def test_empty_envelope_still_well_formed(self):
        vulnerability = build_vulnerability({})
        assert vulnerability['type'] == 'vulnerability'
        assert 'name' not in vulnerability
        assert 'external_references' not in vulnerability
        assert 'description' not in vulnerability
        _parse_iso(vulnerability['created'])


class TestBuildIdentity:

    def test_fixed_tool_identity(self):
        identity = build_identity()
        assert identity['type'] == 'identity'
        assert identity['name'] == 'ObscuraLens'
        assert identity['identity_class'] == 'organization'
        assert identity['created'] == '2024-01-01T00:00:00.000Z'
        assert 'export generator' in identity['description']

    def test_id_deterministic(self):
        first = build_identity()
        second = build_identity()
        assert first['id'] == second['id']
        assert first['id'].startswith('identity--')


class TestBuildNote:

    def test_content_carries_provenance(self):
        note = build_note('ip', '8.8.8.8', _envelope())
        assert note['type'] == 'note'
        assert note['abstract'] == 'ObscuraLens provenance'
        content = note['content']
        assert 'ObscuraLens provenance for ip 8.8.8.8' in content
        assert 'Result: success' in content
        assert 'Fields: 3 from 2 source(s)' in content
        assert 'Sources OK: ipapi, rdap' in content
        assert 'Sources failed: shodan (timeout)' in content

    def test_object_refs_point_at_indicator(self):
        note = build_note('ip', '8.8.8.8', _envelope())
        assert note['object_refs'] == \
            [build_indicator('ip', '8.8.8.8')['id']]

    def test_cve_subject_refs_vulnerability(self):
        note = build_note('cve', 'CVE-2021-44228',
                          {'cve': 'CVE-2021-44228', 'info': {}})
        assert note['object_refs'] == \
            [build_vulnerability({'cve': 'CVE-2021-44228'})['id']]


class TestBuildRelationship:

    def test_relationship_fields(self):
        source = build_indicator('ip', '8.8.8.8')['id']
        target = build_observed_data('ip', _envelope())['id']
        relationship = build_relationship(source, target, 'related-to')
        assert relationship['type'] == 'relationship'
        assert relationship['relationship_type'] == 'related-to'
        assert relationship['source_ref'] == source
        assert relationship['target_ref'] == target
        assert relationship['id'].startswith('relationship--')


# --------------------------------------------------------------------------- #
# bundle assembly
# --------------------------------------------------------------------------- #

class TestBuildBundle:

    def test_default_object_set(self):
        bundle = build_bundle('ip', '8.8.8.8', _envelope())
        assert bundle['type'] == 'bundle'
        assert bundle['id'].startswith('bundle--')
        types = [obj['type'] for obj in bundle['objects']]
        assert types == ['identity', 'indicator', 'observed-data',
                         'relationship', 'note']
        indicator = bundle['objects'][1]
        assert indicator['pattern'] == "[ipv4-addr:value = '8.8.8.8']"

    def test_include_observed_false_drops_two_objects(self):
        bundle = build_bundle('ip', '8.8.8.8', _envelope(),
                              include_observed=False)
        types = [obj['type'] for obj in bundle['objects']]
        assert types == ['identity', 'indicator', 'note']

    def test_include_notes_false_drops_note(self):
        bundle = build_bundle('ip', '8.8.8.8', _envelope(),
                              include_notes=False)
        types = [obj['type'] for obj in bundle['objects']]
        assert types == ['identity', 'indicator', 'observed-data',
                         'relationship']

    def test_both_false_leaves_identity_and_subject(self):
        bundle = build_bundle('ip', '8.8.8.8', _envelope(),
                              include_observed=False, include_notes=False)
        types = [obj['type'] for obj in bundle['objects']]
        assert types == ['identity', 'indicator']

    def test_cve_bundle_uses_vulnerability(self):
        bundle = build_bundle('cve', 'CVE-2021-44228', {
            'cve': 'CVE-2021-44228', 'info': {'description': 'Log4Shell'}})
        types = [obj['type'] for obj in bundle['objects']]
        assert 'vulnerability' in types
        assert 'indicator' not in types
        subject = bundle['objects'][1]
        assert subject['name'] == 'CVE-2021-44228'

    def test_bundle_id_deterministic(self):
        first = build_bundle('ip', '8.8.8.8', _envelope())
        second = build_bundle('ip', '8.8.8.8', _envelope())
        assert first['id'] == second['id']
        assert first['id'] != build_bundle('ip', '9.9.9.9', _envelope())['id']

    def test_value_falls_back_to_envelope(self):
        bundle = build_bundle('ip', '', {'ip': '9.9.9.9', 'info': {}})
        indicator = bundle['objects'][1]
        assert indicator['name'] == 'ip: 9.9.9.9'
        assert indicator['pattern'] == "[ipv4-addr:value = '9.9.9.9']"

    def test_info_keys_capped_at_200(self):
        info = {f'field{index}': index for index in range(250)}
        bundle = build_bundle('ip', '8.8.8.8', {'ip': '8.8.8.8',
                                                'info': info})
        observed = bundle['objects'][2]
        custom = next(obj for obj in observed['objects'].values()
                      if obj.get('type') == 'x-obscuralens')
        field_keys = [key for key in custom if key.startswith('field')]
        assert len(field_keys) == 200
        assert 'field199' in custom
        assert 'field200' not in custom


class TestDumpBundle:

    def test_writes_parseable_file(self, tmp_path):
        bundle = build_bundle('ip', '8.8.8.8', _envelope())
        target = tmp_path / 'nested' / 'bundle.json'
        result = dump_bundle(bundle, target)
        assert result['ok'] is True
        assert result['error'] == ''
        assert result['bytes'] > 0
        assert result['path'] == str(target)
        assert json.loads(target.read_text(encoding='utf-8')) == bundle

    def test_non_dict_bundle_degrades_to_empty_object(self, tmp_path):
        target = tmp_path / 'empty.json'
        result = dump_bundle(['not', 'a', 'dict'], target)
        assert result['ok'] is True
        assert json.loads(target.read_text(encoding='utf-8')) == {}

    def test_unwritable_path_reports_failure(self, tmp_path):
        blocker = tmp_path / 'blocker'
        blocker.write_text('i am a file', encoding='utf-8')
        result = dump_bundle(build_bundle('ip', '8.8.8.8', {}),
                             blocker / 'sub' / 'bundle.json')
        assert result['ok'] is False
        assert result['bytes'] == 0
        assert result['error']


# --------------------------------------------------------------------------- #
# MISP attribute mapping
# --------------------------------------------------------------------------- #

class TestMispAttribute:

    @pytest.mark.parametrize('kind, value, attr_type, category, comment', [
        ('ip', '8.8.8.8', 'ip-src', 'Network activity', ''),
        ('domain', 'example.com', 'domain', 'Network activity', ''),
        ('url', 'https://a.example/x', 'url', 'Network activity', ''),
        ('email', 'a@b.example', 'email-src', 'Payload delivery', ''),
        ('username', 'neo', 'text', 'Attribution', 'username'),
        ('phone', '+15551234567', 'text', 'Other', 'phone'),
        ('cve', 'CVE-2021-44228', 'text', 'Other', 'cve'),
        ('', 'x', 'text', 'Other', 'target'),
    ])
    def test_kind_attribute_map(self, kind, value, attr_type, category,
                                comment):
        attribute = kind_to_attribute(kind, value)
        assert attribute['type'] == attr_type
        assert attribute['category'] == category
        assert attribute['value'] == value
        assert attribute['comment'] == comment
        assert attribute['to_ids'] is False
        assert 'uuid' in attribute

    @pytest.mark.parametrize('digest, hash_type', [
        ('a' * 64, 'sha256'),
        ('a' * 40, 'sha1'),
        ('a' * 32, 'md5'),
    ])
    def test_hash_type_by_digest_length(self, digest, hash_type):
        attribute = kind_to_attribute('hash', digest)
        assert attribute['type'] == hash_type
        assert attribute['category'] == 'Payload delivery'

    def test_uuid_deterministic(self):
        first = kind_to_attribute('ip', '8.8.8.8')
        second = kind_to_attribute('ip', '8.8.8.8')
        other = kind_to_attribute('ip', '9.9.9.9')
        assert first['uuid'] == second['uuid']
        assert first['uuid'] != other['uuid']
        int(first['uuid'].replace('-', ''), 16)

    def test_long_value_clipped(self):
        attribute = kind_to_attribute('ip', 'x' * 1500)
        assert len(attribute['value']) == 1000
        assert attribute['value'].endswith('…')


# --------------------------------------------------------------------------- #
# MISP event assembly
# --------------------------------------------------------------------------- #

class TestBuildMispEvent:

    def test_event_key_set(self):
        event = build_misp_event('ip', '8.8.8.8', _envelope())
        assert set(event) == {'Event'}
        block = event['Event']
        assert {'id', 'info', 'date', 'threat_level_id', 'analysis',
                'published', 'timestamp', 'orgc', 'Attribute', 'Tag'} \
            <= set(block)
        assert block['analysis'] == '0'
        assert block['published'] is False
        assert block['date'].count('-') == 2  # YYYY-MM-DD

    def test_threat_level_success_mapping(self):
        healthy = build_misp_event('ip', '8.8.8.8', _envelope())
        assert healthy['Event']['threat_level_id'] == '3'
        broken = build_misp_event('ip', '8.8.8.8', {
            'ip': '8.8.8.8', 'info': {}, 'success': False,
            'errors': ['everything failed']})
        assert broken['Event']['threat_level_id'] == '2'

    def test_orgc_is_fixed_obscuralens_identity(self):
        event = build_misp_event('ip', '8.8.8.8', _envelope())
        orgc = event['Event']['orgc']
        assert orgc == {'name': MISP_ORG_NAME, 'uuid': MISP_ORG_UUID}
        assert MISP_ORG_NAME == 'ObscuraLens'

    def test_target_attribute_and_field_attributes(self):
        event = build_misp_event('ip', '8.8.8.8', _envelope())
        attributes = event['Event']['Attribute']
        # 1 target + 3 info fields + 1 sources_ok = 5 attributes.
        assert len(attributes) == 5
        assert attributes[0]['type'] == 'ip-src'
        assert attributes[0]['value'] == '8.8.8.8'
        comments = [attr['comment'] for attr in attributes[1:]]
        assert set(comments) == {'country', 'org', 'asn', 'sources_ok'}
        sources = [attr for attr in attributes
                   if attr['comment'] == 'sources_ok']
        assert sources[0]['value'] == 'ipapi, rdap'
        assert all(attr['to_ids'] is False for attr in attributes)

    def test_tag_names(self):
        event = build_misp_event('ip', '8.8.8.8', _envelope())
        assert event['Event']['Tag'] == [{'name': 'obscuralens:ip'}]

    def test_info_summary_line(self):
        event = build_misp_event('ip', '8.8.8.8', _envelope(),
                                 title='Nightly sweep')
        assert event['Event']['info'] == \
            'Nightly sweep - 3 field(s) from 2 source(s), 0 error(s)'
        default = build_misp_event('ip', '8.8.8.8', _envelope())
        assert default['Event']['info'].startswith(
            'ObscuraLens ip lookup: 8.8.8.8 - ')

    def test_value_falls_back_to_envelope(self):
        event = build_misp_event('ip', '', {'ip': '9.9.9.9', 'info': {}})
        assert event['Event']['Attribute'][0]['value'] == '9.9.9.9'

    def test_field_attributes_capped_at_200(self):
        info = {f'field{index}': index for index in range(250)}
        event = build_misp_event('ip', '8.8.8.8', {
            'ip': '8.8.8.8', 'info': info, 'sources_ok': ['ipapi']})
        attributes = event['Event']['Attribute']
        # 1 target + (200 info fields + 1 sources_ok, clipped to 200).
        assert len(attributes) == 201
        comments = [attr['comment'] for attr in attributes]
        assert comments.count('field199') == 1
        assert 'field200' not in comments


class TestBuildEventHelpers:

    def test_build_event_summary_composition(self):
        both = build_event('Title', 'description', tags=['t1', 't2'])
        assert both['Event']['info'] == 'Title - description'
        assert both['Event']['Tag'] == [{'name': 't1'}, {'name': 't2'}]
        only_title = build_event('Title', '')
        assert only_title['Event']['info'] == 'Title'
        neither = build_event('', '')
        assert neither['Event']['info'] == 'ObscuraLens export'

    def test_threat_level_clamped(self):
        assert build_event('t', '', threat_level=9)['Event'][
            'threat_level_id'] == '4'
        assert build_event('t', '', threat_level=-3)['Event'][
            'threat_level_id'] == '1'
        assert build_event('t', '', threat_level='nope')['Event'][
            'threat_level_id'] == '3'

    def test_event_id_deterministic(self):
        first = build_event('same', 'same')
        second = build_event('same', 'same')
        assert first['Event']['id'] == second['Event']['id']
        assert first['Event']['id'].isdigit()

    def test_threat_level_for_pure_helper(self):
        assert threat_level_for({'success': True, 'errors': []}) == 3
        assert threat_level_for({'success': True,
                                 'errors': ['x']}) == 2
        assert threat_level_for({'success': False}) == 2
        assert threat_level_for('not-a-dict') == 2

    def test_result_to_attributes_skips_empty_values(self):
        attributes = result_to_attributes({
            'info': {'a': 'value', 'b': '', 'c': None, 'd': 0},
            'sources_ok': []})
        assert [attr['comment'] for attr in attributes] == ['a', 'd']
        assert result_to_attributes('not-a-dict') == []


class TestDumpEvent:

    def test_writes_parseable_file(self, tmp_path):
        event = build_misp_event('ip', '8.8.8.8', _envelope())
        target = tmp_path / 'nested' / 'event.json'
        result = dump_event(event, target)
        assert result['ok'] is True
        assert result['bytes'] > 0
        assert result['path'] == str(target)
        assert json.loads(target.read_text(encoding='utf-8')) == event

    def test_unwritable_path_reports_failure(self, tmp_path):
        blocker = tmp_path / 'blocker'
        blocker.write_text('file', encoding='utf-8')
        result = dump_event(build_misp_event('ip', '8.8.8.8', {}),
                            blocker / 'sub' / 'event.json')
        assert result['ok'] is False
        assert result['bytes'] == 0
        assert result['error']


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

class TestExportCli:

    def test_stix_export_from_history(self, capsys):
        from obscuralens import commands
        from obscuralens.database import db
        db.save_query('ip', '8.8.8.8', _envelope())
        assert commands.run(['export', 'stix', 'ip', '8.8.8.8']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['type'] == 'bundle'
        types = [obj['type'] for obj in payload['objects']]
        assert 'identity' in types and 'indicator' in types

    def test_stix_export_no_history_returns_2(self, capsys):
        from obscuralens import commands
        assert commands.run(
            ['export', 'stix', 'domain',
             'never-stored-4c9a.example']) == 2
        assert 'no stored' in capsys.readouterr().err

    def test_misp_export_from_history(self, capsys):
        from obscuralens import commands
        from obscuralens.database import db
        db.save_query('ip', '8.8.8.8', _envelope())
        assert commands.run(['export', 'misp', 'ip', '8.8.8.8']) == 0
        payload = json.loads(capsys.readouterr().out)
        assert 'Event' in payload
        assert payload['Event']['orgc']['name'] == 'ObscuraLens'

    def test_misp_export_no_history_returns_2(self, capsys):
        from obscuralens import commands
        assert commands.run(
            ['export', 'misp', 'domain',
             'never-stored-4c9a.example']) == 2
        assert 'no stored' in capsys.readouterr().err

    def test_export_to_file(self, tmp_path, capsys):
        from obscuralens import commands
        from obscuralens.database import db
        db.save_query('ip', '8.8.8.8', _envelope())
        stix_file = tmp_path / 'bundle.json'
        assert commands.run(['export', 'stix', 'ip', '8.8.8.8',
                             '-o', str(stix_file)]) == 0
        assert 'STIX bundle exported' in capsys.readouterr().err
        assert json.loads(stix_file.read_text(
            encoding='utf-8'))['type'] == 'bundle'
        misp_file = tmp_path / 'event.json'
        assert commands.run(['export', 'misp', 'ip', '8.8.8.8',
                             '-o', str(misp_file)]) == 0
        assert 'MISP event exported' in capsys.readouterr().err
        assert 'Event' in json.loads(misp_file.read_text(encoding='utf-8'))


# --------------------------------------------------------------------------- #
# Web API wiring
# --------------------------------------------------------------------------- #

class TestExportWeb:

    @pytest.fixture()
    def client(self):
        pytest.importorskip('fastapi')
        pytest.importorskip('httpx')
        from fastapi.testclient import TestClient

        from obscuralens.web import create_app
        return TestClient(create_app())

    def test_stix_endpoint_from_history(self, client):
        from obscuralens.database import db
        db.save_query('ip', '8.8.8.8', _envelope())
        response = client.get('/api/export/stix/ip/8.8.8.8')
        assert response.status_code == 200
        payload = response.json()
        assert payload['type'] == 'bundle'
        assert any(obj['type'] == 'indicator'
                   for obj in payload['objects'])

    def test_stix_endpoint_no_history_404(self, client):
        response = client.get('/api/export/stix/domain/'
                               'never-stored-4c9a.example')
        assert response.status_code == 404
        assert 'no stored' in response.json()['detail']

    def test_misp_endpoint_from_history(self, client):
        from obscuralens.database import db
        db.save_query('ip', '8.8.8.8', _envelope())
        response = client.get('/api/export/misp/ip/8.8.8.8')
        assert response.status_code == 200
        payload = response.json()
        assert 'Event' in payload
        assert payload['Event']['orgc']['uuid'] == MISP_ORG_UUID

    def test_misp_endpoint_no_history_404(self, client):
        response = client.get('/api/export/misp/domain/'
                               'never-stored-4c9a.example')
        assert response.status_code == 404

    def test_unknown_kind_400(self, client):
        assert client.get('/api/export/stix/pigeon/8.8.8.8') \
            .status_code == 400
        assert client.get('/api/export/misp/pigeon/8.8.8.8') \
            .status_code == 400
