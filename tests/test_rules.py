"""
Offline tests for the explainable YAML rule engine (obscuralens.rules).

Covers every operator through a parametrized True/False matrix plus the
defensive paths (missing fields, invalid regex, junk numerics, CIDR edges,
``age_*`` timestamp parsing), dotted field resolution and the ``info.``
fallback, ``Rule.matches`` AND semantics, loading of every shipped pack
(structure, ids, severities, weights) plus the tolerant paths (corrupt YAML,
unknown operators, ``OBSCURALENS_RULES_DIR`` overrides), scoring through
``evaluate_rules`` (accumulation, 0-100 cap, band edges) and the
``RuleHit`` / ``RuleEvaluation`` shapes, plus ``rules_summary`` and
``merge_pack_dicts``.  Fully offline; user-directory behaviour is exercised
through ``tmp_path`` + ``monkeypatch`` on the rules-dir environment variable.
"""

import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from obscuralens.rules import (
    BANDS,
    EVAL_WARNINGS,
    LOAD_WARNINGS,
    OPERATORS,
    SEVERITIES,
    Condition,
    Rule,
    RuleEvaluation,
    RuleHit,
    RulePack,
    band_for,
    evaluate_condition,
    evaluate_rules,
    load_all_packs,
    load_pack,
    merge_pack_dicts,
    packs_dir,
    reset_rule_caches,
    resolve_field,
    rules_summary,
)
from obscuralens.rules.engine import MISSING, RULES_DIR_ENV

#: Shipped pack directory and the kinds derived from its YAML files.
PACKS_PATH = packs_dir()
PACK_KINDS = sorted(path.stem for path in PACKS_PATH.glob('*.yaml'))
SHIPPED_KINDS = tuple(PACK_KINDS)

#: Rule ids must look like ``DOMAIN-001`` (kind prefix, dash, digits).
ID_PATTERN = re.compile(r'^[A-Z]+-\d+$')

#: A field dict exercising the operators below (mix of real junk values).
BASE_FIELDS = {
    'country': 'RU',
    'region': 'North',
    'score': 42,
    'count': '7',
    'flag': True,
    'off': False,
    'text': 'Hello World',
    'items': ['alpha', 'beta'],
    'mapping': {'alpha': 1},
    'ip': '192.168.1.10',
    'email': 'user@mailinator.com',
    'domain': 'google.com',
    'blank': '',
    'none': None,
    'zero': 0,
    'empty_list': [],
}

#: (field, operator, value, fields, expected) covering every operator.
OPERATOR_MATRIX = [
    # eq / neq (tolerant equality: case and numeric strings)
    ('country', 'eq', 'RU', BASE_FIELDS, True),
    ('country', 'eq', 'US', BASE_FIELDS, False),
    ('country', 'eq', 'ru', BASE_FIELDS, True), ('count', 'eq', 7, BASE_FIELDS, True),
    ('score', 'eq', '42', BASE_FIELDS, True), ('country', 'neq', 'US', BASE_FIELDS, True),
    ('country', 'neq', 'RU', BASE_FIELDS, False),
    # in / not_in
    ('country', 'in', ['RU', 'CN'], BASE_FIELDS, True),
    ('country', 'in', ['DE', 'CN'], BASE_FIELDS, False),
    ('country', 'in', 'RU', BASE_FIELDS, True),
    ('country', 'not_in', ['DE', 'CN'], BASE_FIELDS, True),
    ('country', 'not_in', ['RU'], BASE_FIELDS, False),
    # contains / not_contains (substring, list member, dict key)
    ('text', 'contains', 'world', BASE_FIELDS, True),
    ('text', 'contains', 'xyz', BASE_FIELDS, False),
    ('items', 'contains', 'alpha', BASE_FIELDS, True),
    ('items', 'contains', 'gamma', BASE_FIELDS, False),
    ('mapping', 'contains', 'alpha', BASE_FIELDS, True),
    ('text', 'not_contains', 'xyz', BASE_FIELDS, True),
    ('text', 'not_contains', 'world', BASE_FIELDS, False),
    # startswith / endswith (case sensitive)
    ('text', 'startswith', 'Hello', BASE_FIELDS, True),
    ('text', 'startswith', 'hello', BASE_FIELDS, False),
    ('text', 'endswith', 'World', BASE_FIELDS, True),
    ('text', 'endswith', 'Hello', BASE_FIELDS, False),
    # regex
    ('text', 'regex', r'Wor.d', BASE_FIELDS, True),
    ('text', 'regex', r'^xyz$', BASE_FIELDS, False),
    # gt / gte / lt / lte (numeric strings coerce)
    ('score', 'gt', 40, BASE_FIELDS, True), ('score', 'gt', 42, BASE_FIELDS, False),
    ('score', 'gte', 42, BASE_FIELDS, True), ('score', 'gte', 43, BASE_FIELDS, False),
    ('score', 'lt', 50, BASE_FIELDS, True), ('score', 'lt', 42, BASE_FIELDS, False),
    ('score', 'lte', 42, BASE_FIELDS, True), ('score', 'lte', 41, BASE_FIELDS, False),
    ('count', 'gt', 5, BASE_FIELDS, True),
    # exists / not_exists
    ('country', 'exists', True, BASE_FIELDS, True),
    ('country', 'exists', None, BASE_FIELDS, True),
    ('nope', 'exists', True, BASE_FIELDS, False),
    ('nope', 'not_exists', True, BASE_FIELDS, True),
    ('country', 'not_exists', True, BASE_FIELDS, False),
    # empty / not_empty (missing counts as empty, 0 does not)
    ('blank', 'empty', True, BASE_FIELDS, True), ('none', 'empty', True, BASE_FIELDS, True),
    ('empty_list', 'empty', True, BASE_FIELDS, True),
    ('zero', 'empty', True, BASE_FIELDS, False),
    ('text', 'not_empty', True, BASE_FIELDS, True),
    ('blank', 'not_empty', True, BASE_FIELDS, False),
    # is_true / is_false
    ('flag', 'is_true', True, BASE_FIELDS, True),
    ('off', 'is_true', True, BASE_FIELDS, False),
    ('off', 'is_false', True, BASE_FIELDS, True),
    ('flag', 'is_false', True, BASE_FIELDS, False),
    # in_cidr
    ('ip', 'in_cidr', '192.168.1.0/24', BASE_FIELDS, True),
    ('ip', 'in_cidr', '10.0.0.0/8', BASE_FIELDS, False),
    # known_pack (shipped text data packs)
    ('email', 'known_pack', 'disposable_email_domains', BASE_FIELDS, True),
    ('email', 'known_pack', 'popular_domains', BASE_FIELDS, False),
    ('domain', 'known_pack', 'popular_domains', BASE_FIELDS, True),
]


class WarningLens:
    """Snapshot of the module warning lists; exposes entries added since."""

    def __init__(self):
        self._load = len(LOAD_WARNINGS)
        self._eval = len(EVAL_WARNINGS)

    def new_load(self):
        return LOAD_WARNINGS[self._load:]

    def new_eval(self):
        return EVAL_WARNINGS[self._eval:]


@pytest.fixture()
def warning_lens():
    """Baseline for the append-only LOAD_WARNINGS / EVAL_WARNINGS lists."""
    return WarningLens()


@pytest.fixture()
def fresh_caches():
    """Reset the pack caches around a test (env overrides in particular)."""
    reset_rule_caches()
    yield
    reset_rule_caches()


@pytest.fixture()
def rules_env(tmp_path, monkeypatch):
    """Point OBSCURALENS_RULES_DIR at a per-test directory."""
    monkeypatch.setenv(RULES_DIR_ENV, str(tmp_path))
    reset_rule_caches()
    yield tmp_path
    reset_rule_caches()


def _condition(field, operator, value=None):
    return Condition(field=field, operator=operator, value=value)


def _make_rule(rule_id, conditions, weight=10, enabled=True, kind='test'):
    return Rule(
        id=rule_id,
        kind=kind,
        title=f'rule {rule_id}',
        description='synthetic test rule',
        severity='medium',
        weight=weight,
        conditions=list(conditions),
        tags=['test'],
        references=[],
        enabled=enabled,
    )


def _write_pack(directory, name, text):
    path = Path(directory) / f'{name}.yaml'
    path.write_text(text, encoding='utf-8')
    return path


# --------------------------------------------------------------------------- #
# constants and operator matrix
# --------------------------------------------------------------------------- #

class TestConstants:

    def test_operators_are_the_documented_set(self):
        assert set(OPERATORS) == {
            'eq', 'neq', 'in', 'not_in', 'contains', 'not_contains',
            'startswith', 'endswith', 'regex', 'gt', 'gte', 'lt', 'lte',
            'exists', 'not_exists', 'empty', 'not_empty', 'is_true',
            'is_false', 'in_cidr', 'known_pack', 'age_lt_days',
            'age_gt_days',
        }
        assert len(OPERATORS) == 23

    def test_severities_and_bands(self):
        assert SEVERITIES == ('info', 'low', 'medium', 'high', 'critical')
        assert BANDS == ('clean', 'watch', 'elevated', 'high', 'critical')

    def test_rules_dir_env_name(self):
        assert RULES_DIR_ENV == 'OBSCURALENS_RULES_DIR'

    def test_packs_dir_holds_yaml_files(self):
        assert PACKS_PATH.is_dir()
        assert len(list(PACKS_PATH.glob('*.yaml'))) >= 15

    @pytest.mark.parametrize('field,operator,value,fields,expected', OPERATOR_MATRIX)
    def test_operator_matrix(self, field, operator, value, fields, expected):
        condition = _condition(field, operator, value)
        assert evaluate_condition(condition, fields) is expected

    @pytest.mark.parametrize(
        'operator',
        [op for op in OPERATORS if op not in ('not_exists', 'empty')],
    )
    def test_missing_field_is_false_for_most_operators(self, operator):
        condition = _condition('absent_field', operator, 'anything')
        assert evaluate_condition(condition, {}) is False

    @pytest.mark.parametrize('operator', ['not_exists', 'empty'])
    def test_missing_field_matches_absence_operators(self, operator):
        condition = _condition('absent_field', operator, True)
        assert evaluate_condition(condition, {}) is True

    @pytest.mark.parametrize('operator', ['gt', 'gte', 'lt', 'lte'])
    def test_numeric_operators_with_non_numeric_field(self, operator):
        condition = _condition('country', operator, 10)
        assert evaluate_condition(condition, {'country': 'RU'}) is False

    @pytest.mark.parametrize('operator', ['gt', 'gte', 'lt', 'lte'])
    def test_numeric_operators_with_non_numeric_value(self, operator):
        condition = _condition('score', operator, 'high')
        assert evaluate_condition(condition, {'score': 42}) is False


class TestOperatorDetails:

    def test_is_true_accepts_textual_flags(self):
        for value in ('yes', 'true', 'on', 'TRUE', 'Yes'):
            assert evaluate_condition(_condition('f', 'is_true'), {'f': value}) is True
        for value in ('no', 'false', 'off', 'maybe', 0, None):
            assert evaluate_condition(_condition('f', 'is_true'), {'f': value}) is False

    def test_is_false_accepts_textual_flags(self):
        for value in (False, 'false', 'no', 'off', 'FALSE'):
            assert evaluate_condition(_condition('f', 'is_false'), {'f': value}) is True
        for value in (True, 'true', 'yes', 0, 'maybe'):
            assert evaluate_condition(_condition('f', 'is_false'), {'f': value}) is False

    def test_invalid_regex_returns_false_without_raising(self, warning_lens):
        condition = _condition('text', 'regex', '([unclosed-' + 'unique1')
        assert evaluate_condition(condition, BASE_FIELDS) is False
        assert any('invalid regex' in entry for entry in warning_lens.new_eval())

    def test_invalid_regex_returns_false_every_time(self, warning_lens):
        # Invalid patterns are re-flagged on every evaluation (the compiled
        # cache cannot distinguish "not cached" from "failed to compile").
        pattern = '([unclosed-' + 'unique2'
        condition = _condition('text', 'regex', pattern)
        assert evaluate_condition(condition, BASE_FIELDS) is False
        assert evaluate_condition(condition, BASE_FIELDS) is False
        assert len([e for e in warning_lens.new_eval() if 'invalid regex' in e]) == 2

    def test_regex_with_non_string_pattern(self):
        assert evaluate_condition(_condition('text', 'regex', None), BASE_FIELDS) is False
        assert evaluate_condition(_condition('text', 'regex', 7), BASE_FIELDS) is False

    def test_regex_matches_numeric_fields_via_string_form(self):
        condition = _condition('score', 'regex', r'^\d+$')
        assert evaluate_condition(condition, {'score': 42}) is True

    def test_regex_never_matches_container_fields(self):
        condition = _condition('items', 'regex', r'alpha')
        assert evaluate_condition(condition, BASE_FIELDS) is False

    def test_in_cidr_valid_and_invalid_ip_values(self):
        condition = _condition('ip', 'in_cidr', '192.168.0.0/16')
        assert evaluate_condition(condition, {'ip': '192.168.1.10'}) is True
        assert evaluate_condition(condition, {'ip': '10.0.0.1'}) is False
        assert evaluate_condition(condition, {'ip': 'not-an-ip'}) is False
        assert evaluate_condition(condition, {'ip': ''}) is False
        assert evaluate_condition(condition, {'ip': {'a': 1}}) is False

    def test_in_cidr_accepts_lists_and_host_bits(self):
        condition = _condition('ip', 'in_cidr', ['10.0.0.0/8', '192.168.1.7/24'])
        assert evaluate_condition(condition, {'ip': '192.168.1.10'}) is True

    def test_in_cidr_invalid_literal_warns_and_returns_false(self, warning_lens):
        condition = _condition('ip', 'in_cidr', '300.300.0.0/8')
        assert evaluate_condition(condition, {'ip': '192.168.1.10'}) is False
        assert any('invalid CIDR' in entry for entry in warning_lens.new_eval())

    def test_in_cidr_ipv6_and_version_mismatch(self):
        condition = _condition('ip', 'in_cidr', '2001:db8::/32')
        assert evaluate_condition(condition, {'ip': '2001:db8::1'}) is True
        assert evaluate_condition(condition, {'ip': '192.168.1.10'}) is False

    def test_known_pack_uses_domain_part_of_emails(self):
        condition = _condition('email', 'known_pack', 'disposable_email_domains')
        assert evaluate_condition(condition, {'email': 'x@mailinator.com'}) is True
        assert evaluate_condition(condition, {'email': 'x@evil.mailinator.com'}) is True
        assert evaluate_condition(condition, {'email': 'x@gmail.com'}) is False

    def test_known_pack_with_missing_pack_warns(self, warning_lens):
        condition = _condition('email', 'known_pack', 'no_such_pack_here')
        assert evaluate_condition(condition, {'email': 'a@b.com'}) is False
        assert any('no_such_pack_here' in entry for entry in warning_lens.new_eval())

    def test_known_pack_with_non_string_inputs(self):
        condition = _condition('email', 'known_pack', 'disposable_email_domains')
        assert evaluate_condition(condition, {'email': None}) is False
        assert evaluate_condition(condition, {'email': ['x']}) is False

    def test_age_lt_days_accepts_iso_datetime_string(self):
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        condition = _condition('created', 'age_lt_days', 30)
        assert evaluate_condition(condition, {'created': recent.isoformat()}) is True

    def test_age_lt_days_accepts_date_and_z_suffix_strings(self):
        condition = _condition('created', 'age_lt_days', 30)
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        assert evaluate_condition(condition, {'created': today}) is True
        assert evaluate_condition(condition, {'created': '2020-01-01'}) is False
        assert evaluate_condition(condition, {'created': '2020-01-01T00:00:00Z'}) is False

    def test_age_lt_days_accepts_epoch_seconds_and_milliseconds(self):
        now = datetime.now(timezone.utc)
        condition = _condition('created', 'age_lt_days', 1)
        seconds = (now - timedelta(hours=2)).timestamp()
        assert evaluate_condition(condition, {'created': seconds}) is True
        assert evaluate_condition(condition, {'created': int(seconds)}) is True
        assert evaluate_condition(condition, {'created': seconds * 1000.0}) is True

    def test_age_operators_accept_datetime_and_date_objects(self):
        condition = _condition('created', 'age_lt_days', 30)
        recent = datetime.now(timezone.utc) - timedelta(minutes=30)
        assert evaluate_condition(condition, {'created': recent}) is True
        assert evaluate_condition(condition, {'created': recent.date()}) is True

    def test_age_gt_days_with_old_date_string(self):
        condition = _condition('created', 'age_gt_days', 365)
        assert evaluate_condition(condition, {'created': '2020-01-01'}) is True
        assert evaluate_condition(condition, {'created': date(2019, 6, 1)}) is True

    def test_age_gt_days_with_recent_value(self):
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        condition = _condition('created', 'age_gt_days', 365)
        assert evaluate_condition(condition, {'created': recent.isoformat()}) is False

    def test_age_operators_with_unparseable_values(self):
        for operator in ('age_lt_days', 'age_gt_days'):
            condition = _condition('created', operator, 30)
            assert evaluate_condition(condition, {'created': 'not a date'}) is False
            assert evaluate_condition(condition, {'created': None}) is False

    def test_age_operator_with_non_numeric_limit(self):
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        condition = _condition('created', 'age_lt_days', 'soon')
        assert evaluate_condition(condition, {'created': recent.isoformat()}) is False

    def test_unknown_operator_never_matches_and_warns(self, warning_lens):
        condition = _condition('country', 'bogus_operator', 'RU')
        assert evaluate_condition(condition, {'country': 'RU'}) is False
        assert any('bogus_operator' in entry for entry in warning_lens.new_eval())


# --------------------------------------------------------------------------- #
# field resolution
# --------------------------------------------------------------------------- #

class TestFieldResolution:

    def test_nested_dotted_path(self):
        fields = {'info': {'country': 'RU', 'asn': {'number': 15169}}}
        assert resolve_field(fields, 'info.country') == 'RU'
        assert resolve_field(fields, 'info.asn.number') == 15169

    def test_top_level_path(self):
        assert resolve_field({'country': 'RU'}, 'country') == 'RU'

    def test_info_fallback_for_flat_paths(self):
        fields = {'info': {'country': 'RU'}}
        assert resolve_field(fields, 'country') == 'RU'

    def test_missing_intermediate_is_missing(self):
        assert resolve_field({'info': {}}, 'info.country') is MISSING
        assert resolve_field({}, 'info.country') is MISSING
        assert resolve_field({'other': 1}, 'info.country') is MISSING

    def test_non_dict_intermediate_breaks_walk(self):
        assert resolve_field({'info': 'scalar'}, 'info.country') is MISSING
        assert resolve_field({'info': [1, 2]}, 'info.country') is MISSING

    def test_missing_top_level_is_missing(self):
        assert resolve_field({'a': 1}, 'b') is MISSING

    def test_non_dict_fields_is_missing(self):
        assert resolve_field(None, 'a') is MISSING
        assert resolve_field('text', 'a') is MISSING
        assert resolve_field([1], 'a') is MISSING

    def test_explicit_info_prefix_not_retried(self):
        # 'info.info.x' only resolves a real nested 'info' inside 'info'.
        assert resolve_field({'info': {'info': {'x': 1}}}, 'info.info.x') == 1
        assert resolve_field({'info': {'x': 1}}, 'info.info.x') is MISSING


# --------------------------------------------------------------------------- #
# rules, conditions and packs built in memory
# --------------------------------------------------------------------------- #

class TestConditionHelpers:

    def test_render_equality_operator(self):
        assert _condition('info.country', 'eq', 'RU').render() == "info.country == 'RU'"

    def test_render_presence_operators(self):
        assert _condition('f', 'exists').render() == 'f exists'
        assert _condition('f', 'not_exists').render() == 'f is absent'
        assert _condition('f', 'empty').render() == 'f is empty'
        assert _condition('f', 'not_empty').render() == 'f is not empty'
        assert _condition('f', 'is_true').render() == 'f is true'
        assert _condition('f', 'is_false').render() == 'f is false'

    def test_render_age_operators(self):
        assert _condition('f', 'age_lt_days', 30).render() == 'f age < 30 days'
        assert _condition('f', 'age_gt_days', 365).render() == 'f age > 365 days'

    def test_render_unknown_operator_uses_its_name(self):
        assert _condition('f', 'bogus', 1).render() == 'f bogus 1'

    def test_explain_matching_condition_renders_like_render(self):
        condition = _condition('country', 'eq', 'RU')
        assert condition.explain({'country': 'RU'}) == condition.render()

    def test_explain_non_matching_condition_shows_actual(self):
        condition = _condition('country', 'eq', 'RU')
        explained = condition.explain({'country': 'DE'})
        assert explained.startswith(condition.render())
        assert '(actual:' in explained

    def test_explain_missing_field(self):
        condition = _condition('country', 'eq', 'RU')
        explained = condition.explain({})
        assert '(field missing)' in explained

    def test_to_dict(self):
        condition = _condition('country', 'eq', 'RU')
        assert condition.to_dict() == {
            'field': 'country', 'operator': 'eq', 'value': 'RU',
        }


class TestRuleSemantics:

    def _two_condition_rule(self):
        return _make_rule('TST-001', [
            _condition('country', 'eq', 'RU'),
            _condition('score', 'gte', 10),
        ])

    def test_all_conditions_must_match(self):
        rule = self._two_condition_rule()
        assert rule.matches({'country': 'RU', 'score': 42}) is True

    def test_one_failing_condition_blocks_the_rule(self):
        rule = self._two_condition_rule()
        assert rule.matches({'country': 'RU', 'score': 5}) is False
        assert rule.matches({'country': 'DE', 'score': 42}) is False
        assert rule.matches({}) is False

    def test_explain_returns_one_string_per_condition(self):
        rule = self._two_condition_rule()
        explained = rule.explain({'country': 'RU', 'score': 5})
        assert len(explained) == 2
        assert explained[0] == "country == 'RU'"
        assert '(actual:' in explained[1]

    def test_disabled_rule_never_matches(self):
        rule = _make_rule('TST-002', [_condition('country', 'eq', 'RU')], enabled=False)
        assert rule.matches({'country': 'RU'}) is False

    def test_to_dict_shape(self):
        rule = self._two_condition_rule()
        payload = rule.to_dict()
        assert payload['id'] == 'TST-001'
        assert payload['kind'] == 'test'
        assert payload['severity'] == 'medium'
        assert payload['weight'] == 10
        assert payload['enabled'] is True
        assert len(payload['conditions']) == 2
        assert payload['conditions'][0]['operator'] == 'eq'


class TestRulePackInMemory:

    def _pack(self):
        rules = [
            _make_rule('TST-001', [_condition('country', 'eq', 'RU')], weight=20),
            _make_rule('TST-002', [_condition('score', 'gte', 10)], weight=15),
            _make_rule('TST-003', [_condition('country', 'eq', 'RU')], weight=5,
                       enabled=False),
        ]
        return RulePack(kind='test', name='test-pack', description='d',
                        version=2, rules=rules)

    def test_counts(self):
        pack = self._pack()
        assert pack.rule_count == 3
        assert pack.enabled_count == 2

    def test_find(self):
        pack = self._pack()
        assert pack.find('TST-002').title == 'rule TST-002'
        assert pack.find('NOPE-999') is None

    def test_evaluate_returns_only_enabled_matches(self):
        pack = self._pack()
        hits = pack.evaluate({'country': 'RU', 'score': 42})
        assert [hit.rule.id for hit in hits] == ['TST-001', 'TST-002']

    def test_evaluate_clamps_hit_scores(self):
        pack = RulePack(kind='test', rules=[
            _make_rule('TST-009', [_condition('country', 'eq', 'RU')], weight=150),
        ])
        hits = pack.evaluate({'country': 'RU'})
        assert hits[0].score == 100

    def test_score_sums_and_caps_at_100(self):
        pack = RulePack(kind='test', rules=[
            _make_rule('TST-001', [_condition('country', 'eq', 'RU')], weight=60),
            _make_rule('TST-002', [_condition('score', 'gte', 0)], weight=60),
        ])
        assert pack.score({'country': 'RU', 'score': 1}) == 100
        assert pack.score({'country': 'DE', 'score': 1}) == 60
        assert pack.score({}) == 0

    def test_to_dict_shape(self):
        payload = self._pack().to_dict()
        assert payload['kind'] == 'test'
        assert payload['rule_count'] == 3
        assert len(payload['rules']) == 3

    def test_rule_hit_fields_and_to_dict(self):
        pack = self._pack()
        hit = pack.evaluate({'country': 'RU'})[0]
        assert isinstance(hit, RuleHit)
        assert hit.rule.id == 'TST-001'
        assert hit.score == 20
        assert hit.explanations == ["country == 'RU'"]
        payload = hit.to_dict()
        assert payload['id'] == 'TST-001'
        assert payload['score'] == 20
        assert payload['explanations'] == ["country == 'RU'"]


# --------------------------------------------------------------------------- #
# shipped pack loading
# --------------------------------------------------------------------------- #

class TestShippedPacks:

    @pytest.mark.parametrize('kind', SHIPPED_KINDS)
    def test_pack_loads_with_at_least_eight_rules(self, kind):
        pack = load_pack(kind)
        assert pack is not None, f'pack {kind} failed to load'
        assert pack.kind == kind
        assert pack.rule_count >= 8
        assert pack.name
        assert pack.rules

    @pytest.mark.parametrize('kind', SHIPPED_KINDS)
    def test_pack_rule_structure(self, kind):
        pack = load_pack(kind)
        assert pack is not None
        ids = [rule.id for rule in pack.rules]
        assert len(ids) == len(set(ids)), f'duplicate ids in {kind}'
        for rule in pack.rules:
            assert ID_PATTERN.match(rule.id), rule.id
            assert rule.severity in SEVERITIES
            assert 0 <= rule.weight <= 100
            assert rule.title.strip()
            assert rule.description.strip()
            assert rule.conditions
            for condition in rule.conditions:
                assert condition.operator in OPERATORS
                assert condition.field

    @pytest.mark.parametrize('kind', SHIPPED_KINDS)
    def test_pack_file_is_valid_yaml(self, kind):
        source = PACKS_PATH / f'{kind}.yaml'
        data = yaml.safe_load(source.read_text(encoding='utf-8'))
        assert isinstance(data, dict)
        assert isinstance(data['rules'], list)
        assert data['rules']
        assert len(list(PACKS_PATH.glob('*.yaml'))) >= 15

    def test_load_all_packs_returns_every_kind(self):
        packs = load_all_packs()
        assert set(SHIPPED_KINDS).issubset(packs)
        for kind, pack in packs.items():
            assert isinstance(pack, RulePack)
            assert pack.kind == kind

    def test_load_all_packs_is_cached_until_reset(self):
        first = load_all_packs()
        assert load_all_packs() is first
        reset_rule_caches()
        assert load_all_packs() is not first

    def test_load_pack_is_cached_per_kind(self):
        assert load_pack('domain') is load_pack('domain')

    def test_load_pack_normalises_the_kind_name(self):
        assert load_pack(' Domain ') is not None
        assert load_pack('DOMAIN').rule_count == load_pack('domain').rule_count

    def test_unknown_kind_returns_none_with_warning(self, warning_lens):
        assert load_pack('does-not-exist') is None
        assert any('does-not-exist' in entry for entry in warning_lens.new_load())

    @pytest.mark.parametrize('bad_kind', ['', '   ', '../etc', 'a/b', 'a\\b', None, 42])
    def test_unsafe_kind_names_return_none(self, bad_kind):
        assert load_pack(bad_kind) is None


class TestTolerantLoading:

    def test_corrupt_yaml_returns_none_never_raises(self, rules_env, warning_lens):
        _write_pack(rules_env, 'broken', 'rules: [ unbalanced\n  - id: X\n')
        assert load_pack('broken') is None
        assert any('invalid YAML' in entry for entry in warning_lens.new_load())

    def test_pack_without_rules_returns_none(self, rules_env, warning_lens):
        _write_pack(rules_env, 'norules', 'name: empty\nversion: 1\nrules: []\n')
        assert load_pack('norules') is None
        assert any('no usable rules' in entry for entry in warning_lens.new_load())

    def test_rules_with_unknown_operators_are_skipped(self, rules_env, warning_lens):
        _write_pack(rules_env, 'mixed', (
            'name: mixed\nrules:\n'
            '  - id: MIX-001\n'
            '    title: good\n'
            '    conditions:\n'
            '      - field: country\n'
            '        operator: eq\n'
            '        value: RU\n'
            '  - id: MIX-002\n'
            '    title: bad operator\n'
            '    conditions:\n'
            '      - field: country\n'
            '        operator: totally_bogus\n'
            '        value: RU\n'
        ))
        pack = load_pack('mixed')
        assert pack is not None
        assert [rule.id for rule in pack.rules] == ['MIX-001']
        assert any('totally_bogus' in entry for entry in warning_lens.new_load())

    def test_rule_without_title_is_skipped(self, rules_env, warning_lens):
        _write_pack(rules_env, 'notitle', (
            'name: no-title\nrules:\n'
            '  - id: NT-001\n'
            '    conditions:\n'
            '      - field: a\n'
            '        operator: exists\n'
        ))
        assert load_pack('notitle') is None
        assert any('missing title' in entry for entry in warning_lens.new_load())

    def test_user_override_wins_over_shipped_pack(self, rules_env):
        _write_pack(rules_env, 'mac', (
            'name: custom-mac\nrules:\n'
            '  - id: CUSTOM-001\n'
            '    title: custom rule\n'
            '    conditions:\n'
            '      - field: vendor\n'
            '        operator: eq\n'
            '        value: custom\n'
        ))
        pack = load_pack('mac')
        assert pack is not None
        assert pack.name == 'custom-mac'
        assert [rule.id for rule in pack.rules] == ['CUSTOM-001']

    def test_env_override_keeps_other_shipped_kinds(self, rules_env):
        _write_pack(rules_env, 'mac', 'name: custom-mac\nrules: []\n')
        # 'mac' resolves to the (empty, rejected) override -> None,
        # while untouched kinds still fall back to the shipped directory.
        assert load_pack('mac') is None
        assert load_pack('domain') is not None
        assert load_pack('domain').rule_count >= 8

    def test_explicit_pack_dir_argument(self, tmp_path):
        _write_pack(tmp_path, 'custom', (
            'name: explicit\nrules:\n'
            '  - id: CUS-001\n'
            '    title: t\n'
            '    conditions:\n'
            '      - field: a\n'
            '        operator: exists\n'
        ))
        pack = load_pack('custom', pack_dir=tmp_path)
        assert pack is not None
        assert pack.name == 'explicit'


# --------------------------------------------------------------------------- #
# scoring, bands and evaluate_rules
# --------------------------------------------------------------------------- #

class TestBandFor:

    @pytest.mark.parametrize('score,band', [
        (0, 'clean'), (1, 'clean'), (9, 'clean'),
        (10, 'watch'), (11, 'watch'), (29, 'watch'),
        (30, 'elevated'), (59, 'elevated'),
        (60, 'high'), (79, 'high'),
        (80, 'critical'), (100, 'critical'),
        (-5, 'clean'), (150, 'critical'),
    ])
    def test_documented_boundaries(self, score, band):
        assert band_for(score) == band

    @pytest.mark.parametrize('junk', ['junk', '', None, []])
    def test_non_numeric_score_is_clean(self, junk):
        assert band_for(junk) == 'clean'

    def test_numeric_strings_are_parsed(self):
        assert band_for('42') == 'elevated'


class TestRuleEvaluationDataclass:

    def test_score_is_clamped_and_band_derived(self):
        evaluation = RuleEvaluation(score=150)
        assert evaluation.score == 100
        assert evaluation.band == 'critical'

    def test_negative_score_is_clamped_to_zero(self):
        evaluation = RuleEvaluation(score=-3)
        assert evaluation.score == 0
        assert evaluation.band == 'clean'

    def test_band_is_computed_when_empty(self):
        assert RuleEvaluation(score=45).band == 'elevated'
        assert RuleEvaluation(score=0).band == 'clean'

    def test_explicit_band_is_preserved(self):
        evaluation = RuleEvaluation(score=90, band='custom-band')
        assert evaluation.band == 'custom-band'

    def test_matched_ids_and_to_dict(self):
        rule = _make_rule('TST-001', [_condition('country', 'eq', 'RU')], weight=20)
        hit = RuleHit(rule=rule, explanations=['x'], score=20)
        evaluation = RuleEvaluation(hits=[hit], score=20, kind='test')
        assert evaluation.matched_ids == ['TST-001']
        payload = evaluation.to_dict()
        assert payload['kind'] == 'test'
        assert payload['score'] == 20
        assert payload['band'] == 'watch'
        assert payload['hits'][0]['id'] == 'TST-001'

    def test_summary_lines(self):
        rule = _make_rule('TST-001', [_condition('country', 'eq', 'RU')])
        evaluation = RuleEvaluation(hits=[RuleHit(rule=rule)], score=35, kind='test')
        assert 'score 35' in evaluation.summary()
        assert 'elevated' in evaluation.summary()
        assert 'TST-001' in evaluation.summary()
        empty = RuleEvaluation(hits=[], score=0, kind='test')
        assert 'no rule matched' in empty.summary()


SUSPICIOUS_DOMAIN_FIELDS = {
    'domain': 'secure-login.example-xyz.tk',
    'registration': {'age_days': 3, 'privacy_protected': True},
    'dmarc_record': '',
    'spf_record': 'v=spf1 +all',
    'mx_records': [],
    'tld': 'tk',
    'dnssec': False,
    'wildcard_cert': True,
    'http_title': 'Domain for sale',
    'typosquat_of_popular': 'example.com',
    'urlscan_malicious_verdicts': 2,
    'domain_status': 'expired',
    'expires_in_days': 5,
}

#: Three domain rules with a known weight sum (20 + 25 + 15 = 60) and every
#: other domain/shared signal neutralised by explicit healthy values.
ACCUMULATION_FIELDS = {
    'registration': {'age_days': 3},
    'tld': 'xyz',
    'dmarc_record': 'v=DMARC1; p=reject',
    'mx_records': ['mx.example.org'],
    'spf_record': 'v=spf1 -all',
    'dnssec': True,
    'errors': ['boom'],
    'field_sources': {'country': 'rdap'},
    'wildcard_cert': False,
    'http_title': 'Welcome',
    'typosquat_of_popular': '',
    'urlscan_malicious_verdicts': 0,
    'domain_status': 'active',
    'expires_in_days': 300,
}

CLEAN_DOMAIN_FIELDS = {
    'domain': 'example.org',
    'registration': {'age_days': 4000, 'privacy_protected': False},
    'dmarc_record': 'v=DMARC1; p=reject',
    'spf_record': 'v=spf1 -all',
    'mx_records': ['mx.example.org'],
    'tld': 'org',
    'dnssec': True,
    'wildcard_cert': False,
    'http_title': 'Example Domain',
    'typosquat_of_popular': '',
    'urlscan_malicious_verdicts': 0,
    'domain_status': 'active',
    'expires_in_days': 300,
    'errors': ['boom'],
    'field_sources': {'country': 'rdap'},
}


class TestEvaluateRules:

    def test_returns_rule_evaluation_with_hits_score_band(self):
        evaluation = evaluate_rules('domain', SUSPICIOUS_DOMAIN_FIELDS)
        assert isinstance(evaluation, RuleEvaluation)
        assert evaluation.kind == 'domain'
        assert evaluation.hits
        assert all(isinstance(hit, RuleHit) for hit in evaluation.hits)

    def test_suspicious_domain_hits_at_least_three_rules(self):
        evaluation = evaluate_rules('domain', SUSPICIOUS_DOMAIN_FIELDS)
        domain_ids = [hit.rule.id for hit in evaluation.hits
                      if hit.rule.id.startswith('DOMAIN-')]
        assert len(domain_ids) >= 3
        assert 'DOMAIN-001' in domain_ids      # age <= 30
        assert 'DOMAIN-002' in domain_ids      # age <= 7
        assert 'DOMAIN-003' in domain_ids      # no DMARC
        assert 'DOMAIN-009' in domain_ids      # abused TLD

    def test_score_accumulates_and_caps_at_100(self):
        evaluation = evaluate_rules('domain', SUSPICIOUS_DOMAIN_FIELDS)
        raw = sum(hit.score for hit in evaluation.hits)
        assert raw > 100
        assert evaluation.score == 100
        assert evaluation.band == 'critical'

    def test_exact_weight_accumulation(self):
        evaluation = evaluate_rules('domain', ACCUMULATION_FIELDS)
        assert evaluation.matched_ids == ['DOMAIN-001', 'DOMAIN-002', 'DOMAIN-009']
        assert evaluation.score == 20 + 25 + 15
        assert evaluation.band == 'high'

    def test_clean_domain_scores_zero(self):
        evaluation = evaluate_rules('domain', CLEAN_DOMAIN_FIELDS)
        assert evaluation.hits == []
        assert evaluation.score == 0
        assert evaluation.band == 'clean'

    def test_hits_carry_rule_and_explanations(self):
        evaluation = evaluate_rules('domain', SUSPICIOUS_DOMAIN_FIELDS)
        hit = next(h for h in evaluation.hits if h.rule.id == 'DOMAIN-009')
        assert hit.rule.title
        assert hit.explanations
        assert hit.score == hit.rule.weight

    def test_shared_pack_runs_for_every_kind(self):
        fields = {'errors': ['timeout']}
        evaluation = evaluate_rules('ip', fields)
        assert 'SHARED-004' in evaluation.matched_ids

    def test_shared_kind_runs_the_shared_pack_only_once(self):
        fields = {'errors': ['timeout']}
        evaluation = evaluate_rules('shared', fields)
        assert evaluation.kind == 'shared'
        assert evaluation.matched_ids.count('SHARED-004') == 1

    def test_unknown_kind_never_raises_and_falls_back_to_shared(self):
        evaluation = evaluate_rules('no-such-kind', {'anything': 1})
        assert isinstance(evaluation, RuleEvaluation)
        # Only the kind-agnostic shared pack can still fire.
        assert all(hit.rule.kind == 'shared' for hit in evaluation.hits)
        assert evaluation.kind == 'no-such-kind'
        assert evaluation.score <= 10
        assert evaluation.band == 'clean'

    def test_unsafe_kind_falls_back_to_shared(self):
        evaluation = evaluate_rules('../etc', {'errors': ['timeout']})
        assert isinstance(evaluation, RuleEvaluation)
        assert 'SHARED-004' in evaluation.matched_ids

    def test_non_dict_fields_return_empty_evaluation(self):
        for junk in (None, 'text', 42, [1, 2]):
            evaluation = evaluate_rules('domain', junk)
            assert evaluation.hits == []
            assert evaluation.score == 0
            assert evaluation.band == 'clean'

    def test_summary_mentions_score_band_and_ids(self):
        evaluation = evaluate_rules('domain', ACCUMULATION_FIELDS)
        text = evaluation.summary()
        assert 'domain' in text
        assert '60' in text
        assert 'high' in text
        assert 'DOMAIN-001' in text


class TestHelpers:

    def test_rules_summary_lists_packs_and_counts(self):
        text = rules_summary()
        assert isinstance(text, str)
        assert 'Rule packs loaded' in text
        assert 'pack(s)' in text
        for kind in ('domain', 'ip', 'shared'):
            assert kind in text

    def test_merge_pack_dicts_override_wins_for_top_level_keys(self):
        base = {'name': 'base', 'version': 1, 'rules': [{'id': 'X-001'}]}
        override = {'name': 'override', 'description': 'd'}
        merged = merge_pack_dicts(base, override)
        assert merged['name'] == 'override'
        assert merged['version'] == 1
        assert merged['description'] == 'd'

    def test_merge_pack_dicts_replaces_rules_by_id_in_place(self):
        base = {'rules': [{'id': 'X-001', 'weight': 10}, {'id': 'X-002'}]}
        override = {'rules': [{'id': 'X-001', 'weight': 30}]}
        merged = merge_pack_dicts(base, override)
        ids = [rule['id'] for rule in merged['rules']]
        assert ids == ['X-001', 'X-002']
        assert merged['rules'][0]['weight'] == 30

    def test_merge_pack_dicts_appends_new_rules(self):
        base = {'rules': [{'id': 'X-001'}]}
        override = {'rules': [{'id': 'X-002'}, {'id': 'X-003'}]}
        merged = merge_pack_dicts(base, override)
        assert [rule['id'] for rule in merged['rules']] == ['X-001', 'X-002', 'X-003']

    def test_merge_pack_dicts_does_not_mutate_inputs(self):
        base = {'name': 'base', 'rules': [{'id': 'X-001', 'weight': 10}]}
        override = {'rules': [{'id': 'X-001', 'weight': 99}]}
        merge_pack_dicts(base, override)
        assert base['rules'][0]['weight'] == 10
        assert override['rules'][0]['weight'] == 99

    def test_merge_pack_dicts_with_none_inputs(self):
        base = {'name': 'base', 'rules': [{'id': 'X-001'}]}
        assert merge_pack_dicts(base, None) == base
        merged = merge_pack_dicts(None, {'name': 'only-override'})
        assert merged['name'] == 'only-override'
        assert merged['rules'] == []
