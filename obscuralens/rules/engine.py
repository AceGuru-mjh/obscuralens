"""
Explainable YAML rule engine for ObscuraLens (v5.1).

This module implements a small, dependency-light rule DSL that complements
:mod:`obscuralens.correlation.risk` with **human-readable rule packs**.
Where the correlation scorers weigh technical signals in code, the rule
packs under ``obscuralens/rules/packs/*.yaml`` declare the same style of
OSINT heuristics as data: every rule carries an identifier, a title, an
honest description of *why* the signal matters, a severity, a weight and a
list of conditions that must ALL match (AND semantics).

A rule is evaluated against a *field dict* -- the flat mapping of lookup
results the trackers return (``payload['info']`` for most kinds, the flat
username result for usernames).  Dotted paths such as ``registration.age_days``
walk nested dicts; a missing branch simply means the condition does not
match.  Nothing here ever raises on unexpected field values: every
operator is defensive and treats junk input as "no match".

Public surface::

    pack = load_pack('domain')            # obscuralens/rules/packs/domain.yaml
    hits = pack.evaluate(fields)          # [RuleHit, ...] (only matches)
    evaluation = evaluate_rules('domain', fields)
    evaluation.score, evaluation.band     # 0-100 + clean/watch/elevated/high/critical
    print(rules_summary())                # pretty table of every loaded pack

Loading is tolerant: invalid YAML yields ``None``, unknown operators make
the offending rule (not the whole pack) be skipped, and every skip is
recorded in the module-level :data:`LOAD_WARNINGS` list so pack authors can
debug their YAML.  The ``OBSCURALENS_RULES_DIR`` environment variable
redirects pack discovery to user-supplied directories (several directories
may be given, separated by ``os.pathsep``); directories earlier in the
list win, and the shipped ``packs/`` folder is always searched last as a
fallback for kinds the user did not override.

The rule engine describes **technical indicators, never people**.  Rule
text and weights are heuristics to help an analyst triage lookups; they
are not evidence and not a verdict.
"""

import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import yaml

__all__ = [
    'Condition',
    'Rule',
    'RuleHit',
    'RulePack',
    'RuleEvaluation',
    'LOAD_WARNINGS',
    'EVAL_WARNINGS',
    'SEVERITIES',
    'OPERATORS',
    'band_for',
    'evaluate_condition',
    'evaluate_rules',
    'load_pack',
    'load_all_packs',
    'merge_pack_dicts',
    'packs_dir',
    'reset_rule_caches',
    'rules_summary',
]

#: Rule severities understood by pack loading (worst to mildest order).
SEVERITIES: Tuple[str, ...] = ('info', 'low', 'medium', 'high', 'critical')

#: Risk bands used by :func:`band_for` (order matters for summaries only).
BANDS: Tuple[str, ...] = ('clean', 'watch', 'elevated', 'high', 'critical')

#: Environment variable that redirects pack discovery to user directories.
RULES_DIR_ENV = 'OBSCURALENS_RULES_DIR'

#: Directory holding the shipped ``<kind>.yaml`` rule packs.
_PACKS_DIR = Path(__file__).resolve().parent / 'packs'

#: Sentinel for "field not present" (distinct from a stored None/False).
MISSING: Any = object()

#: Warnings recorded while *loading* packs (invalid YAML, unknown
#: operators, malformed rule entries, out-of-range weights, ...).  Pack
#: authors are expected to inspect this list after editing YAML files.
LOAD_WARNINGS: List[str] = []

#: Warnings recorded while *evaluating* rules (invalid regex patterns,
#: broken CIDR literals in rule values, empty/missing data packs).  These
#: signal data-quality problems rather than authoring bugs.
EVAL_WARNINGS: List[str] = []

#: Operators a condition may declare.  ``age_lt_days`` / ``age_gt_days``
#: treat the field as a date (ISO string or epoch) and compare the age.
OPERATORS: Tuple[str, ...] = (
    'eq', 'neq', 'in', 'not_in', 'contains', 'not_contains',
    'startswith', 'endswith', 'regex', 'gt', 'gte', 'lt', 'lte',
    'exists', 'not_exists', 'empty', 'not_empty', 'is_true', 'is_false',
    'in_cidr', 'known_pack', 'age_lt_days', 'age_gt_days',
)

#: Symbols used by :meth:`Condition.render` for compact human explanations.
_OP_SYMBOLS: Dict[str, str] = {
    'eq': '==', 'neq': '!=', 'in': 'in', 'not_in': 'not in',
    'contains': 'contains', 'not_contains': 'does not contain',
    'startswith': 'starts with', 'endswith': 'ends with',
    'regex': 'matches', 'gt': '>', 'gte': '>=', 'lt': '<', 'lte': '<=',
    'exists': 'exists', 'not_exists': 'is absent',
    'empty': 'is empty', 'not_empty': 'is not empty',
    'is_true': 'is true', 'is_false': 'is false',
    'in_cidr': 'in CIDR', 'known_pack': 'in data pack',
    'age_lt_days': 'age <', 'age_gt_days': 'age >',
}

#: Compiled-regex cache (pattern -> compiled or None when invalid).  Kept
#: small; a flood of unique patterns simply resets the cache.
_REGEX_CACHE: Dict[str, Optional['re.Pattern[str]']] = {}

#: Data-pack names already warned about (avoids warning spam per lookup).
_WARNED_PACKS: set = set()

#: (directory, kind) -> loaded pack (or None when loading failed).  Loading
#: is deterministic per location, so caching is safe and keeps repeated
#: ``evaluate_rules`` calls cheap.
_PACK_CACHE: Dict[Tuple[str, str], Optional['RulePack']] = {}

#: Cache for :func:`load_all_packs` (reset by :func:`reset_rule_caches`).
_ALL_PACKS_CACHE: Optional[Dict[str, 'RulePack']] = None


# --------------------------------------------------------------------------- #
# value coercion helpers (all defensive: junk in -> None/'no match' out)
# --------------------------------------------------------------------------- #

def _safe_kind(kind: Any) -> str:
    """
    Normalise a kind name, returning '' when it cannot name a pack.

    Surrounding whitespace is stripped and lowercased; names containing
    path separators or '..' are rejected so a kind can never escape the
    packs directory (same contract as ``utils.data_packs._safe_name``).
    """
    if not isinstance(kind, str):
        return ''
    key = kind.strip().lower()
    if not key or '/' in key or '\\' in key or '..' in key:
        return ''
    return key


def _as_list(value: Any) -> List[Any]:
    """List form of a rule value (scalars become single-item lists)."""
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _to_number(value: Any) -> Optional[float]:
    """Float form of numbers and numeric strings; None for everything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _text(value: Any) -> Optional[str]:
    """String form of a scalar value; None for containers/None/bools."""
    if value is None or isinstance(value, (bool, dict, list, tuple, set)):
        return None
    return str(value)


def _is_empty(value: Any) -> bool:
    """
    Whether a field value counts as "empty".

    ``None``, blank strings, empty containers, an explicit ``False`` and a
    missing field are empty; numbers (including ``0``) are real values.
    """
    if value is MISSING or value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    if isinstance(value, bool):
        return not value
    return False


def _equals(actual: Any, expected: Any) -> bool:
    """Tolerant equality: direct, numeric-string and stripped-text forms."""
    if actual == expected:
        return True
    actual_num, expected_num = _to_number(actual), _to_number(expected)
    if actual_num is not None and expected_num is not None:
        return actual_num == expected_num
    actual_text, expected_text = _text(actual), _text(expected)
    if actual_text is not None and expected_text is not None:
        return actual_text.strip().lower() == expected_text.strip().lower()
    return False


def _membership(actual: Any, expected: Any) -> bool:
    """Case/number-tolerant membership of ``actual`` in the ``expected`` set."""
    return any(_equals(actual, item) for item in _as_list(expected))


def _contains(actual: Any, expected: Any) -> bool:
    """Whether ``actual`` contains ``expected`` (substring, member or key)."""
    actual_text, expected_text = _text(actual), _text(expected)
    if actual_text is not None and expected_text is not None:
        return expected_text.strip().lower() in actual_text.lower()
    if isinstance(actual, (list, tuple, set)):
        return _membership(expected, list(actual))
    if isinstance(actual, dict):
        return any(_equals(key, expected) for key in actual)
    return False


def _flag(value: Any) -> bool:
    """Boolean form of real booleans and common textual flags."""
    if isinstance(value, bool):
        return value
    text = _text(value)
    if text is None:
        return False
    return text.strip().lower() in ('true', 'yes', 'on')


def _is_false_flag(value: Any) -> bool:
    """Whether a value is an explicit falsy flag (False / 'false' / 'no')."""
    if value is False:
        return True
    text = _text(value)
    if text is None:
        return False
    return text.strip().lower() in ('false', 'no', 'off')


def _compile_regex(pattern: Any) -> Optional['re.Pattern[str]']:
    """Compiled pattern, or None when the pattern is not valid ``re`` syntax."""
    text = _text(pattern)
    if text is None:
        return None
    cached = _REGEX_CACHE.get(text)
    if cached is not None:
        return cached
    try:
        compiled = re.compile(text)
    except re.error:
        compiled = None
        EVAL_WARNINGS.append(f'invalid regex pattern in rule value: {text!r}')
    if len(_REGEX_CACHE) > 512:  # keep the cache bounded
        _REGEX_CACHE.clear()
    _REGEX_CACHE[text] = compiled
    return compiled


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Parse a date-ish field value into a naive UTC ``datetime``.

    Accepted inputs: ``datetime`` objects (aware ones are converted to
    UTC), epoch seconds / milliseconds given as numbers or numeric strings
    (values above ``1e11`` are treated as milliseconds), and ISO-8601-ish
    strings (``fromisoformat`` plus a few common formats; a trailing ``Z``
    is tolerated).  Anything else returns ``None`` -- callers treat that
    as "condition does not match".
    """
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    if isinstance(value, bool):
        return None
    number = _to_number(value)
    if number is not None:
        seconds = number / 1000.0 if number > 1e11 else number
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None
    text = _text(value)
    if text is None:
        return None
    candidate = text.strip()
    if candidate.endswith(('Z', 'z')):
        candidate = candidate[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S', '%d %b %Y', '%b %d %Y'):
            try:
                parsed = datetime.strptime(candidate, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _age_days(value: Any) -> Optional[float]:
    """Age in (fractional) days of a parseable date value; None otherwise."""
    parsed = _parse_timestamp(value)
    if parsed is None:
        return None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return (now - parsed).total_seconds() / 86400.0


def _load_pack_entries(name: Any) -> List[str]:
    """
    Entries of a named text data pack (lazy, guarded import).

    The rule engine must stay importable even when the utils package is
    unavailable (e.g. inside frozen executables during early startup), so
    the import is performed lazily and failures degrade to an empty list.
    """
    text = _text(name)
    if text is None:
        return []
    try:
        from ..utils.data_packs import load_data_pack
    except ImportError:
        return []
    return load_data_pack(text.strip())


def _known_in_pack(actual: Any, pack_name: Any) -> bool:
    """
    Whether a field value is listed in a shipped data pack.

    The value is lowercased and, when it is an email address, its domain
    part is used instead; subdomains of a listed entry also match
    (``evil.mailinator.com`` counts for ``mailinator.com``).  An empty or
    missing pack warns once via :data:`EVAL_WARNINGS` and never matches.
    """
    text = _text(actual)
    pack = _text(pack_name)
    if text is None or pack is None:
        return False
    value = text.strip().lower()
    if '@' in value:
        value = value.rsplit('@', 1)[-1]
    entries = _load_pack_entries(pack)
    if not entries:
        key = pack.strip()
        if key not in _WARNED_PACKS:
            _WARNED_PACKS.add(key)
            EVAL_WARNINGS.append(
                f"known_pack references data pack {key!r} which is empty or missing")
        return False
    if value in entries:
        return True
    return any(value.endswith('.' + entry) for entry in entries)


def _in_cidr(actual: Any, cidrs: Any) -> bool:
    """
    Whether an IP field falls inside any of the rule's CIDR networks.

    Host bits in the rule value are tolerated (``strict=False``), invalid
    IPs simply do not match, and an invalid CIDR literal warns via
    :data:`EVAL_WARNINGS` (an authoring bug in the pack).
    """
    text = _text(actual)
    if text is None:
        return False
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    for cidr in _as_list(cidrs):
        literal = _text(cidr)
        if literal is None:
            continue
        try:
            network = ipaddress.ip_network(literal.strip(), strict=False)
        except ValueError:
            EVAL_WARNINGS.append(f'invalid CIDR literal in rule value: {literal!r}')
            continue
        if address.version == network.version and address in network:
            return True
    return False


# --------------------------------------------------------------------------- #
# conditions
# --------------------------------------------------------------------------- #

@dataclass
class Condition:
    """
    One predicate over a field dict.

    Attributes:
        field: dotted path into the field dict (``info.country`` walks one
            nested dict level; plain names address the top level).
        operator: one of :data:`OPERATORS`.
        value: the rule-side operand -- a scalar, list or regex depending
            on the operator.  ``exists`` / ``empty`` style operators ignore
            it (conventionally ``true`` in YAML for readability).
    """

    field: str
    operator: str
    value: Any = None

    def render(self) -> str:
        """Compact human form, e.g. ``info.country == RU``."""
        symbol = _OP_SYMBOLS.get(self.operator, self.operator)
        if self.operator in ('exists', 'not_exists', 'empty', 'not_empty',
                             'is_true', 'is_false'):
            return f'{self.field} {symbol}'
        if self.operator in ('age_lt_days', 'age_gt_days'):
            return f'{self.field} {symbol} {self.value} days'
        return f'{self.field} {symbol} {self.value!r}'

    def explain(self, fields: Dict[str, Any]) -> str:
        """
        Human explanation against a concrete field dict.

        Matching conditions render exactly like :meth:`render`; a
        non-matching one appends the actual value so reports can show why
        a rule did *not* fire.
        """
        base = self.render()
        actual = resolve_field(fields, self.field)
        if evaluate_condition(self, fields):
            return base
        if actual is MISSING:
            return f'{base} (field missing)'
        return f'{base} (actual: {actual!r})'

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly mapping of this condition."""
        return {'field': self.field, 'operator': self.operator, 'value': self.value}


def _resolve_path(fields: Any, path: str) -> Any:
    """
    Walk a dotted path through nested dicts; :data:`MISSING` when absent.

    ``a.b.c`` resolves ``fields['a']['b']['c']``.  Non-dict containers on
    the way (lists, scalars) break the walk and yield ``MISSING``.
    """
    current: Any = fields
    if not isinstance(current, dict):
        return MISSING
    for part in path.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return MISSING
    return current


def resolve_field(fields: Any, path: str) -> Any:
    """
    Resolve a (dotted) field, falling back to the ``info`` block.

    Trackers return payloads of the shape ``{'info': {...}, ...}`` while
    username results are flat; mirroring the pipeline engine, a path that
    misses at the top level is retried as ``info.<path>`` so both shapes
    work with the same pack.
    """
    if not isinstance(fields, dict):
        return MISSING
    value = _resolve_path(fields, path)
    if value is MISSING and not path.startswith('info.'):
        value = _resolve_path(fields, f'info.{path}')
    return value


def _op_eq(actual: Any, value: Any) -> bool:
    return _equals(actual, value)


def _op_neq(actual: Any, value: Any) -> bool:
    return not _equals(actual, value)


def _op_in(actual: Any, value: Any) -> bool:
    return _membership(actual, value)


def _op_not_in(actual: Any, value: Any) -> bool:
    return not _membership(actual, value)


def _op_contains(actual: Any, value: Any) -> bool:
    return _contains(actual, value)


def _op_not_contains(actual: Any, value: Any) -> bool:
    return not _contains(actual, value)


def _op_startswith(actual: Any, value: Any) -> bool:
    actual_text, expected_text = _text(actual), _text(value)
    if actual_text is None or expected_text is None:
        return False
    return actual_text.startswith(expected_text)


def _op_endswith(actual: Any, value: Any) -> bool:
    actual_text, expected_text = _text(actual), _text(value)
    if actual_text is None or expected_text is None:
        return False
    return actual_text.endswith(expected_text)


def _op_regex(actual: Any, value: Any) -> bool:
    compiled = _compile_regex(value)
    if compiled is None:
        return False
    actual_text = _text(actual)
    if actual_text is None:
        return False
    return compiled.search(actual_text) is not None


def _numeric_compare(actual: Any, value: Any,
                     compare: Callable[[float, float], bool]) -> bool:
    actual_num, expected_num = _to_number(actual), _to_number(value)
    if actual_num is None or expected_num is None:
        return False  # non-numeric field (or value) -> no match
    return compare(actual_num, expected_num)


def _op_gt(actual: Any, value: Any) -> bool:
    return _numeric_compare(actual, value, lambda a, b: a > b)


def _op_gte(actual: Any, value: Any) -> bool:
    return _numeric_compare(actual, value, lambda a, b: a >= b)


def _op_lt(actual: Any, value: Any) -> bool:
    return _numeric_compare(actual, value, lambda a, b: a < b)


def _op_lte(actual: Any, value: Any) -> bool:
    return _numeric_compare(actual, value, lambda a, b: a <= b)


def _op_exists(actual: Any, value: Any) -> bool:
    return actual is not MISSING


def _op_not_exists(actual: Any, value: Any) -> bool:
    return actual is MISSING


def _op_empty(actual: Any, value: Any) -> bool:
    return _is_empty(actual)


def _op_not_empty(actual: Any, value: Any) -> bool:
    return not _is_empty(actual)


def _op_is_true(actual: Any, value: Any) -> bool:
    return _flag(actual)


def _op_is_false(actual: Any, value: Any) -> bool:
    return actual is False or _is_false_flag(actual)


def _op_in_cidr(actual: Any, value: Any) -> bool:
    return _in_cidr(actual, value)


def _op_known_pack(actual: Any, value: Any) -> bool:
    return _known_in_pack(actual, value)


def _op_age_lt_days(actual: Any, value: Any) -> bool:
    age = _age_days(actual)
    limit = _to_number(value)
    if age is None or limit is None:
        return False
    return age < limit


def _op_age_gt_days(actual: Any, value: Any) -> bool:
    age = _age_days(actual)
    limit = _to_number(value)
    if age is None or limit is None:
        return False
    return age > limit


#: operator name -> evaluator(actual, value).  Every evaluator returns a
#: bool and never raises; a MISSING actual only matches the operators
#: that explicitly speak about absence or emptiness.
_OPERATOR_FUNCS: Dict[str, Callable[[Any, Any], bool]] = {
    'eq': _op_eq,
    'neq': _op_neq,
    'in': _op_in,
    'not_in': _op_not_in,
    'contains': _op_contains,
    'not_contains': _op_not_contains,
    'startswith': _op_startswith,
    'endswith': _op_endswith,
    'regex': _op_regex,
    'gt': _op_gt,
    'gte': _op_gte,
    'lt': _op_lt,
    'lte': _op_lte,
    'exists': _op_exists,
    'not_exists': _op_not_exists,
    'empty': _op_empty,
    'not_empty': _op_not_empty,
    'is_true': _op_is_true,
    'is_false': _op_is_false,
    'in_cidr': _op_in_cidr,
    'known_pack': _op_known_pack,
    'age_lt_days': _op_age_lt_days,
    'age_gt_days': _op_age_gt_days,
}


def evaluate_condition(condition: Condition, fields: Dict[str, Any]) -> bool:
    """
    Evaluate one condition against a field dict (never raises).

    Unknown operators evaluate to ``False`` and record a warning in
    :data:`EVAL_WARNINGS`; a missing field only matches ``not_exists``
    and ``empty`` semantics.
    """
    func = _OPERATOR_FUNCS.get(condition.operator)
    if func is None:
        EVAL_WARNINGS.append(
            f"unknown operator {condition.operator!r} on field "
            f"{condition.field!r} (condition never matches)")
        return False
    actual = resolve_field(fields, condition.field)
    if actual is MISSING and condition.operator not in ('not_exists', 'empty'):
        # 'empty' treats MISSING as empty; every other operator needs a
        # present field to say anything meaningful.
        return False
    try:
        return bool(func(actual, condition.value))
    except Exception as exc:  # defensive: operator bugs must not kill a run
        EVAL_WARNINGS.append(
            f"operator {condition.operator!r} failed on "
            f"{condition.field!r}: {type(exc).__name__}")
        return False


# --------------------------------------------------------------------------- #
# rules, hits, packs
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    """
    A single explainable rule (all conditions must match -- AND semantics).

    Attributes:
        id: stable pack-unique identifier such as ``DOMAIN-001``.
        kind: pack kind the rule belongs to (``shared`` rules run everywhere).
        title: short headline shown in reports.
        description: 1-3 honest sentences on WHY the signal matters.
        severity: one of :data:`SEVERITIES`.
        weight: contribution to the pack score when the rule fires (0-100).
        conditions: list of :class:`Condition` (all must match).
        tags: free-form labels for filtering (``age``, ``phishing``...).
        references: real technique/context references (MITRE ATT&CK IDs,
            RFCs, best-practice docs).  Omitted when the authors are unsure.
        enabled: disabled rules are skipped during evaluation.
    """

    id: str
    kind: str
    title: str
    description: str = ''
    severity: str = 'medium'
    weight: int = 10
    conditions: List[Condition] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    enabled: bool = True

    def matches(self, fields: Dict[str, Any]) -> bool:
        """Whether every condition matches the field dict."""
        if not self.enabled:
            return False
        return all(evaluate_condition(condition, fields) for condition in self.conditions)

    def explain(self, fields: Dict[str, Any]) -> List[str]:
        """One human string per condition (see :meth:`Condition.explain`)."""
        return [condition.explain(fields) for condition in self.conditions]

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly mapping of this rule."""
        return {
            'id': self.id,
            'kind': self.kind,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'weight': self.weight,
            'conditions': [condition.to_dict() for condition in self.conditions],
            'tags': list(self.tags),
            'references': list(self.references),
            'enabled': self.enabled,
        }


@dataclass
class RuleHit:
    """A rule that matched, with its per-condition explanations and score."""

    rule: Rule
    explanations: List[str] = field(default_factory=list)
    score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly mapping of this hit."""
        return {
            'id': self.rule.id,
            'title': self.rule.title,
            'description': self.rule.description,
            'severity': self.rule.severity,
            'weight': self.rule.weight,
            'score': self.score,
            'tags': list(self.rule.tags),
            'references': list(self.rule.references),
            'explanations': list(self.explanations),
        }


@dataclass
class RulePack:
    """
    All rules shipped for one kind, loaded from ``packs/<kind>.yaml``.

    Attributes:
        kind: the pack kind (``domain``, ``ip``, ``shared``, ...).
        name: human pack name from the YAML ``name`` key.
        description: what the pack covers.
        version: pack version (int or free-form string).
        rules: the parsed :class:`Rule` list in file order.
    """

    kind: str
    name: str = ''
    description: str = ''
    version: Any = 1
    rules: List[Rule] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        """Number of rules in the pack (enabled and disabled alike)."""
        return len(self.rules)

    @property
    def enabled_count(self) -> int:
        """Number of currently enabled rules."""
        return sum(1 for rule in self.rules if rule.enabled)

    def find(self, rule_id: str) -> Optional[Rule]:
        """The rule with the given id, or None."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def evaluate(self, fields: Dict[str, Any]) -> List[RuleHit]:
        """Every enabled rule that matches the field dict, in pack order."""
        hits: List[RuleHit] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.matches(fields):
                hits.append(RuleHit(
                    rule=rule,
                    explanations=rule.explain(fields),
                    score=max(0, min(100, int(rule.weight))),
                ))
        return hits

    def score(self, fields: Dict[str, Any]) -> int:
        """Sum of matching rule weights, capped to the 0-100 range."""
        total = sum(hit.score for hit in self.evaluate(fields))
        return max(0, min(100, total))

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly mapping of the whole pack."""
        return {
            'kind': self.kind,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'rule_count': self.rule_count,
            'rules': [rule.to_dict() for rule in self.rules],
        }


@dataclass
class RuleEvaluation:
    """
    Result of :func:`evaluate_rules`: the hits, the summed score and band.

    ``band`` is derived from ``score`` on construction (leave it empty to
    have it computed): 0-9 clean, 10-29 watch, 30-59 elevated, 60-79 high,
    80-100 critical.
    """

    hits: List[RuleHit] = field(default_factory=list)
    score: int = 0
    band: str = ''
    kind: str = ''

    def __post_init__(self) -> None:
        self.score = max(0, min(100, int(self.score)))
        if not self.band:
            self.band = band_for(self.score)

    @property
    def matched_ids(self) -> List[str]:
        """Ids of every rule that fired, in evaluation order."""
        return [hit.rule.id for hit in self.hits]

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly mapping used by report/export layers."""
        return {
            'kind': self.kind,
            'score': self.score,
            'band': self.band,
            'hits': [hit.to_dict() for hit in self.hits],
        }

    def summary(self) -> str:
        """One-line human summary of the evaluation."""
        if not self.hits:
            return f"{self.kind or 'target'}: no rule matched (score 0, clean)"
        ids = ', '.join(hit.rule.id for hit in self.hits)
        return f"{self.kind or 'target'}: score {self.score} ({self.band}) via {ids}"


def band_for(score: Any) -> str:
    """
    Risk band for a 0-100 score.

    ``< 10`` -> ``clean``; ``10-29`` -> ``watch``; ``30-59`` -> ``elevated``;
    ``60-79`` -> ``high``; ``>= 80`` -> ``critical``.  Non-numeric input is
    treated as 0; the result is always one of :data:`BANDS`.
    """
    number = _to_number(score)
    if number is None:
        return 'clean'
    if number < 10:
        return 'clean'
    if number < 30:
        return 'watch'
    if number < 60:
        return 'elevated'
    if number < 80:
        return 'high'
    return 'critical'


# --------------------------------------------------------------------------- #
# pack loading (tolerant: never raises, warns into LOAD_WARNINGS)
# --------------------------------------------------------------------------- #

def packs_dir() -> Path:
    """Directory with the shipped rule packs (``obscuralens/rules/packs``)."""
    return _PACKS_DIR


def _candidate_dirs(pack_dir: Optional[Union[str, Path]] = None) -> List[Path]:
    """
    Directories to search for pack files, most specific first.

    An explicit ``pack_dir`` wins outright; otherwise the
    ``OBSCURALENS_RULES_DIR`` directories (``os.pathsep``-separated) come
    first and the shipped ``packs/`` folder is appended as a fallback so
    users can override single kinds without losing the rest.
    """
    if pack_dir is not None:
        return [Path(pack_dir)]
    dirs: List[Path] = []
    env_value = os.environ.get(RULES_DIR_ENV, '')
    for item in env_value.split(os.pathsep):
        item = item.strip()
        if item:
            dirs.append(Path(item))
    dirs.append(_PACKS_DIR)
    return dirs


def _pack_file(kind: str, directories: Sequence[Path]) -> Optional[Path]:
    """First existing ``<kind>.yaml`` among the candidate directories."""
    for directory in directories:
        candidate = directory / f'{kind}.yaml'
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _parse_condition(entry: Any, context: str) -> Optional[Condition]:
    """Parse one condition mapping; None + warning when malformed."""
    if not isinstance(entry, dict):
        LOAD_WARNINGS.append(f'{context}: condition is not a mapping ({entry!r})')
        return None
    field_name = entry.get('field')
    operator = entry.get('operator')
    if not isinstance(field_name, str) or not field_name.strip():
        LOAD_WARNINGS.append(f'{context}: condition is missing a field name')
        return None
    if not isinstance(operator, str) or operator not in OPERATORS:
        LOAD_WARNINGS.append(
            f'{context}: unknown operator {operator!r} '
            f'(expected one of {", ".join(OPERATORS)})')
        return None
    return Condition(field=field_name.strip(), operator=operator,
                     value=entry.get('value'))


def _parse_str_list(value: Any, key: str, context: str) -> List[str]:
    """Coerce a YAML tags/references entry into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            text = _text(item)
            if text is not None:
                out.append(text)
            else:
                LOAD_WARNINGS.append(
                    f'{context}: ignoring non-string {key} entry {item!r}')
        return out
    text = _text(value)
    if text is None:
        LOAD_WARNINGS.append(f'{context}: {key} must be a string or list')
        return []
    return [text]


def _parse_rule(entry: Any, kind: str) -> Optional[Rule]:
    """Parse one rule mapping; None + warning when the rule is unusable."""
    if not isinstance(entry, dict):
        LOAD_WARNINGS.append(f'{kind} pack: rule entry is not a mapping ({entry!r})')
        return None
    rule_id = entry.get('id')
    if not isinstance(rule_id, str) or not rule_id.strip():
        LOAD_WARNINGS.append(f'{kind} pack: rule is missing an id ({entry!r})')
        return None
    rule_id = rule_id.strip()
    context = f'{kind} pack rule {rule_id}'
    title = entry.get('title')
    if not isinstance(title, str) or not title.strip():
        LOAD_WARNINGS.append(f'{context}: missing title - rule skipped')
        return None
    severity = entry.get('severity', 'medium')
    if not isinstance(severity, str) or severity.strip().lower() not in SEVERITIES:
        LOAD_WARNINGS.append(
            f'{context}: invalid severity {severity!r} '
            f"(expected one of {', '.join(SEVERITIES)}) - rule skipped")
        return None
    raw_weight = entry.get('weight', 10)
    weight_number = _to_number(raw_weight)
    if weight_number is None:
        LOAD_WARNINGS.append(
            f'{context}: weight {raw_weight!r} is not numeric - using 10')
        weight = 10
    else:
        weight = int(round(weight_number))
        if weight < 0 or weight > 100:
            clamped = max(0, min(100, weight))
            LOAD_WARNINGS.append(
                f'{context}: weight {weight} outside 0-100 clamped to {clamped}')
            weight = clamped
    raw_conditions = entry.get('conditions')
    if not isinstance(raw_conditions, list) or not raw_conditions:
        LOAD_WARNINGS.append(
            f'{context}: needs a non-empty conditions list - rule skipped')
        return None
    conditions: List[Condition] = []
    for number, condition_entry in enumerate(raw_conditions, start=1):
        condition = _parse_condition(
            condition_entry, f'{context} condition #{number}')
        if condition is None:
            # A rule with a broken/unknown condition would silently match
            # too much or too little - skipping the whole rule is safer.
            LOAD_WARNINGS.append(f'{context}: rule skipped due to bad condition')
            return None
        conditions.append(condition)
    return Rule(
        id=rule_id,
        kind=kind,
        title=title.strip(),
        description=str(entry.get('description') or ''),
        severity=severity.strip().lower(),
        weight=weight,
        conditions=conditions,
        tags=_parse_str_list(entry.get('tags'), 'tags', context),
        references=_parse_str_list(entry.get('references'), 'references', context),
        enabled=bool(entry.get('enabled', True)),
    )


def _parse_pack(data: Any, kind: str, source: Path) -> Optional[RulePack]:
    """Parse an already-loaded YAML document into a :class:`RulePack`."""
    if not isinstance(data, dict):
        LOAD_WARNINGS.append(f'{source}: pack document is not a mapping')
        return None
    name = data.get('name')
    if not isinstance(name, str) or not name.strip():
        LOAD_WARNINGS.append(f'{source}: missing pack name - using {kind}-rules')
        name = f'{kind}-rules'
    raw_rules = data.get('rules')
    if not isinstance(raw_rules, list):
        LOAD_WARNINGS.append(f'{source}: "rules" must be a list - pack skipped')
        return None
    declared_kind = data.get('kind')
    pack_kind = declared_kind.strip().lower() if isinstance(
        declared_kind, str) and declared_kind.strip() else kind
    rules: List[Rule] = []
    seen_ids: set = set()
    for entry in raw_rules:
        rule = _parse_rule(entry, pack_kind)
        if rule is None:
            continue
        if rule.id in seen_ids:
            LOAD_WARNINGS.append(f'{source}: duplicate rule id {rule.id} - dropped')
            continue
        seen_ids.add(rule.id)
        rules.append(rule)
    if not rules:
        LOAD_WARNINGS.append(f'{source}: no usable rules - pack skipped')
        return None
    return RulePack(
        kind=pack_kind,
        name=name.strip(),
        description=str(data.get('description') or ''),
        version=data.get('version', 1),
        rules=rules,
    )


def load_pack(kind: str,
              pack_dir: Optional[Union[str, Path]] = None) -> Optional[RulePack]:
    """
    Load the rule pack for a kind.

    The pack file is ``<kind>.yaml`` inside the explicit ``pack_dir``, the
    ``OBSCURALENS_RULES_DIR`` directories or the shipped ``packs/`` folder
    (first hit wins -- see :func:`_candidate_dirs`).  Results are cached
    per (directory, kind); invalid YAML, missing files and unusable pack
    structures return ``None`` and record a warning in
    :data:`LOAD_WARNINGS` -- this function never raises.
    """
    key = _safe_kind(kind)
    if not key:
        return None
    directories = _candidate_dirs(pack_dir)
    cache_key = (str(directories[0]), key)
    if cache_key in _PACK_CACHE:
        return _PACK_CACHE[cache_key]
    pack: Optional[RulePack] = None
    source = _pack_file(key, directories)
    if source is None:
        LOAD_WARNINGS.append(
            f'no rule pack file for kind {key!r} in '
            f'{", ".join(str(directory) for directory in directories)}')
    else:
        try:
            text = source.read_text(encoding='utf-8')
        except (OSError, ValueError) as exc:
            LOAD_WARNINGS.append(f'{source}: cannot read pack ({exc})')
            text = ''
        if text:
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                LOAD_WARNINGS.append(f'{source}: invalid YAML ({exc})')
                data = None
            if data is not None:
                pack = _parse_pack(data, key, source)
    _PACK_CACHE[cache_key] = pack
    return pack


def load_all_packs() -> Dict[str, RulePack]:
    """
    Load every shipped (and user-overridden) pack, keyed by kind.

    The result is cached; call :func:`reset_rule_caches` (mainly useful in
    tests and after changing ``OBSCURALENS_RULES_DIR``) to force a reload.
    Packs that fail to load are absent from the mapping, never None.
    """
    global _ALL_PACKS_CACHE
    if _ALL_PACKS_CACHE is not None:
        return _ALL_PACKS_CACHE
    packs: Dict[str, RulePack] = {}
    for directory in _candidate_dirs():
        try:
            if not directory.is_dir():
                continue
            candidates = sorted(directory.glob('*.yaml'))
        except OSError:
            continue
        for source in candidates:
            if not source.is_file():
                continue
            key = _safe_kind(source.stem)
            if not key or key in packs:
                continue  # earlier directories win; each kind stays unique
            pack = load_pack(key)
            if pack is not None:
                packs[key] = pack
    _ALL_PACKS_CACHE = packs
    return packs


def reset_rule_caches() -> None:
    """Clear the pack caches (warnings already recorded stay untouched)."""
    global _ALL_PACKS_CACHE
    _PACK_CACHE.clear()
    _ALL_PACKS_CACHE = None


def evaluate_rules(kind: str, fields: Dict[str, Any]) -> RuleEvaluation:
    """
    Evaluate the kind's pack plus the ``shared`` pack against a field dict.

    The shared pack runs for every kind (``shared`` itself only runs once)
    and hits are merged by rule id -- a kind pack rule always wins over a
    shared rule that somehow reuses its id.  The score is the sum of all
    matching rule weights capped at 100; the band follows
    :func:`band_for`.  Unknown kinds or non-dict field input still return
    a well-formed (empty) evaluation -- this function never raises.
    """
    key = _safe_kind(kind) or 'shared'
    if not isinstance(fields, dict):
        return RuleEvaluation(hits=[], score=0, band='clean', kind=key)
    packs: List[RulePack] = []
    if key != 'shared':
        shared = load_pack('shared')
        if shared is not None:
            packs.append(shared)
    own = load_pack(key)
    if own is not None:
        packs.append(own)
    hits: List[RuleHit] = []
    seen: set = set()
    for pack in packs:
        for hit in pack.evaluate(fields):
            if hit.rule.id in seen:
                continue
            seen.add(hit.rule.id)
            hits.append(hit)
    score = max(0, min(100, sum(hit.score for hit in hits)))
    return RuleEvaluation(hits=hits, score=score, kind=key)


def rules_summary() -> str:
    """
    Pretty one-screen table of every loaded pack and its rule counts.

    Intended for ``obscuralens rules list`` style CLI output and debug
    logging; pack loading problems surface as a trailing warning block.
    """
    packs = load_all_packs()
    headers = ('kind', 'pack name', 'version', 'rules', 'enabled')
    rows: List[Tuple[str, str, str, str, str]] = []
    for kind in sorted(packs):
        pack = packs[kind]
        rows.append((pack.kind, pack.name, str(pack.version),
                     str(pack.rule_count), str(pack.enabled_count)))
    widths = []
    for index, header in enumerate(headers):
        width = len(header)
        for row in rows:
            width = max(width, len(row[index]))
        widths.append(width)
    lines = ['Rule packs loaded from ' + ', '.join(
        str(directory) for directory in _candidate_dirs())]
    lines.append('  '.join(header.ljust(widths[index])
                           for index, header in enumerate(headers)))
    lines.append('  '.join('-' * width for width in widths))
    for row in rows:
        lines.append('  '.join(cell.ljust(widths[index])
                               for index, cell in enumerate(row)))
    lines.append(f'{len(packs)} pack(s), {sum(int(row[3]) for row in rows)} rule(s) total')
    if LOAD_WARNINGS:
        lines.append('')
        lines.append(f'load warnings ({len(LOAD_WARNINGS)}):')
        lines.extend(f'  - {warning}' for warning in LOAD_WARNINGS[-10:])
    return '\n'.join(lines)


def merge_pack_dicts(base: Optional[Dict[str, Any]],
                     override: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge two pack dicts (YAML-level) for user-supplied rule overrides.

    ``override`` wins for every top-level key it defines.  Rules are merged
    by ``id``: an override rule replaces the base rule with the same id in
    place, and brand-new override rules are appended in their file order.
    Neither input is mutated; the returned mapping is a shallow copy with
    copied rule dicts, safe to hand to :func:`_parse_pack` or to dump as
    YAML.  This helper exists so the docs and the future ``rules override``
    CLI can describe user packs without re-implementing merge semantics.

    Example::

        merged = merge_pack_dicts(load_yaml('packs/domain.yaml'),
                                  {'rules': [{'id': 'DOMAIN-001',
                                              'weight': 30}]})
    """
    merged: Dict[str, Any] = dict(base or {})
    if not override:
        return merged
    for key, value in override.items():
        if key != 'rules' and value is not None:
            merged[key] = value
    base_rules = merged.get('rules') if isinstance(merged.get('rules'), list) else []
    override_rules = (override.get('rules')
                      if isinstance(override.get('rules'), list) else [])
    override_by_id: Dict[str, Dict[str, Any]] = {}
    for entry in override_rules:
        if isinstance(entry, dict) and isinstance(entry.get('id'), str):
            override_by_id[entry['id'].strip()] = dict(entry)
    merged_rules: List[Any] = []
    replaced: set = set()
    for entry in base_rules:
        if isinstance(entry, dict) and isinstance(entry.get('id'), str):
            rule_id = entry['id'].strip()
            if rule_id in override_by_id:
                merged_rules.append(override_by_id[rule_id])
                replaced.add(rule_id)
                continue
        merged_rules.append(entry)
    for entry in override_rules:
        if isinstance(entry, dict) and isinstance(entry.get('id'), str):
            if entry['id'].strip() not in replaced:
                merged_rules.append(dict(entry))
                replaced.add(entry['id'].strip())
        else:
            merged_rules.append(entry)
    merged['rules'] = merged_rules
    return merged
