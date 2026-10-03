"""
Explainable rule packs for ObscuraLens (v5.1).

The :mod:`obscuralens.rules` package turns OSINT triage heuristics into
YAML data so analysts can read, audit and override the exact criteria an
investigation is scored with.  It complements
:mod:`obscuralens.correlation.risk` (weighted code signals) with packs of
human-reviewable rules::

    from obscuralens.rules import evaluate_rules, rules_summary

    evaluation = evaluate_rules('domain', payload)
    for hit in evaluation.hits:
        print(hit.rule.id, hit.rule.title, hit.explanations)
    print(evaluation.score, evaluation.band)   # 0-100, clean..critical

Packs live in ``obscuralens/rules/packs/<kind>.yaml`` (one per target
kind plus the always-evaluated ``shared`` pack); user directories can be
injected via the ``OBSCURALENS_RULES_DIR`` environment variable.  Loading
is tolerant -- a broken pack is skipped with a warning, never an
exception -- and every rule explains itself with plain-language
conditions such as ``registration.age_days <= 30``.

Like the rest of ObscuraLens, these rules describe *technical
indicators*, not people: they are triage aids for analysts, not
verdicts.
"""

from .engine import (
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

__all__ = [
    'BANDS',
    'EVAL_WARNINGS',
    'LOAD_WARNINGS',
    'OPERATORS',
    'SEVERITIES',
    'Condition',
    'Rule',
    'RuleEvaluation',
    'RuleHit',
    'RulePack',
    'band_for',
    'evaluate_condition',
    'evaluate_rules',
    'load_all_packs',
    'load_pack',
    'merge_pack_dicts',
    'packs_dir',
    'reset_rule_caches',
    'resolve_field',
    'rules_summary',
]
