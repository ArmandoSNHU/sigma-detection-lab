"""Tests that every bundled YAML rule loads and is well formed."""

from pathlib import Path

import pytest

from sigmalab.rule import Rule, load_rules

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def _rules():
    return load_rules(RULES_DIR)


def test_rules_directory_is_not_empty():
    rules = _rules()
    assert len(rules) == 3


@pytest.mark.parametrize("rule", _rules(), ids=lambda r: r.title)
def test_rule_has_required_fields(rule: Rule):
    assert rule.title
    assert rule.level in VALID_LEVELS
    assert rule.attack_id is not None
    assert rule.attack_id.startswith("T")
    assert rule.selections, "rule must define at least one selection"
    assert rule.condition, "rule must define a condition"


def test_expected_techniques_are_present():
    techniques = {rule.attack_id for rule in _rules()}
    assert {"T1110", "T1059.001", "T1136.001"} <= techniques
