"""
test_rules.py
-------------
Unit tests for every Sigma rule under rules/windows/, driven by
JSON fixtures in tests/fixtures/<rule_filename_stem>.json.

Each fixture file is a list of:
    {"description": str, "should_match": bool, "event": {...}}

Run with:  pytest -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pipeline"))
from sigma_evaluator import load_rules  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "windows"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

rules = load_rules(RULES_DIR)


def _fixture_cases():
    """Yield (rule, case_dict) for every rule that has a fixture file."""
    for rule in rules:
        fixture_path = FIXTURES_DIR / f"{rule.path.stem}.json"
        if not fixture_path.exists():
            continue
        cases = json.loads(fixture_path.read_text())
        for case in cases:
            yield pytest.param(rule, case, id=f"{rule.path.stem}::{case['description']}")


@pytest.mark.parametrize("rule,case", list(_fixture_cases()))
def test_rule_against_fixture(rule, case):
    result = rule.matches(case["event"])
    assert result == case["should_match"], (
        f"Rule '{rule.title}' ({rule.path.name}) expected match={case['should_match']} "
        f"for case '{case['description']}' but got {result}"
    )


def test_every_rule_has_a_fixture_file():
    """Guardrail: a rule with no test fixtures is an untested detection."""
    missing = [
        rule.path.name
        for rule in rules
        if not (FIXTURES_DIR / f"{rule.path.stem}.json").exists()
    ]
    assert not missing, f"Rules missing test fixtures: {missing}"


def test_every_rule_has_at_least_one_positive_and_negative_case():
    for rule in rules:
        fixture_path = FIXTURES_DIR / f"{rule.path.stem}.json"
        cases = json.loads(fixture_path.read_text())
        positives = [c for c in cases if c["should_match"]]
        negatives = [c for c in cases if not c["should_match"]]
        assert positives, f"{rule.path.name} has no positive (should-match) fixture"
        assert negatives, f"{rule.path.name} has no negative (should-not-match) fixture"


def test_every_rule_has_an_attack_technique_tag():
    for rule in rules:
        assert rule.attack_techniques, f"{rule.path.name} has no attack.tNNNN tag"
