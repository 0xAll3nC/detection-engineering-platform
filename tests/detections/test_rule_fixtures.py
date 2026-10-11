"""
Rule fixture tests: intended Sigma behaviour of every detection.

Each rule `detections/**/<stem>.yml` has `tests/fixtures/detections/<stem>.json`,
a list of {"description": str, "should_match": bool, "event": {...}}.
Fixtures state what a rule SHOULD match under Sigma semantics; backend
limitations are never encoded here (see tests/backend/).
"""

from __future__ import annotations

import json

import pytest

from tests.conftest import DETECTION_FIXTURES_DIR, RULES


def _fixture_cases():
    for rule in RULES:
        fixture_path = DETECTION_FIXTURES_DIR / f"{rule.path.stem}.json"
        if not fixture_path.exists():
            continue
        for case in json.loads(fixture_path.read_text()):
            yield pytest.param(rule, case, id=f"{rule.path.stem}::{case['description']}")


@pytest.mark.parametrize(("rule", "case"), list(_fixture_cases()))
def test_rule_against_fixture(rule, case):
    result = rule.matches(case["event"])
    assert result == case["should_match"], (
        f"Rule '{rule.title}' ({rule.path.name}) expected match={case['should_match']} "
        f"for case '{case['description']}' but got {result}"
    )


def test_every_rule_has_a_fixture_file():
    """Guardrail: a rule with no test fixtures is an untested detection."""
    missing = [
        r.path.name for r in RULES if not (DETECTION_FIXTURES_DIR / f"{r.path.stem}.json").exists()
    ]
    assert not missing, f"Rules missing test fixtures: {missing}"


def test_every_rule_has_at_least_one_positive_and_negative_case():
    for rule in RULES:
        cases = json.loads((DETECTION_FIXTURES_DIR / f"{rule.path.stem}.json").read_text())
        assert any(c["should_match"] for c in cases), f"{rule.path.name}: no positive fixture"
        assert any(not c["should_match"] for c in cases), f"{rule.path.name}: no negative fixture"


def test_every_rule_has_an_attack_technique_tag():
    for rule in RULES:
        assert rule.attack_techniques, f"{rule.path.name} has no attack.tNNNN tag"
