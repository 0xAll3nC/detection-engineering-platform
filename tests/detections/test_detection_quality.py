"""
Detection quality gates: the machine-checkable parts of
docs/DEFINITION_OF_DONE.md. Items that need human judgement (baseline
review, operational readiness) are reviewer checklist items in the PR
template, not tests.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter

import pytest

from detection_platform.validation.mappings import KNOWN_MECHANISMS, load_mappings
from tests.conftest import (
    DETECTION_FIXTURES_DIR,
    DETECTIONS_DIR,
    REPO_ROOT,
    RULES,
    VALIDATION_MAPPINGS,
)

REQUIRED_FIELDS = {
    "title", "id", "status", "description", "references", "author", "date",
    "logsource", "detection", "falsepositives", "level", "tags",
}  # fmt: skip
STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
PROMOTED = {"test", "stable"}

MAPPINGS = load_mappings(VALIDATION_MAPPINGS)
VALIDATION_RECORDS = list((REPO_ROOT / "docs" / "validation").glob("*.md"))

rule_param = pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)


@rule_param
def test_required_metadata_present(rule):
    missing = REQUIRED_FIELDS - rule.raw.keys()
    assert not missing, f"missing metadata: {sorted(missing)}"
    for key in ("references", "falsepositives", "tags"):
        assert rule.raw[key], f"{key} must not be empty"


@rule_param
def test_status_and_level_are_valid(rule):
    assert rule.status in STATUSES
    assert rule.raw["level"] in LEVELS


@rule_param
def test_id_is_uuid(rule):
    uuid.UUID(rule.rule_id)


def test_ids_titles_and_filenames_are_unique():
    for key, values in {
        "id": [r.rule_id for r in RULES],
        "title": [r.title for r in RULES],
        "filename": [r.path.stem for r in RULES],
    }.items():
        dupes = [v for v, n in Counter(values).items() if n > 1]
        assert not dupes, f"duplicate {key}: {dupes}"


def test_rules_live_under_a_platform_directory():
    for r in RULES:
        rel = r.path.relative_to(DETECTIONS_DIR)
        assert len(rel.parts) == 3, f"{rel}: expected <platform>/<tactic>/<rule>.yml"


def test_no_orphan_fixture_files():
    stems = {r.path.stem for r in RULES}
    orphans = {p.stem for p in DETECTION_FIXTURES_DIR.glob("*.json")} - stems
    assert not orphans, f"fixtures with no rule: {sorted(orphans)}"


@rule_param
def test_every_filter_has_a_regression_fixture(rule):
    """A tuned false-positive filter must be pinned by a negative fixture it excludes."""
    cases = json.loads((DETECTION_FIXTURES_DIR / f"{rule.path.stem}.json").read_text())
    from detection_platform.sigma.evaluator import _match_selection

    for name, spec in rule.selections.items():
        if not name.startswith("filter"):
            continue
        assert any(not c["should_match"] and _match_selection(c["event"], spec) for c in cases), (
            f"{name} has no negative fixture that exercises it"
        )


# --- validation mapping gates ------------------------------------------------


@rule_param
def test_rule_has_a_validation_mapping(rule):
    m = MAPPINGS.get(rule.rule_id)
    assert m is not None, "add an entry to validation/mappings.yml"
    assert m.rule == rule.path.stem
    assert m.mechanism in KNOWN_MECHANISMS
    assert m.technique in rule.attack_techniques, "mapped technique must be one of the rule's tags"


def test_no_orphan_validation_mappings():
    orphans = set(MAPPINGS) - {r.rule_id for r in RULES}
    assert not orphans, f"mappings for unknown rules: {sorted(orphans)}"


@rule_param
def test_promoted_rules_have_verified_live_validation(rule):
    """`test`/`stable` require a verified mapping, a pinned Atomic GUID when the
    mechanism is Atomic Red Team, and a validation record naming the rule."""
    if rule.status not in PROMOTED:
        pytest.skip(f"status {rule.status}: live validation not yet required")
    m = MAPPINGS[rule.rule_id]
    assert m.verified, "validation mapping is not verified"
    if m.mechanism == "atomic":
        assert m.atomic_guid, "Atomic validation requires a pinned auto_generated_guid"
    assert any(rule.rule_id in p.read_text() for p in VALIDATION_RECORDS), (
        "no docs/validation record references this rule id"
    )
