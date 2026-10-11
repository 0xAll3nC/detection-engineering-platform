"""Compiled-query snapshot tests.

tests/snapshots/compiled/<rule-id>.lucene holds the reviewed compiler output
for each rule. A mismatch is not automatically wrong - a rule edit, mapping
edit or pySigma upgrade legitimately changes queries - but it must be
reviewed: regenerate with `make snapshots` and the change appears as a diff
in the PR.
"""

from __future__ import annotations

import re

import pytest

from detection_platform.sigma.compiler import compile_rules, load_field_mapping
from tests.conftest import DETECTIONS_DIR, RULES, SNAPSHOT_DIR

COMPILED = {c.rule_id: c for c in compile_rules(DETECTIONS_DIR)}


def test_all_rules_compile():
    assert set(COMPILED) == {r.rule_id for r in RULES}


@pytest.mark.parametrize("rule_id", sorted(COMPILED))
def test_compiled_query_matches_reviewed_snapshot(rule_id):
    snapshot = SNAPSHOT_DIR / f"{rule_id}.lucene"
    assert snapshot.exists(), f"No snapshot for {rule_id}; run `make snapshots` and review"
    assert COMPILED[rule_id].query == snapshot.read_text().strip(), (
        f"Compiled query for {COMPILED[rule_id].title} changed. If intended, run "
        "`make snapshots` and review the diff in the PR."
    )


def test_no_orphan_snapshots():
    orphans = {p.stem for p in SNAPSHOT_DIR.glob("*.lucene")} - set(COMPILED)
    assert not orphans, f"Snapshots for rules that no longer exist: {sorted(orphans)}"


@pytest.mark.parametrize("rule_id", sorted(COMPILED))
def test_compiled_query_uses_only_mapped_fields(rule_id):
    """No Sigma-native field name may survive compilation unmapped."""
    query = COMPILED[rule_id].query
    for sigma_field in load_field_mapping():
        assert not re.search(rf"(^|[\s(]){re.escape(sigma_field)}:", query), sigma_field
