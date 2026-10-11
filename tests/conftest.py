from __future__ import annotations

from pathlib import Path

import pytest

from detection_platform.sigma.evaluator import SigmaRule, load_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
DETECTION_FIXTURES_DIR = FIXTURES_DIR / "detections"
SNAPSHOT_DIR = REPO_ROOT / "tests" / "snapshots" / "compiled"
VALIDATION_MAPPINGS = REPO_ROOT / "validation" / "mappings.yml"

RULES: list[SigmaRule] = load_rules(DETECTIONS_DIR)


@pytest.fixture(scope="session")
def rules() -> list[SigmaRule]:
    return RULES


def rule_by_stem(stem: str) -> SigmaRule:
    return next(r for r in RULES if r.path.stem == stem)
