"""pySigma's built-in rule validators (structure, conditions, tags, modifiers)."""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

from detection_platform.attack import ATTACK_VERSION, pin_pysigma_attack_data
from tests.conftest import DETECTIONS_DIR

pin_pysigma_attack_data()

# These download MITRE / other taxonomies at runtime.
NETWORK_VALIDATORS = {"attacktag", "cartag", "d3_fendtag", "stptag"}

COLLECTION = SigmaCollection.load_ruleset([DETECTIONS_DIR])


def _issues(names):
    v = SigmaValidator([validators[n] for n in names])
    issues = v.validate_rules(COLLECTION)
    return [f"{type(i).__name__}: {[r.title for r in i.rules]}" for i in issues]


def test_offline_sigma_validators_pass():
    assert not _issues(sorted(set(validators) - NETWORK_VALIDATORS))


@pytest.mark.network
def test_attack_tags_are_valid():
    """Tags must be valid in the pinned ATT&CK release (see detection_platform.attack)."""
    issues = _issues(["attacktag"])
    assert not issues, f"Invalid for ATT&CK {ATTACK_VERSION}: {issues}"
