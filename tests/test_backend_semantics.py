"""
test_backend_semantics.py
-------------------------
Backend-semantics tests: how compiled rules behave on the *target backend*
(Wazuh indexer / OpenSearch), as opposed to what Sigma says a rule should
match (tests/test_rules.py).

These are deliberately separate. A rule fixture states intended Sigma
behaviour and never changes to accommodate a backend limitation. When the
backend diverges from Sigma semantics, the divergence is recorded here as a
strict xfail linked to the evidence, so:
  - CI stays green while the gap is known and tracked;
  - fixing the gap makes the xfail pass unexpectedly, which (strict=True)
    fails CI until the marker is removed - the gap cannot close silently.

Backend model: compiled OpenSearch Lucene wildcards run against
data.win.eventdata.* fields mapped as `keyword` with no normalizer, so
matching is case-sensitive. Confirmed live on 2026-10-11, see
docs/validation/2026-10-11-phase3-recon-tuning.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pipeline"))
from sigma_evaluator import SigmaRule  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RECON_RULE = SigmaRule.load(REPO_ROOT / "rules" / "windows" / "discovery_account_recon.yml")

WHOAMI = "C:\\Windows\\System32\\whoami.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"


def test_backend_model_reproduces_live_lowercase_detection():
    """Live 2026-10-11: lowercase `whoami /all` was DETECTED in wazuh-archives-*."""
    event = {"Image": WHOAMI, "CommandLine": "whoami  /all", "ParentImage": CMD}
    assert RECON_RULE.matches(event, case_sensitive=True)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known DETECTION_GAP: compiled Lucene wildcards are case-sensitive on "
        "Wazuh keyword fields, so `WHOAMI /ALL` (telemetry present) is not "
        "matched. Live-confirmed 2026-10-11; see "
        "docs/validation/2026-10-11-phase3-recon-tuning.md"
    ),
)
def test_uppercase_recon_command_matches_on_wazuh_backend():
    event = {"Image": WHOAMI, "CommandLine": "WHOAMI  /ALL", "ParentImage": CMD}
    assert RECON_RULE.matches(event, case_sensitive=True)
