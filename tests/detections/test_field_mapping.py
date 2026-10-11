"""Every field a rule references must be mapped to a Wazuh indexed field.

An unmapped field passes through pySigma unchanged (e.g. `Image` instead of
`data.win.eventdata.image`) and compiles to a query that can never match on
the indexer - a silent, always-missed detection.
"""

from __future__ import annotations

from detection_platform.sigma.compiler import load_field_mapping
from tests.conftest import RULES


def test_every_rule_field_is_mapped():
    mapping = load_field_mapping()
    unmapped = {f"{r.path.name}:{f}" for r in RULES for f in r.fields if f not in mapping}
    assert not unmapped, f"Fields with no Wazuh mapping: {sorted(unmapped)}"


def test_mapping_targets_are_wazuh_windows_fields():
    for sigma_field, target in load_field_mapping().items():
        assert target.startswith(("data.win.eventdata.", "data.win.system.")), sigma_field
