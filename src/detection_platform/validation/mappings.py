"""Load and check validation/mappings.yml (rule id -> validation mechanism)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

KNOWN_MECHANISMS = {"atomic"}


@dataclass(frozen=True)
class ValidationMapping:
    rule_id: str
    rule: str
    mechanism: str
    technique: str
    verified: bool
    atomic_guid: str | None = None
    atomic_test_numbers: list[int] = field(default_factory=list)
    notes: str = ""


def load_mappings(path: Path) -> dict[str, ValidationMapping]:
    raw: dict[str, Any] = yaml.safe_load(path.read_text())
    if raw.get("schema_version") != 1:
        raise ValueError(f"{path}: unsupported schema_version {raw.get('schema_version')!r}")
    out = {}
    for rule_id, m in (raw.get("mappings") or {}).items():
        atomic = m.get("atomic") or {}
        out[str(rule_id)] = ValidationMapping(
            rule_id=str(rule_id),
            rule=m["rule"],
            mechanism=m["mechanism"],
            technique=m["technique"],
            verified=bool(m.get("verified", False)),
            atomic_guid=atomic.get("guid"),
            atomic_test_numbers=list(atomic.get("test_numbers") or []),
            notes=m.get("notes", ""),
        )
    return out
