"""
Render validation results as a MITRE ATT&CK Navigator layer.

Reporting language (ADR-0005): a coloured technique means "a selected
behaviour mapped to this technique was validated / missed / not tested",
never "this technique is covered". Simulated runs are labelled as such in
the layer name and description so they cannot be mistaken for evidence.

Layer format: https://github.com/mitre-attack/attack-navigator (layer v4.5)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

Status = Literal["detected", "missed", "untested"]

COLORS: dict[Status, str] = {"detected": "#3cb371", "missed": "#c0392b", "untested": "#95a5a6"}
SCORES: dict[Status, int] = {"detected": 100, "missed": 0, "untested": 50}


def build_layer(
    results: dict[str, Status], name: str, description: str, simulated: bool = False
) -> dict:
    techniques = [
        {
            "techniqueID": technique_id,
            "color": COLORS[status],
            "score": SCORES[status],
            "comment": status,
            "enabled": True,
            "showSubtechniques": False,
        }
        for technique_id, status in sorted(results.items())
    ]
    detected = sum(1 for s in results.values() if s == "detected")
    summary = f"{detected}/{len(results)} selected ATT&CK-mapped behaviours detected"
    if simulated:
        name = f"SIMULATED - {name}"
        summary = f"SIMULATED DATA, NOT VALIDATION EVIDENCE. {summary}"
    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{summary}. {description}".strip(),
        "techniques": techniques,
        "legendItems": [
            {"label": "Behaviour detected", "color": COLORS["detected"]},
            {"label": "Behaviour missed", "color": COLORS["missed"]},
            {"label": "Not tested", "color": COLORS["untested"]},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "sorting": 0,
    }


def write_layer(
    results: dict[str, Status],
    out_path: Path,
    name: str = "Detection Validation",
    description: str = "",
    simulated: bool = False,
) -> Path:
    layer = build_layer(results, name=name, description=description, simulated=simulated)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(layer, indent=2) + "\n")
    return out_path
