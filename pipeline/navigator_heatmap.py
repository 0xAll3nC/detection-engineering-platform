"""
navigator_heatmap.py
---------------------
Converts purple team run results (technique_id -> "detected" / "missed" /
"untested") into a MITRE ATT&CK Navigator layer JSON file. Drag-and-drop
the output onto https://mitre-attack.github.io/attack-navigator/ to get a
visual coverage heatmap -- this is the artifact that makes detection gaps
obvious at a glance in a portfolio README or an interview conversation.

Layer format reference: https://github.com/mitre-attack/attack-navigator
(navigator layer schema v4.5)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

Status = Literal["detected", "missed", "untested"]

COLORS: dict[Status, str] = {
    "detected": "#3cb371",  # green
    "missed": "#c0392b",  # red
    "untested": "#95a5a6",  # grey
}

SCORES: dict[Status, int] = {
    "detected": 100,
    "missed": 0,
    "untested": 50,
}


def build_layer(
    results: dict[str, Status],
    name: str = "Detection Engineering Coverage",
    description: str = "",
) -> dict:
    techniques = []
    for technique_id, status in sorted(results.items()):
        techniques.append(
            {
                "techniqueID": technique_id,
                "color": COLORS[status],
                "score": SCORES[status],
                "comment": status,
                "enabled": True,
                "showSubtechniques": False,
            }
        )

    detected = sum(1 for s in results.values() if s == "detected")
    total = len(results)

    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description or f"{detected}/{total} tested techniques detected",
        "techniques": techniques,
        "legendItems": [
            {"label": "Detected", "color": COLORS["detected"]},
            {"label": "Missed", "color": COLORS["missed"]},
            {"label": "Untested", "color": COLORS["untested"]},
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
    name: str = "Detection Engineering Coverage",
    description: str = "",
) -> Path:
    layer = build_layer(results, name=name, description=description)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(layer, indent=2))
    return out_path
