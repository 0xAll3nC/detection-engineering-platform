"""Repository-relative default locations.

The package is used from a repository checkout (detections, mappings and
fixtures are repository content, not package data). Every path can be
overridden on the CLI.
"""

from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    env = os.environ.get("DETPLAT_REPO_ROOT")
    if env:
        return Path(env).resolve()
    here = Path.cwd().resolve()
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "detections").is_dir():
            return candidate
    return here


ROOT = repo_root()
DETECTIONS_DIR = ROOT / "detections"
VALIDATION_MAPPINGS = ROOT / "validation" / "mappings.yml"
BUILD_DIR = ROOT / "build"
COMPILED_DIR = BUILD_DIR / "compiled"
RESULTS_DIR = BUILD_DIR / "results"
