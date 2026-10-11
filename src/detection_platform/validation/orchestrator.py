"""
Purple-team validation orchestrator.

Status: Phase 4 scaffold. The live path executes the mapped Atomic test,
waits a fixed interval and checks whether the compiled query matched in
wazuh-archives-*. It does not yet poll, measure latency, verify execution, or
classify failures (EXECUTION_FAILURE / TELEMETRY_GAP / INGESTION_GAP /
DETECTION_GAP / DETECTED, ADR-0004) - that is the Phase 4 deliverable.

Modes:
  live      Executes atomics on the victim and queries the Wazuh indexer.
            Refuses mappings with verified: false unless allow_unverified.
  simulate  Uses a fixture results file to exercise reporting end to end with
            no infrastructure. Output is labelled SIMULATED.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from detection_platform.sigma.evaluator import load_rules
from detection_platform.validation.mappings import load_mappings

INGESTION_WAIT_SECONDS = 20


def run_live(
    detections_dir: Path,
    mappings_path: Path,
    compiled_dir: Path,
    allow_unverified: bool = False,
) -> dict[str, str]:
    from detection_platform.execution.atomic_winrm import AtomicRunner
    from detection_platform.siem.wazuh import WazuhClient

    rules = load_rules(detections_dir)
    mappings = load_mappings(mappings_path)
    atomic = AtomicRunner()
    wazuh = WazuhClient()
    results: dict[str, str] = {}

    for rule in rules:
        mapping = mappings.get(rule.rule_id)
        if mapping is None or mapping.mechanism != "atomic":
            print(f"[SKIP] {rule.title}: no atomic validation mapping")
            continue
        technique = mapping.technique
        if not mapping.verified and not allow_unverified:
            print(f"[SKIP] {rule.title}: mapping not verified (use --allow-unverified)")
            results[technique] = "untested"
            continue
        query_path = compiled_dir / f"{rule.rule_id}.lucene"
        if not query_path.exists():
            print(f"[SKIP] {rule.title}: no compiled query - run `detplat compile` first")
            results[technique] = "untested"
            continue
        query = query_path.read_text().strip()

        tests = mapping.atomic_test_numbers or None
        print(f"[RUN] {rule.title} -> {technique} test(s) {tests}")
        start = datetime.now(UTC)
        try:
            atomic.run_technique(technique, tests)
            print(f"      waiting {INGESTION_WAIT_SECONDS}s for ingestion...")
            time.sleep(INGESTION_WAIT_SECONDS)
            end = datetime.now(UTC) + timedelta(seconds=5)
            matched = wazuh.query_matched(query, start, end)
            results[technique] = "detected" if matched else "missed"
            print(f"      -> {results[technique]}")
        finally:
            atomic.cleanup_technique(technique, tests)

    return results


def load_simulated(results_file: Path) -> dict[str, str]:
    raw = json.loads(results_file.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}
