"""
purple_team_runner.py
----------------------
Ties atomic_runner.py + wazuh_client.py + navigator_heatmap.py together:
for each detection rule, runs the mapped Atomic Red Team test on the
Windows victim, waits for log ingestion, checks the Wazuh indexer for a
matching alert in that time window, and records detected/missed. Ends by
writing a MITRE ATT&CK Navigator coverage heatmap.

Two modes:
  --live       Actually executes atomics against a real victim VM and
               queries a real Wazuh indexer. Requires ATOMIC_VICTIM_* and
               WAZUH_INDEXER_* environment variables (see atomic_runner.py
               / wazuh_client.py for the exact names).
  --simulate   No live infra needed. Uses pipeline/simulated_results.json
               fixture data to exercise the full reporting + heatmap
               pipeline end to end. Used in CI
               (.github/workflows/detection-ci.yml) and for demoing the
               pipeline's plumbing before the lab is fully wired up.

Usage:
    python pipeline/purple_team_runner.py --simulate
    python pipeline/purple_team_runner.py --live
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "pipeline"))

from navigator_heatmap import write_layer  # noqa: E402
from sigma_evaluator import load_rules  # noqa: E402

RULES_DIR = REPO_ROOT / "rules" / "windows"
TECHNIQUE_MAP_PATH = REPO_ROOT / "pipeline" / "technique_test_map.yml"
COMPILED_DIR = REPO_ROOT / "pipeline" / "compiled"
SIMULATED_RESULTS_PATH = REPO_ROOT / "pipeline" / "simulated_results.json"

INGESTION_WAIT_SECONDS = 20  # buffer for log to travel agent -> manager -> indexer


def load_technique_map() -> dict:
    import yaml

    return yaml.safe_load(TECHNIQUE_MAP_PATH.read_text())


def run_live(args) -> dict[str, str]:
    from atomic_runner import AtomicRunner
    from wazuh_client import WazuhClient

    rules = load_rules(RULES_DIR)
    technique_map = load_technique_map()
    atomic = AtomicRunner()
    wazuh = WazuhClient()

    results: dict[str, str] = {}

    for rule in rules:
        if not rule.attack_techniques:
            continue
        technique_id = rule.attack_techniques[0]  # primary technique for this rule
        mapping = technique_map.get(technique_id)
        if not mapping:
            print(f"[SKIP] {rule.title}: no technique_test_map entry for {technique_id}")
            results[technique_id] = "untested"
            continue

        compiled_query_path = COMPILED_DIR / f"{rule.title.lower().replace(' ', '_')}.lucene"
        if not compiled_query_path.exists():
            print(f"[SKIP] {rule.title}: no compiled query found - run compile_rules.py first")
            results[technique_id] = "untested"
            continue
        query = compiled_query_path.read_text().strip()

        print(f"[RUN] {rule.title} -> {technique_id} test(s) {mapping['test_numbers']}")
        start_time = datetime.now(timezone.utc)
        atomic.run_technique(technique_id, mapping["test_numbers"])
        print(f"      waiting {INGESTION_WAIT_SECONDS}s for log ingestion...")
        time.sleep(INGESTION_WAIT_SECONDS)
        end_time = datetime.now(timezone.utc) + timedelta(seconds=5)

        detected = wazuh.rule_fired(query, start_time, end_time)
        results[technique_id] = "detected" if detected else "missed"
        print(f"      -> {results[technique_id]}")

        atomic.cleanup_technique(technique_id, mapping["test_numbers"])

    return results


def run_simulate() -> dict[str, str]:
    """Exercise the reporting pipeline with fixture data - no live infra required."""
    if not SIMULATED_RESULTS_PATH.exists():
        raise FileNotFoundError(
            f"{SIMULATED_RESULTS_PATH} not found - can't run --simulate without it"
        )
    raw = json.loads(SIMULATED_RESULTS_PATH.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="run against real victim + Wazuh")
    mode.add_argument("--simulate", action="store_true", help="use fixture data, no live infra")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "pipeline" / "results")
    args = parser.parse_args()

    if args.live:
        results = run_live(args)
    else:
        results = run_simulate()

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(results, indent=2))

    layer_path = write_layer(
        results,
        args.out / "navigator_layer.json",
        description=(
            f"Purple team pass ({'live' if args.live else 'simulated'}) - "
            f"{datetime.now(timezone.utc).date().isoformat()}"
        ),
    )

    detected = sum(1 for s in results.values() if s == "detected")
    missed = sum(1 for s in results.values() if s == "missed")
    untested = sum(1 for s in results.values() if s == "untested")
    print(f"\n{detected} detected / {missed} missed / {untested} untested")
    print(f"ATT&CK Navigator layer written to: {layer_path.relative_to(REPO_ROOT)}")
    if missed:
        print("Gap(s) found - review the missed technique(s) above before calling this done.")


if __name__ == "__main__":
    main()
