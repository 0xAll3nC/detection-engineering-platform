"""`detplat` command-line interface.

detplat compile                 Sigma -> Wazuh/OpenSearch Lucene (build/compiled/)
detplat validate --simulate F   Reporting pipeline from a fixture results file
detplat validate --live         Execute mapped atomics and check Wazuh (Phase 4 scaffold)
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from detection_platform import paths
from detection_platform.config import ConfigError, load_dotenv


def _cmd_compile(args: argparse.Namespace) -> int:
    from detection_platform.sigma.compiler import compile_rules, write_compiled

    compiled = compile_rules(args.detections)
    index = write_compiled(compiled, args.out, root=paths.ROOT)
    for c in compiled:
        print(f"[{c.rule_id}] {c.title}\n  {c.query}\n")
    print(f"Compiled {len(compiled)} rule(s) -> {args.out} (index: {index.name})")
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    from detection_platform.reporting.navigator import write_layer
    from detection_platform.validation import orchestrator

    if args.live:
        load_dotenv()
        try:
            results = orchestrator.run_live(
                args.detections, args.mappings, args.compiled, args.allow_unverified
            )
        except ConfigError as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2
    else:
        results = orchestrator.load_simulated(args.simulate)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    mode = "live" if args.live else "simulated"
    layer = write_layer(
        results,
        args.out / "navigator_layer.json",
        description=f"Validation pass ({mode}) {datetime.now(UTC).date().isoformat()}",
        simulated=not args.live,
    )
    counts = {s: sum(1 for v in results.values() if v == s) for s in ("detected", "missed")}
    untested = len(results) - sum(counts.values())
    label = "SIMULATED " if not args.live else ""
    print(f"{label}{counts['detected']} detected / {counts['missed']} missed / {untested} untested")
    print(f"ATT&CK Navigator layer: {layer}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detplat", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("compile", help="compile Sigma rules to Wazuh/OpenSearch Lucene")
    c.add_argument("--detections", type=Path, default=paths.DETECTIONS_DIR)
    c.add_argument("--out", type=Path, default=paths.COMPILED_DIR)
    c.set_defaults(func=_cmd_compile)

    v = sub.add_parser("validate", help="run a validation pass and write a Navigator layer")
    mode = v.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="execute against the lab")
    mode.add_argument("--simulate", type=Path, metavar="RESULTS_JSON", help="fixture results")
    v.add_argument("--detections", type=Path, default=paths.DETECTIONS_DIR)
    v.add_argument("--mappings", type=Path, default=paths.VALIDATION_MAPPINGS)
    v.add_argument("--compiled", type=Path, default=paths.COMPILED_DIR)
    v.add_argument("--out", type=Path, default=paths.RESULTS_DIR)
    v.add_argument("--allow-unverified", action="store_true")
    v.set_defaults(func=_cmd_validate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
