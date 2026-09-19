"""
compile_rules.py
-----------------
Compiles the Sigma rules in rules/windows/ into real, deployable OpenSearch
Lucene queries against Wazuh's indexer (Wazuh 4.x ships an OpenSearch-based
indexer, not raw Elasticsearch, so we target the OpenSearch backend).

This is the "detection-as-code" deployment step: sigma_evaluator.py (used
by tests/test_rules.py) proves the rule LOGIC is correct against sample
events; this script proves the rules actually COMPILE to valid queries you
can run against your Wazuh indexer's REST API or paste into a saved search.

Requires (see requirements.txt):
    pysigma
    pysigma-backend-opensearch

NOTE ON VERIFICATION: this file was written and reviewed against the
pySigma / pySigma-backend-opensearch documentation, but PyPI is not
reachable from the sandbox this project was built in, so this script has
NOT been execution-tested end-to-end yet. Run it on your own machine
(`pip install -r requirements.txt && python pipeline/compile_rules.py`)
as your first Week-2 checkpoint, and fix up any API drift you hit --
pySigma's API has moved before and may have moved again since. Treat this
as a strong first draft, not gospel.

Field mapping: our rules use generic Sysmon field names (Image,
CommandLine, TargetObject, ...). Wazuh's default Windows eventchannel
decoder indexes Sysmon fields under data.win.eventdata.* and
data.win.system.*. WAZUH_FIELD_MAP below bridges the two so the compiled
queries actually match real documents in your Wazuh indices -- verify
these paths against a real alert document in your lab (Wazuh dashboard ->
Discover) in case your decoder/version differs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "windows"
OUTPUT_DIR = REPO_ROOT / "pipeline" / "compiled"

WAZUH_FIELD_MAP = {
    "EventID": "data.win.system.eventID",
    "Image": "data.win.eventdata.image",
    "CommandLine": "data.win.eventdata.commandLine",
    "ParentImage": "data.win.eventdata.parentImage",
    "TargetObject": "data.win.eventdata.targetObject",
    "Details": "data.win.eventdata.details",
    "EventType": "data.win.eventdata.eventType",
    "User": "data.win.eventdata.user",
}


def build_wazuh_pipeline():
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation

    return ProcessingPipeline(
        name="Wazuh Windows eventchannel field mapping",
        priority=10,
        items=[
            ProcessingItem(
                identifier="wazuh_eventchannel_field_mapping",
                transformation=FieldMappingTransformation(mapping=WAZUH_FIELD_MAP),
            ),
        ],
    )


def compile_rules() -> dict[str, str]:
    try:
        from sigma.backends.opensearch import OpensearchLuceneBackend
        from sigma.collection import SigmaCollection
    except ImportError as exc:
        print(
            "Missing pySigma / pySigma-backend-opensearch.\n"
            "Install with:  pip install -r requirements.txt\n"
            f"(import error: {exc})",
            file=sys.stderr,
        )
        sys.exit(1)

    rule_files = sorted(str(p) for p in RULES_DIR.rglob("*.yml"))
    if not rule_files:
        print(f"No rules found under {RULES_DIR}", file=sys.stderr)
        sys.exit(1)

    rules = SigmaCollection.from_files(rule_files)
    backend = OpensearchLuceneBackend(processing_pipeline=build_wazuh_pipeline())
    queries = backend.convert(rules)

    # pySigma returns one query per rule, in the same order rules were
    # loaded. Pair each compiled query back up with its source rule title.
    results = {}
    for rule, query in zip(rules.rules, queries):
        results[rule.title] = query
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=OUTPUT_DIR, help="directory to write compiled queries to"
    )
    args = parser.parse_args()

    results = compile_rules()
    args.out.mkdir(parents=True, exist_ok=True)

    for title, query in results.items():
        slug = title.lower().replace(" ", "_")
        out_file = args.out / f"{slug}.lucene"
        out_file.write_text(query + "\n")
        print(f"[{title}]")
        print(f"  -> {out_file.relative_to(REPO_ROOT)}")
        print(f"  {query}\n")

    print(f"Compiled {len(results)} rule(s) to {args.out.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
