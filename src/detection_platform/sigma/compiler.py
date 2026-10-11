"""
Compile Sigma rules to OpenSearch Lucene queries for the Wazuh indexer.

Wazuh 4.x ships an OpenSearch-based indexer, so we target
pysigma-backend-opensearch. Sigma's generic Sysmon field names (Image,
CommandLine, ...) are mapped to Wazuh's indexed names (data.win.eventdata.*)
by the processing pipeline built from mappings/wazuh_windows.yml.

Outputs are build artifacts (build/compiled/<rule-id>.lucene). Reviewed
reference outputs live in tests/snapshots/compiled/; any change to a compiled
query - from a rule edit, mapping edit or pySigma upgrade - shows up as a
snapshot diff in the PR.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    title: str
    source: Path
    query: str


def load_field_mapping(name: str = "wazuh_windows.yml") -> dict[str, str]:
    text = resources.files("detection_platform.mappings").joinpath(name).read_text()
    return dict(yaml.safe_load(text)["fields"])


def build_wazuh_pipeline(field_map: dict[str, str] | None = None):
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation

    return ProcessingPipeline(
        name="Wazuh Windows eventchannel field mapping",
        priority=10,
        items=[
            ProcessingItem(
                identifier="wazuh_eventchannel_field_mapping",
                transformation=FieldMappingTransformation(
                    mapping=field_map or load_field_mapping()
                ),
            ),
        ],
    )


def compile_rules(detections_dir: Path) -> list[CompiledRule]:
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.collection import SigmaCollection

    paths = sorted(detections_dir.rglob("*.yml"))
    if not paths:
        raise FileNotFoundError(f"No rules found under {detections_dir}")

    backend = OpensearchLuceneBackend(processing_pipeline=build_wazuh_pipeline())
    compiled = []
    # One rule per conversion keeps rule <-> query pairing explicit instead of
    # relying on the backend preserving collection order.
    for path in paths:
        collection = SigmaCollection.from_yaml(path.read_text())
        (rule,) = collection.rules
        queries = backend.convert(collection)
        if len(queries) != 1:
            raise RuntimeError(f"{path}: expected 1 query, backend returned {len(queries)}")
        compiled.append(
            CompiledRule(rule_id=str(rule.id), title=rule.title, source=path, query=queries[0])
        )
    return compiled


def write_compiled(compiled: list[CompiledRule], out_dir: Path, root: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    index = {}
    for c in compiled:
        (out_dir / f"{c.rule_id}.lucene").write_text(c.query + "\n")
        index[c.rule_id] = {"title": c.title, "source": str(c.source.relative_to(root))}
    index_path = out_dir / "index.json"
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    return index_path
