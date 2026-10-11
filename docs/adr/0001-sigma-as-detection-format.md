# ADR-0001: Sigma as the detection source format

- Status: Accepted
- Date: 2026-09-19 (recorded 2026-10-11)

## Context

Detections need to be reviewable as code, testable without a SIEM, and
portable if the backend changes. Writing native Wazuh rules or raw Lucene
couples every detection to one backend and one query language.

## Decision

Detections are authored as Sigma rules under `detections/<platform>/<tactic>/`.
They are compiled to backend queries with pySigma
(`pysigma-backend-opensearch` for the Wazuh indexer) through a field-mapping
pipeline (`src/detection_platform/mappings/`).

## Consequences

- Rule logic is backend-neutral; backend specifics live in the mapping and
  compiler.
- Sigma semantics and backend semantics can diverge (see ADR-0003); this must
  be tested, not assumed.
- pySigma's API has broken compatibility before (`SigmaCollection.from_files`
  removed in 1.x), so versions are pinned and upgrades reviewed via
  compiled-query snapshots.
