# ADR-0004: Validation result classification

- Status: Accepted (implementation: Phase 4)
- Date: 2026-10-11

## Context

The original orchestrator reported `detected` / `missed`. A miss can have
very different causes, each with a different owner and fix: the behaviour
never ran, the endpoint never logged it, the log never reached the indexer, or
the detection logic did not match. Collapsing them hides the actual problem.

## Decision

Each validation attempt produces exactly one result:

| Result | Meaning | Determined by |
|---|---|---|
| `EXECUTION_FAILURE` | The behaviour did not execute | Mechanism reports failure, or no execution evidence |
| `TELEMETRY_GAP` | It executed but the endpoint did not record it | Expected event absent from the endpoint's local log (e.g. Sysmon channel via WinRM) |
| `INGESTION_GAP` | Recorded on the endpoint, not in the indexer before timeout | Present locally, absent from `wazuh-archives-*` |
| `DETECTION_GAP` | Telemetry in the indexer, compiled query did not match | Telemetry query matches, detection query does not |
| `DETECTED` | Compiled query matched | Detection query matches; latency recorded |

Infrastructure and tooling failures (`ORCHESTRATOR_ERROR`, `INFRA_ERROR`:
WinRM/API/auth errors, timeouts of the platform itself) are reported
separately and never counted as detection outcomes.

Telemetry checks use queries independent of the detection under test.
Detection latency = first matching document's index time − execution time.

## Consequences

- Each mapped behaviour needs an "expected telemetry" query in addition to
  the detection query (Phase 4 schema extension of `validation/mappings.yml`).
- Phase 3 already applied this method manually (`docs/validation/`).
