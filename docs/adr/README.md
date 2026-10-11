# Architecture Decision Records

Short records of decisions that shaped the platform, written so the reasoning
survives without conversational memory. Format: context → decision →
consequences. Status is `Proposed`, `Accepted` or `Superseded by ADR-NNNN`.
Accepted ADRs are not edited to change the decision; a new ADR supersedes them.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-sigma-as-detection-format.md) | Sigma as the detection source format | Accepted |
| [0002](0002-wazuh-archives-as-validation-source.md) | `wazuh-archives-*` as the validation telemetry source | Accepted |
| [0003](0003-two-layer-testing-and-backend-semantics.md) | Two-layer testing and the evaluator/backend semantic contract | Accepted |
| [0004](0004-validation-result-classification.md) | Validation result classification | Accepted |
| [0005](0005-validated-behaviours-not-coverage.md) | Report validated behaviours, not "coverage" | Accepted |
| [0006](0006-pluggable-validation-mechanisms.md) | Pluggable validation mechanisms; Atomic tests pinned by GUID | Accepted |
| [0007](0007-environment-specific-fp-filters.md) | Environment-specific false-positive filters | Accepted |
| [0008](0008-detection-lifecycle.md) | Detection lifecycle and status promotion | Accepted |
| [0009](0009-backend-case-insensitive-matching.md) | Achieving case-insensitive matching on the Wazuh backend | Proposed |
