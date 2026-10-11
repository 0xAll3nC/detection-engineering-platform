# ADR-0008: Detection lifecycle and status promotion

- Status: Accepted
- Date: 2026-10-11

## Context

Sigma's `status` field (`experimental`, `test`, `stable`) is often set
arbitrarily. Here it should carry a verifiable meaning tied to evidence.

## Decision

| Status | Meaning | Gate |
|---|---|---|
| `experimental` | Logic written and unit-tested; not proven live | DoD items 1–4 (CI-enforced) |
| `test` | Behaviour validated live end-to-end | + verified validation mapping, pinned Atomic GUID when the mechanism is Atomic, validation record (CI-enforced) |
| `stable` | Fit for operational use | + documented and understood baseline, acceptable FP behaviour, operational criteria met (reviewer-judged, see DoD) |

`stable` does **not** require zero unexplained hits; it requires the baseline
to be documented and understood and false-positive behaviour to be judged
acceptable for the rule's level and intended use.

Rules with confirmed unresolved semantic gaps remain `experimental`.

## Consequences

- All five initial rules are `experimental`. Their known gaps are tracked as
  issues and, where confirmed live, as strict xfails.
