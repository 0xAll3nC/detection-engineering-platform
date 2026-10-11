# ADR-0005: Report validated behaviours, not "coverage"

- Status: Accepted
- Date: 2026-10-11

## Context

ATT&CK techniques are broad; one technique can be performed in many ways. A
rule existing for T1003.001, or one Atomic test being detected, says nothing
about the other procedures under that technique. Heatmaps that colour a
technique green on that basis overstate defensive capability.

## Decision

- Reporting distinguishes **rule exists**, **behaviour validated live**, and
  **behaviour tested and missed**.
- Wording is "validated N selected ATT&CK-mapped behaviours", never
  "covers technique X" or "N% coverage".
- Navigator layers from simulated data are labelled `SIMULATED` and state that
  they are not validation evidence.
- A technique is only shown as detected when a live validation record exists
  for at least one behaviour mapped to it.

## Consequences

- Reports look smaller and more honest; every claim is traceable to a
  validation record.
