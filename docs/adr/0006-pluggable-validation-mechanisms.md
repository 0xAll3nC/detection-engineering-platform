# ADR-0006: Pluggable validation mechanisms; Atomic tests pinned by GUID

- Status: Accepted
- Date: 2026-10-11

## Context

The original technique map selected Atomic Red Team tests by *number*. Test
numbering changes between atomic-red-team releases, and review suggests
several carried-over numbers select unrelated tests (e.g. ProcDump instead of
comsvcs.dll for T1003.001, a Linux test for T1087.001). A wrong selection
would produce a misleading "missed" result. Not every behaviour will be best
produced by Atomic Red Team either.

## Decision

- `validation/mappings.yml` is keyed by **rule id** and records a `mechanism`.
  `atomic` is the only implemented mechanism; the schema admits others
  (manual, replay, custom scripts) without changing rules.
- When `mechanism: atomic`, the test is identified by its
  `auto_generated_guid`. A GUID is required before a rule can be promoted
  beyond `experimental` (enforced by tests).
- Each mapping has `verified: true|false`. The orchestrator refuses unverified
  mappings unless explicitly overridden.

## Consequences

- All current mappings are `verified: false` with `guid: null` until reviewed
  against a pinned atomics checkout (Phase 4).
