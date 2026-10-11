# ADR-0003: Two-layer testing and the evaluator/backend semantic contract

- Status: Accepted
- Date: 2026-10-11

## Context

Rules are unit-tested with a lightweight Python evaluator against JSON
fixtures (fast, no SIEM), and deployed as pySigma-compiled Lucene queries.
The design implicitly assumed both layers agree on what a rule matches.

Live validation on 2026-10-11 disproved that assumption. `WHOAMI /ALL` matched
in the evaluator (Sigma string matching is case-insensitive) but the compiled
query did not match the same event in `wazuh-archives-*`:
`data.win.eventdata.commandLine` is a `keyword` field with no normalizer, so
the Lucene wildcard `*\/all*` is case-sensitive. Unit tests passed while the
live detection missed.

The same validation also showed that stored values contain doubled
backslashes and escaped quotes, which may cause further divergence for
patterns with interior backslashes (unverified hypothesis).

## Decision

1. **Rule fixtures express Sigma intent.** `tests/detections/` fixtures state
   what a rule should match under Sigma semantics. They are never weakened to
   accommodate a backend limitation.
2. **Backend divergences are tested separately.** `tests/backend/` models the
   confirmed backend behaviour (e.g. `case_sensitive=True` evaluation) and
   records each known divergence as a `strict` xfail linked to its evidence.
   When the divergence is fixed the xfail passes unexpectedly and CI fails
   until the marker is removed.
3. **Compiled output is snapshot-tested.** Reviewed queries live in
   `tests/snapshots/compiled/`; any change must be reviewed in the PR.
4. **Backend models must be evidence-based.** A behaviour is modelled in
   `tests/backend/` only after live confirmation; hypotheses are tracked as
   issues.

## Consequences

- The known case-sensitivity gap is visible in every CI run instead of hidden.
- The evaluator gains an explicit `case_sensitive` mode used only by backend
  tests.
- How to fix the gap is a separate decision (ADR-0009).
