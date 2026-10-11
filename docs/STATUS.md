# Status

> Read this first when resuming work. Updated at the end of every working
> session as part of the PR that closes it.

**Last updated:** 2026-10-11
**Phase:** 3.5 — repository hardening (Phase 3 closed 2026-10-11)
**Next phase:** 4 — automated purple-team validation

## Where we are

- Repository created private as `0xAll3nC/detection-engineering-platform`.
  `main` holds the original history plus the Phase 3 work as focused commits
  (identity rewritten to the GitHub noreply address before first publication).
- PR #1 (`refactor/repository-structure`) restructures the repository:
  package, `detplat` CLI, quality gates, ADRs, CI. It introduces no change to
  detection behaviour: all five compiled queries are identical to the
  pre-refactor output.
- Test suite: all rule fixtures pass; one strict xfail documents the confirmed
  case-sensitivity backend gap.

## Phase 3 outcome (live, manual, 2026-10-11)

| Experiment | Result |
|---|---|
| Wazuh-agent `net.exe` FP filter (14-day window) | Validated: 10 → 2 hits; all 8 removed hits agent-parented |
| `whoami /all` | DETECTED (≈1.0 s Sysmon → index) |
| `WHOAMI /ALL` | DETECTION_GAP: telemetry present, compiled query case-sensitive |
| Stored values contain doubled backslashes | Observation; impact on interior-backslash patterns is an **unverified hypothesis** |

Evidence: [docs/validation/2026-10-11-phase3-recon-tuning.md](validation/2026-10-11-phase3-recon-tuning.md)

## Open decisions

- ADR-0009 (Proposed): how to get case-insensitive matching on the backend.

## Known gaps (tracked as GitHub issues)

| Issue | Gap | State |
|---|---|---|
| #2 | Case-sensitive compiled wildcards (`WHOAMI /ALL` evades) | **Confirmed** DETECTION_GAP; strict xfail |
| #3 | Doubled-backslash storage vs interior-backslash patterns (Run-key rule) | **Hypothesis**; verify live before any change |
| #4 | Atomic test selection unverified; pin by GUID | Phase 4 |
| #5 | No logsource → Sysmon channel/EventID constraint | Open |
| #6 | Account recon: over-broad `user`, `net1.exe`, filter anchoring | Open |
| #7 | Encoded PowerShell flag variants | Open |
| #8 | Run-key FP filter on attacker-controllable `Details` | Open (after #3) |
| #9 | LSASS ordinal `#24` form | Open |
| #10 | diskcache PYSEC-2026-2447 accepted risk | Accepted, monitored |

## Next steps

1. Merge PR #1 once CI is green (rebase-merge to keep the file-move history).
2. Make the repository public after CI, sanitisation and the full-history
   secret scan pass; then enable branch protection, secret scanning push
   protection and private vulnerability reporting.
3. Re-point the local working copy at GitHub (see below).
4. Phase 4, starting with #4 (verify and pin Atomic tests by GUID) and the
   #3 doubled-backslash experiment.

## Local working copy

GitHub is the source of truth from the first push. The previous local folder
(`blue-team-detection-pipeline`) is superseded; clone fresh:

```bash
git clone https://github.com/0xAll3nC/detection-engineering-platform.git
cd detection-engineering-platform && make install
```

## Session workflow

At the end of a session: update this file → `make check` → conventional
commits on a feature branch → push → PR → CI green → self-review → merge.
