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

See the issue tracker, label `validation-finding` / `detection`. Summary:

1. Case-sensitive compiled wildcards (confirmed DETECTION_GAP)
2. Doubled-backslash storage vs interior-backslash patterns (hypothesis, Run-key rule; verify live before any change)
3. Atomic test mappings unverified / likely wrong test numbers; pin GUIDs
4. No logsource → channel/EventID constraint in compiled queries
5. Account recon rule: over-broad `user` substring, `net1.exe` missing, agent filter not path-anchored
6. Encoded PowerShell rule misses flag variants (`-ec`, `/enc`, end-of-line)
7. Run-key filter on attacker-controllable `Details` substrings
8. LSASS rule misses the `#24` ordinal form
9. Accepted dependency risk: diskcache PYSEC-2026-2447 (no fix available)

## Next steps

1. Merge PR #1 once CI is green (rebase-merge to keep the file-move history).
2. Make the repository public after CI, sanitisation and the full-history
   secret scan pass; then enable branch protection, secret scanning push
   protection and private vulnerability reporting.
3. Re-point the local working copy at GitHub (see below).
4. Phase 4, starting with verifying and pinning the Atomic tests (GUIDs) and
   the doubled-backslash experiment.

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
