## Summary

<!-- What changes and why. Link issues: "Closes #N" / "Refs #N". -->

## Type

- [ ] Detection (new / tuned / promoted rule)
- [ ] Validation / orchestration
- [ ] Compiler / field mapping
- [ ] Docs / ADR
- [ ] Build / CI / dependencies

## Checklist

- [ ] `make check` passes locally
- [ ] Conventional commit messages (`feat(scope): ...`, `fix(scope): ...`, `test(scope): ...`)
- [ ] `docs/STATUS.md` updated if this ends a working session or changes project state
- [ ] No credentials, hostnames, IPs, usernames or raw telemetry added (sanitised records only)

### Detection changes ([Definition of Done](../docs/DEFINITION_OF_DONE.md))

- [ ] Positive and negative fixtures; a regression fixture for every tuned false positive
- [ ] Compiled-query snapshot diff reviewed (`make snapshots`) and explained below
- [ ] Known backend divergences recorded in `tests/backend/`, not by weakening fixtures
- [ ] Status change justified: promotions to `test`/`stable` link the validation record
- [ ] For `stable`: baseline documented and false-positive behaviour judged acceptable

### Snapshot diff explanation

<!-- Required when tests/snapshots/ changes. -->

## Self-review

<!-- Solo-maintained repository: note what you re-checked before merging. -->
