# Contributing

## Setup

```bash
uv sync --extra lab        # runtime + dev dependencies (pywinrm only needed for live runs)
uv run pre-commit install  # ruff, YAML/JSON checks, gitleaks on every commit
make check                 # lint + tests + compile — must pass before a PR
```

## Workflow

1. Branch from `main`: `feat/…`, `fix/…`, `test/…`, `docs/…`, `refactor/…`.
2. Commit with [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(validation): add Wazuh telemetry correlation`,
   `test(discovery): add Wazuh inventory regression case`,
   `fix(compiler): map Sysmon fields to Wazuh schema`.
   Scopes: a tactic (`discovery`, `persistence`, …) for rule work, or a
   component (`compiler`, `siem`, `validation`, `reporting`, `ci`, `deps`).
3. Open a PR; complete the template checklist; CI must be green.
4. Squash-merge (or rebase-merge when individual commits carry history worth
   keeping, e.g. file moves).
5. Update `docs/STATUS.md` at the end of every working session.

`main` is shared history: never force-push or rewrite it.

## Adding or changing a detection

Follow the [Definition of Done](docs/DEFINITION_OF_DONE.md). In short:

1. `detections/windows/<tactic>/<name>.yml` — Sigma, `status: experimental`.
2. `tests/fixtures/detections/<name>.json` — positive, negative, and a
   regression case for every tuned false positive.
3. Entry in `validation/mappings.yml` keyed by the rule id.
4. `make snapshots`, review the compiled-query diff, explain it in the PR.
5. A backend limitation never changes a fixture's expected result — record it
   in `tests/backend/` instead (ADR-0003).

## Live validation evidence

Raw output stays outside the repository. Commit a sanitised record to
`docs/validation/YYYY-MM-DD-<topic>.md`: method, results, classification,
consequences — no hostnames, usernames, IPs, document IDs or credentials.
