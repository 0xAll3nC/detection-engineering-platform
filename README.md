# Detection Engineering Platform

[![CI](https://github.com/0xAll3nC/detection-engineering-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/0xAll3nC/detection-engineering-platform/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Detection-as-code with live validation. Sigma rules are version-controlled
and tested like software, compiled for a Wazuh (OpenSearch) SIEM, and then
proven or disproven against real ATT&CK-mapped behaviour on a Windows endpoint.
Validation uses raw telemetry, so a miss can be traced to its cause: the
behaviour didn't run, telemetry was missing, ingestion failed, or the
detection logic didn't match.

```
Sigma rule → fixture tests & quality gates → pySigma compile (Wazuh mapping)
  → execute behaviour → Sysmon → Wazuh raw archives → correlate
  → classify (EXECUTION / TELEMETRY / INGESTION / DETECTION gap, or DETECTED)
  → evidence-based ATT&CK reporting
```

## Current state

**Phase 3 (first live validation) is closed. Phase 4 (automated
purple-team validation) is next.** See [docs/STATUS.md](docs/STATUS.md) and
[docs/ROADMAP.md](docs/ROADMAP.md).

All five detections are **`experimental`**. They are unit-tested and compile
to reviewed queries. One has been validated live, manually, and that run
surfaced a confirmed gap. None is production-ready yet.

| Detection | ATT&CK | Live evidence |
|---|---|---|
| Local Account and Group Reconnaissance | T1087.001, T1033 | Manually validated 2026-10-11. Wazuh-agent false positive tuned out and re-validated. **Uppercase variant missed** (confirmed backend gap) |
| LSASS Memory Dump via comsvcs.dll | T1003.001 | Not yet validated live |
| Registry Run Key Persistence | T1547.001 | Not yet validated live; predicted backslash-encoding issue (hypothesis) |
| Scheduled Task Creation via schtasks.exe | T1053.005 | Not yet validated live |
| Base64-Encoded PowerShell | T1059.001, T1027 | Not yet validated live |

This project reports **validated behaviours**, not technique "coverage". A
rule existing for a technique is not evidence that the technique is detected
([ADR-0005](docs/adr/0005-validated-behaviours-not-coverage.md)).

## What the first live validation found

- **Raw archives, not alerts.** Validation queries run against
  `wazuh-archives-*`. Querying `wazuh-alerts-*` would only see events that
  Wazuh's own rules had already selected
  ([ADR-0002](docs/adr/0002-wazuh-archives-as-validation-source.md)).
- **Environment false positive.** The Wazuh agent's inventory collection runs
  `net.exe`. This was filtered by parent process, pinned by a regression
  fixture, and re-validated: 8 of 8 removed hits were agent-parented
  ([ADR-0007](docs/adr/0007-environment-specific-fp-filters.md)).
- **Unit tests and the backend disagree.** Sigma matching is
  case-insensitive, but the compiled Lucene wildcards are case-sensitive on
  Wazuh `keyword` fields, so `WHOAMI /ALL` evaded a rule whose unit tests
  passed. This is tracked as a strict xfail rather than hidden
  ([ADR-0003](docs/adr/0003-two-layer-testing-and-backend-semantics.md),
  [record](docs/validation/2026-10-11-phase3-recon-tuning.md)).

## Quick start

```bash
uv sync --extra lab     # or: pip install -e '.[lab]' plus the dev tools in pyproject.toml
make check              # lint + tests + compile
uv run detplat compile  # → build/compiled/<rule-id>.lucene
make simulate           # reporting pipeline on SIMULATED data (labelled as such)
```

Live runs need a lab. See [docs/SETUP.md](docs/SETUP.md) and `.env.example`.

## Repository layout

| Path | Contents |
|---|---|
| `detections/` | Sigma rules by platform and tactic |
| `src/detection_platform/` | Evaluator, compiler, Wazuh client, execution, validation, reporting, `detplat` CLI |
| `validation/mappings.yml` | How each rule is validated live (mechanism, technique, Atomic GUID) |
| `tests/` | Rule fixtures, quality gates, compiled-query snapshots, backend-semantics tests, unit tests |
| `docs/` | [Architecture](docs/ARCHITECTURE.md), [Definition of Done](docs/DEFINITION_OF_DONE.md), [ADRs](docs/adr/), [validation records](docs/validation/), [status](docs/STATUS.md), [roadmap](docs/ROADMAP.md) |

## Quality gates (CI)

On every pull request, CI runs:
- Lint: ruff, plus YAML/JSON checks.
- Tests on Python 3.11 and 3.13:
  - rule fixtures,
  - Definition of Done gates,
  - pySigma validators, including ATT&CK tags,
  - field-mapping coverage and compiled-query snapshots,
  - known backend divergences, tracked as strict xfails.
- Secret scanning of the full git history (gitleaks).
- A dependency audit (pip-audit).
- CodeQL and Dependabot.

Live validation never runs in public CI.

## License

[Apache-2.0](LICENSE)
