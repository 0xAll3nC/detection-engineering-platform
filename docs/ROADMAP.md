# Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Lab: Wazuh 4.14.6 (Docker), Windows 10 victim, Sysmon (sysmon-modular), agent, archive indexing | ✅ Done |
| 1 | Detection-as-code: 5 Sigma rules, fixtures, evaluator, CI | ✅ Done |
| 2 | pySigma compilation with Wazuh field mapping | ✅ Done |
| 3 | First live validation and tuning loop (archives source, Wazuh-agent FP, case-sensitivity finding) | ✅ Closed 2026-10-11 |
| 3.5 | Repository hardening: package, quality gates, ADRs, CI, security scanning, public release | 🟡 In progress |
| 4 | Automated purple-team validation | ⏭ Next |
| 5 | Metrics and evidence-based ATT&CK reporting | Planned |
| 6 | Continuous validation | Planned |
| 7 | Expansion | Planned |

## Phase 3.5 — repository hardening

- [x] History preserved; Phase 3 work committed as focused commits
- [x] Package (`detection_platform`), locked dependencies, `detplat` CLI
- [x] Evaluator without `eval()`; field mapping as data; compiled-query snapshots
- [x] DoD quality gates, backend-semantics tests, ADRs 0001–0009
- [x] CI: lint, tests, artifacts, full-history gitleaks, pip-audit; CodeQL; Dependabot
- [ ] PR #1 merged; issues opened for all known gaps
- [ ] Repository made public after CI, sanitisation and secret scan pass; branch protection enabled

## Phase 4 — automated purple-team validation

Goal: stop executing behaviours and searching Wazuh by hand.

- Verify and pin Atomic tests by GUID for all five rules (`verified: true`)
- Extend `validation/mappings.yml` with an *expected telemetry* query per behaviour
- Orchestrator: execute → poll archives (no fixed sleep) → correlate by time
  window and host → measure latency → classify (ADR-0004)
- Endpoint-side telemetry check over WinRM to separate TELEMETRY_GAP from INGESTION_GAP
- Separate ORCHESTRATOR_ERROR / INFRA_ERROR from detection outcomes
- Prerequisites (`-GetPrereqs`), cleanup, and execution evidence
- Sanitised machine-readable results + generated validation record
- Introduce WinRM integration tests against a mock session

## Phase 5 — metrics and reporting

- Per-behaviour results history; detection latency distribution
- Navigator layers that distinguish rule-exists / validated / missed (ADR-0005)
- Baseline FP measurement over archive windows (input to `stable`)

## Phase 6 — continuous validation

- Scheduled re-validation from the lab (never from public CI)
- Regression alerts when a previously `DETECTED` behaviour changes outcome
- Optional: deploy compiled queries as OpenSearch alerting monitors

## Phase 7 — expansion

- Resolve ADR-0009 (case-insensitive matching) and the backslash hypothesis
- Fix tracked rule semantic gaps; add detections
- Linux telemetry (auditd) and Linux atomics
