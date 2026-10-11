# Architecture

## Goal

Treat detections as code and prove them against real behaviour: version them,
test them before deployment, compile them for the target SIEM, execute
ATT&CK-mapped behaviour, verify telemetry and detection end to end, classify
*why* something was missed, and report only what has been validated.

## Flow

```
Sigma rule ──► static checks + fixture tests ──► pySigma compile (Wazuh mapping)
                    (CI, no infrastructure)            │
                                                      ▼
Atomic / other mechanism ──► Windows victim ──► Sysmon ──► Wazuh agent ──► manager
                                                                          │ logall_json
                                                                          ▼
                                                            wazuh-archives-* (raw telemetry)
                                                                          │
                       telemetry query (independent) ◄────────────────────┤
                       compiled detection query      ◄────────────────────┘
                                   │
                                   ▼
                 classification ──► results / latency ──► ATT&CK Navigator
         (EXECUTION_FAILURE / TELEMETRY_GAP / INGESTION_GAP / DETECTION_GAP / DETECTED)
```

## Components

| Path | Responsibility |
|---|---|
| `detections/<platform>/<tactic>/*.yml` | Sigma rules — the source of truth (ADR-0001) |
| `tests/fixtures/detections/*.json` | Intended Sigma behaviour per rule: positive, negative, regression cases |
| `src/detection_platform/sigma/evaluator.py` | Fast pure-Python evaluator for fixture tests; explicit `case_sensitive` mode models the backend |
| `src/detection_platform/sigma/compiler.py` | pySigma → OpenSearch Lucene, one query per rule id |
| `src/detection_platform/mappings/wazuh_windows.yml` | Sigma field → Wazuh indexed field, with observed indexing properties |
| `src/detection_platform/siem/wazuh.py` | Indexer search client (archives by default, TLS verified) |
| `src/detection_platform/execution/atomic_winrm.py` | Invoke-AtomicRedTeam over WinRM (Phase 4 scaffold) |
| `src/detection_platform/validation/` | Validation mappings and orchestrator (Phase 4 scaffold) |
| `src/detection_platform/reporting/navigator.py` | Navigator layers with behaviour-based wording (ADR-0005) |
| `validation/mappings.yml` | Rule id → validation mechanism, technique, Atomic GUID (ADR-0006) |
| `tests/backend/` | Confirmed backend divergences as strict xfails (ADR-0003) |
| `tests/snapshots/compiled/` | Reviewed compiled queries |
| `docs/validation/` | Sanitised live validation records — the evidence base |
| `build/` | Generated artifacts (gitignored) |

## Test layers

| Layer | Question answered | Runs |
|---|---|---|
| Rule fixtures | Does the rule logic express the intended Sigma behaviour? | CI |
| Quality gates | Does the rule meet the Definition of Done for its status? | CI |
| Field mapping + snapshots | Does it compile to the reviewed query using only mapped fields? | CI |
| Backend semantics | Where does the backend diverge from Sigma (confirmed only)? | CI |
| Live validation | Does the real behaviour produce telemetry that the compiled query matches? | Lab (manual now, Phase 4 automated) |

## Configuration and secrets

Lab endpoints and credentials come only from environment variables or a
gitignored `.env` (`.env.example` documents them). Nothing environment-specific
is committed. Raw validation output stays local; only sanitised records are
committed to `docs/validation/`.

## Trust boundaries

- CI never reaches the lab. Live validation runs from the operator's machine.
- If live validation is ever automated, it runs via `workflow_dispatch` on a
  self-hosted runner that is never triggered by pull requests.
