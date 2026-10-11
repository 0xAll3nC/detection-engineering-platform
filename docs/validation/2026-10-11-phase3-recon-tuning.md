# Validation record: Local Account and Group Reconnaissance — FP tuning and case sensitivity

| | |
|---|---|
| Date | 2026-10-11 (UTC) |
| Rule | `discovery_account_recon.yml` — id `0f9190b7-e73f-44f9-a131-852c6555c2b5` |
| Rule status | `experimental` |
| Validation source | `wazuh-archives-*` (raw telemetry; see ADR-0002 once added) |
| Lab | Wazuh 4.14.6 single-node (Docker), Windows 10 victim, Sysmon (sysmon-modular), Wazuh agent |
| Toolchain | pySigma 1.5.1, pysigma-backend-opensearch 2.0.3 |
| Method | Manual execution on the victim + read-only `_search` queries against the indexer |

## Background

The first live run (2026-09-29) of the compiled query against `wazuh-archives-*`
returned five hits: one intentional `whoami /all` and four `net.exe` executions
parented by `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` (the agent's own
host-inventory collection). The rule gained `filter_wazuh_agent`
(`ParentImage|endswith: '\wazuh-agent.exe'`) and a negative regression fixture.
This record closes that tuning loop and adds a case-sensitivity experiment.

## Experiments

1. **FP regression** — run the pre-tuning query (filter removed) and the tuned
   query over the same 14-day window; compare.
2. **Positive control** — from `cmd.exe` on the victim: `whoami /all`.
3. **Case experiment** — ~75 s later, from the same `cmd.exe`: `WHOAMI /ALL`.
   Sysmon records `Image` with the on-disk path, so only `CommandLine` differs
   between 2 and 3.
4. **Telemetry check independent of the rule** — list all Sysmon EID 1
   `whoami.exe` events in the window (case-insensitive, client-side filter), then
   test whether the compiled query matches each one.
5. **Field mapping** — `GET wazuh-archives-*/_mapping/field/...`.

## Results

| # | Observation | Result |
|---|---|---|
| 5 | `data.win.eventdata.commandLine` and `.image` are `keyword`, no normalizer | — |
| 1 | Unfiltered: 10 hits. Tuned: 2 hits. 8 removed, **all** parented by `wazuh-agent.exe`; 0 agent-parented hits remain. Both remaining hits are intentional manual tests (2026-09-29 via PowerShell, 2026-10-11 via cmd.exe). | **FP filter validated** |
| 2 | `whoami  /all`: telemetry present, compiled query **matched**; Sysmon `UtcTime` → indexed ≈ 1.04 s | **DETECTED** |
| 3 | `WHOAMI  /ALL`: telemetry present, compiled query **did not match**; ≈ 1.01 s | **DETECTION_GAP** |

## Analysis

- **Case sensitivity (confirmed).** Sigma string matching is case-insensitive and
  the local evaluator implements that (it returns *match* for experiment 3). The
  compiled Lucene wildcard `*\/all*` runs against an un-normalised `keyword` field,
  which is case-sensitive. Unit tests and the live backend therefore disagree.
  Because telemetry was present and ingested within ~1 s, this is a detection-logic
  gap, not a telemetry or ingestion gap.
- **Stored value encoding (new observation, hypothesis only).** The indexed
  values contain literal doubled backslashes and escaped quotes, e.g.
  `C:\\Windows\\System32\\whoami.exe` and `\"C:\\Windows\\system32\\whoami.exe\" /all`.
  Single-backslash `endswith` patterns (`\whoami.exe`, `\wazuh-agent.exe`) still
  match because the final backslash of the pair satisfies them. Patterns with
  *interior* backslashes — e.g. the Run-key rule's
  `\Software\Microsoft\Windows\CurrentVersion\Run\` — are predicted not to match.
  **Not yet tested live; no rule has been changed on this basis.**

## Consequences

- The uppercase case is kept as a **should-match** rule fixture (Sigma intent),
  and the backend divergence is tracked separately as a strict `xfail` in
  `tests/test_backend_semantics.py`.
- Remediation approach (normalizer subfield, case-insensitive query form, or a
  backend transformation) is an open decision.
- The doubled-backslash hypothesis requires a dedicated live experiment before
  any detection is modified.

Hostnames, usernames and document IDs have been omitted from this record.
