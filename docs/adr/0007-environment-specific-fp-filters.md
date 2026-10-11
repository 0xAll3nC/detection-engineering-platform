# ADR-0007: Environment-specific false-positive filters

- Status: Accepted
- Date: 2026-09-29 (recorded 2026-10-11)

## Context

The first live run of *Local Account and Group Reconnaissance* against
`wazuh-archives-*` returned four `net.exe` executions parented by
`C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` — the Wazuh agent's own
host-inventory collection. Options were: lower the rule's severity, drop the
`net user` selection, or filter the known-benign parent.

## Decision

Filter the specific benign source (`filter_wazuh_agent` on `ParentImage`)
rather than weakening the rule, and:

- add a negative **regression fixture** reproducing the observed event;
- require every `filter_*` selection to be exercised by a negative fixture
  (enforced by `tests/detections/test_detection_quality.py`);
- document the filter's origin in the rule's `falsepositives`;
- re-validate live that the filter removes only the intended events.

## Evidence

2026-10-11, 14-day window: unfiltered query 10 hits, filtered 2; all 8 removed
hits were `wazuh-agent.exe`-parented and both remaining hits were intentional
tests (`docs/validation/2026-10-11-phase3-recon-tuning.md`).

## Consequences / known weaknesses

- The filter uses `endswith '\wazuh-agent.exe'`; anchoring it to the full
  install path and `NT AUTHORITY\SYSTEM` would reduce abuse potential. Tracked
  as an issue; not changed without re-validation.
