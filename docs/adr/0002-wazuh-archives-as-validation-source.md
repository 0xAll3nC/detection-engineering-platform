# ADR-0002: `wazuh-archives-*` as the validation telemetry source

- Status: Accepted
- Date: 2026-09-29 (recorded 2026-10-11)

## Context

The first version of the Wazuh client queried `wazuh-alerts-*`. That index
only contains events that Wazuh's own ruleset selected as alerts. Running our
Sigma queries there means a detection can only "fire" if Wazuh's stock rules
happened to flag the same event — the telemetry is pre-filtered by a different
detection layer before our validation sees it.

Validation must be able to distinguish *the telemetry was never there* from
*the telemetry was there and our detection did not match*. With pre-filtered
data those two outcomes are indistinguishable.

## Decision

Validation queries run against `wazuh-archives-*`, which holds every event the
agent shipped. This requires `<logall_json>yes</logall_json>` on the manager
and the Filebeat archives module enabled. The index pattern is configurable
(`WAZUH_INDEX_PATTERN`) but defaults to archives.

## Consequences

- Telemetry presence can be checked independently of the detection query,
  enabling the TELEMETRY_GAP / INGESTION_GAP / DETECTION_GAP split (ADR-0004).
- Archive indexing increases storage use in the lab.
- This is a validation design, not a production alerting design: in
  production, compiled queries would run as monitors over the same raw data.

## Evidence

Validated in practice on 2026-10-11: an uppercase `WHOAMI /ALL` event was
present in `wazuh-archives-*` while the compiled query did not match it — a
finding only observable because raw telemetry was queried
(`docs/validation/2026-10-11-phase3-recon-tuning.md`).
