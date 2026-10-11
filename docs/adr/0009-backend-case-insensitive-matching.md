# ADR-0009: Achieving case-insensitive matching on the Wazuh backend

- Status: **Proposed** — decision pending
- Date: 2026-10-11

## Context

ADR-0003 records the confirmed gap: compiled Lucene wildcards are
case-sensitive on Wazuh's un-normalised `keyword` fields, while Sigma requires
case-insensitive matching. `WHOAMI /ALL` evades the account-recon rule live.
A related, unverified observation is that stored values contain doubled
backslashes.

## Options under consideration

1. **Normalised sub-fields in the index template** — add a
   lowercase-normalised `keyword` sub-field (e.g. `commandLine.lower`) to the
   Wazuh template, map Sigma fields to it and lowercase values at compile time.
   Correct and fast, but changes Wazuh's managed template and needs re-indexing
   for historical data.
2. **Case-insensitive query form** — emit OpenSearch DSL (`wildcard` with
   `case_insensitive: true`) instead of `query_string` Lucene. No index
   changes; needs a custom backend output format or post-processing, and
   validation that the Wazuh indexer version supports it.
3. **pySigma pipeline transformation** — expand values into case-insensitive
   regular expressions. No index changes, but regex queries are expensive and
   harder to review.

## Next step

Prototype options 1 and 2 against the lab, using the existing strict xfail and
the live `WHOAMI /ALL` reproduction as the acceptance test. Decide in a
superseding update to this ADR. The doubled-backslash hypothesis is verified
separately first, because it may influence the choice.

Tracking: #2 (case sensitivity), #3 (backslash hypothesis).
