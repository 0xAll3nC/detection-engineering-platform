# Detection Definition of Done

A detection's `status` states how much evidence exists for it (ADR-0008).
Items marked **[CI]** are enforced by tests; **[Review]** items are checked in
the PR template by the reviewer.

## `experimental` — logic written and unit-tested

1. **Valid Sigma** [CI] — passes pySigma validators (structure, conditions,
   modifiers, ATT&CK tags); UUID `id`; unique id, title and filename; lives at
   `detections/<platform>/<tactic>/<name>.yml`.
2. **Complete metadata** [CI] — `title`, `description`, `references`,
   `author`, `date`, `logsource`, `falsepositives`, `level`, `tags`, with at
   least one `attack.tNNNN` tag.
3. **Fixtures** [CI] — `tests/fixtures/detections/<name>.json` with at least
   one positive and one negative case, and **a negative regression fixture for
   every tuned false positive** (each `filter_*` selection must be exercised).
   Case variants are expected as positives where Sigma semantics require them.
4. **Compiles cleanly** [CI] — every referenced field is mapped; no Sigma field
   survives compilation unmapped; compiled-query snapshot exists.
   [Review] snapshot diff reviewed and explained in the PR.
5. **Validation mapping** [CI] — entry in `validation/mappings.yml` keyed by
   rule id, with a mechanism and an ATT&CK technique that matches the rule's
   tags.

## `test` — behaviour validated live

All of the above, plus:

6. **Verified mapping** [CI] — `verified: true`; when the mechanism is Atomic
   Red Team, the test is pinned by `auto_generated_guid`. Other mechanisms
   carry their own reproducible identifier.
7. **Live validation record** [CI: record exists / Review: content] — a
   sanitised record in `docs/validation/` naming the rule id, showing the
   behaviour executed, telemetry present in `wazuh-archives-*`, the compiled
   query matching (`DETECTED`), and detection latency.
8. **No unresolved confirmed backend divergence** [Review] — no open strict
   xfail in `tests/backend/` for this rule's validated behaviour.

## `stable` — fit for operational use

All of the above, plus [Review]:

9. **Documented, understood baseline** — the compiled query has been run over
   a representative window of archive telemetry; every hit is explained
   (intended, known-benign and filtered, or accepted). Zero hits is not
   required.
10. **Acceptable false-positive behaviour** — FP volume and character are
    appropriate for the rule's `level` and intended use, and documented in
    `falsepositives`.
11. **Operational criteria** — triage guidance exists, the filter logic has
    been reviewed for abuse (e.g. attacker-controllable fields), and the
    detection has stayed `DETECTED` across at least one later re-validation.

## Not done

A rule with a confirmed, unresolved semantic gap stays `experimental`, with
the gap tracked as an issue and, if live-confirmed, as a strict xfail.
