# Detection Engineering CI/CD & Purple Team Validation Pipeline

A full detection engineering lifecycle: Sigma detection rules are
version-controlled and unit-tested like code, compiled into real queries
for a Wazuh/OpenSearch SIEM, and then validated against real attacker
behavior with an automated purple team pass that produces a MITRE ATT&CK
Navigator coverage heatmap -- so "is this detection actually working" has
an evidence-backed answer instead of a guess.

```
commit a rule  ->  CI lints + unit-tests it  ->  compiles to a Wazuh query
      ->  Atomic Red Team executes the real technique on a Windows victim
      ->  orchestrator checks Wazuh for a matching alert
      ->  ATT&CK Navigator heatmap shows what's actually covered
```

## Why this exists

Most "detection engineering" portfolios stop at "I wrote some Sigma
rules." The two things that actually separate a rule-writer from a
detection *engineer* are: (1) rules that are tested and CI-gated like any
other code, and (2) proof the rules fire against real attacker behavior,
not just against the log sample the author had in mind while writing it.
This project does both, end to end.

## Architecture

| Layer | What it does | Key files |
|---|---|---|
| **Detection-as-code** | Sigma rules in Git, unit-tested against fixture log events on every commit | `rules/windows/*.yml`, `pipeline/sigma_evaluator.py`, `tests/test_rules.py` |
| **Compilation** | Compiles Sigma -> real OpenSearch/Lucene queries mapped to Wazuh's actual indexed field names | `pipeline/compile_rules.py` |
| **Purple team automation** | Runs Atomic Red Team techniques on a Windows victim, checks whether the compiled query catches them | `pipeline/atomic_runner.py`, `pipeline/wazuh_client.py`, `pipeline/purple_team_runner.py` |
| **Coverage reporting** | Turns results into a MITRE ATT&CK Navigator heatmap | `pipeline/navigator_heatmap.py` |
| **CI** | Runs all of the above on every push/PR | `.github/workflows/detection-ci.yml` |

## Current rule coverage

5 Windows/Sysmon detections, each unit-tested with positive and negative
fixtures:

| Rule | Technique | Level |
|---|---|---|
| LSASS Memory Dump via comsvcs.dll MiniDump | T1003.001 (Credential Access) | high |
| Registry Run Key Persistence | T1547.001 (Persistence) | medium |
| Scheduled Task Creation via schtasks.exe | T1053.005 (Persistence) | medium |
| Suspicious Base64-Encoded PowerShell Command | T1059.001 / T1027 (Execution / Defense Evasion) | high |
| Local Account and Group Reconnaissance | T1087 / T1033 (Discovery) | low |

## Quick start

```bash
pip install -r requirements.txt

# fast, no infra needed - proves the rule LOGIC is correct
pytest tests/ -v

# compiles rules to real Wazuh/OpenSearch queries
python pipeline/compile_rules.py

# runs the full purple-team-to-heatmap pipeline with fixture data,
# no live Wazuh/Windows required - good for a first look at the plumbing
python pipeline/purple_team_runner.py --simulate
```

Point it at a real lab and run the same command with `--live` once your
Wazuh server + Windows victim are up -- see [docs/SETUP.md](docs/SETUP.md)
for the full walkthrough (Wazuh Docker Compose, Sysmon config, Wazuh agent
enrollment, WinRM, Invoke-AtomicRedTeam install).

## Adding a new detection

1. Write the rule in `rules/windows/<name>.yml` (standard Sigma format,
   tag it with an `attack.tNNNN` MITRE ATT&CK tag).
2. Add `tests/fixtures/<name>.json` with at least one event that should
   match and one that shouldn't (`test_every_rule_has_at_least_one_positive_and_negative_case`
   in CI enforces this).
3. `pytest tests/ -v` locally, then push -- CI lints, tests, and compiles
   the rule automatically.
4. Add the rule's primary technique to `pipeline/technique_test_map.yml`
   so the purple team runner knows which Atomic Red Team test validates it.

## Roadmap

- [x] Windows/Sysmon detection-as-code pipeline with CI-gated unit tests
- [x] Sigma -> Wazuh/OpenSearch query compilation
- [x] Automated purple team validation + ATT&CK Navigator heatmap
- [ ] Live validation run against the real lab (first checkpoint once
      Wazuh + Windows victim are online)
- [ ] Extend `logsource: product` coverage to Linux (auditd-based rules,
      new fixture set, Linux victim + Atomic Red Team Linux atomics)
- [ ] Tune false-positive filters using a short baseline capture period
- [ ] Optional: small LLM step that drafts a candidate Sigma rule when a
      purple team pass finds a gap

## A note on what's execution-tested vs. what isn't

Everything that can run without external infrastructure -- the rule
logic, the fixture-based unit tests, the heatmap generation, the
`--simulate` pipeline run -- has been executed and verified working.
`compile_rules.py` (needs pySigma + PyPI access) and `atomic_runner.py`
(needs a real WinRM host) were written against documented APIs but
couldn't be execution-tested in the environment this project was
scaffolded in. They're the right place to start once your lab is up --
see the notes at the top of each file.
