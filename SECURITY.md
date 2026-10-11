# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/0xAll3nC/detection-engineering-platform/security/advisories/new),
not as public issues. Expect an initial response within 7 days.

In scope: the `detection_platform` package, CI configuration, and anything in
this repository that could leak credentials or lab details. Detection gaps
(behaviours a rule misses) are not vulnerabilities — open an issue with the
*Detection gap* template.

## Handling of secrets and lab data

- Credentials and lab endpoints come only from environment variables or a
  gitignored `.env`; see `.env.example`.
- Every commit is scanned for secrets (gitleaks pre-commit hook) and CI scans
  the full history on every push and PR.
- Raw validation output is never committed. `docs/validation/` contains
  sanitised records without hostnames, usernames, IPs or document IDs.
- Commits use a GitHub noreply address.

## Accepted dependency risks

Advisories ignored by `make audit` must be listed here with a justification
and a tracking issue, and are re-reviewed on every dependency upgrade.

| Advisory | Package | Path | Justification | Review |
|---|---|---|---|---|
| PYSEC-2026-2447 / CVE-2025-69872 | diskcache 5.6.3 | transitive via pySigma (MITRE data cache) | No fixed version exists. Exploitation requires write access to the local cache directory of the user running the tooling, which already implies code execution as that user. CI runners are ephemeral. | On every pySigma/diskcache upgrade; remove once a fix ships |
