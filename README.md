# SecureIncident - Assignment 1 design pack

Status: **DESIGN ONLY. No application code has been implemented.** Initial SSDLC plan is committed as the first Git revision.

This pack records the agreed baseline for the Python Security Incident Management System before implementation. Read in order:

1. `docs/00-getting-started.md`
2. `docs/01-requirements.md`
3. `docs/02-architecture-and-interfaces.md`
4. `docs/03-threat-model.md`
5. `docs/04-vulnerability-experiments.md`
6. `docs/05-initial-ssdlc-plan.md`
7. `diagrams/data-flow.mmd` and `diagrams/report-sequence.mmd`

## Key decisions

- Python 3.12 + FastAPI for three independently running processes: Gateway, Incident Service, Report Service.
- SQLite private to Incident Service; Report Service has no direct database access.
- Three seeded accounts: Alice, Bob (analyst), and Admin (administrator).
- Signed user JWT for Gateway, and separate short-lived audience- and incident-scoped delegated tokens for internal calls.
- Own installable Python helper package (`incident_formatter`) consumed by Report Service.
- Four controlled experiments: SQL injection (CWE-89), missing authorization on update (CWE-862), path traversal (CWE-22), and a composition-origin confused-deputy leak in report generation.
- Final mainline must pass positive and negative authorization tests after remediation.

## Important submission order

The initial SSDLC plan and architecture **are the first commit** of this repository, preceding application code. Do not reinitialize Git. For extraction, history checks, and publishing instructions, see `docs/00-getting-started.md`.

Later, implement the three services and Jenkinsfile. Preserve evidence of vulnerable and corrected states with separate commits/tags. This package is not yet a submission-ready implementation.
