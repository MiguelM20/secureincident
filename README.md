# SecureIncident - Software Security Assignment I

Status: **Phase 2: all three services and the standalone formatter implemented.**
Vulnerability experiments, full Docker Compose integration, Jenkins security
pipeline, and final report are still pending.

The first Git commit must remain the initial SSDLC plan and security design.
Maintain separate commits for each tested implementation increment.

## Services

- `services/gateway/`: Public FastAPI endpoint, verifies users, issues signed user
  tokens and short-lived delegated grants.
- `services/incident_service/`: Private SQLite owner, verifies every delegated
  grant and checks incident ownership before resource operations.
- `services/report_service/`: Private report generator, checks report job grant
  and matched per-incident read/write grants, reads authorized incident data,
  formats content through installed helper package, and persists through the
  Incident Service. It never receives a signing private key or database file.
- `packages/incident_formatter/`: Separate, buildable, installable Python helper.

## Development docs

1. `docs/00-getting-started.md`
2. `docs/01-requirements.md`
3. `docs/02-architecture-and-interfaces.md`
4. `docs/03-threat-model.md`
5. `docs/04-vulnerability-experiments.md`
6. `docs/05-initial-ssdlc-plan.md`
7. `docs/06-report-service-implementation.md`
8. `diagrams/data-flow.mmd` and `diagrams/report-sequence.mmd`

## Local setup and verification

See `services/report_service/README.md` for three-terminal startup commands.

```bash
source .venv/bin/activate
python -m pip install -r requirements-report.txt
python -m pytest tests/test_incident_service.py tests/test_gateway.py tests/test_report_service.py -v
```

After the three services are running, test the whole workflow without pasting
JWTs into the terminal:

```bash
python scripts/verify_report_workflow.py
```

The script prompts for Alice's local synthetic password, then tests allowed
report creation and retrieval, denied access to Bob's incident, and unsafe
filename rejection.

## Four planned vulnerability experiments

1. CWE-89 SQL injection (synthetic incident search).
2. CWE-862 missing authorization (direct incident update).
3. CWE-22 path traversal (report output filename handling).
4. Cross-service confused-deputy disclosure (report generator using too-broad
   authority, despite a direct ownership check).

The ordinary application path intentionally includes mitigations. Preserve any
future vulnerable experimental states in isolated local-only commits/tags, then
confirm the final branch passes the regression tests.

Do not commit `runtime/`, signing keys, database files, passwords, or bearer tokens.
