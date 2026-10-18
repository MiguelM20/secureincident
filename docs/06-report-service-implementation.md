# 06 - Report Service implementation and security evidence

## New functionality

`POST /incidents/{id}/reports` enters the Gateway, traverses Report Service,
and reaches Incident Service for both authorized data retrieval and report
persistence. `GET /incidents/{id}/reports/{report_id}` retrieves saved results.

- Gateway signs one report-job JWT with `aud=report-service` and
  `scope=report:generate`, and separate downstream grants using
  `aud=incident-service`, `scope=incident:read` and `scope=report:create`.
- All grants share original user `sub`, role, incident ID and unique `request_id`.
  The Report Service rejects mismatches or missing/expired claims.
- Incident Service independently verifies the signed grant, stored user role and
  current incident owner on both read and write. No trusted-service bypass.
- Formatter resides in separately installable `secureincident-formatter` v0.1.0;
  install using `requirements-report.txt` and optionally build its wheel.
- Report Service does not have Incident Service's DB volume or Gateway private
  key; it accepts a constrained filename and removes its temporary report file.

## Evidence and expected observations

Automated suite from repository root:

```bash
python -m pytest tests/test_incident_service.py tests/test_gateway.py tests/test_report_service.py -v
```

Manual test while all three processes run:

```bash
python scripts/verify_report_workflow.py
```

Expected status codes: 201 (Alice report generation), 404 (Alice request for
Bob's incident), 422 (unsafe filename), 200 (authorized retrieval). After
running locally, save **redacted** test output and any screenshots under
`docs/evidence/` and record the code commit hash in your assignment report.

## Important limitation

This is the *secure baseline* implementation, not evidence that four planted
vulnerabilities were demonstrated and fixed. Introduce the vulnerable states
separately later, collect evidence, then restore the corrected behavior.
Full fresh-process Docker Compose, dependency/static scans, Jenkins triggers,
release gates, and production discussion are still required.
