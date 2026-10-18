# Experiment 2: Missing Authorization (CWE-862)

**Scope:** pytest-generated temporary SQLite database with synthetic Alice incident #101 and Bob incident #102. Never run the vulnerable version against deployed Docker containers or real records.

## What goes wrong

`PATCH /internal/incidents/{incident_id}` validates the signed grant and identity, but the deliberately vulnerable patch removes `permitted_incident(...)`, the resource-level ownership check. Alice can obtain an operation grant for a requested incident ID, but that grant does **not** establish ownership of the record. The service accepts her signed request to modify Bob's case. This is an authorization failure despite valid authentication.

## Reproduction from project root

1. Stop Docker containers while experimenting: `docker compose down` (do not remove volumes).
2. Start a separate branch: `git switch -c experiment/missing-authorization`.
3. Apply the patch: `git apply experiments/missing_authorization/vulnerable.patch`.
4. Demonstrate unauthorized modification:
   `RUN_MISSING_AUTH_EXPERIMENT=1 python -m pytest tests/test_missing_authorization_experiment.py -q -s | tee docs/evidence/missing-auth-vulnerable.txt`
   Expect **1 passed** and `Alice changed Bob's incident #102: HTTP 200, status open -> resolved`.
5. Commit the vulnerable state on the experiment branch only, including the test, patch, and evidence:
   `git add services/incident_service/app.py tests/test_missing_authorization_experiment.py experiments/missing_authorization docs/evidence/missing-auth-vulnerable.txt`
   `git commit -m "test: demonstrate CWE-862 missing authorization"`
6. Restore the ownership check: `git apply -R experiments/missing_authorization/vulnerable.patch`.
7. Run secure regression:
   `python -m pytest tests/test_incident_service.py::test_alice_cannot_read_or_modify_bobs_case -q | tee docs/evidence/missing-auth-fixed.txt`
   Expect **1 passed**. The check denies Alice's modification with HTTP 404, preserving Bob's `open` status.
8. Commit the fix: `git add services/incident_service/app.py docs/evidence/missing-auth-fixed.txt` then `git commit -m "fix: enforce incident ownership on updates"`.
9. Push experiment branch: `git push -u origin experiment/missing-authorization`, then return to main: `git switch main`.

## Evidence for report

- **CWE:** CWE-862, Missing Authorization.
- **Source:** `services/incident_service/app.py`, function `update_incident`.
- **Attacker:** Authenticated Alice, who has a valid grant for the requested `incident:update` action and case ID but does not own Bob's case.
- **Mistaken assumption:** Signed, action-bound service request implies permission to modify the underlying record.
- **Boundary:** Authenticated request -> authorization for a *specific stored resource*.
- **Impact:** Unauthorized integrity change (`open` -> `resolved`) to incident #102.
- **Fix:** Restore `permitted_incident(...)` immediately before modifying the record.
- **Principles:** Complete mediation and least privilege.
- **Evidence:** Link both Git commits, the positive exploit output, and the secure regression test result.

The experimental test is skipped by default and must not become a release gate expecting a successful exploit.
