# Experiment 1: SQL Injection (CWE-89)

**Scope:** Synthetic incidents Alice #101 and Bob #102, in a pytest-owned temporary SQLite database. Do not use this vulnerable version with real data or expose it on a network.

## Goal and root cause

The `GET /internal/incidents?search=...` endpoint normally enforces Alice's ownership with a parameterized SQL query. The intentionally vulnerable patch changes only the search part into an interpolated SQL string. An input ending the quoted `LIKE` operand can add `OR 1=1`, overriding the ownership predicate. The bug crosses the trust boundary between user-supplied search data and executable SQL. A valid Alice token does not make her authorized to read Bob's case.

Payload: `') OR 1=1 --`

## Exact reproduction (from the repository root)

1. Create an isolated branch before applying the patch: `git switch -c experiment/sql-injection`.
2. Apply the patch: `git apply experiments/sql_injection/vulnerable.patch`.
3. Execute the proof: `RUN_SQLI_EXPERIMENT=1 python -m pytest tests/test_sql_injection_experiment.py -q -s`.
   - Expected on the vulnerable version: **1 passed**; the printed IDs include **101 and 102**.
4. Run the pre-existing secure regression test to demonstrate the violation: `python -m pytest tests/test_incident_service.py::test_list_filters_by_ownership_and_search_uses_parameters -q`.
   - Expected on the vulnerable version: **1 failed**. This pre-existing test uses a different injection string which produces an SQLite syntax error against the vulnerable query. The separate positive exploit test proves Bob's data is disclosed.
5. Save the successful proof output as `docs/evidence/sql-injection-vulnerable.txt` and commit the vulnerable version on **the experiment branch only**.
6. Restore the secure implementation: `git apply -R experiments/sql_injection/vulnerable.patch`.
7. Rerun the secure regression test: `python -m pytest tests/test_incident_service.py::test_list_filters_by_ownership_and_search_uses_parameters -q`.
   - Expected after the fix: **1 passed**.
8. Save the secure regression result as `docs/evidence/sql-injection-fixed.txt` and commit the fix to the experiment branch. Leave `main` unchanged. Running the positive exploit test with `RUN_SQLI_EXPERIMENT=1` after the fix is expected to fail, because incident 102 is no longer returned.

## Report evidence checklist

- Vulnerable location: `services/incident_service/app.py`, function `list_incidents`.
- Attack prerequisite: authenticated analyst able to control the search parameter.
- Wrong assumption: search values stay data when interpolated into SQL syntax.
- Impact: unauthorized disclosure of other users' incident records.
- Remediation: bind both `LIKE` patterns as SQL parameters, retain the ownership predicate.
- Before and after: link experiment branch's two commits, proof output, and secure regression result.
- Secure principle: complete mediation and least privilege, backed by parameterized queries.

The existing `tests/test_incident_service.py` is the secure regression evidence. The temporary proof test is skipped by default, keeping normal test runs meaningful. Do not deploy the intermediate vulnerable commit.
