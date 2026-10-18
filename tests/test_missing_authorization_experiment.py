"""Controlled CWE-862 demonstration using synthetic SQLite data only.

Run explicitly on the experiment branch after applying the vulnerable patch:
RUN_MISSING_AUTH_EXPERIMENT=1 python -m pytest tests/test_missing_authorization_experiment.py -q -s

The positive exploit test is skipped during normal release test runs.
"""
import os

import pytest

from test_incident_service import auth, env, owner
from services.incident_service.store import database


@pytest.mark.skipif(
    os.getenv("RUN_MISSING_AUTH_EXPERIMENT") != "1",
    reason="Controlled missing-authorization proof only; not a release test",
)
def test_alice_changes_bobs_status_without_ownership_check(env):
    client, _ = env
    assert owner(102) == 2
    with database() as conn:
        before = conn.execute("SELECT status FROM incidents WHERE id=?", (102,)).fetchone()[0]
    assert before == "open"

    response = client.patch(
        "/internal/incidents/102",
        json={"status": "resolved"},
        headers=auth(env, user=1, scope="incident:update", incident_id=102),
    )
    with database() as conn:
        after = conn.execute("SELECT status FROM incidents WHERE id=?", (102,)).fetchone()[0]
    print(f"Alice changed Bob's incident #102: HTTP {response.status_code}, status {before} -> {after}")
    assert response.status_code == 200
    assert after == "resolved"
    assert owner(102) == 2, "An unauthorized update must not transfer case ownership"
