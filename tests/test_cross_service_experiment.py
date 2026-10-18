"""Fourth assignment vulnerability: cross-service authority amplification.

The report Gateway intentionally impersonates a seeded admin for delegated report
jobs. Both downstream services validate the signed grants correctly. This test
only runs in the isolated vulnerability branch with an explicit environment flag.
"""
import os

import pytest

from test_report_service import bearer, report_count, setup


@pytest.mark.skipif(
    os.environ.get("RUN_CROSS_SERVICE_EXPERIMENT") != "1",
    reason="Controlled composition exploit only; never run on the secure main branch",
)
def test_gateway_delegates_as_admin_for_alices_bob_report(setup):
    gateway, _, _ = setup
    alice = bearer(gateway, "alice")

    # The resource boundary is intact for a direct call as Alice.
    denied = gateway.get("/incidents/102", headers=alice)
    assert denied.status_code == 404

    # The flawed Gateway signs all report job grants as the seeded admin (ID 3).
    leaked = gateway.post("/incidents/102/reports", headers=alice, json={})
    print(f"Alice GET Bob #102: HTTP {denied.status_code}; "
          f"Alice report Bob #102: HTTP {leaked.status_code}")
    assert leaked.status_code == 201, leaked.text
    report = leaked.json()
    assert report["incident_id"] == 102
    assert report["requested_by"] == 3  # the report executed as admin
    assert "102" in report["content"]
    assert report_count() == 1
    print("Cross-service flaw: Gateway returned Bob's report to Alice using admin authority")
