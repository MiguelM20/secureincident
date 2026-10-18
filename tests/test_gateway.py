"""Gateway and Incident Service integration tests with local ASGI HTTP boundary.

Every test uses temporary keys and a temporary SQLite database. TestClient
starts each FastAPI lifespan; no servers or actual network are needed here.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from services.gateway.app import app as gateway_app
from services.gateway.security import sign_internal_grant
from services.incident_service.app import app as incident_app
from services.incident_service.seed import seed
from services.incident_service.store import database


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Make independent Gateway-to-Incident HTTP calls without external sockets."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "gateway-private.pem"
    public_path = tmp_path / "gateway-public.pem"
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    monkeypatch.setenv("SECUREINCIDENT_PRIVATE_KEY_PATH", str(private_path))
    monkeypatch.setenv("SECUREINCIDENT_PUBLIC_KEY_PATH", str(public_path))
    monkeypatch.setenv("INCIDENT_DB_PATH", str(tmp_path / "incident.db"))
    monkeypatch.setenv("INCIDENT_SERVICE_URL", "http://incident-service.test")

    with TestClient(incident_app):
        seed({"alice": "alice-test-pass", "bob": "bob-test-pass", "admin": "admin-test-pass"})
        gateway_app.state.incident_transport = httpx.ASGITransport(app=incident_app)
        try:
            with TestClient(gateway_app) as client:
                yield client, private_key, public_path
        finally:
            del gateway_app.state.incident_transport


def token(client: TestClient, username: str = "alice") -> str:
    response = client.post(
        "/auth/login", json={"username": username, "password": f"{username}-test-pass"},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth(client: TestClient, username: str = "alice") -> dict[str, str]:
    return {"Authorization": f"Bearer {token(client, username)}"}


def test_gateway_health_authentication_and_no_passwords_leak(setup):
    client, _, public_path = setup
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/incidents").status_code == 401
    assert client.post("/auth/login", json={"username": "alice", "password": "wrong"}).status_code == 401
    assert client.post("/auth/login", json={"username": "absent", "password": "wrong"}).status_code == 401
    token_text = token(client)
    claims = jwt.decode(token_text, public_path.read_text(), algorithms=["RS256"],
                        issuer="secureincident", audience="gateway")
    assert claims["sub"] == "1"
    assert claims["role"] == "analyst"
    assert claims["aud"] == "gateway"
    assert "password" not in str(claims).lower()


def test_alice_cannot_list_or_read_bobs_cases(setup):
    client, _, _ = setup
    alice = auth(client)
    result = client.get("/incidents", headers=alice)
    assert result.status_code == 200
    assert [item["id"] for item in result.json()] == [101]
    assert client.get("/incidents/102", headers=alice).status_code == 404
    assert client.get("/incidents/101", headers=alice).status_code == 200
    bob = auth(client, "bob")
    assert [item["id"] for item in client.get("/incidents", headers=bob).json()] == [102]
    assert client.get("/incidents/101", headers=bob).status_code == 404


def test_admin_overview_and_reassignment(setup):
    client, _, _ = setup
    alice = auth(client)
    admin = auth(client, "admin")
    assert client.get("/admin/overview", headers=alice).status_code == 403
    overview = client.get("/admin/overview", headers=admin)
    assert overview.status_code == 200
    assert overview.json()["total"] == 2
    target = "/incidents/102/assign"
    assert client.patch(target, headers=alice, json={"owner_id": 1}).status_code == 403
    reassigned = client.patch(target, headers=admin, json={"owner_id": 1})
    assert reassigned.status_code == 200
    assert reassigned.json()["owner_id"] == 1
    assert client.get("/incidents/102", headers=alice).status_code == 200


def test_create_does_not_accept_owner_override_and_status_validation(setup):
    client, _, _ = setup
    alice = auth(client)
    body = {"title": "New synthetic case", "description": "Fake event", "severity": "medium"}
    response = client.post("/incidents", json=body, headers=alice)
    assert response.status_code == 201
    assert response.json()["owner_id"] == 1
    assert client.post("/incidents", json={**body, "owner_id": 2}, headers=alice).status_code == 422
    assert client.post("/incidents", json={**body, "severity": "urgent"}, headers=alice).status_code == 422


def test_update_owner_checks_across_gateway_and_resource_service(setup):
    client, _, _ = setup
    alice = auth(client)
    assert client.patch("/incidents/102", json={"status": "resolved"}, headers=alice).status_code == 404
    assert client.patch("/incidents/101", json={"owner_id": 2}, headers=alice).status_code == 422
    assert client.patch("/incidents/101", json={}, headers=alice).status_code == 422
    change = client.patch("/incidents/101", json={"status": "investigating"}, headers=alice)
    assert change.status_code == 200
    assert change.json()["status"] == "investigating"
    bob = auth(client, "bob")
    assert client.get("/incidents/102", headers=bob).json()["status"] == "open"


def test_sql_search_is_parameterized_and_owner_scoped(setup):
    client, _, _ = setup
    response = client.get("/incidents", params={"search": "' OR 1=1 --"}, headers=auth(client))
    assert response.status_code == 200
    assert response.json() == []


def test_wrong_audience_expired_and_forged_tokens_rejected(setup):
    client, attacker_key, _ = setup
    incident_grant = sign_internal_grant(
        user={"sub": "1", "role": "analyst"}, scope="incident:list",
    )
    assert client.get("/incidents", headers={"Authorization": f"Bearer {incident_grant}"}).status_code == 401
    invalid_token = jwt.encode({
        "iss": "secureincident", "aud": "gateway", "sub": "3", "role": "admin",
        "iat": datetime.now(timezone.utc), "nbf": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30), "jti": "attacker",
    }, rsa.generate_private_key(public_exponent=65537, key_size=2048), algorithm="RS256")
    assert client.get("/incidents", headers={"Authorization": f"Bearer {invalid_token}"}).status_code == 401
    expired_token = jwt.encode({
        "iss": "secureincident", "aud": "gateway", "sub": "1", "role": "analyst",
        "iat": datetime.now(timezone.utc) - timedelta(hours=1),
        "nbf": datetime.now(timezone.utc) - timedelta(hours=1),
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1), "jti": "expired",
    }, attacker_key, algorithm="RS256")
    assert client.get("/incidents", headers={"Authorization": f"Bearer {expired_token}"}).status_code == 401


def test_report_retrieval_still_enforces_case_ownership(setup):
    client, _, _ = setup
    alice = auth(client)
    assert client.get("/incidents/102/reports/1", headers=alice).status_code == 404
    assert client.get("/incidents/101/reports/999", headers=alice).status_code == 404


def test_user_supplied_roles_and_invalid_login_shapes_fail(setup):
    client, _, _ = setup
    assert client.post("/auth/login", json={
        "username": "alice", "password": "alice-test-pass", "role": "admin",
    }).status_code == 422
    assert client.post("/auth/login", json={
        "username": "alice", "password": "alice-test-pass", "user_id": 3,
    }).status_code == 422


def test_unavailable_incident_service_fails_closed(setup):
    client, _, _ = setup
    # An upstream outage must not authenticate anyone as a fallback.
    gateway_app.state.incident_transport = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("offline"))
    )
    assert client.post("/auth/login", json={
        "username": "alice", "password": "alice-test-pass",
    }).status_code == 503
    # Existing user token does not bypass the service's resource policy.
    assert client.get("/incidents", headers={"Authorization": f"Bearer {sign_internal_grant(scope='auth:verify')}"}).status_code == 401


def test_invalid_grant_binding_does_not_permit_resource_access(setup):
    client, _, _ = setup
    alice = auth(client)
    # No body-provided role or incident owner is trusted.
    assert client.get("/incidents/102", headers=alice).status_code == 404
    with database() as conn:
        row = conn.execute("SELECT owner_id, status FROM incidents WHERE id=102").fetchone()
    assert row["owner_id"] == 2
    assert row["status"] == "open"
