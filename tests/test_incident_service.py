"""Security regression tests for the protected resource boundary.

These are isolated tests: no real users, networks, or production keys.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from services.incident_service.app import app
from services.incident_service.store import database


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_path = tmp_path / "public.pem"
    public_path.write_bytes(pem)
    monkeypatch.setenv("SECUREINCIDENT_PUBLIC_KEY_PATH", str(public_path))
    monkeypatch.setenv("INCIDENT_DB_PATH", str(tmp_path / "incidents.db"))

    with TestClient(app) as client:
        hasher = PasswordHasher()
        with database() as conn:
            for user_id, username, role in (
                (1, "alice", "analyst"), (2, "bob", "analyst"), (3, "admin", "admin")
            ):
                conn.execute(
                    "INSERT INTO users (id, username, password_hash, role) VALUES (?,?,?,?)",
                    (user_id, username, hasher.hash("fixture-password"), role),
                )
            conn.execute(
                "INSERT INTO incidents (id,owner_id,title,description,severity) VALUES (101,1,?,?,?)",
                ("Alice case", "Alice private information", "medium"),
            )
            conn.execute(
                "INSERT INTO incidents (id,owner_id,title,description,severity) VALUES (102,2,?,?,?)",
                ("Bob case", "Bob private information", "high"),
            )
        yield client, private


def signed_grant(
    key, *, user: int | str = 1, role: str = "analyst", scope: str = "incident:list",
    incident_id: int | None = None, audience: str = "incident-service", expired: bool = False,
):
    now = datetime.now(timezone.utc)
    claims = {
        "iss": "secureincident", "aud": audience, "sub": str(user), "role": role,
        "scope": scope, "iat": now, "nbf": now - timedelta(seconds=2),
        "exp": now - timedelta(seconds=1) if expired else now + timedelta(minutes=2),
        "jti": uuid4().hex,
    }
    if incident_id is not None:
        claims["incident_id"] = incident_id
    token = jwt.encode(claims, key, algorithm="RS256")
    return {"Authorization": f"Bearer {token}"}


def auth(env, *, user=1, role="analyst", scope="incident:list", incident_id=None, **kwargs):
    _, key = env
    return signed_grant(key, user=user, role=role, scope=scope, incident_id=incident_id, **kwargs)


def count_reports():
    with database() as conn:
        return conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]


def owner(incident_id):
    with database() as conn:
        return conn.execute("SELECT owner_id FROM incidents WHERE id=?", (incident_id,)).fetchone()[0]


def test_health_available_and_missing_grants_rejected(env):
    client, _ = env
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/internal/incidents").status_code == 401


def test_credential_verification_is_gateway_only(env):
    client, _ = env
    url = "/internal/auth/verify"
    credentials = {"username": "alice", "password": "fixture-password"}
    assert client.post(url, json=credentials, headers=auth(env, scope="auth:verify")).status_code == 403
    grant = auth(env, user="gateway-service", role="service", scope="auth:verify")
    response = client.post(url, json=credentials, headers=grant)
    assert response.status_code == 200
    assert response.json() == {"user_id": 1, "role": "analyst"}
    assert "password" not in str(response.json())
    assert client.post(url, json={**credentials, "password": "wrong"}, headers=grant).status_code == 401
    assert client.post(url, json={**credentials, "username": "unknown"}, headers=grant).status_code == 401


def test_list_filters_by_ownership_and_search_uses_parameters(env):
    client, _ = env
    alice = client.get("/internal/incidents", headers=auth(env))
    assert alice.status_code == 200
    assert [item["id"] for item in alice.json()] == [101]
    admin = client.get("/internal/incidents", headers=auth(env, user=3, role="admin"))
    assert [item["id"] for item in admin.json()] == [101, 102]
    injection = client.get("/internal/incidents", params={"search": "' OR 1=1 --"}, headers=auth(env))
    assert injection.status_code == 200
    assert injection.json() == []


def test_create_case_sets_owner_and_rejects_client_owner_id(env):
    client, _ = env
    body = {"title": "New case", "description": "Synthetic event", "severity": "low"}
    created = client.post("/internal/incidents", json=body, headers=auth(env, scope="incident:create"))
    assert created.status_code == 201
    assert created.json()["owner_id"] == 1
    attempted = client.post(
        "/internal/incidents", json={**body, "owner_id": 2},
        headers=auth(env, scope="incident:create"),
    )
    assert attempted.status_code == 422


def test_alice_cannot_read_or_modify_bobs_case(env):
    client, _ = env
    read = client.get("/internal/incidents/102", headers=auth(env, scope="incident:read", incident_id=102))
    assert read.status_code == 404
    updated = client.patch(
        "/internal/incidents/102", json={"status": "resolved"},
        headers=auth(env, scope="incident:update", incident_id=102),
    )
    assert updated.status_code == 404
    bob = client.get(
        "/internal/incidents/102", headers=auth(env, user=2, scope="incident:read", incident_id=102)
    )
    assert bob.status_code == 200
    assert bob.json()["status"] == "open"


def test_grant_binds_scope_incident_and_expiry(env):
    client, _ = env
    url = "/internal/incidents/101"
    assert client.get(url, headers=auth(env, scope="incident:list", incident_id=101)).status_code == 403
    assert client.get(url, headers=auth(env, scope="incident:read", incident_id=102)).status_code == 403
    assert client.get(url, headers=auth(env, scope="incident:read")).status_code == 403
    assert client.get(url, headers=auth(env, scope="incident:read", incident_id=101, expired=True)).status_code == 401
    assert client.get(url, headers=auth(env, scope="incident:read", incident_id=101, audience="gateway")).status_code == 401
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = signed_grant(attacker_key, scope="incident:read", incident_id=101)
    assert client.get(url, headers=forged).status_code == 401


def test_roles_checked_against_database(env):
    client, _ = env
    wrong_role = auth(env, user=1, role="admin", scope="incident:list")
    assert client.get("/internal/incidents", headers=wrong_role).status_code == 401
    unknown_user = auth(env, user=999, scope="incident:list")
    assert client.get("/internal/incidents", headers=unknown_user).status_code == 401


def test_admin_reassignment_only_and_no_side_effects_on_denials(env):
    client, _ = env
    url = "/internal/incidents/102/assign"
    not_admin = client.patch(url, json={"owner_id": 1}, headers=auth(env, scope="incident:assign", incident_id=102))
    assert not_admin.status_code == 403
    assert owner(102) == 2
    admin_grant = auth(env, user=3, role="admin", scope="incident:assign", incident_id=102)
    invalid = client.patch(url, json={"owner_id": 999}, headers=admin_grant)
    assert invalid.status_code == 422
    assert owner(102) == 2
    approved = client.patch(url, json={"owner_id": 1}, headers=admin_grant)
    assert approved.status_code == 200
    assert owner(102) == 1


def test_report_creation_checks_owner_and_report_retrieval(env):
    client, _ = env
    bob_attempt = client.post(
        "/internal/incidents/102/reports", json={"content": "restricted"},
        headers=auth(env, scope="report:create", incident_id=102),
    )
    assert bob_attempt.status_code == 404
    assert count_reports() == 0
    created = client.post(
        "/internal/incidents/101/reports", json={"content": "Synthetic incident report"},
        headers=auth(env, scope="report:create", incident_id=101),
    )
    assert created.status_code == 201
    report_id = created.json()["id"]
    assert created.json()["requested_by"] == 1
    retrieval = client.get(
        f"/internal/incidents/101/reports/{report_id}",
        headers=auth(env, scope="report:read", incident_id=101),
    )
    assert retrieval.status_code == 200
    other = client.get(
        f"/internal/incidents/101/reports/{report_id}",
        headers=auth(env, user=2, scope="report:read", incident_id=101),
    )
    assert other.status_code == 404


def test_admin_overview_requires_admin(env):
    client, _ = env
    url = "/internal/admin/overview"
    assert client.get(url, headers=auth(env, scope="admin:overview")).status_code == 403
    response = client.get(url, headers=auth(env, user=3, role="admin", scope="admin:overview"))
    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert response.json()["by_severity"] == {"high": 1, "medium": 1}


def test_valid_update_and_invalid_body(env):
    client, _ = env
    headers = auth(env, scope="incident:update", incident_id=101)
    assert client.patch("/internal/incidents/101", json={}, headers=headers).status_code == 422
    assert client.patch("/internal/incidents/101", json={"owner_id": 2}, headers=headers).status_code == 422
    ok = client.patch("/internal/incidents/101", json={"status": "investigating"}, headers=headers)
    assert ok.status_code == 200
    assert ok.json()["status"] == "investigating"
