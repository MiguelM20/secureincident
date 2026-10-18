"""End-to-end report workflow and security checks over three ASGI interfaces."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from incident_formatter import render_incident

from services.gateway.app import app as gateway_app
from services.gateway.security import sign_internal_grant
from services.incident_service.app import app as incident_app
from services.incident_service.seed import seed
from services.incident_service.store import database
from services.report_service.app import app as report_app


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Three independent ASGI apps with HTTP transports and a private temp database."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    monkeypatch.setenv("SECUREINCIDENT_PRIVATE_KEY_PATH", str(private_path))
    monkeypatch.setenv("SECUREINCIDENT_PUBLIC_KEY_PATH", str(public_path))
    monkeypatch.setenv("INCIDENT_DB_PATH", str(tmp_path / "db.sqlite"))
    monkeypatch.setenv("REPORT_WORKDIR", str(tmp_path / "workdir"))
    monkeypatch.setenv("INCIDENT_SERVICE_URL", "http://incident.test")
    monkeypatch.setenv("REPORT_SERVICE_URL", "http://reports.test")

    with TestClient(incident_app):
        seed({"alice": "alice-test-pass", "bob": "bob-test-pass", "admin": "admin-test-pass"})
        report_app.state.incident_transport = httpx.ASGITransport(app=incident_app)
        gateway_app.state.incident_transport = httpx.ASGITransport(app=incident_app)
        gateway_app.state.report_transport = httpx.ASGITransport(app=report_app)
        try:
            with TestClient(report_app) as report_client, TestClient(gateway_app) as gateway_client:
                yield gateway_client, report_client, tmp_path
        finally:
            del report_app.state.incident_transport
            del gateway_app.state.incident_transport
            del gateway_app.state.report_transport


def bearer(gateway: TestClient, name: str) -> dict[str, str]:
    response = gateway.post("/auth/login", json={
        "username": name, "password": f"{name}-test-pass",
    })
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def job_grants(case: int = 101, *, sub: str = "1", role: str = "analyst", request_id: str | None = None):
    user = {"sub": sub, "role": role}
    job_id = request_id or uuid4().hex
    return (
        sign_internal_grant(user=user, scope="report:generate", incident_id=case,
                            audience="report-service", request_id=job_id),
        sign_internal_grant(user=user, scope="incident:read", incident_id=case,
                            request_id=job_id),
        sign_internal_grant(user=user, scope="report:create", incident_id=case,
                            request_id=job_id),
    )


def direct_generate(report: TestClient, tokens: tuple[str, str, str], case: int = 101,
                    filename: str | None = None):
    job, read, write = tokens
    body = {"incident_id": case, "read_grant": read, "write_grant": write}
    if filename is not None:
        body["filename"] = filename
    return report.post("/internal/generate", headers={"Authorization": f"Bearer {job}"}, json=body)


def report_count() -> int:
    with database() as conn:
        return conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]


def test_third_service_and_formatter_package_render_synthetic_incident(setup):
    gateway, report, _ = setup
    assert report.get("/health").json() == {"status": "ok"}
    content = render_incident({
        "id": 5, "owner_id": 1, "title": "Synthetic case", "description": "Dummy data",
        "severity": "high", "status": "open",
    })
    assert "Incident ID: 5" in content
    assert "Dummy data" in content
    assert gateway.get("/health").status_code == 200


def test_alice_report_three_components_and_retrieval(setup):
    gateway, _, work = setup
    auth = bearer(gateway, "alice")
    result = gateway.post("/incidents/101/reports", headers=auth, json={})
    assert result.status_code == 201, result.text
    record = result.json()
    assert record["incident_id"] == 101 and record["requested_by"] == 1
    assert "Suspicious authentication" in record["content"]
    saved = gateway.get(f"/incidents/101/reports/{record['id']}", headers=auth)
    assert saved.status_code == 200
    assert saved.json()["content"] == record["content"]
    assert report_count() == 1
    assert list((work / "workdir").glob("*.txt")) == []


def test_alice_cannot_generate_bobs_report_and_no_side_effect(setup):
    gateway, _, _ = setup
    auth = bearer(gateway, "alice")
    assert gateway.get("/incidents/102", headers=auth).status_code == 404
    result = gateway.post("/incidents/102/reports", headers=auth, json={})
    assert result.status_code == 404, result.text
    assert "Suspicious" not in result.text
    assert report_count() == 0


def test_bob_and_admin_can_generate_authorized_reports(setup):
    gateway, _, _ = setup
    bob = gateway.post("/incidents/102/reports", headers=bearer(gateway, "bob"), json={})
    assert bob.status_code == 201
    assert bob.json()["requested_by"] == 2
    admin = gateway.post("/incidents/102/reports", headers=bearer(gateway, "admin"), json={})
    assert admin.status_code == 201
    assert admin.json()["requested_by"] == 3
    assert report_count() == 2


def test_path_traversal_denied_with_no_write_or_report(setup):
    gateway, _, work = setup
    marker = work / "marker.txt"
    marker.write_text("unchanged", encoding="utf-8")
    for filename in ("../marker.txt", "/tmp/out.txt", "../escape.txt", "x/hi.txt", "..\\evil.txt"):
        result = gateway.post("/incidents/101/reports", headers=bearer(gateway, "alice"),
                              json={"filename": filename})
        assert result.status_code == 422, (filename, result.text)
    assert marker.read_text(encoding="utf-8") == "unchanged"
    assert report_count() == 0
    assert list((work / "workdir").glob("*.txt")) == []


def test_valid_optional_filename_works_without_file_left_over(setup):
    gateway, _, work = setup
    result = gateway.post("/incidents/101/reports", headers=bearer(gateway, "alice"),
                          json={"filename": "case_101.txt"})
    assert result.status_code == 201
    assert report_count() == 1
    assert list((work / "workdir").glob("*.txt")) == []


def test_missing_job_token_rejected(setup):
    _, report, _ = setup
    _, reader, writer = job_grants()
    result = report.post("/internal/generate", json={
        "incident_id": 101, "read_grant": reader, "write_grant": writer,
    })
    assert result.status_code == 401
    assert report_count() == 0


def test_different_user_or_case_in_grant_rejected(setup):
    _, report, _ = setup
    job, reader, writer = job_grants()
    mixed_writer = sign_internal_grant(
        user={"sub": "2", "role": "analyst"}, scope="report:create",
        incident_id=101, request_id=jwt.decode(
            job, options={"verify_signature": False})["request_id"],
    )
    assert direct_generate(report, (job, reader, mixed_writer)).status_code == 403
    wrong_case = job_grants(case=102)
    assert direct_generate(report, wrong_case, case=101).status_code == 403
    assert report_count() == 0


def test_different_request_id_rejected(setup):
    _, report, _ = setup
    job, reader, writer = job_grants()
    other = sign_internal_grant(user={"sub": "1", "role": "analyst"},
                                scope="incident:read", incident_id=101,
                                request_id=uuid4().hex)
    assert direct_generate(report, (job, other, writer)).status_code == 403
    assert report_count() == 0


def test_expired_grant_rejected(setup):
    _, report, tmp = setup
    job, reader, writer = job_grants()
    old_claims = jwt.decode(job, options={"verify_signature": False})
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    old_claims.update({"iat": past, "nbf": past, "exp": past + timedelta(seconds=30)})
    private = (tmp / "private.pem").read_text()
    expired_job = jwt.encode(old_claims, private, algorithm="RS256")
    assert direct_generate(report, (expired_job, reader, writer)).status_code == 401
    assert report_count() == 0


def test_report_service_will_not_accept_user_token_as_job_grant(setup):
    gateway, report, _ = setup
    user_token = bearer(gateway, "alice")["Authorization"].split(" ", 1)[1]
    _, reader, writer = job_grants()
    assert direct_generate(report, (user_token, reader, writer)).status_code == 401
    assert report_count() == 0


def test_formatter_normalizes_untrusted_metadata(setup):
    formatted = render_incident({
        "id": 101, "owner_id": 1, "title": "Alert\nOwner ID: 999",
        "description": "Untrusted\nNew line", "severity": "low", "status": "open",
    })
    assert "Title: Alert Owner ID: 999" in formatted
    assert "\nOwner ID: 999" not in formatted


def test_invalid_report_service_response_maps_to_gateway_error(setup):
    gateway, _, _ = setup
    gateway_app.state.report_transport = httpx.MockTransport(
        lambda _: httpx.Response(502, json={"detail": "upstream error"})
    )
    result = gateway.post("/incidents/101/reports", headers=bearer(gateway, "alice"), json={})
    assert result.status_code == 502
    assert report_count() == 0
