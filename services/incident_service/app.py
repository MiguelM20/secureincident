"""Protected resource service. Run with uvicorn services.incident_service.app:app.

All /internal endpoints use audience-specific signed grants, and every
resource action checks ownership against stored data.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import FastAPI, HTTPException, Query, Request

from .models import Credentials, IncidentAssign, IncidentCreate, IncidentStatus, IncidentUpdate, ReportCreate
from .security import current_actor, permitted_incident, require_scope, verified_grant
from .store import database, initialize_schema

_passwords = PasswordHasher()


@asynccontextmanager
async def lifespan(_: FastAPI):
    key_file = os.environ.get("SECUREINCIDENT_PUBLIC_KEY_PATH")
    if not key_file or not Path(key_file).is_file():
        raise RuntimeError("Set SECUREINCIDENT_PUBLIC_KEY_PATH to Gateway's JWT public key")
    initialize_schema()
    yield


app = FastAPI(title="SecureIncident: Incident Service", version="0.1.0", lifespan=lifespan)


def public_row(row):
    return dict(row)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/internal/auth/verify")
def verify_credentials(body: Credentials, request: Request):
    grant = verified_grant(request)
    require_scope(grant, "auth:verify")
    if grant.get("sub") != "gateway-service" or grant.get("role") != "service":
        raise HTTPException(status_code=403, detail="Gateway service authorization required")
    with database() as conn:
        user = conn.execute(
            "SELECT id, password_hash, role FROM users WHERE username = ?", (body.username,)
        ).fetchone()
        try:
            if user is None or not _passwords.verify(user["password_hash"], body.password):
                raise HTTPException(status_code=401, detail="Invalid credentials")
        except (VerificationError, InvalidHashError) as exc:
            raise HTTPException(status_code=401, detail="Invalid credentials") from exc
        return {"user_id": user["id"], "role": user["role"]}


@app.post("/internal/incidents", status_code=201)
def create_incident(body: IncidentCreate, request: Request):
    grant = verified_grant(request)
    require_scope(grant, "incident:create")
    with database() as conn:
        actor_id, _ = current_actor(grant, conn)
        cursor = conn.execute(
            "INSERT INTO incidents(owner_id,title,description,severity) VALUES(?,?,?,?)",
            (actor_id, body.title, body.description, body.severity),
        )
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (cursor.lastrowid,)).fetchone()
        return public_row(row)


@app.get("/internal/incidents")
def list_incidents(
    request: Request,
    search: str = Query(default="", max_length=120),
    status: IncidentStatus | None = None,
):
    grant = verified_grant(request)
    require_scope(grant, "incident:list")
    with database() as conn:
        actor_id, role = current_actor(grant, conn)
        sql = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if role != "admin":
            sql += " AND owner_id=?"
            params.append(actor_id)
        if search:
            sql += " AND (title LIKE ? OR description LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY id"
        return [public_row(row) for row in conn.execute(sql, params).fetchall()]


@app.get("/internal/incidents/{incident_id}")
def read_incident(incident_id: int, request: Request):
    grant = verified_grant(request)
    require_scope(grant, "incident:read", incident_id)
    with database() as conn:
        actor_id, role = current_actor(grant, conn)
        return public_row(permitted_incident(conn, incident_id, actor_id, role))


@app.patch("/internal/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, request: Request):
    grant = verified_grant(request)
    require_scope(grant, "incident:update", incident_id)
    with database() as conn:
        actor_id, role = current_actor(grant, conn)
        permitted_incident(conn, incident_id, actor_id, role)
        fields = body.model_dump(exclude_unset=True)
        setters = ", ".join(f"{field}=?" for field in fields)
        conn.execute(
            f"UPDATE incidents SET {setters}, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (*fields.values(), incident_id),
        )
        return public_row(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())


@app.patch("/internal/incidents/{incident_id}/assign")
def assign_incident(incident_id: int, body: IncidentAssign, request: Request):
    grant = verified_grant(request)
    require_scope(grant, "incident:assign", incident_id)
    with database() as conn:
        _, role = current_actor(grant, conn)
        if role != "admin":
            raise HTTPException(status_code=403, detail="Admin permission required")
        if conn.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        if conn.execute("SELECT 1 FROM users WHERE id=?", (body.owner_id,)).fetchone() is None:
            raise HTTPException(status_code=422, detail="Unknown owner")
        conn.execute(
            "UPDATE incidents SET owner_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (body.owner_id, incident_id),
        )
        return public_row(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())


@app.post("/internal/incidents/{incident_id}/reports", status_code=201)
def create_report(incident_id: int, body: ReportCreate, request: Request):
    grant = verified_grant(request)
    require_scope(grant, "report:create", incident_id)
    with database() as conn:
        actor_id, role = current_actor(grant, conn)
        permitted_incident(conn, incident_id, actor_id, role)
        cursor = conn.execute(
            "INSERT INTO reports(incident_id,requested_by,content) VALUES(?,?,?)",
            (incident_id, actor_id, body.content),
        )
        row = conn.execute("SELECT * FROM reports WHERE id=?", (cursor.lastrowid,)).fetchone()
        return public_row(row)


@app.get("/internal/incidents/{incident_id}/reports/{report_id}")
def get_report(incident_id: int, report_id: int, request: Request):
    grant = verified_grant(request)
    require_scope(grant, "report:read", incident_id)
    with database() as conn:
        actor_id, role = current_actor(grant, conn)
        permitted_incident(conn, incident_id, actor_id, role)
        row = conn.execute(
            "SELECT * FROM reports WHERE id=? AND incident_id=?", (report_id, incident_id)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return public_row(row)


@app.get("/internal/admin/overview")
def admin_overview(request: Request):
    grant = verified_grant(request)
    require_scope(grant, "admin:overview")
    with database() as conn:
        _, role = current_actor(grant, conn)
        if role != "admin":
            raise HTTPException(status_code=403, detail="Admin permission required")
        total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        by_status = {row["status"]: row["count"] for row in conn.execute(
            "SELECT status, COUNT(*) AS count FROM incidents GROUP BY status"
        )}
        by_severity = {row["severity"]: row["count"] for row in conn.execute(
            "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity"
        )}
        return {"total": total, "by_status": by_status, "by_severity": by_severity}
