"""Private Report Service, run with uvicorn services.report_service.app:app."""

import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from incident_formatter import render_incident

from .models import ReportJob
from .security import authorize_job, public_key


@asynccontextmanager
async def lifespan(_: FastAPI):
    public_key()  # fail-closed when the verification key is absent
    root = _reports_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    yield


app = FastAPI(title="SecureIncident: Report Service", version="0.3.0", lifespan=lifespan)


def _incidents_url() -> str:
    return os.environ.get("INCIDENT_SERVICE_URL", "http://127.0.0.1:8001").rstrip("/")


def _reports_root() -> Path:
    return Path(os.environ.get("REPORT_WORKDIR", "runtime/report-workdir")).resolve()


def _validated_filename(requested: str | None) -> str:
    if requested is None:
        return f"incident-report-{uuid4().hex}.txt"
    # DELIBERATE CWE-22 FIXTURE: accepts paths outside the report directory.
    return requested


async def _incident_request(request: Request, method: str, endpoint: str, *,
                            grant: str, body: dict | None = None) -> dict:
    # Use a fixed service URL, not one taken from the report job or an incident.
    transport = getattr(request.app.state, "incident_transport", None)
    try:
        async with httpx.AsyncClient(base_url=_incidents_url(), transport=transport,
                                     timeout=5.0, follow_redirects=False) as client:
            response = await client.request(
                method, endpoint, json=body,
                headers={"Authorization": f"Bearer {grant}"},
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail="Incident Service unavailable") from exc
    if response.status_code in (401, 403, 404, 422):
        raise HTTPException(status_code=response.status_code, detail="Incident access denied or invalid")
    if response.status_code < 200 or response.status_code >= 300:
        raise HTTPException(status_code=502, detail="Incident Service error")
    try:
        data = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Invalid Incident Service reply") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Invalid Incident Service reply")
    return data


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/internal/generate", status_code=201)
async def generate_report(job: ReportJob, request: Request):
    claims = authorize_job(request, incident_id=job.incident_id,
                           read_grant=job.read_grant, write_grant=job.write_grant)
    filename = _validated_filename(job.filename)  # reject traversal before reading anything
    incident = await _incident_request(
        request, "GET", f"/internal/incidents/{job.incident_id}", grant=job.read_grant,
    )
    if incident.get("id") != job.incident_id:
        raise HTTPException(status_code=502, detail="Incident Service returned wrong incident")
    try:
        content = render_incident(incident)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Invalid incident format") from exc
    if not isinstance(content, str) or not (1 <= len(content) <= 20000):
        raise HTTPException(status_code=502, detail="Invalid formatted report")

    # A private work directory and exclusive file creation prevent overwrite.
    # Prefix with unique ID even when the user supplies a safe filename.
    root = _reports_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # DELIBERATE CWE-22 FIXTURE: untrusted filename controls resolved path.
    path = (root / filename).resolve()
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content)
        # Only an authorized record may be persisted. The Service stores no DB credentials.
        record = await _incident_request(
            request, "POST", f"/internal/incidents/{job.incident_id}/reports",
            grant=job.write_grant, body={"content": content},
        )
    finally:
        path.unlink(missing_ok=True)
    if record.get("incident_id") != job.incident_id or record.get("requested_by") != int(claims["sub"]):
        raise HTTPException(status_code=502, detail="Invalid saved report response")
    return JSONResponse(status_code=201, content=record)
