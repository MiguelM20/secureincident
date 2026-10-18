"""Public Gateway API; run on 127.0.0.1:8000 during local development.

Client-supplied identities and permissions are never trusted. Every call to
Incident Service carries a new, signed, short-lived operation grant.
"""

import os
import json
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .models import Credentials, IncidentAssign, IncidentCreate, IncidentStatus, IncidentUpdate
from .security import (USER_TTL_SECONDS, check_keys, sign_internal_grant,
                       sign_user_token, verify_user_token)


@asynccontextmanager
async def lifespan(_: FastAPI):
    check_keys()
    yield


app = FastAPI(title="SecureIncident: API Gateway", version="0.2.0", lifespan=lifespan)


def _upstream_url() -> str:
    return os.environ.get("INCIDENT_SERVICE_URL", "http://127.0.0.1:8001").rstrip("/")


async def _forward(request: Request, method: str, endpoint: str, *, grant: str,
                   body: dict[str, Any] | None = None,
                   params: dict[str, Any] | None = None) -> JSONResponse:
    """Contact the fixed internal service URL. Never take destination from user input.

    app.state.incident_transport is used only by isolated ASGI integration tests.
    The production setup leaves it unset and uses a normal network connection.
    """
    transport = getattr(request.app.state, "incident_transport", None)
    try:
        async with httpx.AsyncClient(base_url=_upstream_url(), transport=transport,
                                     timeout=5.0, follow_redirects=False) as client:
            response = await client.request(
                method, endpoint, headers={"Authorization": f"Bearer {grant}"},
                json=body, params=params,
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail="Incident Service unavailable") from exc
    if response.status_code >= 500 or response.status_code < 200 or 300 <= response.status_code < 400:
        raise HTTPException(status_code=502, detail="Incident Service error")
    try:
        content = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Invalid Incident Service response") from exc
    return JSONResponse(status_code=response.status_code, content=content)


async def _authorized_call(
    request: Request, method: str, endpoint: str, *, user: dict[str, Any],
    scope: str, incident_id: int | None = None, body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> JSONResponse:
    grant = sign_internal_grant(scope=scope, user=user, incident_id=incident_id)
    return await _forward(request, method, endpoint, grant=grant, body=body, params=params)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
async def login(body: Credentials, request: Request):
    grant = sign_internal_grant(scope="auth:verify")
    result = await _forward(
        request, "POST", "/internal/auth/verify", grant=grant,
        body=body.model_dump(),
    )
    if result.status_code != 200:
        # Do not disclose whether the username or password was wrong.
        raise HTTPException(status_code=401, detail="Invalid credentials")
    account = json.loads(result.body)
    try:
        token = sign_user_token(account["user_id"], account["role"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Invalid authentication-service response") from exc
    return {"access_token": token, "token_type": "bearer", "expires_in": USER_TTL_SECONDS}


@app.post("/incidents", status_code=201)
async def create_incident(body: IncidentCreate, request: Request,
                          user: dict = Depends(verify_user_token)):
    return await _authorized_call(
        request, "POST", "/internal/incidents", user=user, scope="incident:create",
        body=body.model_dump(),
    )


@app.get("/incidents")
async def list_incidents(
    request: Request,
    search: str = Query(default="", max_length=120),
    status: IncidentStatus | None = None,
    user: dict = Depends(verify_user_token),
):
    params = {"search": search}
    if status is not None:
        params["status"] = status
    return await _authorized_call(
        request, "GET", "/internal/incidents", user=user, scope="incident:list",
        params=params,
    )


@app.get("/incidents/{incident_id}")
async def read_incident(incident_id: int, request: Request,
                        user: dict = Depends(verify_user_token)):
    return await _authorized_call(
        request, "GET", f"/internal/incidents/{incident_id}", user=user,
        scope="incident:read", incident_id=incident_id,
    )


@app.patch("/incidents/{incident_id}")
async def update_incident(incident_id: int, body: IncidentUpdate, request: Request,
                          user: dict = Depends(verify_user_token)):
    return await _authorized_call(
        request, "PATCH", f"/internal/incidents/{incident_id}", user=user,
        scope="incident:update", incident_id=incident_id, body=body.model_dump(exclude_unset=True),
    )


@app.patch("/incidents/{incident_id}/assign")
async def reassign_incident(incident_id: int, body: IncidentAssign, request: Request,
                            user: dict = Depends(verify_user_token)):
    return await _authorized_call(
        request, "PATCH", f"/internal/incidents/{incident_id}/assign", user=user,
        scope="incident:assign", incident_id=incident_id, body=body.model_dump(),
    )


@app.get("/incidents/{incident_id}/reports/{report_id}")
async def read_report(incident_id: int, report_id: int, request: Request,
                      user: dict = Depends(verify_user_token)):
    return await _authorized_call(
        request, "GET", f"/internal/incidents/{incident_id}/reports/{report_id}",
        user=user, scope="report:read", incident_id=incident_id,
    )


@app.get("/admin/overview")
async def admin_overview(request: Request, user: dict = Depends(verify_user_token)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin permission required")
    return await _authorized_call(
        request, "GET", "/internal/admin/overview", user=user, scope="admin:overview",
    )
