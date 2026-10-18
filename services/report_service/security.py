"""Report Service token verification, no signing keys or privileged credentials."""

import os
from pathlib import Path
from typing import Any

import jwt
from fastapi import HTTPException, Request

ISSUER = "secureincident"
REPORT_AUDIENCE = "report-service"
INCIDENT_AUDIENCE = "incident-service"
REQUIRED_CLAIMS = ["iss", "aud", "sub", "scope", "role", "iat", "nbf", "exp", "jti",
                   "incident_id", "request_id"]


def public_key() -> str:
    key_path = os.environ.get("SECUREINCIDENT_PUBLIC_KEY_PATH", "")
    if not key_path or not Path(key_path).is_file():
        raise RuntimeError("Set SECUREINCIDENT_PUBLIC_KEY_PATH to Gateway's public key")
    return Path(key_path).read_text(encoding="utf-8")


def _decode(token: str, *, audience: str, scope: str, incident_id: int) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token, public_key(), algorithms=["RS256"], issuer=ISSUER,
            audience=audience, options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired report grant") from exc
    if claims.get("scope") != scope:
        raise HTTPException(status_code=403, detail="Grant scope does not permit operation")
    if type(claims.get("incident_id")) is not int or claims["incident_id"] != incident_id:
        raise HTTPException(status_code=403, detail="Grant is bound to another incident")
    if (not isinstance(claims.get("sub"), str) or not claims["sub"].isdecimal()
            or int(claims["sub"]) < 1 or claims.get("role") not in ("analyst", "admin")):
        raise HTTPException(status_code=401, detail="Invalid report actor")
    request_id = claims.get("request_id")
    if (not isinstance(request_id, str) or len(request_id) != 32
            or any(c not in "0123456789abcdef" for c in request_id)):
        raise HTTPException(status_code=401, detail="Invalid report request binding")
    return claims


def authorize_job(request: Request, *, incident_id: int, read_grant: str,
                  write_grant: str) -> dict[str, Any]:
    authorization = request.headers.get("authorization", "")
    scheme, _, job_token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not job_token.strip():
        raise HTTPException(status_code=401, detail="Missing report job grant")
    job = _decode(job_token.strip(), audience=REPORT_AUDIENCE,
                  scope="report:generate", incident_id=incident_id)
    reader = _decode(read_grant, audience=INCIDENT_AUDIENCE,
                     scope="incident:read", incident_id=incident_id)
    writer = _decode(write_grant, audience=INCIDENT_AUDIENCE,
                     scope="report:create", incident_id=incident_id)
    # Tokens signed for different users, cases, roles or requests cannot be mixed.
    for grant in (reader, writer):
        if any(grant[field] != job[field] for field in ("sub", "role", "incident_id", "request_id")):
            raise HTTPException(status_code=403, detail="Mismatched delegated authority")
    return job
