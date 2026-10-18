"""Verify delegation grants before any sensitive operation.

Only Gateway owns the RS256 signing private key. The Incident Service only
receives its public verification key and verifies every internal call.
"""

import os
from pathlib import Path
from typing import Any

import jwt
from fastapi import HTTPException, Request, status

ISSUER = "secureincident"
AUDIENCE = "incident-service"


def verified_grant(request: Request) -> dict[str, Any]:
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer grant")

    # A missing verification key is a deployment failure, never a reason to
    # allow a request. Startup validates the key's presence as well.
    public_key_path = os.environ.get("SECUREINCIDENT_PUBLIC_KEY_PATH", "")
    if not public_key_path:
        raise RuntimeError("SECUREINCIDENT_PUBLIC_KEY_PATH must be configured")
    public_key = Path(public_key_path).read_text(encoding="utf-8")
    try:
        claims = jwt.decode(
            token.strip(),
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["iss", "aud", "sub", "scope", "role", "iat", "nbf", "exp", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired grant") from exc
    if not isinstance(claims.get("scope"), str) or not isinstance(claims.get("role"), str):
        raise HTTPException(status_code=401, detail="Invalid grant claims")
    return claims


def require_scope(claims: dict[str, Any], scope: str, incident_id: int | None = None) -> None:
    if claims["scope"] != scope:
        raise HTTPException(status_code=403, detail="Grant does not permit this action")
    if incident_id is not None:
        # An incident grant must be explicitly bound to this resource.
        bound_id = claims.get("incident_id")
        if type(bound_id) is not int or bound_id != incident_id:
            raise HTTPException(status_code=403, detail="Grant does not permit this incident")


def current_actor(claims: dict[str, Any], conn: Any) -> tuple[int, str]:
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.isdecimal():
        raise HTTPException(status_code=401, detail="Invalid identity")
    user_id = int(sub)
    user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None or claims.get("role") != user["role"]:
        raise HTTPException(status_code=401, detail="Unknown or stale user authority")
    return user_id, user["role"]


def permitted_incident(conn: Any, incident_id: int, actor_id: int, role: str) -> Any:
    incident = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    # Hide whether somebody else's incident exists.
    if incident is None or (role != "admin" and incident["owner_id"] != actor_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
