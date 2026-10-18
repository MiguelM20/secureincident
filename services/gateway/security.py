"""RS256 user tokens and short-lived, operation-scoped internal grants.

The signing key is loaded from an untracked runtime location. Gateway alone
holds the private key. Resource services verify with the public key and apply
resource ownership checks independently.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import jwt
from fastapi import HTTPException, Request

ISSUER = "secureincident"
GATEWAY_AUDIENCE = "gateway"
INCIDENT_AUDIENCE = "incident-service"
USER_TTL_SECONDS = 1800
GRANT_TTL_SECONDS = 120


def _keys() -> tuple[str, str]:
    private_path = os.environ.get("SECUREINCIDENT_PRIVATE_KEY_PATH")
    public_path = os.environ.get("SECUREINCIDENT_PUBLIC_KEY_PATH")
    if not private_path or not public_path:
        raise RuntimeError("Gateway signing and verification key paths must be configured")
    return (
        Path(private_path).read_text(encoding="utf-8"),
        Path(public_path).read_text(encoding="utf-8"),
    )


def check_keys() -> None:
    """Refuse to start when keys are missing or are not a matching RS256 pair."""
    private, public = _keys()
    sample = jwt.encode({"test": True}, private, algorithm="RS256")
    jwt.decode(sample, public, algorithms=["RS256"], options={"verify_aud": False})


def _claims(*, sub: str, role: str, audience: str, ttl_seconds: int,
            scope: str | None = None, incident_id: int | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": audience,
        "sub": sub,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "jti": uuid4().hex,
    }
    if scope is not None:
        claims["scope"] = scope
    if incident_id is not None:
        claims["incident_id"] = incident_id
    return claims


def sign_user_token(user_id: int, role: str) -> str:
    if type(user_id) is not int or user_id < 1 or role not in ("analyst", "admin"):
        raise ValueError("Invalid authenticated identity")
    private, _ = _keys()
    return jwt.encode(
        _claims(sub=str(user_id), role=role, audience=GATEWAY_AUDIENCE,
                ttl_seconds=USER_TTL_SECONDS),
        private,
        algorithm="RS256",
    )


def verify_user_token(request: Request) -> dict[str, Any]:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Missing user bearer token")
    _, public = _keys()
    try:
        claims = jwt.decode(
            token.strip(), public, algorithms=["RS256"],
            issuer=ISSUER, audience=GATEWAY_AUDIENCE,
            options={"require": ["iss", "aud", "sub", "role", "iat", "nbf", "exp", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired user token") from exc
    if (not isinstance(claims.get("sub"), str)
            or not claims["sub"].isdecimal()
            or int(claims["sub"]) < 1
            or claims.get("role") not in ("analyst", "admin")):
        raise HTTPException(status_code=401, detail="Invalid user token claims")
    return claims


def sign_internal_grant(*, scope: str, user: dict[str, Any] | None = None,
                        incident_id: int | None = None) -> str:
    if user is None:
        if scope != "auth:verify":
            raise ValueError("Only auth verification has a service-only grant")
        subject, role = "gateway-service", "service"
    else:
        subject, role = user["sub"], user["role"]
        if not str(subject).isdecimal() or role not in ("analyst", "admin"):
            raise ValueError("Invalid user authority")
        if scope == "auth:verify":
            raise ValueError("User cannot request authentication-service authority")
    if incident_id is not None and (type(incident_id) is not int or incident_id < 1):
        raise ValueError("Invalid incident resource")
    private, _ = _keys()
    return jwt.encode(
        _claims(sub=str(subject), role=role, audience=INCIDENT_AUDIENCE,
                ttl_seconds=GRANT_TTL_SECONDS, scope=scope, incident_id=incident_id),
        private, algorithm="RS256",
    )
