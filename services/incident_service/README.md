# Incident Service (Phase 2, step 1)

This is the **first** of three application processes. It owns user/incident/report
records in SQLite and checks signed, audience-specific internal JWT grants **and**
resource ownership. It does not issue grants. The Gateway (next step) will hold
the signing key, authenticate clients, and issue narrowly scoped grants. The
Report Service (later) will use grants to request case-specific operations.

## Local setup (Python 3.12)

From project root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-incident.txt
```

Install requires Internet access. For local startup, a JWT verification key must
exist. Generate an **untracked development-only keypair** using installed
`cryptography` (public key path given to Incident Service; private key will be
used only by Gateway later):

```bash
mkdir -p runtime
python - <<'PY'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
Path('runtime/gateway-private.pem').write_bytes(private_key.private_bytes(
    serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()
))
Path('runtime/gateway-public.pem').write_bytes(private_key.public_key().public_bytes(
    serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo
))
PY
export SECUREINCIDENT_PUBLIC_KEY_PATH="$PWD/runtime/gateway-public.pem"
export INCIDENT_DB_PATH="$PWD/runtime/incident.db"
python -m services.incident_service.seed
uvicorn services.incident_service.app:app --host 127.0.0.1 --port 8001
```

Choose **synthetic, local-only passwords** when prompted. The `runtime/` directory
is gitignored. Never commit signing keys or real credentials.

The Incident Service is deliberately not publicly exposed in the final Compose
configuration. For now, you can view liveness at `http://127.0.0.1:8001/health`.
Every `/internal/*` route needs a *signed* grant from Gateway, so ordinary curl
requests fail until Gateway is implemented. This is intentional.

## Security tests

```bash
python -m pytest tests/test_incident_service.py -v
```

Tests generate temporary RS256 keys and use isolated SQLite databases, and
cover both permitted and rejected requests. Their test signing key is separate
from the service's deployment key. Current status is a tested standalone
resource service, **not** a complete assignment or a complete production system.

## Main internal grants

- `auth:verify`: signed `sub=gateway-service`, `role=service`
- `incident:create`, `incident:list`: user-bound grants
- `incident:read`, `incident:update`, `incident:assign`: user-bound and `incident_id`-bound
- `report:create`, `report:read`: user-bound and `incident_id`-bound
- `admin:overview`: valid administrator only

Each scope is checked independently. Incident records are checked against the
stored owner regardless of the calling service.
