# Report Service, Phase 2 step 3

This is the third separate application process. It receives a signed report-job grant
from Gateway, verifies that *both* delegated Incident Service grants refer to the same
user, case, role, and request, and reads/persists reports through the Incident Service.
It has **no database credentials or RSA private signing key**.

## Install from the project root

```bash
source .venv/bin/activate
python -m pip install -r requirements-report.txt
python -m pytest tests/test_incident_service.py tests/test_gateway.py tests/test_report_service.py -v
```

`./packages/incident_formatter` contains the separately installable formatter. For
an explicit wheel build (optional verification):

```bash
python -m pip wheel ./packages/incident_formatter --no-deps -w artifacts/wheels
```

## Run three processes (three terminals, all from repository root)

**Terminal 1, Incident Service** (after prior seeding):

```bash
source .venv/bin/activate
export SECUREINCIDENT_PUBLIC_KEY_PATH="$PWD/runtime/gateway-public.pem"
export INCIDENT_DB_PATH="$PWD/runtime/incident.db"
python -m uvicorn services.incident_service.app:app --host 127.0.0.1 --port 8001
```

**Terminal 2, Gateway Service**:

```bash
source .venv/bin/activate
export SECUREINCIDENT_PRIVATE_KEY_PATH="$PWD/runtime/gateway-private.pem"
export SECUREINCIDENT_PUBLIC_KEY_PATH="$PWD/runtime/gateway-public.pem"
export INCIDENT_SERVICE_URL="http://127.0.0.1:8001"
export REPORT_SERVICE_URL="http://127.0.0.1:8002"
python -m uvicorn services.gateway.app:app --host 127.0.0.1 --port 8000
```

**Terminal 3, Report Service**:

```bash
source .venv/bin/activate
export SECUREINCIDENT_PUBLIC_KEY_PATH="$PWD/runtime/gateway-public.pem"
export INCIDENT_SERVICE_URL="http://127.0.0.1:8001"
export REPORT_WORKDIR="$PWD/runtime/report-workdir"
python -m uvicorn services.report_service.app:app --host 127.0.0.1 --port 8002
```

Only the Gateway should be exposed outside the private application network in the
later Docker Compose setup. These loopback development ports are for local testing.

## Manual tests

- Log in as Alice at `http://127.0.0.1:8000/docs`, then **Authorize** with her JWT.
- Call `POST /incidents/101/reports` with `{}`. It should produce 201 and a stored report.
- Call `GET /incidents/101/reports/{report_id}` to retrieve it.
- Call `POST /incidents/102/reports` as Alice. It should return 404 with no stored report.
- Call `POST /incidents/101/reports` with `{"filename":"../escape.txt"}`. It should return 422.
- As Bob, case 102 should succeed. As Admin, either case should succeed.

Do not include bearer tokens, signing keys, or synthetic passwords in screenshots or Git
commits. Save redacted response evidence under `docs/evidence/`.

## Security and pending work

- Audience, exact action, incident ID, original user, and short expiration are checked.
- The Report Service cannot sign tokens or bypass the Incident Service owner check.
- The workdir is private; only validated `.txt` basenames are accepted, and
  temporary files are removed after the operation.
- The purposely vulnerable versions are **not** part of this normal release path.
  They will be introduced in isolated experiments with synthetic data later.
- Docker Compose, Jenkins, scanning, and documented vulnerability experiments are
  still required before assignment submission.
