# Gateway Service (Phase 2, step 2)

The Gateway is the user-facing FastAPI process. It verifies login credentials
through Incident Service's signed `auth:verify` endpoint, issues signed 30-minute
user JWTs and delegates each downstream operation using a separate **two-minute,
audience-specific, action-scoped** JWT. Incident Service always checks the
resource's stored owner, even after the signature and scope verify successfully.

## Python 3.12 local setup

From repository root:

```bash
source .venv/bin/activate
python -m pip install -r requirements-gateway.txt
```

Generate local signing keys only if you haven't previously done so:

```bash
python -m services.gateway.keygen
```

The generator refuses to overwrite existing keys. `runtime/` is ignored by Git.
If keys were already generated following Incident Service's README, reuse those.

Set environment variables in **each new terminal session** before starting a
service. Keep terminals 1 and 2 open simultaneously.

Terminal 1 (Incident Service):

```bash
source .venv/bin/activate
export SECUREINCIDENT_PUBLIC_KEY_PATH="$PWD/runtime/gateway-public.pem"
export INCIDENT_DB_PATH="$PWD/runtime/incident.db"
python -m services.incident_service.seed
uvicorn services.incident_service.app:app --host 127.0.0.1 --port 8001
```

Choose example passwords for Alice, Bob, and Admin during the first seed.
Existing seeded accounts will not be overwritten. If you forgot the example
passwords, remove only the untracked local dev database and re-seed.

Terminal 2 (Gateway Service):

```bash
source .venv/bin/activate
export SECUREINCIDENT_PRIVATE_KEY_PATH="$PWD/runtime/gateway-private.pem"
export SECUREINCIDENT_PUBLIC_KEY_PATH="$PWD/runtime/gateway-public.pem"
export INCIDENT_SERVICE_URL="http://127.0.0.1:8001"
uvicorn services.gateway.app:app --host 127.0.0.1 --port 8000
```

Visit `http://127.0.0.1:8000/docs` to test endpoints through Swagger.
Use `POST /auth/login` with an account and its synthetic password to get a
user token, then select **Authorize** in Swagger. For command-line testing:

```bash
curl -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"YOUR_SYNTHETIC_PASSWORD"}'
```

Copy the `access_token` from the response, then:

```bash
curl -H 'Authorization: Bearer PASTE_TOKEN_HERE' \
  http://127.0.0.1:8000/incidents
```

Alice should only see incident 101, Bob should only see incident 102.
Admin may see both. A request for another analyst's incident should respond
404. Report **generation** requires the third service and is not present yet.
Report **retrieval**, for previously stored reports, is supported already.

## Automated integration tests

```bash
python -m pytest tests/test_incident_service.py tests/test_gateway.py -v
```

These tests use a temporary database, keys, and an in-process HTTP transport
simulating the services' real HTTP interfaces. No production network or data
is needed. Later, Docker Compose and Jenkins will run the same flows with three
separate service processes in a fresh environment.

## Security notes

- Never commit `runtime/*.pem`, local databases, or real passwords.
- The Incident Service does not trust the gateway network as authorization.
- Only Gateway owns the private signing key. Both Gateway and Incident Service
  verify with the public key.
- Gateways are not inherently trusted: local signed grants are explicitly
  restricted by target service, action, incident, user identity, and expiry.
- Client-supplied `owner_id`, `role`, or `sub` are not accepted as authority.
- The Report Service, formatter package, Docker Compose, and Jenkins are
  subsequent milestones. Do not claim the assignment is complete yet.
