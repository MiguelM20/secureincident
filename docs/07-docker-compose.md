# Docker Compose deployment (Phase 2 step 4)

This local deployment runs **exactly three application services** as separate Docker containers: Gateway, Incident Service, and Report Service. SQLite is owned by the Incident Service; the formatter is installed as a Python package in the Report Service image. The three images are built independently.

## Requirements

- Docker Desktop running (Docker Engine with `docker compose` v2).
- From repository root, run `docker --version` and `docker compose version`.
- **Stop** earlier terminal-based Uvicorn processes on port 8000 (`Ctrl+C`).
- Do not store passwords, JWTs, or PEM files in the Git repository.

## First-time setup

Run every command **from the SecureIncident repository root**:

```bash
# 1. Verify Compose YAML and build three images
docker compose config -q
docker compose build

# 2. Initialize container-only RSA signing keys in named volumes.
#    Never repeat if the keys already exist.
docker compose run --rm --no-deps gateway python -m scripts.docker_init_keys

# 3. Seed a fresh container-only SQLite volume and three synthetic users.
#    Prompts for Alice, Bob, Admin passwords without displaying them.
docker compose run --rm --no-deps incident-service python -m services.incident_service.seed

# 4. Start all three application containers
docker compose up -d --no-build

# 5. Confirm all three containers are healthy
docker compose ps

# 6. Smoke-check the public Gateway (the only published service)
curl -i http://127.0.0.1:8000/health

# 7. Exercise actual report workflow from your LOCAL Python venv
source .venv/bin/activate
python scripts/verify_report_workflow.py
```

Use the **Docker-seeded Alice password** in step 7, which may differ from the original local Python deployment password. Expected smoke statuses: `201`, `404`, `422`, `200`. `docker compose ps` should show all three `healthy`.

Then open `http://127.0.0.1:8000/docs` for the public Gateway API documentation.

## Why the services are separated

| Container | Exposed to host? | Key access | Persistent state | Runtime communication |
|---|---|---|---|---|
| gateway | `127.0.0.1:8000` only | Private signing key and public key | Signing keys only | Incident Service and Report Service |
| incident-service | No | Public verification key (read-only) | SQLite `incident_data` volume | Gateway and Report Service |
| report-service | No | Public verification key (read-only) | None; report workdir in private tmpfs | Incident Service |

- The public Gateway belongs to both `edge` and internal `backend` Docker networks.
- The two other services belong **only** to the internal `backend` network and have no `ports` mapping.
- Requests between containers use Docker DNS (`incident-service:8001`, `report-service:8002`). **Never use `localhost` for cross-container requests.**
- The Reporter receives only scoped short-lived JWT grants, not signing credentials or direct DB access.
- Each container runs under UID/GID 10001 with a read-only root filesystem, dropped Linux capabilities, and `no-new-privileges`. The Incident Service alone has a writable SQLite volume; the Report Service has temporary writable space in `/tmp`.
- The gateway owns two signing-key volumes: `gateway_private_keys` with its private key, and `public_keys` with the corresponding verification key. Resource services mount **only** `public_keys:ro`.
- Images contain only their individual source trees. The formatter is installed into the Report Service image via `requirements-report.txt` using `packages/incident_formatter`.

## Re-running and cleaning up

```bash
docker compose down           # stops containers, keeps SQLite and key volumes
docker compose up -d          # reuses seeded database and keys
docker compose ps
docker compose logs --tail=80 gateway incident-service report-service
```

**Avoid `docker compose down -v` while preserving work.** The `-v` flag deletes the container signing keys, synthetic accounts, incidents, and reports. If you intentionally remove volumes, repeat initial key and account setup before `up`.

## Common problems

- `docker: command not found` or cannot connect to Docker daemon: install/start Docker Desktop.
- `port is already allocated` on 8000: stop the earlier terminal-based Gateway process.
- Missing signing keys: run `docker compose run --rm --no-deps gateway python -m scripts.docker_init_keys` once, **before** `up`. If one key exists but its pair is absent, examine volumes instead of overwriting an existing private key.
- Login fails despite the original local credentials: Docker's SQLite volume has separate accounts and seed passwords.
- A service is unhealthy: `docker compose logs --tail=100 <service>`; verify the key-generation and seed steps completed.
- Docker key/database data is intentionally **not** in the repository, source images, or build context.

## Security/testing evidence

Capture redacted output from `docker compose ps`, the four smoke test status codes, and the `docker compose config -q` result under `docs/evidence/`. Never capture JWTs or passwords. The isolated network and filesystem restrictions support least privilege, while the resource service still independently enforces authorization. In the report, distinguish deployment controls from application-layer authorization checks.

For later controlled vulnerability experiments, run separate Compose project instances (`docker compose -p secureincident-experiment ...`) with separate volumes. Do not add deliberately vulnerable code to the main release branch.

## Remaining production hardening

This is a **local educational deployment**, not a production release. A production design would require TLS/reverse proxy, secure secret management/rotation, approved image digests and artifact verification, auditable logging, operational monitoring, immutable image scanning, and real identity/account provisioning. Container network isolation does not replace authentication or authorization.
