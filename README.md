# SecureIncident | Software Security Assignment I

**Status:** Secure baseline complete, four controlled vulnerability experiments documented, and Jenkins CI verified.

SecureIncident is a three-service Python incident-management demonstration. Analysts manage their own incidents and generate reports; an administrator can oversee and reassign incidents. Three independent FastAPI processes communicate over HTTP. The Incident Service owns all SQLite data and enforces resource-level authorization. The Report Service uses a separate, installable formatter package. All demonstration accounts and data are synthetic.

## Project structure

- `services/gateway/`: Public API, authentication and user-bound JWT delegation.
- `services/incident_service/`: SQLite incident/report store and resource authorization.
- `services/report_service/`: Report generation, case-specific grant checks and safe temporary files.
- `packages/incident_formatter/`: Independently buildable Python wheel installed by Report Service.
- `compose.yaml`, `docker/`: Three isolated container services with separate volumes and public/private keys.
- `tests/`: Functional, authorization, deployment and optional experiment tests.
- `experiments/`: Four local-only vulnerability patches and experiment instructions.
- `docs/`: Requirements, access matrix, architecture, STRIDE, SSDLC plan, CI instructions, evidence and report.
- `diagrams/`: Data-flow and report sequence diagrams.
- `Jenkinsfile`: CI build, dependency/static analysis, tests, fresh Docker integration and archived evidence.

## Prerequisites

- Python 3.12 and `pip`; Git.
- Docker Desktop with Docker Compose v2 for the container demonstration.
- Jenkins LTS for the local CI demonstration (Homebrew on macOS).

## Local Python test setup

From the repository root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-incident.txt -r requirements-gateway.txt -r requirements-report.txt
python -m pytest tests/ -q
```

The expected secure baseline is **39 passed, 4 skipped**. The skipped tests are the four **exploit demonstration** tests, which require isolated vulnerable fixtures and an explicit experiment environment flag. Do not enable them in ordinary CI runs.

## Build, seed and run using Docker Compose

Run these commands in order from the repository root, with Docker Desktop running:

```bash
docker compose config -q
docker compose build
# Only the first time, with empty named volumes:
docker compose run --rm --no-deps gateway python -m scripts.docker_init_keys
docker compose run --rm --no-deps incident-service python -m services.incident_service.seed
docker compose up -d --no-build
docker compose ps
```

The seed command prompts for **synthetic** passwords for `alice`, `bob` and `admin`. The first initialization creates separate RSA keys in Docker named volumes. The services use different processes/containers. Gateway publishes only `127.0.0.1:8000`, while Incident Service and Report Service remain internal. The signing private key is mounted only in Gateway. **Do not commit passwords or keys.**

Visit the Gateway's Swagger UI at <http://127.0.0.1:8000/docs>. With the local virtual environment active and all three Docker services running, verify the complete workflow:

```bash
python scripts/verify_report_workflow.py
```

The script prompts for Alice's Docker-seeded password. Expected HTTP codes: own report creation `201`, denial of Bob's incident `404`, invalid filename `422`, authorized report retrieval `200`.

Stop containers but retain demonstration data with:

```bash
docker compose down
```

Avoid `docker compose down -v` unless you intend to delete the demo's keys, users, incidents and reports. See `docs/07-docker-compose.md` for recovery instructions.

## Four intentionally planted vulnerabilities

Each experiment runs only in an isolated synthetic pytest fixture. The vulnerable revision and its fix are preserved in Git history, with a patch, explanation, executable test and evidence log in these directories:

1. `experiments/sql_injection/` - CWE-89: unsafe incident search exposed Bob's data to Alice.
2. `experiments/missing_authorization/` - CWE-862: skipping incident ownership checks permitted an unauthorized update.
3. `experiments/path_traversal/` - CWE-22: unsafe report filename escaped the approved working directory.
4. `experiments/cross_service/` - confused deputy: Gateway delegated administrator identity for Alice's report request.

Read each experiment's README **before** applying a vulnerable patch. The final `main` branch contains the repaired service code. Evidence files are in `docs/evidence/`.

## Secure design, SSDLC and report

- Functional requirements and access-control matrix: `docs/01-requirements.md`.
- Interfaces, JWT delegation and boundaries: `docs/02-architecture-and-interfaces.md`.
- Assets and STRIDE model: `docs/03-threat-model.md`.
- Initial pre-implementation SSDLC commit: `954b51d`, described in `docs/05-initial-ssdlc-plan.md`.
- Final report: `docs/09-final-report.md`, `docs/09-final-report.docx` and `docs/09-final-report.pdf`. Review the Word/PDF submission copy and add your identification details if required.
- AI-use declaration draft: `docs/10-ai-use-declaration.md`. Review and adapt in accordance with university policy before submission.

## Jenkins CI/CD

The repository includes a `Jenkinsfile` for Jenkins Multibranch Pipeline jobs. It validates pinned direct dependencies, builds the formatter wheel, runs `pip check`, Bandit and pip-audit, runs pytest with JUnit XML, creates a **fresh** `secureincident-ci` Docker environment on port 18080, performs six HTTP security/functional smoke checks, archives scan and test artifacts, and tears down its disposable Docker volumes.

A local Jenkins LTS run succeeded as **Build #4** after merging the experiment evidence. The saved repository evidence includes `jenkins-build-4.png`, `pytest-results.xml`, `bandit.json`, `pip-audit.json`, `docker-smoke.txt` and `docker-status.txt`. The saved JUnit results show 39 tests with zero failures; the locally executed full suite reported four skipped experiment tests. Known dependency advisories block the pipeline, as demonstrated by earlier failed builds before upgrading affected dependencies.

As the Jenkins instance runs only on localhost, immediate GitHub webhook delivery is not available by default. Configure **Scan Multibranch Pipeline Triggers** for periodic indexing to pick up branch pushes and PRs while Jenkins is running, or provide a reachable webhook endpoint. The successful build verifies the stages, not an externally delivered webhook.

## Security and scope limitations

This is **not** a public/production service. It uses synthetic records and locally generated development credentials. The helper package is installable and tested, but the optional malicious dependency supply-chain experiment was not performed. A production release would require TLS, secrets management/key rotation, monitoring and audit retention, backup/recovery, image digest pinning and a controlled deployment process.
