# 05 - INITIAL SSDLC lifecycle plan - commit before feature development

Version: 0.1 (initial pre-implementation plan). Status: draft for review/first Git commit.

**Objective:** Build SecureIncident, a three-service Python application with user-owned incident and report resources, and demonstrate/fix three catalog weaknesses plus one cross-service composition flaw. Keep a full Git history with test evidence.

## Phase 1: Requirements (gate R)

Deliverables: scope and operation list; 2 main entity types; 3 seeded users with two roles; functional and non-functional requirements; asset register; architecture/data-flow diagram; trust boundaries; access-control matrix; STRIDE model; four vulnerability hypotheses and test expectations.

Review gate: every protected operation has an actor, asset, authorized action and enforcement point; design has three separate processes, one separately installed helper dependency, one three-service operation, clear attack boundaries and three named design principles. **Do not start feature implementation until this design is committed.**

## Phase 2: Implementation and build (gate B)

Deliverables: Python/FastAPI Gateway, Incident Service and Report Service as independently running processes; SQLite seeded synthetic data; helper wheel installed into Report Service via package metadata; Docker Compose; version-pinned dependencies; setup/run instructions.

Build gate: reproducible dependency resolution/build and declared install paths; reject unexpected/unapproved packages/artifacts; no embedded passwords/private keys in committed code; no direct Report Service database access. Record builds and dependency checks.

## Phase 3: Testing, investigation and fixes (gate T)

Deliverables: pytest positive functional tests and negative authorization tests; records of four vulnerable demonstrations using synthetic fixtures and vulnerable Git revisions; fixes and regression tests; Bandit static analysis; pip-audit dependency analysis; Jenkins pipeline running on pushes and PRs, starting a **fresh** Docker Compose test environment and archiving logs, JUnit XML and analysis results.

Test gate: no confirmed cross-user access, cross-user modification, path escape or SQL injection in final mainline; failures from malformed inputs are safe; report generation still completes for authorized user; configured high-confidence/high-severity static findings and known vulnerable dependencies fail the pipeline; required tests and scans all pass. Preserve expected-failing vulnerable-test evidence separately, never quietly weaken release gates to green-light it.

## Phase 4: Release, deploy and operation (gate O)

Deliverables: report discussion, not a public deployment. Discuss production differences: HTTPS/mTLS where relevant; secret manager and signing-key rotation; rate limiting and monitoring; stronger database deployment/backups; container sandbox hardening and strict network policy; dependency updates/provenance; error handling, audit retention, rollout/rollback and incident response.

Operation gate: no release without passing Phase B/T controls, plus human review of documented residual risks. As a university demo, run locally; do not publish intentionally vulnerable revisions.

## Planned Jenkins workflow

- Trigger: push and pull request (requires Jenkins SCM multibranch/webhook or configured polling in addition to the Jenkinsfile).
- Stage 1 checkout and validate project/dependency manifests.
- Stage 2 build/install services and wheel; enforce chosen dependency/artifact allow-list policy.
- Stage 3 run Bandit and pip-audit with machine-readable output.
- Stage 4 bring up new Compose environment with fresh database and temporary volumes; seed data.
- Stage 5 run pytest unit, API, functional, authorization, malformed-input and report end-to-end tests.
- Stage 6 archive JUnit XML, scan results, build logs and selected redacted service logs. Tear down fresh environment even if tests fail.

## Git milestones (suggested)

1. `docs: initial SSDLC plan and security architecture` **before app code**.
2. `feat: seed accounts and three working services`.
3. `feat: installable report formatter and authorized workflow`.
4. `test: document four controlled vulnerability demonstrations` (preserve vulnerable revisions with tags/branch and evidence).
5. `fix: restore ownership and scoped delegation across boundaries`.
6. `ci: enforce security tests and artifact publishing in Jenkins`.
7. `docs: final report, evidence links and AI-use declaration`.

## Report evidence mapping

- Requirements/design decisions -> initial docs commit.
- Authority flow -> architecture and sequence diagram + test logs.
- Principles -> relevant implementation commits and negative tests.
- Vulnerabilities -> vulnerable code commits, demonstrated behavior, corrective commits, regression tests.
- SSDLC/CI -> Jenkinsfile, console logs, JUnit/artifacts, failure/passing gate examples.
- Production discussion -> final report.
