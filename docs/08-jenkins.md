# SecureIncident Jenkins setup (local macOS demo)

Jenkins LTS runs as a Homebrew service under the local macOS user. Docker Desktop supplies the Docker engine. Jenkins is not itself containerized.

## Pipeline job

1. Use Jenkins > New Item > **Multibranch Pipeline**, named `SecureIncident-CI`.
2. Under Branch Sources add **GitHub**. Owner: `MiguelM20`, repository: `secureincident`.
3. This is a private GitHub repository. Add a Jenkins credential for a fine-grained GitHub token with read-only access to repository Contents, Metadata and Pull Requests. Do not paste it into any source file.
4. Discover branches and **pull requests from origin**. Do not enable builds from untrusted forks while the local Jenkins service has Docker access.
5. Script path: `Jenkinsfile`. Save and run **Scan Multibranch Pipeline Now**.
6. Because Jenkins is only reachable on `localhost:8080`, GitHub webhooks cannot directly contact it. Configure **Scan Multibranch Pipeline Triggers > Periodically if not otherwise run** (for example every 5 minutes), enabling indexing of new pushes/PRs while Jenkins is running. This is polling rather than immediate webhook delivery. Document this limitation honestly in the report.

## macOS Jenkins prerequisites

- Homebrew service running: `brew services list` shows `jenkins-lts started`.
- Docker Desktop running, CLI available to Jenkins under `/opt/homebrew/bin`, `/usr/local/bin` or `$HOME/.docker/bin`.
- Python 3.12 executable available in PATH after adding `/opt/homebrew/bin`.
- `docker info` must succeed for the Jenkins macOS user.
- Jenkins needs network access to Python package indexes, GitHub and pip-audit's advisory data service.

## Release gates

- Direct dependencies are pinned in the three service requirements manifests. The formatter is the sole explicitly approved local package.
- `pip check`, Python compilation, and isolated wheel build must pass.
- Bandit blocks HIGH-severity / HIGH-confidence findings.
- pip-audit blocks known advisory findings; do not weaken the gate to get a green check.
- pytest must pass and emit JUnit XML.
- A fresh and separately named Docker Compose project must start all three components, run authorized and denied access checks, and be removed afterwards. The pipeline uses `secureincident-ci` volumes and host port 18080; it must not touch the default SecureIncident Compose environment.
- Archiving saves JUnit, Bandit output, pip-audit results, installed dependencies, helper wheel, and redacted Docker logs.

The Jenkinsfile is intentionally designed for local teaching use. It requires the repository to be trusted because build scripts and Compose have access to the user's Docker daemon. Do not offer this Docker-running builder to untrusted PRs.

## Local smoke test (optional)

To verify only the CI smoke script against a running dedicated test project, export `SECUREINCIDENT_SMOKE_URL` and `SECUREINCIDENT_SMOKE_PASSWORD` from disposable test credentials, then run `python scripts/ci_smoke.py`. Do not use production secrets or expose them in build logs.
