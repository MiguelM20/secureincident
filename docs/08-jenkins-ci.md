# Jenkins CI: minimal required university setup

This CI runs on the macOS Jenkins agent with access to Docker Desktop. It does not require Docker-in-Docker or mounting the host Docker socket inside the Jenkins container. Keep Jenkins local and do not expose it publicly without authentication/TLS. **The Jenkinsfile alone does not configure triggers.**

## One-time Mac setup

1. Stop any manually launched Docker Compose demo only if port conflicts occur (CI uses another port, so normally this is unnecessary). Verify `python3.12 --version`, `docker compose version` in a new Terminal.
2. Install Jenkins LTS via Homebrew: `brew install jenkins-lts`, then `brew services start jenkins-lts`. Open `http://localhost:8080`. Read the unlock password from the location printed by Jenkins or its Homebrew startup instructions. Complete the setup and create an admin account.
3. Install plugins: **Pipeline**, **Git**, **GitHub Branch Source**, **Credentials**, **JUnit**, and **Pipeline: Multibranch** (some come with suggested plugins). Restart if Jenkins requests it.
4. In Jenkins credentials, add a **fine-grained GitHub token** scoped to the private `MiguelM20/secureincident` repository: Contents read and Pull Requests read (Metadata read is implicit). Store as a Secret text credential and select it in GitHub Branch Source, or follow the plugin's required credential format. Never commit or paste the token into the Jenkinsfile.
5. Create a **Multibranch Pipeline** job named `secureincident` with GitHub Branch Source, repository `MiguelM20/secureincident`, `Jenkinsfile` as Script Path, and **discover branches + PRs** as behaviors. Use the appropriate credentials to clone the private repository. Save and scan the repository.
6. The preferred automatic trigger is a GitHub webhook delivered to Jenkins `/github-webhook/` at a reachable, authenticated endpoint. A localhost Jenkins server is not reachable by GitHub. For the classroom demo without a public endpoint, enable **periodic branch indexing (every 1–2 minutes)** on the Multibranch job, and select **build upon discovered revision changes**. Indexing approximates push/PR builds and might coalesce rapid pushes. Test one push and one PR separately, and save the build evidence. A webhook is required if the rubric strictly demands an individual run for *every* event.

## Pipeline gates

- **Manifest:** approved direct requirements pinned, installable local wheel package declared.
- **Build:** installs the three service dependency sets, builds the formatter wheel, records resolved packages, checks installed dependency consistency.
- **Security:** Bandit HIGH severity + HIGH confidence findings fail; pip-audit known vulnerable installed dependencies fail (with machine-readable artifacts).
- **Tests:** pytest positive/negative checks, auth, cross-user, and invalid-input tests, saved as JUnit XML.
- **Fresh Compose:** distinct project/volumes, new signing keys, new synthetic seeded accounts, three healthy containers, HTTP report and cross-user tests, then `down -v` of **only** the CI project.
- **Artifacts:** results from checks, scans, tests, Compose logs; all included in Jenkins build artifacts. No passwords or JWTs written in the logs.

## Notes and known limits

- The CI pipeline *does* destroy **its own temporary CI volumes**, not the normal `secureincident` Docker Compose volumes. Do not change the CI project name to the default.
- The one-line change to `compose.yaml` allows `SECUREINCIDENT_PORT` to vary, while keeping local default port 8000.
- `bandit` and `pip-audit` use unpinned CI tool versions (direct application dependencies remain pinned). To fully reproduce the CI tool environment for production, pin tool versions and hash-lock all transitive dependencies. Our educational gate validates declared direct dependencies and produces resolved-package evidence; it is not a cryptographic supply-chain provenance system.
- Save a screenshot of the green Jenkins build and download `artifacts/` as evidence. Also demonstrate a red gate using a harmless intentionally failing test on a temporary branch, or explain the release rules and provide the Jenkins result in the report.
- If Jenkins cannot access Docker Desktop, run it as the logged-in macOS user and verify PATH includes `/opt/homebrew/bin`, `/usr/local/bin` and `$HOME/.docker/bin`. If you installed Jenkins under a different service account, that account needs Docker Desktop engine access.
