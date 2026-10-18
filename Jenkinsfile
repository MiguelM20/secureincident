// SecureIncident educational CI on macOS (Homebrew Jenkins + Docker Desktop).
// Only run this pipeline for trusted repository branches and pull requests.
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 45, unit: 'MINUTES')
        skipDefaultCheckout(true)
    }

    environment {
        // Do not use the default Compose project: preserve any local demonstration data.
        COMPOSE_PROJECT_NAME = 'secureincident-ci'
        SECUREINCIDENT_PORT = '18080'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p artifacts'
            }
        }

        stage('Build and validate dependencies') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
export PATH="$HOME/.docker/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# Reject any unlisted direct requirement or unpinned direct PyPI dependency.
python3.12 - <<'PY'
from pathlib import Path
import re
files = ('requirements-gateway.txt', 'requirements-incident.txt', 'requirements-report.txt')
pattern = re.compile(r'^[A-Za-z0-9_.-]+(?:\\[[A-Za-z0-9_,.-]+\\])?==[0-9][A-Za-z0-9.+-]*$')
for filename in files:
    for raw in Path(filename).read_text().splitlines():
        entry = raw.strip()
        if not entry or entry.startswith('#'):
            continue
        if filename == 'requirements-report.txt' and entry == './packages/incident_formatter':
            continue
        if not pattern.fullmatch(entry):
            raise SystemExit(f'Unapproved or unpinned direct dependency in {filename}: {entry}')
print('Direct dependency manifests validated')
PY

python3.12 -m venv .ci-venv
source .ci-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-incident.txt -r requirements-gateway.txt -r requirements-report.txt
python -m pip install bandit pip-audit build
python -m pip check
python -m compileall -q services scripts packages/incident_formatter/src
python -m build --wheel --outdir artifacts/wheels packages/incident_formatter
python -m pip freeze > artifacts/installed-dependencies.txt
'''
            }
        }

        stage('Static and dependency analysis') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
source .ci-venv/bin/activate
# Release gate: high-severity, high-confidence Bandit findings are blocking.
bandit -r services scripts packages/incident_formatter/src -lll -iii -f json -o artifacts/bandit.json
# Release gate: any known advisory in the installed environment is blocking.
pip-audit --local --format json --output artifacts/pip-audit.json
'''
            }
        }

        stage('Python functional and authorization tests') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
source .ci-venv/bin/activate
python -m pytest tests/ -q --junitxml=artifacts/pytest-results.xml | tee artifacts/pytest-console.txt
'''
            }
        }

        stage('Fresh Docker integration test') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
export PATH="$HOME/.docker/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
source .ci-venv/bin/activate
# These credentials exist only for the disposable CI Compose project.
export SEED_ALICE_PASSWORD="$(openssl rand -hex 18)"
export SEED_BOB_PASSWORD="$(openssl rand -hex 18)"
export SEED_ADMIN_PASSWORD="$(openssl rand -hex 18)"
export SECUREINCIDENT_SMOKE_PASSWORD="$SEED_ALICE_PASSWORD"
export SECUREINCIDENT_SMOKE_URL="http://127.0.0.1:${SECUREINCIDENT_PORT}"

docker info >/dev/null
docker compose -p "$COMPOSE_PROJECT_NAME" config -q
docker compose -p "$COMPOSE_PROJECT_NAME" build
docker compose -p "$COMPOSE_PROJECT_NAME" run --rm --no-deps gateway python -m scripts.docker_init_keys
docker compose -p "$COMPOSE_PROJECT_NAME" run --rm --no-deps \
    -e SEED_ALICE_PASSWORD -e SEED_BOB_PASSWORD -e SEED_ADMIN_PASSWORD \
    incident-service python -m services.incident_service.seed
docker compose -p "$COMPOSE_PROJECT_NAME" up -d --no-build --wait
python scripts/ci_smoke.py | tee artifacts/docker-smoke.txt
docker compose -p "$COMPOSE_PROJECT_NAME" ps > artifacts/docker-status.txt
'''
            }
        }
    }

    post {
        always {
            // Always tear down this dedicated disposable CI environment only.
            sh '''#!/bin/bash
set +e
export PATH="$HOME/.docker/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
mkdir -p artifacts
docker compose -p secureincident-ci logs --no-color > artifacts/docker-logs.txt 2>&1
docker compose -p secureincident-ci down -v --remove-orphans
exit 0
'''
            junit allowEmptyResults: true, testResults: 'artifacts/pytest-results.xml'
            archiveArtifacts allowEmptyArchive: true, artifacts: 'artifacts/**'
        }
    }
}
