// SecureIncident local Jenkins multibranch pipeline.
// Run Jenkins as your macOS user so it can reach Docker Desktop.
pipeline {
    agent any
    options {
        timestamps()
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        timeout(time: 40, unit: 'MINUTES')
    }
    environment {
        PATH = "/opt/homebrew/bin:/usr/local/bin:${env.HOME}/.docker/bin:${env.PATH}"
    }
    stages {
        stage('Checkout and manifest validation') {
            steps {
                checkout scm
                sh '''#!/bin/bash
set -euo pipefail
rm -rf artifacts .jenkins-venv
mkdir -p artifacts
python3.12 --version
docker compose version
python3.12 ci/verify_manifests.py | tee artifacts/manifest-check.txt
'''
            }
        }
        stage('Build and install') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
python3.12 -m venv .jenkins-venv
. .jenkins-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --no-input -r requirements-incident.txt -r requirements-gateway.txt -r requirements-report.txt bandit pip-audit build
python -m pip check | tee artifacts/pip-check.txt
python -m pip wheel --no-deps ./packages/incident_formatter -w artifacts/wheels
python -m pip freeze --all > artifacts/resolved-packages.txt
'''
            }
        }
        stage('Security analysis') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
. .jenkins-venv/bin/activate
# Any HIGH severity, HIGH confidence Bandit finding fails this stage.
python -m bandit -r services -lll -iii -f json -o artifacts/bandit.json
# Any known vulnerable installed dependency fails this stage.
python -m pip_audit --local --format json --output artifacts/pip-audit.json
'''
            }
        }
        stage('Functional and security tests') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
. .jenkins-venv/bin/activate
python -m pytest tests -q --junitxml=artifacts/junit.xml 2>&1 | tee artifacts/pytest.txt
'''
            }
        }
        stage('Fresh Docker Compose integration') {
            steps {
                sh '''#!/bin/bash
set -euo pipefail
# Unique project name means no overlap with your personal Docker database/keys.
CI_PROJECT="sicci${BUILD_NUMBER}"
# Dynamic loopback host port means no collision with the usual :8000 demo.
SECUREINCIDENT_PORT="$((20000 + BUILD_NUMBER % 20000))"
export SECUREINCIDENT_PORT
cleanup() {
    docker compose -p "$CI_PROJECT" logs --no-color > artifacts/docker-logs.txt 2>&1 || true
    docker compose -p "$CI_PROJECT" down -v --remove-orphans > artifacts/docker-cleanup.txt 2>&1 || true
}
trap cleanup EXIT
# No secrets in source or persisted CI artifacts.
set +x
SEED_ALICE_PASSWORD="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(24))')"
SEED_BOB_PASSWORD="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(24))')"
SEED_ADMIN_PASSWORD="$(python3.12 -c 'import secrets; print(secrets.token_urlsafe(24))')"
export SEED_ALICE_PASSWORD SEED_BOB_PASSWORD SEED_ADMIN_PASSWORD

docker compose -p "$CI_PROJECT" config -q
docker compose -p "$CI_PROJECT" build > artifacts/docker-build.txt 2>&1
docker compose -p "$CI_PROJECT" run --rm --no-deps gateway python -m scripts.docker_init_keys > artifacts/docker-init.txt 2>&1
docker compose -p "$CI_PROJECT" run --rm --no-deps \
    -e SEED_ALICE_PASSWORD -e SEED_BOB_PASSWORD -e SEED_ADMIN_PASSWORD \
    incident-service python -m services.incident_service.seed >> artifacts/docker-init.txt 2>&1
docker compose -p "$CI_PROJECT" up -d --no-build --wait --wait-timeout 120 > artifacts/docker-up.txt 2>&1
docker compose -p "$CI_PROJECT" ps > artifacts/docker-ps.txt
SECUREINCIDENT_BASE_URL="http://127.0.0.1:${SECUREINCIDENT_PORT}" \
    .jenkins-venv/bin/python ci/smoke.py > artifacts/docker-smoke.txt 2>&1
'''
            }
        }
    }
    post {
        always {
            junit testResults: 'artifacts/junit.xml', allowEmptyResults: true
            archiveArtifacts artifacts: 'artifacts/**', allowEmptyArchive: true, fingerprint: true
        }
    }
}
