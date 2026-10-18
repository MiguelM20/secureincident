SecureIncident Jenkins step 5
============================

Extract into your existing secureincident Git repository. This adds Jenkinsfile,
ci/verify_manifests.py, ci/smoke.py, docs/08-jenkins-ci.md and updates compose.yaml
with an optional SECUREINCIDENT_PORT override (default remains 8000).

Before installing Jenkins, run from the project root:
  python3.12 ci/verify_manifests.py
  docker compose config -q
  python -m pytest tests/ -q

Then follow docs/08-jenkins-ci.md to install Jenkins and configure the
multibranch pipeline and GitHub triggers.

Do not commit passwords, signing keys, access tokens or local databases.
