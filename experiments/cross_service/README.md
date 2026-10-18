# Experiment 4: Cross-service authority amplification (confused deputy)

## Context
The three services continue to validate signature, scope, target incident and owner.
The flaw is **not** missing authorization in Incident Service: the public Gateway
mistakenly signs a report job and the two delegated operations as the seeded
**administrator (user ID 3)**, regardless of the identity of the authenticated requester.
The Report Service trusts these signed grants and accesses the resource as admin.
Gateway then returns that report to the ordinary analyst who requested it.

This experiment uses only a temporary SQLite fixture with Alice (ID 1),
Bob (ID 2), and the seeded admin (ID 3). Docker is stopped; do not start
vulnerable services on a network. Do not merge the vulnerable commit into main.

## Security assumption violated
The identity and permissions in a delegated job must represent the original
authenticated requester. A signed grant alone does not establish that the
sender was authorized to delegate that *identity*.

## Evidence
- Direct Alice GET of Bob's incident 102: HTTP 404.
- Alice requests a report for Bob's incident 102 via Gateway: HTTP 201.
- Stored report has `requested_by=3` (admin), even though Alice made the request.
- Restoring delegation to `user` causes the pre-existing isolation regression
test to pass: the same report request returns HTTP 404 and saves nothing.

## Root cause and control
Gateway used privileged ambient authority for ordinary user jobs; downstream
services did their checks against the incorrect delegated identity. Repair:
all job, read and write grants carry the authenticated subject and role,
with explicit audience, incident ID, request correlation ID and short expiry.
Each service independently validates scope, identity and stored ownership.

## Commands, from clean main
```
docker compose down
git switch -c experiment/cross-service
unzip -o secureincident_cross_service_experiment.zip -d .
git apply experiments/cross_service/vulnerable.patch
RUN_CROSS_SERVICE_EXPERIMENT=1 python -m pytest tests/test_cross_service_experiment.py -q -s
```
After committing the vulnerable state, restore it with:
```
git apply -R experiments/cross_service/vulnerable.patch
python -m pytest tests/test_report_service.py::test_alice_cannot_generate_bobs_report_and_no_side_effect -q
```
Preserve both commits on the experiment branch. The final main branch stays secure.
