# 03 - Assets, STRIDE threat model and security traceability

## Asset register

| Asset | Owner/service | Importance | Security objective |
|---|---|---|---|
| Incident description and status | Incident Service | High | Confidentiality and integrity by owner/role |
| Generated report content | Incident Service (stored), Report Service (in transit/temp) | High | Confidentiality, integrity, same-owner policy |
| Account/password hashes | Incident Service storage and restricted internal login verification | High | Secrets protected, reliable authentication |
| Gateway JWT private key | Gateway only | Critical | No token forgery or leaked signing key |
| Delegated service grants | Gateway created, downstream validated | High | Scoped, audience-limited, short lived |
| Audit evidence and test results | Local artifacts/Jenkins | Medium | Traceability, tamper awareness, redaction |
| Helper wheel and dependencies | Report Service build | Medium | Approved provenance, reproducible install |
| SQLite files | Incident Service only | High | No unauthorized direct writes/reads |

## STRIDE threats

| STRIDE | Threat / entry point | Trust assumption challenged | Planned control | Evidence / test |
|---|---|---|---|---|
| S: Spoofing | Forge `X-User` header or JWT at Gateway/Incident Service | Internal headers identify users | Verified signed tokens; fixed issuer, audience and algorithm | Reject unsigned/tampered/wrong-audience tokens |
| T: Tampering | Alice PATCHes Bob's incident ID | Known ID means permitted modification | Per-resource owner check before UPDATE | Bob's record unchanged for Alice |
| R: Repudiation | User denies altering an incident | No trace of who acted | Request ID and audit event with actor, action and result | Test/log sample with secrets redacted |
| I: Information disclosure | SQLi in search or report confused deputy returns Bob's case | User input remains data; trusted internal job has lawful authority | Parameterized SQL and bound delegated authorization | SQLi/foreign-case negative tests |
| D: Denial of service | Huge descriptions, unbounded report jobs | Inputs/job load are bounded | Schema size limits, bounded synchronous demo; document prod quotas/timeouts | Oversize payload rejected, app stays responsive |
| E: Elevation of privilege | `report-service` uses broad backend credentials to read any case | Service identity equals user authority | Separate `sub`, `aud`, `scope`, `incident_id`, TTL and owner check | Alice->Bob via report workflow is rejected |

Supply-chain exposure: formatter dependency is trusted during execution, so build pinning/approval and runtime permissions are relevant. The optional malicious-wheel exercise is deferred.

## Risk and priority rationale

- P1 (highest): unauthorized cross-user incident/report disclosure or modification (C/I). Directly violates assignment focus.
- P1: compromise of Gateway signing key: forged identity and broad authorizations. Protect key in configuration/secrets; downstream services get verification key only.
- P2: SQLi, path traversal and output corruption. Severity depends on accessible database/file privileges; containment matters.
- P2: resource exhaustion through oversized input; test schema limits and discuss production controls.
- P3: audit omissions and inconsistent error codes; fix before release if security evidence unreliable.

This is contextual prioritization, not a formal CVSS calculation. For the report, discuss likelihood, preconditions, affected assets, and impact instead of inventing precise scores.

## Asset -> threat -> requirement/control -> lifecycle -> evidence -> gate

| Asset and threat | Requirement/control | Lifecycle activity | Evidence | Gate decision |
|---|---|---|---|---|
| Bob's incident, unauthorized Alice read/update | Ownership checked at Incident Service | Requirements policy + coding + auth tests | `test_cross_user_*` reports | Block release if exposed/changed |
| Reports, confused deputy | Per-user, per-case, per-action grant through report workflow | Design trust boundary + integration tests | `test_report_cross_user_denied` | Block release on leaked content or saved report |
| Incidents, SQLi | Parameterized SQL and owner query scoping | Code review/static checks, integration tests | SQLi regression test; analyzer results | Block release on confirmed injection |
| Filesystem, path traversal | Generated safe filenames/path containment, restricted temp dir | Coding, negative filesystem tests | `test_export_path_escape_denied` | Block release on path escape |
| Identity, forged/replayed grant | Signed JWT checks `iss,aud,exp,nbf,scope,incident_id` | Implementation, unit/integration security tests | Invalid/expired token tests | Block release on authorization bypass |
| Wheel dependency, unapproved change | Declared package, pinned/approved dependencies, dependency scanning | Build, CI dependency analysis | Manifest/build log and pip-audit output | Block release on unapproved artifact/defined vulnerability findings |
