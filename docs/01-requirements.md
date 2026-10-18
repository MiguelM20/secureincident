# 01 - Requirements and access policy

## Domain and purpose

SecureIncident is a local, synthetic incident-management system. Analysts create and investigate incident cases and request text reports. Administrators have explicitly broader oversight and reassignment permissions. The software must protect case ownership when calls move between independently running services.

## Actors

- `alice`: ordinary analyst; owns her seeded cases.
- `bob`: ordinary analyst; owns his seeded cases.
- `admin`: privileged administrator; may inspect or modify any case and reassign case ownership.
- `report-service`: internal service identity, not an ordinary user. It must not gain blanket rights to user-owned data merely because it is internal.

Accounts are pre-seeded in Incident Service SQLite; no account registration, email or public hosting. Gateway delegates password verification to a restricted Incident Service endpoint, and passwords are hashed with an established password-hashing library. Never store plaintext passwords or commit real secrets.

## Data model

**Incident**: `id` (integer), `owner_id`, `title`, `description`, `severity` (`low|medium|high|critical`), `status` (`open|investigating|resolved`), `created_at`, `updated_at`.

**Report**: `id`, `incident_id`, `requested_by`, `content` (synthetic text), `created_at`.

**User**: `id`, `username`, `password_hash`, `role` (`analyst|admin`). User exists to support authentication; Incident and Report are the two main functional entities.

## Functional requirements

| ID | Requirement | Acceptance criterion |
|---|---|---|
| FR-01 | Login | Seeded user logs in using password, receives time-limited signed token; bad password is rejected |
| FR-02 | Create incident | Authenticated user creates incident; server sets owner to authenticated identity |
| FR-03 | Browse incidents | Analyst sees only own incidents; admin sees all |
| FR-04 | Read/update incident | Analyst reads/updates own incident; cannot read/update another analyst's |
| FR-05 | Generate and retrieve report | Only authorized request generates a report; successful call crosses all three processes; report is owned by a case and retrieved with case authorization |
| FR-06 | Admin reassignment | Only admin reassigns `owner_id` to an existing user |
| FR-07 | Admin overview | Only admin views all-case severity/status counts |

## Non-functional and security requirements

| ID | Requirement | Evidence |
|---|---|---|
| NFR-01 | Three separate processes, communicating over HTTP | Docker Compose and integration test |
| NFR-02 | Incident Service exclusively owns the SQLite DB | Compose volumes/networks and source inspection |
| NFR-03 | Authorization is performed at protected resource boundary for every action | Cross-user negative tests |
| NFR-04 | Internal operations bind identity, action, specific resource and time | Token inspection tests: issuer, audience, scope, incident_id, expiration |
| NFR-05 | Deny invalid tokens, malformed inputs and unauthorized requests | pytest 401/403/404 and unchanged-state assertions |
| NFR-06 | Install own helper package independently, pin/declare dependencies | Package metadata and build logs |
| NFR-07 | Jenkins builds, analyzes dependencies/code, starts clean environment and archives test results | Jenkinsfile, JUnit and scan artifacts |
| NFR-08 | No dependency on production data or publicly accessible servers | Seed fixtures and local Compose configuration |
| NFR-09 | Logs omit secrets and identify request/action outcomes | Log assertions and evidence excerpts |

## Access-control matrix

| Action | Alice (analyst) | Bob (analyst) | Admin |
|---|---|---|---|
| Create incident owned by self | Allow | Allow | Allow |
| List or read own incidents | Allow | Allow | Allow |
| List/read others' incidents | Deny | Deny | Allow |
| Update own incident | Allow | Allow | Allow |
| Update others' incidents | Deny | Deny | Allow |
| Generate/retrieve report for own incident | Allow | Allow | Allow |
| Generate/retrieve report for others' incidents | Deny | Deny | Allow |
| Reassign ownership | Deny | Deny | Allow |
| See global overview | Deny | Deny | Allow |

Ownership is server-side. A user-supplied `owner_id` is ignored/rejected on incident creation. Updating status/severity/description does not include owner changes. Administrators use a dedicated reassignment operation.

## Three selected secure design principles

1. **Least privilege**: Report Service has no database credentials and receives only incident-specific read/report-write grants; test attempts to use grant on a different incident fail.
2. **Complete mediation**: Incident Service checks ownership and signed grants for each read/write, regardless of calling service; test Alice-to-Bob requests through both normal and report workflows fail.
3. **Fail-safe defaults**: Missing/expired/malformed grants and unknown operations deny access without state changes; assert 401/403/404 as applicable and unchanged database rows.

Additional principles: defence in depth (Gateway and Incident Service both check authorization), segmentation (internal services not publicly published), separation of duties (Admin-only reassignment).
