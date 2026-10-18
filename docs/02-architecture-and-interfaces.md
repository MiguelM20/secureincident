# 02 - Architecture, interfaces and trust boundaries

## Components and responsibilities

**Gateway (Python FastAPI, separate process):** The only publicly exposed service. Receives login credentials and asks Incident Service to verify them through a restricted internal authentication endpoint; issues user tokens after successful verification, validates inbound tokens, performs basic input validation and orchestrates actions. It is the sole signer of delegated internal JWTs. It does not directly read or write Incident Service's SQLite database.

**Incident Service (Python FastAPI, separate process):** Owns SQLite, the User/Incident/Report data, ownership policy, and all sensitive resource reads/writes. It validates signed audience-specific internal grants and rechecks resource permissions using the stored owner. Returns only authorized data. It never assumes private network location means authorization.

**Report Service (Python FastAPI, separate process):** Accepts a report-generation job token from the Gateway, validates the job's incident identity, requests that incident via a second, audience-restricted delegated grant, invokes the installable formatter package, and posts the completed report back to Incident Service using a restricted write grant. It cannot issue new grants and has no database credentials. A controlled working directory supports the temporary report file/path validation experiment.

**Helper package:** `packages/incident_formatter` is developed separately, built as a wheel and installed through the dependency/build path (not copied into Report Service code). Its benign function converts an Incident data structure to plain-text report content. Supply-chain attack experiments are optional and not part of the initial scope.

**Database:** SQLite is a data store accessible only from Incident Service. Not one of the three required application processes.

## Authentication and authority flow

- Login `POST /auth/login`: Gateway sends the username/password to Incident Service `POST /internal/auth/verify` over the internal network, authenticated with a short-lived service grant scoped only to `auth:verify`. Incident Service verifies the password using an established password-hashing library and returns the authenticated ID/role, never a password hash. Gateway then issues a signed RS256 JWT with `iss=secureincident`, `aud=gateway`, `sub=user_id`, `role`, `iat`, `nbf`, `exp` (approximately 30 minutes), and `jti`. Only the Gateway has the private signing key. Its own verification and downstream verification use public keys. Private key comes from local secrets/configuration, not source control.
- Other public endpoints: User sends Bearer token to Gateway. Gateway verifies signature, algorithm allow-list, issuer, audience, expiry, and role, and does **not** accept identity/role from user-controlled headers or JSON.
- Gateway mints *new, short-lived delegated internal tokens* after validating the user token. The internal JWT has `aud=incident-service` or `aud=report-service`, `sub` (original user), `role` (authenticated role), `scope` (specific operation), optional `incident_id`, `exp` (approximately 2 minutes), `jti`, and `request_id`. Resource and operation must match the request.
- Incident Service validates the internal token's audience, signature, expiry, exact scope and, when relevant, `incident_id`; **then checks ownership in SQLite** (or approved admin policy). An internally signed JWT is NOT sufficient to bypass user/resource authorization.
- Gateway starts a report job with a report-specific grant (`aud=report-service`, `scope=report:generate`, `incident_id=X`) and a separate downstream Incident Service grant restricted to `scope=incident:read` and `report:create` for the *same* incident, possibly using two grants to keep operations narrow. Report Service cannot change the signed original user ID, case ID, role, or scope.
- Report Service uses its incident-scoped grants for HTTP requests back to Incident Service. Incident Service checks the stored owner on read and write. If Alice requests Bob's case, it refuses before producing or persisting any report. No broad service-account bypass exists in the corrected design.
- Job response returns report ID and report content only after the write succeeds and authorized data has been read. Gateway never serves raw file paths, and case/report retrieval rechecks authorization.

**Important**: Delegated JWTs model service-specific user authority, not a promise that a trusted service is all-powerful. Signing is done with a standard JWT library and standard RS256; no custom crypto design.

## Public Gateway API contract

| Method | Endpoint | Purpose | Policy |
|---|---|---|---|
| POST | `/auth/login` | Username/password login | Public, only valid seeded users authenticated |
| POST | `/incidents` | Create incident | Authenticated, owner forced to user |
| GET | `/incidents?search=&status=` | Filter/list incidents | Own only, admin all; SQLi experiment is on `search` |
| GET | `/incidents/{id}` | Read incident | Owner or admin |
| PATCH | `/incidents/{id}` | Change description/severity/status | Owner or admin, no owner change |
| PATCH | `/incidents/{id}/assign` | Change owner | Admin only |
| POST | `/incidents/{id}/reports` | Produce a text report | Owner or admin; traverses three services |
| GET | `/incidents/{id}/reports/{report_id}` | Retrieve stored report | Owner or admin, report must belong to case |
| GET | `/admin/overview` | All-case totals | Admin only |
| GET | `/health` | Liveness | No data/secrets |

No browser/GUI requirement. Use curl, httpie, FastAPI Swagger, or pytest test client as development interfaces. For the report-path experiment only, `POST /incidents/{id}/reports` takes an optional requested export filename. The secure implementation validates or ignores it and uses a generated safe filename.

## Private service API contract (not published to host)

Incident Service (all `/internal/*` require valid `aud=incident-service` scoped grants):

- `POST /internal/auth/verify` (Gateway-only `auth:verify` service scope; verifies seeded credentials; response excludes stored hashes)
- `POST /internal/incidents`
- `GET /internal/incidents` (own/all filtering, based on signed identity and role)
- `GET /internal/incidents/{id}`
- `PATCH /internal/incidents/{id}`
- `PATCH /internal/incidents/{id}/assign`
- `POST /internal/incidents/{id}/reports`
- `GET /internal/incidents/{id}/reports/{report_id}`
- `GET /internal/admin/overview`

Report Service (private to Gateway):

- `POST /internal/generate` with user-bound job grant and **separate** incident read and report-create grants in request metadata. Validates common `sub` and `incident_id` across them, refusing mismatches. Generates a report only after an authorized incident read; returns content to Gateway only on success.

The exact JSON schemas will be specified when implementation starts. Security-sensitive fields and validation behavior are already fixed here. Denial status: 401 for missing/invalid auth, 403 for role/scope violations, 404 for nonexistent or not-owned individual resource IDs to avoid confirming their existence. Tests must assert no side effects.

## Trust boundaries

- **TB1 User -> Gateway**: Untrusted login, bearer JWT, query parameters, request bodies. Verify identity, authorization eligibility, input constraints and rate-limit in production.
- **TB2 Gateway -> Incident Service**: A private network does not confer trust; require signature, audience, scope, freshness and owner checks.
- **TB3 Gateway -> Report Service**: Require scoped job authorization. The report request does not confer broad privileges.
- **TB4 Report Service -> Incident Service**: Critical composition boundary. The Report Service is a deputy and must carry the original analyst's limited authority, not a privileged service-wide identity.
- **TB5 Report Service -> formatter wheel/filesystem**: Helper package code and user-selected filenames can affect local filesystem. Restrict working directory, install declared artifact, validate output path and format.
- **TB6 Incident Service -> SQLite**: Parameterized SQL, role-specific data access, private DB credentials/file/volume.

## Report sequence (authorized path)

1. Alice sends signed Gateway user JWT and `POST /incidents/101/reports`.
2. Gateway validates JWT and mints a case-101 report-job token for Report Service and case-101 read/report-write grants for Incident Service.
3. Report Service verifies report-job token and matching grants, then requests case 101 from Incident Service.
4. Incident Service verifies the grant, loads owner from SQLite and authorizes Alice for case 101.
5. Report Service renders content via installed `incident_formatter`; saves only into a validated temporary report directory.
6. Report Service submits case-101 report via `POST /internal/incidents/101/reports` using report-create grant. Incident Service checks authorization and persists record.
7. Report Service returns report details; Gateway returns response to Alice.
8. The same steps against Bob's incident 102 must stop at step 4, with no returned content and no saved report.
