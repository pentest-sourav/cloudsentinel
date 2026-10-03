# CloudSentinel SaaS Readiness

## Current Position

CloudSentinel is an **AWS-first, production-oriented security posture and compliance platform**.

The repository currently has a verified regression baseline of:

- **2855 passing tests** in the latest local verification before the current deprecation cleanup
- current branch replaces the FastAPI startup-event and deprecated HTTP 413 APIs; the post-cleanup warning count is pending verification
- AWS is the primary implemented provider
- Azure is intentionally in development

The project should be presented publicly as an **AWS-focused CSPM foundation under active development**, not as a replacement for a mature commercial CSPM platform.

## What Is Already Implemented

### Security engine

- AWS resource discovery
- Service/collector/scanner separation
- Registry-driven rules
- Normalized provider data
- Evidence-backed findings
- Severity and contextual risk
- Compliance mapping
- Idempotent finding persistence
- Scan history
- HTML/PDF reporting
- Background scan execution
- Redis-backed scan queue
- AWS cross-account role assumption
- AWS account identity verification
- Defensive AWS API error handling
- Extensive automated regression coverage

### Application platform

- FastAPI REST API
- PostgreSQL persistence
- Redis job queue
- JWT authentication
- Argon2 password hashing
- Tenant-aware data model
- Tenant-aware cloud accounts
- Tenant-aware scans
- Tenant-aware finding access
- Suspended-tenant token invalidation
- AWS account connection testing
- Read-only AWS scanning model
- Configurable API rate limiting with Redis-backed enforcement
- Role-based authorization for operational mutations
- persisted security audit events for authentication and privileged operations
- tenant-scoped audit event retrieval for owner/administrator roles
- request correlation IDs on API responses
- configurable request body-size limits
- trusted-proxy-aware rate-limit client identification
- production-safe metrics authentication
- optional authenticated Prometheus-format API metrics
- startup cleanup for expired audit events

## SaaS Security Requirements

Before inviting unrestricted public production traffic, the following areas must be explicitly verified and hardened:

### Tenant isolation

Every tenant-owned object must be scoped through the authenticated tenant context.

This includes:

- users
- cloud accounts
- scans
- findings
- reports
- scan execution errors
- future notifications
- future integrations
- future billing data

Tenant isolation is a separate security concern from authentication and authorization.

### AWS credential model

CloudSentinel should use customer-side IAM roles and STS AssumeRole with an external ID.

The application must not require customers to provide long-lived AWS access keys.

Production runtime credentials should come from the CloudSentinel runtime identity, not developer workstation credential mounts.

### Authorization

Role-based authorization is now enforced for operational mutations:
- owner/administrator: manage cloud accounts and delete scan history
- owner/administrator/operator: create scans and test AWS connections
- viewer: read-only access to tenant data

Authenticated users should not automatically receive every operational capability.

The production model should distinguish at least:

- owner
- administrator
- operator
- viewer

Destructive or account-management operations should require an appropriate role.

### API protection

Current implementation includes Redis-backed, configurable rate limiting for authentication, scan creation, and mutation traffic, plus role-based authorization for operational mutations.

Before public exposure:

- verify rate-limit thresholds with expected traffic and proxy topology
- enforce request-size limits
- configure production CORS explicitly
- enable secure response headers, including HSTS only when the service is served over HTTPS
- prevent authentication responses from being cached
- use HTTPS
- disable development-only credential mounts
- keep secrets outside source control
- use short-lived access tokens
- log security-relevant events without logging secrets

### Operational reliability

Production deployment should provide:

- PostgreSQL backups
- Redis persistence/recovery strategy
- worker restart policy
- scan retry/dead-letter handling
- health and readiness checks
- structured JSON application logs with request correlation
- metrics and alerting
- database migrations
- controlled deployment/rollback

### AWS scanning safety

The default scanning path should remain read-only.

Customer-facing documentation should clearly state:

- required IAM permissions
- AWS regions supported
- services scanned
- scan duration expectations
- data collected
- data retained
- how to disconnect an account
- how to delete stored scan data

## Public Launch Position

The recommended public positioning is:

> CloudSentinel is an open-source, AWS-first cloud security posture and compliance auditor that discovers cloud resources, evaluates security configurations, produces evidence-backed findings, assesses risk, and maps controls to compliance requirements. Azure support is under active development.

Avoid claims such as:

- "enterprise CSPM replacement"
- "fully production ready"
- "100% AWS Security Hub coverage"
- "zero false positives"
- "guaranteed compliance"

until those claims have been independently validated.

## Development Priorities

1. Finish high-value AWS control coverage.
2. Harden multi-tenant authorization and isolation.
3. Harden API abuse protection and production configuration.
4. Improve dashboard and onboarding UX.
5. Add deployment/observability documentation.
6. Add security regression tests for tenant isolation.
7. Expand Azure support without weakening AWS correctness.
8. Add CI security gates and dependency/container scanning.
9. Validate production backup/restore and deployment rollback procedures.

## Definition of SaaS Ready

CloudSentinel can be considered ready for a controlled public beta when:

- all tenant isolation tests pass
- authorization boundaries are enforced
- AWS role onboarding is documented and verified
- no long-lived customer credentials are stored
- production secrets are externally managed
- HTTPS and secure headers are enabled
- authentication and scan endpoints are rate-limited
- backups and recovery are tested
- worker failure/retry behavior is tested
- audit/security logging is operational
- dependency vulnerability scanning is part of CI
- production containers run without root privileges
- deployment is reproducible
- the public documentation accurately states supported capabilities and limitations

This checklist is deliberately stricter than simply having a large number of AWS rules.


## Current Production Hardening Layer

The application now exposes a read-only, tenant-scoped audit event API for owner/administrator users:

`GET /api/v1/audit-events`

Supported filters include action, status, and resource type, with bounded pagination.

API request bodies are bounded by `MAX_REQUEST_BODY_BYTES`. Rate limiting only honors `X-Forwarded-For` when the direct peer belongs to an explicitly configured `TRUSTED_PROXY_IPS` network.

Security responses include `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and a restrictive `Permissions-Policy`. HSTS is opt-in through `SECURITY_HEADERS_HSTS_ENABLED=true` with a configurable max-age; it should only be enabled when the public service is HTTPS. Authentication endpoints return `Cache-Control: no-store` and `Pragma: no-cache` so bearer-token responses are not stored by intermediaries.

Metrics are available from `/metrics` only when `METRICS_ENABLED=true`. The endpoint emits Prometheus-compatible text and intentionally uses bounded FastAPI route labels rather than raw resource URLs.

The container image runs as the non-root `cloudsentinel` user, includes an HTTP healthcheck, and is scanned in CI for high/critical OS and Python-library vulnerabilities. Production deployment should still place the service behind a TLS-terminating reverse proxy and configure trusted proxy networks explicitly.

Production logging supports `LOG_LEVEL` and `LOG_FORMAT=auto|json|text`. In production, `auto` selects JSON output. API request logs inherit the `X-Request-ID` correlation value, while worker logs emit structured scan and queue identifiers. Log pipelines should retain security-relevant operational events without collecting passwords, JWTs, AWS credentials, or other secrets.


## Multi-tenant security boundary

Tenant identity is derived from the authenticated user and is never accepted from
client-controlled request fields. Customer-owned resources are scoped by
`tenant_id` at the service/query layer as well as at API-route authorization
boundaries.

The security boundary currently covers cloud accounts, scans, findings, reports,
scan summaries, finding lifecycle history, and audit events. Cross-tenant
resource references return the same not-found semantics used for unknown
resources where applicable, avoiding cross-tenant existence disclosure.

Finding reads additionally enforce tenant scope inside the finding service rather
than relying only on the route's pre-check. This is defense in depth for future
callers and background workflows.

Tenant suspension is checked during authentication on every request, so an
active JWT does not retain access after its tenant is suspended.

Report generation now re-validates the tenant at the report service boundary before loading findings, lifecycle data, or scan execution errors. Execution-error reads can also enforce the scan tenant directly, preventing a future caller from turning a valid scan identifier into cross-tenant operational data access.
