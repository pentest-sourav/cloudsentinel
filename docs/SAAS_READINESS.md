# CloudSentinel SaaS Readiness

## Current Position

CloudSentinel is an **AWS-first, production-oriented security posture and compliance platform**.

The repository currently has a verified regression baseline of:

- **2827 passing tests**
- 1 existing Starlette/AnyIO deprecation warning
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

Authenticated users should not automatically receive every operational capability.

The production model should distinguish at least:

- owner
- administrator
- operator
- viewer

Destructive or account-management operations should require an appropriate role.

### API protection

Before public exposure:

- rate-limit authentication endpoints
- rate-limit scan creation
- enforce request-size limits
- configure production CORS explicitly
- enable secure response headers
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
- structured application logs
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
- deployment is reproducible
- the public documentation accurately states supported capabilities and limitations

This checklist is deliberately stricter than simply having a large number of AWS rules.
