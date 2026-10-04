# CloudSentinel

> **AWS-first Cloud Security Posture & Compliance Auditor**

CloudSentinel is an open-source, production-oriented cloud security platform designed to discover AWS resources, evaluate security configurations, detect misconfigurations, generate evidence-backed findings, assess contextual risk, and map controls to compliance requirements.

> **Current focus:** AWS  
> **Azure:** Development phase  
> **CI:** full regression suite, dependency audit, and container security gate run on every push and pull request

---

## Why CloudSentinel?

Cloud environments accumulate security drift quickly:

- overly permissive IAM
- public network exposure
- missing encryption
- weak logging
- unsafe storage configuration
- risky serverless settings
- insufficient audit controls

CloudSentinel turns those configurations into actionable findings:

```text
AWS Account
    |
    v
Discovery
    |
    v
Configuration Collection
    |
    v
Normalization
    |
    v
Security Rules
    |
    v
Findings + Evidence
    |
    v
Risk Assessment
    |
    v
Compliance Mapping
    |
    +-------> REST API
    |
    +-------> HTML / PDF Reports
    |
    +-------> Scan History
```

---

## Current AWS Coverage

CloudSentinel currently focuses on multiple high-value AWS security domains, including:

| Domain | Coverage |
|---|---|
| EC2 | ✅ |
| IAM | ✅ |
| S3 | ✅ |
| RDS | ✅ |
| Lambda | ✅ |
| KMS | ✅ |
| VPC | ✅ |
| CloudTrail | ✅ |

Coverage is actively expanding based on current AWS Security Hub controls rather than an arbitrary rule-count target.

---

## Architecture

```text
                    CloudSentinel
                          |
             +------------+------------+
             |                         |
        Authentication             Cloud Accounts
             |                         |
             +------------+------------+
                          |
                          v
                     Scan API
                          |
                          v
                    Redis Queue
                          |
                          v
                       Worker
                          |
                          v
              AWS Service / Collector
                          |
                          v
                   Rule Registry
                          |
                          v
                 Findings Engine
                          |
             +------------+------------+
             |                         |
             v                         v
        Risk Assessment          Compliance
             |                         |
             +------------+------------+
                          |
                          v
                     PostgreSQL
                          |
             +------------+------------+
             |                         |
             v                         v
          REST API              HTML / PDF
```

### Design principles

**Read-only by default**

The AWS scanner is designed around read-only assessment and cross-account IAM role assumption.

**Evidence-driven findings**

Findings preserve machine-readable evidence so users can understand why a control failed.

**Tenant-aware application**

Cloud accounts, scans, findings, and reporting APIs are scoped through authenticated tenant context.

**Extensible rule engine**

Provider collection and security evaluation remain separate, so individual controls can be tested and evolved independently.

**Idempotent scan persistence**

Retry/recovery paths avoid creating duplicate logical findings.

---

## AWS Account Connection

CloudSentinel uses an AWS IAM role trust relationship rather than asking users to paste long-lived AWS access keys into the application.

Typical flow:

```text
Customer AWS Account
        |
        | IAM Role
        | External ID
        v
CloudSentinel
        |
        v
STS AssumeRole
        |
        v
Read-only AWS scan
```

Before connecting an account, the customer should create an IAM role with only the permissions required by the enabled CloudSentinel scanners.

See the project documentation for the current onboarding details.

---

## Application Features

### Authentication

- JWT access tokens
- Argon2 password hashing
- tenant-aware login
- inactive-user protection
- suspended-tenant token invalidation

### Cloud Accounts

- AWS account onboarding
- role ARN validation
- external ID support
- connection verification through STS
- expected AWS account identity validation
- connection status tracking

### Scanning

- asynchronous Redis-backed scan queue
- worker-based execution
- retry/recovery handling
- per-tenant bounded scan concurrency
- persistent recurring scan schedules (15 minutes to 7 days)
- scan history
- scan summaries
- finding lifecycle support

### Findings

- severity
- contextual risk score
- risk level
- evidence
- remediation guidance
- compliance references
- tenant-scoped API access

### Reporting

- HTML reports
- PDF reports
- security response headers
- tenant-scoped report access
- security audit event persistence
- request correlation IDs for API responses
- tenant-scoped audit event API with pagination and filtering
- production request-size limits and trusted-proxy-aware rate limiting
- optional authenticated Prometheus-format API metrics

### Operational Readiness

- `/health` liveness endpoint
- `/ready` dependency readiness endpoint for PostgreSQL and Redis
- Redis-backed scan queue recovery, retry, dead-letter handling, and queue metrics
- production deployment baseline with private PostgreSQL/Redis networking and TLS termination
- immutable production container publishing through GitHub Container Registry
- PostgreSQL backup and restore runbook
- repeatable production launch certification workflow with signed-image verification, authenticated smoke tests, and isolated recovery drill

---

## Security & SaaS Readiness

CloudSentinel is being hardened as a real multi-tenant application, not just an AWS rule collection.

Current hardening includes:

- tenant-scoped cloud accounts
- tenant-scoped scans
- tenant-scoped finding retrieval
- role-based authorization for operational mutations
- Redis-backed API rate limiting
- JWT authentication
- Argon2 password hashing
- AWS account identity validation
- idempotent finding persistence
- API security headers
- configurable CORS
- security audit trail for authentication and privileged operations
- request correlation IDs
- CI dependency vulnerability auditing
- CI container vulnerability gating for high/critical findings
- read-only AWS scanner model
- automated regression tests
- CI test/compile gate

See:

```text
docs/SAAS_READINESS.md
docs/OPERATIONS_RUNBOOK.md
docs/DEPLOYMENT.md
```

for the controlled-public-beta checklist and remaining production requirements.

---

## Run Locally

### 1. Clone

```bash
git clone https://github.com/pentest-sourav/cloudsentinel.git
cd cloudsentinel
```

### 2. Configure environment

Create a `.env` file with the required database, Redis, and JWT settings.

### 3. Start infrastructure

```bash
docker compose up -d postgres redis
```

### 4. Start the API

```bash
uvicorn backend.app.main:app --reload
```

### 5. Start the worker

```bash
python -m backend.worker
```

### 6. Run tests

```bash
pytest -q
```

---

## Development Quality Gate

Before pushing changes:

```bash
python -m compileall -q backend engine scanner reporting
pytest -q
git diff --check
```

GitHub Actions also runs compilation and the full pytest suite on pushes and pull requests.

---

## Project Status

CloudSentinel is an active open-source project with a launchable self-hosted web console and an AWS-first security assessment workflow. Scheduled CSPM assessments and tenant-safe scan capacity controls are included for continuous monitoring workflows.

### Implemented

- ✅ AWS-first security scanning architecture
- ✅ multi-service AWS assessment
- ✅ registry-driven security controls
- ✅ evidence-driven findings
- ✅ contextual risk assessment
- ✅ compliance mapping foundation
- ✅ PostgreSQL persistence
- ✅ Redis-backed background scanning
- ✅ authentication and tenant model
- ✅ AWS role onboarding and connection testing
- ✅ HTML and PDF reporting
- ✅ automated test suite
- ✅ CI regression gate

### In development

- 🚧 Expanded AWS Security Hub control coverage
- 🚧 Production backup/restore drills and measured recovery objectives
- 🚧 Real AWS end-to-end launch certification against a dedicated test account
- ✅ Web dashboard and AWS onboarding/verification console
- 🚧 Azure provider implementation
- 🚧 Additional compliance frameworks

---

## Current Scope

CloudSentinel should currently be presented as:

> **An AWS-first cloud security posture and compliance auditing platform with a launchable self-hosted SaaS-style web console.**

Azure is being developed as the next provider.

CloudSentinel is evidence-driven and does not generate synthetic security findings. A finding is persisted from scanner/collector evidence returned by the target AWS account; failed or permission-denied checks are surfaced as execution errors/warnings rather than silently treated as secure. AWS coverage remains explicitly scoped to the implemented and tested controls, and the project does not claim complete AWS Security Hub coverage without validation against the current AWS catalogue.

---

## Contributing

Security rules and provider integrations should include focused unit tests plus integration/regression coverage where appropriate.

Run:

```bash
pytest -q
git diff --check
```

before opening a pull request.

---

## Security

For security vulnerabilities, see:

```text
SECURITY.md
```

Please do not disclose sensitive vulnerabilities through public issue reports.

---

## License

See `LICENSE`.
