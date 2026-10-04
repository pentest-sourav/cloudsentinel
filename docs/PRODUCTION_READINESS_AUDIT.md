# CloudSentinel Production Readiness Audit

Audit basis: repository state on the `main` branch after the AWS certification
hardening, launch certification, backup/restore drill, rollback drill, and
production queue alert-rule work.

## Decision

**Status: controlled-production / public-beta candidate, not yet an unrestricted
commercial SaaS production certification.**

The codebase has crossed the point where it can be described as a serious
production-oriented AWS CSPM foundation. The remaining distinction is operational:
the final deployment environment must actually run the supplied backup scheduler,
Prometheus/Alertmanager stack, real alert receivers, and measured recovery
objectives.

This document deliberately does not convert repository configuration into claims
of operational evidence.

## Evidence already established

| Area | Evidence | Status |
|---|---|---|
| Full automated regression | CI test suite and security gates | PASS |
| Tenant authorization/isolation | route/service scoping and regression tests | PASS |
| Scan evidence integrity | total failure vs partial-success semantics | PASS |
| Worker/Redis recovery logic | retry, reclaim, DLQ, heartbeat, stale-scan handling | PASS |
| AWS multi-region scanning | dedicated real-AWS certification path | PASS with expected AWS service/permission warnings |
| Real AWS findings | certification requires non-zero real findings | PASS |
| AWS partial-permission path | dedicated restricted certification role | IMPLEMENTED |
| Immutable signed release | GHCR digest + Sigstore verification | PASS |
| Production Compose graph | health checks, migrations, non-root containers, network isolation | PASS |
| PostgreSQL backup verification | matching container tooling + explicit DB user | PASS |
| Isolated restore drill | restore into separate database and verify tenant/user records | PASS |
| Rollback drill | previous signed image boot + certified image restoration | PASS |
| Queue/worker alert rules | Prometheus rules committed | IMPLEMENTED |
| Live alert delivery | Prometheus/Alertmanager deployed with a real receiver | NOT YET EVIDENCED |
| Production backup scheduler | daily scheduler artifacts supplied | CONFIGURATION PROVIDED; deployment not evidenced |
| Measured RPO/RTO | restore timing and actual backup interval in the target environment | NOT YET EVIDENCED |

## Required production deployment configuration

### Backups

Default policy:

- PostgreSQL backup: daily at 02:15 local server time.
- Local retention: 14 days.
- Off-host encrypted copy: required for production.
- Backup verification: every backup.
- Restore drill: at least monthly and after major database/platform changes.

The supplied systemd timer uses a persistent daily schedule. The actual production
operator must install and enable it on the database/backup host.

A 24-hour backup interval is the **RPO target**, not a measured RPO. The measured
RPO is the time between the last successful off-host backup and the incident.

### Observability

The repository now contains:

- authenticated CloudSentinel Prometheus metrics;
- queue freshness, worker heartbeat, backlog and DLQ alerts;
- API 5xx-rate alerting;
- Prometheus scrape configuration;
- Alertmanager deployment configuration.

A real receiver must be configured outside Git before calling alerting operational.
Recommended first production checks:

1. stop the worker and confirm the worker-unavailable alert;
2. inject queue backlog and confirm the backlog alert;
3. create a dead-letter event and confirm the DLQ alert;
4. return sustained API 5xx responses and confirm the API error-rate alert;
5. restore the worker and confirm alert resolution.

Record alert detection time and notification delivery time.

### RTO

Do not publish an RTO number until a real deployment has measured:

1. incident detection;
2. operator/recovery start;
3. database restore;
4. migrations;
5. API readiness;
6. worker readiness;
7. representative authenticated request.

The launch certification restore duration is useful evidence, but it is not a
production RTO because it runs on GitHub-hosted infrastructure.

## Release gate

A release should not be called "production certified" unless all of these are
true:

- CI is green for the exact release commit.
- The image is immutable and signature-verified.
- Launch certification passes.
- Real AWS E2E passes against the dedicated certification account.
- Backup creation and verification pass.
- Isolated restore passes.
- Rollback to the previous signed release passes.
- Production monitoring is receiving metrics.
- At least one real alert reaches an operator.
- Backup cadence and off-host replication are active.
- RPO and RTO have been measured and recorded.

## Honest public positioning

Recommended wording:

> CloudSentinel is an AWS-first cloud security posture and compliance auditor
> designed for evidence-backed security findings, risk analysis and compliance
> mapping. It is suitable for controlled production/beta deployments and is
> actively hardened toward broader SaaS operation.

Do not claim "enterprise CSPM replacement", "zero false positives", "guaranteed
compliance", or a measured RPO/RTO until independently evidenced in the target
environment.
