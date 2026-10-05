# CloudSentinel Production Readiness Audit

Audit basis: repository state on the `main` branch after AWS certification
hardening, launch certification, backup/restore and rollback drills, and live
observability verification.

## Decision

**Status: production-grade controlled-deployment candidate; full production certification remains deployment-specific.**

The application and deployment configuration are production-oriented and the
critical worker/queue observability path has been exercised against the running
Compose deployment. Additional worker, Redis, PostgreSQL and Caddy recovery
checks were completed on 2026-10-05. This document deliberately does not turn repository
configuration or a developer workstation into unsupported claims about an
arbitrary production environment.

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
| Caddy proxy health | HTTPS `/health` through Caddy returned HTTP 200; container healthcheck verified healthy | PASS |
| Worker failure/recovery drill | worker stopped, became unhealthy, restarted and returned healthy | PASS (engineering environment) |
| Redis failure/recovery drill | Redis restarted and returned healthy in ~11s; authenticated PING returned PONG | PASS (engineering environment) |
| PostgreSQL failure/recovery drill | PostgreSQL restarted and returned healthy in ~11s; `pg_isready` accepted connections | PASS (engineering environment) |
| API after dependency recovery | HTTPS `/health` returned HTTP 200 after Redis/PostgreSQL recovery | PASS (engineering environment) |
| PostgreSQL backup creation | PostgreSQL 17 custom-format dump + SHA-256 manifest | PASS |
| Off-host backup upload | Dedicated S3 destination, exact object verification | PASS (engineering environment) |
| Backup encryption/versioning | S3 SSE-S3 and returned object VersionId | PASS |
| Isolated restore drill | Fresh separate database restored successfully | PASS |
| Restored data integrity | tenants=622, users=619, cloud_accounts=188, scans=301, findings=25 | PASS |
| Database restore duration | Fresh isolated restore completed in 0.276s on 2026-10-05 | MEASURED ENGINEERING EVIDENCE |
| Rollback drill | previous signed image boot + certified image restoration | PASS |
| Authenticated production metrics | Bearer-protected API metrics + Prometheus scrape | PASS |
| Worker-unavailable alert | real worker stop caused Prometheus critical alert to fire | PASS |
| Alertmanager ingestion | fired worker alert received by Alertmanager | PASS |
| Worker recovery | worker restart restored heartbeat and health | PASS |
| Alert resolution | Prometheus alert disappeared after worker recovery | PASS |
| External operator notification | real email/Slack/PagerDuty/webhook delivery | INTENTIONALLY DEFERRED |
| Production backup scheduler | daily scheduler artifacts supplied | CONFIGURATION PROVIDED; target deployment not evidenced |
| Cross-account backup replication | separate backup account/replica | NOT YET EVIDENCED |
| Measured production RPO | target-environment incident measurement | NOT YET EVIDENCED |
| Measured full-system production RTO | target-environment end-to-end recovery measurement | NOT YET EVIDENCED |

## Backup and restore evidence

On 2026-10-05 a PostgreSQL 17 backup was created and uploaded to the dedicated
S3 backup destination.

Remote object verification returned:

- size: 91,288 bytes;
- server-side encryption: AES256;
- S3 VersionId: present;
- exact dump object verified with `head-object`;
- corresponding manifest object was also remotely verified.

The backup was copied into the running PostgreSQL container and restored into
the isolated database `cloudsentinel_restore_rto`. The live CloudSentinel
database was not used as the restore target.

Restore duration:

- `pg_restore` wall-clock duration: **0.276 seconds**.

Restored record counts:

- tenants: **622**
- users: **619**
- cloud_accounts: **188**
- scans: **301**
- findings: **25**

The isolated database and temporary restore dump were removed after verification.

This proves the backup -> off-host object -> restore -> data verification
lifecycle in the tested environment. It does not by itself prove that the
target production scheduler is installed or that the target production host
has the same restore performance.

## Live observability verification

The running production-style Compose stack was tested on 2026-10-04.

### Worker failure

The worker was stopped and its heartbeat was allowed to expire.

Observed:

- `cloudsentinel_scan_queue_active_workers = 0`
- `cloudsentinel_scan_queue_metrics_fresh = 1`
- `CloudSentinelWorkerUnavailable` entered `firing`
- Alertmanager reported the alert as `active`

### Worker recovery

The worker was started again.

After heartbeat recovery:

- `cloudsentinel_scan_queue_active_workers = 1`
- `cloudsentinel_scan_queue_metrics_fresh = 1`
- `ALERTS{alertname="CloudSentinelWorkerUnavailable"}` returned no active alert
- worker container reported `running | health=healthy | exit=0`

This proves the internal detection, alert ingestion, recovery and alert
resolution path. External human notification is intentionally deferred.

## Required production deployment configuration

### Backups

Default policy:

- PostgreSQL backup: daily at 02:15 local server time.
- Local retention: 14 days.
- Off-host encrypted copy: required for production.
- Backup verification: every backup.
- Restore drill: at least monthly and after major database/platform changes.

The supplied systemd timer uses a persistent daily schedule. The actual
production operator must install and enable it on the database/backup host.

A 24-hour backup interval is the **RPO target**, not a measured RPO. Measured
RPO must be calculated from the actual last successful off-host backup at the
time of an incident.

### Observability

The repository contains:

- authenticated CloudSentinel Prometheus metrics;
- queue freshness, worker heartbeat, backlog and DLQ alerts;
- API 5xx-rate alerting;
- Prometheus scrape configuration;
- Alertmanager deployment configuration.

External operator notification is intentionally deferred until real-world
traffic justifies selecting and configuring a receiver.

### RTO

The isolated database restore provides a measured **0.276s database restore
duration** in the tested local Compose environment. Dependency recovery drills also measured
approximately **11s** for Redis and PostgreSQL container recovery in the same environment.

This must not be published as the application's production RTO.

A production RTO measurement must include:

1. incident detection;
2. operator/recovery start;
3. database restore;
4. migrations;
5. API readiness;
6. worker readiness;
7. representative authenticated request.

## Release gate

A release should not be called **production certified** unless all deployment
specific requirements are actually evidenced:

- CI is green for the exact release commit.
- The image is immutable and signature-verified.
- Launch certification passes.
- Real AWS E2E passes against the dedicated certification account.
- Backup creation and verification pass.
- Isolated restore passes.
- Rollback to the previous signed release passes.
- Production monitoring is receiving metrics.
- Backup cadence is active on the target deployment.
- Off-host backup protection is active on the target deployment.
- Production RPO and full-system RTO have been measured and recorded.

External operator notification is currently outside the release gate by explicit
product decision.

## Current honest positioning

> CloudSentinel is an AWS-first cloud security posture and compliance auditor
> designed for evidence-backed security findings, risk analysis and compliance
> mapping. The current main branch is a production-grade controlled-deployment
> candidate with demonstrated AWS scanning, tenant isolation, signed release
> artifacts, backup/restore, rollback, observability and dependency recovery.
> Target-environment production certification still requires deployment-specific
> backup cadence, replication, RPO and full-system RTO evidence.

Do not claim "enterprise CSPM replacement", "zero false positives",
"guaranteed compliance", or measured production RPO/RTO until those claims are
evidenced in the target deployment.
