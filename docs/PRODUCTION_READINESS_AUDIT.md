# CloudSentinel Production Readiness Audit

Audit basis: repository state on the `main` branch after AWS certification
hardening, launch certification, backup/restore and rollback drills, and live
observability verification.

## Decision

**Status: controlled-production / public-beta candidate; operational enterprise
certification remains gated on deployment-specific evidence.**

The application and deployment configuration are production-oriented and the
critical worker/queue observability path has now been exercised against the
running Compose deployment. This document deliberately does not turn repository
configuration into unsupported claims about an arbitrary production
environment.

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
| Authenticated production metrics | Bearer-protected API metrics + Prometheus scrape | PASS |
| Worker-unavailable alert | real worker stop caused Prometheus critical alert to fire | PASS |
| Alertmanager ingestion | fired worker alert received by Alertmanager | PASS |
| Worker recovery | worker restart restored heartbeat and health | PASS |
| Alert resolution | Prometheus alert disappeared after worker recovery | PASS |
| External operator notification | real email/Slack/PagerDuty/webhook delivery | NOT YET EVIDENCED |
| Production backup scheduler | daily scheduler artifacts supplied | CONFIGURATION PROVIDED; target deployment not evidenced |
| Off-host backup replication | target deployment evidence | NOT YET EVIDENCED |
| Measured RPO/RTO | target-environment measurement | NOT YET EVIDENCED |

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
resolution path. It does **not** prove delivery to a human operator because the
repository intentionally contains no external receiver credentials.

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

Before unrestricted production certification, configure one real external
receiver outside Git and record both alert detection time and notification
delivery time.

### RTO

Do not publish an RTO number until a real deployment measures:

1. incident detection;
2. operator/recovery start;
3. database restore;
4. migrations;
5. API readiness;
6. worker readiness;
7. representative authenticated request.

The launch certification restore duration is useful engineering evidence, but
it is not a production RTO because it does not represent the target deployment.

## Release gate

A release should not be called **production certified** unless all of these are
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

## Current honest positioning

> CloudSentinel is an AWS-first cloud security posture and compliance auditor
> designed for evidence-backed security findings, risk analysis and compliance
> mapping. It is suitable for controlled production/beta deployments and has
> production-oriented observability, recovery and AWS certification workflows.

Do not claim "enterprise CSPM replacement", "zero false positives",
"guaranteed compliance", or measured RPO/RTO until those claims are evidenced in
the target deployment.
