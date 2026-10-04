# Production Launch Certification

CloudSentinel has a release-integrity pipeline, but a signed image is not the same
thing as a verified deployment. This certification workflow closes that gap for a
controlled self-hosted beta environment.

Workflow:

```text
signed immutable GHCR digest
        |
        v
Cosign identity verification
        |
        v
production Compose graph
        |
        +--> PostgreSQL
        +--> Redis
        +--> migrations
        +--> API
        +--> worker
        |
        v
authenticated smoke test
        |
        +--> /health
        +--> /ready
        +--> live worker heartbeat
        +--> register/login/me
        +--> tenant-scoped cloud-account persistence
        +--> pending-account scan guard
        |
        v
isolated PostgreSQL backup/restore drill
        |
        v
optional rollback to previous signed digest
        |
        v
restore certified release
```

## Running the certification

After a real `v*` release has published an image, open:

```text
GitHub Actions -> Production Launch Certification -> Run workflow
```

Supply:

- `image`: the exact GHCR image digest published by the release workflow.
- `previous_image`: optional previous known-good signed digest. When supplied,
  the workflow performs a rollback drill and then restores the certified release.

The workflow rejects mutable image references such as `latest`.

## What the gate proves

A successful run provides evidence that:

- the selected image has a valid Sigstore signature from the expected GitHub
  Actions release workflow identity;
- the production Compose configuration renders successfully;
- PostgreSQL and Redis become healthy;
- database migrations complete;
- the API starts from the production image;
- the worker starts and publishes a live Redis heartbeat;
- authenticated registration, login, and `/me` work against the deployed release;
- tenant-scoped cloud-account persistence works;
- a cloud account that is not connected cannot be scanned;
- a PostgreSQL custom-format backup can be created and read by `pg_restore`;
- the backup can be restored into an isolated database;
- restored tenant and user records remain readable;
- when a previous digest is supplied, the previous release can boot against the
  current database state and the certified release can subsequently be restored.

The workflow uploads the backup/restore timing and restored-record evidence as a
30-day GitHub Actions artifact.

## What the gate intentionally does not claim

This certification does **not** fabricate an AWS scan.

The smoke test uses a synthetic AWS role ARN and deliberately leaves the account in
`pending_connection`. This proves the application boundary without requiring a
real customer AWS credential or producing fake findings.

A real AWS end-to-end certification should be run separately against a dedicated
test AWS account/role with read-only permissions. That test should verify:

1. STS role assumption and expected-account validation.
2. discovery of enabled regions.
3. scanner execution and worker completion.
4. persisted evidence-backed findings.
5. risk posture and dashboard summary.
6. report generation.
7. remediation workflow.
8. security drift against a second completed scan.

Those results should be recorded as release evidence rather than represented as
part of this credential-free CI gate.

## Backup and recovery evidence

The automated drill measures backup and restore duration in an isolated PostgreSQL
database. These measurements are evidence for the certification run only.

Production RPO/RTO must still be derived from the actual deployment environment,
backup frequency, off-host replication, storage performance, and restore procedure.
See `docs/OPERATIONS_RUNBOOK.md`.

## Release readiness interpretation

Use the following language accurately:

- **CI green:** code and automated checks passed.
- **Release signed:** the immutable artifact has verified Sigstore provenance/signature.
- **Launch certified:** the selected signed artifact passed this deployment,
  authenticated smoke, and database recovery gate.
- **Controlled beta ready:** launch certification passed **and** a dedicated AWS
  end-to-end scan plus operational monitoring/alerting have been exercised.
- **Production-ready:** only claim this when the real deployment has measured
  recovery objectives, monitored operations, tested rollback, and completed the
  required AWS end-to-end validation.

Do not mark the project production-ready solely because this workflow exists.
The evidence from the actual run is the certification.
