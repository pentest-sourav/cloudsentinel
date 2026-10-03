# Production Deployment

This deployment baseline is for a controlled self-hosted SaaS/beta environment.
It separates the public TLS edge from the API, keeps PostgreSQL and Redis private,
runs migrations before application startup, and does not mount developer AWS
credentials into production containers.

## Architecture

```text
Internet
   |
 HTTPS
   v
 Caddy
   |
   v
 API ---- PostgreSQL
   |
 Redis <- Worker
```

Caddy terminates HTTPS. PostgreSQL is the system of record and Redis provides
queue/cache state.

## Prerequisites

- Linux host with Docker Engine and Docker Compose v2.
- DNS record for the production hostname pointing to the host.
- Production CloudSentinel image in GHCR or another trusted registry.
- Secret manager or protected environment for database/JWT secrets.
- Runtime AWS workload identity. On AWS, prefer an EC2 instance profile, ECS task
  role, or equivalent workload identity.
- Runtime AWS identity allowed to call STS AssumeRole for customer read-only roles.

## Required environment

Set these outside the repository:

```bash
export CLOUDSENTINEL_IMAGE=ghcr.io/pentest-sourav/cloudsentinel:VERSION
export CLOUDSENTINEL_DOMAIN=cspm.example.com
export POSTGRES_PASSWORD='<random-password>'
export JWT_SECRET_KEY='<random-secret-at-least-32-characters>'
export CORS_ALLOWED_ORIGINS='https://app.example.com'
```

Do not commit these values. Production requires explicit CORS, HSTS, JSON logging,
and a bounded JWT lifetime.

## Start

Validate the rendered configuration:

```bash
docker compose -f deploy/docker-compose.prod.yml config
```

Start:

```bash
docker compose -f deploy/docker-compose.prod.yml up -d
```

The migration service runs `alembic upgrade head` before API and worker startup.

Verify:

```bash
docker compose -f deploy/docker-compose.prod.yml ps
curl -fsS https://$CLOUDSENTINEL_DOMAIN/health
curl -fsS https://$CLOUDSENTINEL_DOMAIN/ready
```

Only Caddy publishes ports 80 and 443. PostgreSQL, Redis, and API ports are private.

## AWS workload identity

Production containers intentionally contain no `~/.aws` volume mount. The AWS SDK
resolves the CloudSentinel runtime identity from the platform credential provider
chain.

For AWS-hosted deployments use an EC2 instance profile, ECS task role, or EKS pod
identity/IRSA. Grant the runtime identity only the STS permissions required to
assume customer onboarding roles. Customer AWS accounts should trust the runtime
identity with an external ID and a read-only role policy.


### External ID lifecycle
CloudSentinel generates the AWS trust external ID server-side and does not accept it from cloud-account creation requests. The connection configuration endpoint is restricted to owner/administrator roles because the external ID is sensitive trust configuration. Owners and administrators can rotate the external ID when required; rotation invalidates the previous trust configuration and moves the account back to `pending_connection` until the customer updates the IAM trust policy and reconnects.

External IDs are not AWS credentials or authentication secrets, but they are sensitive trust configuration. External IDs are never written to audit-event metadata; do not copy the current value into application logs or telemetry.

## Updates and rollback

Never deploy an unpinned `latest` image. Use a release or immutable commit-derived
tag.

For an update:

1. Set `CLOUDSENTINEL_IMAGE` to the new immutable image.
2. Render and review the Compose configuration.
3. Pull the new image.
4. Run `docker compose -f deploy/docker-compose.prod.yml up -d`.
5. Confirm `/health` and `/ready`.
6. Check worker logs and queue metrics.
7. Keep the previous image tag available for rollback.

Rollback is the same process with the previous known-good image. Database migrations
must be backward-compatible with the preceding application version before a rolling
update.

## Backups and recovery

Use the PostgreSQL backup utility in `docs/OPERATIONS_RUNBOOK.md`. Persistent
volumes are not a substitute for off-host backups. Run restore drills against an
isolated PostgreSQL instance.

## Monitoring

Enable authenticated `/metrics` when Prometheus is available. Alert on API/worker
restarts, readiness failures, queue pending count, stream length, dead-letter growth,
backup failures, disk pressure, and TLS certificate failures.

## Security notes

- PostgreSQL and Redis have no host-published ports.
- API is reachable only through Caddy on the edge network.
- Caddy obtains and renews public certificates for the configured DNS name.
- HSTS is enabled in production configuration.
- API logs use JSON.
- Rate limiting trusts forwarded client addresses only from the fixed Caddy edge subnet.
- Developer AWS credential mounts are intentionally absent.
