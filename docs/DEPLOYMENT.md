# Production Deployment

This baseline is for a controlled self-hosted SaaS/beta environment. It separates the public TLS edge from the API, keeps PostgreSQL and Redis private, runs migrations before application startup, and does not mount developer AWS credentials into production containers.

## Architecture

~~~text
Internet
   |
 HTTPS :443
   v
 Caddy
   |
   v
 API ---- PostgreSQL
   |
 Redis <- Worker
          |
          +---- AWS APIs
~~~

The bundled web console is served by the CloudSentinel API image. A separate frontend server is not required.

## Prerequisites

- Linux host with Docker Engine and Docker Compose v2.
- DNS A/AAAA record for the production hostname.
- Ports 80 and 443 reachable from the Internet.
- Production CloudSentinel image in GHCR or another trusted registry.
- Protected production secrets.
- AWS workload identity such as EC2 instance profile, ECS task role, or EKS pod identity.
- Runtime AWS identity allowed to call STS AssumeRole for customer read-only roles.

## Deployment

### 1. Clone

~~~bash
git clone https://github.com/pentest-sourav/cloudsentinel.git
cd cloudsentinel
~~~

For a release deployment, use an intended release/tag rather than a moving development branch.

### 2. Configure secrets

~~~bash
export CLOUDSENTINEL_IMAGE='ghcr.io/pentest-sourav/cloudsentinel@sha256:<verified-digest>'
export CLOUDSENTINEL_DOMAIN='cspm.example.com'
export POSTGRES_PASSWORD='<random-production-password>'
export REDIS_PASSWORD='<random-production-redis-password>'
export JWT_SECRET_KEY='<random-secret-at-least-32-characters>'
export CORS_ALLOWED_ORIGINS='https://cspm.example.com'
~~~

Do not commit these values.

### 3. Validate

~~~bash
docker compose -f deploy/docker-compose.prod.yml config -q
~~~

### 4. Start

~~~bash
docker compose -f deploy/docker-compose.prod.yml pull
docker compose -f deploy/docker-compose.prod.yml up -d
~~~

The migrate service runs the database migrations before API and worker startup.

### 5. Verify

~~~bash
docker compose -f deploy/docker-compose.prod.yml ps
curl -fsS https://$CLOUDSENTINEL_DOMAIN/health
curl -fsS https://$CLOUDSENTINEL_DOMAIN/ready
~~~

Then open https://$CLOUDSENTINEL_DOMAIN.

## AWS workload identity

Production containers intentionally contain no developer credential volume mount. The AWS SDK resolves the CloudSentinel runtime identity from the platform credential provider chain.

For AWS-hosted deployments use an EC2 instance profile, ECS task role, or EKS pod identity/IRSA. Grant the runtime identity only the STS permissions required to assume customer onboarding roles.

Customer AWS accounts should trust the runtime identity with an External ID and read-only role policy.

## External ID lifecycle

CloudSentinel generates the AWS trust External ID server-side. It does not accept the External ID from cloud-account creation requests.

Owners and administrators can rotate the External ID when required. Rotation invalidates the previous trust configuration and returns the account to pending_connection until the customer updates the IAM trust policy and reconnects.

Do not copy External IDs into logs or telemetry.

## Updates and rollback

Never deploy an unpinned latest image.

For an update:

1. Set CLOUDSENTINEL_IMAGE to the new immutable image.
2. Render and review the Compose configuration.
3. Pull the new image.
4. Run docker compose -f deploy/docker-compose.prod.yml up -d.
5. Confirm health and readiness.
6. Check worker logs and queue metrics.
7. Keep the previous immutable image for rollback.

Database migrations must be backward-compatible with the preceding application version before a rolling update.

## Backups and recovery

Use docs/OPERATIONS_RUNBOOK.md. Persistent volumes are not a substitute for off-host backups. Restore drills must use an isolated PostgreSQL instance.

## Monitoring

Enable authenticated /metrics when Prometheus is available. Alert on API/worker restarts, readiness failures, queue backlog, dead-letter growth, backup failures, disk pressure and TLS certificate failures.

## Security notes

- PostgreSQL and Redis have no host-published ports.
- Redis requires authentication in the production Compose deployment.
- API is reachable through Caddy on the edge network.
- Caddy obtains and renews public certificates for the configured DNS name.
- HSTS is enabled in production configuration.
- API logs use JSON.
- Rate limiting trusts forwarded client addresses only from the fixed Caddy edge subnet.
- Developer AWS credential mounts are absent.
- The Caddy healthcheck validates the HTTPS proxy path through /health and does not rely on Caddy's disabled admin endpoint.

## Production evidence

A successful docker compose up is not, by itself, production certification.

For a deployment to be described as production-certified, collect deployment-specific evidence for:

- exact release/immutable image;
- CI status for the exact release;
- real AWS scan;
- real customer-like AssumeRole;
- real multi-region scan;
- findings and evidence integrity;
- partial-permission behavior;
- worker/queue recovery;
- Redis/PostgreSQL recovery;
- backup creation and verification;
- off-host backup protection;
- isolated restore;
- rollback;
- monitoring/alerting;
- measured RPO;
- measured full-system RTO.

See docs/PRODUCTION_READINESS_AUDIT.md for the current evidence-based status.
