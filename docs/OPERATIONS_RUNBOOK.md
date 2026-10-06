# Production Operations Runbook

## PostgreSQL backup and recovery

CloudSentinel treats PostgreSQL as the system of record for tenants, cloud-account connections, scan history, findings, audit events, and related application state. A backup is useful only when it can be verified and restored.

### Backup policy

Set these production environment variables:

- DATABASE_URL
- BACKUP_OUTPUT_DIR
- BACKUP_S3_BUCKET for off-host backup
- BACKUP_S3_PREFIX, default cloudsentinel/postgres
- BACKUP_S3_KMS_KEY_ID when customer-managed KMS encryption is required
- BACKUP_LOCAL_RETENTION_DAYS, default 14

Run:

~~~bash
python ops/backup/postgres_backup.py backup
~~~

The scheduler should run at least daily.

## Verification

Every backup should be verified:

~~~bash
python ops/backup/postgres_backup.py verify backups/postgres/cloudsentinel-postgres-<timestamp>.dump
~~~

Verification checks the SHA-256 manifest and PostgreSQL archive readability.

## Restore drill

Restore only to an isolated PostgreSQL instance:

~~~bash
RESTORE_DATABASE_URL='postgresql+psycopg://...' \
python ops/backup/postgres_backup.py restore \
  backups/postgres/cloudsentinel-postgres-<timestamp>.dump
~~~

After restoration:

1. Run alembic upgrade head.
2. Start the API against the restored database.
3. Check /ready.
4. Confirm expected tenant/user/resource counts.
5. Execute a representative authenticated read-only API request.
6. Record restore duration and outcome.

Never point a restore drill at the live production database.

## Recovery objectives

The application does not claim a fixed RPO/RTO until deployment infrastructure is measured.

Record:

- backup interval;
- backup completion time;
- restore duration;
- last successful restore drill;
- backup retention;
- off-site replication status.

A daily backup schedule is an RPO target, not a measured production RPO.

## Redis

Redis is a queue/cache dependency, not the authoritative source of scan history. PostgreSQL remains the authoritative recovery target.

## Secrets

Never place database passwords, AWS credentials, JWT secrets, or backup credentials in repository files.

---

## Production backup scheduler

Use PostgreSQL client binaries from the same major version as the production PostgreSQL server.

For the current production Compose database, PostgreSQL 17 is used:

~~~bash
sudo mkdir -p /etc/cloudsentinel
sudo install -m 0600 deploy/backup/backup.env.example /etc/cloudsentinel/backup.env
sudo editor /etc/cloudsentinel/backup.env
~~~

Set:

~~~text
PG_DUMP_BIN=/usr/lib/postgresql/17/bin/pg_dump
PG_RESTORE_BIN=/usr/lib/postgresql/17/bin/pg_restore
BACKUP_EXPECTED_POSTGRES_MAJOR=17
~~~

Install the hardened units:

~~~bash
sudo install -m 0644 deploy/backup/cloudsentinel-postgres-backup.service /etc/systemd/system/
sudo install -m 0644 deploy/backup/cloudsentinel-postgres-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cloudsentinel-postgres-backup.timer
sudo systemctl list-timers cloudsentinel-postgres-backup.timer
~~~

Run one real backup before relying on the timer:

~~~bash
sudo systemctl start cloudsentinel-postgres-backup.service
sudo systemctl status cloudsentinel-postgres-backup.service --no-pager
ls -lh /var/lib/cloudsentinel/backups/
~~~

The backup utility uses a temporary file and atomic rename after a successful pg_dump and rejects mismatched PostgreSQL client major versions.

For production, configure an off-host encrypted destination. A local dump alone is not sufficient for host-loss recovery.

Do not give the backup service Docker socket access merely to run pg_dump inside a container.

## Prometheus and alerting

Production metrics and alert rules are in deploy/observability/.

Prometheus scrapes authenticated API metrics using a credentials file. Alerts cover queue freshness, worker heartbeat, backlog, dead-letter growth and API 5xx errors.

Keep Prometheus and Alertmanager on a private/operator network. External operator notification is intentionally deferred by the current product decision.

## Worker queue reliability

The worker uses Redis Streams recovery and dead-letter handling. Relevant settings include:

- SCAN_QUEUE_MAX_RETRIES
- SCAN_QUEUE_RECOVERY_IDLE_MS
- SCAN_QUEUE_RECOVERY_BATCH_SIZE
- SCAN_QUEUE_READ_BLOCK_MS
- SCAN_QUEUE_DEAD_LETTER_MAX_LENGTH

Investigate dead-letter growth rather than silently increasing the limit.

## Restore safety

Restore drills must use an isolated PostgreSQL instance. The backup utility rejects a target equal to DATABASE_URL and uses pg_restore --exit-on-error.

## Production service health

The production Compose deployment exposes health checks for API, worker and Caddy.

- Worker health checks Redis and worker heartbeat visibility.
- Worker heartbeat/stale thresholds are configurable.
- Caddy health validates the HTTPS proxy path to /health from inside the Caddy container.
- The Caddy healthcheck does not depend on Caddy's disabled admin endpoint.

## Scan result integrity

AWS scans distinguish between complete, completed-with-warnings and failed coverage.

A scan is not treated as trustworthy when every attempted scanner execution failed. Execution errors remain attached to the scan.

An empty finding set is valid when supported checks completed successfully and no implemented rule matched.
