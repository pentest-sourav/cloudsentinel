# Production Operations Runbook

## PostgreSQL backup and recovery

CloudSentinel treats PostgreSQL as the system of record for tenants, cloud-account
connections, scan history, findings, audit events, and related application state.
A backup is useful only when it can be verified and restored.

### Backup policy

Set these production environment variables:

- `DATABASE_URL`: PostgreSQL connection URL.
- `BACKUP_OUTPUT_DIR`: local staging directory, preferably on encrypted storage.
- `BACKUP_S3_BUCKET`: optional off-host backup bucket.
- `BACKUP_S3_PREFIX`: optional object prefix; defaults to `cloudsentinel/postgres`.
- `BACKUP_S3_KMS_KEY_ID`: optional KMS key. Without it, S3 server-side AES-256 encryption is used.
- `BACKUP_LOCAL_RETENTION_DAYS`: local retention; defaults to 14 days.

Use an external scheduler such as Kubernetes CronJob, ECS scheduled task, systemd timer,
or the managed platform scheduler to run:

```bash
python ops/backup/postgres_backup.py backup
```

The scheduler should run at least daily. The backup host/runtime should have permission
to write the configured backup destination but should not have application database
write credentials beyond what `pg_dump` requires.

### Verification

Every newly created backup should be checked before it is considered usable:

```bash
python ops/backup/postgres_backup.py verify backups/postgres/cloudsentinel-postgres-<timestamp>.dump
```

Verification checks both the SHA-256 manifest and PostgreSQL archive readability with
`pg_restore --list`.

### Restore drill

A restore drill must use an isolated PostgreSQL instance, never the live production
database.

```bash
RESTORE_DATABASE_URL='postgresql+psycopg://...' \
python ops/backup/postgres_backup.py restore \
  backups/postgres/cloudsentinel-postgres-<timestamp>.dump
```

After restoration:

1. Run `alembic upgrade head`.
2. Start the API against the restored database.
3. Check `/ready`.
4. Confirm tenant/user counts against the backup metadata or expected inventory.
5. Execute a representative authenticated read-only API request.
6. Record the restore duration and outcome.

Do not point the restore command at the live database unless the incident runbook
explicitly requires destructive recovery and an operator has approved it.

### Recovery objectives

The application does not claim a fixed RPO/RTO until deployment infrastructure is
measured. Operators should record:

- backup interval (RPO target)
- backup completion time
- restore duration (RTO measurement)
- last successful restore drill
- backup retention
- off-site replication status

### Redis

Redis is a queue/cache dependency, not the authoritative source of scan history.
The worker queue already supports pending-message recovery and a dead-letter stream.
Production deployments should enable Redis persistence appropriate to the infrastructure,
but PostgreSQL remains the authoritative recovery target.

### Secrets

Do not place database passwords, AWS credentials, JWT secrets, or backup credentials in
repository files. Use the deployment platform's secret store or an external secret
manager and grant the backup runtime only the permissions it needs.


## Worker queue reliability

The worker's Redis Streams recovery behavior is configurable through:

- `SCAN_QUEUE_MAX_RETRIES`: maximum reclaim attempts before dead-lettering.
- `SCAN_QUEUE_RECOVERY_IDLE_MS`: minimum pending-message idle time before reclaim.
- `SCAN_QUEUE_RECOVERY_BATCH_SIZE`: maximum recovered jobs handled per recovery pass.
- `SCAN_QUEUE_READ_BLOCK_MS`: maximum blocking interval for new jobs, which bounds graceful shutdown latency.
- `SCAN_QUEUE_DEAD_LETTER_MAX_LENGTH`: approximate cap for the dead-letter stream.

The dead-letter stream is intentionally bounded so repeated scanner failures cannot
consume unbounded Redis memory. Operators should alert on dead-letter growth and
investigate the underlying scan failure rather than silently increasing the limit.

For controlled shutdown, send SIGTERM to the worker. It stops accepting the next
queue read, finishes the current job, acknowledges only successfully completed jobs,
and closes the Redis connection. Container orchestration should allow enough
termination grace time for the configured scan workload.


### Restore safety

Restore drills must use an isolated PostgreSQL instance. The backup utility rejects a target equal to `DATABASE_URL` and uses `pg_restore --exit-on-error` so a partial restore is not silently accepted.


## Production service health

The production Compose deployment exposes health checks for the API, worker, and Caddy edge proxy.

- The worker health check verifies Redis connectivity and that its expiring worker heartbeat is visible.
- Worker heartbeat and stale-scan thresholds are explicitly configurable through the production environment.
- The Caddy health check verifies its local admin metrics endpoint without exposing that endpoint through the public edge network.

Treat an unhealthy worker as an operational incident: the Redis queue may still retain pending jobs for another worker, but scheduled scans and capacity may be degraded until the worker is restored.
