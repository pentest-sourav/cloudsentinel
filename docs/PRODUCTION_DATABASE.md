# Production Database Connection Management

CloudSentinel uses an explicit SQLAlchemy connection budget for networked production databases.

## Defaults

| Setting | Default | Purpose |
|---|---:|---|
| `DATABASE_POOL_SIZE` | 5 | Persistent connections per API/worker process |
| `DATABASE_MAX_OVERFLOW` | 10 | Temporary connections allowed above the pool |
| `DATABASE_POOL_TIMEOUT_SECONDS` | 30 | Maximum wait for an available connection |
| `DATABASE_POOL_RECYCLE_SECONDS` | 1800 | Recycle long-lived connections |
| `pool_pre_ping` | enabled | Detect stale/broken connections before use |

SQLite test databases intentionally bypass these network-pool settings.

## Why this is a production control

Without an explicit pool budget, scaling API and worker processes can create an uncontrolled database connection footprint. CloudSentinel now makes the budget configurable and bounded at application startup.

A rough upper bound for a deployment is:

`processes × (DATABASE_POOL_SIZE + DATABASE_MAX_OVERFLOW)`

Operators should size that total against PostgreSQL's configured connection limit while reserving capacity for migrations, administration, monitoring, and other trusted clients.

## Deployment

The production Compose stack exposes all four settings as environment variables. The defaults are conservative for a single API + worker deployment and can be tuned for a larger installation.

The application still uses `pool_pre_ping` and `pool_recycle` so stale connections caused by network/database idle timeouts are detected and replaced instead of surfacing as avoidable request failures.

This control does not replace PostgreSQL capacity planning; it provides a deterministic application-side connection budget that can be measured and tuned.
