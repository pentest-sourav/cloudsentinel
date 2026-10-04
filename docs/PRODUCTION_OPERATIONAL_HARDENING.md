# Production Operational Hardening

This milestone focuses on controls that matter after deployment, not only feature correctness.

## Metrics cardinality

The in-process Prometheus registry has a hard series limit. This prevents an attacker or accidental high-cardinality route from causing unbounded process memory growth.

## Dependency degradation

The API tracks repeated database dependency failures and exposes the state through the existing readiness contract. Readiness remains a hard dependency check: traffic should only be routed to an instance whose database and Redis dependencies are healthy.

## Deployment principle

Production observability must remain bounded and failure-tolerant:

- metrics collection must not become an availability dependency
- readiness must fail closed when required dependencies are unavailable
- telemetry cardinality must have an explicit budget
- application logs remain structured JSON in production
- database connection pools are explicitly bounded

These controls complement, rather than replace, external monitoring, alerting, capacity planning, and incident response.
