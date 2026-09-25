from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ElastiCacheAutomaticBackupsResult:
    resource_arn: str
    resource_id: str
    engine: str | None
    snapshot_retention_limit: int
    automatic_backups_enabled: bool
    resource: dict[str, Any]


def check_elasticache_automatic_backups(
    resource_arn: str,
    resource_id: str,
    engine: str | None,
    snapshot_retention_limit: int | None,
    resource: dict[str, Any],
) -> ElastiCacheAutomaticBackupsResult:
    retention = (
        snapshot_retention_limit
        if isinstance(snapshot_retention_limit, int)
        else 0
    )

    enabled = retention > 0

    return ElastiCacheAutomaticBackupsResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        engine=engine,
        snapshot_retention_limit=retention,
        automatic_backups_enabled=enabled,
        resource=resource,
    )


def build_elasticache_automatic_backups_finding(
    result: ElastiCacheAutomaticBackupsResult,
) -> Finding | None:
    if result.automatic_backups_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-ELASTICACHE-001",
        title="ElastiCache Redis OSS Cluster Does Not Have Automatic Backups Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="elasticache_cache_cluster",
        resource_id=result.resource_arn or result.resource_id,
        description=(
            "The ElastiCache Redis OSS cache cluster does not have "
            "automatic backups enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            "engine": result.engine,
            "snapshot_retention_limit": (
                result.snapshot_retention_limit
            ),
        },
        remediation=(
            "Enable automatic backups by configuring a positive "
            "snapshot retention period."
        ),
        compliance=[
            "AWS Security Hub ElastiCache.1",
        ],
    )
