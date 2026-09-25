from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ElastiCacheAutomaticFailoverResult:
    resource_arn: str
    resource_id: str
    automatic_failover: str | None
    enabled: bool
    resource: dict[str, Any]


def check_elasticache_automatic_failover(
    resource_arn: str,
    resource_id: str,
    automatic_failover: str | None,
    resource: dict[str, Any],
) -> ElastiCacheAutomaticFailoverResult:
    enabled = automatic_failover == "enabled"

    return ElastiCacheAutomaticFailoverResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        automatic_failover=automatic_failover,
        enabled=enabled,
        resource=resource,
    )


def build_elasticache_automatic_failover_finding(
    result: ElastiCacheAutomaticFailoverResult,
) -> Finding | None:
    if result.enabled:
        return None

    return Finding(
        rule_id="CS-AWS-ELASTICACHE-003",
        title="ElastiCache Replication Group Should Have Automatic Failover Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="elasticache_replication_group",
        resource_id=result.resource_arn or result.resource_id,
        description=(
            "The ElastiCache replication group does not have "
            "automatic failover enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            "automatic_failover": result.automatic_failover,
        },
        remediation=(
            "Enable automatic failover for the ElastiCache "
            "replication group."
        ),
        compliance=[
            "AWS Security Hub ElastiCache.3",
        ],
    )
