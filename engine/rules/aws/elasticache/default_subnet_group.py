from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ElastiCacheDefaultSubnetGroupResult:
    resource_arn: str
    resource_id: str
    subnet_group_name: str | None
    uses_default_subnet_group: bool
    resource: dict[str, Any]


def check_elasticache_default_subnet_group(
    resource_arn: str,
    resource_id: str,
    cache_subnet_group_name: str | None,
    resource: dict[str, Any],
) -> ElastiCacheDefaultSubnetGroupResult:
    uses_default = (
        isinstance(cache_subnet_group_name, str)
        and cache_subnet_group_name.lower() == "default"
    )

    return ElastiCacheDefaultSubnetGroupResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        subnet_group_name=cache_subnet_group_name,
        uses_default_subnet_group=uses_default,
        resource=resource,
    )


def build_elasticache_default_subnet_group_finding(
    result: ElastiCacheDefaultSubnetGroupResult,
) -> Finding | None:
    if not result.uses_default_subnet_group:
        return None

    return Finding(
        rule_id="CS-AWS-ELASTICACHE-007",
        title="ElastiCache Cluster Should Not Use The Default Subnet Group",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="elasticache_cache_cluster",
        resource_id=result.resource_arn or result.resource_id,
        description=(
            "The ElastiCache cache cluster uses the default "
            "subnet group."
        ),
        evidence={
            "resource_id": result.resource_id,
            "cache_subnet_group_name": (
                result.subnet_group_name
            ),
        },
        remediation=(
            "Create and use a custom ElastiCache subnet group "
            "instead of the default subnet group."
        ),
        compliance=[
            "AWS Security Hub ElastiCache.7",
        ],
    )
