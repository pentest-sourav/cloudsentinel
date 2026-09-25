from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ElastiCacheEncryptionAtRestResult:
    resource_arn: str
    resource_id: str
    engine: str | None
    encryption_enabled: bool
    resource: dict[str, Any]


def check_elasticache_encryption_at_rest(
    resource_arn: str,
    resource_id: str,
    engine: str | None,
    at_rest_encryption_enabled: bool | None,
    resource: dict[str, Any],
) -> ElastiCacheEncryptionAtRestResult:
    return ElastiCacheEncryptionAtRestResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        engine=engine,
        encryption_enabled=(
            at_rest_encryption_enabled is True
        ),
        resource=resource,
    )


def build_elasticache_encryption_at_rest_finding(
    result: ElastiCacheEncryptionAtRestResult,
) -> Finding | None:
    if result.encryption_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-ELASTICACHE-004",
        title="ElastiCache Replication Group Should Be Encrypted At Rest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="elasticache_replication_group",
        resource_id=result.resource_arn or result.resource_id,
        description=(
            "The ElastiCache replication group does not have "
            "encryption at rest enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            "engine": result.engine,
            "at_rest_encryption_enabled": (
                result.encryption_enabled
            ),
        },
        remediation=(
            "Enable encryption at rest for the ElastiCache "
            "replication group."
        ),
        compliance=[
            "AWS Security Hub ElastiCache.4",
        ],
    )
