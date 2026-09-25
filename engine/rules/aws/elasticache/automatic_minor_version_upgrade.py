from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ElastiCacheAutomaticMinorVersionUpgradeResult:
    resource_arn: str
    resource_id: str
    engine: str | None
    engine_version: str | None
    auto_minor_version_upgrade: bool
    applicable: bool
    resource: dict[str, Any]


def _major_version(version: str | None) -> int | None:
    if not isinstance(version, str) or not version:
        return None

    try:
        return int(version.split(".", 1)[0])
    except ValueError:
        return None


def check_elasticache_automatic_minor_version_upgrade(
    resource_arn: str,
    resource_id: str,
    engine: str | None,
    engine_version: str | None,
    auto_minor_version_upgrade: bool | None,
    resource: dict[str, Any],
) -> ElastiCacheAutomaticMinorVersionUpgradeResult:
    normalized_engine = (
        engine.lower()
        if isinstance(engine, str)
        else None
    )

    major = _major_version(engine_version)

    applicable = (
        normalized_engine == "redis"
        and (major is None or major >= 6)
    )

    return ElastiCacheAutomaticMinorVersionUpgradeResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        engine=engine,
        engine_version=engine_version,
        auto_minor_version_upgrade=(
            auto_minor_version_upgrade is True
        ),
        applicable=applicable,
        resource=resource,
    )


def build_elasticache_automatic_minor_version_upgrade_finding(
    result: ElastiCacheAutomaticMinorVersionUpgradeResult,
) -> Finding | None:
    if not result.applicable:
        return None

    if result.auto_minor_version_upgrade:
        return None

    return Finding(
        rule_id="CS-AWS-ELASTICACHE-002",
        title="ElastiCache Cluster Should Have Automatic Minor Version Upgrades Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="elasticache_cache_cluster",
        resource_id=result.resource_arn or result.resource_id,
        description=(
            "The ElastiCache Redis OSS cluster does not have "
            "automatic minor version upgrades enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            "engine": result.engine,
            "engine_version": result.engine_version,
            "auto_minor_version_upgrade": (
                result.auto_minor_version_upgrade
            ),
        },
        remediation=(
            "Enable automatic minor version upgrades for the "
            "ElastiCache Redis OSS cluster."
        ),
        compliance=[
            "AWS Security Hub ElastiCache.2",
        ],
    )
