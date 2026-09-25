from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ElastiCacheRedisAuthResult:
    resource_arn: str
    resource_id: str
    engine: str | None
    engine_version: str | None
    auth_token_enabled: bool
    applicable: bool
    resource: dict[str, Any]


def _major_version(version: str | None) -> int | None:
    if not isinstance(version, str) or not version:
        return None

    try:
        return int(version.split(".", 1)[0])
    except ValueError:
        return None


def check_elasticache_redis_auth(
    resource_arn: str,
    resource_id: str,
    engine: str | None,
    engine_version: str | None,
    auth_token_enabled: bool | None,
    resource: dict[str, Any],
) -> ElastiCacheRedisAuthResult:
    normalized_engine = (
        engine.lower()
        if isinstance(engine, str)
        else None
    )

    major = _major_version(engine_version)

    applicable = (
        normalized_engine == "redis"
        and major is not None
        and major < 6
    )

    return ElastiCacheRedisAuthResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        engine=engine,
        engine_version=engine_version,
        auth_token_enabled=(
            auth_token_enabled is True
        ),
        applicable=applicable,
        resource=resource,
    )


def build_elasticache_redis_auth_finding(
    result: ElastiCacheRedisAuthResult,
) -> Finding | None:
    if not result.applicable:
        return None

    if result.auth_token_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-ELASTICACHE-006",
        title="ElastiCache Redis OSS Replication Group Should Have AUTH Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="elasticache_replication_group",
        resource_id=result.resource_arn or result.resource_id,
        description=(
            "The ElastiCache Redis OSS replication group uses a "
            "Redis OSS version earlier than 6.0 without AUTH enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            "engine": result.engine,
            "engine_version": result.engine_version,
            "auth_token_enabled": result.auth_token_enabled,
        },
        remediation=(
            "Enable Redis OSS AUTH for the replication group, "
            "or upgrade to Redis OSS 6.0 or later and use RBAC."
        ),
        compliance=[
            "AWS Security Hub ElastiCache.6",
        ],
    )
