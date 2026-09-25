from engine.findings.model import Severity

from engine.rules.aws.elasticache.automatic_backups import (
    build_elasticache_automatic_backups_finding,
    check_elasticache_automatic_backups,
)
from engine.rules.aws.elasticache.automatic_failover import (
    build_elasticache_automatic_failover_finding,
    check_elasticache_automatic_failover,
)
from engine.rules.aws.elasticache.automatic_minor_version_upgrade import (
    build_elasticache_automatic_minor_version_upgrade_finding,
    check_elasticache_automatic_minor_version_upgrade,
)
from engine.rules.aws.elasticache.default_subnet_group import (
    build_elasticache_default_subnet_group_finding,
    check_elasticache_default_subnet_group,
)
from engine.rules.aws.elasticache.encryption_at_rest import (
    build_elasticache_encryption_at_rest_finding,
    check_elasticache_encryption_at_rest,
)
from engine.rules.aws.elasticache.encryption_in_transit import (
    build_elasticache_encryption_in_transit_finding,
    check_elasticache_encryption_in_transit,
)
from engine.rules.aws.elasticache.redis_auth import (
    build_elasticache_redis_auth_finding,
    check_elasticache_redis_auth,
)


ARN = (
    "arn:aws:elasticache:ap-south-1:"
    "123456789012:resource:test"
)


def test_automatic_backups_passes():
    result = check_elasticache_automatic_backups(
        ARN,
        "cluster-1",
        "redis",
        7,
        {},
    )

    assert result.automatic_backups_enabled is True
    assert build_elasticache_automatic_backups_finding(result) is None


def test_automatic_backups_fails():
    result = check_elasticache_automatic_backups(
        ARN,
        "cluster-1",
        "redis",
        0,
        {},
    )

    finding = build_elasticache_automatic_backups_finding(result)

    assert result.automatic_backups_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-ELASTICACHE-001"
    assert finding.severity == Severity.MEDIUM


def test_minor_upgrade_passes():
    result = check_elasticache_automatic_minor_version_upgrade(
        ARN,
        "cluster-1",
        "redis",
        "7.1",
        True,
        {},
    )

    assert result.applicable is True
    assert result.auto_minor_version_upgrade is True
    assert (
        build_elasticache_automatic_minor_version_upgrade_finding(
            result
        )
        is None
    )


def test_minor_upgrade_fails():
    result = check_elasticache_automatic_minor_version_upgrade(
        ARN,
        "cluster-1",
        "redis",
        "7.1",
        False,
        {},
    )

    finding = (
        build_elasticache_automatic_minor_version_upgrade_finding(
            result
        )
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-ELASTICACHE-002"
    assert finding.severity == Severity.HIGH


def test_minor_upgrade_not_applicable_to_old_redis():
    result = check_elasticache_automatic_minor_version_upgrade(
        ARN,
        "cluster-1",
        "redis",
        "5.0.6",
        False,
        {},
    )

    assert result.applicable is False
    assert (
        build_elasticache_automatic_minor_version_upgrade_finding(
            result
        )
        is None
    )


def test_automatic_failover_passes():
    result = check_elasticache_automatic_failover(
        ARN,
        "group-1",
        "enabled",
        {},
    )

    assert result.enabled is True
    assert build_elasticache_automatic_failover_finding(result) is None


def test_automatic_failover_fails():
    result = check_elasticache_automatic_failover(
        ARN,
        "group-1",
        "disabled",
        {},
    )

    finding = build_elasticache_automatic_failover_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-ELASTICACHE-003"
    assert finding.severity == Severity.MEDIUM


def test_encryption_at_rest_passes():
    result = check_elasticache_encryption_at_rest(
        ARN,
        "group-1",
        "redis",
        True,
        {},
    )

    assert result.encryption_enabled is True
    assert build_elasticache_encryption_at_rest_finding(result) is None


def test_encryption_at_rest_fails():
    result = check_elasticache_encryption_at_rest(
        ARN,
        "group-1",
        "redis",
        False,
        {},
    )

    finding = build_elasticache_encryption_at_rest_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-ELASTICACHE-004"


def test_encryption_in_transit_passes():
    result = check_elasticache_encryption_in_transit(
        ARN,
        "group-1",
        "redis",
        True,
        {},
    )

    assert result.encryption_enabled is True
    assert (
        build_elasticache_encryption_in_transit_finding(result)
        is None
    )


def test_encryption_in_transit_fails():
    result = check_elasticache_encryption_in_transit(
        ARN,
        "group-1",
        "redis",
        False,
        {},
    )

    finding = build_elasticache_encryption_in_transit_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-ELASTICACHE-005"


def test_redis_auth_passes_for_old_redis_with_auth():
    result = check_elasticache_redis_auth(
        ARN,
        "group-1",
        "redis",
        "5.0.6",
        True,
        {},
    )

    assert result.applicable is True
    assert result.auth_token_enabled is True
    assert build_elasticache_redis_auth_finding(result) is None


def test_redis_auth_fails_for_old_redis_without_auth():
    result = check_elasticache_redis_auth(
        ARN,
        "group-1",
        "redis",
        "5.0.6",
        False,
        {},
    )

    finding = build_elasticache_redis_auth_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-ELASTICACHE-006"
    assert finding.severity == Severity.MEDIUM


def test_redis_auth_not_applicable_to_redis_6():
    result = check_elasticache_redis_auth(
        ARN,
        "group-1",
        "redis",
        "6.2",
        False,
        {},
    )

    assert result.applicable is False
    assert build_elasticache_redis_auth_finding(result) is None


def test_default_subnet_group_passes_for_custom_group():
    result = check_elasticache_default_subnet_group(
        ARN,
        "cluster-1",
        "custom-subnet-group",
        {},
    )

    assert result.uses_default_subnet_group is False
    assert build_elasticache_default_subnet_group_finding(result) is None


def test_default_subnet_group_fails():
    result = check_elasticache_default_subnet_group(
        ARN,
        "cluster-1",
        "default",
        {},
    )

    finding = build_elasticache_default_subnet_group_finding(result)

    assert result.uses_default_subnet_group is True
    assert finding is not None
    assert finding.rule_id == "CS-AWS-ELASTICACHE-007"
    assert finding.severity == Severity.HIGH
