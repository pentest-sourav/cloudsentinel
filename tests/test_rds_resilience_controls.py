from engine.findings.model import Severity
from engine.rules.aws.rds.resilience_controls import (
    build_rds_aurora_backtracking_finding,
    build_rds_cluster_multi_az_finding,
    build_rds_global_cluster_supported_version_finding,
    check_rds_aurora_backtracking,
    check_rds_cluster_multi_az,
    check_rds_global_cluster_supported_version,
)


def test_aurora_backtracking_enabled_is_compliant():
    result = check_rds_aurora_backtracking(
        db_cluster_id="cluster-001",
        engine="aurora-mysql",
        backtrack_window=86400,
    )

    assert result is None


def test_aurora_backtracking_disabled_is_non_compliant():
    result = check_rds_aurora_backtracking(
        db_cluster_id="cluster-001",
        engine="aurora-mysql",
        backtrack_window=0,
    )

    assert result is not None
    assert result.evidence["backtracking_enabled"] is False

    finding = build_rds_aurora_backtracking_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-030"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "cluster-001"


def test_aurora_backtracking_ignores_postgres():
    result = check_rds_aurora_backtracking(
        db_cluster_id="cluster-002",
        engine="aurora-postgresql",
        backtrack_window=0,
    )

    assert result is None


def test_rds_cluster_multi_az_passes_with_two_zones():
    result = check_rds_cluster_multi_az(
        db_cluster_id="cluster-001",
        engine="aurora-mysql",
        availability_zone_count=2,
    )

    assert result is None


def test_rds_cluster_multi_az_fails_with_one_zone():
    result = check_rds_cluster_multi_az(
        db_cluster_id="cluster-001",
        engine="aurora-mysql",
        availability_zone_count=1,
    )

    assert result is not None
    assert result.evidence["multi_az"] is False

    finding = build_rds_cluster_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-031"
    assert finding.severity == Severity.MEDIUM


def test_global_cluster_supported_minimum_version():
    result = check_rds_global_cluster_supported_version(
        global_cluster_id="global-001",
        engine="aurora-mysql",
        engine_version="8.0.mysql_aurora.3.08.0",
    )

    assert result is None


def test_global_cluster_supported_lts_version():
    result = check_rds_global_cluster_supported_version(
        global_cluster_id="global-001",
        engine="aurora-mysql",
        engine_version="8.0.mysql_aurora.3.04.3",
    )

    assert result is None


def test_global_cluster_unsupported_version():
    result = check_rds_global_cluster_supported_version(
        global_cluster_id="global-001",
        engine="aurora-mysql",
        engine_version="8.0.mysql_aurora.3.07.0",
    )

    assert result is not None
    assert (
        result.evidence["minimum_supported_version"]
        == "8.0.mysql_aurora.3.08.0"
    )

    finding = (
        build_rds_global_cluster_supported_version_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-RDS-032"
    assert finding.severity == Severity.HIGH


def test_global_cluster_ignores_non_aurora_mysql():
    result = check_rds_global_cluster_supported_version(
        global_cluster_id="global-001",
        engine="aurora-postgresql",
        engine_version="16.1",
    )

    assert result is None


def test_global_cluster_malformed_version_fails_closed():
    result = check_rds_global_cluster_supported_version(
        global_cluster_id="global-001",
        engine="aurora-mysql",
        engine_version="not-a-valid-version",
    )

    assert result is not None
