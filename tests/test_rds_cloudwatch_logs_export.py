from engine.rules.aws.rds.cloudwatch_logs_export import (
    build_rds_cloudwatch_logs_export_finding,
    check_rds_cloudwatch_logs_export,
)


def test_detects_missing_cloudwatch_log_exports():
    result = check_rds_cloudwatch_logs_export(
        db_instance_id="db-1",
        engine="postgres",
        enabled_cloudwatch_logs_exports=[],
    )

    assert result is not None
    assert result.enabled_cloudwatch_logs_exports == ()

    finding = build_rds_cloudwatch_logs_export_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-008"
    assert finding.severity.value == "medium"


def test_accepts_configured_cloudwatch_log_exports():
    assert (
        check_rds_cloudwatch_logs_export(
            db_instance_id="db-1",
            engine="postgres",
            enabled_cloudwatch_logs_exports=["postgresql"],
        )
        is None
    )


def test_normalizes_duplicate_log_exports():
    result = check_rds_cloudwatch_logs_export(
        db_instance_id="db-1",
        engine="postgres",
        enabled_cloudwatch_logs_exports=[
            "postgresql",
            "postgresql",
            " error ",
        ],
    )

    assert result is None


def test_skips_missing_log_export_data():
    assert (
        check_rds_cloudwatch_logs_export(
            db_instance_id="db-1",
            engine="postgres",
            enabled_cloudwatch_logs_exports=None,
        )
        is None
    )


def test_skips_aurora():
    assert (
        check_rds_cloudwatch_logs_export(
            db_instance_id="db-1",
            engine="aurora-postgresql",
            enabled_cloudwatch_logs_exports=[],
        )
        is None
    )


def test_skips_rds_custom():
    assert (
        check_rds_cloudwatch_logs_export(
            db_instance_id="db-1",
            engine="custom-oracle-ee",
            enabled_cloudwatch_logs_exports=[],
        )
        is None
    )
