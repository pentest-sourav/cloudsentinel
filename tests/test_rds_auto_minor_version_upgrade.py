from engine.rules.aws.rds.auto_minor_version_upgrade import (
    build_rds_auto_minor_version_upgrade_finding,
    check_rds_auto_minor_version_upgrade,
)


def test_detects_disabled_auto_minor_version_upgrade():
    result = check_rds_auto_minor_version_upgrade(
        db_instance_id="db-1",
        engine="postgres",
        auto_minor_version_upgrade=False,
    )

    assert result is not None
    assert result.db_instance_id == "db-1"

    finding = build_rds_auto_minor_version_upgrade_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-006"
    assert finding.severity.value == "medium"


def test_accepts_enabled_auto_minor_version_upgrade():
    assert (
        check_rds_auto_minor_version_upgrade(
            db_instance_id="db-1",
            engine="postgres",
            auto_minor_version_upgrade=True,
        )
        is None
    )


def test_skips_missing_auto_minor_version_upgrade_data():
    assert (
        check_rds_auto_minor_version_upgrade(
            db_instance_id="db-1",
            engine="postgres",
            auto_minor_version_upgrade=None,
        )
        is None
    )


def test_skips_aurora_instance_level_evaluation():
    assert (
        check_rds_auto_minor_version_upgrade(
            db_instance_id="db-1",
            engine="aurora-postgresql",
            auto_minor_version_upgrade=False,
        )
        is None
    )


def test_skips_rds_custom():
    assert (
        check_rds_auto_minor_version_upgrade(
            db_instance_id="db-1",
            engine="custom-oracle-ee",
            auto_minor_version_upgrade=False,
        )
        is None
    )
