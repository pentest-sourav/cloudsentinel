from engine.rules.aws.rds.backup_retention import (
    build_rds_backup_retention_finding,
    check_rds_backup_retention,
)
from engine.findings.model import Severity


def test_rds_without_backup_retention_is_detected():
    result = check_rds_backup_retention(
        db_instance_id="cloudsentinel-db",
        backup_retention_period=0,
    )

    assert result is not None
    assert result.db_instance_id == "cloudsentinel-db"
    assert result.backup_retention_period == 0


def test_rds_with_backup_retention_is_not_detected():
    result = check_rds_backup_retention(
        db_instance_id="cloudsentinel-db",
        backup_retention_period=7,
    )

    assert result is None


def test_missing_db_instance_id_is_ignored():
    result = check_rds_backup_retention(
        db_instance_id="",
        backup_retention_period=0,
    )

    assert result is None


def test_backup_retention_finding():
    result = check_rds_backup_retention(
        db_instance_id="cloudsentinel-db",
        backup_retention_period=0,
    )

    finding = build_rds_backup_retention_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-003"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "rds_instance"
    assert finding.resource_id == "cloudsentinel-db"
    assert finding.evidence["backup_retention_period"] == 0
