from engine.findings.model import Severity
from engine.rules.aws.rds.deletion_protection import (
    build_rds_deletion_protection_finding,
    check_rds_deletion_protection,
)


def test_rds_without_deletion_protection_is_detected():
    result = check_rds_deletion_protection(
        db_instance_id="cloudsentinel-db",
        deletion_protection=False,
    )

    assert result is not None
    assert result.db_instance_id == "cloudsentinel-db"


def test_rds_with_deletion_protection_is_not_detected():
    result = check_rds_deletion_protection(
        db_instance_id="cloudsentinel-db",
        deletion_protection=True,
    )

    assert result is None


def test_missing_db_instance_id_is_ignored():
    result = check_rds_deletion_protection(
        db_instance_id="",
        deletion_protection=False,
    )

    assert result is None


def test_deletion_protection_finding():
    result = check_rds_deletion_protection(
        db_instance_id="cloudsentinel-db",
        deletion_protection=False,
    )

    finding = build_rds_deletion_protection_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-005"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "rds_instance"
    assert finding.resource_id == "cloudsentinel-db"
    assert finding.evidence["deletion_protection"] is False
