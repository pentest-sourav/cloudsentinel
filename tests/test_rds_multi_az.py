from engine.findings.model import Severity
from engine.rules.aws.rds.multi_az import (
    build_rds_multi_az_finding,
    check_rds_multi_az,
)


def test_rds_without_multi_az_is_detected():
    result = check_rds_multi_az(
        db_instance_id="cloudsentinel-db",
        multi_az=False,
    )

    assert result is not None
    assert result.db_instance_id == "cloudsentinel-db"


def test_rds_with_multi_az_is_not_detected():
    result = check_rds_multi_az(
        db_instance_id="cloudsentinel-db",
        multi_az=True,
    )

    assert result is None


def test_missing_db_instance_id_is_ignored():
    result = check_rds_multi_az(
        db_instance_id="",
        multi_az=False,
    )

    assert result is None


def test_multi_az_finding():
    result = check_rds_multi_az(
        db_instance_id="cloudsentinel-db",
        multi_az=False,
    )

    finding = build_rds_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-004"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "rds_instance"
    assert finding.resource_id == "cloudsentinel-db"
    assert finding.evidence["multi_az"] is False
