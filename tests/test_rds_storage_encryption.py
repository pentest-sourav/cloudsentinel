from engine.findings.model import Severity
from engine.rules.aws.rds.storage_encryption import (
    build_rds_storage_encryption_finding,
    check_rds_storage_encryption,
)


def test_unencrypted_rds_is_detected():
    result = check_rds_storage_encryption(
        db_instance_id="test-db",
        storage_encrypted=False,
    )

    assert result is not None
    assert result.db_instance_id == "test-db"


def test_encrypted_rds_is_not_detected():
    result = check_rds_storage_encryption(
        db_instance_id="test-db",
        storage_encrypted=True,
    )

    assert result is None


def test_missing_db_instance_id_is_ignored():
    result = check_rds_storage_encryption(
        db_instance_id="",
        storage_encrypted=False,
    )

    assert result is None


def test_storage_encryption_finding():
    result = check_rds_storage_encryption(
        db_instance_id="test-db",
        storage_encrypted=False,
    )

    finding = build_rds_storage_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-002"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "rds_instance"
    assert finding.resource_id == "test-db"
    assert finding.evidence["storage_encrypted"] is False
