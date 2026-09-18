from engine.findings.model import Severity
from engine.rules.aws.rds.public_access import (
    RDSPublicAccessResult,
    build_public_rds_finding,
    check_public_rds,
)


def test_public_rds_is_detected():
    result = check_public_rds(
        db_instance_id="cloudsentinel-db",
        publicly_accessible=True,
    )

    assert result == RDSPublicAccessResult(
        db_instance_id="cloudsentinel-db",
    )


def test_private_rds_is_not_detected():
    result = check_public_rds(
        db_instance_id="cloudsentinel-db",
        publicly_accessible=False,
    )

    assert result is None


def test_missing_db_instance_id_is_not_detected():
    result = check_public_rds(
        db_instance_id="",
        publicly_accessible=True,
    )

    assert result is None


def test_public_rds_finding_metadata():
    result = check_public_rds(
        db_instance_id="cloudsentinel-db",
        publicly_accessible=True,
    )

    assert result is not None

    finding = build_public_rds_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-001"
    assert finding.title == "RDS Instance Is Publicly Accessible"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "rds_instance"
    assert finding.resource_id == "cloudsentinel-db"


def test_public_rds_finding_contains_exposure_evidence():
    result = check_public_rds(
        db_instance_id="cloudsentinel-db",
        publicly_accessible=True,
    )

    assert result is not None

    finding = build_public_rds_finding(result)

    assert finding.evidence == {
        "db_instance_id": "cloudsentinel-db",
        "publicly_accessible": True,
        "internet_exposed": True,
    }


def test_public_rds_finding_contains_remediation():
    result = check_public_rds(
        db_instance_id="cloudsentinel-db",
        publicly_accessible=True,
    )

    assert result is not None

    finding = build_public_rds_finding(result)

    assert "Disable public accessibility" in finding.remediation
    assert "private subnets" in finding.remediation
    assert finding.compliance == ["CIS AWS Foundations"]
