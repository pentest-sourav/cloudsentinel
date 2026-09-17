from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.ebs_encryption import (
    build_ebs_encryption_finding,
    check_ebs_encryption,
)


def test_unencrypted_ebs_volume_is_detected():
    result = check_ebs_encryption(
        instance_id="i-001",
        volume_id="vol-001",
        encrypted=False,
    )

    assert result is not None
    assert result.instance_id == "i-001"
    assert result.volume_id == "vol-001"
    assert result.encrypted is False


def test_encrypted_ebs_volume_is_not_detected():
    result = check_ebs_encryption(
        instance_id="i-002",
        volume_id="vol-002",
        encrypted=True,
    )

    assert result is None


def test_ebs_encryption_finding_contains_expected_details():
    result = check_ebs_encryption(
        instance_id="i-001",
        volume_id="vol-001",
        encrypted=False,
    )

    finding = build_ebs_encryption_finding(result)

    assert isinstance(finding, Finding)

    assert finding.rule_id == "CS-AWS-EC2-004"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "ebs_volume"
    assert finding.resource_id == "vol-001"

    assert finding.evidence["instance_id"] == "i-001"
    assert finding.evidence["volume_id"] == "vol-001"
    assert finding.evidence["encrypted"] is False
