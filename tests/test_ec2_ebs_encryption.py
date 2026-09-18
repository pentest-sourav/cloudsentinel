from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.ebs_encryption import (
    EBSEncryptionResult,
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
    assert isinstance(result, EBSEncryptionResult)
    assert result.instance_id == "i-001"
    assert result.volume_id == "vol-001"
    assert result.encrypted is False
    assert result.is_unencrypted is True


def test_encrypted_ebs_volume_is_not_detected():
    result = check_ebs_encryption(
        instance_id="i-002",
        volume_id="vol-002",
        encrypted=True,
    )

    assert result is None


def test_ebs_encryption_result_is_immutable():
    result = EBSEncryptionResult(
        instance_id="i-003",
        volume_id="vol-003",
        encrypted=False,
    )

    try:
        result.encrypted = True
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "EBSEncryptionResult must be immutable"
        )


def test_ebs_encryption_finding_contains_expected_details():
    result = check_ebs_encryption(
        instance_id="i-001",
        volume_id="vol-001",
        encrypted=False,
    )

    assert result is not None

    finding = build_ebs_encryption_finding(result)

    assert isinstance(finding, Finding)

    assert finding.rule_id == "CS-AWS-EC2-004"
    assert finding.title == "EBS Volume Is Not Encrypted"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "ebs_volume"
    assert finding.resource_id == "vol-001"

    assert "not encrypted" in finding.description.lower()
    assert "i-001" in finding.description
    assert "vol-001" in finding.description

    assert finding.evidence["instance_id"] == "i-001"
    assert finding.evidence["volume_id"] == "vol-001"
    assert finding.evidence["encrypted"] is False
    assert finding.evidence["encryption_status"] == "unencrypted"

    assert finding.remediation
    assert "encrypted" in finding.remediation.lower()

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]


def test_encrypted_volume_never_produces_finding():
    result = check_ebs_encryption(
        instance_id="i-004",
        volume_id="vol-004",
        encrypted=True,
    )

    assert result is None
