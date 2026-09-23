from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.ebs_default_encryption import (
    EBSDefaultEncryptionResult,
    build_ebs_default_encryption_finding,
    check_ebs_default_encryption,
)


def test_disabled_ebs_default_encryption_is_detected():
    result = check_ebs_default_encryption(
        ebs_encryption_by_default=False,
    )

    assert result is not None
    assert isinstance(result, EBSDefaultEncryptionResult)
    assert result.enabled is False


def test_enabled_ebs_default_encryption_is_not_detected():
    result = check_ebs_default_encryption(
        ebs_encryption_by_default=True,
    )

    assert result is None


def test_ebs_default_encryption_finding_contains_expected_details():
    result = check_ebs_default_encryption(
        ebs_encryption_by_default=False,
    )

    assert result is not None

    finding = build_ebs_default_encryption_finding(result)

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-006"
    assert finding.title == "EBS Encryption by Default Is Disabled"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "aws_ec2_region"

    assert finding.evidence["ebs_encryption_by_default"] is False
    assert finding.remediation
    assert "encryption" in finding.remediation.lower()


def test_enabled_default_encryption_never_produces_finding():
    result = check_ebs_default_encryption(
        ebs_encryption_by_default=True,
    )

    assert result is None
