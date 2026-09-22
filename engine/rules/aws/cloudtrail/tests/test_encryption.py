from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.encryption import (
    build_cloudtrail_encryption_finding,
    check_cloudtrail_encryption,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)

KMS_KEY_ARN = (
    "arn:aws:kms:eu-north-1:"
    "123456789012:key/12345678-1234-1234-1234-123456789012"
)


def test_cloudtrail_without_kms_key_is_detected():
    result = check_cloudtrail_encryption(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        kms_key_id=None,
    )

    assert result is not None
    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.kms_key_id is None


def test_cloudtrail_with_kms_key_is_ignored():
    result = check_cloudtrail_encryption(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        kms_key_id=KMS_KEY_ARN,
    )

    assert result is None


def test_empty_kms_key_is_detected():
    result = check_cloudtrail_encryption(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        kms_key_id="",
    )

    assert result is not None
    assert result.kms_key_id is None


def test_cloudtrail_encryption_finding_is_built_correctly():
    result = check_cloudtrail_encryption(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        kms_key_id=None,
    )

    finding = build_cloudtrail_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-CT-006"
    assert finding.title == (
        "CloudTrail trail is not encrypted with a KMS key"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN

    assert finding.evidence == {
        "trail_arn": TRAIL_ARN,
        "trail_name": "cloudtrail-main",
        "kms_key_id": None,
    }

    assert finding.remediation
    assert "CIS AWS Foundations" in finding.compliance
