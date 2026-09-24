from engine.findings.model import Severity
from engine.rules.aws.sns.delivery_status import (
    build_sns_delivery_status_finding,
    check_sns_delivery_status,
)
from engine.rules.aws.sns.encryption import (
    build_sns_encryption_finding,
    check_sns_encryption,
)
from engine.rules.aws.sns.public_access import (
    build_sns_public_access_finding,
    check_sns_public_access,
)
from engine.rules.aws.sns.tagging import (
    build_sns_tagging_finding,
    check_sns_tagging,
)


TOPIC_ARN = "arn:aws:sns:ap-south-1:123456789012:cloudsentinel"


def test_public_access_detects_wildcard_principal():
    result = check_sns_public_access(
        TOPIC_ARN,
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sns:Publish",
                    "Resource": TOPIC_ARN,
                }
            ]
        },
    )

    assert result.public_access is True
    assert len(result.public_statements) == 1

    finding = build_sns_public_access_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-SNS-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == TOPIC_ARN


def test_public_access_allows_non_public_principal():
    result = check_sns_public_access(
        TOPIC_ARN,
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "sns:Publish",
                    "Resource": TOPIC_ARN,
                }
            ]
        },
    )

    assert result.public_access is False
    assert build_sns_public_access_finding(result) is None


def test_encryption_detects_missing_kms_key():
    result = check_sns_encryption(
        TOPIC_ARN,
        {},
    )

    assert result.encryption_enabled is False
    assert result.kms_master_key_id is None

    finding = build_sns_encryption_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-SNS-002"
    assert finding.severity == Severity.MEDIUM


def test_encryption_passes_when_kms_key_is_configured():
    result = check_sns_encryption(
        TOPIC_ARN,
        {
            "KmsMasterKeyId": "alias/aws/sns",
        },
    )

    assert result.encryption_enabled is True
    assert result.kms_master_key_id == "alias/aws/sns"
    assert build_sns_encryption_finding(result) is None


def test_delivery_status_detects_missing_configuration():
    result = check_sns_delivery_status(
        TOPIC_ARN,
        {},
    )

    assert result.logging_configured is False
    assert result.configured_protocols == []

    finding = build_sns_delivery_status_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-SNS-003"
    assert finding.severity == Severity.LOW


def test_delivery_status_passes_when_protocol_is_configured():
    result = check_sns_delivery_status(
        TOPIC_ARN,
        {
            "HTTPSuccessFeedbackRoleArn": (
                "arn:aws:iam::123456789012:role/sns-feedback"
            )
        },
    )

    assert result.logging_configured is True
    assert result.configured_protocols == ["HTTP"]
    assert build_sns_delivery_status_finding(result) is None


def test_tagging_detects_missing_tags():
    result = check_sns_tagging(
        TOPIC_ARN,
        [],
    )

    assert result.tagged is False
    assert result.tags == []

    finding = build_sns_tagging_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-SNS-004"
    assert finding.severity == Severity.LOW


def test_tagging_passes_when_valid_tag_exists():
    result = check_sns_tagging(
        TOPIC_ARN,
        [
            {
                "Key": "Environment",
                "Value": "production",
            }
        ],
    )

    assert result.tagged is True
    assert build_sns_tagging_finding(result) is None
