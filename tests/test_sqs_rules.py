from engine.findings.model import Severity
from engine.rules.aws.sqs.encryption import (
    build_sqs_encryption_finding,
    check_sqs_encryption,
)
from engine.rules.aws.sqs.public_access import (
    build_sqs_public_access_finding,
    check_sqs_public_access,
)
from engine.rules.aws.sqs.tagging import (
    build_sqs_tagging_finding,
    check_sqs_tagging,
)


QUEUE_ARN = "arn:aws:sqs:ap-south-1:123456789012:test-queue"


def test_sqs_encryption_passes_with_sse_sqs():
    result = check_sqs_encryption(
        QUEUE_ARN,
        None,
        "true",
    )

    assert result.encryption_enabled is True
    assert result.encryption_type == "SSE-SQS"
    assert build_sqs_encryption_finding(result) is None


def test_sqs_encryption_passes_with_kms():
    result = check_sqs_encryption(
        QUEUE_ARN,
        "alias/my-key",
        "false",
    )

    assert result.encryption_enabled is True
    assert result.encryption_type == "SSE-KMS"
    assert build_sqs_encryption_finding(result) is None


def test_sqs_encryption_fails_without_encryption():
    result = check_sqs_encryption(
        QUEUE_ARN,
        None,
        "false",
    )

    finding = build_sqs_encryption_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-SQS-001"
    assert finding.severity == Severity.MEDIUM


def test_sqs_tagging_passes_with_non_system_tag():
    result = check_sqs_tagging(
        QUEUE_ARN,
        [
            {"Key": "Environment", "Value": "prod"},
        ],
    )

    assert result.tagged is True
    assert build_sqs_tagging_finding(result) is None


def test_sqs_tagging_ignores_system_tags():
    result = check_sqs_tagging(
        QUEUE_ARN,
        [
            {"Key": "aws:cloudformation:stack-id", "Value": "stack"},
        ],
    )

    finding = build_sqs_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-SQS-002"


def test_sqs_public_access_detects_wildcard_principal():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": QUEUE_ARN,
            }
        ]
    }

    result = check_sqs_public_access(QUEUE_ARN, policy)

    assert result.public_access is True

    finding = build_sqs_public_access_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-SQS-003"
    assert finding.severity == Severity.CRITICAL


def test_sqs_public_access_detects_wildcard_aws_principal():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sqs:ReceiveMessage",
                "Resource": QUEUE_ARN,
            }
        ]
    }

    result = check_sqs_public_access(QUEUE_ARN, policy)

    assert result.public_access is True


def test_sqs_public_access_allows_fixed_condition():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": QUEUE_ARN,
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": (
                            "arn:aws:sns:ap-south-1:"
                            "123456789012:notifications"
                        )
                    }
                },
            }
        ]
    }

    result = check_sqs_public_access(QUEUE_ARN, policy)

    assert result.public_access is False
    assert build_sqs_public_access_finding(result) is None


def test_sqs_public_access_rejects_wildcard_condition():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": QUEUE_ARN,
                "Condition": {
                    "ArnLike": {
                        "aws:SourceArn": "arn:aws:sns:*"
                    }
                },
            }
        ]
    }

    result = check_sqs_public_access(QUEUE_ARN, policy)

    assert result.public_access is True


def test_sqs_public_access_rejects_policy_variable():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": QUEUE_ARN,
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/Team": "${aws:username}"
                    }
                },
            }
        ]
    }

    result = check_sqs_public_access(QUEUE_ARN, policy)

    assert result.public_access is True


def test_sqs_public_access_ignores_deny_statement():
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sqs:*",
                "Resource": QUEUE_ARN,
            }
        ]
    }

    result = check_sqs_public_access(QUEUE_ARN, policy)

    assert result.public_access is False
