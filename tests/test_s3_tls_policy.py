from engine.findings.model import Severity
from engine.rules.aws.s3.tls_policy import (
    build_s3_tls_policy_finding,
    check_s3_tls_policy,
)


def tls_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::secure-bucket",
                    "arn:aws:s3:::secure-bucket/*",
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false",
                    }
                },
            }
        ],
    }


def test_detects_bucket_policy_requiring_tls():
    result = check_s3_tls_policy(
        bucket_name="secure-bucket",
        policy=tls_policy(),
    )

    assert result.bucket_name == "secure-bucket"
    assert result.tls_required is True
    assert build_s3_tls_policy_finding(result) is None


def test_detects_missing_tls_requirement():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "*",
            }
        ],
    }

    result = check_s3_tls_policy(
        bucket_name="insecure-bucket",
        policy=policy,
    )

    assert result.tls_required is False

    finding = build_s3_tls_policy_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-009"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "s3_bucket"
    assert finding.resource_id == "insecure-bucket"
    assert finding.evidence["tls_required"] is False


def test_missing_policy_requires_tls():
    result = check_s3_tls_policy(
        bucket_name="bucket-without-policy",
        policy={},
    )

    assert result.tls_required is False
    assert build_s3_tls_policy_finding(result) is not None


def test_supports_single_statement_object():
    policy = tls_policy()
    policy["Statement"] = policy["Statement"][0]

    result = check_s3_tls_policy(
        bucket_name="secure-bucket",
        policy=policy,
    )

    assert result.tls_required is True


def test_supports_principal_aws_star():
    policy = tls_policy()
    policy["Statement"][0]["Principal"] = {"AWS": "*"}

    result = check_s3_tls_policy(
        bucket_name="secure-bucket",
        policy=policy,
    )

    assert result.tls_required is True


def test_supports_action_list():
    policy = tls_policy()
    policy["Statement"][0]["Action"] = [
        "s3:GetObject",
        "s3:*",
    ]

    result = check_s3_tls_policy(
        bucket_name="secure-bucket",
        policy=policy,
    )

    assert result.tls_required is True


def test_rejects_wrong_secure_transport_value():
    policy = tls_policy()
    policy["Statement"][0]["Condition"]["Bool"][
        "aws:SecureTransport"
    ] = "true"

    result = check_s3_tls_policy(
        bucket_name="insecure-bucket",
        policy=policy,
    )

    assert result.tls_required is False


def test_rejects_allow_statement():
    policy = tls_policy()
    policy["Statement"][0]["Effect"] = "Allow"

    result = check_s3_tls_policy(
        bucket_name="insecure-bucket",
        policy=policy,
    )

    assert result.tls_required is False


def test_rejects_non_s3_wildcard_action():
    policy = tls_policy()
    policy["Statement"][0]["Action"] = "*"

    result = check_s3_tls_policy(
        bucket_name="insecure-bucket",
        policy=policy,
    )

    assert result.tls_required is False


def test_rejects_specific_principal():
    policy = tls_policy()
    policy["Statement"][0]["Principal"] = {
        "AWS": "arn:aws:iam::123456789012:root"
    }

    result = check_s3_tls_policy(
        bucket_name="insecure-bucket",
        policy=policy,
    )

    assert result.tls_required is False
