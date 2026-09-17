from engine.findings.model import Severity
from engine.rules.aws.s3.policy import (
    build_s3_bucket_policy_finding,
    check_s3_bucket_policy,
)


def test_public_bucket_policy_generates_high_finding():
    policy_status = {
        "IsPublic": True,
    }

    result = check_s3_bucket_policy(
        bucket_name="public-bucket",
        policy_status=policy_status,
    )

    assert result.policy_is_public is True
    assert result.bucket_name == "public-bucket"

    finding = build_s3_bucket_policy_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-003"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "public-bucket"
    assert finding.evidence["policy_is_public"] is True
    assert finding.evidence["policy_status"] == policy_status


def test_private_bucket_policy_has_no_finding():
    policy_status = {
        "IsPublic": False,
    }

    result = check_s3_bucket_policy(
        bucket_name="secure-bucket",
        policy_status=policy_status,
    )

    assert result.policy_is_public is False
    assert result.bucket_name == "secure-bucket"

    finding = build_s3_bucket_policy_finding(result)

    assert finding is None


def test_missing_policy_status_has_no_public_finding():
    policy_status = {}

    result = check_s3_bucket_policy(
        bucket_name="bucket-without-policy",
        policy_status=policy_status,
    )

    assert result.policy_is_public is False
    assert result.policy_status == {}

    finding = build_s3_bucket_policy_finding(result)

    assert finding is None
