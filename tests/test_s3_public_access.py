from engine.findings.model import Severity
from engine.rules.aws.s3.public_access import (
    build_s3_public_access_finding,
    check_s3_public_access,
)


def test_s3_public_access_block_disabled_generates_high_finding():
    configuration = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }

    result = check_s3_public_access(
        bucket_name="test-bucket",
        public_access_block=configuration,
    )

    assert result.public_access_signal is True
    assert result.bucket_name == "test-bucket"

    finding = build_s3_public_access_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "test-bucket"
    assert finding.evidence["configuration"] == configuration
    assert finding.evidence["public_access_signal"] is True


def test_s3_public_access_block_fully_enabled_has_no_finding():
    configuration = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    result = check_s3_public_access(
        bucket_name="secure-bucket",
        public_access_block=configuration,
    )

    assert result.public_access_signal is False
    assert result.bucket_name == "secure-bucket"

    finding = build_s3_public_access_finding(result)

    assert finding is None


def test_s3_public_access_block_partially_disabled_generates_finding():
    configuration = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": True,
    }

    result = check_s3_public_access(
        bucket_name="partially-secure-bucket",
        public_access_block=configuration,
    )

    assert result.public_access_signal is True

    finding = build_s3_public_access_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "partially-secure-bucket"

    assert (
        "BlockPublicPolicy"
        in finding.evidence["reason"]
    )


def test_missing_public_access_block_configuration_generates_finding():
    configuration = {}

    result = check_s3_public_access(
        bucket_name="unconfigured-bucket",
        public_access_block=configuration,
    )

    assert result.public_access_signal is True

    finding = build_s3_public_access_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "unconfigured-bucket"

    assert finding.evidence["configuration"] == {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
