from engine.findings.model import Finding, Severity
from engine.rules.aws.s3.public_access import (
    S3PublicAccessResult,
    build_s3_public_access_finding,
    check_s3_public_access,
)


def test_s3_public_access_when_all_settings_enabled():
    result = check_s3_public_access(
        "private-bucket",
        {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    assert result.bucket_name == "private-bucket"
    assert result.is_public is False
    assert result.reason == (
        "All S3 Public Access Block settings are enabled."
    )

    assert result.configuration == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }


def test_s3_public_access_when_settings_are_disabled():
    result = check_s3_public_access(
        "public-bucket",
        {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    assert result.bucket_name == "public-bucket"
    assert result.is_public is True
    assert "BlockPublicAcls" in result.reason
    assert "IgnorePublicAcls" in result.reason

    assert result.configuration == {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }


def test_s3_public_access_when_setting_is_missing():
    result = check_s3_public_access(
        "unknown-bucket",
        {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
        },
    )

    assert result.bucket_name == "unknown-bucket"
    assert result.is_public is True
    assert "RestrictPublicBuckets" in result.reason

    assert result.configuration == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": False,
    }


def test_build_s3_public_access_finding():
    result = S3PublicAccessResult(
        bucket_name="public-bucket",
        is_public=True,
        reason="BlockPublicPolicy is disabled.",
        configuration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
    )

    finding = build_s3_public_access_finding(result)

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-S3-001"
    assert finding.title == "S3 Public Access Block Not Fully Enabled"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "s3_bucket"
    assert finding.resource_id == "public-bucket"

    assert finding.evidence["configuration"] == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": True,
    }

    assert finding.evidence["reason"] == (
        "BlockPublicPolicy is disabled."
    )

    assert finding.compliance == ["CIS AWS Foundations"]


def test_build_s3_public_access_finding_returns_none_when_secure():
    result = S3PublicAccessResult(
        bucket_name="private-bucket",
        is_public=False,
        reason="All Public Access Block settings are enabled.",
        configuration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    finding = build_s3_public_access_finding(result)

    assert finding is None
