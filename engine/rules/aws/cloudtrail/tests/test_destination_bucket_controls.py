from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.destination_bucket_logging import (
    CloudTrailDestinationBucketLoggingResult,
    build_cloudtrail_destination_bucket_logging_finding,
    check_cloudtrail_destination_bucket_logging,
)
from engine.rules.aws.cloudtrail.destination_bucket_public_access import (
    CloudTrailDestinationBucketPublicAccessResult,
    build_cloudtrail_destination_bucket_public_access_finding,
    check_cloudtrail_destination_bucket_public_access,
)


BUCKET_NAME = "cloudtrail-logs-production"


def test_ct017_all_public_access_block_controls_enabled():
    result = check_cloudtrail_destination_bucket_public_access(
        BUCKET_NAME,
        {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    assert isinstance(
        result,
        CloudTrailDestinationBucketPublicAccessResult,
    )
    assert result.public_access_block_enabled is True

    assert (
        build_cloudtrail_destination_bucket_public_access_finding(
            result
        )
        is None
    )


def test_ct017_missing_public_access_block_is_detected():
    result = check_cloudtrail_destination_bucket_public_access(
        BUCKET_NAME,
        {},
    )

    assert result.public_access_block_enabled is False

    finding = (
        build_cloudtrail_destination_bucket_public_access_finding(
            result
        )
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-017"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == BUCKET_NAME


def test_ct017_partial_public_access_block_is_detected():
    result = check_cloudtrail_destination_bucket_public_access(
        BUCKET_NAME,
        {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        },
    )

    assert result.public_access_block_enabled is False

    finding = (
        build_cloudtrail_destination_bucket_public_access_finding(
            result
        )
    )

    assert finding is not None
    assert finding.evidence["restrict_public_buckets"] is False


def test_ct018_access_logging_enabled():
    result = check_cloudtrail_destination_bucket_logging(
        BUCKET_NAME,
        {
            "TargetBucket": "s3-access-logs",
            "TargetPrefix": "cloudtrail/",
        },
    )

    assert isinstance(
        result,
        CloudTrailDestinationBucketLoggingResult,
    )
    assert result.access_logging_enabled is True

    assert (
        build_cloudtrail_destination_bucket_logging_finding(
            result
        )
        is None
    )


def test_ct018_access_logging_disabled_is_detected():
    result = check_cloudtrail_destination_bucket_logging(
        BUCKET_NAME,
        {},
    )

    assert result.access_logging_enabled is False

    finding = (
        build_cloudtrail_destination_bucket_logging_finding(
            result
        )
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-018"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == BUCKET_NAME
