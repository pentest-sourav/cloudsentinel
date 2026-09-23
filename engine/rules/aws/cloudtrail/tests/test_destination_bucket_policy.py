from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.destination_bucket_policy import (
    CloudTrailDestinationBucketPolicyResult,
    build_cloudtrail_destination_bucket_policy_finding,
    check_cloudtrail_destination_bucket_policy,
)


BUCKET_NAME = "cloudtrail-logs"

BUCKET_ARN = (
    "arn:aws:s3:::cloudtrail-logs"
)

TRAIL_ARN = (
    "arn:aws:cloudtrail:ap-south-1:123456789012:"
    "trail/ProductionTrail"
)


def _policy(condition=None):
    statement = {
        "Effect": "Allow",
        "Principal": {
            "Service": "cloudtrail.amazonaws.com",
        },
        "Action": [
            "s3:GetBucketAcl",
            "s3:PutObject",
        ],
        "Resource": [
            BUCKET_ARN,
            f"{BUCKET_ARN}/AWSLogs/123456789012/*",
        ],
    }

    if condition is not None:
        statement["Condition"] = condition

    return {
        "Version": "2012-10-17",
        "Statement": [statement],
    }


def test_ct020_source_arn_restriction_is_compliant():
    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN],
        _policy(
            {
                "StringEquals": {
                    "aws:SourceArn": TRAIL_ARN,
                },
            }
        ),
    )

    assert isinstance(
        result,
        CloudTrailDestinationBucketPolicyResult,
    )
    assert result.cloudtrail_statement_found is True
    assert result.source_arn_restricted is True

    assert (
        build_cloudtrail_destination_bucket_policy_finding(
            result
        )
        is None
    )


def test_ct020_missing_source_arn_is_detected():
    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN],
        _policy(),
    )

    assert result.cloudtrail_statement_found is True
    assert result.source_arn_restricted is False

    finding = (
        build_cloudtrail_destination_bucket_policy_finding(
            result
        )
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-020"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == BUCKET_NAME


def test_ct020_source_account_only_is_not_accepted():
    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN],
        _policy(
            {
                "StringEquals": {
                    "aws:SourceAccount": "123456789012",
                },
            }
        ),
    )

    assert result.source_arn_restricted is False


def test_ct020_wrong_source_arn_is_detected():
    wrong_trail_arn = (
        "arn:aws:cloudtrail:ap-south-1:123456789012:"
        "trail/OtherTrail"
    )

    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN],
        _policy(
            {
                "ArnEquals": {
                    "aws:SourceArn": wrong_trail_arn,
                },
            }
        ),
    )

    assert result.source_arn_restricted is False


def test_ct020_multiple_trails_are_supported():
    second_trail_arn = (
        "arn:aws:cloudtrail:ap-south-1:123456789012:"
        "trail/SecondaryTrail"
    )

    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN, second_trail_arn],
        _policy(
            {
                "ArnEquals": {
                    "aws:SourceArn": [
                        TRAIL_ARN,
                        second_trail_arn,
                    ],
                },
            }
        ),
    )

    assert result.source_arn_restricted is True


def test_ct020_partial_multiple_trails_is_detected():
    second_trail_arn = (
        "arn:aws:cloudtrail:ap-south-1:123456789012:"
        "trail/SecondaryTrail"
    )

    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN, second_trail_arn],
        _policy(
            {
                "ArnEquals": {
                    "aws:SourceArn": TRAIL_ARN,
                },
            }
        ),
    )

    assert result.source_arn_restricted is False


def test_ct020_unrestricted_statement_cannot_be_hidden():
    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "s3:PutObject",
                    "Resource": (
                        f"{BUCKET_ARN}/AWSLogs/123456789012/*"
                    ),
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": TRAIL_ARN,
                        },
                    },
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "s3:GetBucketAcl",
                    "Resource": BUCKET_ARN,
                },
            ],
        },
    )

    assert result.cloudtrail_statement_found is True
    assert result.source_arn_restricted is False


def test_ct020_unrelated_s3_statement_is_ignored():
    result = check_cloudtrail_destination_bucket_policy(
        BUCKET_NAME,
        [TRAIL_ARN],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "s3.amazonaws.com",
                    },
                    "Action": "s3:PutObject",
                    "Resource": BUCKET_ARN,
                },
            ],
        },
    )

    assert result.cloudtrail_statement_found is False
    assert (
        build_cloudtrail_destination_bucket_policy_finding(
            result
        )
        is None
    )
