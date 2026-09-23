from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.sns_topic_policy import (
    CloudTrailSNSTopicPolicyResult,
    build_cloudtrail_sns_topic_policy_finding,
    check_cloudtrail_sns_topic_policy,
)


TOPIC_ARN = (
    "arn:aws:sns:ap-south-1:123456789012:cloudtrail-notifications"
)

TRAIL_ARN = (
    "arn:aws:cloudtrail:ap-south-1:123456789012:"
    "trail/ProductionTrail"
)


def test_ct019_source_arn_restriction_is_compliant():
    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceArn": TRAIL_ARN,
                        },
                    },
                },
            ],
        },
    )

    assert isinstance(
        result,
        CloudTrailSNSTopicPolicyResult,
    )
    assert result.cloudtrail_publish_statement_found is True
    assert result.source_arn_restricted is True

    assert (
        build_cloudtrail_sns_topic_policy_finding(result)
        is None
    )


def test_ct019_missing_source_arn_is_detected():
    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                },
            ],
        },
    )

    assert result.cloudtrail_publish_statement_found is True
    assert result.source_arn_restricted is False

    finding = build_cloudtrail_sns_topic_policy_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-019"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == TOPIC_ARN


def test_ct019_partial_multi_trail_source_arn_is_detected():
    second_trail_arn = (
        "arn:aws:cloudtrail:ap-south-1:123456789012:"
        "trail/SecondaryTrail"
    )

    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN, second_trail_arn],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceArn": TRAIL_ARN,
                        },
                    },
                },
            ],
        },
    )

    assert result.source_arn_restricted is False
    assert (
        build_cloudtrail_sns_topic_policy_finding(result)
        is not None
    )


def test_ct019_multi_trail_source_arns_are_supported():
    second_trail_arn = (
        "arn:aws:cloudtrail:ap-south-1:123456789012:"
        "trail/SecondaryTrail"
    )

    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN, second_trail_arn],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": [
                                TRAIL_ARN,
                                second_trail_arn,
                            ],
                        },
                    },
                },
            ],
        },
    )

    assert result.source_arn_restricted is True
    assert (
        build_cloudtrail_sns_topic_policy_finding(result)
        is None
    )


def test_ct019_unrelated_publish_statement_is_ignored():
    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "s3.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                },
            ],
        },
    )

    assert result.cloudtrail_publish_statement_found is False
    assert (
        build_cloudtrail_sns_topic_policy_finding(result)
        is None
    )


def test_ct019_source_account_only_is_not_treated_as_source_arn():
    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": "123456789012",
                        },
                    },
                },
            ],
        },
    )

    assert result.source_arn_restricted is False
    assert (
        build_cloudtrail_sns_topic_policy_finding(result)
        is not None
    )


def test_ct019_unrestricted_statement_cannot_be_hidden_by_restricted_statement():
    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RestrictedCloudTrailPublish",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": TRAIL_ARN,
                        },
                    },
                },
                {
                    "Sid": "UnrestrictedCloudTrailPublish",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                },
            ],
        },
    )

    assert result.cloudtrail_publish_statement_found is True
    assert result.source_arn_restricted is False
    assert (
        build_cloudtrail_sns_topic_policy_finding(result)
        is not None
    )


def test_ct019_separate_restricted_statements_can_cover_multiple_trails():
    second_trail_arn = (
        "arn:aws:cloudtrail:ap-south-1:123456789012:"
        "trail/SecondaryTrail"
    )

    result = check_cloudtrail_sns_topic_policy(
        TOPIC_ARN,
        [TRAIL_ARN, second_trail_arn],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ProductionTrailPublish",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": TRAIL_ARN,
                        },
                    },
                },
                {
                    "Sid": "SecondaryTrailPublish",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com",
                    },
                    "Action": "SNS:Publish",
                    "Resource": TOPIC_ARN,
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": second_trail_arn,
                        },
                    },
                },
            ],
        },
    )

    assert result.cloudtrail_publish_statement_found is True
    assert result.source_arn_restricted is True
    assert (
        build_cloudtrail_sns_topic_policy_finding(result)
        is None
    )
