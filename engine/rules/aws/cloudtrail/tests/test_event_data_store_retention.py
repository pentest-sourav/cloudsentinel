from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.event_data_store_retention import (
    CloudTrailEventDataStoreRetentionResult,
    build_cloudtrail_event_data_store_retention_finding,
    check_cloudtrail_event_data_store_retention,
)


EVENT_DATA_STORE_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:eventdatastore/"
    "11111111-2222-3333-4444-555555555555"
)


def test_event_data_store_meeting_default_retention_is_ignored():
    result = check_cloudtrail_event_data_store_retention(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        retention_period=365,
    )

    assert result is None


def test_event_data_store_above_default_retention_is_ignored():
    result = check_cloudtrail_event_data_store_retention(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        retention_period=366,
    )

    assert result is None


def test_event_data_store_below_default_retention_is_detected():
    result = check_cloudtrail_event_data_store_retention(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        retention_period=364,
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreRetentionResult,
    )
    assert result.event_data_store_arn == EVENT_DATA_STORE_ARN
    assert result.name == "security-events"
    assert result.retention_period == 364
    assert result.minimum_retention_days == 365


def test_event_data_store_custom_retention_threshold_is_respected():
    result = check_cloudtrail_event_data_store_retention(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        retention_period=180,
        minimum_retention_days=180,
    )

    assert result is None


def test_event_data_store_below_custom_retention_threshold_is_detected():
    result = check_cloudtrail_event_data_store_retention(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        retention_period=179,
        minimum_retention_days=180,
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreRetentionResult,
    )
    assert result.retention_period == 179
    assert result.minimum_retention_days == 180


def test_event_data_store_missing_retention_is_not_failed():
    result = check_cloudtrail_event_data_store_retention(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        retention_period=None,
    )

    assert result is None


def test_event_data_store_retention_finding_contains_expected_details():
    result = check_cloudtrail_event_data_store_retention(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        retention_period=90,
        minimum_retention_days=365,
    )

    assert result is not None

    finding = build_cloudtrail_event_data_store_retention_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CT-012"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail_event_data_store"
    assert finding.resource_id == EVENT_DATA_STORE_ARN
    assert finding.evidence["event_data_store_arn"] == (
        EVENT_DATA_STORE_ARN
    )
    assert finding.evidence["event_data_store_name"] == "security-events"
    assert finding.evidence["retention_period"] == 90
    assert finding.evidence["minimum_retention_days"] == 365
    assert finding.compliance == ["NIST SP 800-53 Rev. 5"]
