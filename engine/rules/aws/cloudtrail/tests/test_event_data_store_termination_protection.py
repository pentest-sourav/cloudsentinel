from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.event_data_store_termination_protection import (
    CloudTrailEventDataStoreTerminationProtectionResult,
    build_cloudtrail_event_data_store_termination_protection_finding,
    check_cloudtrail_event_data_store_termination_protection,
)


EVENT_DATA_STORE_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:eventdatastore/"
    "11111111-2222-3333-4444-555555555555"
)


def test_event_data_store_with_termination_protection_is_ignored():
    result = check_cloudtrail_event_data_store_termination_protection(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        termination_protection_enabled=True,
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreTerminationProtectionResult,
    )
    assert result.event_data_store_arn == EVENT_DATA_STORE_ARN
    assert result.name == "security-events"
    assert result.termination_protection_enabled is True
    assert result.termination_protection_disabled is False

    assert (
        build_cloudtrail_event_data_store_termination_protection_finding(
            result
        )
        is None
    )


def test_event_data_store_without_termination_protection_is_detected():
    result = check_cloudtrail_event_data_store_termination_protection(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        termination_protection_enabled=False,
    )

    assert result.termination_protection_disabled is True

    finding = (
        build_cloudtrail_event_data_store_termination_protection_finding(
            result
        )
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-011"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail_event_data_store"
    assert finding.resource_id == EVENT_DATA_STORE_ARN
    assert finding.evidence["event_data_store_arn"] == (
        EVENT_DATA_STORE_ARN
    )
    assert finding.evidence["event_data_store_name"] == "security-events"
    assert finding.evidence["termination_protection_enabled"] is False
    assert finding.compliance == ["NIST SP 800-53 Rev. 5"]


def test_event_data_store_with_missing_termination_protection_is_not_failed():
    result = check_cloudtrail_event_data_store_termination_protection(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        termination_protection_enabled=None,
    )

    assert result.termination_protection_disabled is False

    assert (
        build_cloudtrail_event_data_store_termination_protection_finding(
            result
        )
        is None
    )
