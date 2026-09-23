from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.event_data_store_ingestion import (
    CloudTrailEventDataStoreIngestionResult,
    build_cloudtrail_event_data_store_ingestion_finding,
    check_cloudtrail_event_data_store_ingestion,
)
from engine.rules.aws.cloudtrail.event_data_store_management_events import (
    CloudTrailEventDataStoreManagementEventsResult,
    build_cloudtrail_event_data_store_management_events_finding,
    check_cloudtrail_event_data_store_management_events,
)
from engine.rules.aws.cloudtrail.event_data_store_multi_region import (
    CloudTrailEventDataStoreMultiRegionResult,
    build_cloudtrail_event_data_store_multi_region_finding,
    check_cloudtrail_event_data_store_multi_region,
)
from engine.rules.aws.cloudtrail.event_data_store_organization import (
    CloudTrailEventDataStoreOrganizationResult,
    build_cloudtrail_event_data_store_organization_finding,
    check_cloudtrail_event_data_store_organization,
)


EVENT_DATA_STORE_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:eventdatastore/"
    "11111111-2222-3333-4444-555555555555"
)


def test_ct013_enabled_event_data_store_is_ignored():
    result = check_cloudtrail_event_data_store_ingestion(
        EVENT_DATA_STORE_ARN,
        "security-events",
        "ENABLED",
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreIngestionResult,
    )
    assert result.ingestion_stopped is False
    assert build_cloudtrail_event_data_store_ingestion_finding(
        result
    ) is None


def test_ct013_stopped_event_data_store_is_detected():
    result = check_cloudtrail_event_data_store_ingestion(
        EVENT_DATA_STORE_ARN,
        "security-events",
        "STOPPED_INGESTION",
    )

    assert result.ingestion_stopped is True

    finding = build_cloudtrail_event_data_store_ingestion_finding(
        result
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-013"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == EVENT_DATA_STORE_ARN
    assert finding.evidence["status"] == "STOPPED_INGESTION"


def test_ct013_transitional_status_is_not_failed():
    result = check_cloudtrail_event_data_store_ingestion(
        EVENT_DATA_STORE_ARN,
        "security-events",
        "STARTING_INGESTION",
    )

    assert result.ingestion_stopped is False
    assert build_cloudtrail_event_data_store_ingestion_finding(
        result
    ) is None


def test_ct013_missing_status_is_not_failed():
    result = check_cloudtrail_event_data_store_ingestion(
        EVENT_DATA_STORE_ARN,
        "security-events",
        None,
    )

    assert result.ingestion_stopped is False
    assert build_cloudtrail_event_data_store_ingestion_finding(
        result
    ) is None


def test_ct014_management_events_enabled_is_ignored():
    result = check_cloudtrail_event_data_store_management_events(
        EVENT_DATA_STORE_ARN,
        "security-events",
        True,
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreManagementEventsResult,
    )
    assert result.management_events_disabled is False
    assert (
        build_cloudtrail_event_data_store_management_events_finding(
            result
        )
        is None
    )


def test_ct014_management_events_disabled_is_detected():
    result = check_cloudtrail_event_data_store_management_events(
        EVENT_DATA_STORE_ARN,
        "security-events",
        False,
    )

    assert result.management_events_disabled is True

    finding = (
        build_cloudtrail_event_data_store_management_events_finding(
            result
        )
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-014"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == EVENT_DATA_STORE_ARN
    assert finding.evidence["management_events_enabled"] is False


def test_ct014_missing_management_events_data_is_not_failed():
    result = check_cloudtrail_event_data_store_management_events(
        EVENT_DATA_STORE_ARN,
        "security-events",
        None,
    )

    assert result.management_events_disabled is False
    assert (
        build_cloudtrail_event_data_store_management_events_finding(
            result
        )
        is None
    )


def test_ct015_multi_region_enabled_is_ignored():
    result = check_cloudtrail_event_data_store_multi_region(
        EVENT_DATA_STORE_ARN,
        "security-events",
        True,
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreMultiRegionResult,
    )
    assert result.multi_region_disabled is False
    assert build_cloudtrail_event_data_store_multi_region_finding(
        result
    ) is None


def test_ct015_multi_region_disabled_is_detected():
    result = check_cloudtrail_event_data_store_multi_region(
        EVENT_DATA_STORE_ARN,
        "security-events",
        False,
    )

    assert result.multi_region_disabled is True

    finding = build_cloudtrail_event_data_store_multi_region_finding(
        result
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-015"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == EVENT_DATA_STORE_ARN
    assert finding.evidence["multi_region_enabled"] is False


def test_ct015_missing_multi_region_data_is_not_failed():
    result = check_cloudtrail_event_data_store_multi_region(
        EVENT_DATA_STORE_ARN,
        "security-events",
        None,
    )

    assert result.multi_region_disabled is False
    assert build_cloudtrail_event_data_store_multi_region_finding(
        result
    ) is None


def test_ct016_organization_enabled_is_ignored():
    result = check_cloudtrail_event_data_store_organization(
        EVENT_DATA_STORE_ARN,
        "security-events",
        True,
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreOrganizationResult,
    )
    assert result.organization_disabled is False
    assert build_cloudtrail_event_data_store_organization_finding(
        result
    ) is None


def test_ct016_organization_disabled_is_detected():
    result = check_cloudtrail_event_data_store_organization(
        EVENT_DATA_STORE_ARN,
        "security-events",
        False,
    )

    assert result.organization_disabled is True

    finding = build_cloudtrail_event_data_store_organization_finding(
        result
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-016"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == EVENT_DATA_STORE_ARN
    assert finding.evidence["organization_enabled"] is False


def test_ct016_missing_organization_data_is_not_failed():
    result = check_cloudtrail_event_data_store_organization(
        EVENT_DATA_STORE_ARN,
        "security-events",
        None,
    )

    assert result.organization_disabled is False
    assert build_cloudtrail_event_data_store_organization_finding(
        result
    ) is None
