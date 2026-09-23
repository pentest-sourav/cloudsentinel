from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.event_data_store_encryption import (
    CloudTrailEventDataStoreEncryptionResult,
    build_cloudtrail_event_data_store_encryption_finding,
    check_cloudtrail_event_data_store_encryption,
)


EVENT_DATA_STORE_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:eventdatastore/"
    "11111111-2222-3333-4444-555555555555"
)


def test_event_data_store_without_kms_key_is_detected():
    result = check_cloudtrail_event_data_store_encryption(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        kms_key_id=None,
    )

    assert isinstance(
        result,
        CloudTrailEventDataStoreEncryptionResult,
    )
    assert result.event_data_store_arn == EVENT_DATA_STORE_ARN
    assert result.name == "security-events"
    assert result.kms_key_id is None
    assert result.encrypted_with_customer_managed_key is False


def test_event_data_store_with_kms_key_is_ignored():
    kms_key_id = (
        "arn:aws:kms:eu-north-1:"
        "123456789012:key/"
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )

    result = check_cloudtrail_event_data_store_encryption(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        kms_key_id=kms_key_id,
    )

    assert result.encrypted_with_customer_managed_key is True
    assert (
        build_cloudtrail_event_data_store_encryption_finding(result)
        is None
    )


def test_event_data_store_encryption_finding_is_built_correctly():
    result = check_cloudtrail_event_data_store_encryption(
        event_data_store_arn=EVENT_DATA_STORE_ARN,
        name="security-events",
        kms_key_id=None,
    )

    finding = (
        build_cloudtrail_event_data_store_encryption_finding(result)
    )

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-010"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail_event_data_store"
    assert finding.resource_id == EVENT_DATA_STORE_ARN
    assert finding.evidence["event_data_store_arn"] == (
        EVENT_DATA_STORE_ARN
    )
    assert finding.evidence["event_data_store_name"] == "security-events"
    assert finding.evidence["kms_key_id"] is None
    assert finding.evidence["customer_managed_kms_encryption"] is False
    assert finding.compliance == ["NIST SP 800-53 Rev. 5"]
