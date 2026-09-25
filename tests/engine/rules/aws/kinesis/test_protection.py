from engine.findings.model import Severity

from engine.rules.aws.kinesis.encryption import (
    build_kinesis_encryption_finding,
    check_kinesis_encryption,
)
from engine.rules.aws.kinesis.retention import (
    build_kinesis_retention_finding,
    check_kinesis_retention,
)
from engine.rules.aws.kinesis.tagging import (
    build_kinesis_tagging_finding,
    check_kinesis_tagging,
)


STREAM_ARN = (
    "arn:aws:kinesis:ap-south-1:"
    "123456789012:stream/orders"
)


def test_kinesis_encryption_passes_with_kms():
    assert (
        check_kinesis_encryption(
            STREAM_ARN,
            "KMS",
        )
        is None
    )


def test_kinesis_encryption_fails_without_encryption():
    result = check_kinesis_encryption(
        STREAM_ARN,
        "NONE",
    )

    assert result is not None
    assert result.actual_configuration == "NONE"


def test_kinesis_encryption_fails_when_missing():
    result = check_kinesis_encryption(
        STREAM_ARN,
        None,
    )

    assert result is not None
    assert result.actual_configuration == "MISSING"


def test_kinesis_tagging_passes_with_tag():
    assert (
        check_kinesis_tagging(
            STREAM_ARN,
            [{"Key": "Environment", "Value": "prod"}],
        )
        is None
    )


def test_kinesis_tagging_fails_without_tags():
    result = check_kinesis_tagging(
        STREAM_ARN,
        [],
    )

    assert result is not None
    assert result.actual_configuration == "NO_TAGS"


def test_kinesis_tagging_ignores_invalid_tags():
    result = check_kinesis_tagging(
        STREAM_ARN,
        [
            {},
            {"Value": "prod"},
            {"Key": ""},
        ],
    )

    assert result is not None
    assert result.actual_configuration == "NO_TAGS"


def test_kinesis_retention_passes_at_default_minimum():
    assert (
        check_kinesis_retention(
            STREAM_ARN,
            168,
        )
        is None
    )


def test_kinesis_retention_passes_above_minimum():
    assert (
        check_kinesis_retention(
            STREAM_ARN,
            720,
        )
        is None
    )


def test_kinesis_retention_fails_below_minimum():
    result = check_kinesis_retention(
        STREAM_ARN,
        24,
    )

    assert result is not None
    assert result.actual_configuration == "24"


def test_kinesis_retention_fails_when_missing():
    result = check_kinesis_retention(
        STREAM_ARN,
        None,
    )

    assert result is not None
    assert result.actual_configuration == "MISSING"


def test_build_kinesis_encryption_finding():
    result = check_kinesis_encryption(
        STREAM_ARN,
        "NONE",
    )

    finding = build_kinesis_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-KINESIS-001"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "kinesis_stream"
    assert finding.compliance == [
        "AWS Security Hub Kinesis.1"
    ]


def test_build_kinesis_tagging_finding():
    result = check_kinesis_tagging(
        STREAM_ARN,
        [],
    )

    finding = build_kinesis_tagging_finding(result)

    assert finding.rule_id == "CS-AWS-KINESIS-002"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "kinesis_stream"
    assert finding.compliance == [
        "AWS Security Hub Kinesis.2"
    ]


def test_build_kinesis_retention_finding():
    result = check_kinesis_retention(
        STREAM_ARN,
        24,
    )

    finding = build_kinesis_retention_finding(result)

    assert finding.rule_id == "CS-AWS-KINESIS-003"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "kinesis_stream"
    assert finding.compliance == [
        "AWS Security Hub Kinesis.3"
    ]
