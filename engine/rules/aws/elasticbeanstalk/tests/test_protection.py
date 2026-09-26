from engine.findings.model import Severity
from engine.rules.aws.elasticbeanstalk.protection import (
    build_cloudwatch_log_streaming_finding,
    build_enhanced_health_reporting_finding,
    build_managed_platform_updates_finding,
    check_cloudwatch_log_streaming,
    check_enhanced_health_reporting,
    check_managed_platform_updates,
)


RESOURCE_ID = "e-env123456"
RESOURCE_TYPE = "elasticbeanstalk_environment"


def test_enhanced_health_reporting_passes_when_enabled():
    assert (
        check_enhanced_health_reporting(
            RESOURCE_ID,
            True,
        )
        is None
    )


def test_enhanced_health_reporting_fails_when_disabled():
    result = check_enhanced_health_reporting(
        RESOURCE_ID,
        False,
    )

    assert result is not None
    assert result.resource_id == RESOURCE_ID
    assert result.details["enhanced_health_reporting"] is False


def test_enhanced_health_reporting_rejects_empty_resource_id():
    assert (
        check_enhanced_health_reporting(
            "",
            False,
        )
        is None
    )


def test_enhanced_health_reporting_finding():
    result = check_enhanced_health_reporting(
        RESOURCE_ID,
        False,
    )

    finding = build_enhanced_health_reporting_finding(
        result,
    )

    assert finding.rule_id == (
        "CS-AWS-ELASTICBEANSTALK-001"
    )
    assert finding.severity == Severity.LOW
    assert finding.resource_type == RESOURCE_TYPE
    assert finding.resource_id == RESOURCE_ID


def test_managed_platform_updates_passes_when_enabled():
    assert (
        check_managed_platform_updates(
            RESOURCE_ID,
            True,
            "minor",
        )
        is None
    )


def test_managed_platform_updates_passes_for_patch_level():
    assert (
        check_managed_platform_updates(
            RESOURCE_ID,
            True,
            "patch",
        )
        is None
    )


def test_managed_platform_updates_fails_when_disabled():
    result = check_managed_platform_updates(
        RESOURCE_ID,
        False,
        None,
    )

    assert result is not None
    assert result.details["managed_actions_enabled"] is False


def test_managed_platform_updates_finding():
    result = check_managed_platform_updates(
        RESOURCE_ID,
        False,
        None,
    )

    finding = build_managed_platform_updates_finding(
        result,
    )

    assert finding.rule_id == (
        "CS-AWS-ELASTICBEANSTALK-002"
    )
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == RESOURCE_ID


def test_cloudwatch_log_streaming_passes_when_enabled():
    assert (
        check_cloudwatch_log_streaming(
            RESOURCE_ID,
            True,
        )
        is None
    )


def test_cloudwatch_log_streaming_fails_when_disabled():
    result = check_cloudwatch_log_streaming(
        RESOURCE_ID,
        False,
    )

    assert result is not None
    assert result.details["stream_logs"] is False


def test_cloudwatch_log_streaming_rejects_empty_resource_id():
    assert (
        check_cloudwatch_log_streaming(
            "",
            False,
        )
        is None
    )


def test_cloudwatch_log_streaming_finding():
    result = check_cloudwatch_log_streaming(
        RESOURCE_ID,
        False,
    )

    finding = build_cloudwatch_log_streaming_finding(
        result,
    )

    assert finding.rule_id == (
        "CS-AWS-ELASTICBEANSTALK-003"
    )
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == RESOURCE_TYPE
    assert finding.resource_id == RESOURCE_ID
