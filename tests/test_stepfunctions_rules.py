from engine.findings.model import Severity

from engine.rules.aws.stepfunctions.logging import (
    build_stepfunctions_logging_finding,
    check_stepfunctions_logging,
)
from engine.rules.aws.stepfunctions.tagging import (
    build_stepfunctions_tagging_finding,
    check_stepfunctions_tagging,
)


STATE_MACHINE_ARN = (
    "arn:aws:states:ap-south-1:123456789012:"
    "stateMachine:test-machine"
)

ACTIVITY_ARN = (
    "arn:aws:states:ap-south-1:123456789012:"
    "activity:test-activity"
)


def test_stepfunctions_logging_passes_with_all():
    result = check_stepfunctions_logging(
        STATE_MACHINE_ARN,
        {
            "level": "ALL",
            "includeExecutionData": True,
        },
    )

    assert result.logging_enabled is True
    assert result.logging_level == "ALL"
    assert build_stepfunctions_logging_finding(result) is None


def test_stepfunctions_logging_passes_with_error():
    result = check_stepfunctions_logging(
        STATE_MACHINE_ARN,
        {
            "level": "ERROR",
        },
    )

    assert result.logging_enabled is True
    assert build_stepfunctions_logging_finding(result) is None


def test_stepfunctions_logging_passes_with_fatal():
    result = check_stepfunctions_logging(
        STATE_MACHINE_ARN,
        {
            "level": "FATAL",
        },
    )

    assert result.logging_enabled is True
    assert build_stepfunctions_logging_finding(result) is None


def test_stepfunctions_logging_fails_when_missing():
    result = check_stepfunctions_logging(
        STATE_MACHINE_ARN,
        {},
    )

    finding = build_stepfunctions_logging_finding(result)

    assert result.logging_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-SFN-001"
    assert finding.severity == Severity.MEDIUM


def test_stepfunctions_logging_fails_when_off():
    result = check_stepfunctions_logging(
        STATE_MACHINE_ARN,
        {
            "level": "OFF",
        },
    )

    finding = build_stepfunctions_logging_finding(result)

    assert result.logging_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-SFN-001"


def test_stepfunctions_tagging_passes_with_non_system_tag():
    result = check_stepfunctions_tagging(
        ACTIVITY_ARN,
        [
            {
                "key": "Environment",
                "value": "prod",
            }
        ],
    )

    assert result.tagged is True
    assert build_stepfunctions_tagging_finding(result) is None


def test_stepfunctions_tagging_ignores_system_tags():
    result = check_stepfunctions_tagging(
        ACTIVITY_ARN,
        [
            {
                "key": "aws:cloudformation:stack-id",
                "value": "stack",
            }
        ],
    )

    finding = build_stepfunctions_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-SFN-002"


def test_stepfunctions_tagging_fails_without_tags():
    result = check_stepfunctions_tagging(
        ACTIVITY_ARN,
        [],
    )

    finding = build_stepfunctions_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-SFN-002"
    assert finding.severity == Severity.LOW
