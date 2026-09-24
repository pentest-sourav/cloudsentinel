from engine.findings.model import Severity

from engine.rules.aws.eventbridge.global_endpoint_replication import (
    build_eventbridge_global_endpoint_replication_finding,
    check_eventbridge_global_endpoint_replication,
)
from engine.rules.aws.eventbridge.resource_policy import (
    build_eventbridge_resource_policy_finding,
    check_eventbridge_resource_policy,
)
from engine.rules.aws.eventbridge.tagging import (
    build_eventbridge_tagging_finding,
    check_eventbridge_tagging,
)


EVENT_BUS_ARN = (
    "arn:aws:events:ap-south-1:123456789012:"
    "event-bus/test-bus"
)

ENDPOINT_ARN = (
    "arn:aws:events:ap-south-1:123456789012:"
    "endpoint/test-endpoint"
)


def test_eventbridge_tagging_passes_with_non_system_tag():
    result = check_eventbridge_tagging(
        EVENT_BUS_ARN,
        [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ],
    )

    assert result.tagged is True
    assert build_eventbridge_tagging_finding(result) is None


def test_eventbridge_tagging_ignores_system_tags():
    result = check_eventbridge_tagging(
        EVENT_BUS_ARN,
        [
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": "stack",
            }
        ],
    )

    finding = build_eventbridge_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-EVENTBRIDGE-002"


def test_eventbridge_tagging_fails_without_tags():
    result = check_eventbridge_tagging(
        EVENT_BUS_ARN,
        [],
    )

    finding = build_eventbridge_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.severity == Severity.LOW


def test_eventbridge_resource_policy_passes_for_custom_bus():
    result = check_eventbridge_resource_policy(
        EVENT_BUS_ARN,
        "custom-bus",
        None,
        {
            "Version": "2012-10-17",
            "Statement": [],
        },
    )

    assert result.is_custom_event_bus is True
    assert result.policy_attached is True
    assert build_eventbridge_resource_policy_finding(result) is None


def test_eventbridge_resource_policy_fails_for_custom_bus_without_policy():
    result = check_eventbridge_resource_policy(
        EVENT_BUS_ARN,
        "custom-bus",
        None,
        None,
    )

    finding = build_eventbridge_resource_policy_finding(result)

    assert result.is_custom_event_bus is True
    assert result.policy_attached is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-EVENTBRIDGE-003"
    assert finding.severity == Severity.LOW


def test_eventbridge_resource_policy_skips_default_bus():
    result = check_eventbridge_resource_policy(
        EVENT_BUS_ARN,
        "default",
        None,
        None,
    )

    assert result.is_custom_event_bus is False
    assert build_eventbridge_resource_policy_finding(result) is None


def test_eventbridge_resource_policy_skips_partner_bus():
    result = check_eventbridge_resource_policy(
        EVENT_BUS_ARN,
        "partner-bus",
        "aws.partner/example",
        None,
    )

    assert result.is_custom_event_bus is False
    assert build_eventbridge_resource_policy_finding(result) is None


def test_eventbridge_replication_passes_when_enabled():
    result = check_eventbridge_global_endpoint_replication(
        ENDPOINT_ARN,
        {
            "State": "ENABLED",
        },
    )

    assert result.replication_enabled is True
    assert result.replication_state == "ENABLED"
    assert (
        build_eventbridge_global_endpoint_replication_finding(
            result
        )
        is None
    )


def test_eventbridge_replication_fails_when_disabled():
    result = check_eventbridge_global_endpoint_replication(
        ENDPOINT_ARN,
        {
            "State": "DISABLED",
        },
    )

    finding = (
        build_eventbridge_global_endpoint_replication_finding(
            result
        )
    )

    assert result.replication_enabled is False
    assert result.replication_state == "DISABLED"
    assert finding is not None
    assert finding.rule_id == "CS-AWS-EVENTBRIDGE-004"
    assert finding.severity == Severity.MEDIUM


def test_eventbridge_replication_fails_when_missing():
    result = check_eventbridge_global_endpoint_replication(
        ENDPOINT_ARN,
        {},
    )

    finding = (
        build_eventbridge_global_endpoint_replication_finding(
            result
        )
    )

    assert result.replication_enabled is False
    assert result.replication_state is None
    assert finding is not None
