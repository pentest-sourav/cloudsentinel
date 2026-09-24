from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EventBridgeResourcePolicyResult:
    event_bus_arn: str
    event_bus_name: str
    is_custom_event_bus: bool
    policy_attached: bool
    policy: dict[str, Any] | None


def check_eventbridge_resource_policy(
    event_bus_arn: str,
    event_bus_name: str,
    event_source_name: str | None,
    policy: dict[str, Any] | None,
) -> EventBridgeResourcePolicyResult:
    is_custom_event_bus = (
        event_bus_name != "default"
        and not event_source_name
    )

    policy_attached = isinstance(policy, dict) and bool(policy)

    return EventBridgeResourcePolicyResult(
        event_bus_arn=event_bus_arn,
        event_bus_name=event_bus_name,
        is_custom_event_bus=is_custom_event_bus,
        policy_attached=policy_attached,
        policy=policy,
    )


def build_eventbridge_resource_policy_finding(
    result: EventBridgeResourcePolicyResult,
) -> Finding | None:
    if not result.is_custom_event_bus:
        return None

    if result.policy_attached:
        return None

    return Finding(
        rule_id="CS-AWS-EVENTBRIDGE-003",
        title="Custom EventBridge Event Bus Has No Resource-Based Policy",
        severity=Severity.LOW,
        provider="aws",
        resource_type="eventbridge_event_bus",
        resource_id=result.event_bus_arn,
        description=(
            "The custom EventBridge event bus does not have a "
            "resource-based policy attached."
        ),
        evidence={
            "event_bus_name": result.event_bus_name,
            "is_custom_event_bus": result.is_custom_event_bus,
            "policy_attached": result.policy_attached,
            "policy": result.policy,
        },
        remediation=(
            "Attach an appropriate resource-based policy to the "
            "custom EventBridge event bus to explicitly control "
            "cross-account or other authorized access."
        ),
        compliance=[
            "AWS Security Hub EventBridge.3",
        ],
    )
