from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EventBridgeTaggingResult:
    event_bus_arn: str
    tagged: bool
    tags: list[dict[str, Any]]


def check_eventbridge_tagging(
    event_bus_arn: str,
    tags: list[dict[str, Any]],
) -> EventBridgeTaggingResult:
    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and tag.get("Key")
        and not tag["Key"].startswith("aws:")
    ]

    return EventBridgeTaggingResult(
        event_bus_arn=event_bus_arn,
        tagged=bool(valid_tags),
        tags=valid_tags,
    )


def build_eventbridge_tagging_finding(
    result: EventBridgeTaggingResult,
) -> Finding | None:
    if result.tagged:
        return None

    return Finding(
        rule_id="CS-AWS-EVENTBRIDGE-002",
        title="EventBridge Event Bus Has No Tags",
        severity=Severity.LOW,
        provider="aws",
        resource_type="eventbridge_event_bus",
        resource_id=result.event_bus_arn,
        description=(
            "The EventBridge event bus does not have any "
            "non-system tags configured for ownership, inventory, "
            "or governance."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or other governance tags to the EventBridge event bus."
        ),
        compliance=[
            "AWS Security Hub EventBridge.2",
        ],
    )
