from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EventBridgeGlobalEndpointReplicationResult:
    endpoint_arn: str
    replication_enabled: bool
    replication_state: str | None
    replication_config: dict[str, Any]


def check_eventbridge_global_endpoint_replication(
    endpoint_arn: str,
    replication_config: dict[str, Any],
) -> EventBridgeGlobalEndpointReplicationResult:
    if not isinstance(replication_config, dict):
        replication_config = {}

    raw_state = replication_config.get("State")

    replication_state = (
        str(raw_state).upper()
        if isinstance(raw_state, str)
        else None
    )

    replication_enabled = replication_state == "ENABLED"

    return EventBridgeGlobalEndpointReplicationResult(
        endpoint_arn=endpoint_arn,
        replication_enabled=replication_enabled,
        replication_state=replication_state,
        replication_config=replication_config,
    )


def build_eventbridge_global_endpoint_replication_finding(
    result: EventBridgeGlobalEndpointReplicationResult,
) -> Finding | None:
    if result.replication_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-EVENTBRIDGE-004",
        title="EventBridge Global Endpoint Event Replication Is Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="eventbridge_global_endpoint",
        resource_id=result.endpoint_arn,
        description=(
            "The EventBridge global endpoint does not have event "
            "replication enabled."
        ),
        evidence={
            "replication_enabled": result.replication_enabled,
            "replication_state": result.replication_state,
            "replication_config": result.replication_config,
        },
        remediation=(
            "Enable event replication for the EventBridge global "
            "endpoint and configure the required replication role."
        ),
        compliance=[
            "AWS Security Hub EventBridge.4",
        ],
    )
