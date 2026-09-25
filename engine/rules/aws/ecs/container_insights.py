from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSContainerInsightsResult:
    resource_arn: str
    resource_id: str
    container_insights: str | None
    resource: dict[str, Any]


def check_ecs_container_insights(
    resource_arn: str,
    resource_id: str,
    settings: list[dict[str, Any]],
    resource: dict[str, Any],
) -> ECSContainerInsightsResult:
    value = None

    for setting in settings:
        if (
            isinstance(setting, dict)
            and setting.get("name") == "containerInsights"
        ):
            setting_value = setting.get("value")

            if isinstance(setting_value, str):
                value = setting_value

    return ECSContainerInsightsResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        container_insights=value,
        resource=resource,
    )


def build_ecs_container_insights_finding(
    result: ECSContainerInsightsResult,
):
    if result.container_insights in {
        "enabled",
        "enhanced",
    }:
        return None

    return finding(
        rule_id="CS-AWS-ECS-012",
        title="ECS Cluster Should Use Container Insights",
        severity=Severity.MEDIUM,
        resource_type="ecs_cluster",
        resource_id=result.resource_arn,
        description=(
            "The ECS cluster does not have Container Insights "
            "enabled."
        ),
        evidence={
            "container_insights": result.container_insights,
        },
        remediation=(
            "Enable Container Insights or Container Insights "
            "with enhanced observability for the ECS cluster."
        ),
        compliance="AWS Security Hub ECS.12",
    )
