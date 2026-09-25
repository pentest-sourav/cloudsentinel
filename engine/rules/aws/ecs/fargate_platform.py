from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


LATEST_LINUX_PLATFORM = "1.4.0"
LATEST_WINDOWS_PLATFORM = "1.0.0"


@dataclass(frozen=True)
class ECSFargatePlatformResult:
    resource_arn: str
    resource_id: str
    launch_type: str | None
    platform_version: str | None
    latest_platform_version: str | None
    resource: dict[str, Any]


def check_ecs_fargate_platform(
    resource_arn: str,
    resource_id: str,
    launch_type: str | None,
    platform_version: str | None,
    resource: dict[str, Any],
) -> ECSFargatePlatformResult:
    latest = None

    if launch_type == "FARGATE":
        operating_system = resource.get(
            "operating_system_family"
        )

        if (
            isinstance(operating_system, str)
            and operating_system.upper().startswith("WINDOWS")
        ):
            latest = LATEST_WINDOWS_PLATFORM
        else:
            latest = LATEST_LINUX_PLATFORM

    return ECSFargatePlatformResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        launch_type=launch_type,
        platform_version=platform_version,
        latest_platform_version=latest,
        resource=resource,
    )


def build_ecs_fargate_platform_finding(
    result: ECSFargatePlatformResult,
):
    if result.launch_type != "FARGATE":
        return None

    if not result.latest_platform_version:
        return None

    if result.platform_version in (
        None,
        "LATEST",
        result.latest_platform_version,
    ):
        return None

    return finding(
        rule_id="CS-AWS-ECS-010",
        title="ECS Fargate Service Should Use the Latest Platform Version",
        severity=Severity.MEDIUM,
        resource_type="ecs_service",
        resource_id=result.resource_arn,
        description=(
            "The ECS Fargate service explicitly uses a platform "
            "version older than the Security Hub control baseline."
        ),
        evidence={
            "launch_type": result.launch_type,
            "platform_version": result.platform_version,
            "latest_platform_version": (
                result.latest_platform_version
            ),
        },
        remediation=(
            "Update the Fargate service to the current supported "
            "platform version or use LATEST."
        ),
        compliance="AWS Security Hub ECS.10",
    )
