from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ECSEFSTLSResult:
    resource_arn: str
    resource_id: str
    efs_volumes: list[dict[str, Any]]
    non_compliant_volumes: list[dict[str, Any]]
    encryption_enabled: bool
    resource: dict[str, Any]


def check_ecs_efs_tls(
    resource_arn: str,
    resource_id: str,
    volumes: list[dict[str, Any]] | None,
    resource: dict[str, Any],
) -> ECSEFSTLSResult:
    efs_volumes: list[dict[str, Any]] = []

    for volume in volumes or []:
        if not isinstance(volume, dict):
            continue

        efs_config = volume.get("efsVolumeConfiguration")

        if isinstance(efs_config, dict):
            efs_volumes.append(volume)

    non_compliant_volumes = [
        volume
        for volume in efs_volumes
        if volume.get("efsVolumeConfiguration", {}).get(
            "transitEncryption"
        ) != "ENABLED"
    ]

    return ECSEFSTLSResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        efs_volumes=efs_volumes,
        non_compliant_volumes=non_compliant_volumes,
        encryption_enabled=not non_compliant_volumes,
        resource=resource,
    )


def build_ecs_efs_tls_finding(
    result: ECSEFSTLSResult,
) -> Finding | None:
    if result.encryption_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-ECS-018",
        title="ECS EFS Volumes Should Use TLS",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn or result.resource_id,
        description=(
            "The ECS task definition contains EFS volumes that "
            "do not have transit encryption enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            "efs_volume_count": len(result.efs_volumes),
            "non_compliant_volume_count": len(
                result.non_compliant_volumes
            ),
            "non_compliant_volumes": result.non_compliant_volumes,
        },
        remediation=(
            "Set transitEncryption to ENABLED for every EFS volume "
            "configuration used by the ECS task definition."
        ),
        compliance=[
            "AWS Security Hub ECS.18",
        ],
    )
