from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SpotFleetEBSEncryptionResult:
    spot_fleet_request_id: str
    launch_parameters_present: bool
    ebs_volume_count: int
    unencrypted_volume_count: int


def check_spot_fleet_ebs_encryption(
    spot_fleet_request_id: str,
    launch_parameters_present: bool,
    ebs_volume_count: int,
    unencrypted_volume_count: int,
) -> SpotFleetEBSEncryptionResult | None:
    if not launch_parameters_present:
        return None

    if unencrypted_volume_count == 0:
        return None

    return SpotFleetEBSEncryptionResult(
        spot_fleet_request_id=spot_fleet_request_id,
        launch_parameters_present=launch_parameters_present,
        ebs_volume_count=ebs_volume_count,
        unencrypted_volume_count=unencrypted_volume_count,
    )


def build_spot_fleet_ebs_encryption_finding(
    result: SpotFleetEBSEncryptionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-018",
        title="Spot Fleet launch parameters include unencrypted EBS volumes",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="spot-fleet-request",
        resource_id=result.spot_fleet_request_id,
        description=(
            "The Spot Fleet request has launch parameters with one or "
            "more EBS volumes that are not explicitly configured as "
            "encrypted."
        ),
        evidence={
            "spot_fleet_request_id": result.spot_fleet_request_id,
            "launch_parameters_present": (
                result.launch_parameters_present
            ),
            "ebs_volume_count": result.ebs_volume_count,
            "unencrypted_volume_count": (
                result.unencrypted_volume_count
            ),
        },
        remediation=(
            "Configure encryption for all applicable EBS volumes in "
            "the Spot Fleet launch parameters. Where a launch template "
            "is used, ensure its EBS block-device configuration "
            "provides encrypted volumes."
        ),
        compliance=[
            "AWS Security Hub EC2.173",
        ],
    )
