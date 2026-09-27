from dataclasses import dataclass

from engine.findings.model import Finding, Severity


MANAGED_INTERFACE_TYPES = {
    "aws_codestar_connections_managed",
    "branch",
    "efa",
    "interface",
    "lambda",
    "quicksight",
}


@dataclass(frozen=True)
class ENISourceDestinationCheckResult:
    network_interface_id: str
    interface_type: str
    source_dest_check: bool
    vpc_id: str | None
    subnet_id: str | None


def check_eni_source_destination_check(
    network_interface_id: str,
    interface_type: str,
    source_dest_check: bool,
    vpc_id: str | None,
    subnet_id: str | None,
) -> ENISourceDestinationCheckResult | None:
    normalized_type = str(interface_type).lower()

    if normalized_type not in MANAGED_INTERFACE_TYPES:
        return None

    if source_dest_check:
        return None

    return ENISourceDestinationCheckResult(
        network_interface_id=network_interface_id,
        interface_type=normalized_type,
        source_dest_check=source_dest_check,
        vpc_id=vpc_id,
        subnet_id=subnet_id,
    )


def build_eni_source_destination_check_finding(
    result: ENISourceDestinationCheckResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-019",
        title="Network interface has source/destination checking disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="network-interface",
        resource_id=result.network_interface_id,
        description=(
            "The network interface has source/destination checking "
            "disabled. AWS Security Hub requires source/destination "
            "checking to be enabled for the evaluated network "
            "interface types."
        ),
        evidence={
            "network_interface_id": result.network_interface_id,
            "interface_type": result.interface_type,
            "source_dest_check": result.source_dest_check,
            "vpc_id": result.vpc_id,
            "subnet_id": result.subnet_id,
        },
        remediation=(
            "Enable source/destination checking on the affected "
            "network interface unless the interface is intentionally "
            "used for a networking function that requires the check "
            "to be disabled and is outside the evaluated resource "
            "scope."
        ),
        compliance=[
            "AWS Security Hub EC2.180",
        ],
    )
