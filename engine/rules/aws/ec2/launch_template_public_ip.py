from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class LaunchTemplatePublicIPResult:
    launch_template_id: str
    launch_template_name: str | None
    version_number: int | None
    network_interface_index: int
    associate_public_ip_address: bool


def check_launch_template_public_ip(
    launch_template_id: str,
    launch_template_name: str | None,
    version_number: int | None,
    network_interface_index: int,
    associate_public_ip_address: bool | None,
) -> LaunchTemplatePublicIPResult | None:
    if associate_public_ip_address is not True:
        return None

    return LaunchTemplatePublicIPResult(
        launch_template_id=launch_template_id,
        launch_template_name=launch_template_name,
        version_number=version_number,
        network_interface_index=network_interface_index,
        associate_public_ip_address=associate_public_ip_address,
    )


def build_launch_template_public_ip_finding(
    result: LaunchTemplatePublicIPResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-025",
        title="EC2 Launch Template Assigns Public IP Addresses",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ec2_launch_template",
        resource_id=result.launch_template_id,
        description=(
            "The default version of an EC2 launch template explicitly "
            "configures a network interface to receive a public IP address."
        ),
        evidence={
            "launch_template_id": result.launch_template_id,
            "launch_template_name": result.launch_template_name,
            "version_number": result.version_number,
            "network_interface_index": result.network_interface_index,
            "associate_public_ip_address": (
                result.associate_public_ip_address
            ),
        },
        remediation=(
            "Remove the public-IP association from the launch template "
            "unless direct internet addressing is explicitly required."
        ),
        compliance=["AWS Security Hub EC2.25"],
    )
