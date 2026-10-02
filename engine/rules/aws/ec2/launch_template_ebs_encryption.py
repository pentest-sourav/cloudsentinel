from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class LaunchTemplateEBSEncryptionResult:
    launch_template_id: str
    launch_template_name: str | None
    version_number: int | None
    device_name: str | None
    encrypted: bool


def check_launch_template_ebs_encryption(
    launch_template_id: str,
    launch_template_name: str | None,
    version_number: int | None,
    device_name: str | None,
    encrypted: bool,
) -> LaunchTemplateEBSEncryptionResult | None:
    if encrypted:
        return None

    return LaunchTemplateEBSEncryptionResult(
        launch_template_id=launch_template_id,
        launch_template_name=launch_template_name,
        version_number=version_number,
        device_name=device_name,
        encrypted=encrypted,
    )


def build_launch_template_ebs_encryption_finding(
    result: LaunchTemplateEBSEncryptionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-181",
        title=(
            "EC2 Launch Template EBS Volume Is Not Encrypted"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ec2_launch_template",
        resource_id=result.launch_template_id,
        description=(
            "The default version of the EC2 launch template contains "
            "an explicitly configured EBS volume with encryption "
            "disabled. Instances launched from this configuration "
            "can create unencrypted EBS volumes."
        ),
        evidence={
            "launch_template_id": result.launch_template_id,
            "launch_template_name": result.launch_template_name,
            "version_number": result.version_number,
            "device_name": result.device_name,
            "encrypted": result.encrypted,
        },
        remediation=(
            "Create or modify the affected launch template default "
            "version so every explicitly configured EBS volume has "
            "encryption enabled."
        ),
        compliance=[
            "AWS Security Hub EC2.181",
        ],
    )
