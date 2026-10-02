from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class LaunchTemplateIMDSv2Result:
    launch_template_id: str
    launch_template_name: str | None
    version_number: int | None
    http_tokens: str | None


def check_launch_template_imdsv2(
    launch_template_id: str,
    launch_template_name: str | None,
    version_number: int | None,
    http_tokens: str | None,
) -> LaunchTemplateIMDSv2Result | None:
    if not http_tokens:
        return None

    if http_tokens.lower() == "required":
        return None

    return LaunchTemplateIMDSv2Result(
        launch_template_id=launch_template_id,
        launch_template_name=launch_template_name,
        version_number=version_number,
        http_tokens=http_tokens,
    )


def build_launch_template_imdsv2_finding(
    result: LaunchTemplateIMDSv2Result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-170",
        title="EC2 Launch Template Should Require IMDSv2",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ec2_launch_template",
        resource_id=result.launch_template_id,
        description=(
            "The default version of an EC2 launch template does not "
            "explicitly require IMDSv2."
        ),
        evidence={
            "launch_template_id": result.launch_template_id,
            "launch_template_name": result.launch_template_name,
            "version_number": result.version_number,
            "http_tokens": result.http_tokens,
        },
        remediation=(
            "Set MetadataOptions.HttpTokens to required in the "
            "launch template default version."
        ),
        compliance=["AWS Security Hub EC2.170"],
    )
