from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class IMDSv1Result:
    """
    Result of detecting an EC2 instance where
    IMDSv2 is not enforced.
    """

    instance_id: str
    http_tokens: str

    @property
    def is_vulnerable(self) -> bool:
        return self.http_tokens.lower() == "optional"


def check_imdsv1(
    instance_id: str,
    metadata_http_tokens: str | None,
) -> IMDSv1Result | None:
    """
    Detect EC2 instances where IMDSv2 is not required.

    IMDSv2 is considered enforced when HttpTokens
    is set to 'required'.
    """

    if not metadata_http_tokens:
        return None

    if metadata_http_tokens.lower() == "required":
        return None

    if metadata_http_tokens.lower() != "optional":
        return None

    return IMDSv1Result(
        instance_id=instance_id,
        http_tokens=metadata_http_tokens,
    )


def build_imdsv1_finding(
    result: IMDSv1Result,
) -> Finding:
    """
    Convert an IMDSv1 detection result into
    a CloudSentinel Finding.
    """

    return Finding(
        rule_id="CS-AWS-EC2-003",
        title="EC2 Instance Allows IMDSv1",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ec2_instance",
        resource_id=result.instance_id,
        description=(
            f"The EC2 instance {result.instance_id} does not "
            "require IMDSv2. IMDSv1 may increase the risk of "
            "credential or metadata exposure if an application "
            "is vulnerable to server-side request forgery (SSRF)."
        ),
        evidence={
            "instance_id": result.instance_id,
            "http_tokens": result.http_tokens,
        },
        remediation=(
            "Configure the EC2 instance metadata service to "
            "require IMDSv2 by setting HttpTokens to 'required'."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
