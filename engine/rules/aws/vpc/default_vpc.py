from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DefaultVPCResult:
    vpc_id: str
    cidr_block: str | None


def check_default_vpc(
    vpc_id: str,
    cidr_block: str | None,
    is_default: bool,
) -> DefaultVPCResult | None:
    """
    Detect the presence of an AWS default VPC.

    A default VPC is not automatically a vulnerability.
    This rule treats it as a security-hygiene finding because
    unused default networking can increase configuration risk.
    """

    if not is_default:
        return None

    return DefaultVPCResult(
        vpc_id=vpc_id,
        cidr_block=cidr_block,
    )


def build_default_vpc_finding(
    result: DefaultVPCResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-001",
        title="Default VPC is present",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="vpc",
        resource_id=result.vpc_id,
        description=(
            "The AWS account contains a default VPC. Default networking "
            "resources may remain unused but can increase the chance of "
            "unintended exposure or configuration drift."
        ),
        evidence={
            "vpc_id": result.vpc_id,
            "cidr_block": result.cidr_block,
            "is_default": True,
        },
        remediation=(
            "Review whether the default VPC is required. If it is unused, "
            "remove unnecessary default networking resources according to "
            "your organization's AWS governance and change-management process."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
