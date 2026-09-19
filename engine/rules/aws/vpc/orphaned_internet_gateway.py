from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OrphanedInternetGatewayResult:
    internet_gateway_id: str


def check_orphaned_internet_gateway(
    internet_gateway_id: str,
    vpc_id: str | None,
    state: str | None,
):
    if vpc_id:
        return None

    return OrphanedInternetGatewayResult(
        internet_gateway_id=internet_gateway_id,
    )


def build_orphaned_internet_gateway_finding(
    result: OrphanedInternetGatewayResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-002",
        title="Internet Gateway is not attached to a VPC",
        severity=Severity.LOW,
        provider="aws",
        resource_type="internet_gateway",
        resource_id=result.internet_gateway_id,
        description=(
            "The Internet Gateway is not attached to a VPC. "
            "Unused Internet Gateways can increase configuration "
            "clutter and may indicate stale networking resources."
        ),
        evidence={
            "internet_gateway_id": result.internet_gateway_id,
            "vpc_id": None,
            "state": "detached",
        },
        remediation=(
            "Review the Internet Gateway and remove it if it is "
            "no longer required, following your organization's "
            "change-management process."
        ),
        compliance=["CIS AWS Foundations"],
    )
