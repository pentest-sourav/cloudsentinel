from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class VPCBlockPublicAccessResult:
    region: str | None
    internet_gateway_block_mode: str | None
    state: str | None
    managed_by: str | None
    exclusions_allowed: str | None


def check_vpc_block_public_access(
    region: str | None,
    internet_gateway_block_mode: str | None,
    state: str | None,
    managed_by: str | None,
    exclusions_allowed: str | None,
) -> VPCBlockPublicAccessResult | None:
    """
    Detect whether VPC Block Public Access blocks internet gateway traffic.

    AWS Security Hub EC2.172 passes when the regional VPC BPA
    InternetGatewayBlockMode is either:
      - block-bidirectional
      - block-ingress

    Any other value, including missing/unknown configuration,
    is treated as non-compliant.
    """

    mode = str(
        internet_gateway_block_mode or ""
    ).strip().lower()

    if mode in {
        "block-bidirectional",
        "block-ingress",
    }:
        return None

    return VPCBlockPublicAccessResult(
        region=region,
        internet_gateway_block_mode=internet_gateway_block_mode,
        state=state,
        managed_by=managed_by,
        exclusions_allowed=exclusions_allowed,
    )


def build_vpc_block_public_access_finding(
    result: VPCBlockPublicAccessResult,
) -> Finding:
    region = result.region or "unknown"

    return Finding(
        rule_id="CS-AWS-VPC-007",
        title=(
            "VPC Block Public Access does not block "
            "internet gateway traffic"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="vpc_block_public_access_options",
        resource_id=f"vpc-bpa:{region}",
        description=(
            "VPC Block Public Access is not configured to block "
            "internet gateway traffic in the AWS Region. AWS Security "
            "Hub EC2.172 requires the InternetGatewayBlockMode to be "
            "block-bidirectional or block-ingress."
        ),
        evidence={
            "region": result.region,
            "internet_gateway_block_mode": (
                result.internet_gateway_block_mode
            ),
            "state": result.state,
            "managed_by": result.managed_by,
            "exclusions_allowed": result.exclusions_allowed,
        },
        remediation=(
            "Configure VPC Block Public Access for the Region with "
            "InternetGatewayBlockMode set to block-bidirectional or "
            "block-ingress. If exclusions are required for legitimate "
            "public workloads, review and configure the appropriate "
            "VPC BPA exclusions according to your organization's "
            "network security requirements."
        ),
        compliance=[
            "AWS Security Hub EC2.172",
        ],
    )
