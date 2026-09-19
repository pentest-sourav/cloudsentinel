from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UnrestrictedInboundResult:
    group_id: str
    group_name: str | None
    cidr: str


def check_unrestricted_inbound(
    group_id: str,
    group_name: str | None,
    inbound_rule: dict,
) -> UnrestrictedInboundResult | None:
    """
    Detect inbound Security Group rules that allow traffic
    from the entire IPv4 or IPv6 internet.
    """

    for ip_range in inbound_rule.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            return UnrestrictedInboundResult(
                group_id=group_id,
                group_name=group_name,
                cidr="0.0.0.0/0",
            )

    for ip_range in inbound_rule.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") == "::/0":
            return UnrestrictedInboundResult(
                group_id=group_id,
                group_name=group_name,
                cidr="::/0",
            )

    return None


def build_unrestricted_inbound_finding(
    result: UnrestrictedInboundResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SG-001",
        title="Security Group allows unrestricted inbound traffic",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="security_group",
        resource_id=result.group_id,
        description=(
            "The Security Group contains an inbound rule that allows "
            "traffic from the entire internet."
        ),
        evidence={
            "group_id": result.group_id,
            "group_name": result.group_name,
            "cidr": result.cidr,
        },
        remediation=(
            "Restrict the inbound source to the specific IP ranges, "
            "Security Groups, or network locations that require access. "
            "Avoid exposing services directly to the entire internet "
            "unless explicitly required."
        ),
        compliance=["CIS AWS Foundations"],
    )
