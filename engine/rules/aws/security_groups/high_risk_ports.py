from dataclasses import dataclass

from engine.findings.model import Finding, Severity
from engine.rules.aws.security_groups.common import (
    HIGH_RISK_PORTS,
    is_unrestricted_ipv4,
    is_unrestricted_ipv6,
    port_range_intersects,
)


@dataclass(frozen=True)
class HighRiskPortsResult:
    group_id: str
    group_name: str | None
    cidr: str
    protocol: str


def check_high_risk_ports(
    group_id: str,
    group_name: str | None,
    inbound_rule: dict,
) -> HighRiskPortsResult | None:
    if not (
        is_unrestricted_ipv4(inbound_rule)
        or is_unrestricted_ipv6(inbound_rule)
    ):
        return None

    if not port_range_intersects(inbound_rule, HIGH_RISK_PORTS):
        return None

    cidr = (
        "0.0.0.0/0"
        if is_unrestricted_ipv4(inbound_rule)
        else "::/0"
    )

    return HighRiskPortsResult(
        group_id=group_id,
        group_name=group_name,
        cidr=cidr,
        protocol=str(inbound_rule.get("IpProtocol", "")),
    )


def build_high_risk_ports_finding(
    result: HighRiskPortsResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SG-003",
        title="Security Group allows unrestricted access to high-risk ports",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="security_group",
        resource_id=result.group_id,
        description=(
            "The Security Group allows unrestricted inbound access "
            "to one or more high-risk network ports."
        ),
        evidence={
            "group_id": result.group_id,
            "group_name": result.group_name,
            "cidr": result.cidr,
            "protocol": result.protocol,
            "high_risk_ports": sorted(HIGH_RISK_PORTS),
        },
        remediation=(
            "Remove unrestricted internet access to high-risk ports "
            "and restrict access to required trusted sources only."
        ),
        compliance=["AWS Security Hub"],
    )
