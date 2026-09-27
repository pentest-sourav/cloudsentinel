from dataclasses import dataclass

from engine.findings.model import Finding, Severity
from engine.rules.aws.security_groups.common import (
    is_unrestricted_ipv4,
    port_range_intersects,
    REMOTE_ADMIN_PORTS,
)


@dataclass(frozen=True)
class RemoteAdminIPv4Result:
    group_id: str
    group_name: str | None
    cidr: str
    protocol: str


def check_remote_admin_ipv4(
    group_id: str,
    group_name: str | None,
    inbound_rule: dict,
) -> RemoteAdminIPv4Result | None:
    if not is_unrestricted_ipv4(inbound_rule):
        return None

    if not port_range_intersects(inbound_rule, REMOTE_ADMIN_PORTS):
        return None

    return RemoteAdminIPv4Result(
        group_id=group_id,
        group_name=group_name,
        cidr="0.0.0.0/0",
        protocol=str(inbound_rule.get("IpProtocol", "")),
    )


def build_remote_admin_ipv4_finding(
    result: RemoteAdminIPv4Result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SG-005",
        title="Security Group exposes remote administration ports to IPv4 internet",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="security_group",
        resource_id=result.group_id,
        description=(
            "SSH or RDP is reachable from the entire IPv4 internet "
            "through a Security Group inbound rule."
        ),
        evidence={
            "group_id": result.group_id,
            "group_name": result.group_name,
            "cidr": result.cidr,
            "protocol": result.protocol,
            "ports": [22, 3389],
        },
        remediation=(
            "Restrict SSH/RDP access to trusted administrative "
            "network ranges or other controlled access paths."
        ),
        compliance=["CIS AWS Foundations"],
    )
