from dataclasses import dataclass

from engine.findings.model import Finding, Severity
from engine.rules.aws.security_groups.common import (
    is_unrestricted_ipv4,
    is_unrestricted_ipv6,
    tcp_range_is_authorized,
)


AUTHORIZED_TCP_PORTS = frozenset({80, 443})


@dataclass(frozen=True)
class AuthorizedPortsResult:
    group_id: str
    group_name: str | None
    cidr: str
    protocol: str


def check_authorized_ports(
    group_id: str,
    group_name: str | None,
    inbound_rule: dict,
) -> AuthorizedPortsResult | None:
    unrestricted_sources = []

    if is_unrestricted_ipv4(inbound_rule):
        unrestricted_sources.append("0.0.0.0/0")

    if is_unrestricted_ipv6(inbound_rule):
        unrestricted_sources.append("::/0")

    if not unrestricted_sources:
        return None

    if tcp_range_is_authorized(inbound_rule, AUTHORIZED_TCP_PORTS):
        return None

    return AuthorizedPortsResult(
        group_id=group_id,
        group_name=group_name,
        cidr=unrestricted_sources[0],
        protocol=str(inbound_rule.get("IpProtocol", "")),
    )


def build_authorized_ports_finding(
    result: AuthorizedPortsResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SG-002",
        title="Security Group allows unrestricted traffic on unauthorized ports",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="security_group",
        resource_id=result.group_id,
        description=(
            "The Security Group allows unrestricted inbound traffic "
            "on ports outside the authorized HTTP/HTTPS ports."
        ),
        evidence={
            "group_id": result.group_id,
            "group_name": result.group_name,
            "cidr": result.cidr,
            "protocol": result.protocol,
            "authorized_tcp_ports": [80, 443],
        },
        remediation=(
            "Restrict unrestricted inbound access to explicitly "
            "authorized ports and trusted source ranges."
        ),
        compliance=["AWS Security Hub"],
    )
