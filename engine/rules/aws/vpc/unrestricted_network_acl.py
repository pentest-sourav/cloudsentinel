from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UnrestrictedNetworkACLResult:
    network_acl_id: str
    vpc_id: str
    rule_number: int | None
    egress: bool
    protocol: str | None
    cidr_block: str | None
    ipv6_cidr_block: str | None


def check_unrestricted_network_acl(
    network_acl_id: str,
    vpc_id: str,
    is_default: bool,
    rule_number: int | None,
    egress: bool,
    rule_action: str | None,
    protocol: str | None,
    cidr_block: str | None,
    ipv6_cidr_block: str | None,
) -> UnrestrictedNetworkACLResult | None:
    if is_default:
        return None

    if str(rule_action or "").lower() != "allow":
        return None

    if str(protocol or "") != "-1":
        return None

    unrestricted_ipv4 = cidr_block == "0.0.0.0/0"
    unrestricted_ipv6 = ipv6_cidr_block == "::/0"

    if not unrestricted_ipv4 and not unrestricted_ipv6:
        return None

    return UnrestrictedNetworkACLResult(
        network_acl_id=network_acl_id,
        vpc_id=vpc_id,
        rule_number=rule_number,
        egress=egress,
        protocol=protocol,
        cidr_block=cidr_block,
        ipv6_cidr_block=ipv6_cidr_block,
    )


def build_unrestricted_network_acl_finding(
    result: UnrestrictedNetworkACLResult,
) -> Finding:
    direction = "outbound" if result.egress else "inbound"

    return Finding(
        rule_id="CS-AWS-VPC-005",
        title="Network ACL allows unrestricted traffic",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="network_acl",
        resource_id=result.network_acl_id,
        description=(
            f"The Network ACL contains an allow rule for unrestricted "
            f"{direction} traffic. The rule permits all protocols from "
            f"the entire IPv4 or IPv6 address space."
        ),
        evidence={
            "network_acl_id": result.network_acl_id,
            "vpc_id": result.vpc_id,
            "rule_number": result.rule_number,
            "direction": direction,
            "egress": result.egress,
            "protocol": result.protocol,
            "cidr_block": result.cidr_block,
            "ipv6_cidr_block": result.ipv6_cidr_block,
        },
        remediation=(
            "Review the Network ACL rule and replace unrestricted "
            "allow traffic with narrowly scoped rules that permit "
            "only the protocols and network ranges required by the "
            "workload."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
