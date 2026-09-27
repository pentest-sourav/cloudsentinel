from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class NACLRemoteAdminResult:
    network_acl_id: str
    vpc_id: str | None
    rule_number: int | None
    protocol: str | None
    cidr_block: str | None
    ipv6_cidr_block: str | None
    from_port: int | None
    to_port: int | None
    egress: bool


def _normalise_protocol(protocol: str | None) -> str:
    value = str(protocol or "").strip().lower()

    if value in {"6", "tcp"}:
        return "tcp"

    if value in {"17", "udp"}:
        return "udp"

    if value in {"-1", "all"}:
        return "all"

    return value


def _covers_port(
    from_port: int | None,
    to_port: int | None,
    port: int,
) -> bool:
    if from_port is None or to_port is None:
        return False

    return from_port <= port <= to_port


def check_nacl_remote_admin(
    network_acl_id: str,
    vpc_id: str | None,
    rule_number: int | None,
    egress: bool,
    protocol: str | None,
    cidr_block: str | None,
    ipv6_cidr_block: str | None,
    from_port: int | None,
    to_port: int | None,
) -> NACLRemoteAdminResult | None:
    if egress:
        return None

    public_source = (
        cidr_block == "0.0.0.0/0"
        or ipv6_cidr_block == "::/0"
    )

    if not public_source:
        return None

    normalized_protocol = _normalise_protocol(protocol)

    if normalized_protocol == "all":
        return NACLRemoteAdminResult(
            network_acl_id=network_acl_id,
            vpc_id=vpc_id,
            rule_number=rule_number,
            protocol=protocol,
            cidr_block=cidr_block,
            ipv6_cidr_block=ipv6_cidr_block,
            from_port=from_port,
            to_port=to_port,
            egress=egress,
        )

    if normalized_protocol != "tcp":
        return None

    if (
        _covers_port(from_port, to_port, 22)
        or _covers_port(from_port, to_port, 3389)
    ):
        return NACLRemoteAdminResult(
            network_acl_id=network_acl_id,
            vpc_id=vpc_id,
            rule_number=rule_number,
            protocol=protocol,
            cidr_block=cidr_block,
            ipv6_cidr_block=ipv6_cidr_block,
            from_port=from_port,
            to_port=to_port,
            egress=egress,
        )

    return None


def build_nacl_remote_admin_finding(
    result: NACLRemoteAdminResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-010",
        title="Network ACL allows unrestricted SSH/RDP ingress",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="network_acl",
        resource_id=(
            f"{result.network_acl_id}:"
            f"{result.rule_number}"
        ),
        description=(
            "A Network ACL inbound rule permits unrestricted public "
            "access to SSH/RDP traffic. AWS Security Hub EC2.21 "
            "requires Network ACLs to restrict public ingress to "
            "ports 22 and 3389."
        ),
        evidence={
            "network_acl_id": result.network_acl_id,
            "vpc_id": result.vpc_id,
            "rule_number": result.rule_number,
            "protocol": result.protocol,
            "cidr_block": result.cidr_block,
            "ipv6_cidr_block": result.ipv6_cidr_block,
            "from_port": result.from_port,
            "to_port": result.to_port,
            "egress": result.egress,
        },
        remediation=(
            "Remove or restrict the public inbound Network ACL rule "
            "for SSH/RDP traffic. Allow only trusted source networks "
            "when administrative access is required."
        ),
        compliance=["AWS Security Hub EC2.21"],
    )
