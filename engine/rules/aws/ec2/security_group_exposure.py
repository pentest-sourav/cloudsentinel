from dataclasses import dataclass

from engine.findings.model import Finding, Severity
from scanner.aws.models.security_group import SecurityGroupRule


MANAGEMENT_PORTS = {
    22: "SSH",
    3389: "RDP",
}


@dataclass(frozen=True)
class SecurityGroupExposureResult:
    """
    Result of evaluating an EC2 security-group ingress rule
    for internet exposure.
    """

    security_group_id: str
    rule: SecurityGroupRule
    exposure_type: str
    management_service: str | None

    @property
    def is_exposed(self) -> bool:
        return True


def check_security_group_exposure(
    security_group_id: str,
    rule: SecurityGroupRule,
) -> SecurityGroupExposureResult | None:
    """
    Detect publicly reachable EC2 management ports.

    Detects:
    - SSH (22)
    - RDP (3389)
    - All-port exposure

    Supports:
    - Public IPv4
    - Public IPv6

    Does not treat private CIDRs or security-group references
    as internet exposure.
    """

    if not rule.is_cidr_source:
        return None

    if not (
        rule.is_all_ipv4
        or rule.is_all_ipv6
    ):
        return None

    protocol = rule.protocol.lower()

    if protocol not in {"tcp", "-1"}:
        return None

    management_service = None

    if rule.from_port in MANAGEMENT_PORTS:
        management_service = MANAGEMENT_PORTS[
            rule.from_port
        ]

    if (
        protocol == "-1"
        or rule.from_port is None
        or rule.to_port is None
    ):
        return SecurityGroupExposureResult(
            security_group_id=security_group_id,
            rule=rule,
            exposure_type="all_ports",
            management_service=None,
        )

    if (
        rule.from_port <= 22
        and rule.to_port >= 22
    ):
        return SecurityGroupExposureResult(
            security_group_id=security_group_id,
            rule=rule,
            exposure_type="ssh_port_range",
            management_service="SSH",
        )

    if (
        rule.from_port <= 3389
        and rule.to_port >= 3389
    ):
        return SecurityGroupExposureResult(
            security_group_id=security_group_id,
            rule=rule,
            exposure_type="rdp_port_range",
            management_service="RDP",
        )

    return None


def build_security_group_exposure_finding(
    result: SecurityGroupExposureResult,
) -> Finding:
    """
    Convert a detected security-group exposure into
    a normalized CloudSentinel Finding.
    """

    rule = result.rule

    if rule.is_all_ipv4:
        source = "0.0.0.0/0"

    elif rule.is_all_ipv6:
        source = "::/0"

    else:
        source = "unknown"

    if result.management_service:
        title = (
            f"{result.management_service} Port Exposed "
            "to the Internet"
        )
    else:
        title = "Management Ports Exposed to the Internet"

    if result.exposure_type == "all_ports":
        port_description = "all ports"

    elif rule.from_port == rule.to_port:
        port_description = str(rule.from_port)

    else:
        port_description = (
            f"{rule.from_port}-{rule.to_port}"
        )

    return Finding(
        rule_id="CS-AWS-EC2-001",
        title=title,
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ec2_security_group",
        resource_id=result.security_group_id,
        description=(
            f"The security group allows internet-wide access "
            f"from {source} to {port_description}. "
            "This may expose a management service or other "
            "sensitive network surface to the public internet."
        ),
        evidence={
            "security_group_id": result.security_group_id,
            "protocol": rule.protocol,
            "from_port": rule.from_port,
            "to_port": rule.to_port,
            "ipv4_cidr": rule.ipv4_cidr,
            "ipv6_cidr": rule.ipv6_cidr,
            "source_security_group_id": (
                rule.source_security_group_id
            ),
            "source": source,
            "exposure_type": result.exposure_type,
            "management_service": result.management_service,
        },
        remediation=(
            "Restrict the security-group ingress rule to "
            "trusted source IP ranges or security groups. "
            "Avoid exposing management services directly "
            "to the public internet unless explicitly required."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
