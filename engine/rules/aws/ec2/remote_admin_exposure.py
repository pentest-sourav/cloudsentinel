from dataclasses import dataclass

from engine.findings.model import Finding, Severity
from scanner.aws.models.security_group import SecurityGroupRule


REMOTE_ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
}


@dataclass(frozen=True)
class RemoteAdminExposureResult:
    security_group_id: str
    rule: SecurityGroupRule
    ip_version: str
    management_service: str | None


def check_remote_admin_exposure(
    security_group_id: str,
    rule: SecurityGroupRule,
) -> RemoteAdminExposureResult | None:
    if not rule.is_cidr_source:
        return None

    if rule.is_all_ipv4:
        ip_version = "ipv4"
    elif rule.is_all_ipv6:
        ip_version = "ipv6"
    else:
        return None

    if rule.protocol.lower() not in {"tcp", "-1"}:
        return None

    if (
        rule.protocol.lower() == "-1"
        or rule.from_port is None
        or rule.to_port is None
    ):
        return RemoteAdminExposureResult(
            security_group_id=security_group_id,
            rule=rule,
            ip_version=ip_version,
            management_service=None,
        )

    for port, service in REMOTE_ADMIN_PORTS.items():
        if rule.from_port <= port <= rule.to_port:
            return RemoteAdminExposureResult(
                security_group_id=security_group_id,
                rule=rule,
                ip_version=ip_version,
                management_service=service,
            )

    return None


def build_remote_admin_exposure_finding(
    result: RemoteAdminExposureResult,
) -> Finding:
    source = (
        "0.0.0.0/0"
        if result.ip_version == "ipv4"
        else "::/0"
    )

    return Finding(
        rule_id=(
            "CS-AWS-EC2-053"
            if result.ip_version == "ipv4"
            else "CS-AWS-EC2-054"
        ),
        title=(
            "Remote Server Administration Port Exposed over IPv4"
            if result.ip_version == "ipv4"
            else "Remote Server Administration Port Exposed over IPv6"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ec2_security_group",
        resource_id=result.security_group_id,
        description=(
            f"The security group allows {source} to reach "
            "a remote server administration port."
        ),
        evidence={
            "security_group_id": result.security_group_id,
            "source": source,
            "protocol": result.rule.protocol,
            "from_port": result.rule.from_port,
            "to_port": result.rule.to_port,
            "management_service": result.management_service,
            "ip_version": result.ip_version,
        },
        remediation=(
            "Restrict SSH/RDP and other remote administration access "
            "to trusted source networks or security groups."
        ),
        compliance=[
            "AWS Security Hub EC2.53"
            if result.ip_version == "ipv4"
            else "AWS Security Hub EC2.54"
        ],
    )
