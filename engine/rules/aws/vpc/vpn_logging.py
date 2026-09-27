from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class VPNLoggingResult:
    vpn_connection_id: str
    tunnel_1_logging_enabled: bool
    tunnel_2_logging_enabled: bool


def check_vpn_logging(
    vpn_connection_id: str,
    tunnel_1_logging_enabled: bool,
    tunnel_2_logging_enabled: bool,
) -> VPNLoggingResult | None:
    if (
        tunnel_1_logging_enabled
        and tunnel_2_logging_enabled
    ):
        return None

    return VPNLoggingResult(
        vpn_connection_id=vpn_connection_id,
        tunnel_1_logging_enabled=tunnel_1_logging_enabled,
        tunnel_2_logging_enabled=tunnel_2_logging_enabled,
    )


def build_vpn_logging_finding(
    result: VPNLoggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-017",
        title="Site-to-Site VPN connection logging is not enabled for both tunnels",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="vpn-connection",
        resource_id=result.vpn_connection_id,
        description=(
            "The Site-to-Site VPN connection does not have CloudWatch "
            "Logs enabled for both VPN tunnels."
        ),
        evidence={
            "vpn_connection_id": result.vpn_connection_id,
            "tunnel_1_logging_enabled": (
                result.tunnel_1_logging_enabled
            ),
            "tunnel_2_logging_enabled": (
                result.tunnel_2_logging_enabled
            ),
        },
        remediation=(
            "Enable CloudWatch tunnel logging for both tunnels of the "
            "Site-to-Site VPN connection."
        ),
        compliance=[
            "AWS Security Hub EC2.171",
        ],
    )
