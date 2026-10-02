from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class VPNTunnelResult:
    vpn_connection_id: str
    tunnel_states: list[dict[str, Any]]

    @property
    def both_tunnels_up(self) -> bool:
        states = [
            str(item.get("status", "")).lower()
            for item in self.tunnel_states
        ]
        return len(states) >= 2 and all(state == "up" for state in states[:2])


def check_vpn_tunnels(
    vpn_connection_id: str,
    tunnel_states: list[dict[str, Any]],
) -> VPNTunnelResult | None:
    result = VPNTunnelResult(
        vpn_connection_id=vpn_connection_id,
        tunnel_states=tunnel_states,
    )

    if result.both_tunnels_up:
        return None

    return result


def build_vpn_tunnels_finding(result: VPNTunnelResult) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-020",
        title="Both Site-to-Site VPN Tunnels Should Be Up",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ec2_vpn_connection",
        resource_id=result.vpn_connection_id,
        description=(
            "The AWS Site-to-Site VPN connection does not have "
            "both VPN tunnels in the UP state."
        ),
        evidence={
            "vpn_connection_id": result.vpn_connection_id,
            "tunnel_states": result.tunnel_states,
        },
        remediation=(
            "Investigate the affected VPN tunnels and restore both "
            "tunnels to the UP state."
        ),
        compliance=["AWS Security Hub EC2.20"],
    )
