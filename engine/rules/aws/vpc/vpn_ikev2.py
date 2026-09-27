from dataclasses import dataclass

from engine.findings.model import Finding, Severity


def _is_ikev2_only(versions: list[str]) -> bool:
    if not versions:
        return False

    normalized = {
        str(version).strip().lower()
        for version in versions
        if version is not None
    }

    return normalized == {"ikev2"}


@dataclass(frozen=True)
class VPNIKEv2Result:
    vpn_connection_id: str
    tunnel_1_ike_versions: tuple[str, ...]
    tunnel_2_ike_versions: tuple[str, ...]


def check_vpn_ikev2(
    vpn_connection_id: str,
    tunnel_1_ike_versions: list[str],
    tunnel_2_ike_versions: list[str],
) -> VPNIKEv2Result | None:
    if (
        _is_ikev2_only(tunnel_1_ike_versions)
        and _is_ikev2_only(tunnel_2_ike_versions)
    ):
        return None

    return VPNIKEv2Result(
        vpn_connection_id=vpn_connection_id,
        tunnel_1_ike_versions=tuple(tunnel_1_ike_versions),
        tunnel_2_ike_versions=tuple(tunnel_2_ike_versions),
    )


def build_vpn_ikev2_finding(
    result: VPNIKEv2Result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-020",
        title="Site-to-Site VPN connection is not restricted to IKEv2",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="vpn-connection",
        resource_id=result.vpn_connection_id,
        description=(
            "The Site-to-Site VPN connection allows a tunnel to use "
            "IKEv1 or does not explicitly restrict both tunnels to "
            "IKEv2."
        ),
        evidence={
            "vpn_connection_id": result.vpn_connection_id,
            "tunnel_1_ike_versions": list(
                result.tunnel_1_ike_versions
            ),
            "tunnel_2_ike_versions": list(
                result.tunnel_2_ike_versions
            ),
        },
        remediation=(
            "Modify the VPN tunnel options so that IKEv2 is the only "
            "permitted IKE version on both VPN tunnels."
        ),
        compliance=[
            "AWS Security Hub EC2.183",
        ],
    )
