from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ClientVPNLoggingResult:
    endpoint_id: str
    vpc_id: str | None
    connection_log_enabled: bool


def check_client_vpn_logging(
    endpoint_id: str,
    vpc_id: str | None,
    connection_log_enabled: bool,
) -> ClientVPNLoggingResult | None:
    if connection_log_enabled:
        return None

    return ClientVPNLoggingResult(
        endpoint_id=endpoint_id,
        vpc_id=vpc_id,
        connection_log_enabled=connection_log_enabled,
    )


def build_client_vpn_logging_finding(
    result: ClientVPNLoggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-016",
        title="Client VPN endpoint does not have connection logging enabled",
        severity=Severity.LOW,
        provider="aws",
        resource_type="client-vpn-endpoint",
        resource_id=result.endpoint_id,
        description=(
            "The Client VPN endpoint does not have client connection "
            "logging enabled. Connection logs provide visibility into "
            "client activity on the VPN endpoint."
        ),
        evidence={
            "endpoint_id": result.endpoint_id,
            "vpc_id": result.vpc_id,
            "connection_log_enabled": result.connection_log_enabled,
        },
        remediation=(
            "Enable client connection logging for the Client VPN "
            "endpoint and configure an appropriate CloudWatch Logs "
            "destination."
        ),
        compliance=[
            "AWS Security Hub EC2.51",
        ],
    )
