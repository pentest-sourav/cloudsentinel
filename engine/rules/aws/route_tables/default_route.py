from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DefaultRouteResult:
    route_table_id: str
    vpc_id: str | None
    destination: str
    gateway_id: str
    state: str


def check_default_route(
    route_table_id: str,
    vpc_id: str | None,
    route: dict,
):
    """
    Detect an active IPv4 default route that points
    directly to an Internet Gateway.
    """

    destination = route.get("DestinationCidrBlock")
    gateway_id = route.get("GatewayId")
    state = route.get("State")

    if destination != "0.0.0.0/0":
        return None

    if not gateway_id or not gateway_id.startswith("igw-"):
        return None

    if state != "active":
        return None

    return DefaultRouteResult(
        route_table_id=route_table_id,
        vpc_id=vpc_id,
        destination=destination,
        gateway_id=gateway_id,
        state=state,
    )


def build_default_route_finding(
    result: DefaultRouteResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RT-001",
        title="Route Table has an active default route to an Internet Gateway",
        severity=Severity.LOW,
        provider="aws",
        resource_type="route_table",
        resource_id=result.route_table_id,
        description=(
            "The Route Table contains an active IPv4 default route "
            "to an Internet Gateway. This provides a path to the "
            "internet for resources associated with the relevant "
            "subnets. Internet reachability should be reviewed "
            "together with subnet, resource, and Security Group "
            "configuration."
        ),
        evidence={
            "route_table_id": result.route_table_id,
            "vpc_id": result.vpc_id,
            "destination": result.destination,
            "gateway_id": result.gateway_id,
            "state": result.state,
        },
        remediation=(
            "Review whether direct internet routing is required. "
            "If the associated subnet or resources do not require "
            "internet access, remove or replace the default route "
            "according to the organization's network architecture "
            "and change-management process."
        ),
        compliance=["CIS AWS Foundations"],
    )
