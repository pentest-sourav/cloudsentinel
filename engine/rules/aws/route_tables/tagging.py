from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RouteTableTaggingResult:
    route_table_id: str
    vpc_id: str | None
    tags: list[dict]


def _non_system_tags(tags: list[dict] | None) -> list[dict]:
    if not isinstance(tags, list):
        return []

    return [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and not tag["Key"].startswith("aws:")
    ]


def check_route_table_tagging(
    route_table_id: str,
    vpc_id: str | None,
    tags: list[dict] | None,
):
    """
    Detect a Route Table with no non-system tags.

    This aligns with AWS Security Hub EC2.42 behavior when no
    requiredTagKeys parameter is supplied.
    """

    non_system_tags = _non_system_tags(tags)

    if non_system_tags:
        return None

    return RouteTableTaggingResult(
        route_table_id=route_table_id,
        vpc_id=vpc_id,
        tags=[],
    )


def build_route_table_tagging_finding(
    result: RouteTableTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RT-002",
        title="Route Table is not tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="route_table",
        resource_id=result.route_table_id,
        description=(
            "The Route Table does not have any non-system tags. "
            "Route Table tagging improves resource ownership, "
            "inventory, organization, and accountability."
        ),
        evidence={
            "route_table_id": result.route_table_id,
            "vpc_id": result.vpc_id,
            "tags": result.tags,
        },
        remediation=(
            "Add one or more meaningful non-system tags to the "
            "Route Table, such as Environment, Owner, Application, "
            "or CostCenter, according to the organization's tagging "
            "standard."
        ),
        compliance=["AWS Security Hub"],
    )
