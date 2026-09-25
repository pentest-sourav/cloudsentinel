from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class Route53TaggingResult:
    resource_id: str
    resource_type: str


def check_route53_health_check_tagging(
    resource_id: str,
    resource_type: str,
    tags: list[dict[str, str]],
) -> Route53TaggingResult | None:
    if not resource_id:
        return None

    if tags:
        return None

    return Route53TaggingResult(
        resource_id=resource_id,
        resource_type=resource_type,
    )


def build_route53_health_check_tagging_finding(
    result: Route53TaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ROUTE53-001",
        title="Route 53 health checks should be tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Route 53 health check "
            f"{result.resource_id} does not have any "
            "non-system tags."
        ),
        evidence={
            "resource_id": result.resource_id,
            "resource_type": result.resource_type,
            "tagged": False,
        },
        remediation=(
            "Add one or more meaningful non-system tags "
            "to the Route 53 health check. If your "
            "organization uses required tag keys, "
            "configure the corresponding Security Hub "
            "control parameter."
        ),
        compliance=[
            "AWS Security Hub Route53.1",
        ],
    )


@dataclass(frozen=True)
class Route53QueryLoggingResult:
    resource_id: str
    query_logging_enabled: bool


def check_route53_query_logging(
    resource_id: str,
    private_zone: bool,
    query_logging_enabled: bool,
) -> Route53QueryLoggingResult | None:
    if not resource_id:
        return None

    if private_zone:
        return None

    if query_logging_enabled:
        return None

    return Route53QueryLoggingResult(
        resource_id=resource_id,
        query_logging_enabled=query_logging_enabled,
    )


def build_route53_query_logging_finding(
    result: Route53QueryLoggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ROUTE53-002",
        title=(
            "Route 53 public hosted zones should "
            "log DNS queries"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="route53_hosted_zone",
        resource_id=result.resource_id,
        description=(
            f"The public Route 53 hosted zone "
            f"{result.resource_id} does not have DNS "
            "query logging enabled."
        ),
        evidence={
            "hosted_zone_id": result.resource_id,
            "private_zone": False,
            "query_logging_enabled": (
                result.query_logging_enabled
            ),
        },
        remediation=(
            "Configure DNS query logging for the public "
            "Route 53 hosted zone and publish the query "
            "logs to an appropriate CloudWatch Logs "
            "log group."
        ),
        compliance=[
            "AWS Security Hub Route53.2",
        ],
    )
