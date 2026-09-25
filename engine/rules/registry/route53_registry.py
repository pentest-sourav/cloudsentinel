from engine.rules.aws.route53.protection import (
    build_route53_health_check_tagging_finding,
    build_route53_query_logging_finding,
    check_route53_health_check_tagging,
    check_route53_query_logging,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


ROUTE53_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-ROUTE53-001",
            name="Route 53 health checks should be tagged",
            data_source="route53_health_checks",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_type",
                "tags",
            ],
            check=check_route53_health_check_tagging,
            build_finding=(
                build_route53_health_check_tagging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-ROUTE53-002",
            name=(
                "Route 53 public hosted zones should "
                "log DNS queries"
            ),
            data_source="route53_hosted_zones",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "private_zone",
                "query_logging_enabled",
            ],
            check=check_route53_query_logging,
            build_finding=build_route53_query_logging_finding,
        ),
    ]
)
