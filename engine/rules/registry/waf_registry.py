from engine.rules.aws.waf.rule_group_metrics import (
    build_waf_rule_group_metrics_finding,
    check_waf_rule_group_metrics,
)
from engine.rules.aws.waf.web_acl_logging import (
    build_waf_web_acl_logging_finding,
    check_waf_web_acl_logging,
)
from engine.rules.aws.waf.web_acl_rules import (
    build_waf_web_acl_rules_finding,
    check_waf_web_acl_rules,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


WAF_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-WAF-010",
            name="waf_web_acl_rules",
            data_source="waf_web_acls",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "name",
                "scope",
                "rule_count",
            ],
            check=check_waf_web_acl_rules,
            build_finding=(
                build_waf_web_acl_rules_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-WAF-011",
            name="waf_web_acl_logging",
            data_source="waf_web_acls",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "name",
                "scope",
                "logging_configuration",
            ],
            check=check_waf_web_acl_logging,
            build_finding=(
                build_waf_web_acl_logging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-WAF-012",
            name="waf_rule_group_metrics",
            data_source="waf_rule_groups",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "name",
                "scope",
                "cloudwatch_metrics_enabled",
            ],
            check=check_waf_rule_group_metrics,
            build_finding=(
                build_waf_rule_group_metrics_finding
            ),
        ),
    ]
)
