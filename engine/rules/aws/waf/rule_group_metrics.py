from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class WAFRuleGroupMetricsResult:
    resource_id: str
    resource_arn: str
    name: str
    scope: str
    cloudwatch_metrics_enabled: bool | None


def check_waf_rule_group_metrics(
    resource_id: str,
    resource_arn: str,
    name: str,
    scope: str,
    cloudwatch_metrics_enabled: bool | None,
) -> WAFRuleGroupMetricsResult | None:
    if cloudwatch_metrics_enabled is True:
        return None

    return WAFRuleGroupMetricsResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        name=name,
        scope=scope,
        cloudwatch_metrics_enabled=(
            cloudwatch_metrics_enabled
        ),
    )


def build_waf_rule_group_metrics_finding(
    result: WAFRuleGroupMetricsResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-WAF-012",
        title="WAF Rule Group CloudWatch Metrics Are Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="waf_rule_group",
        resource_id=result.resource_id,
        description=(
            "CloudWatch metrics are not enabled for the "
            "AWS WAFv2 rule group."
        ),
        evidence={
            "rule_group_name": result.name,
            "rule_group_arn": result.resource_arn,
            "scope": result.scope,
            "cloudwatch_metrics_enabled": (
                result.cloudwatch_metrics_enabled
            ),
        },
        remediation=(
            "Enable CloudWatch metrics for the WAF rule group "
            "through its VisibilityConfig."
        ),
        compliance=[
            "AWS Security Hub WAF.12",
        ],
    )
