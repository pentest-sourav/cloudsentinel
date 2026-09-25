from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class WAFWebACLRulesResult:
    resource_id: str
    resource_arn: str
    name: str
    scope: str
    rule_count: int


def check_waf_web_acl_rules(
    resource_id: str,
    resource_arn: str,
    name: str,
    scope: str,
    rule_count: int,
) -> WAFWebACLRulesResult | None:
    if rule_count > 0:
        return None

    return WAFWebACLRulesResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        name=name,
        scope=scope,
        rule_count=rule_count,
    )


def build_waf_web_acl_rules_finding(
    result: WAFWebACLRulesResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-WAF-010",
        title="WAF Web ACL Has No Rules or Rule Groups",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="waf_web_acl",
        resource_id=result.resource_id,
        description=(
            "The AWS WAFv2 Web ACL does not contain any rules "
            "or rule groups."
        ),
        evidence={
            "web_acl_name": result.name,
            "web_acl_arn": result.resource_arn,
            "scope": result.scope,
            "rule_count": result.rule_count,
        },
        remediation=(
            "Configure the WAF Web ACL with at least one "
            "rule or rule group that inspects and controls "
            "web requests."
        ),
        compliance=[
            "AWS Security Hub WAF.10",
        ],
    )
