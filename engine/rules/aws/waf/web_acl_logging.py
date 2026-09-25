from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class WAFWebACLLoggingResult:
    resource_id: str
    resource_arn: str
    name: str
    scope: str


def check_waf_web_acl_logging(
    resource_id: str,
    resource_arn: str,
    name: str,
    scope: str,
    logging_configuration: dict | None,
) -> WAFWebACLLoggingResult | None:
    if logging_configuration:
        return None

    return WAFWebACLLoggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        name=name,
        scope=scope,
    )


def build_waf_web_acl_logging_finding(
    result: WAFWebACLLoggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-WAF-011",
        title="WAF Web ACL Logging Is Not Enabled",
        severity=Severity.LOW,
        provider="aws",
        resource_type="waf_web_acl",
        resource_id=result.resource_id,
        description=(
            "Logging is not enabled for the AWS WAFv2 "
            "Web ACL."
        ),
        evidence={
            "web_acl_name": result.name,
            "web_acl_arn": result.resource_arn,
            "scope": result.scope,
            "logging_enabled": False,
        },
        remediation=(
            "Enable AWS WAF logging for the Web ACL and "
            "configure an appropriate logging destination."
        ),
        compliance=[
            "AWS Security Hub WAF.11",
        ],
    )
