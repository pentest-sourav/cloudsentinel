from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AccessAnalyzerSecurityWarningResult:
    permission_source: str
    policy_name: str
    policy_arn: str | None
    principals: list[str]
    finding_type: str
    issue_code: str | None
    finding_details: str | None
    learn_more_link: str | None
    locations: list[dict[str, Any]]


def check_access_analyzer_security_warning(
    permission_source: str,
    policy_name: str,
    policy_arn: str | None,
    principals: list[str],
    finding_type: str,
    issue_code: str | None,
    finding_details: str | None,
    learn_more_link: str | None,
    locations: list[dict[str, Any]],
) -> AccessAnalyzerSecurityWarningResult | None:
    if finding_type != "SECURITY_WARNING":
        return None

    return AccessAnalyzerSecurityWarningResult(
        permission_source=permission_source,
        policy_name=policy_name,
        policy_arn=policy_arn,
        principals=principals,
        finding_type=finding_type,
        issue_code=issue_code,
        finding_details=finding_details,
        learn_more_link=learn_more_link,
        locations=locations,
    )


def build_access_analyzer_security_warning_finding(
    result: AccessAnalyzerSecurityWarningResult,
) -> Finding:
    resource_id = (
        result.policy_arn
        or result.policy_name
    )

    return Finding(
        rule_id="CS-AWS-IAM-036",
        title=(
            "IAM Access Analyzer detected a security warning "
            f"in policy '{result.policy_name}'"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_policy",
        resource_id=resource_id,
        description=(
            result.finding_details
            or (
                "IAM Access Analyzer reported a security warning "
                "for an IAM identity policy."
            )
        ),
        evidence={
            "permission_source": result.permission_source,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "principals": result.principals,
            "finding_type": result.finding_type,
            "issue_code": result.issue_code,
            "finding_details": result.finding_details,
            "learn_more_link": result.learn_more_link,
            "locations": result.locations,
        },
        remediation=(
            "Review the IAM policy statement identified by IAM "
            "Access Analyzer and remove or constrain the "
            "overly permissive configuration. Follow the AWS "
            "Access Analyzer guidance for the reported issue."
        ),
    )
