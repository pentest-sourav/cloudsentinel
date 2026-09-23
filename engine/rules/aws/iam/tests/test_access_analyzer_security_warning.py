from engine.findings.model import Severity
from engine.rules.aws.iam.access_analyzer_security_warning import (
    build_access_analyzer_security_warning_finding,
    check_access_analyzer_security_warning,
)


def test_access_analyzer_security_warning_detects_security_warning():
    result = check_access_analyzer_security_warning(
        permission_source="user_managed_policy",
        policy_name="CustomPolicy",
        policy_arn="arn:aws:iam::123456789012:policy/CustomPolicy",
        principals=["alice"],
        finding_type="SECURITY_WARNING",
        issue_code="PASS_ROLE_WITH_STAR_IN_RESOURCE",
        finding_details="Policy allows overly broad PassRole access.",
        learn_more_link="https://example.com",
        locations=[],
    )

    assert result is not None
    assert result.issue_code == "PASS_ROLE_WITH_STAR_IN_RESOURCE"


def test_access_analyzer_security_warning_ignores_non_security_finding():
    result = check_access_analyzer_security_warning(
        permission_source="user_managed_policy",
        policy_name="CustomPolicy",
        policy_arn=None,
        principals=["alice"],
        finding_type="SUGGESTION",
        issue_code="STYLE",
        finding_details="Suggestion",
        learn_more_link=None,
        locations=[],
    )

    assert result is None


def test_access_analyzer_security_warning_builds_high_finding():
    result = check_access_analyzer_security_warning(
        permission_source="role_inline_policy",
        policy_name="InlinePolicy",
        policy_arn=None,
        principals=["arn:aws:iam::123456789012:role/TestRole"],
        finding_type="SECURITY_WARNING",
        issue_code="ALLOW_WITH_NOT_PRINCIPAL",
        finding_details="Using NotPrincipal can be overly permissive.",
        learn_more_link="https://example.com",
        locations=[{"path": []}],
    )

    finding = build_access_analyzer_security_warning_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-036"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "InlinePolicy"
    assert finding.evidence["issue_code"] == (
        "ALLOW_WITH_NOT_PRINCIPAL"
    )
