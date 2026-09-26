from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AmplifyResourceResult:
    resource_name: str
    resource_arn: str
    resource_type: str
    reason: str
    evidence: dict


def _finding(
    result: AmplifyResourceResult,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    compliance_control: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=description,
        evidence={
            "resource_name": result.resource_name,
            "resource_arn": result.resource_arn,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=remediation,
        compliance=[
            f"AWS Security Hub {compliance_control}",
        ],
    )


def check_amplify_app_tags(
    app_name: str,
    app_arn: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AmplifyResourceResult | None:
    if not app_name or not app_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return AmplifyResourceResult(
        resource_name=app_name,
        resource_arn=app_arn,
        resource_type="amplify_app",
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_amplify_app_tags_finding(
    result: AmplifyResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AMPLIFY-001",
        "Amplify App Is Not Tagged",
        Severity.LOW,
        (
            f"Amplify app {result.resource_name} "
            "does not have any non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "Amplify app. CloudSentinel evaluates baseline "
            "presence of at least one non-system tag; "
            "Security Hub Amplify.1 can additionally enforce "
            "configured requiredKeyTags."
        ),
        "Amplify.1",
    )


def check_amplify_branch_tags(
    branch_name: str,
    branch_arn: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AmplifyResourceResult | None:
    if not branch_name or not branch_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return AmplifyResourceResult(
        resource_name=branch_name,
        resource_arn=branch_arn,
        resource_type="amplify_branch",
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_amplify_branch_tags_finding(
    result: AmplifyResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AMPLIFY-002",
        "Amplify Branch Is Not Tagged",
        Severity.LOW,
        (
            f"Amplify branch {result.resource_name} "
            "does not have any non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "Amplify branch. CloudSentinel evaluates baseline "
            "presence of at least one non-system tag; "
            "Security Hub Amplify.2 can additionally enforce "
            "configured requiredKeyTags."
        ),
        "Amplify.2",
    )
