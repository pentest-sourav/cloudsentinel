from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudFormationStackResult:
    stack_name: str
    stack_id: str
    reason: str
    evidence: dict


def _finding(
    result: CloudFormationStackResult,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type="cloudformation_stack",
        resource_id=result.stack_id,
        description=description,
        evidence={
            "stack_name": result.stack_name,
            "stack_id": result.stack_id,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=remediation,
        compliance=[
            (
                "AWS Security Hub "
                f"CloudFormation.{rule_id.rsplit('-', 1)[-1].lstrip('0')}"
            )
        ],
    )


def check_cloudformation_stack_tags(
    stack_name: str,
    stack_id: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> CloudFormationStackResult | None:
    if not stack_name or not stack_id:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return CloudFormationStackResult(
        stack_name=stack_name,
        stack_id=stack_id,
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_cloudformation_stack_tags_finding(
    result: CloudFormationStackResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-CLOUDFORMATION-002",
        "CloudFormation Stack Is Not Tagged",
        Severity.LOW,
        (
            f"CloudFormation stack {result.stack_name} "
            "does not have any non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "CloudFormation stack. CloudSentinel evaluates "
            "baseline presence of at least one non-system tag; "
            "Security Hub CloudFormation.2 can additionally "
            "enforce configured requiredTagKeys."
        ),
    )


def check_cloudformation_termination_protection(
    stack_name: str,
    stack_id: str,
    termination_protection_enabled: bool | None,
) -> CloudFormationStackResult | None:
    if not stack_name or not stack_id:
        return None

    if termination_protection_enabled is None:
        return None

    if termination_protection_enabled:
        return None

    return CloudFormationStackResult(
        stack_name=stack_name,
        stack_id=stack_id,
        reason="termination_protection_disabled",
        evidence={
            "termination_protection_enabled": False,
        },
    )


def build_cloudformation_termination_protection_finding(
    result: CloudFormationStackResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-CLOUDFORMATION-003",
        "CloudFormation Stack Does Not Have Termination Protection",
        Severity.MEDIUM,
        (
            f"CloudFormation stack {result.stack_name} "
            "does not have termination protection enabled."
        ),
        (
            "Enable termination protection for the CloudFormation "
            "stack to reduce the risk of accidental stack deletion."
        ),
    )


def check_cloudformation_service_role(
    stack_name: str,
    stack_id: str,
    role_arn: str | None,
) -> CloudFormationStackResult | None:
    if not stack_name or not stack_id:
        return None

    if role_arn:
        return None

    return CloudFormationStackResult(
        stack_name=stack_name,
        stack_id=stack_id,
        reason="service_role_not_associated",
        evidence={
            "role_arn": None,
        },
    )


def build_cloudformation_service_role_finding(
    result: CloudFormationStackResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-CLOUDFORMATION-004",
        "CloudFormation Stack Has No Associated Service Role",
        Severity.MEDIUM,
        (
            f"CloudFormation stack {result.stack_name} "
            "does not have an associated service role."
        ),
        (
            "Associate a least-privilege IAM service role with "
            "the CloudFormation stack so CloudFormation operates "
            "using explicitly scoped permissions."
        ),
    )
