from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudFormationStackResult:
    stack_name: str
    stack_id: str
    reason: str
    evidence: dict


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue

        key = key.strip()

        if not key or key.lower().startswith("aws:"):
            continue

        if key not in seen:
            seen.add(key)
            normalized.append(key)

    return normalized


def _missing_required_tag_keys(
    tags: dict[str, str] | None,
    required_tag_keys: list[str],
) -> list[str]:
    if not required_tag_keys:
        return []

    present_keys = {
        key
        for key in (tags or {})
        if isinstance(key, str)
        and not key.lower().startswith("aws:")
    }

    return [
        key
        for key in required_tag_keys
        if key not in present_keys
    ]


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
    tags: dict[str, str] | None = None,
    required_tag_keys: list[str] | None = None,
) -> CloudFormationStackResult | None:
    if not stack_name or not stack_id:
        return None

    if not tag_data_available:
        return None

    normalized_required = _normalize_required_tag_keys(
        required_tag_keys
    )

    missing_required = _missing_required_tag_keys(
        tags,
        normalized_required,
    )

    if normalized_required:
        if not missing_required:
            return None
    elif has_non_system_tags:
        return None

    return CloudFormationStackResult(
        stack_name=stack_name,
        stack_id=stack_id,
        reason=(
            "missing_required_tag_keys"
            if normalized_required
            else "missing_non_system_tags"
        ),
        evidence={
            "has_non_system_tags": has_non_system_tags,
            "required_tag_keys": normalized_required,
            "missing_tag_keys": missing_required,
        },
    )


def build_cloudformation_stack_tags_finding(
    result: CloudFormationStackResult,
) -> Finding:
    required = result.evidence.get(
        "required_tag_keys",
        [],
    )

    missing = result.evidence.get(
        "missing_tag_keys",
        [],
    )

    if required:
        remediation = (
            "Add the missing required tag keys to the "
            "CloudFormation stack: "
            + ", ".join(missing)
        )
    else:
        remediation = (
            "Add the required organizational tags to the "
            "CloudFormation stack. CloudSentinel evaluates "
            "baseline presence of at least one non-system tag."
        )

    return _finding(
        result,
        "CS-AWS-CLOUDFORMATION-002",
        "CloudFormation Stack Is Not Tagged",
        Severity.LOW,
        (
            f"CloudFormation stack {result.stack_name} "
            "does not satisfy the configured tagging "
            "requirements."
        ),
        remediation,
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
