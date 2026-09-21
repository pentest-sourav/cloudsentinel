from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


def _contains_full_wildcard(value: Any) -> bool:
    if value == "*":
        return True

    if isinstance(value, (list, tuple, set)):
        return "*" in value

    return False


def _has_value(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(value, (list, tuple, set)):
        return any(
            isinstance(item, str) and item.strip()
            for item in value
        )

    return False


@dataclass(frozen=True)
class NotResourceBroadActionResult:
    permission_source: str
    resource_id: str
    principal_type: str
    principal_id: str
    username: str | None
    group_name: str | None
    policy_name: str
    policy_arn: str | None
    policy_version_id: str | None
    statement_index: int | None
    effect: str
    action: Any
    not_resource: Any
    condition: Any


def check_notresource_broad_action(
    permission_source: str,
    resource_id: str,
    principal_type: str,
    principal_id: str,
    username: str | None,
    group_name: str | None,
    policy_name: str,
    policy_arn: str | None,
    policy_version_id: str | None,
    statement_index: int | None,
    effect: str | None,
    action: Any,
    not_resource: Any,
    condition: Any,
) -> NotResourceBroadActionResult | None:
    if effect != "Allow":
        return None

    if not _contains_full_wildcard(action):
        return None

    if not _has_value(not_resource):
        return None

    return NotResourceBroadActionResult(
        permission_source=permission_source,
        resource_id=resource_id,
        principal_type=principal_type,
        principal_id=principal_id,
        username=username,
        group_name=group_name,
        policy_name=policy_name,
        policy_arn=policy_arn,
        policy_version_id=policy_version_id,
        statement_index=statement_index,
        effect=effect,
        action=action,
        not_resource=not_resource,
        condition=condition,
    )


def build_notresource_broad_action_finding(
    result: NotResourceBroadActionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-031",
        title="IAM Policy Uses Broad Action With NotResource",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' has an Allow statement "
            f"using wildcard Action with NotResource."
        ),
        evidence={
            "permission_source": result.permission_source,
            "principal_type": result.principal_type,
            "principal_id": result.principal_id,
            "username": result.username,
            "group_name": result.group_name,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "policy_version_id": result.policy_version_id,
            "statement_index": result.statement_index,
            "effect": result.effect,
            "action": result.action,
            "not_resource": result.not_resource,
            "condition_present": bool(result.condition),
        },
        remediation=(
            "Replace wildcard Action permissions with explicit "
            "required actions and replace NotResource with explicit "
            "resource ARNs wherever practical."
        ),
        compliance=["CIS AWS Foundations"],
    )
