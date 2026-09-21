from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


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
class NotActionWildcardResourceResult:
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
    not_action: Any
    resource: Any
    condition: Any


def check_notaction_wildcard_resource(
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
    not_action: Any,
    resource: Any,
    condition: Any,
) -> NotActionWildcardResourceResult | None:
    if effect != "Allow":
        return None

    if not _has_value(not_action):
        return None

    if resource != "*":
        return None

    return NotActionWildcardResourceResult(
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
        not_action=not_action,
        resource=resource,
        condition=condition,
    )


def build_notaction_wildcard_resource_finding(
    result: NotActionWildcardResourceResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-030",
        title="IAM Policy Uses NotAction With Wildcard Resource",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' has an Allow statement using "
            f"NotAction with Resource='*'."
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
            "not_action": result.not_action,
            "resource": result.resource,
            "condition_present": bool(result.condition),
        },
        remediation=(
            "Review the NotAction statement carefully. Replace it "
            "with explicit required actions and restrict Resource "
            "to the smallest practical scope."
        ),
        compliance=["CIS AWS Foundations"],
    )
