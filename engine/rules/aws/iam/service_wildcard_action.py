from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


def _values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]

    if isinstance(value, (list, tuple, set)):
        return [
            item
            for item in value
            if isinstance(item, str)
        ]

    return []


def _find_service_wildcard(action: Any) -> str | None:
    for value in _values(action):
        normalized = value.strip().lower()

        if (
            normalized.endswith(":*")
            and normalized != "*"
            and normalized.count(":") == 1
        ):
            return value

    return None


def _is_customer_managed_policy(
    policy_arn: str | None,
) -> bool:
    if not policy_arn:
        return False

    parts = policy_arn.split(":", 5)

    if len(parts) != 6:
        return False

    partition = parts[1]
    service = parts[2]
    account = parts[4]
    resource = parts[5]

    if not partition or service != "iam":
        return False

    if account == "aws":
        return False

    return resource.startswith("policy/")


@dataclass(frozen=True)
class ServiceWildcardActionResult:
    permission_source: str
    resource_id: str
    principal_type: str
    principal_id: str
    username: str | None
    group_name: str | None
    policy_name: str
    policy_arn: str
    policy_version_id: str | None
    statement_index: int | None
    effect: str
    action: Any
    resource: Any
    condition: Any
    matching_action: str


def check_service_wildcard_action(
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
    resource: Any,
    condition: Any,
) -> ServiceWildcardActionResult | None:
    if effect != "Allow":
        return None

    if not _is_customer_managed_policy(policy_arn):
        return None

    matching_action = _find_service_wildcard(action)

    if matching_action is None:
        return None

    return ServiceWildcardActionResult(
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
        resource=resource,
        condition=condition,
        matching_action=matching_action,
    )


def build_service_wildcard_action_finding(
    result: ServiceWildcardActionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-029",
        title="Customer-Managed IAM Policy Uses Service Wildcard Action",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' has a customer-managed "
            f"policy '{result.policy_name}' granting the service "
            f"wildcard action '{result.matching_action}'."
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
            "resource": result.resource,
            "condition_present": bool(result.condition),
            "matching_action": result.matching_action,
        },
        remediation=(
            "Replace service-level wildcard actions with the minimum "
            "specific actions required by the identity. Review the "
            "resource scope and conditions at the same time."
        ),
        compliance=["CIS AWS Foundations"],
    )
