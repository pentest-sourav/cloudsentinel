from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from engine.findings.model import Finding, Severity
from engine.rules.aws.iam.policy_scope import first_matching_action


SELF_MODIFICATION_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
}


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


def _is_customer_managed_policy(
    policy_arn: str | None,
) -> bool:
    if not policy_arn:
        return False

    return (
        policy_arn.startswith("arn:aws:iam::")
        and ":policy/" in policy_arn
        and ":iam::aws:policy/" not in policy_arn
    )


def _resource_targets_policy(
    resource: Any,
    policy_arn: str,
) -> bool:
    """
    Return True when the policy statement can target the policy
    that supplies the principal's permissions.

    Resource='*' is intentionally treated as a match.

    IAM ARN wildcards are supported, for example:

        arn:aws:iam::123456789012:policy/Developer*

    The comparison is performed against the concrete source
    policy ARN.
    """
    for value in _values(resource):
        normalized = value.strip()

        if normalized == "*":
            return True

        if fnmatchcase(policy_arn, normalized):
            return True

    return False


@dataclass(frozen=True)
class SelfModifiablePolicyResult:
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
    matching_action: str
    resource: Any
    condition: Any


def check_self_modifiable_policy(
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
) -> SelfModifiablePolicyResult | None:
    if effect != "Allow":
        return None

    if not _is_customer_managed_policy(policy_arn):
        return None

    matching_action = first_matching_action(
        action,
        SELF_MODIFICATION_ACTIONS,
    )

    if matching_action is None:
        return None

    if not _resource_targets_policy(
        resource,
        policy_arn,
    ):
        return None

    return SelfModifiablePolicyResult(
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
        matching_action=matching_action,
        resource=resource,
        condition=condition,
    )


def build_self_modifiable_policy_finding(
    result: SelfModifiablePolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-034",
        title="IAM Principal Can Modify Its Own Permission Policy",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' receives permissions from "
            f"customer-managed policy '{result.policy_name}' and "
            f"can perform '{result.matching_action}' against that "
            f"same policy. This creates a potential self-modification "
            f"privilege-escalation path."
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
            "matching_action": result.matching_action,
            "resource": result.resource,
            "condition": result.condition,
            "condition_present": bool(result.condition),
            "self_modification_target": result.policy_arn,
        },
        remediation=(
            "Remove policy-version management permissions from the "
            "principal's own permission policy. If delegated policy "
            "administration is required, separate policy-management "
            "permissions from the principal's own authorization "
            "policy and restrict the Resource to explicitly approved "
            "policies. Use permissions boundaries or other IAM "
            "guardrails to prevent privilege escalation."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
