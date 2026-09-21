from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class BroadActionRestrictedResourceResult:
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
    resource: Any
    condition: Any


def _contains_full_wildcard(value: Any) -> bool:
    """
    Return True when the value contains the full IAM wildcard '*'.

    IAM Action and Resource values may be represented either as a
    single string or as a list of strings.
    """
    if value == "*":
        return True

    if isinstance(value, list):
        return "*" in value

    return False


def _has_scoped_resource(value: Any) -> bool:
    """
    Return True when Resource is present and does not contain
    the full wildcard '*'.
    """
    if value is None:
        return False

    if isinstance(value, list):
        if not value:
            return False

        return "*" not in value

    if isinstance(value, str):
        return bool(value) and value != "*"

    return False


def check_broad_action_restricted_resource(
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
) -> BroadActionRestrictedResourceResult | None:
    """
    Detect an Allow statement with wildcard Action over scoped
    resources.

    This rule detects a broad-permission signal. It does not claim
    unrestricted effective access because AWS policy evaluation can
    also involve explicit denies, permissions boundaries, SCPs,
    resource policies, and session policies.
    """
    if effect != "Allow":
        return None

    if not _contains_full_wildcard(action):
        return None

    if _contains_full_wildcard(resource):
        return None

    if not _has_scoped_resource(resource):
        return None

    return BroadActionRestrictedResourceResult(
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
    )


def build_broad_action_restricted_resource_finding(
    result: BroadActionRestrictedResourceResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-016",
        title="IAM Policy Grants Broad Actions on Scoped Resources",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' has a policy "
            f"named '{result.policy_name}' containing an Allow "
            f"statement with wildcard Action permissions over "
            f"one or more scoped resources."
        ),
        evidence={
            "permission_source": result.permission_source,
            "resource_id": result.resource_id,
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
            "broad_action": True,
            "scoped_resource": True,
        },
        remediation=(
            "Review the policy statement and replace wildcard Action "
            "permissions with the minimum actions required for the "
            "specified resources. Also review permissions boundaries, "
            "SCPs, resource policies, and explicit Deny statements "
            "when evaluating effective access."
        ),
        compliance=["CIS AWS Foundations"],
    )
