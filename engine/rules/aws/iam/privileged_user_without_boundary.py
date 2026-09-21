from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity
from engine.rules.aws.iam.policy_scope import first_matching_action


PRIVILEGE_MANAGEMENT_ACTIONS = {
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:DeleteGroupPermissionsBoundary",
    "iam:DeleteGroupPolicy",
    "iam:DeletePolicy",
    "iam:DeletePolicyVersion",
    "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteRolePolicy",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteUserPolicy",
    "iam:DetachGroupPolicy",
    "iam:DetachRolePolicy",
    "iam:DetachUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutGroupPermissionsBoundary",
    "iam:PutRolePolicy",
    "iam:PutRolePermissionsBoundary",
    "iam:PutUserPolicy",
    "iam:PutUserPermissionsBoundary",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
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


def _has_privilege_management_action(
    action: Any,
) -> str | None:
    return first_matching_action(
        action,
        PRIVILEGE_MANAGEMENT_ACTIONS,
    )


@dataclass(frozen=True)
class PrivilegedUserWithoutBoundaryResult:
    username: str
    permissions_boundary: str | None
    policy_name: str
    policy_arn: str | None
    action: Any
    matching_action: str
    resource: Any
    permission_source: str
    condition: Any


def check_privileged_user_without_boundary(
    username: str,
    permissions_boundary: str | None,
    policy_name: str,
    policy_arn: str | None,
    action: Any,
    resource: Any,
    permission_source: str,
    condition: Any,
) -> PrivilegedUserWithoutBoundaryResult | None:
    if permissions_boundary:
        return None

    matching_action = _has_privilege_management_action(action)

    if matching_action is None:
        return None

    return PrivilegedUserWithoutBoundaryResult(
        username=username,
        permissions_boundary=permissions_boundary,
        policy_name=policy_name,
        policy_arn=policy_arn,
        action=action,
        matching_action=matching_action,
        resource=resource,
        permission_source=permission_source,
        condition=condition,
    )


def build_privileged_user_without_boundary_finding(
    result: PrivilegedUserWithoutBoundaryResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-032",
        title="Privileged IAM User Has No Permissions Boundary",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"IAM user '{result.username}' has a policy granting "
            f"privilege-management action "
            f"'{result.matching_action}' but has no permissions "
            f"boundary configured."
        ),
        evidence={
            "username": result.username,
            "permissions_boundary": result.permissions_boundary,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "action": result.action,
            "matching_action": result.matching_action,
            "resource": result.resource,
            "permission_source": result.permission_source,
            "condition_present": bool(result.condition),
        },
        remediation=(
            "Review whether the user requires privilege-management "
            "permissions. If delegated administration is intentional, "
            "consider applying an appropriate permissions boundary "
            "and restricting the delegated IAM actions."
        ),
        compliance=["CIS AWS Foundations"],
    )
