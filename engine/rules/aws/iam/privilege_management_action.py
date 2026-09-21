from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity
from engine.rules.aws.iam.policy_scope import (
    first_matching_action,
    has_wildcard_resource,
)


PRIVILEGE_MANAGEMENT_ACTIONS = {
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:DeletePolicy",
    "iam:DeletePolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:DetachUserPolicy",
    "iam:DetachGroupPolicy",
    "iam:DetachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:DeleteUserPolicy",
    "iam:DeleteGroupPolicy",
    "iam:DeleteRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:PutUserPermissionsBoundary",
    "iam:PutGroupPermissionsBoundary",
    "iam:PutRolePermissionsBoundary",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
}


@dataclass(frozen=True)
class PrivilegeManagementActionResult:
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
    action: str
    resource: Any
    condition: Any


def check_privilege_management_action(
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
) -> PrivilegeManagementActionResult | None:
    if effect != "Allow":
        return None

    if not has_wildcard_resource(resource):
        return None

    matched_action = first_matching_action(
        action,
        PRIVILEGE_MANAGEMENT_ACTIONS,
    )

    if matched_action is None:
        return None

    return PrivilegeManagementActionResult(
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
        action=matched_action,
        resource=resource,
        condition=condition,
    )


def build_privilege_management_action_finding(
    result: PrivilegeManagementActionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-027",
        title="IAM Privilege Management Action Uses Wildcard Resource",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' is allowed to perform "
            f"privilege-management action '{result.action}' "
            f"against all IAM resources."
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
            "condition": result.condition,
        },
        remediation=(
            "Restrict privilege-management actions to the specific "
            "IAM principals or policies that must be managed. "
            "Where possible, constrain the Resource element and "
            "use conditions such as iam:PolicyArn to limit which "
            "policies may be attached or modified."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
