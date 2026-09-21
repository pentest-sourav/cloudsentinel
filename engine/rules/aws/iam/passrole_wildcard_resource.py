from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity
from engine.rules.aws.iam.policy_scope import (
    first_matching_action,
    has_wildcard_resource,
)


PASSROLE_ACTIONS = {
    "iam:PassRole",
}


@dataclass(frozen=True)
class PassRoleWildcardResourceResult:
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


def check_passrole_wildcard_resource(
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
) -> PassRoleWildcardResourceResult | None:
    if effect != "Allow":
        return None

    if not has_wildcard_resource(resource):
        return None

    matched_action = first_matching_action(
        action,
        PASSROLE_ACTIONS,
    )

    if matched_action is None:
        return None

    return PassRoleWildcardResourceResult(
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


def build_passrole_wildcard_resource_finding(
    result: PassRoleWildcardResourceResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-028",
        title="IAM PassRole Uses Wildcard Resource",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' can pass arbitrary IAM "
            "roles because iam:PassRole is granted with a "
            "wildcard resource."
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
            "Replace the wildcard Resource with the specific IAM "
            "role ARNs that the principal must pass. Where "
            "appropriate, additionally constrain the statement "
            "with the iam:PassedToService condition key."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
