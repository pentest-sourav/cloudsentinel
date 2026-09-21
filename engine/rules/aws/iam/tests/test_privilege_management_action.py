from engine.findings.model import Severity
from engine.rules.aws.iam.privilege_management_action import (
    build_privilege_management_action_finding,
    check_privilege_management_action,
)


def _check(**overrides):
    data = {
        "permission_source": "user_managed_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "PrivilegePolicy",
        "policy_arn": "arn:aws:iam::123456789012:policy/PrivilegePolicy",
        "policy_version_id": "v1",
        "statement_index": None,
        "effect": "Allow",
        "action": "iam:CreatePolicyVersion",
        "resource": "*",
        "condition": None,
    }
    data.update(overrides)
    return check_privilege_management_action(**data)


def test_detects_create_policy_version_on_wildcard():
    result = _check()

    assert result is not None
    assert result.action == "iam:CreatePolicyVersion"


def test_detects_attach_policy_action():
    result = _check(
        action="iam:AttachUserPolicy",
    )

    assert result is not None


def test_supports_action_lists():
    result = _check(
        action=[
            "iam:GetPolicy",
            "iam:SetDefaultPolicyVersion",
        ]
    )

    assert result is not None
    assert result.action == "iam:SetDefaultPolicyVersion"


def test_does_not_flag_scoped_resource():
    result = _check(
        resource=(
            "arn:aws:iam::123456789012:"
            "policy/team-a/*"
        ),
    )

    assert result is None


def test_does_not_flag_deny():
    result = _check(effect="Deny")

    assert result is None


def test_builds_high_severity_finding():
    result = _check()

    finding = build_privilege_management_action_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-027"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "iam_identity"
