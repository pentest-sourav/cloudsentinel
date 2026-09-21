from engine.findings.model import Severity
from engine.rules.aws.iam.privileged_user_without_boundary import (
    check_privileged_user_without_boundary,
    build_privileged_user_without_boundary_finding,
)


def _base(**overrides):
    data = {
        "username": "alice",
        "permissions_boundary": None,
        "policy_name": "CustomAdminPolicy",
        "policy_arn": (
            "arn:aws:iam::123456789012:policy/"
            "CustomAdminPolicy"
        ),
        "action": "iam:AttachUserPolicy",
        "resource": "*",
        "permission_source": "user_managed_policy",
        "condition": None,
    }
    data.update(overrides)
    return data


def test_detects_privileged_user_without_boundary():
    result = check_privileged_user_without_boundary(
        **_base()
    )

    assert result is not None
    assert result.username == "alice"


def test_detects_multiple_privilege_management_actions():
    for action in (
        "iam:AttachUserPolicy",
        "iam:CreatePolicy",
        "iam:PutUserPolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
    ):
        result = check_privileged_user_without_boundary(
            **_base(action=action)
        )

        assert result is not None


def test_does_not_flag_user_with_permissions_boundary():
    result = check_privileged_user_without_boundary(
        **_base(
            permissions_boundary={
                "PermissionsBoundaryArn": (
                    "arn:aws:iam::123456789012:"
                    "policy/Boundary"
                )
            }
        )
    )

    assert result is None


def test_does_not_flag_non_privileged_action():
    result = check_privileged_user_without_boundary(
        **_base(action="s3:GetObject")
    )

    assert result is None


def test_preserves_condition():
    condition = {
        "StringEquals": {
            "aws:PrincipalTag/Environment": "prod"
        }
    }

    result = check_privileged_user_without_boundary(
        **_base(condition=condition)
    )

    assert result is not None
    assert result.condition == condition


def test_finding_has_expected_metadata():
    result = check_privileged_user_without_boundary(
        **_base()
    )

    finding = build_privileged_user_without_boundary_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-032"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"


def test_finding_contains_boundary_and_action_evidence():
    result = check_privileged_user_without_boundary(
        **_base()
    )

    finding = build_privileged_user_without_boundary_finding(
        result
    )

    assert finding.evidence["username"] == "alice"
    assert finding.evidence["permissions_boundary"] is None
    assert finding.evidence["action"] == "iam:AttachUserPolicy"


def test_does_not_flag_unrelated_iam_action():
    result = check_privileged_user_without_boundary(
        **_base(action="iam:GetPolicy")
    )

    assert result is None


def test_does_not_flag_update_ssh_public_key():
    result = check_privileged_user_without_boundary(
        **_base(action="iam:UpdateSSHPublicKey")
    )

    assert result is None


def test_does_not_flag_update_service_last_accessed():
    result = check_privileged_user_without_boundary(
        **_base(action="iam:UpdateServiceLastAccessed")
    )

    assert result is None


def test_flags_attach_action_wildcard_pattern():
    result = check_privileged_user_without_boundary(
        **_base(action="iam:Attach*")
    )

    assert result is not None
    assert result.matching_action == "iam:AttachGroupPolicy"


def test_flags_full_iam_wildcard():
    result = check_privileged_user_without_boundary(
        **_base(action="iam:*")
    )

    assert result is not None
    assert result.matching_action in {
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:DeleteGroupPolicy",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:DeleteRolePolicy",
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


def test_flags_user_permissions_boundary_management():
    result = check_privileged_user_without_boundary(
        **_base(
            action="iam:PutUserPermissionsBoundary"
        )
    )

    assert result is not None
    assert (
        result.matching_action
        == "iam:PutUserPermissionsBoundary"
    )

def test_flags_delete_permissions_boundary_action():
    result = check_privileged_user_without_boundary(
        username="alice",
        permissions_boundary=None,
        policy_name="AdminDelegation",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/AdminDelegation"
        ),
        action="iam:DeleteUserPermissionsBoundary",
        resource="*",
        permission_source="managed",
        condition=None,
    )

    assert result is not None
    assert result.matching_action == (
        "iam:DeleteUserPermissionsBoundary"
    )
