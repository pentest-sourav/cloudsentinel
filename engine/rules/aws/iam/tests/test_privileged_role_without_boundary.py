from engine.findings.model import Severity
from engine.rules.aws.iam.privileged_role_without_boundary import (
    build_privileged_role_without_boundary_finding,
    check_privileged_role_without_boundary,
)


def _base(**overrides):
    data = {
        "role_name": "AdminRole",
        "role_arn": (
            "arn:aws:iam::123456789012:"
            "role/AdminRole"
        ),
        "permissions_boundary": None,
        "policy_name": "RoleAdminPolicy",
        "policy_arn": (
            "arn:aws:iam::123456789012:"
            "policy/RoleAdminPolicy"
        ),
        "action": "iam:AttachRolePolicy",
        "resource": "*",
        "permission_source": "role_managed_policy",
        "condition": None,
        "statement_index": 0,
    }
    data.update(overrides)
    return data


def test_detects_privileged_role_without_boundary():
    result = check_privileged_role_without_boundary(
        **_base()
    )

    assert result is not None
    assert result.role_name == "AdminRole"


def test_detects_multiple_privilege_management_actions():
    for action in (
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:PutRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:UpdateAssumeRolePolicy",
    ):
        result = check_privileged_role_without_boundary(
            **_base(action=action)
        )

        assert result is not None


def test_does_not_flag_role_with_permissions_boundary():
    result = check_privileged_role_without_boundary(
        **_base(
            permissions_boundary=(
                "arn:aws:iam::123456789012:"
                "policy/Boundary"
            )
        )
    )

    assert result is None


def test_does_not_flag_non_privileged_action():
    result = check_privileged_role_without_boundary(
        **_base(action="s3:GetObject")
    )

    assert result is None


def test_preserves_condition():
    condition = {
        "StringEquals": {
            "aws:PrincipalTag/Environment": "prod"
        }
    }

    result = check_privileged_role_without_boundary(
        **_base(condition=condition)
    )

    assert result is not None
    assert result.condition == condition


def test_preserves_statement_index():
    result = check_privileged_role_without_boundary(
        **_base(statement_index=3)
    )

    assert result is not None
    assert result.statement_index == 3


def test_finding_has_expected_metadata():
    result = check_privileged_role_without_boundary(
        **_base()
    )

    finding = build_privileged_role_without_boundary_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-038"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_role"
    assert finding.resource_id == (
        "arn:aws:iam::123456789012:role/AdminRole"
    )


def test_finding_contains_role_and_policy_evidence():
    result = check_privileged_role_without_boundary(
        **_base()
    )

    finding = build_privileged_role_without_boundary_finding(
        result
    )

    assert finding.evidence["role_name"] == "AdminRole"
    assert finding.evidence["role_arn"] == (
        "arn:aws:iam::123456789012:role/AdminRole"
    )
    assert finding.evidence["permissions_boundary"] is None
    assert finding.evidence["action"] == (
        "iam:AttachRolePolicy"
    )
    assert finding.evidence["permission_source"] == (
        "role_managed_policy"
    )


def test_does_not_flag_unrelated_iam_action():
    result = check_privileged_role_without_boundary(
        **_base(action="iam:GetPolicy")
    )

    assert result is None


def test_flags_attach_action_wildcard_pattern():
    result = check_privileged_role_without_boundary(
        **_base(action="iam:Attach*")
    )

    assert result is not None


def test_flags_full_iam_wildcard():
    result = check_privileged_role_without_boundary(
        **_base(action="iam:*")
    )

    assert result is not None
