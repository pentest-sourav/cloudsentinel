from engine.findings.model import Severity
from engine.rules.aws.iam.self_modifiable_policy import (
    build_self_modifiable_policy_finding,
    check_self_modifiable_policy,
)


POLICY_ARN = (
    "arn:aws:iam::123456789012:policy/DeveloperPolicy"
)


def _check(**overrides):
    data = {
        "permission_source": "user_managed_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "DeveloperPolicy",
        "policy_arn": POLICY_ARN,
        "policy_version_id": "v3",
        "statement_index": 0,
        "effect": "Allow",
        "action": "iam:CreatePolicyVersion",
        "resource": POLICY_ARN,
        "condition": None,
    }

    data.update(overrides)

    return check_self_modifiable_policy(**data)


def test_detects_create_policy_version_on_own_policy():
    result = _check()

    assert result is not None
    assert result.matching_action == "iam:CreatePolicyVersion"
    assert result.policy_arn == POLICY_ARN


def test_detects_set_default_policy_version_on_own_policy():
    result = _check(
        action="iam:SetDefaultPolicyVersion",
    )

    assert result is not None
    assert result.matching_action == "iam:SetDefaultPolicyVersion"


def test_detects_full_iam_wildcard():
    result = _check(
        action="iam:*",
        resource="*",
    )

    assert result is not None


def test_detects_policy_arn_wildcard():
    result = _check(
        resource=(
            "arn:aws:iam::123456789012:"
            "policy/Developer*"
        ),
    )

    assert result is not None


def test_detects_resource_wildcard():
    result = _check(
        resource="*",
    )

    assert result is not None


def test_supports_action_lists():
    result = _check(
        action=[
            "iam:GetPolicy",
            "iam:SetDefaultPolicyVersion",
        ],
    )

    assert result is not None
    assert result.matching_action == "iam:SetDefaultPolicyVersion"


def test_supports_resource_lists():
    result = _check(
        resource=[
            "arn:aws:iam::123456789012:policy/OtherPolicy",
            POLICY_ARN,
        ],
    )

    assert result is not None


def test_preserves_condition():
    condition = {
        "StringEquals": {
            "aws:PrincipalTag/Team": "security",
        }
    }

    result = _check(
        condition=condition,
    )

    assert result is not None
    assert result.condition == condition


def test_does_not_flag_deny():
    result = _check(
        effect="Deny",
    )

    assert result is None


def test_does_not_flag_unrelated_action():
    result = _check(
        action="iam:GetPolicy",
    )

    assert result is None


def test_does_not_flag_scoped_other_policy():
    result = _check(
        resource=(
            "arn:aws:iam::123456789012:"
            "policy/OtherPolicy"
        ),
    )

    assert result is None


def test_does_not_flag_inline_policy():
    result = _check(
        policy_arn=None,
    )

    assert result is None


def test_does_not_flag_aws_managed_policy():
    result = _check(
        policy_arn=(
            "arn:aws:iam::aws:policy/"
            "AdministratorAccess"
        ),
    )

    assert result is None


def test_builds_critical_finding():
    result = _check()

    finding = build_self_modifiable_policy_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-034"
    assert finding.severity == Severity.CRITICAL
    assert finding.resource_type == "iam_identity"
    assert finding.resource_id == "alice"

    assert finding.evidence["policy_arn"] == POLICY_ARN
    assert (
        finding.evidence["matching_action"]
        == "iam:CreatePolicyVersion"
    )
    assert finding.evidence["self_modification_target"] == POLICY_ARN
