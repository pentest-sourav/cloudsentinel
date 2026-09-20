from engine.findings.model import Severity
from engine.rules.aws.iam.broad_user_policy import (
    BroadUserPolicyResult,
    build_broad_user_policy_finding,
    check_broad_user_policy,
)


def test_allow_wildcard_action_and_resource_returns_finding():
    result = check_broad_user_policy(
        username="alice",
        policy_name="AdminLikePolicy",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/"
            "AdminLikePolicy"
        ),
        policy_version_id="v1",
        effect="Allow",
        action="*",
        resource="*",
        condition=None,
    )

    assert isinstance(
        result,
        BroadUserPolicyResult,
    )

    assert result.username == "alice"
    assert result.policy_name == "AdminLikePolicy"
    assert result.effect == "Allow"
    assert result.action == "*"
    assert result.resource == "*"


def test_deny_wildcard_action_and_resource_returns_none():
    result = check_broad_user_policy(
        username="alice",
        policy_name="DenyPolicy",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/"
            "DenyPolicy"
        ),
        policy_version_id="v1",
        effect="Deny",
        action="*",
        resource="*",
        condition=None,
    )

    assert result is None


def test_allow_specific_action_returns_none():
    result = check_broad_user_policy(
        username="alice",
        policy_name="S3ReadOnlyPolicy",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/"
            "S3ReadOnlyPolicy"
        ),
        policy_version_id="v1",
        effect="Allow",
        action=[
            "s3:GetObject",
            "s3:ListBucket",
        ],
        resource="*",
        condition=None,
    )

    assert result is None


def test_allow_wildcard_action_specific_resource_returns_none():
    result = check_broad_user_policy(
        username="alice",
        policy_name="ScopedPolicy",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/"
            "ScopedPolicy"
        ),
        policy_version_id="v1",
        effect="Allow",
        action="*",
        resource=(
            "arn:aws:s3:::cloudsentinel-lab-997139435592"
        ),
        condition=None,
    )

    assert result is None


def test_allow_wildcard_action_and_resource_list_returns_finding():
    result = check_broad_user_policy(
        username="alice",
        policy_name="BroadPolicy",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/"
            "BroadPolicy"
        ),
        policy_version_id="v1",
        effect="Allow",
        action=["*"],
        resource=["*"],
        condition=None,
    )

    assert isinstance(
        result,
        BroadUserPolicyResult,
    )


def test_condition_does_not_hide_broad_permission_signal():
    result = check_broad_user_policy(
        username="alice",
        policy_name="ConditionalBroadPolicy",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/"
            "ConditionalBroadPolicy"
        ),
        policy_version_id="v1",
        effect="Allow",
        action="*",
        resource="*",
        condition={
            "Bool": {
                "aws:MultiFactorAuthPresent": "true",
            }
        },
    )

    assert isinstance(
        result,
        BroadUserPolicyResult,
    )

    assert result.condition is not None


def test_build_broad_user_policy_finding():
    result = BroadUserPolicyResult(
        username="alice",
        policy_name="AdminLikePolicy",
        policy_arn=(
            "arn:aws:iam::123456789012:policy/"
            "AdminLikePolicy"
        ),
        policy_version_id="v1",
        effect="Allow",
        action="*",
        resource="*",
        condition=None,
    )

    finding = build_broad_user_policy_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-012"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"

    assert finding.evidence["username"] == "alice"
    assert finding.evidence["policy_name"] == "AdminLikePolicy"
    assert finding.evidence["policy_version_id"] == "v1"
    assert finding.evidence["effect"] == "Allow"
    assert finding.evidence["action"] == "*"
    assert finding.evidence["resource"] == "*"
    assert finding.evidence["broad_permission"] is True
    assert finding.evidence["condition_present"] is False
