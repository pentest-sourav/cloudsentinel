from engine.findings.model import Severity
from engine.rules.aws.iam.broad_user_inline_policy import (
    BroadUserInlinePolicyResult,
    build_broad_user_inline_policy_finding,
    check_broad_user_inline_policy,
)


def test_check_broad_user_inline_policy_detects_wildcard_allow():
    result = check_broad_user_inline_policy(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=0,
        effect="Allow",
        action="*",
        resource="*",
        condition=None,
    )

    assert result == BroadUserInlinePolicyResult(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=0,
        effect="Allow",
        action="*",
        resource="*",
        condition=None,
    )


def test_check_broad_user_inline_policy_preserves_statement_index():
    result = check_broad_user_inline_policy(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=3,
        effect="Allow",
        action="*",
        resource="*",
        condition=None,
    )

    assert result is not None
    assert result.statement_index == 3


def test_check_broad_user_inline_policy_detects_wildcard_lists():
    result = check_broad_user_inline_policy(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=1,
        effect="Allow",
        action=["s3:GetObject", "*"],
        resource=["arn:aws:s3:::example/*", "*"],
        condition=None,
    )

    assert result is not None
    assert result.statement_index == 1


def test_check_broad_user_inline_policy_ignores_deny():
    result = check_broad_user_inline_policy(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=0,
        effect="Deny",
        action="*",
        resource="*",
        condition=None,
    )

    assert result is None


def test_check_broad_user_inline_policy_ignores_specific_action():
    result = check_broad_user_inline_policy(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=0,
        effect="Allow",
        action="s3:GetObject",
        resource="*",
        condition=None,
    )

    assert result is None


def test_check_broad_user_inline_policy_ignores_specific_resource():
    result = check_broad_user_inline_policy(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=0,
        effect="Allow",
        action="*",
        resource="arn:aws:s3:::example/*",
        condition=None,
    )

    assert result is None


def test_check_broad_user_inline_policy_preserves_condition():
    condition = {
        "Bool": {
            "aws:SecureTransport": "false",
        }
    }

    result = check_broad_user_inline_policy(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=2,
        effect="Allow",
        action="*",
        resource="*",
        condition=condition,
    )

    assert result is not None
    assert result.condition == condition
    assert result.statement_index == 2


def test_build_broad_user_inline_policy_finding_includes_statement_index():
    result = BroadUserInlinePolicyResult(
        username="alice",
        policy_name="AdminInlinePolicy",
        statement_index=4,
        effect="Allow",
        action="*",
        resource="*",
        condition=None,
    )

    finding = build_broad_user_inline_policy_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-014"
    assert finding.title == (
        "IAM User Inline Policy Grants Broad Permissions"
    )
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"

    assert finding.evidence == {
        "username": "alice",
        "policy_name": "AdminInlinePolicy",
        "statement_index": 4,
        "effect": "Allow",
        "action": "*",
        "resource": "*",
        "condition_present": False,
        "broad_permission": True,
        "permission_source": "iam_user_inline",
    }
