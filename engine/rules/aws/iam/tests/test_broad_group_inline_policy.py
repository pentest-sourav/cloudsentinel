from engine.findings.model import Severity
from engine.rules.aws.iam.broad_group_inline_policy import (
    BroadGroupInlinePolicyResult,
    build_broad_group_inline_policy_finding,
    check_broad_group_inline_policy,
)


def _base_arguments() -> dict:
    return {
        "group_name": "Developers",
        "policy_name": "AdminInlinePolicy",
        "statement_index": 0,
        "effect": "Allow",
        "action": "*",
        "resource": "*",
        "condition": None,
    }


def test_allow_wildcard_action_and_resource_is_detected():
    result = check_broad_group_inline_policy(
        **_base_arguments()
    )

    assert isinstance(
        result,
        BroadGroupInlinePolicyResult,
    )

    assert result.group_name == "Developers"
    assert result.policy_name == "AdminInlinePolicy"
    assert result.statement_index == 0
    assert result.action == "*"
    assert result.resource == "*"


def test_statement_index_is_preserved():
    arguments = _base_arguments()
    arguments["statement_index"] = 4

    result = check_broad_group_inline_policy(
        **arguments
    )

    assert result is not None
    assert result.statement_index == 4


def test_deny_statement_is_not_detected():
    arguments = _base_arguments()
    arguments["effect"] = "Deny"

    result = check_broad_group_inline_policy(
        **arguments
    )

    assert result is None


def test_specific_action_is_not_detected():
    arguments = _base_arguments()
    arguments["action"] = "s3:GetObject"

    result = check_broad_group_inline_policy(
        **arguments
    )

    assert result is None


def test_specific_resource_is_not_detected():
    arguments = _base_arguments()
    arguments["resource"] = (
        "arn:aws:s3:::example-bucket/*"
    )

    result = check_broad_group_inline_policy(
        **arguments
    )

    assert result is None


def test_wildcard_lists_are_detected():
    arguments = _base_arguments()
    arguments["action"] = [
        "ec2:DescribeInstances",
        "*",
    ]
    arguments["resource"] = [
        "arn:aws:s3:::example-bucket",
        "*",
    ]

    result = check_broad_group_inline_policy(
        **arguments
    )

    assert isinstance(
        result,
        BroadGroupInlinePolicyResult,
    )


def test_condition_does_not_hide_broad_permission_signal():
    arguments = _base_arguments()
    arguments["condition"] = {
        "Bool": {
            "aws:MultiFactorAuthPresent": "true",
        }
    }

    result = check_broad_group_inline_policy(
        **arguments
    )

    assert isinstance(
        result,
        BroadGroupInlinePolicyResult,
    )

    assert result.condition == {
        "Bool": {
            "aws:MultiFactorAuthPresent": "true",
        }
    }


def test_finding_builder_uses_group_as_resource():
    result = check_broad_group_inline_policy(
        **_base_arguments()
    )

    assert result is not None

    finding = build_broad_group_inline_policy_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-015"
    assert finding.title == (
        "IAM Group Inline Policy Grants Broad Permissions"
    )
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_group"
    assert finding.resource_id == "Developers"

    assert finding.evidence == {
        "group_name": "Developers",
        "policy_name": "AdminInlinePolicy",
        "statement_index": 0,
        "effect": "Allow",
        "action": "*",
        "resource": "*",
        "condition_present": False,
        "broad_permission": True,
        "permission_source": "iam_group_inline",
    }

    assert finding.compliance == [
        "CIS AWS Foundations"
    ]

    assert "inline policy" in (
        finding.title + finding.description
    ).lower()

    assert "wildcard" in finding.description.lower()
