from engine.findings.model import Severity
from engine.rules.aws.iam.broad_group_policy import (
    BroadGroupPolicyResult,
    build_broad_group_policy_finding,
    check_broad_group_policy,
)


def _base_arguments() -> dict:
    return {
        "username": "alice",
        "group_name": "Developers",
        "policy_name": "DeveloperAccess",
        "policy_arn": (
            "arn:aws:iam::123456789012:policy/"
            "DeveloperAccess"
        ),
        "policy_version_id": "v3",
        "effect": "Allow",
        "action": "*",
        "resource": "*",
        "condition": None,
    }


def test_allow_wildcard_action_and_resource_is_detected():
    result = check_broad_group_policy(
        **_base_arguments()
    )

    assert isinstance(
        result,
        BroadGroupPolicyResult,
    )

    assert result.username == "alice"
    assert result.group_name == "Developers"
    assert result.policy_name == "DeveloperAccess"
    assert result.action == "*"
    assert result.resource == "*"


def test_deny_statement_is_not_detected():
    arguments = _base_arguments()
    arguments["effect"] = "Deny"

    result = check_broad_group_policy(
        **arguments
    )

    assert result is None


def test_specific_action_is_not_detected():
    arguments = _base_arguments()
    arguments["action"] = "s3:GetObject"

    result = check_broad_group_policy(
        **arguments
    )

    assert result is None


def test_wildcard_action_with_specific_resource_is_not_detected():
    arguments = _base_arguments()
    arguments["resource"] = (
        "arn:aws:s3:::example-bucket/*"
    )

    result = check_broad_group_policy(
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

    result = check_broad_group_policy(
        **arguments
    )

    assert isinstance(
        result,
        BroadGroupPolicyResult,
    )


def test_condition_does_not_hide_broad_permission_signal():
    arguments = _base_arguments()
    arguments["condition"] = {
        "Bool": {
            "aws:MultiFactorAuthPresent": "true"
        }
    }

    result = check_broad_group_policy(
        **arguments
    )

    assert isinstance(
        result,
        BroadGroupPolicyResult,
    )

    assert result.condition == {
        "Bool": {
            "aws:MultiFactorAuthPresent": "true"
        }
    }


def test_finding_builder_preserves_group_relationship():
    result = check_broad_group_policy(
        **_base_arguments()
    )

    assert result is not None

    finding = build_broad_group_policy_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-013"
    assert finding.title == (
        "IAM User Receives Broad Permissions Through Group"
    )
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"

    assert finding.evidence == {
        "username": "alice",
        "group_name": "Developers",
        "policy_name": "DeveloperAccess",
        "policy_arn": (
            "arn:aws:iam::123456789012:policy/"
            "DeveloperAccess"
        ),
        "policy_version_id": "v3",
        "effect": "Allow",
        "action": "*",
        "resource": "*",
        "condition_present": False,
        "broad_permission": True,
        "permission_source": "iam_group",
    }

    assert finding.compliance == [
        "CIS AWS Foundations"
    ]

    assert "group" in finding.remediation.lower()
    assert "wildcard" in finding.description.lower()
