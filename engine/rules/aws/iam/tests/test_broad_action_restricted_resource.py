from engine.findings.model import Severity
from engine.rules.aws.iam.broad_action_restricted_resource import (
    BroadActionRestrictedResourceResult,
    build_broad_action_restricted_resource_finding,
    check_broad_action_restricted_resource,
)


def _base_arguments() -> dict:
    return {
        "permission_source": "iam_user_managed",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "AdminLikePolicy",
        "policy_arn": (
            "arn:aws:iam::123456789012:policy/AdminLikePolicy"
        ),
        "policy_version_id": "v1",
        "statement_index": 0,
        "effect": "Allow",
        "action": "*",
        "resource": "arn:aws:s3:::company-data/*",
        "condition": None,
    }


def test_allow_wildcard_action_on_scoped_resource_is_detected():
    result = check_broad_action_restricted_resource(
        **_base_arguments()
    )

    assert isinstance(
        result,
        BroadActionRestrictedResourceResult,
    )

    assert result.permission_source == "iam_user_managed"
    assert result.resource_id == "alice"
    assert result.principal_type == "user"
    assert result.principal_id == "alice"
    assert result.username == "alice"
    assert result.group_name is None
    assert result.policy_name == "AdminLikePolicy"
    assert result.policy_arn == (
        "arn:aws:iam::123456789012:policy/AdminLikePolicy"
    )
    assert result.policy_version_id == "v1"
    assert result.statement_index == 0
    assert result.effect == "Allow"
    assert result.action == "*"
    assert result.resource == (
        "arn:aws:s3:::company-data/*"
    )


def test_deny_statement_is_not_detected():
    arguments = _base_arguments()
    arguments["effect"] = "Deny"

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is None


def test_specific_action_is_not_detected():
    arguments = _base_arguments()
    arguments["action"] = "s3:GetObject"

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is None


def test_full_wildcard_resource_is_not_detected():
    arguments = _base_arguments()
    arguments["resource"] = "*"

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is None


def test_empty_resource_is_not_detected():
    arguments = _base_arguments()
    arguments["resource"] = []

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is None


def test_none_resource_is_not_detected():
    arguments = _base_arguments()
    arguments["resource"] = None

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is None


def test_wildcard_action_inside_list_is_detected():
    arguments = _base_arguments()
    arguments["action"] = [
        "ec2:DescribeInstances",
        "*",
    ]

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert isinstance(
        result,
        BroadActionRestrictedResourceResult,
    )


def test_scoped_resource_list_is_detected():
    arguments = _base_arguments()
    arguments["resource"] = [
        "arn:aws:s3:::company-data",
        "arn:aws:s3:::company-data/*",
    ]

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert isinstance(
        result,
        BroadActionRestrictedResourceResult,
    )


def test_resource_list_containing_full_wildcard_is_not_detected():
    arguments = _base_arguments()
    arguments["resource"] = [
        "arn:aws:s3:::company-data/*",
        "*",
    ]

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is None


def test_condition_does_not_hide_broad_action_signal():
    arguments = _base_arguments()
    arguments["condition"] = {
        "Bool": {
            "aws:MultiFactorAuthPresent": "true",
        }
    }

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert isinstance(
        result,
        BroadActionRestrictedResourceResult,
    )

    assert result.condition == {
        "Bool": {
            "aws:MultiFactorAuthPresent": "true",
        }
    }


def test_statement_index_is_preserved():
    arguments = _base_arguments()
    arguments["statement_index"] = 4

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is not None
    assert result.statement_index == 4


def test_group_permission_metadata_is_preserved():
    arguments = _base_arguments()

    arguments.update(
        {
            "permission_source": "iam_group_managed",
            "resource_id": "Developers",
            "principal_type": "group",
            "principal_id": "Developers",
            "username": "alice",
            "group_name": "Developers",
        }
    )

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is not None
    assert result.permission_source == "iam_group_managed"
    assert result.resource_id == "Developers"
    assert result.principal_type == "group"
    assert result.principal_id == "Developers"
    assert result.username == "alice"
    assert result.group_name == "Developers"


def test_inline_policy_metadata_is_preserved():
    arguments = _base_arguments()

    arguments.update(
        {
            "permission_source": "iam_user_inline",
            "policy_arn": None,
            "policy_version_id": None,
            "statement_index": 3,
        }
    )

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is not None
    assert result.permission_source == "iam_user_inline"
    assert result.policy_arn is None
    assert result.policy_version_id is None
    assert result.statement_index == 3


def test_finding_builder_creates_medium_finding():
    result = check_broad_action_restricted_resource(
        **_base_arguments()
    )

    assert result is not None

    finding = build_broad_action_restricted_resource_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-016"
    assert finding.title == (
        "IAM Policy Grants Broad Actions on Scoped Resources"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_identity"
    assert finding.resource_id == "alice"

    assert finding.evidence == {
        "permission_source": "iam_user_managed",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "AdminLikePolicy",
        "policy_arn": (
            "arn:aws:iam::123456789012:policy/AdminLikePolicy"
        ),
        "policy_version_id": "v1",
        "statement_index": 0,
        "effect": "Allow",
        "action": "*",
        "resource": "arn:aws:s3:::company-data/*",
        "condition_present": False,
        "broad_action": True,
        "scoped_resource": True,
    }

    assert finding.compliance == [
        "CIS AWS Foundations"
    ]

    assert "wildcard Action" in finding.description
    assert "scoped resources" in finding.description


def test_condition_is_reflected_in_finding_evidence():
    arguments = _base_arguments()
    arguments["condition"] = {
        "StringEquals": {
            "aws:PrincipalTag/Environment": "prod",
        }
    }

    result = check_broad_action_restricted_resource(
        **arguments
    )

    assert result is not None

    finding = build_broad_action_restricted_resource_finding(
        result
    )

    assert finding.evidence["condition_present"] is True
