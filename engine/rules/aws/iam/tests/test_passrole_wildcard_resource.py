from engine.findings.model import Severity
from engine.rules.aws.iam.passrole_wildcard_resource import (
    build_passrole_wildcard_resource_finding,
    check_passrole_wildcard_resource,
)


def _check(**overrides):
    data = {
        "permission_source": "user_managed_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "PassRolePolicy",
        "policy_arn": "arn:aws:iam::123456789012:policy/PassRolePolicy",
        "policy_version_id": "v1",
        "statement_index": None,
        "effect": "Allow",
        "action": "iam:PassRole",
        "resource": "*",
        "condition": None,
    }
    data.update(overrides)
    return check_passrole_wildcard_resource(**data)


def test_detects_passrole_wildcard_resource():
    result = _check()

    assert result is not None
    assert result.action == "iam:PassRole"


def test_supports_action_lists():
    result = _check(
        action=[
            "iam:GetRole",
            "iam:PassRole",
        ]
    )

    assert result is not None


def test_detects_passrole_when_action_pattern_covers_it():
    result = _check(
        action="iam:*",
    )

    assert result is not None


def test_does_not_flag_scoped_role_resource():
    result = _check(
        resource=(
            "arn:aws:iam::123456789012:"
            "role/application-*"
        ),
    )

    assert result is None


def test_does_not_flag_deny():
    result = _check(effect="Deny")

    assert result is None


def test_preserves_passed_to_service_condition():
    condition = {
        "StringEquals": {
            "iam:PassedToService": "lambda.amazonaws.com",
        }
    }

    result = _check(condition=condition)

    assert result is not None
    assert result.condition == condition


def test_builds_high_severity_finding():
    result = _check()

    finding = build_passrole_wildcard_resource_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-028"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "iam_identity"
