from engine.findings.model import Severity
from engine.rules.aws.iam.notaction_wildcard_resource import (
    check_notaction_wildcard_resource,
    build_notaction_wildcard_resource_finding,
)


def _base(**overrides):
    data = {
        "permission_source": "user_inline_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "InlinePolicy",
        "policy_arn": None,
        "policy_version_id": None,
        "statement_index": 0,
        "effect": "Allow",
        "not_action": "iam:*",
        "resource": "*",
        "condition": None,
    }
    data.update(overrides)
    return data


def test_detects_notaction_with_wildcard_resource():
    result = check_notaction_wildcard_resource(**_base())

    assert result is not None
    assert result.not_action == "iam:*"


def test_detects_notaction_list():
    result = check_notaction_wildcard_resource(
        **_base(
            not_action=[
                "iam:CreateUser",
                "iam:DeleteUser",
            ]
        )
    )

    assert result is not None


def test_does_not_flag_scoped_resource():
    result = check_notaction_wildcard_resource(
        **_base(
            resource="arn:aws:s3:::company-data/*"
        )
    )

    assert result is None


def test_does_not_flag_deny_statement():
    result = check_notaction_wildcard_resource(
        **_base(effect="Deny")
    )

    assert result is None


def test_does_not_flag_missing_notaction():
    result = check_notaction_wildcard_resource(
        **_base(not_action=None)
    )

    assert result is None


def test_preserves_condition():
    condition = {
        "StringEquals": {
            "aws:PrincipalTag/Environment": "prod"
        }
    }

    result = check_notaction_wildcard_resource(
        **_base(condition=condition)
    )

    assert result is not None
    assert result.condition == condition


def test_finding_has_expected_metadata():
    result = check_notaction_wildcard_resource(**_base())

    finding = build_notaction_wildcard_resource_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-030"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_identity"
    assert finding.resource_id == "alice"


def test_finding_contains_notaction_evidence():
    result = check_notaction_wildcard_resource(**_base())

    finding = build_notaction_wildcard_resource_finding(result)

    assert finding.evidence["not_action"] == "iam:*"
    assert finding.evidence["resource"] == "*"
