from engine.findings.model import Severity
from engine.rules.aws.iam.notresource_broad_action import (
    check_notresource_broad_action,
    build_notresource_broad_action_finding,
)


def _base(**overrides):
    data = {
        "permission_source": "user_managed_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "BroadPolicy",
        "policy_arn": "arn:aws:iam::123456789012:policy/BroadPolicy",
        "policy_version_id": "v1",
        "statement_index": 0,
        "effect": "Allow",
        "action": "*",
        "not_resource": "arn:aws:s3:::safe-bucket/*",
        "condition": None,
    }
    data.update(overrides)
    return data


def test_detects_full_wildcard_action_with_notresource():
    result = check_notresource_broad_action(**_base())

    assert result is not None
    assert result.action == "*"


def test_detects_wildcard_in_action_list():
    result = check_notresource_broad_action(
        **_base(action=["s3:GetObject", "*"])
    )

    assert result is not None


def test_does_not_flag_specific_action():
    result = check_notresource_broad_action(
        **_base(action="s3:GetObject")
    )

    assert result is None


def test_does_not_flag_missing_notresource():
    result = check_notresource_broad_action(
        **_base(not_resource=None)
    )

    assert result is None


def test_does_not_flag_empty_notresource():
    result = check_notresource_broad_action(
        **_base(not_resource="")
    )

    assert result is None


def test_does_not_flag_deny_statement():
    result = check_notresource_broad_action(
        **_base(effect="Deny")
    )

    assert result is None


def test_preserves_condition():
    condition = {
        "Bool": {
            "aws:SecureTransport": "false"
        }
    }

    result = check_notresource_broad_action(
        **_base(condition=condition)
    )

    assert result is not None
    assert result.condition == condition


def test_finding_has_expected_metadata():
    result = check_notresource_broad_action(**_base())

    finding = build_notresource_broad_action_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-031"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_identity"
    assert finding.resource_id == "alice"


def test_finding_contains_notresource_evidence():
    result = check_notresource_broad_action(**_base())

    finding = build_notresource_broad_action_finding(result)

    assert finding.evidence["action"] == "*"
    assert finding.evidence["not_resource"] == (
        "arn:aws:s3:::safe-bucket/*"
    )
