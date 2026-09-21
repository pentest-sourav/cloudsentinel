from engine.findings.model import Severity
from engine.rules.aws.iam.sensitive_credential_action import (
    build_sensitive_credential_action_finding,
    check_sensitive_credential_action,
)


def _check(**overrides):
    data = {
        "permission_source": "user_managed_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "CredentialPolicy",
        "policy_arn": "arn:aws:iam::123456789012:policy/CredentialPolicy",
        "policy_version_id": "v1",
        "statement_index": None,
        "effect": "Allow",
        "action": "iam:CreateAccessKey",
        "resource": "*",
        "condition": None,
    }
    data.update(overrides)
    return check_sensitive_credential_action(**data)


def test_detects_sensitive_credential_action_with_wildcard_resource():
    result = _check()

    assert result is not None
    assert result.action == "iam:CreateAccessKey"


def test_supports_action_lists():
    result = _check(
        action=[
            "s3:GetObject",
            "iam:UpdateLoginProfile",
        ]
    )

    assert result is not None
    assert result.action == "iam:UpdateLoginProfile"


def test_supports_wildcard_action_patterns():
    result = _check(
        action="iam:Create*",
    )

    assert result is not None


def test_does_not_flag_scoped_resource():
    result = _check(
        resource="arn:aws:iam::123456789012:user/alice",
    )

    assert result is None


def test_does_not_flag_deny():
    result = _check(
        effect="Deny",
    )

    assert result is None


def test_preserves_condition_metadata():
    condition = {
        "StringEquals": {
            "aws:PrincipalTag/team": "security",
        }
    }

    result = _check(condition=condition)

    assert result is not None
    assert result.condition == condition


def test_builds_high_severity_finding():
    result = _check()

    finding = build_sensitive_credential_action_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-024"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "iam_identity"
    assert finding.resource_id == "alice"
    assert finding.evidence["action"] == "iam:CreateAccessKey"
