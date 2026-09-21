from engine.findings.model import Severity
from engine.rules.aws.iam.administrative_policy import (
    build_administrative_group_policy_finding,
    build_administrative_user_policy_finding,
    check_administrative_group_policy,
    check_administrative_user_policy,
)


ADMIN_ARN = (
    "arn:aws:iam::aws:policy/AdministratorAccess"
)


def _check_user(**overrides):
    data = {
        "username": "alice",
        "policy_name": "AdministratorAccess",
        "policy_arn": ADMIN_ARN,
        "policy_version_id": "v1",
        "effect": "Allow",
        "action": "*",
        "resource": "*",
        "condition": None,
    }
    data.update(overrides)
    return check_administrative_user_policy(**data)


def test_detects_administrator_access_directly_on_user():
    result = _check_user()

    assert result is not None
    assert result.username == "alice"
    assert result.policy_name == "AdministratorAccess"


def test_does_not_flag_non_admin_policy():
    result = _check_user(
        policy_name="ReadOnlyAccess",
        policy_arn=(
            "arn:aws:iam::aws:policy/ReadOnlyAccess"
        ),
    )

    assert result is None


def test_does_not_flag_custom_policy_named_administrator_access():
    result = _check_user(
        policy_arn=(
            "arn:aws:iam::123456789012:"
            "policy/AdministratorAccess"
        ),
    )

    assert result is None


def test_does_not_flag_deny_statement():
    result = _check_user(
        effect="Deny",
    )

    assert result is None


def test_user_finding_contains_policy_metadata():
    result = _check_user()

    finding = build_administrative_user_policy_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-025"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"
    assert finding.evidence["policy_name"] == (
        "AdministratorAccess"
    )
    assert finding.evidence["policy_arn"] == ADMIN_ARN
    assert finding.evidence["policy_version_id"] == "v1"


def test_detects_administrator_access_on_group():
    result = check_administrative_group_policy(
        group_name="Administrators",
        policy_name="AdministratorAccess",
        policy_arn=ADMIN_ARN,
    )

    assert result is not None
    assert result.group_name == "Administrators"


def test_does_not_flag_other_group_policy():
    result = check_administrative_group_policy(
        group_name="Developers",
        policy_name="PowerUserAccess",
        policy_arn=(
            "arn:aws:iam::aws:policy/"
            "PowerUserAccess"
        ),
    )

    assert result is None


def test_group_finding_metadata():
    result = check_administrative_group_policy(
        group_name="Administrators",
        policy_name="AdministratorAccess",
        policy_arn=ADMIN_ARN,
    )

    finding = build_administrative_group_policy_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-026"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "iam_group"
    assert finding.resource_id == "Administrators"
    assert finding.evidence["policy_arn"] == ADMIN_ARN
