from engine.findings.model import Severity
from engine.rules.aws.iam.service_wildcard_action import (
    check_service_wildcard_action,
    build_service_wildcard_action_finding,
)


def _base(**overrides):
    data = {
        "permission_source": "user_managed_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "CustomPolicy",
        "policy_arn": "arn:aws:iam::123456789012:policy/CustomPolicy",
        "policy_version_id": "v1",
        "statement_index": 0,
        "effect": "Allow",
        "action": "s3:*",
        "resource": "*",
        "condition": None,
    }
    data.update(overrides)
    return data


def test_detects_service_level_wildcard_action():
    result = check_service_wildcard_action(**_base())

    assert result is not None
    assert result.action == "s3:*"


def test_detects_service_level_wildcard_in_action_list():
    result = check_service_wildcard_action(
        **_base(action=["s3:GetObject", "ec2:*"])
    )

    assert result is not None
    assert result.action == ["s3:GetObject", "ec2:*"]
    assert result.matching_action == "ec2:*"


def test_detects_iam_service_wildcard_pattern():
    result = check_service_wildcard_action(
        **_base(action="iam:*")
    )

    assert result is not None
    assert result.action == "iam:*"


def test_does_not_flag_full_wildcard_action():
    result = check_service_wildcard_action(
        **_base(action="*")
    )

    assert result is None


def test_does_not_flag_specific_action():
    result = check_service_wildcard_action(
        **_base(action="s3:GetObject")
    )

    assert result is None


def test_does_not_flag_deny_statement():
    result = check_service_wildcard_action(
        **_base(effect="Deny")
    )

    assert result is None


def test_excludes_aws_managed_policy():
    result = check_service_wildcard_action(
        **_base(
            policy_arn=(
                "arn:aws:iam::aws:policy/"
                "AmazonS3FullAccess"
            )
        )
    )

    assert result is None


def test_preserves_condition_and_metadata():
    condition = {
        "StringEquals": {
            "aws:PrincipalTag/Environment": "prod"
        }
    }

    result = check_service_wildcard_action(
        **_base(condition=condition)
    )

    assert result is not None
    assert result.condition == condition
    assert result.username == "alice"
    assert result.policy_name == "CustomPolicy"


def test_finding_has_expected_metadata():
    result = check_service_wildcard_action(**_base())

    finding = build_service_wildcard_action_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-029"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_identity"
    assert finding.resource_id == "alice"


def test_finding_contains_action_evidence():
    result = check_service_wildcard_action(**_base())

    finding = build_service_wildcard_action_finding(result)

    assert finding.evidence["action"] == "s3:*"
    assert finding.evidence["policy_name"] == "CustomPolicy"


def test_does_not_flag_inline_policy():
    result = check_service_wildcard_action(
        **_base(
            policy_arn=None,
            permission_source="user_inline_policy",
        )
    )

    assert result is None


def test_does_not_flag_aws_managed_policy():
    result = check_service_wildcard_action(
        **_base(
            policy_arn=(
                "arn:aws:iam::aws:policy/"
                "AmazonS3FullAccess"
            )
        )
    )

    assert result is None


def test_flags_customer_managed_policy():
    result = check_service_wildcard_action(
        **_base(
            policy_arn=(
                "arn:aws:iam::123456789012:"
                "policy/CustomS3Policy"
            )
        )
    )

    assert result is not None
    assert result.matching_action == "s3:*"

def test_flags_customer_managed_policy_in_govcloud_partition():
    result = check_service_wildcard_action(
        permission_source="managed",
        resource_id="alice",
        principal_type="user",
        principal_id="alice",
        username="alice",
        group_name=None,
        policy_name="GovPolicy",
        policy_arn=(
            "arn:aws-us-gov:iam::123456789012:policy/GovPolicy"
        ),
        policy_version_id="v1",
        statement_index=0,
        effect="Allow",
        action="s3:*",
        resource="*",
        condition=None,
    )

    assert result is not None
    assert result.matching_action == "s3:*"


def test_flags_customer_managed_policy_in_china_partition():
    result = check_service_wildcard_action(
        permission_source="managed",
        resource_id="alice",
        principal_type="user",
        principal_id="alice",
        username="alice",
        group_name=None,
        policy_name="ChinaPolicy",
        policy_arn=(
            "arn:aws-cn:iam::123456789012:policy/ChinaPolicy"
        ),
        policy_version_id="v1",
        statement_index=0,
        effect="Allow",
        action="ec2:*",
        resource="*",
        condition=None,
    )

    assert result is not None
    assert result.matching_action == "ec2:*"
