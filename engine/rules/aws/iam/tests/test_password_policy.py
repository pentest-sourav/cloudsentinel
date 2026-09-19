from engine.rules.aws.iam.password_policy import (
    build_password_policy_finding,
    check_password_policy_minimum_length,
)


def test_password_policy_flags_short_password_length():
    result = check_password_policy_minimum_length(
        minimum_password_length=8,
    )

    assert result is not None
    assert result.minimum_password_length == 8
    assert result.threshold == 14


def test_password_policy_allows_14_character_password_length():
    result = check_password_policy_minimum_length(
        minimum_password_length=14,
    )

    assert result is None


def test_password_policy_allows_password_length_above_threshold():
    result = check_password_policy_minimum_length(
        minimum_password_length=20,
    )

    assert result is None


def test_password_policy_finding_contains_expected_details():
    result = check_password_policy_minimum_length(
        minimum_password_length=8,
    )

    assert result is not None

    finding = build_password_policy_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-005"
    assert finding.severity == "medium"
    assert finding.resource_type == "iam_password_policy"
    assert finding.resource_id == "account-password-policy"

    assert finding.evidence["minimum_password_length"] == 8
    assert finding.evidence["threshold"] == 14
