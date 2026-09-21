from engine.findings.model import Severity
from engine.rules.aws.iam.cross_account_trust_without_condition import (
    build_cross_account_trust_without_condition_finding,
    check_cross_account_trust_without_condition,
)


ROLE_ARN = (
    "arn:aws:iam::111111111111:"
    "role/ProductionRole"
)


def _check(**overrides):
    data = {
        "role_name": "ProductionRole",
        "role_arn": ROLE_ARN,
        "statement_index": 0,
        "effect": "Allow",
        "principal": {
            "AWS": "222222222222",
        },
        "action": "sts:AssumeRole",
        "condition": None,
    }

    data.update(overrides)

    return check_cross_account_trust_without_condition(
        **data
    )


def test_detects_external_account_without_condition():
    result = _check()

    assert result is not None
    assert result.external_account_id == "222222222222"


def test_detects_external_root_arn():
    result = _check(
        principal={
            "AWS": (
                "arn:aws:iam::222222222222:"
                "root"
            )
        }
    )

    assert result is not None
    assert result.external_account_id == "222222222222"


def test_detects_external_account_in_list():
    result = _check(
        principal={
            "AWS": [
                "111111111111",
                "222222222222",
            ]
        }
    )

    assert result is not None
    assert result.external_account_id == "222222222222"


def test_supports_sts_wildcard():
    result = _check(
        action="sts:*",
    )

    assert result is not None


def test_supports_full_action_wildcard():
    result = _check(
        action="*",
    )

    assert result is not None


def test_supports_action_list():
    result = _check(
        action=[
            "iam:GetRole",
            "sts:AssumeRole",
        ],
    )

    assert result is not None


def test_does_not_flag_same_account():
    result = _check(
        principal={
            "AWS": "111111111111",
        }
    )

    assert result is None


def test_does_not_flag_when_condition_exists():
    result = _check(
        condition={
            "StringEquals": {
                "aws:PrincipalOrgID": "o-example",
            }
        }
    )

    assert result is None


def test_does_not_flag_empty_condition_object():
    result = _check(
        condition={},
    )

    assert result is not None


def test_does_not_flag_deny():
    result = _check(
        effect="Deny",
    )

    assert result is None


def test_does_not_flag_unrelated_action():
    result = _check(
        action="iam:GetRole",
    )

    assert result is None


def test_does_not_flag_service_principal():
    result = _check(
        principal={
            "Service": "ec2.amazonaws.com",
        }
    )

    assert result is None


def test_does_not_flag_unknown_role_arn():
    result = _check(
        role_arn="not-an-iam-role-arn",
    )

    assert result is None


def test_builds_medium_finding():
    result = _check()

    assert result is not None

    finding = (
        build_cross_account_trust_without_condition_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-IAM-035"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "iam_role"
    assert finding.resource_id == ROLE_ARN

    assert (
        finding.evidence["external_account_id"]
        == "222222222222"
    )

    assert (
        finding.evidence["condition_present"]
        is False
    )

    assert finding.evidence["statement_index"] == 0
