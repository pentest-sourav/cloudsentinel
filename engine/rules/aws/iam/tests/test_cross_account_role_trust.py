from engine.findings.model import Severity
from engine.rules.aws.iam.cross_account_role_trust import (
    build_cross_account_role_trust_finding,
    check_cross_account_role_trust,
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

    return check_cross_account_role_trust(**data)


def test_detects_cross_account_trust_without_external_id():
    result = _check()

    assert result is not None
    assert result.external_account_ids == [
        "222222222222"
    ]


def test_detects_cross_account_role_principal():
    result = _check(
        principal={
            "AWS": (
                "arn:aws:iam::222222222222:"
                "role/ThirdPartyRole"
            )
        }
    )

    assert result is not None
    assert result.external_account_ids == [
        "222222222222"
    ]


def test_detects_multiple_external_accounts():
    result = _check(
        principal={
            "AWS": [
                "111111111111",
                "222222222222",
                "333333333333",
            ]
        }
    )

    assert result is not None
    assert result.external_account_ids == [
        "222222222222",
        "333333333333",
    ]


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


def test_ignores_external_id_condition():
    result = _check(
        condition={
            "StringEquals": {
                "sts:ExternalId": "customer-123",
            }
        }
    )

    assert result is None


def test_external_id_condition_is_case_insensitive():
    result = _check(
        condition={
            "StringEquals": {
                "STS:ExternalID": "customer-123",
            }
        }
    )

    assert result is None


def test_ignores_same_account():
    result = _check(
        principal={
            "AWS": "111111111111",
        }
    )

    assert result is None


def test_ignores_service_principal():
    result = _check(
        principal={
            "Service": "ec2.amazonaws.com",
        }
    )

    assert result is None


def test_ignores_deny():
    result = _check(
        effect="Deny",
    )

    assert result is None


def test_ignores_unrelated_action():
    result = _check(
        action="iam:GetRole",
    )

    assert result is None


def test_ignores_invalid_role_arn():
    result = _check(
        role_arn="not-an-iam-role-arn",
    )

    assert result is None


def test_builds_medium_finding():
    result = _check()

    assert result is not None

    finding = build_cross_account_role_trust_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-037"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "iam_role"
    assert finding.resource_id == ROLE_ARN

    assert finding.evidence[
        "external_account_ids"
    ] == ["222222222222"]

    assert finding.evidence[
        "external_id_present"
    ] is False
