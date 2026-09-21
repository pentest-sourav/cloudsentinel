from engine.findings.model import Severity
from engine.rules.aws.iam.wildcard_role_trust_principal import (
    check_wildcard_role_trust_principal,
    build_wildcard_role_trust_principal_finding,
)


def _base(**overrides):
    data = {
        "role_name": "CrossAccountRole",
        "role_arn": (
            "arn:aws:iam::123456789012:"
            "role/CrossAccountRole"
        ),
        "statement_index": 0,
        "effect": "Allow",
        "principal": "*",
        "action": "sts:AssumeRole",
        "condition": None,
    }
    data.update(overrides)
    return data


def test_detects_wildcard_principal():
    result = check_wildcard_role_trust_principal(
        **_base()
    )

    assert result is not None
    assert result.role_name == "CrossAccountRole"


def test_detects_wildcard_inside_principal_dict():
    result = check_wildcard_role_trust_principal(
        **_base(
            principal={
                "AWS": "*"
            }
        )
    )

    assert result is not None


def test_detects_wildcard_inside_principal_list():
    result = check_wildcard_role_trust_principal(
        **_base(
            principal={
                "AWS": [
                    "arn:aws:iam::123456789012:root",
                    "*",
                ]
            }
        )
    )

    assert result is not None


def test_does_not_flag_specific_principal():
    result = check_wildcard_role_trust_principal(
        **_base(
            principal={
                "AWS": (
                    "arn:aws:iam::123456789012:root"
                )
            }
        )
    )

    assert result is None


def test_does_not_flag_deny_statement():
    result = check_wildcard_role_trust_principal(
        **_base(effect="Deny")
    )

    assert result is None


def test_preserves_condition():
    condition = {
        "StringEquals": {
            "sts:ExternalId": "trusted-app"
        }
    }

    result = check_wildcard_role_trust_principal(
        **_base(condition=condition)
    )

    assert result is not None
    assert result.condition == condition


def test_finding_has_expected_metadata():
    result = check_wildcard_role_trust_principal(
        **_base()
    )

    finding = build_wildcard_role_trust_principal_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-033"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_role"
    assert finding.resource_id == "CrossAccountRole"


def test_finding_contains_role_and_principal_evidence():
    result = check_wildcard_role_trust_principal(
        **_base()
    )

    finding = build_wildcard_role_trust_principal_finding(
        result
    )

    assert finding.evidence["role_name"] == (
        "CrossAccountRole"
    )
    assert finding.evidence["principal"] == "*"
    assert finding.evidence["statement_index"] == 0

def test_does_not_flag_unrelated_nested_wildcard_value():
    result = check_wildcard_role_trust_principal(
        role_name="TestRole",
        role_arn="arn:aws:iam::123456789012:role/TestRole",
        statement_index=0,
        effect="Allow",
        principal={
            "AWS": "arn:aws:iam::123456789012:root",
            "ConditionData": {"Value": "*"},
        },
        action="sts:AssumeRole",
        condition=None,
    )

    assert result is None
