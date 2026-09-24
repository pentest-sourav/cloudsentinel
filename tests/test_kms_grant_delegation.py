from engine.findings.model import Severity
from engine.rules.aws.kms.grant_delegation import (
    build_kms_grant_delegation_finding,
    check_kms_grant_delegation,
)


def test_create_grant_without_constraints_fails():
    grants = [
        {
            "GrantId": "grant-1",
            "GranteePrincipal": (
                "arn:aws:iam::123456789012:role/AppRole"
            ),
            "Operations": [
                "Decrypt",
                "CreateGrant",
            ],
        }
    ]

    result = check_kms_grant_delegation("key-1", grants)

    assert result is not None
    assert result.grant_id == "grant-1"
    assert result.operations == ("CreateGrant", "Decrypt")

    finding = build_kms_grant_delegation_finding(result)

    assert finding.rule_id == "CS-AWS-KMS-005"
    assert finding.severity == Severity.HIGH


def test_create_grant_with_constraints_is_compliant():
    grants = [
        {
            "GrantId": "grant-1",
            "GranteePrincipal": (
                "arn:aws:iam::123456789012:role/AppRole"
            ),
            "Operations": [
                "Decrypt",
                "CreateGrant",
            ],
            "Constraints": {
                "EncryptionContextEquals": {
                    "Department": "IT"
                }
            },
        }
    ]

    assert check_kms_grant_delegation("key-1", grants) is None


def test_grant_without_create_grant_is_compliant():
    grants = [
        {
            "GrantId": "grant-1",
            "GranteePrincipal": (
                "arn:aws:iam::123456789012:role/AppRole"
            ),
            "Operations": [
                "Decrypt",
                "GenerateDataKey",
            ],
        }
    ]

    assert check_kms_grant_delegation("key-1", grants) is None


def test_empty_grants_are_compliant():
    assert check_kms_grant_delegation("key-1", []) is None


def test_missing_grants_are_compliant():
    assert check_kms_grant_delegation("key-1", None) is None
