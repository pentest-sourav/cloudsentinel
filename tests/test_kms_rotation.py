from engine.findings.model import Severity
from engine.rules.aws.kms.rotation import (
    build_kms_rotation_finding,
    check_kms_rotation,
)


def test_customer_managed_key_with_rotation_enabled_is_compliant():
    assert check_kms_rotation(
        "key-1",
        "CUSTOMER",
        True,
    ) is None


def test_customer_managed_key_with_rotation_disabled_fails():
    result = check_kms_rotation(
        "key-1",
        "CUSTOMER",
        False,
    )

    assert result is not None
    assert result.key_id == "key-1"

    finding = build_kms_rotation_finding(result)

    assert finding.rule_id == "CS-AWS-KMS-001"
    assert finding.severity == Severity.MEDIUM


def test_aws_managed_key_is_ignored():
    assert check_kms_rotation(
        "key-1",
        "AWS",
        None,
    ) is None


def test_unknown_rotation_state_is_ignored():
    assert check_kms_rotation(
        "key-1",
        "CUSTOMER",
        None,
    ) is None
