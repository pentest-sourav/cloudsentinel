from engine.rules.aws.iam.user_mfa import (
    build_user_mfa_finding,
    check_user_mfa,
)


def test_user_without_mfa_creates_high_finding():
    result = check_user_mfa(
        username="test-user",
        mfa_devices=[],
    )

    assert result.mfa_enabled is False
    assert result.username == "test-user"

    finding = build_user_mfa_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-IAM-002"
    assert finding.severity.value == "high"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "test-user"


def test_user_with_mfa_creates_no_finding():
    result = check_user_mfa(
        username="test-user",
        mfa_devices=[
            {
                "SerialNumber": "arn:aws:iam::123456789012:mfa/test-user"
            }
        ],
    )

    assert result.mfa_enabled is True

    finding = build_user_mfa_finding(result)

    assert finding is None


def test_multiple_mfa_devices_still_counts_as_enabled():
    result = check_user_mfa(
        username="test-user",
        mfa_devices=[
            {"SerialNumber": "mfa-device-1"},
            {"SerialNumber": "mfa-device-2"},
        ],
    )

    assert result.mfa_enabled is True
