from engine.rules.aws.iam.root_mfa import (
    build_root_mfa_finding,
    check_root_mfa,
)


def test_root_mfa_disabled_creates_critical_finding():
    result = check_root_mfa(
        root_mfa_enabled=False,
    )

    assert result.mfa_enabled is False
    assert result.reason


def test_root_mfa_enabled_creates_no_finding():
    result = check_root_mfa(
        root_mfa_enabled=True,
    )

    assert result.mfa_enabled is True

    finding = build_root_mfa_finding(result)

    assert finding is None


def test_root_mfa_disabled_builds_critical_finding():
    result = check_root_mfa(
        root_mfa_enabled=False,
    )

    finding = build_root_mfa_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-IAM-001"
    assert finding.severity.value == "critical"
    assert finding.provider == "aws"
    assert finding.resource_type == "aws_account"
