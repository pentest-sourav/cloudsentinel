from engine.findings.model import Severity

from engine.rules.aws.macie.protection import (
    build_macie_001,
    build_macie_002,
    check_automated_sensitive_data_discovery,
    check_macie_enabled,
)


def test_macie_enabled_passes_when_enabled():
    assert (
        check_macie_enabled(
            "123456789012",
            "ENABLED",
        )
        is None
    )


def test_macie_enabled_fails_when_paused():
    result = check_macie_enabled(
        "123456789012",
        "PAUSED",
    )

    assert result is not None
    assert result.actual_configuration == "PAUSED"


def test_macie_enabled_fails_when_missing():
    result = check_macie_enabled(
        "123456789012",
        None,
    )

    assert result is not None
    assert result.actual_configuration == "MISSING"


def test_automated_discovery_passes_when_enabled():
    assert (
        check_automated_sensitive_data_discovery(
            "123456789012",
            "ENABLED",
            False,
            "ENABLED",
        )
        is None
    )


def test_automated_discovery_fails_when_disabled():
    result = check_automated_sensitive_data_discovery(
        "123456789012",
        "ENABLED",
        False,
        "DISABLED",
    )

    assert result is not None
    assert result.actual_configuration == (
        "Macie=ENABLED; "
        "AutomatedSensitiveDataDiscovery=DISABLED"
    )


def test_automated_discovery_fails_when_missing():
    result = check_automated_sensitive_data_discovery(
        "123456789012",
        "ENABLED",
        False,
        None,
    )

    assert result is not None
    assert result.actual_configuration == (
        "Macie=ENABLED; "
        "AutomatedSensitiveDataDiscovery=MISSING"
    )


def test_automated_discovery_fails_when_macie_disabled():
    result = check_automated_sensitive_data_discovery(
        "123456789012",
        "PAUSED",
        False,
        "ENABLED",
    )

    assert result is not None
    assert "Macie=PAUSED" in (
        result.actual_configuration
    )


def test_automated_discovery_not_applicable_for_member():
    assert (
        check_automated_sensitive_data_discovery(
            "123456789012",
            "ENABLED",
            True,
            None,
        )
        is None
    )


def test_build_macie_001():
    result = check_macie_enabled(
        "123456789012",
        "PAUSED",
    )

    finding = build_macie_001(result)

    assert finding.rule_id == "CS-AWS-MACIE-001"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "macie_account"
    assert finding.compliance == [
        "AWS Security Hub Macie.1"
    ]


def test_build_macie_002():
    result = check_automated_sensitive_data_discovery(
        "123456789012",
        "ENABLED",
        False,
        "DISABLED",
    )

    finding = build_macie_002(result)

    assert finding.rule_id == "CS-AWS-MACIE-002"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "macie_account"
    assert finding.compliance == [
        "AWS Security Hub Macie.2"
    ]
