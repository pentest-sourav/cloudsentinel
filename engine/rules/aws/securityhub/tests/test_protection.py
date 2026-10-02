from engine.findings.model import Severity
from engine.rules.aws.securityhub.protection import (
    build_hub_finding,
    build_standard_finding,
    check_hub_enabled,
    check_standard_ready,
)


def test_check_hub_enabled_passes_when_enabled():
    assert check_hub_enabled(
        "hub",
        True,
    ) is None


def test_check_hub_enabled_fails_when_disabled():
    result = check_hub_enabled(
        "securityhub",
        False,
    )

    assert result is not None
    assert result.actual_configuration == "DISABLED"


def test_check_standard_ready_passes_when_ready():
    assert check_standard_ready(
        "standard",
        "subscription",
        "arn",
        "READY",
        "READY_FOR_UPDATES",
        None,
        "AWS",
    ) is None


def test_check_standard_ready_fails_for_incomplete():
    result = check_standard_ready(
        "standard",
        "subscription",
        "arn",
        "INCOMPLETE",
        "NOT_READY_FOR_UPDATES",
        "NO_AVAILABLE_CONFIGURATION_RECORDER",
        "AWS",
    )

    assert result is not None
    assert result.actual_configuration == "INCOMPLETE"
    assert result.evidence[
        "standards_status_reason"
    ] == "NO_AVAILABLE_CONFIGURATION_RECORDER"


def test_build_hub_finding():
    result = check_hub_enabled(
        "securityhub",
        False,
    )

    finding = build_hub_finding(result)

    assert finding.rule_id == "CS-AWS-SH-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "securityhub_hub"


def test_build_standard_finding():
    result = check_standard_ready(
        "standard",
        "subscription",
        "arn",
        "FAILED",
        "NOT_READY_FOR_UPDATES",
        "INTERNAL_ERROR",
        "AWS",
    )

    finding = build_standard_finding(result)

    assert finding.rule_id == "CS-AWS-SH-002"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "securityhub_standard"
