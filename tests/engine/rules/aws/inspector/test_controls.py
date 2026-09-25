from engine.findings.model import Severity

from engine.rules.aws.inspector.common import (
    check_scanning_enabled,
)
from engine.rules.aws.inspector.protection import (
    build_inspector_001,
    build_inspector_002,
    build_inspector_003,
    build_inspector_004,
    check_ec2_scanning,
    check_ecr_scanning,
    check_lambda_code_scanning,
    check_lambda_scanning,
)


def test_enabled_status_passes():
    assert check_scanning_enabled(
        "123456789012",
        "ENABLED",
        control_name="Inspector",
        status_field="ec2_status",
    ) is None


def test_disabled_status_fails():
    result = check_ec2_scanning(
        "123456789012",
        "DISABLED",
    )

    finding = build_inspector_001(result)

    assert finding.rule_id == "CS-AWS-INSPECTOR-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "123456789012"
    assert finding.evidence["actual_status"] == "DISABLED"


def test_enabling_status_fails():
    result = check_ecr_scanning(
        "123456789012",
        "ENABLING",
    )

    finding = build_inspector_002(result)

    assert finding.rule_id == "CS-AWS-INSPECTOR-002"
    assert finding.evidence["actual_status"] == "ENABLING"


def test_missing_status_fails():
    result = check_lambda_code_scanning(
        "123456789012",
        None,
    )

    finding = build_inspector_003(result)

    assert finding.rule_id == "CS-AWS-INSPECTOR-003"
    assert finding.evidence["actual_status"] == "MISSING"


def test_lambda_scanning_fails_when_suspended():
    result = check_lambda_scanning(
        "123456789012",
        "SUSPENDED",
    )

    finding = build_inspector_004(result)

    assert finding.rule_id == "CS-AWS-INSPECTOR-004"
    assert finding.severity == Severity.HIGH


def test_all_controls_pass_when_enabled():
    assert check_ec2_scanning(
        "123456789012",
        "ENABLED",
    ) is None

    assert check_ecr_scanning(
        "123456789012",
        "ENABLED",
    ) is None

    assert check_lambda_code_scanning(
        "123456789012",
        "ENABLED",
    ) is None

    assert check_lambda_scanning(
        "123456789012",
        "ENABLED",
    ) is None
