from engine.findings.model import Severity
from engine.rules.aws.config.controls import (
    build_config_account_enabled_finding,
    build_config_recorder_enabled_finding,
    build_config_service_linked_role_finding,
    check_config_account_enabled,
    check_config_recorder_enabled,
    check_config_service_linked_role,
)


def test_config_recorder_enabled_passes_when_recording():
    result = check_config_recorder_enabled(
        name="default",
        recording=True,
        last_status="SUCCESS",
        last_error_code=None,
        last_error_message=None,
    )

    assert result is None


def test_config_recorder_enabled_detects_stopped_recorder():
    result = check_config_recorder_enabled(
        name="default",
        recording=False,
        last_status="FAILURE",
        last_error_code="InternalError",
        last_error_message="failed",
    )

    assert result is not None
    assert result.recorder_name == "default"

    finding = build_config_recorder_enabled_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CONFIG-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "default"


def test_config_service_linked_role_passes():
    result = check_config_service_linked_role(
        name="default",
        role_arn=(
            "arn:aws:iam::123456789012:"
            "role/aws-service-role/"
            "config.amazonaws.com/"
            "AWSServiceRoleForConfig"
        ),
        service_principal="config.amazonaws.com",
        recording=True,
    )

    assert result is None


def test_config_service_linked_role_detects_custom_role():
    result = check_config_service_linked_role(
        name="default",
        role_arn=(
            "arn:aws:iam::123456789012:"
            "role/CustomConfigRole"
        ),
        service_principal=None,
        recording=True,
    )

    assert result is not None
    assert result.role_arn.endswith(
        "CustomConfigRole"
    )

    finding = build_config_service_linked_role_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CONFIG-002"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "default"


def test_config_service_linked_role_does_not_flag_stopped_recorder():
    result = check_config_service_linked_role(
        name="default",
        role_arn=(
            "arn:aws:iam::123456789012:"
            "role/CustomConfigRole"
        ),
        service_principal=None,
        recording=False,
    )

    assert result is None


def test_config_account_enabled_detects_no_recorder():
    result = check_config_account_enabled(
        recorder_count=0,
        active_recorder_count=0,
        recorder_names=[],
        active_recorder_names=[],
    )

    assert result is not None
    assert result.recorder_count == 0
    assert result.active_recorder_count == 0

    finding = build_config_account_enabled_finding(result)

    assert finding.rule_id == "CS-AWS-CONFIG-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "account"


def test_config_account_enabled_detects_all_recorders_stopped():
    result = check_config_account_enabled(
        recorder_count=1,
        active_recorder_count=0,
        recorder_names=["default"],
        active_recorder_names=[],
    )

    assert result is not None


def test_config_account_enabled_passes_with_active_recorder():
    result = check_config_account_enabled(
        recorder_count=1,
        active_recorder_count=1,
        recorder_names=["default"],
        active_recorder_names=["default"],
    )

    assert result is None


def test_config_service_linked_role_passes_with_service_principal():
    result = check_config_service_linked_role(
        name="AWSConfigurationRecorderForSecurityHubCSPM",
        role_arn=None,
        service_principal="securityhubv2.amazonaws.com",
        recording=True,
    )

    assert result is None
