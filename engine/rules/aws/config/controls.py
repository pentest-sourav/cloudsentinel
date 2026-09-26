from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ConfigRecorderResult:
    recorder_name: str
    recording: bool
    last_status: str | None
    last_error_code: str | None
    last_error_message: str | None


@dataclass(frozen=True)
class ConfigRoleResult:
    recorder_name: str
    role_arn: str | None
    service_principal: str | None


@dataclass(frozen=True)
class ConfigAccountResult:
    recorder_count: int
    active_recorder_count: int
    recorder_names: list[str]
    active_recorder_names: list[str]


def check_config_account_enabled(
    recorder_count: int,
    active_recorder_count: int,
    recorder_names: list[str],
    active_recorder_names: list[str],
) -> ConfigAccountResult | None:
    if active_recorder_count > 0:
        return None

    return ConfigAccountResult(
        recorder_count=recorder_count,
        active_recorder_count=active_recorder_count,
        recorder_names=list(recorder_names),
        active_recorder_names=list(active_recorder_names),
    )


def build_config_account_enabled_finding(
    result: ConfigAccountResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CONFIG-001",
        title="AWS Config Is Not Actively Recording",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="aws_config_account",
        resource_id="account",
        description=(
            "AWS Config does not have an actively recording "
            "configuration recorder for this account."
        ),
        evidence={
            "recorder_count": result.recorder_count,
            "active_recorder_count": result.active_recorder_count,
            "recorder_names": result.recorder_names,
            "active_recorder_names": result.active_recorder_names,
        },
        remediation=(
            "Enable AWS Config and ensure that a configuration "
            "recorder is actively recording the resource types "
            "required by your security controls."
        ),
        compliance=[
            "AWS Security Hub CSPM Config.1",
        ],
    )


def check_config_recorder_enabled(
    name: str,
    recording: bool,
    last_status: str | None,
    last_error_code: str | None,
    last_error_message: str | None,
) -> ConfigRecorderResult | None:
    if not name:
        return None

    if recording:
        return None

    return ConfigRecorderResult(
        recorder_name=name,
        recording=recording,
        last_status=last_status,
        last_error_code=last_error_code,
        last_error_message=last_error_message,
    )


def build_config_recorder_enabled_finding(
    result: ConfigRecorderResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CONFIG-001",
        title="AWS Config Configuration Recorder Is Not Recording",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="aws_config_configuration_recorder",
        resource_id=result.recorder_name,
        description=(
            "The AWS Config configuration recorder is not "
            "actively recording resource configuration changes."
        ),
        evidence={
            "recorder_name": result.recorder_name,
            "recording": result.recording,
            "last_status": result.last_status,
            "last_error_code": result.last_error_code,
            "last_error_message": result.last_error_message,
        },
        remediation=(
            "Start the AWS Config configuration recorder and "
            "verify that resource recording succeeds."
        ),
        compliance=[
            "AWS Security Hub CSPM Config.1",
        ],
    )


def check_config_service_linked_role(
    name: str,
    role_arn: str | None,
    service_principal: str | None,
    recording: bool,
) -> ConfigRoleResult | None:
    if not name or not recording:
        return None

    # AWS service-linked configuration recorders are managed by the
    # linked AWS service. AWS requires AWSServiceRoleForConfig for
    # these recorders, so the presence of a service principal is
    # treated as service-linked recorder evidence.
    if service_principal:
        return None

    if (
        role_arn
        and role_arn.rsplit("/", 1)[-1]
        == "AWSServiceRoleForConfig"
    ):
        return None

    return ConfigRoleResult(
        recorder_name=name,
        role_arn=role_arn,
        service_principal=service_principal,
    )


def build_config_service_linked_role_finding(
    result: ConfigRoleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CONFIG-002",
        title="AWS Config Recorder Does Not Use Its Service-Linked Role",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="aws_config_configuration_recorder",
        resource_id=result.recorder_name,
        description=(
            "The active AWS Config configuration recorder does "
            "not use the AWS Config service-linked role "
            "AWSServiceRoleForConfig."
        ),
        evidence={
            "recorder_name": result.recorder_name,
            "role_arn": result.role_arn,
            "service_principal": result.service_principal,
        },
        remediation=(
            "Configure AWS Config to use the AWS Config "
            "service-linked role AWSServiceRoleForConfig."
        ),
        compliance=[
            "AWS Security Hub CSPM Config.1",
        ],
    )
