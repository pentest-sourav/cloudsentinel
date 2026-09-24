from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class StepFunctionsLoggingResult:
    state_machine_arn: str
    logging_enabled: bool
    logging_level: str | None
    logging_configuration: dict[str, Any]


_VALID_LOGGING_LEVELS = {
    "ALL",
    "ERROR",
    "FATAL",
}


def check_stepfunctions_logging(
    state_machine_arn: str,
    logging_configuration: dict[str, Any],
) -> StepFunctionsLoggingResult:
    if not isinstance(logging_configuration, dict):
        logging_configuration = {}

    raw_level = logging_configuration.get("level")

    logging_level = (
        str(raw_level).upper()
        if isinstance(raw_level, str)
        else None
    )

    logging_enabled = logging_level in _VALID_LOGGING_LEVELS

    return StepFunctionsLoggingResult(
        state_machine_arn=state_machine_arn,
        logging_enabled=logging_enabled,
        logging_level=logging_level,
        logging_configuration=logging_configuration,
    )


def build_stepfunctions_logging_finding(
    result: StepFunctionsLoggingResult,
) -> Finding | None:
    if result.logging_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-SFN-001",
        title="Step Functions State Machine Logging Is Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="stepfunctions_state_machine",
        resource_id=result.state_machine_arn,
        description=(
            "The Step Functions state machine does not have "
            "CloudWatch logging enabled with a supported logging "
            "level."
        ),
        evidence={
            "logging_enabled": result.logging_enabled,
            "logging_level": result.logging_level,
            "logging_configuration": (
                result.logging_configuration
            ),
        },
        remediation=(
            "Enable Step Functions state machine logging and "
            "configure a logging level of ALL, ERROR, or FATAL."
        ),
        compliance=[
            "AWS Security Hub StepFunctions.1",
        ],
    )
