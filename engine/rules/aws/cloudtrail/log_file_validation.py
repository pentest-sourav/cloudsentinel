from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailLogFileValidationResult:
    trail_arn: str
    name: str | None
    log_file_validation_enabled: bool


def check_cloudtrail_log_file_validation(
    trail_arn: str,
    name: str | None,
    enable_log_file_validation: bool | None,
) -> CloudTrailLogFileValidationResult | None:
    """
    Detect a CloudTrail trail where log file validation is disabled.
    """
    if enable_log_file_validation:
        return None

    return CloudTrailLogFileValidationResult(
        trail_arn=trail_arn,
        name=name,
        log_file_validation_enabled=False,
    )


def build_cloudtrail_log_file_validation_finding(
    result: CloudTrailLogFileValidationResult,
) -> Finding:
    """
    Build a finding for a CloudTrail trail with
    log file validation disabled.
    """
    return Finding(
        rule_id="CS-AWS-CT-003",
        title="CloudTrail log file validation is disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail does not have log file validation "
            "enabled. Without log file validation, modifications to "
            "CloudTrail log files may be harder to detect."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "log_file_validation_enabled": (
                result.log_file_validation_enabled
            ),
        },
        remediation=(
            "Enable CloudTrail log file validation for the affected "
            "trail and verify that the setting is applied."
        ),
        compliance=["CIS AWS Foundations"],
    )
