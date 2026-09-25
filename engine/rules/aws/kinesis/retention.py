from dataclasses import dataclass

from engine.findings.model import Finding, Severity


DEFAULT_MINIMUM_RETENTION_HOURS = 168


@dataclass(frozen=True)
class KinesisRetentionResult:
    resource_id: str
    expected_configuration: str
    actual_configuration: str


def check_kinesis_retention(
    stream_arn: str,
    retention_period_hours: int | None,
) -> KinesisRetentionResult | None:
    if (
        isinstance(retention_period_hours, int)
        and retention_period_hours
        >= DEFAULT_MINIMUM_RETENTION_HOURS
    ):
        return None

    actual = (
        str(retention_period_hours)
        if retention_period_hours is not None
        else "MISSING"
    )

    return KinesisRetentionResult(
        resource_id=stream_arn,
        expected_configuration=(
            f">={DEFAULT_MINIMUM_RETENTION_HOURS} hours"
        ),
        actual_configuration=actual,
    )


def build_kinesis_retention_finding(
    result: KinesisRetentionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KINESIS-003",
        title=(
            "Kinesis streams should have an adequate "
            "data retention period"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="kinesis_stream",
        resource_id=result.resource_id,
        description=(
            "The Kinesis stream retention period is "
            "below the Security Hub CSPM default minimum."
        ),
        evidence={
            "stream_arn": result.resource_id,
            "expected_configuration": (
                result.expected_configuration
            ),
            "actual_configuration": (
                result.actual_configuration
            ),
        },
        remediation=(
            "Increase the Kinesis stream data retention "
            "period to at least 168 hours, or to the "
            "configured organizational minimum."
        ),
        compliance=[
            "AWS Security Hub Kinesis.3",
        ],
    )
