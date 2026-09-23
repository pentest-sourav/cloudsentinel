from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEventDataStoreRetentionResult:
    event_data_store_arn: str
    name: str | None
    retention_period: int
    minimum_retention_days: int


def check_cloudtrail_event_data_store_retention(
    event_data_store_arn: str,
    name: str | None,
    retention_period: int | None,
    minimum_retention_days: int = 365,
) -> CloudTrailEventDataStoreRetentionResult | None:
    """
    Evaluate whether a CloudTrail Lake event data store
    retains events for at least the configured minimum period.
    """
    if retention_period is None:
        return None

    if retention_period >= minimum_retention_days:
        return None

    return CloudTrailEventDataStoreRetentionResult(
        event_data_store_arn=event_data_store_arn,
        name=name,
        retention_period=retention_period,
        minimum_retention_days=minimum_retention_days,
    )


def build_cloudtrail_event_data_store_retention_finding(
    result: CloudTrailEventDataStoreRetentionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CT-012",
        title=(
            "CloudTrail Lake event data store retention "
            "period is below the configured minimum"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail_event_data_store",
        resource_id=result.event_data_store_arn,
        description=(
            f"The CloudTrail Lake event data store retains events "
            f"for {result.retention_period} days, which is below "
            f"the configured minimum of "
            f"{result.minimum_retention_days} days."
        ),
        evidence={
            "event_data_store_arn": result.event_data_store_arn,
            "event_data_store_name": result.name,
            "retention_period": result.retention_period,
            "minimum_retention_days": result.minimum_retention_days,
        },
        remediation=(
            "Increase the CloudTrail Lake event data store retention "
            "period to at least the configured minimum."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
