from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEventDataStoreIngestionResult:
    event_data_store_arn: str
    name: str | None
    status: str | None

    @property
    def ingestion_stopped(self) -> bool:
        return self.status == "STOPPED_INGESTION"


def check_cloudtrail_event_data_store_ingestion(
    event_data_store_arn: str,
    name: str | None,
    status: str | None,
) -> CloudTrailEventDataStoreIngestionResult:
    """
    Evaluate whether a CloudTrail Lake event data store
    has stopped ingesting events.
    """
    return CloudTrailEventDataStoreIngestionResult(
        event_data_store_arn=event_data_store_arn,
        name=name,
        status=status,
    )


def build_cloudtrail_event_data_store_ingestion_finding(
    result: CloudTrailEventDataStoreIngestionResult,
) -> Finding | None:
    if not result.ingestion_stopped:
        return None

    return Finding(
        rule_id="CS-AWS-CT-013",
        title=(
            "CloudTrail Lake event data store has stopped "
            "ingesting events"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="cloudtrail_event_data_store",
        resource_id=result.event_data_store_arn,
        description=(
            "The CloudTrail Lake event data store is in "
            "STOPPED_INGESTION status and is not currently "
            "ingesting new events."
        ),
        evidence={
            "event_data_store_arn": result.event_data_store_arn,
            "event_data_store_name": result.name,
            "status": result.status,
        },
        remediation=(
            "Review the CloudTrail Lake event data store configuration "
            "and restart event ingestion so new events are collected."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
